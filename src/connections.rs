//! Connections: how many there may be, how many from one address, and how
//! long one may take to say what it wants.
//!
//! The request timeout in [`crate::api`] starts once a request has been read.
//! Everything before that is here. A connection that opens and says nothing,
//! or trickles its headers in a byte at a time, or sits idle after its last
//! request, holds a socket and a task for as long as it likes unless something
//! closes it — and a few thousand of those are a server nobody else reaches.
//! So hyper gets a clock and a deadline for the headers, a connection that has
//! not yet said which HTTP it speaks gets a deadline of its own, and there are
//! only so many connections at once: in all, and from any one address.
//!
//! What is being answered is never cut short by any of this. An event stream
//! says nothing for minutes on end and that is fine: the deadlines are for
//! reading a request, not for serving one.

use crate::config::Config;
use axum::Router;
use axum_server::accept::{Accept, DefaultAcceptor};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use axum_server::Handle;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Sleep;

/// How long a client has for the headers of a request, and how long an idle
/// connection is kept between two. Plenty for a phone on a bad link; a
/// connection that needs longer is not a device syncing.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(15);

/// HTTP/2 has no header deadline — a request's headers arrive in one frame —
/// but a connection can go quiet for good. A ping every half minute finds
/// out, and one not answered within twenty seconds ends it.
const H2_PING_EVERY: Duration = Duration::from_secs(30);
const H2_PING_TIMEOUT: Duration = Duration::from_secs(20);

/// Requests in flight on one HTTP/2 connection. A device needs a handful.
const H2_STREAMS: u32 = 64;

/// Before hyper's own deadline can start, the connection has to say which
/// HTTP it speaks, and hyper waits for that without a clock: up to the 24
/// bytes of the HTTP/2 preface. No HTTP/1.1 request is shorter than that
/// either — it has to name its host — so every honest client sends them at
/// once.
const FIRST_BYTES: usize = 24;

/// What connections may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Open at once, from everybody.
    pub max: usize,
    /// Open at once from one address; zero for no limit.
    pub per_address: usize,
    /// For the headers of a request, and for a connection to start one.
    pub header_timeout: Duration,
}

impl Limits {
    /// The configured ones. Behind a proxy every connection comes from the
    /// proxy, so counting per address would count the proxy — there, only the
    /// total counts.
    pub fn from_config(config: &Config) -> Self {
        Self {
            max: config.max_connections,
            per_address: if config.trust_forwarded {
                0
            } else {
                config.max_connections_per_address
            },
            header_timeout: HEADER_TIMEOUT,
        }
    }
}

/// Serve `app` on `listener` until `handle` says to stop: with TLS when there
/// is a certificate, plain otherwise, and within `limits` either way.
pub async fn serve(
    listener: std::net::TcpListener,
    app: Router,
    tls: Option<RustlsConfig>,
    limits: Limits,
    handle: Handle<SocketAddr>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let gate = Gate::new(limits);
    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    let server = axum_server::from_tcp(listener)?.handle(handle);
    match tls {
        Some(tls) => {
            let mut server = server.acceptor(Limited {
                inner: RustlsAcceptor::new(tls),
                gate,
            });
            tune(server.http_builder(), &limits);
            server.serve(app).await
        }
        None => {
            let mut server = server.acceptor(Limited {
                inner: DefaultAcceptor::new(),
                gate,
            });
            tune(server.http_builder(), &limits);
            server.serve(app).await
        }
    }
}

/// A clock for hyper, without which it has no deadlines at all.
fn tune(builder: &mut Builder<TokioExecutor>, limits: &Limits) {
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(H2_PING_EVERY)
        .keep_alive_timeout(H2_PING_TIMEOUT)
        .max_concurrent_streams(H2_STREAMS);
}

/// The count of open connections, in all and per address.
#[derive(Clone)]
pub struct Gate {
    limits: Limits,
    open: Arc<Mutex<Open>>,
}

#[derive(Default)]
struct Open {
    all: usize,
    by_address: HashMap<String, usize>,
    /// When the log last heard that somebody was turned away: once a minute
    /// is enough, a flood of refusals must not become a flood of lines.
    said: Option<Instant>,
}

impl Gate {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            open: Arc::default(),
        }
    }

    /// Room for one more connection from `peer`, or none. The room is taken
    /// until what comes back is dropped.
    pub fn admit(&self, peer: IpAddr) -> Option<Admitted> {
        // Counted the way the rate limiter counts: an IPv6 machine has a whole
        // /64 to pick addresses from.
        let address = crate::state::counted(peer);
        let mut open = self.open.lock();
        let from_there = open.by_address.get(&address).copied().unwrap_or(0);
        let full = open.all >= self.limits.max;
        if full || (self.limits.per_address > 0 && from_there >= self.limits.per_address) {
            if open
                .said
                .is_none_or(|said| said.elapsed() >= Duration::from_secs(60))
            {
                open.said = Some(Instant::now());
                if full {
                    tracing::warn!(
                        open = open.all,
                        "as many connections as the server takes; new ones are turned away"
                    );
                } else {
                    tracing::warn!(
                        %address, open = from_there,
                        "as many connections from one address as the server takes from one"
                    );
                }
            }
            return None;
        }
        open.all += 1;
        *open.by_address.entry(address.clone()).or_default() += 1;
        Some(Admitted {
            open: self.open.clone(),
            address,
        })
    }

    /// How many connections are open.
    pub fn open(&self) -> usize {
        self.open.lock().all
    }
}

/// One connection's room, given back when it closes.
pub struct Admitted {
    open: Arc<Mutex<Open>>,
    address: String,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut open = self.open.lock();
        open.all = open.all.saturating_sub(1);
        if let Some(count) = open.by_address.get_mut(&self.address) {
            *count -= 1;
            if *count == 0 {
                open.by_address.remove(&self.address);
            }
        }
    }
}

/// Lets a connection in only when there is room, before anything else — the
/// TLS handshake included, which costs more than turning it away.
#[derive(Clone)]
struct Limited<A> {
    inner: A,
    gate: Gate,
}

type Accepted<S, T> = Pin<Box<dyn Future<Output = io::Result<(Guarded<S>, T)>> + Send>>;

impl<A, S> Accept<TcpStream, S> for Limited<A>
where
    A: Accept<TcpStream, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = Guarded<A::Stream>;
    type Service = A::Service;
    type Future = Accepted<A::Stream, A::Service>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let Some(admitted) = stream
            .peer_addr()
            .ok()
            .and_then(|peer| self.gate.admit(peer.ip()))
        else {
            // Dropping the stream closes it.
            return Box::pin(std::future::ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "no room for another connection",
            ))));
        };
        let deadline = self.gate.limits.header_timeout;
        let accepting = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = accepting.await?;
            Ok((Guarded::new(stream, admitted, deadline), service))
        })
    }
}

/// A connection that holds its room, and has to have said its first
/// [`FIRST_BYTES`] before its deadline. After that hyper's own deadlines take
/// over, and this is only a stream.
pub struct Guarded<S> {
    inner: S,
    _admitted: Admitted,
    /// How much has arrived, and until when the rest may take — until there
    /// has been enough.
    first: Option<(usize, Pin<Box<Sleep>>)>,
}

impl<S> Guarded<S> {
    fn new(inner: S, admitted: Admitted, deadline: Duration) -> Self {
        Self {
            inner,
            _admitted: admitted,
            first: Some((0, Box::pin(tokio::time::sleep(deadline)))),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        let Some((seen, deadline)) = this.first.as_mut() else {
            return polled;
        };
        match polled {
            Poll::Ready(Ok(())) => {
                *seen += buf.filled().len() - before;
                if *seen >= FIRST_BYTES {
                    this.first = None;
                }
            }
            // Polled here, so the task wakes when time is up even if the
            // client never sends another byte.
            Poll::Pending if deadline.as_mut().poll(cx).is_ready() => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "a connection that did not say what it wants in time",
                )));
            }
            _ => {}
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// On unix, as many open files as the machine lets this process have: every
/// connection is one, and the default of 1024 that some container runtimes
/// hand out is less than the connections this server takes. Returns the limit
/// there is now, where there is one to tell.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // rlim_t is not u64 everywhere
pub fn raise_open_files() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit only read and write the struct passed
    // to them, which lives on this stack for the length of the call.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return None;
        }
        if limit.rlim_cur < limit.rlim_max {
            let raised = libc::rlimit {
                rlim_cur: limit.rlim_max,
                rlim_max: limit.rlim_max,
            };
            // Refused on some systems when the hard limit is "unlimited";
            // then the soft one stays what it was.
            if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) == 0 {
                limit = raised;
            }
        }
    }
    Some(limit.rlim_cur as u64)
}

#[cfg(not(unix))]
pub fn raise_open_files() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(max: usize, per_address: usize) -> Gate {
        Gate::new(Limits {
            max,
            per_address,
            header_timeout: HEADER_TIMEOUT,
        })
    }

    #[test]
    fn one_address_gets_its_share_and_no_more() {
        let gate = gate(10, 2);
        let home: IpAddr = "203.0.113.7".parse().unwrap();
        let first = gate.admit(home).expect("room");
        let _second = gate.admit(home).expect("room");
        assert!(gate.admit(home).is_none());
        assert!(
            gate.admit("198.51.100.1".parse().unwrap()).is_some(),
            "somebody else"
        );
        drop(first);
        assert!(gate.admit(home).is_some(), "a closed one makes room");
    }

    #[test]
    fn a_whole_ipv6_network_counts_as_one_address() {
        let gate = gate(10, 2);
        let _one = gate.admit("2001:db8:1:2::1".parse().unwrap()).unwrap();
        let _two = gate.admit("2001:db8:1:2::2".parse().unwrap()).unwrap();
        assert!(gate.admit("2001:db8:1:2::3".parse().unwrap()).is_none());
    }

    #[test]
    fn everybody_together_gets_the_total_and_no_more() {
        let gate = gate(3, 0);
        let open: Vec<_> = (1..=3)
            .map(|n| gate.admit(IpAddr::from([10, 0, 0, n])).expect("room"))
            .collect();
        assert_eq!(gate.open(), 3);
        assert!(gate.admit("10.0.0.9".parse().unwrap()).is_none());
        drop(open);
        assert_eq!(gate.open(), 0);
        assert!(gate.open.lock().by_address.is_empty(), "nothing left over");
    }

    #[test]
    fn behind_a_proxy_only_the_total_counts() {
        let proxied = Config {
            trust_forwarded: true,
            ..Config::default()
        };
        assert_eq!(Limits::from_config(&proxied).per_address, 0);
        let direct = Limits::from_config(&Config::default());
        assert_eq!(direct.per_address, 32);
        assert_eq!(direct.max, 512);
        // A household behind one address: several devices, each with an
        // event stream and a couple of requests going.
        assert!(direct.per_address >= 8 * 3);
    }
}
