//! Connections over real sockets, served the way `serve` serves them: what a
//! client that says nothing, or says it slowly, gets — and that a client
//! being answered slowly is left alone.
//!
//! The deadlines here are a fraction of a second instead of fifteen, so the
//! tests wait for them on a real clock without taking all day.

use axum::body::Body;
use axum::routing::get;
use axum::Router;
use axum_server::Handle;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uwusync_server::connections::{serve, Limits};

const DEADLINE: Duration = Duration::from_millis(300);

/// Something to ask for: a quick answer, a slow one, and one that trickles
/// out for longer than any deadline, as an event stream does.
fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "hello" }))
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(DEADLINE * 4).await;
                "worth the wait"
            }),
        )
        .route(
            "/stream",
            get(|| async {
                let ticks = ticks(6, DEADLINE / 2);
                Body::from_stream(ticks)
            }),
        )
}

/// `count` chunks, one every `every`.
fn ticks(
    count: usize,
    every: Duration,
) -> impl futures_core::Stream<Item = Result<String, std::convert::Infallible>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        for n in 0..count {
            tokio::time::sleep(every).await;
            if sender.send(Ok(format!("tick {n}\n"))).await.is_err() {
                return;
            }
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(receiver)
}

async fn start(limits: Limits) -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, app(), None, limits, Handle::new()));
    address
}

fn limits() -> Limits {
    Limits {
        max: 64,
        per_address: 16,
        header_timeout: DEADLINE,
    }
}

/// Whether the server closes this connection within `within`. Reading
/// nothing, or a reset, is closed; still waiting at the end is open.
async fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 1024];
    let started = Instant::now();
    loop {
        let left = within.saturating_sub(started.elapsed());
        match tokio::time::timeout(left, stream.read(&mut buf)).await {
            Err(_) => return false,
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            // An answer, say a 408: read on until it closes.
            Ok(Ok(_)) => continue,
        }
    }
}

/// A whole request, and the whole answer to it, on a connection kept open.
async fn ask(stream: &mut TcpStream, path: &str) -> String {
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut answer = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("an answer")
            .unwrap();
        assert!(read > 0, "closed before the answer was whole");
        answer.extend_from_slice(&buf[..read]);
        let text = String::from_utf8_lossy(&answer);
        // Plain bodies say their length; the stream ends with an empty chunk.
        if text.contains("\r\n\r\n")
            && (text.ends_with("0\r\n\r\n")
                || text.contains("hello")
                || text.contains("worth the wait"))
        {
            return text.into_owned();
        }
    }
}

#[tokio::test]
async fn a_connection_that_says_nothing_is_closed() {
    let address = start(limits()).await;
    let mut silent = TcpStream::connect(address).await.unwrap();
    assert!(closed_within(&mut silent, DEADLINE * 10).await);
}

#[tokio::test]
async fn a_connection_that_stops_halfway_through_its_headers_is_closed() {
    let address = start(limits()).await;
    let mut slow = TcpStream::connect(address).await.unwrap();
    slow.write_all(b"GET / HTTP/1.1\r\nHost: test\r\nX-Slow: ")
        .await
        .unwrap();
    assert!(closed_within(&mut slow, DEADLINE * 10).await);
}

#[tokio::test]
async fn a_connection_that_stops_before_saying_which_http_is_closed() {
    let address = start(limits()).await;
    // The first bytes of the HTTP/2 preface, and then nothing: without a
    // deadline of its own, hyper would wait for the rest for ever.
    let mut slow = TcpStream::connect(address).await.unwrap();
    slow.write_all(b"PRI * HTTP/2.0\r\n").await.unwrap();
    assert!(closed_within(&mut slow, DEADLINE * 10).await);
}

#[tokio::test]
async fn an_idle_connection_is_closed_after_its_last_answer() {
    let address = start(limits()).await;
    let mut idle = TcpStream::connect(address).await.unwrap();
    assert!(ask(&mut idle, "/").await.contains("hello"));
    assert!(closed_within(&mut idle, DEADLINE * 10).await);
}

#[tokio::test]
async fn a_slow_answer_and_a_long_stream_are_not_cut_short() {
    let address = start(limits()).await;
    let mut waiting = TcpStream::connect(address).await.unwrap();
    assert!(ask(&mut waiting, "/slow").await.contains("worth the wait"));

    // Three deadlines long, and the connection says nothing all the while.
    let mut listening = TcpStream::connect(address).await.unwrap();
    let streamed = ask(&mut listening, "/stream").await;
    assert!(
        streamed.contains("tick 0") && streamed.contains("tick 5"),
        "{streamed}"
    );
}

#[tokio::test]
async fn one_address_holds_only_so_many_connections() {
    let address = start(Limits {
        per_address: 3,
        // Long enough that what closes a connection here is the count.
        header_timeout: Duration::from_secs(30),
        ..limits()
    })
    .await;
    let mut open = Vec::new();
    for _ in 0..3 {
        let mut stream = TcpStream::connect(address).await.unwrap();
        assert!(ask(&mut stream, "/").await.contains("hello"));
        open.push(stream);
    }
    let mut one_more = TcpStream::connect(address).await.unwrap();
    assert!(
        closed_within(&mut one_more, Duration::from_secs(2)).await,
        "turned away at once"
    );

    // One closes, and there is room again once the server has noticed.
    drop(open.pop());
    let started = Instant::now();
    loop {
        let mut again = TcpStream::connect(address).await.unwrap();
        if again
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .is_ok()
        {
            let mut buf = [0u8; 256];
            if let Ok(Ok(read)) =
                tokio::time::timeout(Duration::from_millis(500), again.read(&mut buf)).await
            {
                if read > 0 {
                    break;
                }
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no room after one closed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for stream in &mut open {
        assert!(
            ask(stream, "/").await.contains("hello"),
            "the others stayed"
        );
    }
}

#[tokio::test]
async fn everybody_together_holds_only_so_many_connections() {
    let address = start(Limits {
        max: 2,
        per_address: 0,
        header_timeout: Duration::from_secs(30),
    })
    .await;
    let mut first = TcpStream::connect(address).await.unwrap();
    let mut second = TcpStream::connect(address).await.unwrap();
    assert!(ask(&mut first, "/").await.contains("hello"));
    assert!(ask(&mut second, "/").await.contains("hello"));
    let mut third = TcpStream::connect(address).await.unwrap();
    assert!(closed_within(&mut third, Duration::from_secs(2)).await);
}

// ── HTTP/2 ──────────────────────────────────────────────────────────────────
//
// hyper has no idle deadline for HTTP/2: a client that has said hello and
// answers every ping looks alive to it. What closes one is the count of what
// the connection is answering.

/// An HTTP/2 connection without TLS, the way a client that knows the server
/// speaks it opens one. The client answers pings by itself.
async fn h2(
    address: SocketAddr,
) -> (
    SendRequest<String>,
    tokio::task::JoinHandle<Result<(), hyper::Error>>,
) {
    let stream = TcpStream::connect(address).await.unwrap();
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    (sender, tokio::spawn(connection))
}

#[tokio::test]
async fn an_idle_http2_connection_is_closed() {
    let address = start(limits()).await;
    let (sender, connection) = h2(address).await;
    assert!(
        tokio::time::timeout(DEADLINE * 10, connection)
            .await
            .is_ok(),
        "still open with nothing to answer"
    );
    drop(sender);
}

#[tokio::test]
async fn an_idle_http2_connection_is_closed_after_its_last_answer() {
    let address = start(limits()).await;
    let (mut sender, connection) = h2(address).await;

    // Three deadlines long, and the connection says nothing all the while:
    // an answer in progress keeps it.
    let request = hyper::Request::get(format!("http://{address}/stream"))
        .body(String::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let streamed = axum::body::to_bytes(Body::new(response.into_body()), usize::MAX)
        .await
        .unwrap();
    let streamed = String::from_utf8_lossy(&streamed);
    assert!(
        streamed.contains("tick 0") && streamed.contains("tick 5"),
        "{streamed}"
    );

    assert!(
        tokio::time::timeout(DEADLINE * 10, connection)
            .await
            .is_ok(),
        "still open after the answer was done"
    );
    drop(sender);
}

#[tokio::test]
async fn an_http2_connection_takes_only_a_few_requests_at_once() {
    let address = start(limits()).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    // The preface and an empty SETTINGS frame: enough for the server to say
    // its own settings, which come first.
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        .await
        .unwrap();
    let mut header = [0u8; 9];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[3], 0x4, "a SETTINGS frame");
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let mut settings = vec![0u8; length];
    stream.read_exact(&mut settings).await.unwrap();
    // SETTINGS_MAX_CONCURRENT_STREAMS is setting 3.
    let streams = settings
        .as_chunks::<6>()
        .0
        .iter()
        .find(|setting| u16::from_be_bytes([setting[0], setting[1]]) == 0x3)
        .map(|setting| u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]));
    assert_eq!(streams, Some(8), "a handful, not the 64 from before");
}
