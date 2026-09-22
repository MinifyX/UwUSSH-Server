//! `uwusync-server health`: the container's health check, asked from inside.
//!
//! The image has no shell and no curl, so the binary asks itself. It calls
//! the running server where it listens, the way a device would — over the
//! server's own TLS — and only calls it healthy when `/healthz` says so **and**
//! the other end proved it holds the key in `tls/key.pem` — the one every
//! device pinned. (A server with accounts never makes itself a new one: it
//! refuses to start instead, which this check sees as well.)

use crate::config::{Config, TlsMode};
use crate::tls;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Ask the running server, and say what is wrong if it is not well.
pub fn probe(config: &Config) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(check(config))?;
    println!("ok");
    Ok(())
}

/// The same, for a caller that already has a runtime.
pub async fn check(config: &Config) -> Result<(), String> {
    let tls = match config.tls {
        TlsMode::Auto => {
            let key = tls::public_key_of(&config.data_dir)
                .map_err(|error| format!("the certificate key: {error}"))?
                .ok_or("no certificate key yet — the server has not started")?;
            own_key(key)
        }
        // Plain HTTP; the configuration is never used, but a client needs one.
        TlsMode::Off => own_key(Vec::new()),
    };
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| error.to_string())?;

    let scheme = match config.tls {
        TlsMode::Auto => "https",
        TlsMode::Off => "http",
    };
    let url = format!("{scheme}://{}/healthz", local(config.listen));
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| format!("{url}: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("{url} answered {}", response.status()));
    }
    let health: uwussh_proto::api::Health = response
        .json()
        .await
        .map_err(|error| format!("{url} answered something else: {error}"))?;
    if !health.ok {
        return Err(format!("{url} says it is not well"));
    }
    Ok(())
}

/// Where to knock: a server listening on every address is asked on loopback.
fn local(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, listen.port())
}

/// TLS 1.3 that accepts exactly one key: this server's own.
fn own_key(spki: Vec<u8>) -> rustls::ClientConfig {
    let provider = Arc::new(ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring speaks TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(OwnKey { spki, provider }))
        .with_no_client_auth()
}

/// Looks past the certificate — it is made fresh at every start, so there is
/// nothing in it to expect — and checks the one thing that matters: that the
/// handshake was signed with the key in `tls/key.pem`. That signature is what
/// a certificate would only have vouched for.
#[derive(Debug)]
struct OwnKey {
    spki: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for OwnKey {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Never asked: the configuration only speaks 1.3.
        Err(TlsError::General("TLS 1.2 is not spoken here".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(self.spki.as_slice()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_on_every_address_is_asked_on_loopback() {
        assert_eq!(
            local("0.0.0.0:8443".parse().unwrap()),
            "127.0.0.1:8443".parse().unwrap()
        );
        assert_eq!(
            local("[::]:8443".parse().unwrap()),
            "[::1]:8443".parse().unwrap()
        );
        assert_eq!(
            local("10.0.0.5:9000".parse().unwrap()),
            "10.0.0.5:9000".parse().unwrap()
        );
    }
}
