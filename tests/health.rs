//! The container's health check against a real server — over the server's own
//! TLS, the way the image runs it.

use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use std::net::SocketAddr;
use std::path::PathBuf;
use uuid::Uuid;
use uwusync_server::config::TlsMode;
use uwusync_server::db::Db;
use uwusync_server::{api, connections, health, tls, AppState, Config};

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("uwusync-health-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A server with its own certificate from `data_dir`, as `serve` starts one.
async fn serve_tls(data_dir: &std::path::Path) -> SocketAddr {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let identity = tls::load_or_create(data_dir, &tls::names_for(None)).unwrap();
    let config = RustlsConfig::from_pem(
        identity.cert_pem.into_bytes(),
        identity.key_pem.into_bytes(),
    )
    .await
    .unwrap();
    let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
    let limits = connections::Limits::from_config(&state.config);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let handle = Handle::new();
    tokio::spawn(connections::serve(
        listener,
        api::router(state),
        Some(config),
        limits,
        handle.clone(),
    ));
    handle.listening().await.expect("the server listens")
}

fn asking(data_dir: PathBuf, listen: SocketAddr, tls: TlsMode) -> Config {
    Config {
        data_dir,
        listen,
        tls,
        ..Config::default()
    }
}

#[tokio::test]
async fn a_server_with_its_own_key_is_healthy() {
    let dir = scratch();
    let listen = serve_tls(&dir).await;
    health::check(&asking(dir.clone(), listen, TlsMode::Auto))
        .await
        .expect("healthy");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_server_answering_with_another_key_is_not() {
    // The server runs with one key; the data directory the check reads holds
    // another. That is a restored volume without its `tls/`, and every device
    // that pinned the old key would be locked out.
    let serving = scratch();
    let listen = serve_tls(&serving).await;
    let other = scratch();
    tls::load(&other, &["localhost".into()], true).unwrap();

    let error = health::check(&asking(other.clone(), listen, TlsMode::Auto))
        .await
        .expect_err("not this server's key");
    assert!(error.contains("/healthz"), "{error}");

    std::fs::remove_dir_all(&serving).unwrap();
    std::fs::remove_dir_all(&other).unwrap();
}

#[tokio::test]
async fn before_the_first_start_there_is_nothing_to_ask() {
    let dir = scratch();
    let error = health::check(&asking(
        dir.clone(),
        "127.0.0.1:9".parse().unwrap(),
        TlsMode::Auto,
    ))
    .await
    .expect_err("no key yet");
    assert!(error.contains("no certificate key"), "{error}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn behind_a_proxy_it_asks_over_plain_http() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
    let app = api::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    health::check(&asking(scratch(), listen, TlsMode::Off))
        .await
        .expect("healthy over http");
    // And a server that is not there is not healthy.
    let gone = "127.0.0.1:9".parse().unwrap();
    assert!(health::check(&asking(scratch(), gone, TlsMode::Off))
        .await
        .is_err());
}
