//! The real client against the real server.
//!
//! Every other test here speaks the protocol by hand, which proves the server
//! does what it says — but not that the client agrees. This one runs the
//! actual crates from the client repository: its store, its vault, its sync
//! engine, its transport. What is checked is the one thing neither side can
//! check alone: that a host saved on one device, with a password in the vault,
//! turns up on a second device that joined the account — and that the server
//! carried it without being able to read any of it.
//!
//! The server runs on a runtime of its own thread, and the client work happens
//! on this one, blocking. That is how the app will run it too: sync belongs on
//! its own thread, not in the runtime that drives a terminal.

use std::net::SocketAddr;
use std::sync::mpsc;
use uwussh_proto::api::{CreateAccount, EnrolDevice, NewDevice};
use uwussh_server::config::Registration;
use uwussh_server::db::Db;
use uwussh_server::{api, b64, random_bytes, AppState, Config};
use uwussh_store::{AuthMethod, HostDraft, PasswordChange, SecretText, Store};
use uwussh_sync::{from_wire, sync_once, to_wire, Server};
use uwussh_vault::{AccountKey, KdfParams};

const PASSWORD: &[u8] = b"correct horse battery staple";
/// The cheap parameters, because these tests run on every commit and the real
/// ones take 64 MiB a call.
const KDF: KdfParams = KdfParams::INSECURE_FOR_TESTS;

/// A server on a port of its own, on a runtime of its own thread.
struct Running {
    url: String,
    state: AppState,
}

fn start() -> Running {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ready, started) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        runtime.block_on(async move {
            let config = Config {
                registration: Registration::Open,
                ..Config::default()
            };
            let state = AppState::new(Db::open_in_memory().expect("a database"), config);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a port");
            let address = listener.local_addr().expect("an address");
            ready
                .send((address, state.clone()))
                .expect("the test is there");
            axum::serve(
                listener,
                api::router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serving");
        });
    });
    let (address, state) = started.recv().expect("the server starts");
    Running {
        // Plain HTTP, which the client allows for localhost and nothing else.
        url: format!("http://{address}"),
        state,
    }
}

/// A device's signing key: the seed, and the public half the server enrols.
///
/// The seed is made here and handed to the client, which signs with its own
/// version of ed25519 — so this also shows the two versions in the two
/// repositories producing signatures the other accepts.
fn device_key() -> ([u8; 32], String) {
    let seed = random_bytes::<32>();
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    (seed, b64::encode(public))
}

fn host(name: &str, address: &str) -> HostDraft {
    HostDraft {
        id: None,
        name: name.into(),
        address: address.into(),
        port: 22,
        username: "uwu".into(),
        auth: AuthMethod::Password,
        key_path: None,
        group_path: None,
        workspace: None,
        key_id: None,
        password: PasswordChange::Keep,
    }
}

fn names(store: &Store) -> Vec<String> {
    let mut names: Vec<String> = store
        .list_hosts()
        .unwrap()
        .into_iter()
        .map(|host| host.name)
        .collect();
    names.sort();
    names
}

#[test]
fn a_host_saved_on_one_device_turns_up_on_the_one_that_joined() {
    let running = start();
    let account_key = AccountKey::generate();

    // ── The first device ───────────────────────────────────────────────────
    let first = Store::open_in_memory().unwrap();
    first
        .create_synced_vault(PASSWORD, &account_key, KDF)
        .unwrap();
    let header = first.vault_header().unwrap().unwrap();
    let login_key = header.login_key(PASSWORD, Some(&account_key)).unwrap();

    let mut prox = host("prox-1", "10.0.0.12");
    prox.group_path = Some("Homelab".into());
    prox.password = PasswordChange::Set {
        value: SecretText::new("hunter2"),
    };
    let saved = first.save_host(prox).unwrap();

    let (seed, public_key) = device_key();
    let server = Server::connect(&running.url, None).unwrap();
    let admitted = server
        .create_account(&CreateAccount {
            invite: String::new(),
            vault: to_wire(&header),
            auth_key: b64::encode(*login_key),
            device: NewDevice {
                name: "LVDesk1".into(),
                public_key,
            },
        })
        .unwrap();
    let server = server.as_device(admitted.account_id, admitted.device_id, &seed);

    let up = sync_once(&first, &server).unwrap();
    assert!(up.pushed >= 4, "host, login, group and password: {up:?}");
    assert_eq!(up.apply.rejected, 0);

    // What the server holds: ciphertext, and nothing that reads as a hostname.
    let held = running.state.db.lock();
    let blobs: Vec<Vec<u8>> = held
        .prepare("SELECT blob FROM records")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    drop(held);
    assert!(blobs.len() >= 4);
    for blob in &blobs {
        let text = String::from_utf8_lossy(blob).to_string();
        for secret in ["prox-1", "10.0.0.12", "hunter2", "Homelab"] {
            assert!(!text.contains(secret), "{secret} must not be readable");
        }
    }

    // ── The second device joins ────────────────────────────────────────────
    let enrolment = server.enrolment_token().unwrap();

    let second = Store::open_in_memory().unwrap();
    let joining = Server::connect(&running.url, None).unwrap();
    // Before it can prove anything, it needs the salt and the costs — and is
    // told that the account key is wanted as well.
    let params = joining.vault_params(&enrolment.token).unwrap();
    assert_eq!(params.vault_id, header.vault_id);
    assert!(
        params.needs_account_key,
        "so a missing kit is not blamed on the password"
    );

    let (seed, public_key) = device_key();
    let admitted = joining
        .enrol(&EnrolDevice {
            enrolment: enrolment.token.clone(),
            auth_key: b64::encode(*login_key),
            device: NewDevice {
                name: "LVLaptop".into(),
                public_key,
            },
        })
        .unwrap();
    let joining = joining.as_device(admitted.account_id, admitted.device_id, &seed);

    // Now it may have the wrapped key, and opens it with the password and the
    // account key the pairing would have carried.
    let downloaded = from_wire(&joining.vault().unwrap()).unwrap();
    assert_eq!(downloaded, header, "the header came back as it was written");
    let key = downloaded
        .unlock_with(PASSWORD, Some(&account_key))
        .unwrap()
        .export_key();
    second.adopt_vault(&downloaded, key).unwrap();

    let down = sync_once(&second, &joining).unwrap();
    assert_eq!(down.apply.rejected, 0, "{down:?}");
    let hosts = second.list_hosts().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].id, saved.id);
    assert_eq!(hosts[0].address, "10.0.0.12");
    assert_eq!(hosts[0].group_path.as_deref(), Some("Homelab"));
    assert_eq!(
        second.reveal_host_password(saved.id).unwrap().as_slice(),
        b"hunter2",
        "the password opens on the device that joined"
    );

    // ── And back the other way ─────────────────────────────────────────────
    second.save_host(host("nas", "10.0.0.9")).unwrap();
    sync_once(&second, &joining).unwrap();
    sync_once(&first, &server).unwrap();
    assert_eq!(names(&first), vec!["nas", "prox-1"]);
    assert_eq!(names(&second), vec!["nas", "prox-1"]);

    // A device that has signed in can do it again with its key alone, which
    // is what every pass after the first hour does.
    assert!(server.sign_in().is_ok());
    assert_eq!(sync_once(&first, &server).unwrap().apply.rejected, 0);
}

#[test]
fn the_relay_carries_what_the_two_devices_say_to_each_other() {
    let running = start();
    let account_key = AccountKey::generate();
    let first = Store::open_in_memory().unwrap();
    first
        .create_synced_vault(PASSWORD, &account_key, KDF)
        .unwrap();
    let header = first.vault_header().unwrap().unwrap();
    let login_key = header.login_key(PASSWORD, Some(&account_key)).unwrap();

    let (seed, public_key) = device_key();
    let server = Server::connect(&running.url, None).unwrap();
    let admitted = server
        .create_account(&CreateAccount {
            invite: String::new(),
            vault: to_wire(&header),
            auth_key: b64::encode(*login_key),
            device: NewDevice {
                name: "LVDesk1".into(),
                public_key,
            },
        })
        .unwrap();
    let server = server.as_device(admitted.account_id, admitted.device_id, &seed);

    // The device that is in opens a session; the joining one needs no account.
    let session = server.open_pairing().unwrap();
    assert_eq!(session.id.len(), 5, "a code somebody reads out loud");
    let joining = Server::connect(&running.url, None).unwrap();

    server.pair_send(&session.id, "a", b"spake from a").unwrap();
    assert!(
        server
            .pair_receive(&session.id, "a", 0, false)
            .unwrap()
            .is_empty(),
        "a device does not hear itself"
    );
    assert_eq!(
        joining.pair_receive(&session.id, "b", 0, false).unwrap(),
        vec![b"spake from a".to_vec()]
    );

    joining
        .pair_send(&session.id, "b", b"spake from b")
        .unwrap();
    server
        .pair_send(&session.id, "a", b"the sealed account key")
        .unwrap();
    assert_eq!(
        joining.pair_receive(&session.id, "b", 1, false).unwrap(),
        vec![b"the sealed account key".to_vec()],
        "and only what it has not seen yet"
    );

    server.close_pairing(&session.id).unwrap();
    assert!(joining.pair_receive(&session.id, "b", 0, false).is_err());
}

#[test]
fn a_client_pointed_at_the_wrong_thing_says_so_rather_than_trying() {
    // Plain HTTP to anywhere but this machine is refused before a socket is
    // opened, because what travels here is a login key.
    assert!(Server::connect("http://nas.lan:8443", None).is_err());
    assert!(Server::connect("https://nas.lan:8443", None).is_ok());

    // And a device with no token does not send a request it knows will fail.
    let running = start();
    let stranger = Server::connect(&running.url, None).unwrap();
    assert!(stranger.devices().is_err());
}
