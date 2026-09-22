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
use uwussh_store::{AuthMethod, HostDraft, PasswordChange, SecretText, Store};
use uwussh_sync::{from_wire, sync_once, to_wire, Server};
use uwussh_vault::{AccountKey, KdfParams};
use uwusync_server::config::Registration;
use uwusync_server::db::accounts::KdfFloor;
use uwusync_server::db::Db;
use uwusync_server::{api, b64, random_bytes, AppState, Config};

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
    start_with(Registration::Open)
}

fn start_with(registration: Registration) -> Running {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ready, started) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        runtime.block_on(async move {
            let config = Config {
                registration,
                // The cheap parameters above are below what the server takes
                // from a real client.
                kdf_floor: KdfFloor {
                    memory_kib: KDF.memory_kib,
                    time_cost: KDF.time_cost,
                },
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

    // Side a signs in as the device that opened it; side b holds its side
    // with a secret it made up.
    let claim = Some("the joining device's own secret");
    server
        .pair_send(&session.id, "a", None, b"spake from a")
        .unwrap();
    assert!(
        server
            .pair_receive(&session.id, "a", None, 0, false)
            .unwrap()
            .is_empty(),
        "a device does not hear itself"
    );
    assert_eq!(
        joining
            .pair_receive(&session.id, "b", claim, 0, false)
            .unwrap(),
        vec![b"spake from a".to_vec()]
    );

    joining
        .pair_send(&session.id, "b", claim, b"spake from b")
        .unwrap();
    server
        .pair_send(&session.id, "a", None, b"the sealed account key")
        .unwrap();
    assert_eq!(
        joining
            .pair_receive(&session.id, "b", claim, 1, false)
            .unwrap(),
        vec![b"the sealed account key".to_vec()],
        "and only what it has not seen yet"
    );

    // Somebody else who learned the id speaks for neither side.
    let stranger = Server::connect(&running.url, None).unwrap();
    assert!(stranger
        .pair_send(&session.id, "a", None, b"me too")
        .is_err());
    assert!(stranger
        .pair_receive(&session.id, "b", Some("a guess"), 0, false)
        .is_err());

    server.close_pairing(&session.id).unwrap();
    assert!(joining
        .pair_receive(&session.id, "b", claim, 0, false)
        .is_err());
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

// ── The whole thing, as a person does it ────────────────────────────────────

/// Sealing for this device, as the operating system would. A test has no
/// DPAPI, and what matters here is that the same bytes come back.
fn protect(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(bytes.iter().map(|byte| byte ^ 0x5a).collect())
}

fn unprotect(bytes: &[u8]) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    Ok(zeroize::Zeroizing::new(
        bytes.iter().map(|byte| byte ^ 0x5a).collect(),
    ))
}

/// The setup code the server prints, built the way `uwusync-server invite`
/// builds it.
fn setup_code(running: &Running) -> uwussh_sync::Setup {
    let invite = {
        let conn = running.state.db.lock();
        uwusync_server::db::invites::create_invite(&conn, 60_000).unwrap()
    };
    let body = serde_json::json!({ "u": running.url, "i": invite }).to_string();
    let code = format!("uwu1_{}", b64::encode(body));
    uwussh_sync::parse_setup(&code).expect("the server's own code")
}

#[test]
fn a_second_device_joins_by_reading_out_three_words() {
    let running = start_with(Registration::Invite);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);

    // ── The first device: a setup code, a master password, and that is all ──
    let first = std::sync::Arc::new(Store::open_in_memory().unwrap());
    // It already has a host, from before there was ever a server.
    first.create_vault_with(PASSWORD, KDF).unwrap();
    let mut prox = host("prox-1", "10.0.0.12");
    prox.password = PasswordChange::Set {
        value: SecretText::new("hunter2"),
    };
    let saved = first.save_host(prox).unwrap();

    let setup = setup_code(&running);
    let (server, paired) =
        uwussh_sync::create_account(&first, &setup, PASSWORD, "LVDesk1", protect).unwrap();
    let kit = paired.recovery.expect("the recovery kit, shown once");
    assert_eq!(
        first.reveal_host_password(saved.id).unwrap().as_slice(),
        b"hunter2",
        "turning sync on wrapped one key again and re-encrypted nothing"
    );
    assert!(
        first.vault_needs_account_key().unwrap(),
        "and the vault now wants the kit as well"
    );
    sync_once(&first, &server).unwrap();

    // ── The code, as it goes on screen ─────────────────────────────────────
    let offer = uwussh_sync::flow::offer_pairing(&first, &server).unwrap();
    let spoken = offer.offer.spoken.clone();
    let (id, words) = uwussh_sync::pairing::parse_spoken(&spoken).expect("a code to read out");
    // The joining device is told the address and the fingerprint by the
    // pasteable form; typing the spoken code needs the address as well, which
    // is what the interface asks for.
    let pasted = uwussh_sync::pairing::parse_offer(&offer.offer.pasteable).unwrap();
    assert_eq!(pasted.id, id);
    assert_eq!(pasted.words, words);

    // ── The second device: the code and the master password ────────────────
    let second = std::sync::Arc::new(Store::open_in_memory().unwrap());
    let joining = {
        let second = second.clone();
        let target = pasted.clone();
        std::thread::spawn(move || {
            uwussh_sync::join(&second, &target, PASSWORD, "LVLaptop", protect, deadline)
        })
    };

    let joined =
        uwussh_sync::flow::wait_for_device(&first, &server, &offer, unprotect, deadline).unwrap();
    assert_eq!(joined.device_name, "LVLaptop");

    let (other, paired) = joining.join().unwrap().unwrap();
    assert!(
        paired.recovery.is_none(),
        "only the device that made the key shows a kit"
    );
    assert_eq!(
        Some(paired.account_id),
        first.sync_state().unwrap().account_id,
        "both devices are in the same account"
    );

    // It has the vault, and the vault wants the kit — which it has, because
    // the handshake carried it.
    assert!(second.vault_needs_account_key().unwrap());
    sync_once(&second, &other).unwrap();
    let hosts = second.list_hosts().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].address, "10.0.0.12");
    assert_eq!(
        second.reveal_host_password(saved.id).unwrap().as_slice(),
        b"hunter2",
        "and the password opens on a device that was only ever told three words"
    );

    // Locked and opened again with what this device keeps: no kit typed.
    second.lock_vault();
    let key = uwussh_sync::flow::account_key(&second, unprotect)
        .unwrap()
        .expect("the account key this device kept");
    second.unlock_vault_with(PASSWORD, Some(&key)).unwrap();
    assert_eq!(
        second.reveal_host_password(saved.id).unwrap().as_slice(),
        b"hunter2"
    );
    // And the kit from the other device is the same key.
    assert_eq!(key.to_code(), kit.to_code());

    // Signing in again from scratch, the way tomorrow's first pass does.
    let returning = uwussh_sync::reconnect(&second, unprotect).unwrap();
    assert_eq!(sync_once(&second, &returning).unwrap().apply.rejected, 0);

    // The account has two devices, and each can see them.
    assert_eq!(server.devices().unwrap().len(), 2);
    assert_eq!(other.devices().unwrap().len(), 2);
}

#[test]
fn a_device_that_heard_the_wrong_words_gets_nothing() {
    let running = start_with(Registration::Invite);
    // Short: the handshake fails on the first answer, and the other side is
    // only waiting for something that will never come.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let first = std::sync::Arc::new(Store::open_in_memory().unwrap());
    let setup = setup_code(&running);
    let (server, _) =
        uwussh_sync::create_account(&first, &setup, PASSWORD, "LVDesk1", protect).unwrap();

    let offer = uwussh_sync::flow::offer_pairing(&first, &server).unwrap();
    let mut wrong = uwussh_sync::pairing::parse_offer(&offer.offer.pasteable).unwrap();
    wrong.words = "tiger-tiger-tiger".into();

    let second = std::sync::Arc::new(Store::open_in_memory().unwrap());
    let joining = {
        let second = second.clone();
        std::thread::spawn(move || {
            uwussh_sync::join(&second, &wrong, PASSWORD, "LVLaptop", protect, deadline)
        })
    };
    assert!(
        uwussh_sync::flow::wait_for_device(&first, &server, &offer, unprotect, deadline).is_err(),
        "the handover must not happen"
    );
    assert!(joining.join().unwrap().is_err());

    // The account still has one device, and the other store is untouched.
    assert_eq!(server.devices().unwrap().len(), 1);
    assert!(second.vault_header().unwrap().is_none());
}
