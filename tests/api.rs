//! The server over real HTTP, driven the way a device drives it.
//!
//! Each test starts a server on a port of its own with a database in memory,
//! then speaks the actual protocol: create an account, sign a challenge, push,
//! pull, join a second device, revoke one. What is checked is both halves of
//! the job — that a device which does everything right gets its records
//! across, and that one which does not gets nowhere.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;
use uwussh_proto::{EntityKind, Envelope, Hlc, PullResponse, PushResponse, SCHEMA_VERSION};
use uwusync_server::api;
use uwusync_server::config::Registration;
use uwusync_server::db::Db;
use uwusync_server::{AppState, Config};

/// A server on a port of its own, with nothing on disk.
struct Server {
    base: String,
    state: AppState,
    client: reqwest::Client,
}

async fn start(registration: Registration) -> Server {
    start_with(Config {
        registration,
        ..Config::default()
    })
    .await
}

async fn start_with(config: Config) -> Server {
    // The client crate brings in a rustls that expects its provider to be
    // chosen, and cargo unifies features across the test binary. Choosing it
    // here is what the server itself does when it serves.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let state = AppState::new(Db::open_in_memory().unwrap(), config);
    let app = api::router(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    Server {
        base: format!("http://{address}"),
        state,
        client: reqwest::Client::new(),
    }
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn invite(&self) -> String {
        let conn = self.state.db.lock();
        uwusync_server::db::invites::create_invite(&conn, 60_000).unwrap()
    }

    /// The vault header a device uploads. Its contents are opaque here — the
    /// server never opens it, which is the point.
    fn vault(vault_id: Uuid) -> serde_json::Value {
        json!({
            "vaultId": vault_id,
            "kdfMemoryKib": 65536,
            "kdfTimeCost": 3,
            "kdfParallelism": 4,
            "salt": "c2FsdHktc2FsdHktc2FsdA",
            "wrappedNonce": "bm9uY2Utbm9uY2Utbm9uY2U",
            "wrappedBlob": "d3JhcHBlZC12YXVsdC1rZXk",
        })
    }
}

/// A device: its key, its ids, and its token.
struct Device {
    signing: SigningKey,
    account: Uuid,
    id: Uuid,
    token: String,
    vault_id: Uuid,
}

/// The login key a device derives from the master password and the account
/// key. Here it is just the password's stand-in — the server only ever sees
/// these 32 bytes and stores their hash.
fn login_key(password: &str) -> String {
    let mut key = [0u8; 32];
    for (slot, byte) in key.iter_mut().zip(password.bytes().cycle()) {
        *slot = byte;
    }
    uwusync_server::b64::encode(key)
}

impl Device {
    fn new_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    async fn create_account(server: &Server, invite: &str, password: &str, seed: u8) -> Device {
        let signing = Self::new_key(seed);
        let vault_id = Uuid::now_v7();
        let response = server
            .client
            .post(server.url("/v1/accounts"))
            .json(&json!({
                "invite": invite,
                "vault": Server::vault(vault_id),
                "authKey": login_key(password),
                "device": {
                    "name": "LVDesk1",
                    "publicKey": uwusync_server::b64::encode(signing.verifying_key().to_bytes()),
                },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{:?}", response.text().await);
        let body: serde_json::Value = response.json().await.unwrap();
        Device {
            signing,
            account: body["accountId"].as_str().unwrap().parse().unwrap(),
            id: body["deviceId"].as_str().unwrap().parse().unwrap(),
            token: body["token"].as_str().unwrap().to_string(),
            vault_id,
        }
    }

    /// Sign in again with the device key: challenge, signature, token.
    async fn login(&mut self, server: &Server) -> reqwest::StatusCode {
        let challenge: serde_json::Value = server
            .client
            .post(server.url("/v1/session/challenge"))
            .json(&json!({ "deviceId": self.id }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let challenge =
            uwusync_server::b64::decode(challenge["challenge"].as_str().unwrap()).unwrap();
        let material = uwusync_server::auth::session_material(self.account, self.id, &challenge);
        let signature = self.signing.sign(&material).to_bytes();

        let response = server
            .client
            .post(server.url("/v1/session"))
            .json(&json!({
                "deviceId": self.id,
                "signature": uwusync_server::b64::encode(signature),
            }))
            .send()
            .await
            .unwrap();
        let status = response.status();
        if status == 200 {
            let body: serde_json::Value = response.json().await.unwrap();
            self.token = body["token"].as_str().unwrap().to_string();
        }
        status
    }

    fn envelope(&self, id: Uuid, base_seq: u64, blob: &[u8]) -> Envelope {
        Envelope {
            id,
            vault_id: self.vault_id,
            kind: EntityKind::Host,
            updated_at: Hlc::new(1_700_000_000_000, 0, 1),
            base_seq,
            deleted: false,
            nonce: vec![7; 24],
            blob: blob.to_vec(),
            seq: None,
        }
    }

    async fn push(&self, server: &Server, envelopes: &[Envelope]) -> PushResponse {
        let response = server
            .client
            .post(server.url("/v1/records"))
            .bearer_auth(&self.token)
            .json(&json!({ "schema": SCHEMA_VERSION, "envelopes": envelopes }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{:?}", response.text().await);
        response.json().await.unwrap()
    }

    async fn pull(&self, server: &Server, since: u64) -> PullResponse {
        let response = server
            .client
            .get(server.url(&format!("/v1/records?since={since}")))
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{:?}", response.text().await);
        response.json().await.unwrap()
    }
}

#[tokio::test]
async fn a_device_creates_an_account_and_gets_its_records_across() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let device = Device::create_account(&server, &invite, "master", 1).await;

    let id = Uuid::now_v7();
    let pushed = device
        .push(&server, &[device.envelope(id, 0, b"sealed host")])
        .await;
    assert_eq!(pushed.accepted.len(), 1);
    assert_eq!(pushed.accepted[0].seq, 1);

    let page = device.pull(&server, 0).await;
    assert_eq!(page.envelopes.len(), 1);
    assert_eq!(page.envelopes[0].id, id);
    assert_eq!(page.envelopes[0].blob, b"sealed host".to_vec());
    assert!(!page.has_more);

    // And the device can sign in again tomorrow with the key it enrolled.
    let mut device = device;
    assert_eq!(device.login(&server).await, 200);
    assert_eq!(device.pull(&server, 0).await.envelopes.len(), 1);
}

#[tokio::test]
async fn a_second_device_joins_with_a_token_and_the_master_password() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let first = Device::create_account(&server, &invite, "master", 1).await;
    let id = Uuid::now_v7();
    first
        .push(&server, &[first.envelope(id, 0, b"from the first")])
        .await;

    // The device that is already in makes a one-time token. In the real flow
    // it travels to the other device through the pairing channel.
    let enrolment: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/invite"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = enrolment["token"].as_str().unwrap().to_string();

    // Before it can prove anything, the joining device needs the salt and the
    // costs — and gets nothing it could attack offline.
    let params: serde_json::Value = server
        .client
        .post(server.url("/v1/vault/params"))
        .json(&json!({ "enrolment": token }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(params["salt"], "c2FsdHktc2FsdHktc2FsdA");
    assert!(params.get("wrappedBlob").is_none(), "{params}");

    let second_key = Device::new_key(2);
    let second_public = uwusync_server::b64::encode(second_key.verifying_key().to_bytes());
    let join = |password: &'static str| {
        let body = json!({
            "enrolment": token,
            "authKey": login_key(password),
            "device": { "name": "LVLaptop", "publicKey": second_public },
        });
        server
            .client
            .post(server.url("/v1/devices/enrol"))
            .json(&body)
            .send()
    };

    // The wrong master password gets nowhere — and does not burn the token.
    assert_eq!(join("wrong").await.unwrap().status(), 401);

    let response = join("master").await.unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let second = Device {
        signing: second_key,
        account: body["accountId"].as_str().unwrap().parse().unwrap(),
        id: body["deviceId"].as_str().unwrap().parse().unwrap(),
        token: body["token"].as_str().unwrap().to_string(),
        vault_id: first.vault_id,
    };
    assert_eq!(second.account, first.account);

    // Now it may have the wrapped key, and everything the first device wrote.
    let header: serde_json::Value = server
        .client
        .get(server.url("/v1/vault"))
        .bearer_auth(&second.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(header["wrappedBlob"], "d3JhcHBlZC12YXVsdC1rZXk");

    let page = second.pull(&server, 0).await;
    assert_eq!(page.envelopes.len(), 1);
    assert_eq!(page.envelopes[0].blob, b"from the first".to_vec());

    // The token was spent: nobody joins twice with it.
    assert_eq!(join("master").await.unwrap().status(), 401);

    // And both devices show up in the list.
    let devices: serde_json::Value = server
        .client
        .get(server.url("/v1/devices"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn two_devices_editing_one_record_meet_the_version_check() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let first = Device::create_account(&server, &invite, "master", 1).await;

    let id = Uuid::now_v7();
    first.push(&server, &[first.envelope(id, 0, b"one")]).await;
    first.push(&server, &[first.envelope(id, 1, b"two")]).await;

    // A device still believing version 1 is current is refused, and told what
    // the server holds instead.
    let response = first
        .push(&server, &[first.envelope(id, 1, b"three")])
        .await;
    assert!(response.accepted.is_empty());
    assert_eq!(response.conflicts.len(), 1);
    assert_eq!(response.conflicts[0].blob, b"two".to_vec());
    assert_eq!(response.conflicts[0].seq, Some(2));

    // Based on that, it goes through.
    let response = first
        .push(&server, &[first.envelope(id, 2, b"three")])
        .await;
    assert_eq!(response.accepted.len(), 1);
}

#[tokio::test]
async fn nothing_reaches_anyone_who_did_not_sign() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let device = Device::create_account(&server, &invite, "master", 1).await;

    for token in ["", "not-a-token", &format!("{}x", device.token)] {
        let response = server
            .client
            .get(server.url("/v1/records"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "with token {token:?}");
    }
    let response = server
        .client
        .get(server.url("/v1/records"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401, "and with no token at all");

    // A signature by the wrong key is no signature.
    let mut impostor = Device {
        signing: Device::new_key(9),
        account: device.account,
        id: device.id,
        token: String::new(),
        vault_id: device.vault_id,
    };
    assert_eq!(impostor.login(&server).await, 401);

    // Nor is one for a challenge that was already answered.
    let challenge: serde_json::Value = server
        .client
        .post(server.url("/v1/session/challenge"))
        .json(&json!({ "deviceId": device.id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let raw = uwusync_server::b64::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let material = uwusync_server::auth::session_material(device.account, device.id, &raw);
    let signature = uwusync_server::b64::encode(device.signing.sign(&material).to_bytes());
    let replay = json!({ "deviceId": device.id, "signature": signature });

    let first = server
        .client
        .post(server.url("/v1/session"))
        .json(&replay)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let again = server
        .client
        .post(server.url("/v1/session"))
        .json(&replay)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 401, "a challenge is answered once");
}

#[tokio::test]
async fn a_revoked_device_is_out_at_once() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let first = Device::create_account(&server, &invite, "master", 1).await;

    // A second device, so the first is not the last one standing.
    let enrolment: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/invite"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second_key = Device::new_key(2);
    let body: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/enrol"))
        .json(&json!({
            "enrolment": enrolment["token"],
            "authKey": login_key("master"),
            "device": {
                "name": "LVLaptop",
                "publicKey": uwusync_server::b64::encode(second_key.verifying_key().to_bytes()),
            },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut second = Device {
        signing: second_key,
        account: first.account,
        id: body["deviceId"].as_str().unwrap().parse().unwrap(),
        token: body["token"].as_str().unwrap().to_string(),
        vault_id: first.vault_id,
    };
    assert_eq!(second.pull(&server, 0).await.envelopes.len(), 0);

    assert_eq!(
        revoke(&server, &first, second.id, Some("master")).await,
        204
    );

    // The token it was holding is worthless from this moment.
    let response = server
        .client
        .get(server.url("/v1/records"))
        .bearer_auth(&second.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    // And it cannot sign in again either.
    assert_eq!(second.login(&server).await, 401);

    // The last device standing cannot shut itself out: nobody would be left.
    assert_eq!(revoke(&server, &first, first.id, None).await, 400);
}

/// Revoke `target`, signed in as `by`, with the master password or without.
async fn revoke(
    server: &Server,
    by: &Device,
    target: Uuid,
    password: Option<&str>,
) -> reqwest::StatusCode {
    let body = match password {
        Some(password) => json!({ "currentAuthKey": login_key(password) }),
        None => json!({}),
    };
    server
        .client
        .post(server.url(&format!("/v1/devices/{target}/revoke")))
        .bearer_auth(&by.token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
}

/// An enrolment token made by `by`.
async fn enrolment_token(server: &Server, by: &Device) -> String {
    let enrolment: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/invite"))
        .bearer_auth(&by.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    enrolment["token"].as_str().unwrap().to_string()
}

/// Join `first`'s account as a device with key `seed`.
async fn join(server: &Server, token: &str, password: &str, seed: u8) -> reqwest::Response {
    let key = Device::new_key(seed);
    server
        .client
        .post(server.url("/v1/devices/enrol"))
        .json(&json!({
            "enrolment": token,
            "authKey": login_key(password),
            "device": {
                "name": format!("device {seed}"),
                "publicKey": uwusync_server::b64::encode(key.verifying_key().to_bytes()),
            },
        }))
        .send()
        .await
        .unwrap()
}

async fn second_device(server: &Server, first: &Device, seed: u8) -> Device {
    let token = enrolment_token(server, first).await;
    let response = join(server, &token, "master", seed).await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    Device {
        signing: Device::new_key(seed),
        account: first.account,
        id: body["deviceId"].as_str().unwrap().parse().unwrap(),
        token: body["token"].as_str().unwrap().to_string(),
        vault_id: first.vault_id,
    }
}

#[tokio::test]
async fn shutting_another_device_out_takes_the_master_password() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let second = second_device(&server, &first, 2).await;
    let third = second_device(&server, &first, 3).await;

    // A stolen laptop has its token, and that is all it has.
    assert_eq!(revoke(&server, &second, first.id, None).await, 403);
    assert_eq!(
        revoke(&server, &second, first.id, Some("a guess")).await,
        403
    );
    assert_eq!(
        first.pull(&server, 0).await.envelopes.len(),
        0,
        "and the owner's device is still in"
    );
    // Guessing on is slowed down for that laptop alone: it cannot use up the
    // tries of the owner's devices, and so cannot keep itself from being
    // revoked.
    let mut slowed = false;
    for _ in 0..12 {
        if revoke(&server, &second, first.id, Some("another guess")).await == 429 {
            slowed = true;
            break;
        }
    }
    assert!(slowed, "ten wrong proofs an hour from one device");

    // The owner, with the password, can shut the laptop out.
    assert_eq!(
        revoke(&server, &first, second.id, Some("master")).await,
        204
    );
    // And a device may always take itself out.
    assert_eq!(revoke(&server, &third, third.id, None).await, 204);
}

#[tokio::test]
async fn a_revoked_device_takes_its_tokens_and_pairings_along() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let second = second_device(&server, &first, 2).await;

    // Before it is shut out, it makes a token and opens a pairing.
    let token = enrolment_token(&server, &second).await;
    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&second.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pairing = opened["id"].as_str().unwrap().to_string();

    assert_eq!(
        revoke(&server, &first, second.id, Some("master")).await,
        204
    );

    assert_eq!(
        join(&server, &token, "master", 9).await.status(),
        401,
        "its token died with it"
    );
    let gone = server
        .client
        .get(server.url(&format!("/v1/pair/{pairing}?side=b")))
        .header("x-uwussh-pair-claim", "somebody")
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status(), 404, "and so did its pairing");
}

#[tokio::test]
async fn an_enrolment_token_is_no_licence_to_guess_the_password() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let token = enrolment_token(&server, &first).await;
    // A typo or two is fine...
    assert_eq!(join(&server, &token, "mastr", 2).await.status(), 401);
    // ...but five wrong passwords use the token up, the right one included.
    for _ in 0..4 {
        assert_eq!(join(&server, &token, "guess", 2).await.status(), 401);
    }
    assert_eq!(join(&server, &token, "master", 2).await.status(), 401);
}

#[tokio::test]
async fn open_registration_counts_every_account_it_makes() {
    let server = start(Registration::Open).await;
    for seed in 0..5 {
        Device::create_account(&server, "", "master", seed).await;
    }
    let response = server
        .client
        .post(server.url("/v1/accounts"))
        .json(&json!({
            "invite": "",
            "vault": Server::vault(Uuid::now_v7()),
            "authKey": login_key("master"),
            "device": { "name": "x", "publicKey": uwusync_server::b64::encode([7u8; 32]) },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        429,
        "five an hour from one address, not more"
    );
}

#[tokio::test]
async fn a_full_server_takes_no_more_accounts_and_keeps_the_invite() {
    let server = start_with(Config {
        registration: Registration::Invite,
        max_accounts: 1,
        ..Config::default()
    })
    .await;
    let first = server.invite().await;
    Device::create_account(&server, &first, "master", 1).await;

    let second = server.invite().await;
    let response = server
        .client
        .post(server.url("/v1/accounts"))
        .json(&json!({
            "invite": second,
            "vault": Server::vault(Uuid::now_v7()),
            "authKey": login_key("master"),
            "device": { "name": "x", "publicKey": uwusync_server::b64::encode([8u8; 32]) },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "server-full");
    let open = uwusync_server::db::invites::count_open_invites(&server.state.db.lock()).unwrap();
    assert_eq!(open, 1, "the invite was not spent on a refusal");
}

#[tokio::test]
async fn a_push_of_several_mebibytes_gets_through() {
    // The records are the one endpoint that takes more than a few kilobytes,
    // and the limit it has is the one it says, not a framework's default.
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;
    let big = vec![3u8; uwussh_proto::MAX_BLOB_BYTES];
    let batch: Vec<Envelope> = (0..12)
        .map(|_| device.envelope(Uuid::now_v7(), 0, &big))
        .collect();
    let pushed = device.push(&server, &batch).await;
    assert_eq!(pushed.accepted.len(), 12);

    // Everything else stays small.
    let response = server
        .client
        .post(server.url("/v1/session/challenge"))
        .header("content-type", "application/json")
        .body(format!(
            "{{\"deviceId\":\"{}\",\"pad\":\"{}\"}}",
            device.id,
            "x".repeat(100 * 1024)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
}

#[tokio::test]
async fn a_request_over_its_limit_is_turned_away_before_its_body_is_read() {
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;
    for seed in 2..=5 {
        Device::create_account(&server, "", "master", seed).await;
    }
    // Five accounts this hour from this address. The sixth request is refused
    // for that, not for what its body says: the body is never read.
    let response = server
        .client
        .post(server.url("/v1/accounts"))
        .header("content-type", "application/json")
        .body("not even json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 429);

    // The same for pushes, whose bodies may be 16 MiB: a push that is one
    // too many is counted before it is read, whatever it holds.
    let mut statuses = Vec::new();
    for _ in 0..=uwusync_server::limits::PUSH.max {
        let response = server
            .client
            .post(server.url("/v1/records"))
            .bearer_auth(&device.token)
            .header("content-type", "application/json")
            .body("not even json")
            .send()
            .await
            .unwrap();
        statuses.push(response.status());
    }
    assert_eq!(statuses[0], 400, "read and refused for what it says");
    assert_eq!(statuses.last().copied().unwrap(), 429);
}

#[tokio::test]
async fn an_account_holds_what_the_server_allows_and_no_more() {
    let server = start_with(Config {
        registration: Registration::Open,
        quota: uwusync_server::db::records::Quota {
            records: 3,
            bytes: 1024 * 1024,
            ..Default::default()
        },
        ..Config::default()
    })
    .await;
    let device = Device::create_account(&server, "", "master", 1).await;
    let three: Vec<Envelope> = (0..3)
        .map(|_| device.envelope(Uuid::now_v7(), 0, b"a host"))
        .collect();
    device.push(&server, &three).await;

    let response = server
        .client
        .post(server.url("/v1/records"))
        .bearer_auth(&device.token)
        .json(&json!({
            "schema": SCHEMA_VERSION,
            "envelopes": [device.envelope(Uuid::now_v7(), 0, b"one more")],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    assert_eq!(device.pull(&server, 0).await.envelopes.len(), 3);
}

#[tokio::test]
async fn records_of_one_account_never_reach_another() {
    let server = start(Registration::Open).await;
    let mine = Device::create_account(&server, "", "master", 1).await;
    let theirs = Device::create_account(&server, "", "other", 2).await;
    theirs
        .push(&server, &[theirs.envelope(Uuid::now_v7(), 0, b"theirs")])
        .await;

    assert!(mine.pull(&server, 0).await.envelopes.is_empty());

    // Nor can one account's device push into the other's vault.
    let mut stranger = mine.envelope(Uuid::now_v7(), 0, b"mine");
    stranger.vault_id = theirs.vault_id;
    let response = server
        .client
        .post(server.url("/v1/records"))
        .bearer_auth(&mine.token)
        .json(&json!({ "schema": SCHEMA_VERSION, "envelopes": [stranger] }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    // And the device list is the account's own.
    let devices: serde_json::Value = server
        .client
        .get(server.url("/v1/devices"))
        .bearer_auth(&mine.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_invite_lets_exactly_one_account_in() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    Device::create_account(&server, &invite, "master", 1).await;

    for code in [invite.as_str(), "MADE-UPCO-DEXX", ""] {
        let response = server
            .client
            .post(server.url("/v1/accounts"))
            .json(&json!({
                "invite": code,
                "vault": Server::vault(Uuid::now_v7()),
                "authKey": login_key("master"),
                "device": { "name": "another", "publicKey": uwusync_server::b64::encode([3u8; 32]) },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "with {code:?}");
    }
}

#[tokio::test]
async fn a_closed_server_takes_no_new_accounts() {
    let server = start(Registration::Closed).await;
    // The same answer every time, and none of them counted: a closed server
    // has nothing to slow down, and nothing to fill its limiter with.
    for _ in 0..=uwusync_server::limits::ACCOUNTS.max {
        let response = server
            .client
            .post(server.url("/v1/accounts"))
            .json(&json!({
                "vault": Server::vault(Uuid::now_v7()),
                "authKey": login_key("master"),
                "device": { "name": "x", "publicKey": uwusync_server::b64::encode([4u8; 32]) },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
}

#[tokio::test]
async fn a_client_from_another_schema_is_turned_away_before_anything_is_stored() {
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;

    let response = server
        .client
        .post(server.url("/v1/records"))
        .bearer_auth(&device.token)
        .json(&json!({
            "schema": SCHEMA_VERSION + 1,
            "envelopes": [device.envelope(Uuid::now_v7(), 0, b"from the future")],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "schema");
    assert!(device.pull(&server, 0).await.envelopes.is_empty());
}

#[tokio::test]
async fn changing_the_master_password_takes_the_old_one() {
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;

    let change = |current: &'static str, next: &'static str, vault: Uuid| {
        server
            .client
            .put(server.url("/v1/vault/key"))
            .bearer_auth(&device.token)
            .json(&json!({
                "currentAuthKey": login_key(current),
                "vault": Server::vault(vault),
                "authKey": login_key(next),
            }))
            .send()
    };

    assert_eq!(
        change("not the password", "new", device.vault_id)
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        change("master", "new", Uuid::now_v7())
            .await
            .unwrap()
            .status(),
        400,
        "and it stays the same vault"
    );
    assert_eq!(
        change("master", "new", device.vault_id)
            .await
            .unwrap()
            .status(),
        204
    );

    // The new password is the one that counts now — which the next device to
    // join finds out.
    let enrolment: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/invite"))
        .bearer_auth(&device.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let join = |password: &'static str| {
        server
            .client
            .post(server.url("/v1/devices/enrol"))
            .json(&json!({
                "enrolment": enrolment["token"],
                "authKey": login_key(password),
                "device": { "name": "next", "publicKey": uwusync_server::b64::encode([5u8; 32]) },
            }))
            .send()
    };
    assert_eq!(join("master").await.unwrap().status(), 401);
    assert_eq!(join("new").await.unwrap().status(), 200);
}

#[tokio::test]
async fn a_vault_too_cheap_to_guess_against_is_not_taken() {
    let server = start(Registration::Open).await;
    let mut cheap = Server::vault(Uuid::now_v7());
    cheap["kdfMemoryKib"] = json!(1024);
    cheap["kdfTimeCost"] = json!(1);
    let response = server
        .client
        .post(server.url("/v1/accounts"))
        .json(&json!({
            "vault": cheap,
            "authKey": login_key("master"),
            "device": { "name": "x", "publicKey": uwusync_server::b64::encode([6u8; 32]) },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(
        response.text().await.unwrap().contains("too cheap"),
        "and says why"
    );
    assert_eq!(
        uwusync_server::db::accounts::count(&server.state.db.lock()).unwrap(),
        0
    );

    // Nor as a new password on an account that is fine.
    let device = Device::create_account(&server, "", "master", 1).await;
    let mut cheap = Server::vault(device.vault_id);
    cheap["kdfTimeCost"] = json!(1);
    let response = server
        .client
        .put(server.url("/v1/vault/key"))
        .bearer_auth(&device.token)
        .json(&json!({
            "currentAuthKey": login_key("master"),
            "vault": cheap,
            "authKey": login_key("new"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn a_device_hears_that_there_is_something_new() {
    let server = start(Registration::Open).await;
    let listener = Device::create_account(&server, "", "master", 1).await;

    let mut stream = server
        .client
        .get(server.url("/v1/events"))
        .bearer_auth(&listener.token)
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);

    // Wait until the stream is really subscribed, then push.
    for _ in 0..100 {
        if server.state.events.listeners(listener.account) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    listener
        .push(
            &server,
            &[listener.envelope(Uuid::now_v7(), 0, b"new host")],
        )
        .await;

    let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), stream.chunk())
        .await
        .expect("an event within five seconds")
        .unwrap()
        .expect("some bytes");
    let text = String::from_utf8_lossy(&chunk).to_string();
    assert!(text.contains("event: records"), "{text}");
    assert!(text.contains("data: 1"), "{text}");
}

#[tokio::test]
async fn the_health_check_says_nothing_about_the_accounts() {
    let server = start(Registration::Open).await;
    Device::create_account(&server, "", "master", 1).await;

    let body: serde_json::Value = server
        .client
        .get(server.url("/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["schema"], SCHEMA_VERSION);
    assert_eq!(body.as_object().unwrap().len(), 2, "{body}");
}

#[tokio::test]
async fn guessing_is_slowed_down() {
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;

    // The session bucket allows thirty tries a minute per address.
    let mut refused = false;
    for _ in 0..40 {
        let response = server
            .client
            .post(server.url("/v1/session"))
            .json(&json!({ "deviceId": device.id, "signature": uwusync_server::b64::encode([0u8; 64]) }))
            .send()
            .await
            .unwrap();
        if response.status() == 429 {
            refused = true;
            break;
        }
    }
    assert!(refused, "a guesser must run into a wall");
}

#[tokio::test]
async fn asking_for_made_up_devices_does_not_lock_out_the_real_ones() {
    let server = start(Registration::Open).await;
    let mut device = Device::create_account(&server, "", "master", 1).await;
    // From the very address the device signs in from, as every IPv6 client
    // does behind Docker's proxy: more challenges than a device may ask for
    // in a minute, each for a device that is not there.
    for _ in 0..=uwusync_server::limits::SESSION.max {
        let response = server
            .client
            .post(server.url("/v1/session/challenge"))
            .json(&json!({ "deviceId": Uuid::new_v4() }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
    assert_eq!(device.login(&server).await, 200);
}

#[tokio::test]
async fn a_device_cannot_be_kept_from_signing_in_from_elsewhere() {
    let server = start_with(Config {
        registration: Registration::Open,
        trust_forwarded: true,
        ..Config::default()
    })
    .await;
    let mut device = Device::create_account(&server, "", "master", 1).await;
    // Somebody who knows the device's id uses up every try it has — at the
    // address they ask from.
    let mut refused = false;
    for _ in 0..=uwusync_server::limits::SESSION.max {
        let response = server
            .client
            .post(server.url("/v1/session"))
            .header("x-forwarded-for", "192.0.2.66")
            .json(&json!({ "deviceId": device.id, "signature": uwusync_server::b64::encode([0u8; 64]) }))
            .send()
            .await
            .unwrap();
        if response.status() == 429 {
            refused = true;
        }
    }
    assert!(refused);
    assert_eq!(
        device.login(&server).await,
        200,
        "the device itself, from its own address"
    );
}

// ── Pairing ──────────────────────────────────────────────────────────────────
//
// The server carries messages between two devices and understands none of
// them. What is checked here is that it carries them to the right side, that
// it cannot be used for anything else, and that a session is over when it is
// over.

#[tokio::test]
async fn two_devices_hand_a_secret_through_the_relay() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;

    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = opened["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 5, "a code somebody reads out loud");

    // Side a is the device that opened it, signed in; side b has no account
    // yet and holds its side with a secret it made up.
    let speaking_as = |side: &str, request: reqwest::RequestBuilder| match side {
        "a" => request.bearer_auth(&first.token),
        _ => request.header("x-uwussh-pair-claim", "the joining device's secret"),
    };
    let post = |side: &'static str, message: &'static [u8]| {
        speaking_as(
            side,
            server
                .client
                .post(server.url(&format!("/v1/pair/{id}")))
                .json(&json!({ "side": side, "message": uwusync_server::b64::encode(message) })),
        )
        .send()
    };
    let read = |side: &'static str, after: usize| {
        speaking_as(
            side,
            server
                .client
                .get(server.url(&format!("/v1/pair/{id}?side={side}&after={after}"))),
        )
        .send()
    };

    // The handshake: one message each way, then the sealed payload.
    assert_eq!(post("a", b"spake from a").await.unwrap().status(), 204);

    let mine: serde_json::Value = read("a", 0).await.unwrap().json().await.unwrap();
    assert!(
        mine["messages"].as_array().unwrap().is_empty(),
        "a device does not read its own message back"
    );

    let theirs: serde_json::Value = read("b", 0).await.unwrap().json().await.unwrap();
    assert_eq!(
        theirs["messages"][0],
        uwusync_server::b64::encode(b"spake from a")
    );
    assert_eq!(theirs["next"], 1);

    assert_eq!(post("b", b"spake from b").await.unwrap().status(), 204);
    assert_eq!(
        post("a", b"sealed account key").await.unwrap().status(),
        204
    );

    let theirs: serde_json::Value = read("b", 1).await.unwrap().json().await.unwrap();
    assert_eq!(
        theirs["messages"][0],
        uwusync_server::b64::encode(b"sealed account key"),
        "and only what it has not seen yet"
    );

    // Somebody who only knows the id speaks for neither side.
    let as_a = server
        .client
        .post(server.url(&format!("/v1/pair/{id}")))
        .json(&json!({ "side": "a", "message": uwusync_server::b64::encode(b"me too") }))
        .send()
        .await
        .unwrap();
    assert_eq!(as_a.status(), 401, "side a without the opener's token");
    let as_b = server
        .client
        .get(server.url(&format!("/v1/pair/{id}?side=b&after=0")))
        .header("x-uwussh-pair-claim", "a different secret")
        .send()
        .await
        .unwrap();
    assert_eq!(as_b.status(), 401, "side b is taken");

    // Finished: the device that opened it says so.
    let closed = server
        .client
        .delete(server.url(&format!("/v1/pair/{id}")))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap();
    assert_eq!(closed.status(), 204);
    assert_eq!(read("b", 0).await.unwrap().status(), 404);
}

#[tokio::test]
async fn a_waiting_device_is_woken_when_the_other_speaks() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = opened["id"].as_str().unwrap().to_string();

    let waiting = server
        .client
        .get(server.url(&format!("/v1/pair/{id}?side=b&after=0&wait=true")))
        .header("x-uwussh-pair-claim", "waiting")
        .send();
    let speaking = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        server
            .client
            .post(server.url(&format!("/v1/pair/{id}")))
            .bearer_auth(&first.token)
            .json(&json!({ "side": "a", "message": uwusync_server::b64::encode(b"at last") }))
            .send()
            .await
            .unwrap()
    };

    let (answer, _) =
        tokio::time::timeout(std::time::Duration::from_secs(5), both(waiting, speaking))
            .await
            .expect("the wait ends when the message arrives");

    let body: serde_json::Value = answer.unwrap().json().await.unwrap();
    assert_eq!(body["messages"][0], uwusync_server::b64::encode(b"at last"));
}

/// `tokio::join!` as a function, so both halves can be put under one timeout.
async fn both<A: std::future::Future, B: std::future::Future>(
    a: A,
    b: B,
) -> (A::Output, B::Output) {
    tokio::join!(a, b)
}

#[tokio::test]
async fn the_relay_is_a_handshake_and_not_storage() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = opened["id"].as_str().unwrap().to_string();
    let post = |message: String| {
        server
            .client
            .post(server.url(&format!("/v1/pair/{id}")))
            .bearer_auth(&first.token)
            .json(&json!({ "side": "a", "message": message }))
            .send()
    };

    assert_eq!(
        post(uwusync_server::b64::encode(vec![0u8; 9 * 1024]))
            .await
            .unwrap()
            .status(),
        413,
        "a handshake message is small"
    );
    assert_eq!(post(String::new()).await.unwrap().status(), 400);
    assert_eq!(
        post("not base64 at all !!".into()).await.unwrap().status(),
        400
    );

    for _ in 0..4 {
        assert_eq!(
            post(uwusync_server::b64::encode(b"fine"))
                .await
                .unwrap()
                .status(),
            204
        );
    }
    assert_eq!(
        post(uwusync_server::b64::encode(b"one too many"))
            .await
            .unwrap()
            .status(),
        400,
        "and there are only so many of them"
    );

    // A side nobody named is not a side.
    let bad_side = server
        .client
        .post(server.url(&format!("/v1/pair/{id}")))
        .json(&json!({ "side": "c", "message": uwusync_server::b64::encode(b"x") }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_side.status(), 400);
}

#[tokio::test]
async fn a_session_nobody_opened_is_not_there_and_not_everyones_to_close() {
    let server = start(Registration::Open).await;
    let mine = Device::create_account(&server, "", "master", 1).await;
    let theirs = Device::create_account(&server, "", "other", 2).await;

    // Opening one needs a device that is already in.
    let anonymous = server
        .client
        .post(server.url("/v1/pair"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 401);

    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&mine.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = opened["id"].as_str().unwrap().to_string();

    // Another account cannot close it, and is not told that it exists.
    let stranger = server
        .client
        .delete(server.url(&format!("/v1/pair/{id}")))
        .bearer_auth(&theirs.token)
        .send()
        .await
        .unwrap();
    assert_eq!(stranger.status(), 404);

    let unknown = server
        .client
        .get(server.url("/v1/pair/ZZZZZ?side=b"))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);

    // It is still there for the account that opened it.
    assert_eq!(
        server
            .client
            .get(server.url(&format!("/v1/pair/{id}?side=b")))
            .header("x-uwussh-pair-claim", "the joining device")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}
