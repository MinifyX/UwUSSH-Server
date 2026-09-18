//! `uwussh-server` — run it, or ask it something.
//!
//! With no arguments it serves. The other commands are the ones you reach for
//! from a shell on the box: make an invite, see the devices, shut one out, take
//! a backup.

use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;
use uwussh_server::api;
use uwussh_server::config::TlsMode;
use uwussh_server::db::{accounts, devices, invites, records, Db};
use uwussh_server::{now_ms, tls, AppState, Config};

#[derive(Parser)]
#[command(name = "uwussh-server", version, about = "Sync server for UwUSSH")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve. The default.
    Serve,
    /// Make an invite code for a new account.
    Invite,
    /// List the accounts on this server, and how many devices each has.
    Accounts,
    /// List the devices of an account.
    Devices { account: Uuid },
    /// Shut a device out.
    Revoke { device: Uuid },
    /// Print the fingerprint of this server certificate, which is what a
    /// device pins.
    Fingerprint,
    /// Write a consistent copy of the database.
    Backup {
        /// Where to write it. The default is a dated file under `backups`.
        #[arg(long)]
        to: Option<PathBuf>,
    },
}

fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "uwussh_server=info,tower_http=warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::from_env()?;
    let db = Db::open(&config.database()).map_err(|error| format!("database: {error}"))?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(db, config),
        Command::Invite => {
            let code = {
                let conn = db.lock();
                invites::create_invite(&conn, invites::INVITE_TTL_MS)
                    .map_err(|error| error.to_string())?
            };
            let fingerprint = match config.tls {
                TlsMode::Auto => {
                    Some(tls::fingerprint_of(&config.data_dir).map_err(|error| error.to_string())?)
                }
                TlsMode::Off => None,
            };
            println!("Invite code: {code}");
            println!(
                "Setup code:  {}",
                setup_code(&config, &code, fingerprint.as_deref())
            );
            println!("Good for a week, and for one account.");
            Ok(())
        }
        Command::Accounts => {
            let conn = db.lock();
            let mut stmt = conn
                .prepare("SELECT id, created_ms FROM accounts ORDER BY created_ms")
                .map_err(|error| error.to_string())?;
            let rows: Vec<(String, i64)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|error| error.to_string())?
                .collect::<rusqlite::Result<_>>()
                .map_err(|error| error.to_string())?;
            if rows.is_empty() {
                println!("No accounts yet. `uwussh-server invite` makes the first one possible.");
            }
            for (id, created) in rows {
                let account = Uuid::parse_str(&id).unwrap_or(Uuid::nil());
                let count = devices::live_count(&conn, account).unwrap_or(0);
                println!("{id}  {} device(s)  since {}", count, date(created as u64));
            }
            Ok(())
        }
        Command::Devices { account } => {
            let conn = db.lock();
            for device in devices::list(&conn, account).map_err(|error| error.to_string())? {
                let state = match device.revoked_ms {
                    Some(when) => format!("revoked {}", date(when)),
                    None => match device.last_seen_ms {
                        Some(when) => format!("last seen {}", date(when)),
                        None => "never here".to_string(),
                    },
                };
                println!("{}  {}  {state}", device.id, device.name);
            }
            Ok(())
        }
        Command::Revoke { device } => {
            let conn = db.lock();
            let found = devices::get(&conn, device)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("no device {device}"))?;
            let revoked = devices::revoke(&conn, found.account_id, device)
                .map_err(|error| error.to_string())?;
            println!(
                "{}",
                if revoked {
                    "Revoked. It stops syncing at once — but rotate the keys and passwords it held."
                } else {
                    "It was already revoked."
                }
            );
            Ok(())
        }
        Command::Fingerprint => {
            match config.tls {
                TlsMode::Auto => {
                    let fingerprint =
                        tls::fingerprint_of(&config.data_dir).map_err(|error| error.to_string())?;
                    println!("{fingerprint}");
                    println!("{}", config.base_url());
                    println!("A device pins this on the first connection, like an SSH host key.");
                }
                TlsMode::Off => {
                    println!("UWUSSH_TLS is off: the certificate belongs to whatever is in front.")
                }
            }
            Ok(())
        }
        Command::Backup { to } => {
            let path = to.unwrap_or_else(|| {
                config
                    .backups()
                    .join(format!("uwussh-{}.db", date(now_ms())))
            });
            db.backup_to(&path).map_err(|error| error.to_string())?;
            println!("Written to {}", path.display());
            Ok(())
        }
    }
}

#[tokio::main]
async fn serve(db: Db, config: Config) -> Result<(), String> {
    // The certificate first: its fingerprint belongs in the setup code, and a
    // key that cannot be written is a reason not to start at all.
    let identity = match config.tls {
        TlsMode::Auto => Some(
            tls::load_or_create(&config.data_dir, &tls::names_for(config.public.as_deref()))
                .map_err(|error| format!("certificate: {error}"))?,
        ),
        TlsMode::Off => None,
    };
    let fingerprint = identity
        .as_ref()
        .map(|identity| identity.fingerprint.clone());

    // A server nobody can join is not much use, so the first start says how.
    if accounts::count(&db.lock()).unwrap_or(0) == 0
        && invites::count_open_invites(&db.lock()).unwrap_or(0) == 0
    {
        let code = {
            let conn = db.lock();
            invites::create_invite(&conn, invites::INVITE_TTL_MS)
                .map_err(|error| error.to_string())?
        };
        tracing::info!("no accounts yet — here is the setup code for the first device:");
        tracing::info!("    {}", setup_code(&config, &code, fingerprint.as_deref()));
        tracing::info!("paste it into UwUSSH under Settings → Sync. It is good for a week.");
    }

    let listen = config.listen;
    let url = config.base_url();
    let state = AppState::new(db, config);
    maintenance(state.clone());
    let app = api::router(state).into_make_service_with_connect_info::<SocketAddr>();

    match identity {
        Some(identity) => {
            // `ring` rather than the default provider: it needs no C toolchain,
            // so this builds the same everywhere.
            rustls::crypto::ring::default_provider()
                .install_default()
                .map_err(|_| "could not set up TLS".to_string())?;
            let tls = RustlsConfig::from_pem(
                identity.cert_pem.into_bytes(),
                identity.key_pem.into_bytes(),
            )
            .await
            .map_err(|error| format!("certificate: {error}"))?;

            let handle = Handle::new();
            tokio::spawn({
                let handle = handle.clone();
                async move {
                    shutdown().await;
                    handle.graceful_shutdown(Some(Duration::from_secs(5)));
                }
            });
            tracing::info!(%listen, %url, fingerprint = %identity.fingerprint, "UwUSSH sync server ready");
            axum_server::bind_rustls(listen, tls)
                .handle(handle)
                .serve(app)
                .await
                .map_err(|error| error.to_string())
        }
        None => {
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .map_err(|error| format!("cannot listen on {listen}: {error}"))?;
            tracing::warn!(
                %listen, %url,
                "serving plain HTTP — put a reverse proxy with a certificate in front"
            );
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown())
                .await
                .map_err(|error| error.to_string())
        }
    }
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("stopping");
}

/// Once a day: a backup, and a sweep of what nobody needs any more.
fn maintenance(state: AppState) {
    tokio::spawn(async move {
        let day = Duration::from_secs(24 * 60 * 60);
        // Not at once on start: a server that is restarted in a loop should
        // not write a backup every time.
        tokio::time::sleep(Duration::from_secs(60 * 10)).await;
        loop {
            let db = state.db.clone();
            let config = state.config.clone();
            let done = tokio::task::spawn_blocking(move || {
                let path = config
                    .backups()
                    .join(format!("uwussh-{}.db", date(now_ms())));
                if let Err(error) = db.backup_to(&path) {
                    tracing::warn!(%error, "backup failed");
                } else {
                    keep_newest(&config.backups(), 14);
                }
                purge(&db);
            })
            .await;
            if done.is_err() {
                tracing::warn!("maintenance did not finish");
            }
            tokio::time::sleep(day).await;
        }
    });
}

/// Tombstones every device has read and that are older than a season, and
/// codes that are long expired.
fn purge(db: &Db) {
    const NINETY_DAYS_MS: u64 = 90 * 24 * 60 * 60 * 1000;
    let conn = db.lock();
    let _ = invites::purge(&conn);
    let ids: Vec<String> = match conn
        .prepare("SELECT id FROM accounts")
        .and_then(|mut stmt| stmt.query_map([], |row| row.get(0))?.collect())
    {
        Ok(ids) => ids,
        Err(error) => {
            tracing::warn!(%error, "could not read the accounts");
            return;
        }
    };
    for id in ids {
        let Ok(id) = Uuid::parse_str(&id) else {
            continue;
        };
        let Ok(Some(account)) = accounts::get(&conn, id) else {
            continue;
        };
        let below = devices::lowest_cursor(&conn, id).unwrap_or(0);
        let before = now_ms().saturating_sub(NINETY_DAYS_MS);
        match records::purge_tombstones(&conn, &account, before, below) {
            Ok(0) => {}
            Ok(gone) => tracing::info!(%id, gone, "tombstones forgotten"),
            Err(error) => tracing::warn!(%error, "could not purge tombstones"),
        }
    }
}

/// Keep the newest `keep` backups and remove the rest.
fn keep_newest(dir: &std::path::Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "db")
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("uwussh-"))
        })
        .collect();
    files.sort();
    for old in files.iter().rev().skip(keep) {
        let _ = std::fs::remove_file(old);
    }
}

/// One setup code to paste: where the server is, its certificate fingerprint,
/// and the invite. The fingerprint is the part that matters — the first device
/// pins it the way an SSH client pins a host key, and passes it on to every
/// device that pairs with it afterwards.
fn setup_code(config: &Config, invite: &str, fingerprint: Option<&str>) -> String {
    let mut body = serde_json::json!({ "u": config.base_url(), "i": invite });
    if let Some(fingerprint) = fingerprint {
        body["f"] = serde_json::json!(fingerprint);
    }
    format!("uwu1_{}", uwussh_server::b64::encode(body.to_string()))
}

/// `YYYY-MM-DD` from milliseconds since the epoch, without pulling in a date
/// library for one line of output. (Howard Hinnant's civil-from-days.)
fn date(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_is_the_date() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_700_000_000_000), "2023-11-14");
        assert_eq!(date(1_789_000_000_000), "2026-09-10");
    }

    fn decode(code: &str) -> serde_json::Value {
        assert!(code.starts_with("uwu1_"), "{code}");
        let decoded = uwussh_server::b64::decode(&code["uwu1_".len()..]).unwrap();
        serde_json::from_slice(&decoded).unwrap()
    }

    #[test]
    fn a_setup_code_carries_the_address_the_fingerprint_and_the_invite() {
        let config = Config {
            public: Some("nas.lan:8443".into()),
            ..Config::default()
        };
        let parsed = decode(&setup_code(
            &config,
            "ABCDE-FGHJK-MNPQR",
            Some("SHA256:abc"),
        ));
        assert_eq!(parsed["u"], "https://nas.lan:8443");
        assert_eq!(parsed["f"], "SHA256:abc");
        assert_eq!(parsed["i"], "ABCDE-FGHJK-MNPQR");
    }

    #[test]
    fn without_its_own_certificate_there_is_nothing_to_pin() {
        let config = Config {
            tls: TlsMode::Off,
            public: Some("https://uwussh.example.com".into()),
            ..Config::default()
        };
        let parsed = decode(&setup_code(&config, "X", None));
        assert_eq!(parsed["u"], "https://uwussh.example.com");
        assert!(parsed.get("f").is_none(), "{parsed}");
    }

    #[test]
    fn a_setup_code_falls_back_to_where_the_server_listens() {
        let parsed = decode(&setup_code(&Config::default(), "X", None));
        assert_eq!(parsed["u"], "https://0.0.0.0:8443");
    }

    #[test]
    fn only_the_newest_backups_are_kept() {
        let dir = std::env::temp_dir().join(format!("uwussh-backups-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        for day in 1..=5 {
            std::fs::write(dir.join(format!("uwussh-2026-09-0{day}.db")), b"x").unwrap();
        }
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();

        keep_newest(&dir, 2);

        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec!["notes.txt", "uwussh-2026-09-04.db", "uwussh-2026-09-05.db"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
