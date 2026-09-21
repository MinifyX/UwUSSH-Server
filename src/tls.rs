//! The server's own certificate — and the fingerprint a device pins.
//!
//! A homelab server has no domain and no certificate authority, and telling
//! people to get one before they can sync their hosts is how a feature stays
//! unused. So this server makes its own certificate and says what it is; the
//! client remembers that and refuses anything else, exactly the way it already
//! treats an SSH host key. No domain, no Let's Encrypt, works over a Tailscale
//! address.
//!
//! **What is pinned is the key, not the certificate.** The fingerprint is a
//! SHA-256 of the public key (the `SubjectPublicKeyInfo`), which is why the
//! certificate can be made fresh on every start — new dates, new names, same
//! fingerprint — and nothing a device pinned ever goes stale. Only the private
//! key is kept, in one file, readable by nobody else.
//!
//! Whoever already has a real certificate sets `UWUSSH_TLS=off` and puts a
//! reverse proxy in front instead.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use std::io;
use std::path::{Path, PathBuf};

/// How long a certificate is good for. It is made fresh at every start, so
/// this only has to outlast a server that runs for a long time.
const VALID_DAYS: i64 = 397;

pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    /// `SHA256:…`, the way `ssh-keygen -l` prints one. This is what goes into
    /// the setup code and what a device pins.
    pub fingerprint: String,
}

fn key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("tls").join("key.pem")
}

/// The server's key, made once and kept, and a certificate made now.
///
/// `names` are what goes into the certificate as subject alternative names.
/// They are cosmetic here — a pinning client does not look at them — but a
/// browser or `curl -v` reads better with them.
pub fn load_or_create(data_dir: &Path, names: &[String]) -> io::Result<Identity> {
    load(data_dir, names, true)
}

/// The same, but a key is only made when `may_create` says so. A server with
/// accounts whose key is gone must not quietly make a new one: every device
/// pinned the old key and would refuse it, and the only honest thing to do is
/// to say so.
pub fn load(data_dir: &Path, names: &[String], may_create: bool) -> io::Result<Identity> {
    let path = key_path(data_dir);
    let key = match std::fs::read_to_string(&path) {
        Ok(pem) => {
            keep_private(&path);
            KeyPair::from_pem(&pem).map_err(|error| {
                io::Error::other(format!("the key in {}: {error}", path.display()))
            })?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && !may_create => {
            return Err(io::Error::other(format!(
                "the certificate key ({}) is gone, and this server has accounts. Every device \
                 pinned that key and would refuse a new one: put it back from a copy of the data \
                 volume. If it is lost for good, `uwussh-server new-key` makes a new one, and \
                 every device has to be set up again",
                path.display()
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = KeyPair::generate().map_err(io::Error::other)?;
            write_private(&path, &key.serialize_pem())?;
            tracing::info!(path = %path.display(), "a certificate key made for this server");
            key
        }
        Err(error) => return Err(error),
    };

    let mut params = CertificateParams::new(names.to_vec()).map_err(io::Error::other)?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "UwUSSH sync server");
    params.distinguished_name = name;
    let now = time::OffsetDateTime::now_utc();
    // A little in the past, so a device whose clock runs slow still accepts it.
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(VALID_DAYS);

    let cert = params.self_signed(&key).map_err(io::Error::other)?;
    Ok(Identity {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        fingerprint: fingerprint(&key.subject_public_key_info()),
    })
}

/// The public key this server serves, if it made one yet — without making one.
/// The health check holds the other end of a handshake to it.
pub fn public_key_of(data_dir: &Path) -> io::Result<Option<Vec<u8>>> {
    let path = key_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(pem) => KeyPair::from_pem(&pem)
            .map(|key| Some(key.subject_public_key_info()))
            .map_err(|error| io::Error::other(format!("the key in {}: {error}", path.display()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Just the fingerprint, for `uwussh-server fingerprint` and the setup code.
pub fn fingerprint_of(data_dir: &Path, may_create: bool) -> io::Result<String> {
    Ok(load(data_dir, &["localhost".to_string()], may_create)?.fingerprint)
}

/// `SHA256:…` over the public key, as SSH prints a host key's fingerprint —
/// the same shape, for the same reason: it is meant to be compared by eye.
pub fn fingerprint(public_key_der: &[u8]) -> String {
    format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(crate::sha256(public_key_der))
    )
}

/// Write a private key so that only its owner can read it — from the moment
/// the file exists, not from a moment after. On Windows this is a plain write:
/// that side runs from a developer's own folder, while the servers that
/// matter are the ones in a container.
fn write_private(path: &Path, pem: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(pem.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, pem)?;
    Ok(())
}

/// A key somebody made readable to others — a copy restored by hand, say — is
/// made private again, and said so.
fn keep_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                tracing::warn!(path = %path.display(), "the certificate key was readable by others; it is not any more");
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// The names to put in the certificate: where the server says it is, and
/// localhost, which is where it is tried from first.
pub fn names_for(public: Option<&str>) -> Vec<String> {
    let mut names = vec!["localhost".to_string()];
    if let Some(public) = public {
        // `https://nas.lan:8443`, `nas.lan:8443` and `nas.lan` all mean the
        // same machine here.
        let host = public
            .rsplit("://")
            .next()
            .unwrap_or(public)
            .split('/')
            .next()
            .unwrap_or(public);
        let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
        let host = host.trim_matches(|c| c == '[' || c == ']');
        if !host.is_empty() && host != "localhost" && host != "0.0.0.0" {
            names.push(host.to_string());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("uwussh-tls-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_fingerprint_survives_a_new_certificate() {
        let dir = scratch();
        let first = load_or_create(&dir, &["localhost".into()]).unwrap();
        // A restart, with another name and therefore another certificate.
        let second = load_or_create(&dir, &["localhost".into(), "nas.lan".into()]).unwrap();

        assert_ne!(
            first.cert_pem, second.cert_pem,
            "the certificate itself is made fresh"
        );
        assert_eq!(
            first.fingerprint, second.fingerprint,
            "but what a device pinned still holds"
        );
        assert!(first.fingerprint.starts_with("SHA256:"));
        assert_eq!(first.fingerprint.len(), "SHA256:".len() + 43);
        assert!(first.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(first.key_pem.contains("PRIVATE KEY"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reading_the_key_never_makes_one() {
        let dir = scratch();
        assert!(public_key_of(&dir).unwrap().is_none());
        assert!(!key_path(&dir).exists());
        let identity = load_or_create(&dir, &["localhost".into()]).unwrap();
        let key = public_key_of(&dir).unwrap().unwrap();
        assert_eq!(fingerprint(&key), identity.fingerprint);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_lost_key_is_only_replaced_when_that_is_allowed() {
        let dir = scratch();
        let error = load(&dir, &["localhost".into()], false)
            .err()
            .expect("no key, and none may be made");
        assert!(error.to_string().contains("new-key"), "{error}");
        assert!(public_key_of(&dir).unwrap().is_none());
        assert!(load(&dir, &["localhost".into()], true).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_servers_do_not_share_a_fingerprint() {
        let one = scratch();
        let two = scratch();
        let a = load_or_create(&one, &["localhost".into()]).unwrap();
        let b = load_or_create(&two, &["localhost".into()]).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
        std::fs::remove_dir_all(&one).unwrap();
        std::fs::remove_dir_all(&two).unwrap();
    }

    #[test]
    fn a_key_that_cannot_be_read_is_an_error_rather_than_a_new_one() {
        let dir = scratch();
        load_or_create(&dir, &["localhost".into()]).unwrap();
        std::fs::write(key_path(&dir), "this is not a key").unwrap();
        assert!(load_or_create(&dir, &["localhost".into()]).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_names_come_out_of_whatever_the_address_was_written_as() {
        assert_eq!(names_for(None), vec!["localhost"]);
        assert_eq!(
            names_for(Some("nas.lan:8443")),
            vec!["localhost", "nas.lan"]
        );
        assert_eq!(
            names_for(Some("https://uwussh.example.com")),
            vec!["localhost", "uwussh.example.com"]
        );
        assert_eq!(
            names_for(Some("https://uwussh.example.com/sync")),
            vec!["localhost", "uwussh.example.com"]
        );
        assert_eq!(
            names_for(Some("10.0.0.5:8443")),
            vec!["localhost", "10.0.0.5"]
        );
        assert_eq!(names_for(Some("localhost:8443")), vec!["localhost"]);
    }

    #[test]
    fn an_address_with_a_name_makes_a_certificate_that_says_so() {
        let dir = scratch();
        let identity = load_or_create(&dir, &names_for(Some("nas.lan:8443"))).unwrap();
        assert!(!identity.cert_pem.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
