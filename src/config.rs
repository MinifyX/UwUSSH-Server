//! Everything the server reads from its environment, and nothing else.
//!
//! No config file: a container gets its settings from environment variables,
//! and a setting that lives in two places is a setting that disagrees with
//! itself.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Who may create an account on this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// Anyone who can reach the server. For a server on a tailnet, say.
    Open,
    /// Only with a code from `uwussh-server invite`. The default, and what the
    /// first start prints one of.
    Invite,
    /// Nobody. For a server whose devices are all enrolled.
    Closed,
}

impl Registration {
    fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "open" => Self::Open,
            "invite" => Self::Invite,
            "closed" => Self::Closed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Where the database and, later, the certificate live. One volume.
    pub data_dir: PathBuf,
    pub listen: SocketAddr,
    /// How devices reach this server — `nas.lan:8443`. The server cannot know
    /// it (it listens on every address), and it goes into the setup code, so
    /// a server behind a name or a proxy is told.
    pub public: Option<String>,
    pub registration: Registration,
    /// Trust `X-Forwarded-For` for the address rate limits are counted per.
    /// Only ever true behind a proxy that sets it, or anyone can pretend to be
    /// someone else.
    pub trust_forwarded: bool,
    /// How long a device's session token lives before it signs again.
    pub session_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            listen: "0.0.0.0:8443".parse().expect("a literal address"),
            public: None,
            registration: Registration::Invite,
            trust_forwarded: false,
            session_secs: 60 * 60,
        }
    }
}

impl Config {
    /// Read the environment. A variable that is set but unusable is an error
    /// rather than a default quietly taking over — a server that listens
    /// somewhere else than asked is worse than one that refuses to start.
    pub fn from_env() -> Result<Self, String> {
        let mut config = Config::default();

        if let Some(dir) = var("UWUSSH_DATA") {
            config.data_dir = PathBuf::from(dir);
        }
        if let Some(listen) = var("UWUSSH_LISTEN") {
            config.listen = listen
                .parse()
                .map_err(|_| format!("UWUSSH_LISTEN is not an address: {listen}"))?;
        }
        config.public = var("UWUSSH_PUBLIC");
        if let Some(registration) = var("UWUSSH_REGISTRATION") {
            config.registration = Registration::parse(&registration).ok_or_else(|| {
                format!("UWUSSH_REGISTRATION must be open, invite or closed: {registration}")
            })?;
        }
        if let Some(trust) = var("UWUSSH_TRUST_FORWARDED") {
            config.trust_forwarded = matches!(trust.as_str(), "1" | "true" | "yes");
        }
        if let Some(secs) = var("UWUSSH_SESSION_SECS") {
            config.session_secs = secs
                .parse()
                .map_err(|_| format!("UWUSSH_SESSION_SECS is not a number: {secs}"))?;
        }
        Ok(config)
    }

    pub fn database(&self) -> PathBuf {
        self.data_dir.join("uwussh.db")
    }

    pub fn backups(&self) -> PathBuf {
        self.data_dir.join("backups")
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let config = Config::default();
        assert_eq!(config.listen.port(), 8443);
        assert_eq!(config.registration, Registration::Invite);
        assert!(!config.trust_forwarded, "off unless a proxy is in front");
        assert_eq!(config.database().file_name().unwrap(), "uwussh.db");
    }

    #[test]
    fn registration_only_takes_the_three_words() {
        assert_eq!(Registration::parse("OPEN"), Some(Registration::Open));
        assert_eq!(Registration::parse("closed"), Some(Registration::Closed));
        assert_eq!(Registration::parse("maybe"), None);
    }
}
