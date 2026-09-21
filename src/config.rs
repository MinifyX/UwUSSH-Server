//! Everything the server reads from its environment, and nothing else.
//!
//! No config file: a container gets its settings from environment variables,
//! and a setting that lives in two places is a setting that disagrees with
//! itself.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Whether the server brings its own certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Make one, keep the key, and say what its fingerprint is. The client
    /// pins that, the way it pins an SSH host key.
    Auto,
    /// Speak plain HTTP, because something in front does the TLS.
    Off,
}

impl TlsMode {
    fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "on" | "1" | "true" => Self::Auto,
            "off" | "0" | "false" | "proxy" => Self::Off,
            _ => return None,
        })
    }
}

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
    pub tls: TlsMode,
    /// Trust `X-Forwarded-For` for the address rate limits are counted per.
    /// Only ever true behind a proxy that sets it, or anyone can pretend to be
    /// someone else.
    pub trust_forwarded: bool,
    /// How long a device's session token lives before it signs again.
    pub session_secs: u64,
    /// Ask GitHub once a day whether there is a newer release, and say so in
    /// the log. The only connection the server opens on its own.
    pub update_check: bool,
    /// The image tag this machine follows (`latest`, `beta`, `edge` or a
    /// version), which decides what counts as an update.
    pub channel: Option<String>,
    /// How many accounts this server takes, whoever asks.
    pub max_accounts: u64,
    /// What one account may hold.
    pub quota: crate::db::records::Quota,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            listen: "0.0.0.0:8443".parse().expect("a literal address"),
            public: None,
            registration: Registration::Invite,
            tls: TlsMode::Auto,
            trust_forwarded: false,
            session_secs: 60 * 60,
            update_check: true,
            channel: None,
            max_accounts: 100,
            quota: crate::db::records::Quota::default(),
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
        if let Some(tls) = var("UWUSSH_TLS") {
            config.tls = TlsMode::parse(&tls)
                .ok_or_else(|| format!("UWUSSH_TLS must be auto or off: {tls}"))?;
        }
        if let Some(trust) = var("UWUSSH_TRUST_FORWARDED") {
            config.trust_forwarded = switch(&trust)
                .ok_or_else(|| format!("UWUSSH_TRUST_FORWARDED must be on or off: {trust}"))?;
        }
        if let Some(secs) = var("UWUSSH_SESSION_SECS") {
            config.session_secs = secs
                .parse()
                .map_err(|_| format!("UWUSSH_SESSION_SECS is not a number: {secs}"))?;
        }
        if let Some(check) = var("UWUSSH_UPDATE_CHECK") {
            config.update_check = switch(&check)
                .ok_or_else(|| format!("UWUSSH_UPDATE_CHECK must be on or off: {check}"))?;
        }
        config.channel = var("UWUSSH_CHANNEL");
        if let Some(max) = var("UWUSSH_MAX_ACCOUNTS") {
            config.max_accounts = number("UWUSSH_MAX_ACCOUNTS", &max)?;
        }
        if let Some(records) = var("UWUSSH_ACCOUNT_MAX_RECORDS") {
            config.quota.records = number("UWUSSH_ACCOUNT_MAX_RECORDS", &records)?;
        }
        if let Some(megabytes) = var("UWUSSH_ACCOUNT_MAX_MB") {
            config.quota.bytes = number("UWUSSH_ACCOUNT_MAX_MB", &megabytes)?
                .checked_mul(1024 * 1024)
                .ok_or("UWUSSH_ACCOUNT_MAX_MB is more than any disk")?;
        }
        Ok(config)
    }

    pub fn database(&self) -> PathBuf {
        self.data_dir.join("uwussh.db")
    }

    pub fn backups(&self) -> PathBuf {
        self.data_dir.join("backups")
    }

    /// How a device writes this server down: the scheme follows whether the
    /// server does its own TLS, unless the address already says.
    pub fn base_url(&self) -> String {
        let scheme = match self.tls {
            TlsMode::Auto => "https",
            TlsMode::Off => "http",
        };
        match &self.public {
            Some(public) if public.contains("://") => public.trim_end_matches('/').to_string(),
            Some(public) => format!("{scheme}://{public}"),
            None => format!("{scheme}://{}", self.listen),
        }
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn number(name: &str, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse()
        .map_err(|_| format!("{name} is not a number: {value}"))
}

fn switch(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "1" | "true" | "yes" => Some(true),
        "off" | "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let config = Config::default();
        assert_eq!(config.listen.port(), 8443);
        assert_eq!(config.registration, Registration::Invite);
        assert_eq!(config.tls, TlsMode::Auto, "secure without being asked");
        assert!(!config.trust_forwarded, "off unless a proxy is in front");
        assert!(config.update_check);
        assert_eq!(config.database().file_name().unwrap(), "uwussh.db");
    }

    #[test]
    fn the_address_a_device_writes_down_says_how_to_reach_it() {
        let plain = Config {
            tls: TlsMode::Off,
            public: Some("nas.lan:8443".into()),
            ..Config::default()
        };
        assert_eq!(plain.base_url(), "http://nas.lan:8443");

        let secure = Config {
            public: Some("nas.lan:8443".into()),
            ..Config::default()
        };
        assert_eq!(secure.base_url(), "https://nas.lan:8443");
        assert_eq!(Config::default().base_url(), "https://0.0.0.0:8443");

        let proxied = Config {
            tls: TlsMode::Off,
            public: Some("https://uwussh.example.com/".into()),
            ..Config::default()
        };
        assert_eq!(proxied.base_url(), "https://uwussh.example.com");
    }

    #[test]
    fn a_switch_is_on_or_off_and_nothing_else() {
        assert_eq!(switch("OFF"), Some(false));
        assert_eq!(switch("on"), Some(true));
        assert_eq!(switch("0"), Some(false));
        assert_eq!(switch("later"), None);
    }

    #[test]
    fn registration_only_takes_the_three_words() {
        assert_eq!(Registration::parse("OPEN"), Some(Registration::Open));
        assert_eq!(Registration::parse("closed"), Some(Registration::Closed));
        assert_eq!(Registration::parse("maybe"), None);
    }
}
