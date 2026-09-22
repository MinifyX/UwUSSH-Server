//! Knowing when there is something newer.
//!
//! Once a day the server asks GitHub which releases there are and, when one on
//! its channel is newer than itself, says so in its log along with the one
//! command that updates it. A build of `main` (the `edge` tag) asks how many
//! commits came since instead. That is the only connection this server ever
//! opens on its own, and `UWUSYNC_UPDATE_CHECK=off` stops it.
//!
//! Updating is not something the server does to itself: `update.sh` does it on
//! the machine, with a backup first and the old version back if the new one
//! does not come up. A sync server that can replace itself from the network is
//! one more way in, and the script does the job better anyway — it can bring a
//! new compose file too.

use crate::Config;
use serde::Deserialize;
use std::cmp::Ordering;
use std::sync::Arc;
use std::time::Duration;

const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_RESPONSE: usize = 2 * 1024 * 1024;

/// What this binary is: its version, and for a CI build its commit and
/// whether it was built from a release tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Build {
    pub version: &'static str,
    pub commit: Option<&'static str>,
    /// Built from a `v…` tag. Otherwise it is an `edge` build of `main`, or
    /// one made by hand.
    pub release: bool,
}

pub fn build() -> Build {
    Build {
        version: env!("CARGO_PKG_VERSION"),
        commit: option_env!("UWUSYNC_GIT_SHA").filter(|sha| !sha.is_empty()),
        release: option_env!("UWUSYNC_RELEASE").is_some_and(|tag| !tag.is_empty()),
    }
}

/// `owner/name` of the repository this server comes from.
fn repository() -> &'static str {
    env!("CARGO_PKG_REPOSITORY")
        .trim_start_matches("https://github.com/")
        .trim_end_matches('/')
}

/// Which releases count as newer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Stable releases only — what the `latest` tag follows.
    Stable,
    /// Every release, betas included — the `beta` tag.
    Beta,
}

impl Channel {
    /// From the tag the machine follows (`UWUSYNC_VERSION` in `.env`, handed in
    /// as `UWUSYNC_CHANNEL`), and from what is running: a beta that is told
    /// about stable releases only would hear nothing until the next one.
    pub fn of(followed: Option<&str>, running: &str) -> Self {
        if followed.is_some_and(|tag| tag.trim().eq_ignore_ascii_case("beta"))
            || running.contains('-')
        {
            Channel::Beta
        } else {
            Channel::Stable
        }
    }
}

/// `1.2.3-beta.4` as comparable parts; a pre-release sorts before its release.
fn version_key(version: &str) -> Option<(Vec<u64>, Option<Vec<String>>)> {
    let version = version.trim().trim_start_matches('v');
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre.split('.').map(str::to_owned).collect())),
        None => (version, None),
    };
    let numbers = core
        .split('.')
        .map(|part| part.parse().ok())
        .collect::<Option<Vec<u64>>>()?;
    Some((numbers, pre))
}

pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let (Some((a_core, a_pre)), Some((b_core, b_pre))) = (version_key(a), version_key(b)) else {
        return Ordering::Equal;
    };
    a_core.cmp(&b_core).then_with(|| match (a_pre, b_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a), Some(b)) => {
            for (x, y) in a.iter().zip(&b) {
                let order = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    _ => x.cmp(y),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
            a.len().cmp(&b.len())
        }
    })
}

#[derive(Debug, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    pub html_url: String,
}

/// The newest release on the channel that is newer than `current`, if any.
pub fn newest_release<'a>(
    list: &'a [GitHubRelease],
    current: &str,
    channel: Channel,
) -> Option<&'a GitHubRelease> {
    list.iter()
        .filter(|release| !release.draft && (channel == Channel::Beta || !release.prerelease))
        .filter(|release| compare_versions(&release.tag_name, current) == Ordering::Greater)
        .max_by(|a, b| compare_versions(&a.tag_name, &b.tag_name))
}

#[derive(Deserialize)]
struct Comparison {
    ahead_by: u32,
}

/// What a check found out, as one line for the log.
#[derive(Debug, PartialEq, Eq)]
pub enum Finding {
    UpToDate,
    Release { version: String, url: String },
    Commits(u32),
}

/// Once a day, from a minute after the start: long enough that a server
/// restarted in a loop does not ask GitHub every time.
pub fn spawn(config: Arc<Config>) {
    if !config.update_check {
        tracing::info!("not checking for updates (UWUSYNC_UPDATE_CHECK=off)");
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            match check(&config).await {
                Ok(Finding::UpToDate) => tracing::debug!("up to date"),
                Ok(Finding::Release { version, url }) => tracing::info!(
                    running = build().version,
                    %url,
                    "UwUSync Server {version} is out. To update: sudo bash update.sh, next to compose.yaml"
                ),
                Ok(Finding::Commits(count)) => tracing::info!(
                    "main is {count} commit(s) ahead of this build. To update: sudo bash update.sh, next to compose.yaml"
                ),
                Err(error) => tracing::info!(%error, "could not check for updates"),
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

/// Ask GitHub once.
pub async fn check(config: &Config) -> Result<Finding, String> {
    let build = build();
    let client = client()?;
    match (build.release, build.commit) {
        // A build of main: how far main has moved on since.
        (false, Some(commit)) => {
            let url = format!(
                "https://api.github.com/repos/{}/compare/{commit}...main",
                repository()
            );
            let comparison: Comparison = fetch_json(&client, &url).await?;
            Ok(match comparison.ahead_by {
                0 => Finding::UpToDate,
                count => Finding::Commits(count),
            })
        }
        _ => {
            let url = format!(
                "https://api.github.com/repos/{}/releases?per_page=30",
                repository()
            );
            let list: Vec<GitHubRelease> = fetch_json(&client, &url).await?;
            let channel = Channel::of(config.channel.as_deref(), build.version);
            Ok(match newest_release(&list, build.version, channel) {
                Some(release) => Finding::Release {
                    version: release.tag_name.trim_start_matches('v').to_owned(),
                    url: release.html_url.clone(),
                },
                None => Finding::UpToDate,
            })
        }
    }
}

fn client() -> Result<reqwest::Client, String> {
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring speaks the versions rustls asks for")
    .with_root_certificates(roots)
    .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .user_agent(concat!("uwusync-server/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| error.to_string())
}

/// A GET that reads at most [`MAX_RESPONSE`] bytes, whatever the other end
/// says the length is.
async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let mut response = client
        .get(url)
        .header("accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("GitHub answered {}", response.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if body.len() + chunk.len() > MAX_RESPONSE {
            return Err("GitHub answered with far more than a list of releases".into());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| "GitHub answered something unexpected".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, prerelease: bool) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag.into(),
            draft: false,
            prerelease,
            html_url: format!("https://github.com/example/releases/{tag}"),
        }
    }

    #[test]
    fn versions_compare_like_semver() {
        assert_eq!(compare_versions("0.1.0", "0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("v0.2.0", "0.1.9"), Ordering::Greater);
        assert_eq!(compare_versions("0.2.0-beta.1", "0.2.0"), Ordering::Less);
        assert_eq!(
            compare_versions("0.2.0-beta.10", "0.2.0-beta.2"),
            Ordering::Greater
        );
        assert_eq!(compare_versions("0.10.0", "0.9.0"), Ordering::Greater);
    }

    #[test]
    fn each_channel_hears_about_its_own_releases() {
        let list = vec![
            release("v0.1.0", false),
            release("v0.2.0-beta.1", true),
            release("v0.1.1", false),
        ];
        let stable = newest_release(&list, "0.1.0", Channel::Stable).unwrap();
        assert_eq!(stable.tag_name, "v0.1.1");
        let beta = newest_release(&list, "0.1.0", Channel::Beta).unwrap();
        assert_eq!(beta.tag_name, "v0.2.0-beta.1");
        assert!(newest_release(&list, "0.2.0", Channel::Beta).is_none());
        assert!(newest_release(&list, "0.1.1", Channel::Stable).is_none());
    }

    #[test]
    fn a_draft_is_nobody_s_update() {
        let mut draft = release("v9.0.0", false);
        draft.draft = true;
        assert!(newest_release(&[draft], "0.1.0", Channel::Beta).is_none());
    }

    #[test]
    fn the_channel_follows_the_tag_and_what_runs() {
        assert_eq!(Channel::of(None, "0.1.0"), Channel::Stable);
        assert_eq!(Channel::of(Some("latest"), "0.1.0"), Channel::Stable);
        assert_eq!(Channel::of(Some("beta"), "0.1.0"), Channel::Beta);
        assert_eq!(
            Channel::of(Some("latest"), "0.2.0-beta.1"),
            Channel::Beta,
            "a beta hears about the next beta"
        );
    }

    #[test]
    fn the_repository_comes_from_the_package() {
        assert_eq!(repository(), "MinifyX/UwUSync-Server");
    }
}
