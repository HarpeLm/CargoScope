//! Maintenance data of direct dependencies: crates.io owners, repository URL
//! and whether the GitHub repository is archived.
//!
//! Fetched by `cargoscope update` for direct crates.io dependencies only, and
//! cached for [`MAX_AGE`] per crate. The crates.io API is called at most once
//! per second; the GitHub API uses `GITHUB_TOKEN` or `GH_TOKEN` when set
//! (60 requests per hour without one). When GitHub refuses (rate limit), the
//! archived status stays unknown and is retried at the next update.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crates_io::{ApiClock, MAX_API_BYTES, fetch_text};

pub(crate) const DIR: &str = "maintenance";
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const GITHUB_API: &str = "https://api.github.com";

/// Cached maintenance data of one crate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Maintenance {
    /// When the data was complete, in seconds since the epoch; 0 if a part
    /// is missing and must be fetched again.
    checked: u64,
    pub(crate) owners: Option<Vec<String>>,
    pub(crate) repository: Option<String>,
    pub(crate) archived: Option<bool>,
}

impl Maintenance {
    fn format(&self) -> String {
        let mut out = format!("checked\t{}\n", self.checked);
        if let Some(owners) = &self.owners {
            out.push_str("owners\t\n");
            for owner in owners {
                out.push_str(&format!("owner\t{owner}\n"));
            }
        }
        if let Some(repository) = &self.repository {
            out.push_str(&format!("repository\t{repository}\n"));
        }
        if let Some(archived) = self.archived {
            out.push_str(&format!("archived\t{archived}\n"));
        }
        out
    }

    fn parse(text: &str) -> Self {
        let mut data = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('\t') else {
                continue;
            };
            match key {
                "checked" => data.checked = value.parse().unwrap_or(0),
                "owners" => data.owners = Some(Vec::new()),
                "owner" if is_safe_text(value) => {
                    data.owners
                        .get_or_insert_with(Vec::new)
                        .push(value.to_owned());
                }
                "repository" if is_safe_text(value) => data.repository = Some(value.to_owned()),
                "archived" => data.archived = value.parse().ok(),
                _ => {}
            }
        }
        data
    }
}

/// Owner logins and URLs never contain control characters or tabs.
fn is_safe_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= 512 && !text.chars().any(char::is_control)
}

/// Reads the cached data of `name`, if any.
pub(crate) fn read(root: &Path, name: &str) -> Option<Maintenance> {
    fs::read_to_string(root.join(DIR).join(name))
        .ok()
        .map(|text| Maintenance::parse(&text))
}

/// `owner/repo` of a GitHub repository URL.
fn github_repo(url: &str) -> Option<(String, String)> {
    let rest = url
        .trim()
        .strip_prefix("https://github.com/")
        .or_else(|| url.trim().strip_prefix("http://github.com/"))
        .or_else(|| url.trim().strip_prefix("https://www.github.com/"))?;
    let mut parts = rest.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let valid = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && part != "."
            && part != ".."
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    (valid(owner) && valid(repo)).then(|| (owner.to_owned(), repo.to_owned()))
}

fn parse_owners(text: &str) -> Result<Vec<String>, String> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let users = value
        .get("users")
        .and_then(serde_json::Value::as_array)
        .ok_or("no owner list in the answer")?;
    Ok(users
        .iter()
        .filter_map(|user| user.get("login")?.as_str())
        .filter(|login| is_safe_text(login))
        .map(str::to_owned)
        .collect())
}

fn parse_repository(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value
        .get("crate")?
        .get("repository")?
        .as_str()
        .filter(|url| is_safe_text(url))
        .map(str::to_owned)
}

/// Repository declared in an unpacked registry copy of `name-version`
/// (the newest version, whose repository is current).
fn local_repository(sources: &[PathBuf], name: &str, version: &str) -> Option<String> {
    sources.iter().find_map(|source| {
        let manifest = source.join(format!("{name}-{version}")).join("Cargo.toml");
        let metadata = fs::symlink_metadata(&manifest).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_API_BYTES {
            return None;
        }
        let value: toml::Value = toml::from_str(&fs::read_to_string(&manifest).ok()?).ok()?;
        value
            .get("package")?
            .get("repository")?
            .as_str()
            .filter(|url| is_safe_text(url))
            .map(str::to_owned)
    })
}

/// What happened when asking GitHub.
enum GithubAnswer {
    Archived(bool),
    /// The repository does not exist (or is private): nothing to retry.
    NotFound,
    /// Refused or failed: retry at the next update.
    Failed(String),
}

fn github_archived(
    agent: &ureq::Agent,
    token: Option<&str>,
    owner: &str,
    repo: &str,
) -> GithubAnswer {
    let mut request = agent
        .get(&format!("{GITHUB_API}/repos/{owner}/{repo}"))
        .set("Accept", "application/vnd.github+json");
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    match request.call() {
        Ok(response) => {
            let mut text = String::new();
            if std::io::Read::read_to_string(
                &mut std::io::Read::take(response.into_reader(), MAX_API_BYTES),
                &mut text,
            )
            .is_err()
            {
                return GithubAnswer::Failed("unreadable answer".to_owned());
            }
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|value| value.get("archived")?.as_bool())
                .map_or_else(
                    || GithubAnswer::Failed("no archived field in the answer".to_owned()),
                    GithubAnswer::Archived,
                )
        }
        Err(ureq::Error::Status(404, _)) => GithubAnswer::NotFound,
        Err(ureq::Error::Status(403 | 429, _)) => GithubAnswer::Failed(if token.is_some() {
            "GitHub rate limit reached".to_owned()
        } else {
            "GitHub rate limit reached (set GITHUB_TOKEN to raise it)".to_owned()
        }),
        Err(error) => GithubAnswer::Failed(error.to_string()),
    }
}

/// Counts of a maintenance refresh.
#[derive(Debug, Default)]
pub(crate) struct Refreshed {
    pub(crate) crates: usize,
    pub(crate) failures: Vec<String>,
}

/// Fetches maintenance data for `crates` (name, newest version), skipping
/// crates whose cached data is complete and recent.
pub(crate) fn refresh(
    root: &Path,
    crates: &[(&str, String)],
    api_agent: &ureq::Agent,
    clock: &mut ApiClock,
    local_sources: &[PathBuf],
) -> Result<Refreshed, crate::AdvisoryError> {
    let dir = root.join(DIR);
    fs::create_dir_all(&dir).map_err(crate::io_error(&dir))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GH_TOKEN").ok())
        .filter(|token| !token.trim().is_empty());
    let mut github: Option<ureq::Agent> = None;
    let mut github_blocked = false;
    let mut refreshed = Refreshed::default();

    for (name, newest) in crates {
        let name = *name;
        let previous = read(root, name).unwrap_or_default();
        if previous.checked > 0 && now.saturating_sub(previous.checked) < MAX_AGE.as_secs() {
            continue;
        }
        let mut data = Maintenance {
            checked: now,
            ..previous
        };

        clock.wait();
        match fetch_text(
            api_agent,
            &format!("{}/{name}/owners", crate::crates_io::API_URL),
            MAX_API_BYTES,
        )
        .and_then(|text| parse_owners(&text))
        {
            Ok(owners) => data.owners = Some(owners),
            Err(error) => {
                refreshed.failures.push(format!("{name} owners: {error}"));
                data.checked = 0;
            }
        }

        if let Some(repository) = local_repository(local_sources, name, newest) {
            data.repository = Some(repository);
        } else {
            clock.wait();
            match fetch_text(
                api_agent,
                &format!("{}/{name}", crate::crates_io::API_URL),
                MAX_API_BYTES,
            ) {
                Ok(text) => data.repository = parse_repository(&text),
                Err(error) => {
                    refreshed
                        .failures
                        .push(format!("{name} repository: {error}"));
                    data.checked = 0;
                }
            }
        }

        data.archived = None;
        if let Some((owner, repo)) = data.repository.as_deref().and_then(github_repo) {
            if github_blocked {
                data.checked = 0;
            } else {
                if github.is_none() {
                    github = Some(
                        crate::proxy::agent(
                            GITHUB_API,
                            Some(Duration::from_secs(30)),
                            Some(crate::crates_io::USER_AGENT),
                        )
                        .map_err(crate::AdvisoryError::Download)?,
                    );
                }
                let agent = github.as_ref().expect("GitHub agent was just created");
                match github_archived(agent, token.as_deref(), &owner, &repo) {
                    GithubAnswer::Archived(archived) => data.archived = Some(archived),
                    GithubAnswer::NotFound => {}
                    GithubAnswer::Failed(error) => {
                        if error.contains("rate limit") {
                            github_blocked = true;
                        }
                        refreshed
                            .failures
                            .push(format!("{name} archived status: {error}"));
                        data.checked = 0;
                    }
                }
            }
        }

        let target = dir.join(name);
        fs::write(&target, data.format()).map_err(crate::io_error(&target))?;
        refreshed.crates += 1;
    }
    Ok(refreshed)
}

#[cfg(test)]
mod tests {
    use super::{Maintenance, github_repo, parse_owners, parse_repository};

    #[test]
    fn reads_github_repositories_only() {
        let repo = |owner: &str, name: &str| Some((owner.to_owned(), name.to_owned()));
        assert_eq!(
            github_repo("https://github.com/serde-rs/serde"),
            repo("serde-rs", "serde")
        );
        assert_eq!(github_repo("https://github.com/a/b.git"), repo("a", "b"));
        assert_eq!(
            github_repo("https://github.com/rust-lang/cargo/tree/master/crates/x"),
            repo("rust-lang", "cargo")
        );
        assert_eq!(github_repo("https://gitlab.com/a/b"), None);
        assert_eq!(github_repo("https://github.com/a"), None);
        assert_eq!(github_repo("https://github.com/../x"), None);
        assert_eq!(github_repo("https://github.com/a/b?c"), None);
    }

    #[test]
    fn parses_crates_io_answers() {
        let owners = r#"{"users":[{"id":1,"login":"dtolnay","kind":"user"},{"login":"github:serde-rs:publish","kind":"team"}]}"#;
        assert_eq!(
            parse_owners(owners).unwrap(),
            vec!["dtolnay".to_owned(), "github:serde-rs:publish".to_owned()]
        );
        assert!(parse_owners("{}").is_err());
        assert_eq!(
            parse_repository(r#"{"crate":{"repository":"https://github.com/a/b"}}"#).as_deref(),
            Some("https://github.com/a/b")
        );
        assert_eq!(parse_repository(r#"{"crate":{"repository":null}}"#), None);
    }

    #[test]
    fn round_trips_the_cache_format() {
        let data = Maintenance {
            checked: 42,
            owners: Some(vec!["alice".to_owned()]),
            repository: Some("https://github.com/a/b".to_owned()),
            archived: Some(true),
        };
        assert_eq!(Maintenance::parse(&data.format()), data);
        let empty_owners = Maintenance {
            owners: Some(Vec::new()),
            ..Maintenance::default()
        };
        assert_eq!(Maintenance::parse(&empty_owners.format()), empty_owners);
    }
}
