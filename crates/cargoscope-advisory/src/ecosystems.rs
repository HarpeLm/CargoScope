//! Cached remote version metadata for non-Cargo Dependabot ecosystems:
//! GitHub Actions releases/tags (`github-actions`) and OCI/Docker Hub image tags
//! (`docker`).
//!
//! Scans read only from disk; `update` and `fix --updates` populate or refresh
//! the cache under `CARGOSCOPE_CACHE_DIR` with graceful offline fallback.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::proxy;

const CACHE_TTL_SECS: u64 = 6 * 3_600;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
const USER_AGENT: &str = "CargoScope (+https://github.com/HarpeLm/CargoScope)";

/// One remote tag or release discovered for a GitHub Action or container image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRelease {
    /// Raw tag string (e.g. `v4.2.2`, `4`, `1.85.0-slim-bookworm`).
    pub tag: String,
    /// Loose SemVer parsed from the version prefix (`v4` -> `4.0.0`), if any.
    pub version: Option<semver::Version>,
    /// Unix publication/push timestamp in seconds, for cooldown checks.
    pub published_unix: Option<u64>,
    /// Git commit SHA associated with a GitHub Action tag, if resolved.
    pub sha: Option<String>,
    /// OCI manifest digest (`sha256:...`), when available.
    pub digest: Option<String>,
}

/// Parses a loose tag such as `v4`, `v4.2`, `4.2.2`, or `1.85-slim` into a
/// `(SemVer, variant_suffix)` pair.
#[must_use]
pub fn parse_tag_version(tag: &str) -> Option<(semver::Version, String)> {
    let trimmed = tag.trim().trim_start_matches('v');
    if trimmed.is_empty() || !trimmed.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let split_at = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(trimmed.len());
    let num_part = trimmed[..split_at].trim_end_matches('.');
    let suffix = &trimmed[split_at..];
    if num_part.is_empty() {
        return None;
    }
    let mut parts = num_part.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().map_or(Some(0), |p| p.parse::<u64>().ok())?;
    let patch = parts.next().map_or(Some(0), |p| p.parse::<u64>().ok())?;
    if parts.next().is_some() {
        return None;
    }
    Some((semver::Version::new(major, minor, patch), suffix.to_owned()))
}

/// Normalizes `image` into `(registry, repository)`:
/// - `rust` -> `("docker.io", "library/rust")`
/// - `postgres` -> `("docker.io", "library/postgres")`
/// - `org/app` -> `("docker.io", "org/app")`
/// - `ghcr.io/org/app` -> `("ghcr.io", "org/app")`
#[must_use]
pub fn normalize_docker_image(image: &str) -> (String, String) {
    let parts: Vec<&str> = image.splitn(2, '/').collect();
    match parts.as_slice() {
        [single] => ("docker.io".to_owned(), format!("library/{single}")),
        [first, rest] if first.contains('.') || first.contains(':') || *first == "localhost" => {
            ((*first).to_owned(), (*rest).to_owned())
        }
        [org, name] => ("docker.io".to_owned(), format!("{org}/{name}")),
        _ => ("docker.io".to_owned(), image.to_owned()),
    }
}

fn cache_key(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn github_cache_path(cache_dir: &Path, repo: &str) -> PathBuf {
    cache_dir
        .join("github-actions")
        .join(format!("{}.tsv", cache_key(repo)))
}

fn docker_cache_path(cache_dir: &Path, image: &str) -> PathBuf {
    let (registry, repo) = normalize_docker_image(image);
    cache_dir.join("docker").join(format!(
        "{}__{}.tsv",
        cache_key(&registry),
        cache_key(&repo)
    ))
}

fn read_cached_tsv(path: &Path, max_age_secs: Option<u64>) -> Option<Vec<RemoteRelease>> {
    let text = fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    let header = lines.next()?;
    let fetched = header
        .strip_prefix("# fetched ")
        .and_then(|s| s.trim().parse::<u64>().ok())?;
    if let Some(ttl) = max_age_secs
        && now_unix().saturating_sub(fetched) > ttl
    {
        return None;
    }
    let mut out = Vec::new();
    for line in lines {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        let Some(&tag) = cols.first() else {
            continue;
        };
        let published_unix = cols
            .get(1)
            .and_then(|s| (!s.is_empty()).then(|| s.parse::<u64>().ok()))
            .flatten();
        let sha = cols
            .get(2)
            .filter(|s| !s.is_empty())
            .map(|s| (*s).to_owned());
        let digest = cols
            .get(3)
            .filter(|s| !s.is_empty())
            .map(|s| (*s).to_owned());
        out.push(RemoteRelease {
            version: parse_tag_version(tag).map(|(v, _)| v),
            tag: tag.to_owned(),
            published_unix,
            sha,
            digest,
        });
    }
    Some(out)
}

fn write_cached_tsv(path: &Path, items: &[RemoteRelease]) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut out = format!("# fetched {}\n", now_unix());
    for item in items {
        let pub_s = item
            .published_unix
            .map(|u| u.to_string())
            .unwrap_or_default();
        let sha = item.sha.as_deref().unwrap_or("");
        let digest = item.digest.as_deref().unwrap_or("");
        out.push_str(&format!("{}\t{}\t{}\t{}\n", item.tag, pub_s, sha, digest));
    }
    let _ = fs::write(path, out);
}

/// Reads cached releases for a GitHub Action (`owner/repo`) without accessing the network.
#[must_use]
pub fn cached_github_releases(cache_dir: &Path, repo: &str) -> Option<Vec<RemoteRelease>> {
    read_cached_tsv(&github_cache_path(cache_dir, repo), None)
}

/// Reads cached container tags for `image` without accessing the network.
#[must_use]
pub fn cached_docker_tags(cache_dir: &Path, image: &str) -> Option<Vec<RemoteRelease>> {
    read_cached_tsv(&docker_cache_path(cache_dir, image), None)
}

fn github_get(url: &str) -> Result<String, String> {
    let agent = proxy::agent(url, Some(REQUEST_TIMEOUT), Some(USER_AGENT))?;
    let mut req = agent.get(url).set("Accept", "application/vnd.github+json");
    if let Some(token) = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
    {
        req = req.set("Authorization", &format!("Bearer {token}"));
    }
    let resp = req.call().map_err(|e| format!("{url}: {e}"))?;
    resp.into_string().map_err(|e| format!("{url}: {e}"))
}

/// Parses GitHub `GET /repos/{owner}/{repo}/releases` JSON payload.
#[must_use]
pub fn parse_github_releases_json(json_str: &str) -> Vec<RemoteRelease> {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str(json_str) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        if item
            .get("draft")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            || item
                .get("prerelease")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        {
            continue;
        }
        let Some(tag) = item.get("tag_name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let published_unix = item
            .get("published_at")
            .and_then(serde_json::Value::as_str)
            .and_then(cargoscope_core::unix_seconds);
        let sha = item
            .get("target_commitish")
            .and_then(serde_json::Value::as_str)
            .filter(|s| s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .map(str::to_owned);
        out.push(RemoteRelease {
            version: parse_tag_version(tag).map(|(v, _)| v),
            tag: tag.to_owned(),
            published_unix,
            sha,
            digest: None,
        });
    }
    out
}

/// Parses GitHub `GET /repos/{owner}/{repo}/tags` JSON payload.
#[must_use]
pub fn parse_github_tags_json(json_str: &str) -> Vec<RemoteRelease> {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str(json_str) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        let Some(tag) = item.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let sha = item
            .get("commit")
            .and_then(|c| c.get("sha"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        out.push(RemoteRelease {
            version: parse_tag_version(tag).map(|(v, _)| v),
            tag: tag.to_owned(),
            published_unix: None,
            sha,
            digest: None,
        });
    }
    out
}

/// Fetches releases and tag SHAs for `owner/repo`, using `cache_dir` when fresh
/// and falling back to stale cache if offline.
pub fn fetch_github_releases(
    cache_dir: &Path,
    repo: &str,
    force_refresh: bool,
) -> Option<Vec<RemoteRelease>> {
    let path = github_cache_path(cache_dir, repo);
    if !force_refresh && let Some(cached) = read_cached_tsv(&path, Some(CACHE_TTL_SECS)) {
        return Some(cached);
    }
    let releases_url = format!("https://api.github.com/repos/{repo}/releases?per_page=30");
    let tags_url = format!("https://api.github.com/repos/{repo}/tags?per_page=30");
    let mut items = github_get(&releases_url)
        .ok()
        .map(|body| parse_github_releases_json(&body))
        .unwrap_or_default();
    if let Ok(tags_body) = github_get(&tags_url) {
        let tags = parse_github_tags_json(&tags_body);
        for t in tags {
            if let Some(existing) = items.iter_mut().find(|r| r.tag == t.tag) {
                if existing.sha.is_none() {
                    existing.sha = t.sha;
                }
            } else {
                items.push(t);
            }
        }
    }
    if items.is_empty() {
        return read_cached_tsv(&path, None);
    }
    write_cached_tsv(&path, &items);
    Some(items)
}

/// Parses Docker Hub `GET /v2/repositories/{repo}/tags` JSON response.
#[must_use]
pub fn parse_docker_hub_tags_json(json_str: &str) -> Vec<RemoteRelease> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return Vec::new();
    };
    let Some(results) = val.get("results").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in results {
        let Some(tag) = item.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let published_unix = item
            .get("tag_last_pushed")
            .or_else(|| item.get("last_updated"))
            .and_then(serde_json::Value::as_str)
            .and_then(cargoscope_core::unix_seconds);
        let digest = item
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                item.get("images")
                    .and_then(serde_json::Value::as_array)
                    .and_then(|imgs| imgs.first())
                    .and_then(|img| img.get("digest"))
                    .and_then(serde_json::Value::as_str)
            })
            .map(str::to_owned);
        out.push(RemoteRelease {
            version: parse_tag_version(tag).map(|(v, _)| v),
            tag: tag.to_owned(),
            published_unix,
            sha: None,
            digest,
        });
    }
    out
}

/// Parses OCI Registry v2 `GET /v2/{repo}/tags/list` JSON response.
#[must_use]
pub fn parse_oci_tags_json(json_str: &str) -> Vec<RemoteRelease> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return Vec::new();
    };
    let Some(tags) = val.get("tags").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    tags.iter()
        .filter_map(serde_json::Value::as_str)
        .map(|tag| RemoteRelease {
            version: parse_tag_version(tag).map(|(v, _)| v),
            tag: tag.to_owned(),
            published_unix: None,
            sha: None,
            digest: None,
        })
        .collect()
}

fn fetch_oci_v2_tags(registry: &str, repo: &str) -> Option<Vec<RemoteRelease>> {
    let url = format!("https://{registry}/v2/{repo}/tags/list");
    let agent = proxy::agent(&url, Some(REQUEST_TIMEOUT), Some(USER_AGENT)).ok()?;
    match agent.get(&url).call() {
        Ok(resp) => resp
            .into_string()
            .ok()
            .map(|body| parse_oci_tags_json(&body)),
        Err(ureq::Error::Status(401, resp)) => {
            let auth_header = resp.header("www-authenticate")?.to_owned();
            let bearer_url = parse_www_authenticate_bearer(&auth_header)?;
            let tok_agent =
                proxy::agent(&bearer_url, Some(REQUEST_TIMEOUT), Some(USER_AGENT)).ok()?;
            let tok_body = tok_agent.get(&bearer_url).call().ok()?.into_string().ok()?;
            let tok_val: serde_json::Value = serde_json::from_str(&tok_body).ok()?;
            let token = tok_val
                .get("token")
                .or_else(|| tok_val.get("access_token"))
                .and_then(serde_json::Value::as_str)?;
            let body = agent
                .get(&url)
                .set("Authorization", &format!("Bearer {token}"))
                .call()
                .ok()?
                .into_string()
                .ok()?;
            Some(parse_oci_tags_json(&body))
        }
        Err(_) => None,
    }
}

fn parse_www_authenticate_bearer(header: &str) -> Option<String> {
    let rest = header
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| header.trim().strip_prefix("bearer "))?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in rest.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            continue;
        };
        let val = v.trim().trim_matches('"');
        match k.trim() {
            "realm" => realm = Some(val),
            "service" => service = Some(val),
            "scope" => scope = Some(val),
            _ => {}
        }
    }
    let realm = realm?;
    let mut url = realm.to_owned();
    let mut sep = if realm.contains('?') { '&' } else { '?' };
    if let Some(svc) = service {
        url.push(sep);
        url.push_str("service=");
        url.push_str(svc);
        sep = '&';
    }
    if let Some(scp) = scope {
        url.push(sep);
        url.push_str("scope=");
        url.push_str(scp);
    }
    Some(url)
}

/// Fetches container image tags from Docker Hub or OCI v2 registries with caching.
pub fn fetch_docker_tags(
    cache_dir: &Path,
    image: &str,
    force_refresh: bool,
) -> Option<Vec<RemoteRelease>> {
    let path = docker_cache_path(cache_dir, image);
    if !force_refresh && let Some(cached) = read_cached_tsv(&path, Some(CACHE_TTL_SECS)) {
        return Some(cached);
    }
    let (registry, repo) = normalize_docker_image(image);
    let items = if registry == "docker.io" || registry == "registry-1.docker.io" {
        let url = format!("https://hub.docker.com/v2/repositories/{repo}/tags?page_size=100");
        let agent = proxy::agent(&url, Some(REQUEST_TIMEOUT), Some(USER_AGENT)).ok()?;
        agent
            .get(&url)
            .call()
            .ok()
            .and_then(|r| r.into_string().ok())
            .map(|body| parse_docker_hub_tags_json(&body))
            .unwrap_or_default()
    } else {
        fetch_oci_v2_tags(&registry, &repo).unwrap_or_default()
    };
    if items.is_empty() {
        return read_cached_tsv(&path, None);
    }
    write_cached_tsv(&path, &items);
    Some(items)
}

#[cfg(test)]
mod tests {
    use super::{
        cached_docker_tags, cached_github_releases, normalize_docker_image,
        parse_docker_hub_tags_json, parse_github_releases_json, parse_tag_version,
        write_cached_tsv,
    };

    #[test]
    fn parses_action_and_docker_tags_and_roundtrips_cache() {
        assert_eq!(
            parse_tag_version("v4.2.2"),
            Some((semver::Version::new(4, 2, 2), String::new()))
        );
        assert_eq!(
            parse_tag_version("v5"),
            Some((semver::Version::new(5, 0, 0), String::new()))
        );
        assert_eq!(
            parse_tag_version("1.85-slim-bookworm"),
            Some((semver::Version::new(1, 85, 0), "-slim-bookworm".to_owned()))
        );
        assert_eq!(
            normalize_docker_image("rust"),
            ("docker.io".to_owned(), "library/rust".to_owned())
        );
        assert_eq!(
            normalize_docker_image("ghcr.io/harpelm/cargoscope"),
            ("ghcr.io".to_owned(), "harpelm/cargoscope".to_owned())
        );

        let gh = parse_github_releases_json(
            r#"[
              {"tag_name":"v4.2.2","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"},
              {"tag_name":"v5.0.0-rc.1","draft":false,"prerelease":true,"published_at":"2026-11-20T00:00:00Z"}
            ]"#,
        );
        assert_eq!(gh.len(), 1);
        assert_eq!(gh[0].tag, "v4.2.2");
        assert!(gh[0].published_unix.is_some());

        let docker = parse_docker_hub_tags_json(
            r#"{"results":[{"name":"1.85.0-slim","tag_last_pushed":"2026-10-15T12:00:00Z","digest":"sha256:abc"}]}"#,
        );
        assert_eq!(docker.len(), 1);
        assert_eq!(docker[0].digest.as_deref(), Some("sha256:abc"));

        let dir = std::env::temp_dir().join(format!("cargoscope-eco-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_cached_tsv(&super::github_cache_path(&dir, "actions/checkout"), &gh);
        write_cached_tsv(&super::docker_cache_path(&dir, "rust"), &docker);
        assert_eq!(cached_github_releases(&dir, "actions/checkout"), Some(gh));
        assert_eq!(cached_docker_tags(&dir, "rust"), Some(docker));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
