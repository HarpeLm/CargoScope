//! crates.io data: available versions, yanked status and licenses.
//!
//! [`refresh`] is called only by `cargoscope update`. It downloads the sparse
//! index entry of every crates.io package in an inventory and finds licenses,
//! first in the local Cargo registry sources (no network), then through the
//! crates.io API at most once per second, as its crawler policy asks.
//! [`RegistryCache::info`] reads only the local cache.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cargoscope_core::{Inventory, PackageInfo};

use crate::{AdvisoryError, io_error, utc_date};

const DIR: &str = "crates-io";
const FETCHED_AT_FILE: &str = "fetched-at";
const INDEX_URL: &str = "https://index.crates.io";
const API_URL: &str = "https://crates.io/api/v1/crates";
const USER_AGENT: &str = concat!(
    "cargoscope/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/HarpeLm/CargoScope)"
);
const MAX_INDEX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_API_BYTES: u64 = 4 * 1024 * 1024;
const API_INTERVAL: Duration = Duration::from_secs(1);
const NO_LICENSE: &str = "";

/// Returns whether a Cargo source is crates.io.
#[must_use]
pub fn is_crates_io(source: Option<&str>) -> bool {
    source.is_some_and(|source| crate::CRATES_IO_SOURCES.contains(&source))
}

/// Sparse index path of a crate, as defined by Cargo.
fn index_path(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

/// Crate names are restricted to ASCII alphanumerics, `-` and `_`; anything
/// else is refused before it reaches a URL or a file name.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn is_valid_version(version: &str) -> bool {
    semver::Version::parse(version).is_ok()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// One published version, as stored in the cache: `version \t yanked \t date`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedVersion {
    version: String,
    yanked: bool,
    published: Option<String>,
}

fn parse_index(text: &str) -> Vec<PublishedVersion> {
    text.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|entry| {
            let version = entry.get("vers")?.as_str()?.to_owned();
            is_valid_version(&version).then(|| PublishedVersion {
                version,
                yanked: entry
                    .get("yanked")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                published: entry
                    .get("pubtime")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|time| time.get(..10))
                    .map(str::to_owned),
            })
        })
        .collect()
}

fn format_versions(versions: &[PublishedVersion]) -> String {
    versions
        .iter()
        .map(|version| {
            format!(
                "{}\t{}\t{}\n",
                version.version,
                version.yanked,
                version.published.as_deref().unwrap_or("")
            )
        })
        .collect()
}

fn read_versions(text: &str) -> Vec<PublishedVersion> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let version = fields.next()?.to_owned();
            let yanked = fields.next()? == "true";
            let published = fields
                .next()
                .filter(|date| !date.is_empty())
                .map(str::to_owned);
            is_valid_version(&version).then_some(PublishedVersion {
                version,
                yanked,
                published,
            })
        })
        .collect()
}

/// Latest non-yanked version: stable first, pre-release only if nothing else.
fn latest(versions: &[PublishedVersion]) -> Option<&PublishedVersion> {
    let parse = |version: &PublishedVersion| semver::Version::parse(&version.version).ok();
    let candidates = || versions.iter().filter(|version| !version.yanked);
    candidates()
        .filter(|version| parse(version).is_some_and(|parsed| parsed.pre.is_empty()))
        .max_by_key(|version| parse(version))
        .or_else(|| candidates().max_by_key(|version| parse(version)))
}

/// Summary of a registry refresh.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefreshSummary {
    /// crates.io crates whose versions were downloaded.
    pub crates: usize,
    /// Licenses found in the local Cargo registry sources.
    pub licenses_local: usize,
    /// Licenses fetched from the crates.io API.
    pub licenses_api: usize,
    /// Crates or versions that could not be fetched.
    pub failures: Vec<String>,
}

/// Downloads crates.io data for every crates.io package of `inventory`.
///
/// Licenses are immutable per version: a license already cached is never
/// fetched again. `cargo_home` is used to find local registry sources.
pub fn refresh(
    cache_dir: &Path,
    inventory: &Inventory,
    cargo_home: Option<&Path>,
) -> Result<RefreshSummary, AdvisoryError> {
    let root = cache_dir.join(DIR);
    let versions_dir = root.join("versions");
    let licenses_dir = root.join("licenses");
    for dir in [&versions_dir, &licenses_dir] {
        fs::create_dir_all(dir).map_err(io_error(dir))?;
    }

    let mut wanted: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for package in &inventory.packages {
        if is_crates_io(package.source.as_deref())
            && is_valid_name(&package.name)
            && is_valid_version(&package.version)
        {
            wanted
                .entry(package.name.as_str())
                .or_default()
                .push(package.version.as_str());
        }
    }

    let agent = ureq::AgentBuilder::new()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build();
    let mut summary = RefreshSummary::default();
    let local_sources = local_registry_sources(cargo_home);
    let mut last_api_call: Option<Instant> = None;

    for (name, versions) in wanted {
        let url = format!("{INDEX_URL}/{}", index_path(name));
        match fetch_text(&agent, &url, MAX_INDEX_BYTES) {
            Ok(text) => {
                let target = versions_dir.join(name);
                fs::write(&target, format_versions(&parse_index(&text)))
                    .map_err(io_error(&target))?;
                summary.crates += 1;
            }
            Err(error) => summary.failures.push(format!("{name}: {error}")),
        }

        for version in versions {
            let target = licenses_dir.join(format!("{name}-{version}"));
            if target.is_file() {
                continue;
            }
            let license = if let Some(license) = local_license(&local_sources, name, version) {
                summary.licenses_local += 1;
                Some(license)
            } else {
                if let Some(previous) = last_api_call {
                    let elapsed = previous.elapsed();
                    if elapsed < API_INTERVAL {
                        std::thread::sleep(API_INTERVAL - elapsed);
                    }
                }
                last_api_call = Some(Instant::now());
                match api_license(&agent, name, version) {
                    Ok(license) => {
                        summary.licenses_api += 1;
                        Some(license.unwrap_or_else(|| NO_LICENSE.to_owned()))
                    }
                    Err(error) => {
                        summary
                            .failures
                            .push(format!("{name} {version} license: {error}"));
                        None
                    }
                }
            };
            if let Some(license) = license {
                fs::write(&target, license).map_err(io_error(&target))?;
            }
        }
    }

    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let stamp = root.join(FETCHED_AT_FILE);
    fs::write(&stamp, seconds.to_string()).map_err(io_error(&stamp))?;
    Ok(summary)
}

fn fetch_text(agent: &ureq::Agent, url: &str, limit: u64) -> Result<String, String> {
    let response = agent.get(url).call().map_err(|error| error.to_string())?;
    let mut text = String::new();
    response
        .into_reader()
        .take(limit)
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    Ok(text)
}

fn api_license(agent: &ureq::Agent, name: &str, version: &str) -> Result<Option<String>, String> {
    let text = fetch_text(agent, &format!("{API_URL}/{name}/{version}"), MAX_API_BYTES)?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| error.to_string())?;
    Ok(value
        .get("version")
        .and_then(|version| version.get("license"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned))
}

/// `$CARGO_HOME/registry/src/*` directories, where Cargo unpacks downloaded crates.
fn local_registry_sources(cargo_home: Option<&Path>) -> Vec<PathBuf> {
    let Some(src) = cargo_home.map(|home| home.join("registry").join("src")) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(src) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// Reads the license of `name-version` from an unpacked registry copy.
fn local_license(sources: &[PathBuf], name: &str, version: &str) -> Option<String> {
    sources.iter().find_map(|source| {
        let manifest = source.join(format!("{name}-{version}")).join("Cargo.toml");
        let metadata = fs::symlink_metadata(&manifest).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_API_BYTES {
            return None;
        }
        let value: toml::Value = toml::from_str(&fs::read_to_string(&manifest).ok()?).ok()?;
        let package = value.get("package")?;
        package
            .get("license")
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .or_else(|| package.get("license-file").map(|_| NO_LICENSE.to_owned()))
            .or_else(|| Some(NO_LICENSE.to_owned()))
    })
}

/// Locally cached crates.io data. Never accesses the network.
#[derive(Debug, Clone)]
pub struct RegistryCache {
    root: PathBuf,
    /// When the data was downloaded, as `YYYY-MM-DD` (UTC), if ever.
    pub fetched_on: Option<String>,
}

impl RegistryCache {
    /// Opens the cache in `cache_dir`; it may be empty.
    #[must_use]
    pub fn open(cache_dir: &Path) -> Self {
        let root = cache_dir.join(DIR);
        let fetched_on = fs::read_to_string(root.join(FETCHED_AT_FILE))
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .map(utc_date);
        Self { root, fetched_on }
    }

    /// Registry data for every package of `inventory`, in the same order.
    /// Packages that are not from crates.io get an empty entry.
    #[must_use]
    pub fn info(&self, inventory: &Inventory) -> Vec<PackageInfo> {
        inventory
            .packages
            .iter()
            .map(|package| {
                if !is_crates_io(package.source.as_deref())
                    || !is_valid_name(&package.name)
                    || !is_valid_version(&package.version)
                {
                    return PackageInfo::default();
                }
                let license = fs::read_to_string(
                    self.root
                        .join("licenses")
                        .join(format!("{}-{}", package.name, package.version)),
                )
                .ok()
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty());

                let versions = fs::read_to_string(self.root.join("versions").join(&package.name))
                    .map(|text| read_versions(&text))
                    .unwrap_or_default();
                let yanked = versions
                    .iter()
                    .find(|version| version.version == package.version)
                    .map(|version| version.yanked);
                let newest = latest(&versions);
                let outdated = newest.is_some_and(|newest| {
                    match (
                        semver::Version::parse(&newest.version),
                        semver::Version::parse(&package.version),
                    ) {
                        (Ok(newest), Ok(current)) => newest > current,
                        _ => false,
                    }
                });
                PackageInfo {
                    license,
                    latest_version: newest.map(|version| version.version.clone()),
                    latest_published: newest.and_then(|version| version.published.clone()),
                    yanked,
                    outdated,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PublishedVersion, format_versions, index_path, is_valid_name, latest, parse_index,
        read_versions,
    };

    fn version(text: &str, yanked: bool) -> PublishedVersion {
        PublishedVersion {
            version: text.to_owned(),
            yanked,
            published: None,
        }
    }

    #[test]
    fn computes_sparse_index_paths() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("Serde_JSON"), "se/rd/serde_json");
    }

    #[test]
    fn refuses_unsafe_crate_names() {
        assert!(is_valid_name("serde-json_2"));
        assert!(!is_valid_name("../etc"));
        assert!(!is_valid_name("a/b"));
        assert!(!is_valid_name(""));
    }

    #[test]
    fn parses_index_lines_and_round_trips_the_cache_format() {
        let index = r#"{"name":"x","vers":"1.0.0","yanked":false,"pubtime":"2024-03-04T05:06:07Z"}
{"name":"x","vers":"1.1.0","yanked":true}
not json
{"name":"x","vers":"../bad","yanked":false}"#;
        let versions = parse_index(index);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].published.as_deref(), Some("2024-03-04"));
        assert!(versions[1].yanked);
        assert_eq!(read_versions(&format_versions(&versions)), versions);
    }

    #[test]
    fn latest_skips_yanked_and_prefers_stable() {
        let versions = vec![
            version("1.0.0", false),
            version("1.2.0", true),
            version("1.1.0", false),
            version("2.0.0-beta.1", false),
        ];
        assert_eq!(latest(&versions).map(|v| v.version.as_str()), Some("1.1.0"));
        let only_pre = vec![version("0.1.0-alpha", false), version("0.1.0-beta", false)];
        assert_eq!(
            latest(&only_pre).map(|v| v.version.as_str()),
            Some("0.1.0-beta")
        );
    }
}
