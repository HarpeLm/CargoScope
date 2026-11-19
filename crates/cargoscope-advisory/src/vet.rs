//! Audits that organisations publish with cargo-vet
//! (<https://mozilla.github.io/cargo-vet/>): which crate versions Mozilla,
//! Google, the Bytecode Alliance and others reviewed, and to which criteria.
//!
//! [`update`] downloads the cargo-vet registry of published audit files, then
//! each file, and stores every audited version as one line of
//! `vet/audited.tsv`: `crate \t version \t organisation \t criteria`. A
//! version counts as audited when an organisation reviewed it in full, or
//! reviewed the changes (`delta`) from a version it had audited before.
//! Scans read the file offline.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use cargoscope_core::{Audit, AuditCriteria};

use crate::{AdvisoryError, io_error};

/// The cargo-vet registry of organisations that publish their audits.
pub const DEFAULT_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/mozilla/cargo-vet/main/registry.toml";

const DIR: &str = "vet";
const FILE: &str = "audited.tsv";
const FETCHED_AT_FILE: &str = "fetched-at";
const MAX_REGISTRY_BYTES: u64 = 1024 * 1024;
const MAX_AUDITS_BYTES: u64 = 32 * 1024 * 1024;

/// Summary of an audit update.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VetSummary {
    /// Organisations whose audits were downloaded.
    pub organisations: Vec<String>,
    /// Crate versions audited by at least one of them.
    pub versions: usize,
    /// Organisations whose audits could not be downloaded or read.
    pub failures: Vec<String>,
}

/// Downloads the published audits listed by the registry at `registry_url`.
pub fn update(cache_dir: &Path, registry_url: &str) -> Result<VetSummary, AdvisoryError> {
    let registry = fetch(registry_url, MAX_REGISTRY_BYTES)?;
    let registry: toml::Value = toml::from_str(&registry)
        .map_err(|error| AdvisoryError::Download(format!("cargo-vet registry: {error}")))?;
    let mut summary = VetSummary::default();
    let mut audited: BTreeMap<(String, String), BTreeMap<String, AuditCriteria>> = BTreeMap::new();
    let entries = registry
        .get("registry")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    for (organisation, entry) in entries {
        let Some(url) = entry.get("url").and_then(toml::Value::as_str) else {
            continue;
        };
        if !is_safe(&organisation) || !url.starts_with("https://") {
            continue;
        }
        let audits = fetch(url, MAX_AUDITS_BYTES)
            .map_err(|error| error.to_string())
            .and_then(|text| toml::from_str::<toml::Value>(&text).map_err(|e| e.to_string()));
        match audits {
            Ok(audits) => {
                for (name, version, criteria) in audited_versions(&audits) {
                    let best = audited
                        .entry((name, version))
                        .or_default()
                        .entry(organisation.clone())
                        .or_insert(criteria);
                    *best = (*best).max(criteria);
                }
                summary.organisations.push(organisation);
            }
            Err(error) => summary.failures.push(format!("{organisation}: {error}")),
        }
    }
    if summary.organisations.is_empty() {
        return Err(AdvisoryError::Download(
            "no published audit could be downloaded".to_owned(),
        ));
    }

    let mut text = String::new();
    for ((name, version), by) in &audited {
        for (organisation, criteria) in by {
            text.push_str(&format!(
                "{name}\t{version}\t{organisation}\t{}\n",
                criteria.as_str()
            ));
        }
    }
    summary.versions = audited.len();

    let final_dir = cache_dir.join(DIR);
    let staging = cache_dir.join(format!("{DIR}.partial"));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(io_error(&staging))?;
    }
    fs::create_dir_all(&staging).map_err(io_error(&staging))?;
    let target = staging.join(FILE);
    fs::write(&target, text).map_err(io_error(&target))?;
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let stamp = staging.join(FETCHED_AT_FILE);
    fs::write(&stamp, seconds.to_string()).map_err(io_error(&stamp))?;
    if final_dir.exists() {
        fs::remove_dir_all(&final_dir).map_err(io_error(&final_dir))?;
    }
    fs::rename(&staging, &final_dir).map_err(io_error(&final_dir))?;
    Ok(summary)
}

fn fetch(url: &str, limit: u64) -> Result<String, AdvisoryError> {
    let timeout = Some(std::time::Duration::from_secs(60));
    let agent = crate::proxy::agent(url, timeout, Some(crate::crates_io::USER_AGENT))
        .map_err(AdvisoryError::Download)?;
    let response = agent
        .get(url)
        .call()
        .map_err(|error| AdvisoryError::Download(error.to_string()))?;
    let mut text = String::new();
    response
        .into_reader()
        .take(limit + 1)
        .read_to_string(&mut text)
        .map_err(|error| AdvisoryError::Download(error.to_string()))?;
    if text.len() as u64 > limit {
        return Err(AdvisoryError::ArchiveTooLarge);
    }
    Ok(text)
}

fn is_safe(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
}

/// The best standard criteria an audit entry certifies, if any: custom
/// criteria (Google's `ub-risk-…`, say) alone certify neither.
fn entry_criteria(entry: &toml::Value) -> Option<AuditCriteria> {
    let names: Vec<&str> = match entry.get("criteria")? {
        toml::Value::String(name) => vec![name.as_str()],
        toml::Value::Array(names) => names.iter().filter_map(toml::Value::as_str).collect(),
        _ => return None,
    };
    if names.contains(&"safe-to-deploy") {
        Some(AuditCriteria::SafeToDeploy)
    } else if names.contains(&"safe-to-run") {
        Some(AuditCriteria::SafeToRun)
    } else {
        None
    }
}

/// Every (crate, version, criteria) an audits file certifies: full audits,
/// and versions reached by a chain of delta audits from one, each step at
/// least at the criteria.
fn audited_versions(audits: &toml::Value) -> Vec<(String, String, AuditCriteria)> {
    let mut out = Vec::new();
    let Some(crates) = audits.get("audits").and_then(toml::Value::as_table) else {
        return out;
    };
    for (name, entries) in crates {
        if !is_safe(name) {
            continue;
        }
        let entries = entries.as_array().map(Vec::as_slice).unwrap_or_default();
        for level in [AuditCriteria::SafeToRun, AuditCriteria::SafeToDeploy] {
            let mut full: BTreeSet<String> = BTreeSet::new();
            let mut deltas: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for entry in entries {
                if entry_criteria(entry).is_none_or(|criteria| criteria < level) {
                    continue;
                }
                if let Some(version) = entry.get("version").and_then(toml::Value::as_str) {
                    full.insert(version.trim().to_owned());
                } else if let Some((from, to)) = entry
                    .get("delta")
                    .and_then(toml::Value::as_str)
                    .and_then(|delta| delta.split_once("->"))
                {
                    deltas
                        .entry(from.trim().to_owned())
                        .or_default()
                        .push(to.trim().to_owned());
                }
            }
            let mut reached: BTreeSet<String> = full.clone();
            let mut queue: VecDeque<String> = full.into_iter().collect();
            while let Some(version) = queue.pop_front() {
                for next in deltas.get(&version).into_iter().flatten() {
                    if reached.insert(next.clone()) {
                        queue.push_back(next.clone());
                    }
                }
            }
            for version in reached {
                if is_safe(&version) {
                    out.push((name.clone(), version, level));
                }
            }
        }
    }
    out
}

/// Published audits read from the cache.
#[derive(Debug, Clone, Default)]
pub struct Audits {
    by_version: BTreeMap<(String, String), Vec<Audit>>,
    /// Organisations with at least one audit, sorted.
    pub organisations: Vec<String>,
    /// When the audits were downloaded, as `YYYY-MM-DD`.
    pub fetched_on: Option<String>,
}

impl Audits {
    /// Reads the audits stored in `cache_dir`; `None` before the first
    /// update that downloaded them.
    #[must_use]
    pub fn open(cache_dir: &Path) -> Option<Self> {
        let root = cache_dir.join(DIR);
        let text = fs::read_to_string(root.join(FILE)).ok()?;
        let mut audits = Self {
            fetched_on: fs::read_to_string(root.join(FETCHED_AT_FILE))
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
                .map(crate::utc_date),
            ..Self::default()
        };
        let mut organisations = BTreeSet::new();
        for line in text.lines() {
            let mut fields = line.split('\t');
            let (Some(name), Some(version), Some(by), Some(criteria)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let criteria = match criteria {
                "safe-to-deploy" => AuditCriteria::SafeToDeploy,
                "safe-to-run" => AuditCriteria::SafeToRun,
                _ => continue,
            };
            organisations.insert(by.to_owned());
            audits
                .by_version
                .entry((name.to_owned(), version.to_owned()))
                .or_default()
                .push(Audit {
                    by: by.to_owned(),
                    criteria,
                });
        }
        audits.organisations = organisations.into_iter().collect();
        Some(audits)
    }

    /// The audits of one crate version, best criteria first.
    #[must_use]
    pub fn of(&self, name: &str, version: &str) -> Vec<Audit> {
        let mut audits = self
            .by_version
            .get(&(name.to_owned(), version.to_owned()))
            .cloned()
            .unwrap_or_default();
        audits.sort_by(|left, right| {
            right
                .criteria
                .cmp(&left.criteria)
                .then(left.by.cmp(&right.by))
        });
        audits
    }
}

#[cfg(test)]
mod tests {
    use super::{Audits, audited_versions};
    use cargoscope_core::AuditCriteria;

    #[test]
    fn follows_delta_chains_from_full_audits() {
        let audits: toml::Value = toml::from_str(
            r#"
            [[audits.demo]]
            who = "a"
            criteria = "safe-to-deploy"
            version = "1.0.0"

            [[audits.demo]]
            who = "a"
            criteria = "safe-to-deploy"
            delta = "1.0.0 -> 1.1.0"

            [[audits.demo]]
            who = "a"
            criteria = "safe-to-run"
            delta = "1.1.0 -> 1.2.0"

            [[audits.demo]]
            who = "a"
            criteria = "safe-to-deploy"
            delta = "2.0.0 -> 2.1.0"

            [[audits.other]]
            who = "b"
            criteria = ["safe-to-deploy", "does-not-implement-crypto"]
            version = "0.3.0"

            [[audits.custom]]
            who = "c"
            criteria = "ub-risk-2"
            version = "1.0.0"
            "#,
        )
        .expect("valid TOML");
        let mut found = audited_versions(&audits);
        found.sort();
        let expect =
            |name: &str, version: &str, criteria| (name.to_owned(), version.to_owned(), criteria);
        assert_eq!(
            found,
            [
                expect("demo", "1.0.0", AuditCriteria::SafeToRun),
                expect("demo", "1.0.0", AuditCriteria::SafeToDeploy),
                expect("demo", "1.1.0", AuditCriteria::SafeToRun),
                expect("demo", "1.1.0", AuditCriteria::SafeToDeploy),
                // Reached only through a safe-to-run delta.
                expect("demo", "1.2.0", AuditCriteria::SafeToRun),
                expect("other", "0.3.0", AuditCriteria::SafeToRun),
                expect("other", "0.3.0", AuditCriteria::SafeToDeploy),
            ]
        );
    }

    #[test]
    fn reads_stored_audits() {
        let cache =
            std::env::temp_dir().join(format!("cargoscope-vet-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        std::fs::create_dir_all(cache.join("vet")).expect("create cache");
        std::fs::write(
            cache.join("vet/audited.tsv"),
            "demo\t1.0.0\tgoogle\tsafe-to-run\ndemo\t1.0.0\tmozilla\tsafe-to-deploy\nbad line\n",
        )
        .expect("write audits");
        let audits = Audits::open(&cache).expect("audits open");
        assert_eq!(audits.organisations, ["google", "mozilla"]);
        let found = audits.of("demo", "1.0.0");
        assert_eq!(found[0].by, "mozilla");
        assert_eq!(found[0].criteria, AuditCriteria::SafeToDeploy);
        assert_eq!(found.len(), 2);
        assert!(audits.of("demo", "2.0.0").is_empty());
        let _ = std::fs::remove_dir_all(&cache);
    }
}
