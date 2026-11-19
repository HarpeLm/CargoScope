//! Advisories from OSV (<https://osv.dev>) that RustSec does not have: GitHub
//! security advisories (`GHSA-…`) and malicious crates (`MAL-…`).
//!
//! [`update`] downloads the crates.io export of OSV, a zip of one JSON file
//! per advisory, and keeps only entries that no RustSec advisory covers (an
//! OSV entry is the same issue when its ID or one of its aliases is an alias
//! of a RustSec advisory). Scans read the result offline, after RustSec.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cargoscope_core::{AdvisoryFinding, AdvisoryKind, AdvisoryRelevance, Severity};

use crate::{AdvisoryError, UpdateSummary, io_error};

/// Where the crates.io export of OSV is downloaded from.
pub const DEFAULT_OSV_URL: &str =
    "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip";

pub(crate) const OSV_DIR: &str = "osv";
const FETCHED_AT_FILE: &str = "fetched-at";
const MAX_ZIP_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 1024 * 1024;

/// Downloads the OSV crates.io export from `url` into `cache_dir`.
///
/// The previous data is replaced only after the new one is fully written.
pub fn update(cache_dir: &Path, url: &str) -> Result<UpdateSummary, AdvisoryError> {
    let agent = crate::proxy::agent(url, None, None).map_err(AdvisoryError::Download)?;
    let response = agent
        .get(url)
        .call()
        .map_err(|error| AdvisoryError::Download(error.to_string()))?;
    let mut archive = Vec::new();
    response
        .into_reader()
        .take(MAX_ZIP_BYTES + 1)
        .read_to_end(&mut archive)
        .map_err(|error| AdvisoryError::Download(error.to_string()))?;
    if archive.len() as u64 > MAX_ZIP_BYTES {
        return Err(AdvisoryError::ArchiveTooLarge);
    }
    install_zip(cache_dir, &archive)
}

/// Stores the OSV entries of a crates.io export zip that RustSec does not
/// cover, as `osv/crates/<crate>/<ID>.json` in `cache_dir`.
pub fn install_zip(cache_dir: &Path, archive: &[u8]) -> Result<UpdateSummary, AdvisoryError> {
    let entries = read_zip(archive).map_err(AdvisoryError::Download)?;
    let mut parsed: Vec<(String, serde_json::Value, &[u8])> = Vec::new();
    for (name, contents) in &entries {
        if !name.ends_with(".json") {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(contents) else {
            continue;
        };
        let Some(id) = value.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if is_safe_name(id) {
            parsed.push((id.to_owned(), value, contents));
        }
    }

    // Every ID a RustSec entry names: those issues already come from RustSec.
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for (id, value, _) in &parsed {
        if id.starts_with("RUSTSEC-") {
            covered.insert(id.clone());
            covered.extend(ids(value, "aliases"));
            covered.extend(ids(value, "related"));
        }
    }

    let final_dir = cache_dir.join(OSV_DIR);
    let staging = cache_dir.join(format!("{OSV_DIR}.partial"));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(io_error(&staging))?;
    }
    fs::create_dir_all(staging.join("crates")).map_err(io_error(&staging))?;

    let mut count = 0;
    for (id, value, contents) in &parsed {
        if id.starts_with("RUSTSEC-")
            || value.get("withdrawn").is_some()
            || covered.contains(id)
            || ids(value, "aliases")
                .iter()
                .any(|alias| covered.contains(alias))
        {
            continue;
        }
        let crates: BTreeSet<&str> = value
            .get("affected")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|affected| affected.get("package"))
            .filter(|package| {
                package.get("ecosystem").and_then(serde_json::Value::as_str) == Some("crates.io")
            })
            .filter_map(|package| package.get("name").and_then(serde_json::Value::as_str))
            .filter(|name| is_safe_name(name))
            .collect();
        if crates.is_empty() {
            continue;
        }
        for name in crates {
            let dir = staging.join("crates").join(name);
            fs::create_dir_all(&dir).map_err(io_error(&dir))?;
            let target = dir.join(format!("{id}.json"));
            fs::write(&target, contents).map_err(io_error(&target))?;
        }
        count += 1;
    }

    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let stamp = staging.join(FETCHED_AT_FILE);
    fs::write(&stamp, seconds.to_string()).map_err(io_error(&stamp))?;
    if final_dir.exists() {
        fs::remove_dir_all(&final_dir).map_err(io_error(&final_dir))?;
    }
    fs::rename(&staging, &final_dir).map_err(io_error(&final_dir))?;
    Ok(UpdateSummary {
        path: final_dir,
        advisories: count,
    })
}

fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn ids(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// The files of a zip archive (stored or deflated entries, no ZIP64), each
/// at most [`MAX_ENTRY_BYTES`] once decompressed.
fn read_zip(archive: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let u16_at = |at: usize| -> Result<usize, String> {
        archive
            .get(at..at + 2)
            .map(|bytes| usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
            .ok_or_else(|| "truncated zip archive".to_owned())
    };
    let u32_at = |at: usize| -> Result<usize, String> {
        archive
            .get(at..at + 4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
            .ok_or_else(|| "truncated zip archive".to_owned())
    };
    // End of central directory: the last record with its signature.
    let search_from = archive.len().saturating_sub(22 + 65_535);
    let end = (search_from..archive.len().saturating_sub(21))
        .rev()
        .find(|&at| archive[at..at + 4] == [0x50, 0x4b, 0x05, 0x06])
        .ok_or_else(|| "not a zip archive".to_owned())?;
    let count = u16_at(end + 10)?;
    let mut at = u32_at(end + 16)?;

    let mut files = Vec::with_capacity(count);
    for _ in 0..count {
        if archive.get(at..at + 4) != Some(&[0x50, 0x4b, 0x01, 0x02]) {
            return Err("damaged zip central directory".to_owned());
        }
        let method = u16_at(at + 10)?;
        let compressed = u32_at(at + 20)?;
        let name_len = u16_at(at + 28)?;
        let extra_len = u16_at(at + 30)?;
        let comment_len = u16_at(at + 32)?;
        let local = u32_at(at + 42)?;
        let name = archive
            .get(at + 46..at + 46 + name_len)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .ok_or_else(|| "truncated zip archive".to_owned())?;
        at += 46 + name_len + extra_len + comment_len;

        if archive.get(local..local + 4) != Some(&[0x50, 0x4b, 0x03, 0x04]) {
            return Err("damaged zip entry".to_owned());
        }
        let start = local + 30 + u16_at(local + 26)? + u16_at(local + 28)?;
        let Some(data) = archive.get(start..start + compressed) else {
            return Err("truncated zip entry".to_owned());
        };
        let mut contents = Vec::new();
        let read = match method {
            0 => data.take(MAX_ENTRY_BYTES + 1).read_to_end(&mut contents),
            8 => flate2::read::DeflateDecoder::new(data)
                .take(MAX_ENTRY_BYTES + 1)
                .read_to_end(&mut contents),
            _ => continue,
        };
        if read.is_err() || contents.len() as u64 > MAX_ENTRY_BYTES {
            continue;
        }
        files.push((name, contents));
    }
    Ok(files)
}

/// The OSV advisories stored for a crate.
pub(crate) fn crate_files(root: &Path, name: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root.join("crates").join(name)) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
}

/// A parsed OSV advisory, for one crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OsvAdvisory {
    pub(crate) id: String,
    pub(crate) aliases: Vec<String>,
    title: String,
    date: String,
    severity: Option<Severity>,
    withdrawn: bool,
    malicious: bool,
    /// Affected ranges: (introduced, fixed, last affected) events in order.
    ranges: Vec<Vec<Event>>,
    versions: Vec<String>,
    fixed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Introduced(Option<semver::Version>),
    Fixed(semver::Version),
    LastAffected(semver::Version),
}

impl OsvAdvisory {
    /// Parses an OSV entry, keeping what concerns the crate `name`.
    pub(crate) fn parse(text: &str, name: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(text).ok()?;
        let id = value.get("id")?.as_str()?.to_owned();
        let string = |key: &str| value.get(key).and_then(serde_json::Value::as_str);
        let mut ranges = Vec::new();
        let mut versions = Vec::new();
        let mut fixed = Vec::new();
        for affected in value
            .get("affected")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let package = affected.get("package");
            let field = |key: &str| {
                package
                    .and_then(|package| package.get(key))
                    .and_then(serde_json::Value::as_str)
            };
            if field("ecosystem") != Some("crates.io") || field("name") != Some(name) {
                continue;
            }
            versions.extend(ids(affected, "versions"));
            for range in affected
                .get("ranges")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                if range.get("type").and_then(serde_json::Value::as_str) != Some("SEMVER") {
                    continue;
                }
                let mut events = Vec::new();
                for event in range
                    .get("events")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let version = |key: &str| {
                        event
                            .get(key)
                            .and_then(serde_json::Value::as_str)
                            .map(|text| semver::Version::parse(text.trim_start_matches('v')))
                    };
                    if let Some(introduced) = event.get("introduced").and_then(|v| v.as_str()) {
                        if introduced == "0" {
                            events.push(Event::Introduced(None));
                        } else if let Some(Ok(version)) = version("introduced") {
                            events.push(Event::Introduced(Some(version)));
                        }
                    } else if let Some(Ok(version)) = version("fixed") {
                        fixed.push(version.to_string());
                        events.push(Event::Fixed(version));
                    } else if let Some(Ok(version)) = version("last_affected") {
                        events.push(Event::LastAffected(version));
                    }
                }
                ranges.push(events);
            }
        }

        let severity = value
            .get("severity")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("score").and_then(serde_json::Value::as_str))
            .find_map(crate::severity_from_cvss)
            .or_else(|| {
                let label = value
                    .get("database_specific")
                    .and_then(|specific| specific.get("severity"))
                    .and_then(serde_json::Value::as_str)?;
                Some(match label.to_ascii_uppercase().as_str() {
                    "LOW" => Severity::Low,
                    "MODERATE" | "MEDIUM" => Severity::Medium,
                    "HIGH" => Severity::High,
                    "CRITICAL" => Severity::Critical,
                    _ => return None,
                })
            });
        let malicious = id.starts_with("MAL-");
        let title = string("summary")
            .map(str::to_owned)
            .or_else(|| {
                string("details")
                    .and_then(|details| details.lines().find(|line| !line.trim().is_empty()))
                    .map(|line| line.trim().chars().take(120).collect())
            })
            .unwrap_or_else(|| id.clone());
        let date = string("published")
            .or_else(|| string("modified"))
            .and_then(|stamp| stamp.get(..10))
            .filter(|day| {
                day.len() == 10
                    && day.char_indices().all(|(at, c)| {
                        if at == 4 || at == 7 {
                            c == '-'
                        } else {
                            c.is_ascii_digit()
                        }
                    })
            })
            .unwrap_or("")
            .to_owned();
        fixed.sort();
        fixed.dedup();
        Some(Self {
            aliases: ids(&value, "aliases"),
            title,
            date,
            severity: if malicious {
                Some(Severity::Critical)
            } else {
                severity
            },
            withdrawn: value.get("withdrawn").is_some(),
            malicious,
            ranges,
            versions,
            fixed,
            id,
        })
    }

    pub(crate) fn is_withdrawn(&self) -> bool {
        self.withdrawn
    }

    /// Whether `version` is affected, as OSV defines its SEMVER ranges.
    pub(crate) fn affects(&self, version: &semver::Version) -> bool {
        use std::cmp::Ordering;
        if self.versions.iter().any(|listed| {
            semver::Version::parse(listed)
                .is_ok_and(|listed| listed.cmp_precedence(version) == Ordering::Equal)
        }) {
            return true;
        }
        self.ranges.iter().any(|events| {
            let mut inside = false;
            for event in events {
                match event {
                    Event::Introduced(None) => inside = true,
                    Event::Introduced(Some(start)) => {
                        if version.cmp_precedence(start) != Ordering::Less {
                            inside = true;
                        }
                    }
                    Event::Fixed(end) => {
                        if version.cmp_precedence(end) != Ordering::Less {
                            inside = false;
                        }
                    }
                    Event::LastAffected(end) => {
                        if version.cmp_precedence(end) == Ordering::Greater {
                            inside = false;
                        }
                    }
                }
            }
            inside
        })
    }

    pub(crate) fn into_finding(self, package: usize) -> AdvisoryFinding {
        let url = if self.id.starts_with("GHSA-") {
            format!("https://github.com/advisories/{}", self.id)
        } else {
            format!("https://osv.dev/vulnerability/{}", self.id)
        };
        let title = if self.malicious && !self.title.to_ascii_lowercase().contains("malicious") {
            format!("Malicious crate: {}", self.title)
        } else {
            self.title
        };
        AdvisoryFinding {
            package,
            id: self.id,
            aliases: self.aliases,
            title,
            date: self.date,
            url: Some(url),
            kind: AdvisoryKind::Vulnerability,
            severity: self.severity,
            patched: self
                .fixed
                .iter()
                .map(|version| format!(">= {version}"))
                .collect(),
            affected_arch: Vec::new(),
            affected_os: Vec::new(),
            affected_functions: Vec::new(),
            relevance: AdvisoryRelevance::AffectsYou,
            relevance_reason: None,
            ignored: None,
        }
    }
}

/// Fetch date of the stored OSV data, as `YYYY-MM-DD`.
pub(crate) fn fetched_on(root: &Path) -> Option<String> {
    fs::read_to_string(root.join(FETCHED_AT_FILE))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .map(crate::utc_date)
}

#[cfg(test)]
mod tests {
    use super::{OsvAdvisory, install_zip, read_zip};

    /// A zip archive of stored (uncompressed) entries.
    fn zip(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, contents) in entries {
            let offset = out.len() as u32;
            let size = contents.len() as u32;
            let header = |signature: [u8; 4], central: bool| {
                let mut bytes = signature.to_vec();
                if central {
                    bytes.extend_from_slice(&[20, 0]);
                }
                bytes.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                bytes.extend_from_slice(&size.to_le_bytes());
                bytes.extend_from_slice(&size.to_le_bytes());
                bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&[0, 0]);
                if central {
                    bytes.extend_from_slice(&[0; 10]);
                    bytes.extend_from_slice(&offset.to_le_bytes());
                }
                bytes.extend_from_slice(name.as_bytes());
                bytes
            };
            out.extend(header([0x50, 0x4b, 0x03, 0x04], false));
            out.extend_from_slice(contents.as_bytes());
            central.extend(header([0x50, 0x4b, 0x01, 0x02], true));
        }
        let central_offset = out.len() as u32;
        let central_size = central.len() as u32;
        out.extend(central);
        out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&central_size.to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    fn entry(id: &str, aliases: &[&str], name: &str, events: &str) -> String {
        format!(
            r#"{{"id":"{id}","aliases":{aliases:?},"summary":"{id} summary","published":"2026-11-01T00:00:00Z","affected":[{{"package":{{"ecosystem":"crates.io","name":"{name}"}},"ranges":[{{"type":"SEMVER","events":{events}}}]}}]}}"#
        )
    }

    fn version(text: &str) -> semver::Version {
        semver::Version::parse(text).expect("valid version")
    }

    #[test]
    fn reads_stored_zip_entries() {
        let archive = zip(&[("a.json", "{}"), ("b.json", "[1]")]);
        let files = read_zip(&archive).expect("zip reads");
        assert_eq!(files.len(), 2);
        assert_eq!(files[1], ("b.json".to_owned(), b"[1]".to_vec()));
        assert!(read_zip(b"not a zip").is_err());
    }

    #[test]
    fn keeps_only_advisories_rustsec_does_not_cover() {
        let rustsec = entry(
            "RUSTSEC-2026-0001",
            &["GHSA-aaaa-aaaa-aaaa", "CVE-2026-1"],
            "demo",
            r#"[{"introduced":"0"},{"fixed":"1.0.0"}]"#,
        );
        let same_issue = entry(
            "GHSA-bbbb-bbbb-bbbb",
            &["CVE-2026-1"],
            "demo",
            r#"[{"introduced":"0"},{"fixed":"1.0.0"}]"#,
        );
        let aliased = entry(
            "GHSA-aaaa-aaaa-aaaa",
            &[],
            "demo",
            r#"[{"introduced":"0"}]"#,
        );
        let github_only = entry(
            "GHSA-cccc-cccc-cccc",
            &["CVE-2026-2"],
            "demo",
            r#"[{"introduced":"0.5.0"},{"fixed":"0.9.1"}]"#,
        );
        let malicious = entry("MAL-2026-1", &[], "evil-crate", r#"[{"introduced":"0"}]"#);
        let withdrawn = entry(
            "GHSA-dddd-dddd-dddd",
            &[],
            "demo",
            r#"[{"introduced":"0"}]"#,
        )
        .replacen('{', r#"{"withdrawn":"2026-11-02T00:00:00Z","#, 1);
        let archive = zip(&[
            ("RUSTSEC-2026-0001.json", &rustsec),
            ("GHSA-bbbb-bbbb-bbbb.json", &same_issue),
            ("GHSA-aaaa-aaaa-aaaa.json", &aliased),
            ("GHSA-cccc-cccc-cccc.json", &github_only),
            ("MAL-2026-1.json", &malicious),
            ("GHSA-dddd-dddd-dddd.json", &withdrawn),
            ("../escape.json", "{}"),
        ]);
        let cache =
            std::env::temp_dir().join(format!("cargoscope-osv-install-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        let summary = install_zip(&cache, &archive).expect("installs");
        assert_eq!(summary.advisories, 2);
        let stored = |name: &str| {
            let mut ids: Vec<String> = std::fs::read_dir(cache.join("osv/crates").join(name))
                .map(|entries| {
                    entries
                        .filter_map(Result::ok)
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            ids.sort();
            ids
        };
        assert_eq!(stored("demo"), ["GHSA-cccc-cccc-cccc.json"]);
        assert_eq!(stored("evil-crate"), ["MAL-2026-1.json"]);
        let _ = std::fs::remove_dir_all(&cache);
    }

    #[test]
    fn matches_osv_semver_ranges_and_listed_versions() {
        let text = entry(
            "GHSA-cccc-cccc-cccc",
            &[],
            "demo",
            r#"[{"introduced":"0.5.0"},{"fixed":"0.9.1"},{"introduced":"1.2.0"},{"last_affected":"1.3.0"}]"#,
        );
        let advisory = OsvAdvisory::parse(&text, "demo").expect("parses");
        for affected in ["0.5.0", "0.9.0", "1.2.0", "1.3.0"] {
            assert!(advisory.affects(&version(affected)), "{affected}");
        }
        for safe in ["0.4.9", "0.9.1", "1.0.0", "1.3.1"] {
            assert!(!advisory.affects(&version(safe)), "{safe}");
        }
        // Another crate of the same entry is not this crate's range.
        assert!(
            !OsvAdvisory::parse(&text, "other")
                .expect("parses")
                .affects(&version("0.6.0"))
        );
        let finding = advisory.into_finding(3);
        assert_eq!(finding.patched, [">= 0.9.1"]);
        assert_eq!(finding.date, "2026-11-01");
        assert_eq!(
            finding.url.as_deref(),
            Some("https://github.com/advisories/GHSA-cccc-cccc-cccc")
        );
    }

    #[test]
    fn malicious_crates_are_critical() {
        let text = entry("MAL-2026-1", &[], "evil-crate", r#"[{"introduced":"0"}]"#);
        let finding = OsvAdvisory::parse(&text, "evil-crate")
            .expect("parses")
            .into_finding(0);
        assert_eq!(finding.severity, Some(cargoscope_core::Severity::Critical));
        assert!(finding.title.starts_with("Malicious crate: "));
    }
}
