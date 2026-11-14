//! External data: the RustSec advisory database and crates.io metadata,
//! with explicit download, local cache and offline matching.
//!
//! [`update`] is the only function that accesses the network. Scans use
//! [`AdvisoryDatabase::open`] and [`AdvisoryDatabase::check`], which read only
//! the local cache.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use cargoscope_core::{AdvisoryFinding, AdvisoryKind, Inventory, Severity};

pub mod crates_io;

/// Where the RustSec database archive is downloaded from.
pub const DEFAULT_ARCHIVE_URL: &str =
    "https://github.com/rustsec/advisory-db/archive/refs/heads/main.tar.gz";

/// Environment variable overriding the cache directory.
pub const CACHE_DIR_ENV: &str = "CARGOSCOPE_CACHE_DIR";

const DB_DIR: &str = "advisory-db";
const FETCHED_AT_FILE: &str = "fetched-at";
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ADVISORY_BYTES: u64 = 256 * 1024;

/// crates.io sources covered by RustSec.
pub(crate) const CRATES_IO_SOURCES: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// An error while updating or reading the advisory database.
#[derive(Debug)]
pub enum AdvisoryError {
    /// No cache directory could be determined.
    NoCacheDir,
    /// The database has not been downloaded yet.
    Missing { path: PathBuf },
    /// Downloading the archive failed.
    Download(String),
    /// The downloaded archive is larger than allowed.
    ArchiveTooLarge,
    /// The archive contained no advisory.
    EmptyArchive,
    /// A filesystem or decompression error.
    Io { path: PathBuf, source: io::Error },
}

impl fmt::Display for AdvisoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCacheDir => write!(
                formatter,
                "no cache directory found; set {CACHE_DIR_ENV} to choose one"
            ),
            Self::Missing { path } => write!(
                formatter,
                "no advisory database at {}; run `cargoscope update` first",
                path.display()
            ),
            Self::Download(message) => write!(formatter, "download failed: {message}"),
            Self::ArchiveTooLarge => write!(
                formatter,
                "advisory archive exceeds {} MiB",
                MAX_ARCHIVE_BYTES / 1024 / 1024
            ),
            Self::EmptyArchive => write!(formatter, "advisory archive contains no advisory"),
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for AdvisoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) fn io_error(path: &Path) -> impl FnOnce(io::Error) -> AdvisoryError + '_ {
    move |source| AdvisoryError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Returns the CargoScope cache directory.
///
/// Uses `CARGOSCOPE_CACHE_DIR` when set, otherwise the platform cache
/// directory (`~/Library/Caches` on macOS, `%LOCALAPPDATA%` on Windows,
/// `$XDG_CACHE_HOME` or `~/.cache` elsewhere), followed by `cargoscope`.
pub fn cache_dir() -> Result<PathBuf, AdvisoryError> {
    if let Some(dir) = std::env::var_os(CACHE_DIR_ENV).filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let base = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Caches"))
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
    };
    base.map(|base| base.join("cargoscope"))
        .ok_or(AdvisoryError::NoCacheDir)
}

/// Summary of a completed update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSummary {
    /// Directory holding the database.
    pub path: PathBuf,
    /// Number of advisory files stored.
    pub advisories: usize,
}

/// Downloads the RustSec database archive from `url` into `cache_dir`.
///
/// The previous database is replaced only after the new one is fully extracted.
pub fn update(cache_dir: &Path, url: &str) -> Result<UpdateSummary, AdvisoryError> {
    let response = ureq::get(url)
        .call()
        .map_err(|error| AdvisoryError::Download(error.to_string()))?;
    let mut archive = Vec::new();
    response
        .into_reader()
        .take(MAX_ARCHIVE_BYTES + 1)
        .read_to_end(&mut archive)
        .map_err(|error| AdvisoryError::Download(error.to_string()))?;
    if archive.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(AdvisoryError::ArchiveTooLarge);
    }
    install_archive(cache_dir, &archive)
}

/// Extracts a `.tar.gz` RustSec archive into `cache_dir`.
///
/// Only `<root>/crates/<crate>/<file>.md` entries with safe names and a
/// bounded size are kept; everything else in the archive is ignored.
pub fn install_archive(cache_dir: &Path, archive: &[u8]) -> Result<UpdateSummary, AdvisoryError> {
    let final_dir = cache_dir.join(DB_DIR);
    let staging = cache_dir.join(format!("{DB_DIR}.partial"));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(io_error(&staging))?;
    }
    fs::create_dir_all(staging.join("crates")).map_err(io_error(&staging))?;

    let mut count = 0;
    let decoder = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(decoder);
    let entries = tar.entries().map_err(io_error(&staging))?;
    for entry in entries {
        let mut entry = entry.map_err(io_error(&staging))?;
        if !entry.header().entry_type().is_file() || entry.size() > MAX_ADVISORY_BYTES {
            continue;
        }
        let path = entry.path().map_err(io_error(&staging))?.into_owned();
        let Some((crate_name, file_name)) = advisory_entry(&path) else {
            continue;
        };
        let crate_dir = staging.join("crates").join(&crate_name);
        fs::create_dir_all(&crate_dir).map_err(io_error(&crate_dir))?;
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .map_err(io_error(&crate_dir))?;
        let target = crate_dir.join(&file_name);
        fs::write(&target, contents).map_err(io_error(&target))?;
        count += 1;
    }

    if count == 0 {
        let _ = fs::remove_dir_all(&staging);
        return Err(AdvisoryError::EmptyArchive);
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

/// Accepts `<root>/crates/<crate>/<file>.md` with safe names only.
fn advisory_entry(path: &Path) -> Option<(String, String)> {
    let parts: Vec<&str> = path
        .components()
        .map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let [_, "crates", crate_name, file_name] = parts.as_slice() else {
        return None;
    };
    let safe = |name: &str| {
        !name.is_empty()
            && !name.starts_with('.')
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    (safe(crate_name) && safe(file_name) && file_name.ends_with(".md"))
        .then(|| ((*crate_name).to_owned(), (*file_name).to_owned()))
}

/// A locally cached RustSec database.
#[derive(Debug, Clone)]
pub struct AdvisoryDatabase {
    root: PathBuf,
    /// When the database was downloaded, as `YYYY-MM-DD` (UTC).
    pub fetched_on: Option<String>,
}

/// Result of checking an inventory against the database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvisoryCheck {
    /// Advisories affecting resolved packages, sorted by package then ID.
    pub findings: Vec<AdvisoryFinding>,
    /// Advisory files that could not be read or parsed.
    pub unreadable: Vec<PathBuf>,
}

impl AdvisoryDatabase {
    /// Opens the database stored in `cache_dir`. Never accesses the network.
    pub fn open(cache_dir: &Path) -> Result<Self, AdvisoryError> {
        let root = cache_dir.join(DB_DIR);
        if !root.join("crates").is_dir() {
            return Err(AdvisoryError::Missing { path: root });
        }
        let fetched_on = fs::read_to_string(root.join(FETCHED_AT_FILE))
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .map(utc_date);
        Ok(Self { root, fetched_on })
    }

    /// Returns the advisories that affect crates.io packages of `inventory`.
    #[must_use]
    pub fn check(&self, inventory: &Inventory) -> AdvisoryCheck {
        let mut check = AdvisoryCheck::default();

        for (index, package) in inventory.packages.iter().enumerate() {
            let from_crates_io = crates_io::is_crates_io(package.source.as_deref());
            if !from_crates_io {
                continue;
            }
            let Ok(version) = semver::Version::parse(&package.version) else {
                continue;
            };
            let crate_dir = self.root.join("crates").join(&package.name);
            let Ok(entries) = fs::read_dir(&crate_dir) else {
                continue;
            };
            let mut files: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
                .collect();
            files.sort();

            for file in files {
                let parsed = fs::read_to_string(&file)
                    .ok()
                    .and_then(|text| Advisory::parse(&text));
                let Some(advisory) = parsed else {
                    check.unreadable.push(file);
                    continue;
                };
                if advisory.withdrawn || advisory.package != package.name {
                    continue;
                }
                if advisory.affects(&version) {
                    check.findings.push(advisory.into_finding(index));
                }
            }
        }

        check
    }
}

/// A parsed RustSec advisory file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Advisory {
    id: String,
    package: String,
    title: String,
    date: String,
    url: Option<String>,
    aliases: Vec<String>,
    informational: Option<String>,
    severity: Option<Severity>,
    withdrawn: bool,
    patched: Vec<semver::VersionReq>,
    patched_text: Vec<String>,
    unaffected: Vec<semver::VersionReq>,
}

impl Advisory {
    /// Parses the TOML front matter (inside a ```` ```toml ```` block) and the
    /// first `# ` heading, which RustSec uses as the title.
    fn parse(text: &str) -> Option<Self> {
        let start = text.find("```toml")? + "```toml".len();
        let length = text[start..].find("```")?;
        let front_matter = &text[start..start + length];
        let body = &text[start + length + 3..];

        let value: toml::Value = toml::from_str(front_matter).ok()?;
        let advisory = value.get("advisory")?;
        let string = |key: &str| {
            advisory
                .get(key)
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };
        let list = |table: Option<&toml::Value>, key: &str| -> Vec<String> {
            table
                .and_then(|table| table.get(key))
                .and_then(toml::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        let versions = value.get("versions");
        let requirements = |items: &[String]| -> Option<Vec<semver::VersionReq>> {
            items
                .iter()
                .map(|item| semver::VersionReq::parse(item).ok())
                .collect()
        };

        let patched_text = list(versions, "patched");
        let unaffected_text = list(versions, "unaffected");
        let title = body
            .lines()
            .find_map(|line| line.strip_prefix("# "))
            .map(str::trim)
            .map(str::to_owned)
            .or_else(|| string("title"))
            .unwrap_or_default();

        Some(Self {
            id: string("id")?,
            package: string("package")?,
            title,
            date: string("date").unwrap_or_default(),
            url: string("url"),
            aliases: list(Some(advisory), "aliases"),
            informational: string("informational"),
            severity: string("cvss").and_then(|vector| severity_from_cvss(&vector)),
            withdrawn: advisory.get("withdrawn").is_some(),
            patched: requirements(&patched_text)?,
            patched_text,
            unaffected: requirements(&unaffected_text)?,
        })
    }

    fn affects(&self, version: &semver::Version) -> bool {
        let matches = |requirements: &[semver::VersionReq]| {
            requirements
                .iter()
                .any(|requirement| requirement.matches(version))
        };
        !matches(&self.patched) && !matches(&self.unaffected)
    }

    fn into_finding(self, package: usize) -> AdvisoryFinding {
        AdvisoryFinding {
            package,
            id: self.id,
            aliases: self.aliases,
            title: self.title,
            date: self.date,
            url: self.url,
            kind: self
                .informational
                .map_or(AdvisoryKind::Vulnerability, AdvisoryKind::Informational),
            severity: self.severity,
            patched: self.patched_text,
            ignored: None,
        }
    }
}

fn severity_from_cvss(vector: &str) -> Option<Severity> {
    let cvss = cvss::Cvss::from_str(vector).ok()?;
    Some(match cvss.severity() {
        cvss::Severity::None => Severity::None,
        cvss::Severity::Low => Severity::Low,
        cvss::Severity::Medium => Severity::Medium,
        cvss::Severity::High => Severity::High,
        cvss::Severity::Critical => Severity::Critical,
    })
}

/// Converts Unix seconds to a `YYYY-MM-DD` UTC date.
pub(crate) fn utc_date(seconds: u64) -> String {
    // Days-to-civil conversion (Howard Hinnant's algorithm).
    let days = i64::try_from(seconds / 86_400).unwrap_or(0) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::{Advisory, AdvisoryDatabase, advisory_entry, install_archive, utc_date};
    use cargoscope_core::Severity;
    use std::path::Path;

    const SAMPLE: &str = r#"```toml
[advisory]
id = "RUSTSEC-0000-0001"
package = "demo"
date = "2024-01-02"
url = "https://example.test/report"
aliases = ["CVE-0000-0001"]
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

[versions]
patched = [">= 1.2.0"]
unaffected = ["< 1.0.0"]
```

# Demo crate does something bad

Details.
"#;

    fn version(text: &str) -> semver::Version {
        semver::Version::parse(text).expect("valid version")
    }

    #[test]
    fn parses_front_matter_title_and_severity() {
        let advisory = Advisory::parse(SAMPLE).expect("sample parses");
        assert_eq!(advisory.id, "RUSTSEC-0000-0001");
        assert_eq!(advisory.package, "demo");
        assert_eq!(advisory.title, "Demo crate does something bad");
        assert_eq!(advisory.aliases, vec!["CVE-0000-0001"]);
        assert_eq!(advisory.severity, Some(Severity::Critical));
        assert!(!advisory.withdrawn);
    }

    #[test]
    fn matches_only_affected_versions() {
        let advisory = Advisory::parse(SAMPLE).expect("sample parses");
        assert!(advisory.affects(&version("1.1.9")));
        assert!(!advisory.affects(&version("1.2.0")));
        assert!(!advisory.affects(&version("0.9.0")));
    }

    #[test]
    fn rejects_files_without_front_matter() {
        assert!(Advisory::parse("# Just a heading").is_none());
    }

    #[test]
    fn accepts_only_safe_advisory_paths() {
        assert_eq!(
            advisory_entry(Path::new(
                "advisory-db-main/crates/demo/RUSTSEC-0000-0001.md"
            )),
            Some(("demo".to_owned(), "RUSTSEC-0000-0001.md".to_owned()))
        );
        assert_eq!(
            advisory_entry(Path::new("advisory-db-main/crates/../evil.md")),
            None
        );
        assert_eq!(
            advisory_entry(Path::new("advisory-db-main/README.md")),
            None
        );
        assert_eq!(advisory_entry(Path::new("/crates/demo/a.md")), None);
        assert_eq!(
            advisory_entry(Path::new("advisory-db-main/crates/demo/notes.txt")),
            None
        );
    }

    #[test]
    fn formats_utc_dates() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(1_709_164_800), "2024-02-29");
    }

    fn archive(entries: &[(&str, &str)]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, contents.as_bytes())
                .expect("append entry");
        }
        builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip")
    }

    fn temp_cache(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cargoscope-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn installs_only_advisory_files_and_replaces_previous_database() {
        let cache = temp_cache("install");
        let first = archive(&[
            ("advisory-db-main/crates/demo/RUSTSEC-0000-0001.md", SAMPLE),
            ("advisory-db-main/README.md", "ignored"),
            ("advisory-db-main/crates/demo/notes.txt", "ignored"),
        ]);
        let summary = install_archive(&cache, &first).expect("install works");
        assert_eq!(summary.advisories, 1);
        let database = AdvisoryDatabase::open(&cache).expect("database opens");
        assert!(database.fetched_on.is_some());
        assert!(!cache.join("advisory-db/README.md").exists());

        let second = archive(&[("advisory-db-main/crates/other/RUSTSEC-0000-0002.md", SAMPLE)]);
        install_archive(&cache, &second).expect("second install works");
        assert!(!cache.join("advisory-db/crates/demo").exists());
        assert!(
            cache
                .join("advisory-db/crates/other/RUSTSEC-0000-0002.md")
                .is_file()
        );
        let _ = std::fs::remove_dir_all(&cache);
    }

    #[test]
    fn empty_archive_keeps_previous_database() {
        let cache = temp_cache("empty");
        install_archive(
            &cache,
            &archive(&[("advisory-db-main/crates/demo/RUSTSEC-0000-0001.md", SAMPLE)]),
        )
        .expect("install works");
        assert!(install_archive(&cache, &archive(&[("advisory-db-main/README.md", "x")])).is_err());
        assert!(
            cache
                .join("advisory-db/crates/demo/RUSTSEC-0000-0001.md")
                .is_file()
        );
        let _ = std::fs::remove_dir_all(&cache);
    }

    #[test]
    fn missing_database_is_reported() {
        let cache = temp_cache("missing");
        let error = AdvisoryDatabase::open(&cache).expect_err("no database");
        assert!(error.to_string().contains("cargoscope update"));
    }
}
