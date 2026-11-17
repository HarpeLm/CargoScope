//! A few files of a published crate version: its `Cargo.toml` (minimum Rust
//! version, license) and its changelog, for update pull requests.
//!
//! The files are read from Cargo's own copies first (`registry/src` and
//! `registry/cache` under `$CARGO_HOME`), then from a `.crate` archive kept
//! in CargoScope's cache, downloaded from crates.io when missing.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::crates_io::USER_AGENT;
use crate::proxy;

const DIR: &str = "crate-files";
const DOWNLOAD_URL: &str = "https://static.crates.io/crates";
const MAX_CRATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Changelog file names, most common first; compared without case.
const CHANGELOGS: [&str; 7] = [
    "CHANGELOG.md",
    "CHANGES.md",
    "RELEASES.md",
    "HISTORY.md",
    "NEWS.md",
    "CHANGELOG",
    "CHANGELOG.txt",
];

/// What an update pull request needs from one crate version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrateFiles {
    /// `package.rust-version` of its `Cargo.toml`.
    pub rust_version: Option<String>,
    /// `package.license` of its `Cargo.toml`.
    pub license: Option<String>,
    /// Name and text of its changelog, at the root of the crate.
    pub changelog: Option<(String, String)>,
}

impl CrateFiles {
    /// Reads `Cargo.toml` and the changelog from the files of a crate.
    fn from_files(manifest: Option<&str>, changelog: Option<(String, String)>) -> Self {
        let package = manifest
            .and_then(|text| toml::from_str::<toml::Value>(text).ok())
            .and_then(|value| value.get("package").cloned());
        let field = |name: &str| {
            package
                .as_ref()
                .and_then(|package| package.get(name))
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };
        Self {
            rust_version: field("rust-version"),
            license: field("license"),
            changelog,
        }
    }
}

fn is_changelog(file_name: &str) -> Option<usize> {
    CHANGELOGS
        .iter()
        .position(|candidate| candidate.eq_ignore_ascii_case(file_name))
}

fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .or_else(|| std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo")))
}

/// Subdirectories of `dir` (one per registry), empty when it does not exist.
fn registries(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect()
        })
        .unwrap_or_default()
}

fn read_limited(path: &Path) -> Option<String> {
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_FILE_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// The files of an unpacked crate directory.
fn from_dir(dir: &Path) -> Option<CrateFiles> {
    let manifest = read_limited(&dir.join("Cargo.toml"))?;
    let mut changelogs: Vec<(usize, String)> = fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            is_changelog(&name).map(|rank| (rank, name))
        })
        .collect();
    changelogs.sort();
    let changelog = changelogs
        .into_iter()
        .find_map(|(_, name)| read_limited(&dir.join(&name)).map(|text| (name, text)));
    Some(CrateFiles::from_files(Some(&manifest), changelog))
}

/// The files of a `.crate` archive (a gzipped tar with one top directory).
fn from_archive(bytes: &[u8]) -> Option<CrateFiles> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    let mut manifest = None;
    let mut changelog: Option<(usize, String, String)> = None;
    for entry in archive.entries().ok()? {
        let Ok(mut entry) = entry else { continue };
        let Ok(path) = entry.path().map(|path| path.into_owned()) else {
            continue;
        };
        let parts: Vec<String> = path
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        let [_, file_name] = parts.as_slice() else {
            continue;
        };
        let wanted_manifest = file_name == "Cargo.toml";
        let rank = is_changelog(file_name);
        if !wanted_manifest && rank.is_none() {
            continue;
        }
        let mut text = String::new();
        if (&mut entry)
            .take(MAX_FILE_BYTES)
            .read_to_string(&mut text)
            .is_err()
        {
            continue;
        }
        if wanted_manifest {
            manifest = Some(text);
        } else if let Some(rank) = rank
            && changelog.as_ref().is_none_or(|(best, _, _)| rank < *best)
        {
            changelog = Some((rank, file_name.clone(), text));
        }
    }
    let manifest = manifest?;
    Some(CrateFiles::from_files(
        Some(&manifest),
        changelog.map(|(_, name, text)| (name, text)),
    ))
}

/// The files of `name` `version` from Cargo's local copies, without network.
fn from_cargo(name: &str, version: &str) -> Option<CrateFiles> {
    let home = cargo_home()?;
    let folder = format!("{name}-{version}");
    if let Some(files) = registries(&home.join("registry").join("src"))
        .iter()
        .find_map(|registry| from_dir(&registry.join(&folder)))
    {
        return Some(files);
    }
    registries(&home.join("registry").join("cache"))
        .iter()
        .find_map(|registry| {
            let bytes = fs::read(registry.join(format!("{folder}.crate"))).ok()?;
            from_archive(&bytes)
        })
}

/// The files of the crates.io crate `name` `version`: from Cargo's local
/// copies, else from CargoScope's cache in `cache_dir`, else downloaded from
/// crates.io (and kept there).
///
/// # Errors
///
/// Returns a message when the crate is nowhere on disk and cannot be
/// downloaded or read.
pub fn crate_files(cache_dir: &Path, name: &str, version: &str) -> Result<CrateFiles, String> {
    if let Some(files) = from_cargo(name, version) {
        return Ok(files);
    }
    let path = cache_dir.join(DIR).join(format!("{name}-{version}.crate"));
    if let Ok(bytes) = fs::read(&path)
        && let Some(files) = from_archive(&bytes)
    {
        return Ok(files);
    }
    let url = format!("{DOWNLOAD_URL}/{name}/{name}-{version}.crate");
    let agent = proxy::agent(&url, Some(Duration::from_secs(60)), Some(USER_AGENT))?;
    let response = agent.get(&url).call().map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_CRATE_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let files = from_archive(&bytes).ok_or_else(|| format!("{url} is not a crate archive"))?;
    if let Some(parent) = path.parent()
        && fs::create_dir_all(parent).is_ok()
    {
        let _ = fs::write(&path, &bytes);
    }
    Ok(files)
}

/// The GitHub releases of `repository` (an `https://github.com/owner/repo`
/// URL), newest first, as a Markdown changelog: one `## tag name` section
/// per release of `name` with its notes. Uses `GITHUB_TOKEN` or `GH_TOKEN` when set.
///
/// # Errors
///
/// Returns a message when the URL is not a GitHub repository or GitHub
/// refuses or fails to answer.
pub fn github_releases(repository: &str, name: &str) -> Result<String, String> {
    let path = repository
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .strip_prefix("https://github.com/")
        .filter(|path| path.matches('/').count() == 1)
        .ok_or_else(|| format!("{repository} is not a GitHub repository"))?;
    let url = format!("https://api.github.com/repos/{path}/releases?per_page=100");
    let agent = proxy::agent(&url, Some(Duration::from_secs(30)), Some(USER_AGENT))?;
    let mut request = agent.get(&url).set("Accept", "application/vnd.github+json");
    if let Some(token) = std::env::var("GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GH_TOKEN").ok())
        .filter(|token| !token.trim().is_empty())
    {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response = request.call().map_err(|error| error.to_string())?;
    let mut text = String::new();
    response
        .into_reader()
        .take(MAX_FILE_BYTES * 8)
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    let releases: Vec<serde_json::Value> =
        serde_json::from_str(&text).map_err(|error| error.to_string())?;
    Ok(releases_as_changelog(&releases, name))
}

/// Whether a release tag is a version of `name`: `1.2.3`, `v1.2.3`, or the
/// same after `name-`, `name@`, `name/` or `name `, so that the releases of the other
/// crates of a repository (`tokio-macros-2.6.0` next to `tokio-1.41.0`) are
/// left out.
fn tag_of(tag: &str, name: &str) -> bool {
    let rest = [
        format!("{name}-"),
        format!("{name}@"),
        format!("{name} "),
        format!("{name}_"),
        format!("{name}/"),
    ]
    .iter()
    .find_map(|prefix| tag.strip_prefix(prefix.as_str()))
    .unwrap_or(tag);
    let rest = rest.strip_prefix('v').unwrap_or(rest);
    semver::Version::parse(rest).is_ok()
}

/// The GitHub releases of `name` as a Markdown changelog; drafts are left
/// out.
fn releases_as_changelog(releases: &[serde_json::Value], name: &str) -> String {
    let mut out = String::new();
    for release in releases {
        if release.get("draft").and_then(serde_json::Value::as_bool) == Some(true) {
            continue;
        }
        let field = |name: &str| release.get(name).and_then(serde_json::Value::as_str);
        let Some(tag) = field("tag_name").filter(|tag| tag_of(tag, name)) else {
            continue;
        };
        // A name that only repeats the version (`0.4.45` for `v0.4.45`) adds nothing.
        let title = field("name").filter(|name| {
            let name = name.trim();
            !name.is_empty() && !tag.contains(name.trim_start_matches('v'))
        });
        out.push_str("## ");
        out.push_str(tag);
        if let Some(title) = title {
            out.push_str(" — ");
            out.push_str(title.trim());
        }
        out.push_str("\n\n");
        // Headings inside the notes go below the release heading, so that
        // `## What's Changed` does not end its section.
        let body = field("body").unwrap_or("").replace("\r\n", "\n");
        for line in body.trim().lines() {
            if line.trim_start().starts_with('#') {
                out.push_str("##");
            }
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{CrateFiles, from_archive, releases_as_changelog};

    fn archive(files: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, text) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(text.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, text.as_bytes())
                .expect("append");
        }
        builder.into_inner().expect("tar").finish().expect("gzip")
    }

    #[test]
    fn reads_the_manifest_and_the_root_changelog() {
        let bytes = archive(&[
            (
                "demo-1.2.0/Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"1.2.0\"\nrust-version = \"1.70\"\nlicense = \"MIT\"\n",
            ),
            ("demo-1.2.0/docs/CHANGELOG.md", "not this one"),
            ("demo-1.2.0/changelog", "plain"),
            ("demo-1.2.0/CHANGELOG.md", "## 1.2.0\n- new\n"),
        ]);
        assert_eq!(
            from_archive(&bytes),
            Some(CrateFiles {
                rust_version: Some("1.70".to_owned()),
                license: Some("MIT".to_owned()),
                changelog: Some(("CHANGELOG.md".to_owned(), "## 1.2.0\n- new\n".to_owned())),
            })
        );
        let bare = archive(&[("demo-0.1.0/Cargo.toml", "[package]\nname = \"demo\"\n")]);
        assert_eq!(from_archive(&bare), Some(CrateFiles::default()));
        assert_eq!(from_archive(b"not gzip"), None);
    }

    #[test]
    fn turns_github_releases_into_a_changelog() {
        let releases: Vec<serde_json::Value> = serde_json::from_str(
            r###"[{"tag_name":"v0.4.45","name":"0.4.45","body":"## What's Changed\r\n- fix\r\n- docs","draft":false},
                {"tag_name":"v0.4.44.1","name":"Hotfix","body":""},
                {"tag_name":"v0.4.44","name":"","body":null},
                {"tag_name":"v9.9.9","draft":true,"body":"secret"},
                {"tag_name":"chrono-tz-v0.5.0","body":"another crate"},
                {"tag_name":"chrono-0.4.43","body":"prefixed"},
                {"tag_name":"chrono/v0.4.42","body":"slash"}]"###,
        )
        .expect("json");
        assert_eq!(
            releases_as_changelog(&releases, "chrono"),
            "## v0.4.45\n\n#### What's Changed\n- fix\n- docs\n\n## v0.4.44\n\n\n## chrono-0.4.43\n\nprefixed\n\n## chrono/v0.4.42\n\nslash\n\n"
        );
    }
}
