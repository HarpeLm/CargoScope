//! License facts read from disk, as cargo-deny gathers them.
//!
//! For each package whose license the policy checks:
//!
//! 1. a verified `clarify` entry wins (handled by the policy itself);
//! 2. otherwise the `license` field: from crates.io data for crates.io
//!    packages, from the package's own `Cargo.toml` for the project's
//!    packages, git dependencies and other registries;
//! 3. when there is no `license` field or it cannot be read, the texts of the
//!    `LICENSE*` and `COPYING*` files of the package root (and `license-file`)
//!    are matched against the SPDX license list. Every license found with a
//!    score of at least `confidence-threshold` is required (`A AND B`), the
//!    conservative reading cargo-deny uses.
//!
//! Text matching uses the same store and settings as cargo-deny 0.20 (the
//! `spdx` crate's askalono port), so both tools reach the same licenses.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use cargoscope_core::policy::{LicenseFacts, Policy};
use cargoscope_core::{Inventory, PackageInfo};

use crate::crate_sources::resolve_package_dirs;

const CRATES_IO: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];
/// License files larger than this are not read.
const MAX_LICENSE_BYTES: u64 = 1024 * 1024;

/// What was found for the packages of an inventory.
#[derive(Debug, Default)]
pub struct Gathered {
    /// Facts per package, in inventory order.
    pub facts: Vec<LicenseFacts>,
    /// Licenses to put in the report, per package (`Some` replaces the
    /// registry data, `None` keeps it).
    pub licenses: Vec<Option<String>>,
    /// Problems worth telling (missing sources, unrecognised license texts).
    pub warnings: Vec<String>,
}

/// The license-related fields of one manifest.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ManifestLicense {
    license: Option<String>,
    /// `license-file`, relative to the package root.
    license_file: Option<PathBuf>,
    /// `publish`: `None` when absent (publishable anywhere), `Some(vec![])`
    /// for `publish = false`, else the allowed registries.
    publish: Option<Vec<String>>,
}

/// Reads `[package]` of a manifest, resolving `{ workspace = true }` from
/// the workspace root's `[workspace.package]`.
fn manifest_license(
    dir: &Path,
    workspace_package: Option<&toml::Table>,
    workspace_dir: &Path,
) -> Option<ManifestLicense> {
    let text = fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    let manifest: toml::Value = toml::from_str(&text).ok()?;
    let package = manifest.get("package")?.as_table()?;
    let inherited = |key: &str| -> Option<(&toml::Value, bool)> {
        match package.get(key)? {
            toml::Value::Table(table)
                if table.get("workspace").and_then(toml::Value::as_bool) == Some(true) =>
            {
                workspace_package?.get(key).map(|value| (value, true))
            }
            value => Some((value, false)),
        }
    };
    let license = inherited("license")
        .and_then(|(value, _)| value.as_str())
        .map(str::trim)
        .filter(|license| !license.is_empty())
        .map(str::to_owned);
    let license_file = inherited("license-file").and_then(|(value, from_workspace)| {
        let path = PathBuf::from(value.as_str()?);
        if from_workspace {
            // Relative to the workspace root: make it relative to `dir` when
            // possible, else keep it absolute.
            let absolute = workspace_dir.join(&path);
            Some(
                absolute
                    .strip_prefix(dir)
                    .map_or(absolute.clone(), Path::to_path_buf),
            )
        } else {
            Some(path)
        }
    });
    let publish = inherited("publish").and_then(|(value, _)| match value {
        toml::Value::Boolean(false) => Some(Vec::new()),
        toml::Value::Array(registries) => Some(
            registries
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect(),
        ),
        _ => None,
    });
    Some(ManifestLicense {
        license,
        license_file,
        publish,
    })
}

/// `LICENSE*` and `COPYING*` files of `dir`, plus `license_file`, sorted.
fn license_files(dir: &Path, license_file: Option<&Path>) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("LICENSE") || name.starts_with("COPYING"))
        .map(PathBuf::from)
        .collect();
    if let Some(extra) = license_file
        && !files
            .iter()
            .any(|file| file.ends_with(extra) || extra.ends_with(file))
    {
        files.push(extra.to_path_buf());
    }
    files.sort();
    files
}

/// Reads a license text with plain newlines, as cargo-deny does.
fn read_text(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_LICENSE_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let mut out = String::with_capacity(text.len() + 1);
    for line in text.lines() {
        out.push_str(line);
        out.push('\n');
    }
    Some(out)
}

fn store() -> Option<&'static spdx::detection::Store> {
    static STORE: OnceLock<Option<spdx::detection::Store>> = OnceLock::new();
    STORE
        .get_or_init(|| spdx::detection::Store::load_inline().ok())
        .as_ref()
}

/// Result of matching the license files of one package.
#[derive(Debug, Default, PartialEq, Eq)]
struct Detected {
    /// `A AND B` of the licenses found, if any.
    expression: Option<String>,
    /// Files whose license was found.
    sources: Vec<String>,
    /// Files whose text matched no license well enough, with the score.
    unmatched: Vec<String>,
}

/// Matches one license text: the SPDX identifier and the score.
fn identify(text: &str) -> Option<(Option<&'static str>, f32)> {
    let store = store()?;
    let scanner = spdx::detection::scan::Scanner::new(store)
        .confidence_threshold(0.5)
        .optimize(false)
        .max_passes(1);
    let result = scanner.scan(&spdx::detection::TextData::new(text));
    let score = result.score;
    let Some(identified) = result.license else {
        return Some((None, score));
    };
    // cargo-deny issue 625: an Apache-2.0 text without its appendix
    // matches the Pixar license best; it is Apache-2.0 unless it says so.
    let name = if identified.name == "Pixar"
        && !text.trim_start().starts_with("Modified Apache 2.0 License")
    {
        "Apache-2.0"
    } else {
        identified.name
    };
    Some((spdx::license_id(name).map(|id| id.name), score))
}

fn detect(dir: &Path, license_file: Option<&Path>, threshold: u16) -> Detected {
    let threshold = f32::from(threshold) / 1000.0;
    let mut detected = Detected::default();
    let mut ids: Vec<&str> = Vec::new();
    for file in license_files(dir, license_file) {
        let label = file.display().to_string();
        let Some(text) = read_text(&dir.join(&file)) else {
            detected.unmatched.push(format!("{label} (unreadable)"));
            continue;
        };
        match identify(&text) {
            Some((Some(id), score)) if score >= threshold => {
                ids.push(id);
                detected.sources.push(label);
            }
            Some((_, score)) => detected
                .unmatched
                .push(format!("{label} (score {score:.2})")),
            None => detected
                .unmatched
                .push(format!("{label} (no license store)")),
        }
    }
    if !ids.is_empty() {
        detected.expression = Some(ids.join(" AND "));
    }
    detected
}

/// Whether `source` is one of the registry URLs in `ignored`.
fn source_ignored(source: &str, ignored: &[String]) -> bool {
    let url = source
        .strip_prefix("registry+")
        .or_else(|| source.strip_prefix("sparse+"))
        .unwrap_or(source)
        .trim_end_matches('/');
    ignored.iter().any(|entry| {
        let entry = entry
            .strip_prefix("sparse+")
            .unwrap_or(entry)
            .trim_end_matches('/');
        entry == url
            || (CRATES_IO.contains(&source)
                && (entry == "https://index.crates.io"
                    || entry == "https://github.com/rust-lang/crates.io-index"))
    })
}

/// Gathers license facts for the packages `policy` checks. `info` holds the
/// crates.io data; `clarified[index]` is set for packages with a verified
/// clarification (their license is not looked for).
#[must_use]
pub fn gather(
    project_root: &Path,
    inventory: &Inventory,
    policy: &Policy,
    info: &[PackageInfo],
    clarified: &[Option<usize>],
) -> Gathered {
    let count = inventory.packages.len();
    let mut gathered = Gathered {
        facts: vec![LicenseFacts::default(); count],
        licenses: vec![None; count],
        warnings: Vec::new(),
    };
    if !policy.check_licenses {
        return gathered;
    }
    let workspace_package = fs::read_to_string(project_root.join("Cargo.toml"))
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
        .and_then(|manifest| {
            manifest
                .get("workspace")?
                .get("package")?
                .as_table()
                .cloned()
        });
    let mut dirs: Option<Vec<Option<PathBuf>>> = None;

    for (index, package) in inventory.packages.iter().enumerate() {
        if clarified.get(index).copied().flatten().is_some() {
            continue;
        }
        let source = package.source.as_deref();
        if source.is_none() && !policy.licenses_include_workspace {
            continue;
        }
        let from_crates_io = source.is_some_and(|source| CRATES_IO.contains(&source));
        let registry_license = info.get(index).and_then(|info| info.license.clone());
        let readable = |license: &str| cargoscope_core::license::parse(license).is_ok();
        // crates.io data with a readable license is all that is needed.
        if from_crates_io && registry_license.as_deref().is_some_and(readable) {
            continue;
        }
        if policy.private_ignore
            && source.is_some_and(|source| source_ignored(source, &policy.private_ignore_sources))
        {
            gathered.facts[index].skip = true;
            continue;
        }
        let dirs = dirs.get_or_insert_with(|| resolve_package_dirs(project_root, inventory));
        let Some(dir) = dirs.get(index).cloned().flatten() else {
            if !from_crates_io
                || info
                    .get(index)
                    .is_some_and(|info| info.latest_version.is_some())
            {
                gathered.warnings.push(format!(
                    "the license of {} {} could not be read: its sources are not on disk (run `cargo fetch`)",
                    package.name, package.version
                ));
            }
            continue;
        };
        let manifest =
            manifest_license(&dir, workspace_package.as_ref(), project_root).unwrap_or_default();
        if policy.private_ignore
            && manifest.publish.as_ref().is_some_and(|registries| {
                registries
                    .iter()
                    .all(|registry| policy.private_registries.contains(registry))
            })
        {
            gathered.facts[index].skip = true;
            continue;
        }
        let declared = if from_crates_io {
            registry_license.or(manifest.license.clone())
        } else {
            manifest.license.clone()
        };
        let facts = &mut gathered.facts[index];
        facts.known = true;
        if let Some(license) = declared.as_deref().filter(|license| readable(license)) {
            gathered.licenses[index] = Some(license.to_owned());
            continue;
        }
        let detected = detect(
            &dir,
            manifest.license_file.as_deref(),
            policy.confidence_threshold,
        );
        if let Some(expression) = detected.expression {
            facts.origin = Some(format!("detected in {}", detected.sources.join(", ")));
            gathered.licenses[index] = Some(expression);
            if !detected.unmatched.is_empty() {
                gathered.warnings.push(format!(
                    "{} {}: no license recognised in {}",
                    package.name,
                    package.version,
                    detected.unmatched.join(", ")
                ));
            }
        } else if let Some(declared) = declared {
            // Unreadable and nothing found in files: report the expression.
            gathered.licenses[index] = Some(declared);
        } else {
            gathered.licenses[index] = None;
            let detail = if detected.unmatched.is_empty() {
                "no license field and no LICENSE or COPYING file".to_owned()
            } else {
                format!(
                    "no license field, and no license recognised in {}",
                    detected.unmatched.join(", ")
                )
            };
            gathered
                .warnings
                .push(format!("{} {}: {detail}", package.name, package.version));
        }
    }
    gathered
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{detect, license_files, manifest_license, source_ignored};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cargoscope-licenses-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    const MIT: &str = "MIT License

Copyright (c) 2026 Someone

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
";

    #[test]
    fn detects_licenses_from_files_and_joins_them_with_and() {
        let dir = temp_dir("detect");
        fs::write(dir.join("LICENSE-MIT"), MIT).expect("write");
        fs::write(dir.join("COPYING"), "All rights reserved. Do not copy.\n").expect("write");
        fs::write(dir.join("README.md"), MIT).expect("write");
        let detected = detect(&dir, None, 800);
        assert_eq!(detected.expression.as_deref(), Some("MIT"));
        assert_eq!(detected.sources, vec!["LICENSE-MIT"]);
        assert_eq!(detected.unmatched.len(), 1, "{:?}", detected.unmatched);
        assert!(detected.unmatched[0].starts_with("COPYING (score"));

        fs::write(
            dir.join("LICENSE-ZLIB"),
            "This software is provided 'as-is', without any express or implied
warranty.  In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
",
        )
        .expect("write");
        let detected = detect(&dir, None, 800);
        assert_eq!(detected.expression.as_deref(), Some("MIT AND Zlib"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_licenses_and_publish_from_manifests_with_workspace_inheritance() {
        let dir = temp_dir("manifest");
        fs::create_dir_all(dir.join("member")).expect("dir");
        fs::write(
            dir.join("member/Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\nlicense.workspace = true\npublish = false\n",
        )
        .expect("write");
        let workspace: toml::Table =
            toml::from_str("license = \"MIT OR Apache-2.0\"").expect("toml");
        let read = manifest_license(&dir.join("member"), Some(&workspace), &dir).expect("manifest");
        assert_eq!(read.license.as_deref(), Some("MIT OR Apache-2.0"));
        assert_eq!(read.publish, Some(Vec::new()));

        fs::write(
            dir.join("member/Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\nlicense-file = \"COPYRIGHT\"\npublish = [\"corp\"]\n",
        )
        .expect("write");
        fs::write(dir.join("member/COPYRIGHT"), MIT).expect("write");
        let read = manifest_license(&dir.join("member"), None, &dir).expect("manifest");
        assert_eq!(read.license, None);
        assert_eq!(read.publish, Some(vec!["corp".to_owned()]));
        assert_eq!(
            license_files(&dir.join("member"), read.license_file.as_deref()),
            vec![std::path::PathBuf::from("COPYRIGHT")]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn matches_ignored_registry_sources() {
        let ignored = vec!["https://corp.example.com/index/".to_owned()];
        assert!(source_ignored(
            "registry+https://corp.example.com/index",
            &ignored
        ));
        assert!(source_ignored(
            "sparse+https://corp.example.com/index/",
            &ignored
        ));
        assert!(!source_ignored(
            "registry+https://github.com/rust-lang/crates.io-index",
            &ignored
        ));
        assert!(source_ignored(
            "sparse+https://index.crates.io/",
            &["https://index.crates.io".to_owned()]
        ));
    }
}
