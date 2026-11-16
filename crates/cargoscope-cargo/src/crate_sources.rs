//! On-disk inspection of Cargo package sources (`$CARGO_HOME` and local
//! manifests) for `[bans.build]` build scripts and `[licenses.clarify]`
//! `license-files` checksums.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Component, Path, PathBuf};

use cargoscope_core::Inventory;
use cargoscope_core::policy::{ActivePackages, LicenseClarification};

use crate::workspace;

const PRIME32_1: u32 = 0x9E37_79B1;
const PRIME32_2: u32 = 0x85EB_CA77;
const PRIME32_3: u32 = 0xC2B2_AE3D;
const PRIME32_4: u32 = 0x27D4_EB2F;
const PRIME32_5: u32 = 0x1656_67B1;

/// Incremental pure-Rust 32-bit xxHash matching `twox_hash::XxHash32`.
struct XxHash32 {
    seed: u32,
    total_len: u64,
    v: [u32; 4],
    buf: [u8; 16],
    buf_len: usize,
}

impl XxHash32 {
    fn new(seed: u32) -> Self {
        Self {
            seed,
            total_len: 0,
            v: [
                seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2),
                seed.wrapping_add(PRIME32_2),
                seed,
                seed.wrapping_sub(PRIME32_1),
            ],
            buf: [0; 16],
            buf_len: 0,
        }
    }

    fn round(acc: u32, lane: u32) -> u32 {
        acc.wrapping_add(lane.wrapping_mul(PRIME32_2))
            .rotate_left(13)
            .wrapping_mul(PRIME32_1)
    }

    fn read_le_u32(bytes: &[u8]) -> u32 {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn consume_stripe(&mut self, stripe: &[u8]) {
        for (i, acc) in self.v.iter_mut().enumerate() {
            let lane = Self::read_le_u32(&stripe[i * 4..i * 4 + 4]);
            *acc = Self::round(*acc, lane);
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total_len = self.total_len.wrapping_add(input.len() as u64);
        if self.buf_len + input.len() < 16 {
            self.buf[self.buf_len..self.buf_len + input.len()].copy_from_slice(input);
            self.buf_len += input.len();
            return;
        }
        if self.buf_len > 0 {
            let fill = 16 - self.buf_len;
            self.buf[self.buf_len..16].copy_from_slice(&input[..fill]);
            let stripe = self.buf;
            self.consume_stripe(&stripe);
            input = &input[fill..];
            self.buf_len = 0;
        }
        while input.len() >= 16 {
            self.consume_stripe(&input[..16]);
            input = &input[16..];
        }
        if !input.is_empty() {
            self.buf[..input.len()].copy_from_slice(input);
            self.buf_len = input.len();
        }
    }

    fn finish(&self) -> u32 {
        let mut h = if self.total_len >= 16 {
            self.v[0]
                .rotate_left(1)
                .wrapping_add(self.v[1].rotate_left(7))
                .wrapping_add(self.v[2].rotate_left(12))
                .wrapping_add(self.v[3].rotate_left(18))
        } else {
            self.seed.wrapping_add(PRIME32_5)
        };
        #[allow(clippy::cast_possible_truncation)]
        {
            h = h.wrapping_add(self.total_len as u32);
        }

        let mut rem = &self.buf[..self.buf_len];
        while rem.len() >= 4 {
            let lane = Self::read_le_u32(&rem[..4]);
            h = h
                .wrapping_add(lane.wrapping_mul(PRIME32_3))
                .rotate_left(17)
                .wrapping_mul(PRIME32_4);
            rem = &rem[4..];
        }
        for &byte in rem {
            h = h
                .wrapping_add(u32::from(byte).wrapping_mul(PRIME32_5))
                .rotate_left(11)
                .wrapping_mul(PRIME32_1);
        }

        h ^= h >> 15;
        h = h.wrapping_mul(PRIME32_2);
        h ^= h >> 13;
        h = h.wrapping_mul(PRIME32_3);
        h ^= h >> 16;
        h
    }
}

/// Computes the 32-bit xxHash checksum of a license file using cargo-deny's
/// line-ending normalization (`\r\n` and EOF normalized to `\n`, seed `0`).
///
/// # Errors
///
/// Returns an I/O error if reading from `reader` fails.
pub fn hash_license_reader(mut reader: impl BufRead) -> std::io::Result<u32> {
    let mut hasher = XxHash32::new(0);
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        hasher.update(trimmed.as_bytes());
        hasher.update(b"\n");
        line.clear();
    }
    Ok(hasher.finish())
}

fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .or_else(|| std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo")))
}

fn safe_relative_file(base: &Path, relative: &str) -> Option<PathBuf> {
    let rel = Path::new(relative);
    if rel.as_os_str().is_empty() {
        return None;
    }
    for component in rel.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    let path = base.join(rel);
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.file_type().is_symlink() && metadata.is_file() {
        Some(path)
    } else {
        None
    }
}

fn local_package_dirs(project_root: &Path) -> BTreeMap<(String, String), PathBuf> {
    let mut map = BTreeMap::new();
    let root_manifest_path = project_root.join("Cargo.toml");
    let Ok(root_text) = fs::read_to_string(&root_manifest_path) else {
        return map;
    };
    let Ok(root_manifest) = toml::from_str::<toml::Value>(&root_text) else {
        return map;
    };

    let canonical = |dir: PathBuf| fs::canonicalize(&dir).unwrap_or(dir);
    let mut dirs = vec![canonical(project_root.to_path_buf())];
    let (members, _) = workspace::members(project_root, &root_manifest);
    for member in members {
        dirs.push(canonical(project_root.join(member)));
    }

    let mut visited = BTreeSet::new();
    let mut queue = dirs;
    while let Some(dir) = queue.pop() {
        if !visited.insert(dir.clone()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(dir.join("Cargo.toml")) else {
            continue;
        };
        let Ok(manifest) = toml::from_str::<toml::Value>(&text) else {
            continue;
        };
        if let Some(pkg) = manifest.get("package").and_then(toml::Value::as_table)
            && let Some(name) = pkg.get("name").and_then(toml::Value::as_str)
        {
            let version = pkg
                .get("version")
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    pkg.get("version")
                        .and_then(toml::Value::as_table)
                        .filter(|v| v.get("workspace") == Some(&toml::Value::Boolean(true)))
                        .and_then(|_| {
                            root_manifest
                                .get("workspace")
                                .and_then(|w| w.get("package"))
                                .and_then(|p| p.get("version"))
                                .and_then(toml::Value::as_str)
                                .map(str::to_owned)
                        })
                })
                .unwrap_or_default();
            map.insert((name.to_owned(), version), dir.clone());
        }
        collect_path_dep_dirs(&dir, &manifest, &mut queue);
    }
    map
}

fn collect_path_dep_dirs(base: &Path, manifest: &toml::Value, queue: &mut Vec<PathBuf>) {
    let mut inspect_table = |deps: &toml::Table| {
        for value in deps.values() {
            if let Some(path) = value.get("path").and_then(toml::Value::as_str) {
                // Canonical, so that `a/../b` and `b` are visited once:
                // path dependencies that point back at each other would
                // otherwise grow the queue without end.
                let candidate = base.join(path);
                if candidate.join("Cargo.toml").is_file()
                    && let Ok(candidate) = fs::canonicalize(&candidate)
                {
                    queue.push(candidate);
                }
            }
        }
    };
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(deps) = manifest.get(key).and_then(toml::Value::as_table) {
            inspect_table(deps);
        }
    }
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(deps) = target.get(key).and_then(toml::Value::as_table) {
                    inspect_table(deps);
                }
            }
        }
    }
    if let Some(ws_deps) = manifest
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        inspect_table(ws_deps);
    }
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            fs::symlink_metadata(path)
                .is_ok_and(|meta| !meta.file_type().is_symlink() && meta.is_dir())
        })
        .collect();
    found.sort();
    found
}

fn git_revision(source: &str) -> Option<&str> {
    let (_, rev) = source.split_once('#')?;
    let rev = rev.trim();
    (!rev.is_empty()).then_some(rev)
}

fn find_git_package_dir(
    checkouts_dir: &Path,
    name: &str,
    version: &str,
    source: &str,
) -> Option<PathBuf> {
    let rev = git_revision(source)?;
    let short = &rev[..rev.len().min(7)];
    for repo_dir in subdirs(checkouts_dir) {
        for rev_dir in subdirs(&repo_dir) {
            let Some(dir_name) = rev_dir.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if dir_name != short && dir_name != rev && !rev.starts_with(dir_name) {
                continue;
            }
            if matches_manifest(&rev_dir, name, version) {
                return Some(rev_dir);
            }
            // Git checkouts may host a workspace whose root or subdirs contain the crate.
            if let Ok(text) = fs::read_to_string(rev_dir.join("Cargo.toml"))
                && let Ok(manifest) = toml::from_str::<toml::Value>(&text)
            {
                let (members, _) = workspace::members(&rev_dir, &manifest);
                for member in members {
                    let candidate = rev_dir.join(member);
                    if matches_manifest(&candidate, name, version) {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

fn matches_manifest(dir: &Path, expected_name: &str, expected_version: &str) -> bool {
    let Ok(text) = fs::read_to_string(dir.join("Cargo.toml")) else {
        return false;
    };
    let Ok(manifest) = toml::from_str::<toml::Value>(&text) else {
        return false;
    };
    let Some(pkg) = manifest.get("package").and_then(toml::Value::as_table) else {
        return false;
    };
    let name_ok = pkg.get("name").and_then(toml::Value::as_str) == Some(expected_name);
    let version_ok = pkg
        .get("version")
        .and_then(toml::Value::as_str)
        .is_none_or(|ver| ver == expected_version);
    name_ok && version_ok
}

/// Resolves the unpacked source directory on disk for each package in `inventory`.
#[must_use]
pub fn resolve_package_dirs(project_root: &Path, inventory: &Inventory) -> Vec<Option<PathBuf>> {
    let locals = local_package_dirs(project_root);
    let mut locals_by_name: BTreeMap<String, PathBuf> = BTreeMap::new();
    for ((name, _), dir) in &locals {
        locals_by_name
            .entry(name.clone())
            .or_insert_with(|| dir.clone());
    }

    let cargo = cargo_home();
    let registry_srcs = cargo
        .as_ref()
        .map(|home| subdirs(&home.join("registry").join("src")))
        .unwrap_or_default();
    let git_checkouts = cargo.map(|home| home.join("git").join("checkouts"));

    inventory
        .packages
        .iter()
        .map(|package| {
            let Some(source) = package.source.as_deref() else {
                return locals
                    .get(&(package.name.clone(), package.version.clone()))
                    .or_else(|| locals_by_name.get(&package.name))
                    .cloned();
            };
            if source.starts_with("git+") {
                return git_checkouts.as_deref().and_then(|dir| {
                    find_git_package_dir(dir, &package.name, &package.version, source)
                });
            }
            let folder = format!("{}-{}", package.name, package.version);
            registry_srcs
                .iter()
                .map(|src| src.join(&folder))
                .find(|candidate| candidate.join("Cargo.toml").is_file())
        })
        .collect()
}

/// Checks whether a package source directory declares a Cargo custom build
/// script (`build.rs` or `[package] build = "..."`, respecting `build = false`).
#[must_use]
pub fn has_build_script(package_dir: &Path) -> Option<bool> {
    let text = fs::read_to_string(package_dir.join("Cargo.toml")).ok()?;
    let manifest: toml::Value = toml::from_str(&text).ok()?;
    let package = manifest.get("package")?.as_table()?;
    match package.get("build") {
        Some(toml::Value::Boolean(false)) => Some(false),
        Some(toml::Value::String(path)) => Some(safe_relative_file(package_dir, path).is_some()),
        None | Some(toml::Value::Boolean(true)) => {
            Some(safe_relative_file(package_dir, "build.rs").is_some())
        }
        Some(_) => None,
    }
}

/// Detects packages in `inventory` that have a custom build script on disk.
///
/// Only packages matching `include_workspace` (or non-workspace crates) that
/// belong to `active` (when provided) are inspected. Emits a warning if any
/// checked package's unpacked source directory could not be found.
#[must_use]
pub fn detect_build_scripts(
    project_root: &Path,
    inventory: &Inventory,
    active: Option<&ActivePackages>,
    include_workspace: bool,
) -> (ActivePackages, Vec<String>) {
    let dirs = resolve_package_dirs(project_root, inventory);
    let mut scripts = ActivePackages::new();
    let mut missing = 0usize;

    for (package, dir) in inventory.packages.iter().zip(dirs.iter()) {
        if let Some(active_set) = active
            && !active_set.contains(&(package.name.clone(), package.version.clone()))
        {
            continue;
        }
        if package.root && !include_workspace {
            continue;
        }
        let Some(dir) = dir.as_deref() else {
            missing += 1;
            continue;
        };
        match has_build_script(dir) {
            Some(true) => {
                scripts.insert((package.name.clone(), package.version.clone()));
            }
            Some(false) => {}
            None => missing += 1,
        }
    }

    let mut warnings = Vec::new();
    if missing > 0 {
        warnings.push(format!(
            "[bans.build] skipped {missing} package(s) whose unpacked sources were not found in Cargo home; run `cargo fetch` first"
        ));
    }
    (scripts, warnings)
}

fn version_matches(requirement: Option<&str>, version: &str) -> bool {
    match requirement {
        None => true,
        Some(requirement) => match (
            semver::VersionReq::parse(requirement),
            semver::Version::parse(version),
        ) {
            (Ok(requirement), Ok(version)) => requirement.matches(&version),
            _ => true,
        },
    }
}

fn verify_clarification_files(
    dir: &Path,
    clarification: &LicenseClarification,
) -> Result<(), String> {
    for file in &clarification.license_files {
        let Some(path) = safe_relative_file(dir, &file.path) else {
            return Err(format!("license file `{}` not found", file.path));
        };
        if let Some(expected) = file.hash {
            let opened = fs::File::open(&path)
                .map_err(|err| format!("could not read `{}`: {err}", file.path))?;
            let actual = hash_license_reader(BufReader::new(opened))
                .map_err(|err| format!("could not hash `{}`: {err}", file.path))?;
            if actual != expected {
                return Err(format!(
                    "hash of `{}` is 0x{actual:08x}, expected 0x{expected:08x}",
                    file.path
                ));
            }
        }
    }
    Ok(())
}

/// Verifies `license-files` entries on [`LicenseClarification`] against unpacked
/// crate directories on disk.
///
/// Returns an index vector aligned with `inventory.packages` mapping each
/// package to the first matching & verified clarification index (if any),
/// along with warnings for clarifications that failed checksum verification or
/// could not be verified because sources were missing.
#[must_use]
pub fn verify_clarifications(
    project_root: &Path,
    inventory: &Inventory,
    clarifications: &[LicenseClarification],
) -> (Vec<Option<usize>>, Vec<String>) {
    let mut verified = vec![None; inventory.packages.len()];
    if clarifications.is_empty() {
        return (verified, Vec::new());
    }

    let needs_disk = clarifications
        .iter()
        .any(|clarification| !clarification.license_files.is_empty());
    let dirs = if needs_disk {
        resolve_package_dirs(project_root, inventory)
    } else {
        vec![None; inventory.packages.len()]
    };

    let mut warnings = Vec::new();
    for (pkg_idx, package) in inventory.packages.iter().enumerate() {
        let matching: Vec<(usize, &LicenseClarification)> = clarifications
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                c.name == package.name && version_matches(c.version.as_deref(), &package.version)
            })
            .collect();
        if matching.is_empty() {
            continue;
        }

        let mut last_failure: Option<String> = None;
        for (clarify_idx, clarification) in matching {
            if clarification.license_files.is_empty() {
                verified[pkg_idx] = Some(clarify_idx);
                last_failure = None;
                break;
            }
            let Some(dir) = dirs[pkg_idx].as_deref() else {
                last_failure = Some(
                    "source directory not found in Cargo home (run `cargo fetch` to verify license-files)"
                        .to_owned(),
                );
                continue;
            };
            match verify_clarification_files(dir, clarification) {
                Ok(()) => {
                    verified[pkg_idx] = Some(clarify_idx);
                    last_failure = None;
                    break;
                }
                Err(reason) => {
                    last_failure = Some(reason);
                }
            }
        }
        if let Some(reason) = last_failure {
            warnings.push(format!(
                "license clarification for {} {} rejected: {reason}",
                package.name, package.version
            ));
        }
    }

    (verified, warnings)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;

    use cargoscope_core::policy::{LicenseClarification, LicenseFileHash};
    use cargoscope_core::{Inventory, Package};

    use super::{
        detect_build_scripts, has_build_script, hash_license_reader, verify_clarifications,
    };

    #[test]
    fn path_dependencies_that_point_at_each_other_are_visited_once() {
        let dir = std::env::temp_dir().join(format!("cargoscope-cycle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for (name, other) in [("a", "b"), ("b", "a")] {
            fs::create_dir_all(dir.join(name)).expect("dir");
            fs::write(
                dir.join(name).join("Cargo.toml"),
                format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n[dev-dependencies]\n{other} = {{ path = \"../{other}\" }}\n"),
            )
            .expect("manifest");
        }
        fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers = [\"a\"]\n").expect("root");
        let dirs = super::local_package_dirs(&dir);
        assert_eq!(dirs.len(), 2, "{dirs:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn xxhash32_matches_cargo_deny_line_normalization() {
        // Known empty hash (0x02CC_5D05) and CRLF == LF normalization.
        assert_eq!(hash_license_reader(Cursor::new(b"")).unwrap(), 0x02CC_5D05);
        let lf = hash_license_reader(Cursor::new(b"MIT\nLine two\n")).unwrap();
        let crlf = hash_license_reader(Cursor::new(b"MIT\r\nLine two\r\n")).unwrap();
        let no_eof = hash_license_reader(Cursor::new(b"MIT\r\nLine two")).unwrap();
        assert_eq!(lf, crlf);
        assert_eq!(lf, no_eof);

        // Cross-check standard xxHash32 vectors (seed 0).
        let mut h = super::XxHash32::new(0);
        h.update(b"");
        assert_eq!(h.finish(), 0x02CC_5D05);

        let mut h_long = super::XxHash32::new(0);
        h_long.update(b"Nobody inspects the spammish repetition");
        assert_eq!(h_long.finish(), 0xe229_3b2f);

        let mut h_split = super::XxHash32::new(0);
        h_split.update(b"Nobody inspects");
        h_split.update(b" the spammish repetition");
        assert_eq!(h_long.finish(), h_split.finish());
    }

    #[test]
    fn detects_build_scripts_respecting_false_and_custom_paths() {
        let dir = std::env::temp_dir().join(format!("cargoscope-src-build-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("default-bs")).unwrap();
        fs::write(
            dir.join("default-bs/Cargo.toml"),
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(dir.join("default-bs/build.rs"), "fn main() {}\n").unwrap();
        assert_eq!(has_build_script(&dir.join("default-bs")), Some(true));

        fs::create_dir_all(dir.join("disabled-bs")).unwrap();
        fs::write(
            dir.join("disabled-bs/Cargo.toml"),
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\nbuild = false\n",
        )
        .unwrap();
        fs::write(dir.join("disabled-bs/build.rs"), "fn main() {}\n").unwrap();
        assert_eq!(has_build_script(&dir.join("disabled-bs")), Some(false));

        fs::create_dir_all(dir.join("custom-bs")).unwrap();
        fs::write(
            dir.join("custom-bs/Cargo.toml"),
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\nbuild = \"custom.rs\"\n",
        )
        .unwrap();
        fs::write(dir.join("custom-bs/custom.rs"), "fn main() {}\n").unwrap();
        assert_eq!(has_build_script(&dir.join("custom-bs")), Some(true));

        // Traversal is rejected.
        fs::write(
            dir.join("custom-bs/Cargo.toml"),
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\nbuild = \"../default-bs/build.rs\"\n",
        )
        .unwrap();
        assert_eq!(has_build_script(&dir.join("custom-bs")), Some(false));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verifies_clarification_hashes_and_workspace_build_scripts() {
        let dir =
            std::env::temp_dir().join(format!("cargoscope-src-verify-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("dep")).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ndep = { path = \"dep\" }\n",
        )
        .unwrap();
        fs::write(dir.join("build.rs"), "fn main() {}\n").unwrap();
        fs::write(
            dir.join("dep/Cargo.toml"),
            "[package]\nname = \"dep\"\nversion = \"0.2.0\"\n",
        )
        .unwrap();
        fs::write(dir.join("dep/LICENSE"), "MIT License\n").unwrap();

        let expected = hash_license_reader(Cursor::new(b"MIT License\r\n")).unwrap();
        let inventory = Inventory {
            packages: vec![
                Package {
                    name: "app".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: false,
                    dependencies: vec![1],
                },
                Package {
                    name: "dep".to_owned(),
                    version: "0.2.0".to_owned(),
                    source: None,
                    root: false,
                    direct: true,
                    dependencies: vec![],
                },
            ],
        };

        let (scripts_no_ws, warnings) = detect_build_scripts(&dir, &inventory, None, false);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(scripts_no_ws.is_empty());

        let (scripts_ws, warnings) = detect_build_scripts(&dir, &inventory, None, true);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(scripts_ws.contains(&("app".to_owned(), "0.1.0".to_owned())));

        let ok_clarify = vec![LicenseClarification {
            name: "dep".to_owned(),
            version: None,
            expression: "MIT".to_owned(),
            reason: "checked".to_owned(),
            license_files: vec![LicenseFileHash {
                path: "LICENSE".to_owned(),
                hash: Some(expected),
            }],
        }];
        let (verified, warnings) = verify_clarifications(&dir, &inventory, &ok_clarify);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(verified, vec![None, Some(0)]);

        let bad_clarify = vec![LicenseClarification {
            name: "dep".to_owned(),
            version: None,
            expression: "MIT".to_owned(),
            reason: "checked".to_owned(),
            license_files: vec![LicenseFileHash {
                path: "LICENSE".to_owned(),
                hash: Some(expected ^ 1),
            }],
        }];
        let (verified, warnings) = verify_clarifications(&dir, &inventory, &bad_clarify);
        assert_eq!(verified, vec![None, None]);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("expected"));

        let _ = fs::remove_dir_all(dir);
    }
}
