//! `cargoscope fix --advisories`: moves vulnerable packages to the smallest
//! fixed version that Cargo can resolve.
//!
//! For each vulnerability with a fixed version, the lower bounds of its
//! patched ranges are tried in order with `cargo update --precise ...
//! --dry-run`: Cargo knows the version requirements of every dependent, so it
//! decides. When that fails on a direct dependency (because a manifest pins a
//! narrower requirement or an older major line), the candidate is retried with
//! `set_requirement` updating the project manifests. When none is accepted,
//! Cargo's explanation (which dependency requires an older version) is shown.
//!
//! This is the only part of `fix` that runs Cargo. `cargo update` only
//! resolves versions (it may read the registry index over the network); it
//! compiles and runs nothing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use cargoscope_advisory::crates_io::RegistryCache;
use cargoscope_cargo::fix::set_requirement_for_version;
use cargoscope_core::{AdvisoryKind, Inventory, Package, PackageInfo};

use crate::execution_error;

/// What to do with one vulnerable package.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// Cargo accepts this version: `cargo update -p spec --precise version`,
    /// after updating `manifests` when non-empty.
    Update {
        spec: String,
        version: String,
        manifests: Vec<String>,
        /// When non-empty, `cargo update -p` of these crates (the ones that
        /// require the package, within their own range) moves the package
        /// to `version`; `spec` is not updated itself.
        parents: Vec<String>,
    },
    /// No candidate accepted: Cargo's reason for the last one tried.
    Blocked(String),
}

/// Smallest versions the patched ranges allow (`>= 0.2.23`, `^1.1.4`,
/// `>= 0.4.20, < 0.5`), newer than `current`, oldest first.
fn candidates(patched: &[String], current: &str) -> Vec<semver::Version> {
    let Ok(current) = semver::Version::parse(current) else {
        return Vec::new();
    };
    let mut found: BTreeSet<semver::Version> = BTreeSet::new();
    for range in patched {
        let Ok(requirement) = semver::VersionReq::parse(range) else {
            continue;
        };
        for comparator in &requirement.comparators {
            use semver::Op;
            if !matches!(
                comparator.op,
                Op::GreaterEq | Op::Caret | Op::Tilde | Op::Exact | Op::Wildcard
            ) {
                continue;
            }
            let version = semver::Version::new(
                comparator.major,
                comparator.minor.unwrap_or(0),
                comparator.patch.unwrap_or(0),
            );
            if version > current && requirement.matches(&version) {
                found.insert(version);
            }
        }
    }
    found.into_iter().collect()
}

/// Runs `cargo update --color never -p target [--precise version] [--dry-run]`,
/// returning Cargo's stderr on success or failure.
fn run_cargo_update(
    root: &Path,
    target: &str,
    precise: Option<&str>,
    dry_run: bool,
) -> Result<String, String> {
    run_cargo_update_all(root, &[target], precise, dry_run)
}

/// [`run_cargo_update`] with one `-p` per target.
fn run_cargo_update_all(
    root: &Path,
    targets: &[&str],
    precise: Option<&str>,
    dry_run: bool,
) -> Result<String, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .current_dir(root)
        .args(["update", "--color", "never"])
        .stdin(Stdio::null());
    for target in targets {
        command.args(["-p", target]);
    }
    if let Some(version) = precise {
        command.args(["--precise", version]);
    }
    if dry_run {
        command.arg("--dry-run");
    }
    let output = command
        .output()
        .map_err(|error| format!("could not run cargo: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if output.status.success() {
        Ok(stderr)
    } else {
        Err(stderr)
    }
}

/// Runs `cargo update -p spec --precise version` (with `--dry-run` unless
/// applying); returns Cargo's error output on failure.
pub(crate) fn cargo_update(
    root: &Path,
    spec: &str,
    version: &str,
    dry_run: bool,
) -> Result<(), String> {
    run_cargo_update(root, spec, Some(version), dry_run).map(|_| ())
}

/// Removes terminal color codes (`ESC [ ... m`), in case Cargo colors its
/// output anyway (`CARGO_TERM_COLOR=always` in CI).
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The useful part of Cargo's resolution error: the lines that name a
/// requirement and who requires it.
pub(crate) fn reason(stderr: &str) -> String {
    let stderr = strip_ansi(stderr);
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.contains("required by package")
                || line.contains("failed to select a version")
                || line.starts_with("error:")
        })
        .take(3)
        .collect();
    if lines.is_empty() {
        stderr
            .lines()
            .last()
            .unwrap_or("cargo refused the update")
            .trim()
            .to_owned()
    } else {
        lines.join(" / ")
    }
}

/// The version of `name` that replaced `from` in a `cargo update` output:
/// `Updating name vFROM -> vTO`, or `Removing name vFROM` with `Adding name vTO`.
fn replacement(stderr: &str, name: &str, from: &str) -> Option<String> {
    let clean = strip_ansi(stderr);
    let mut removed = false;
    let mut added = None;
    for line in clean.lines().map(str::trim) {
        let mut words = line.split_whitespace();
        let (Some(action), Some(crate_name), Some(version)) =
            (words.next(), words.next(), words.next())
        else {
            continue;
        };
        if crate_name != name {
            continue;
        }
        let version = version.trim_start_matches('v');
        match action {
            "Updating" if version == from => {
                let to = words.nth(1)?.trim_start_matches('v');
                return Some(to.to_owned());
            }
            "Removing" if version == from => removed = true,
            "Adding" => added = Some(version.to_owned()),
            _ => {}
        }
    }
    added.filter(|_| removed)
}

/// When the fix is a breaking version that the crates requiring the package
/// do not accept, a newer release of those crates within the range the
/// project already requires may: `cargo update -p xcb` moves xcb 1.7.0 to
/// 1.7.1, which takes quick-xml 0.41. Tried with `--dry-run`; the package
/// must land on a version that fixes every advisory and brings none.
fn probe_parents(
    root: &Path,
    inventory: &Inventory,
    index: usize,
    patched_sets: &[Vec<String>],
    vulnerable: &dyn Fn(&semver::Version) -> bool,
) -> Option<Step> {
    let package = &inventory.packages[index];
    let pooled: Vec<String> = patched_sets.iter().flatten().cloned().collect();
    let fix = candidates(&pooled, &package.version)
        .into_iter()
        .find(|version| fixes_all(version, patched_sets))?;
    let blockers = cargoscope_report::fix_blockers(inventory, index, &fix);
    if blockers.is_empty() {
        return None;
    }
    let parents: Vec<String> = blockers
        .iter()
        .map(|&at| {
            let parent = &inventory.packages[at];
            format!("{}@{}", parent.name, parent.version)
        })
        .collect();
    let targets: Vec<&str> = parents.iter().map(String::as_str).collect();
    let stderr = run_cargo_update_all(root, &targets, None, true).ok()?;
    let to = replacement(&stderr, &package.name, &package.version)?;
    let version = semver::Version::parse(&to).ok()?;
    (fixes_all(&version, patched_sets) && !vulnerable(&version)).then(|| Step::Update {
        spec: format!("{}@{}", package.name, package.version),
        version: to,
        manifests: Vec::new(),
        parents,
    })
}

/// The requirement Cargo could not meet, from its error: `^0.30.0` in
/// ``failed to select a version for the requirement `quick-xml = "^0.30.0"` ``.
fn refused_requirement(reason: &str) -> Option<&str> {
    let start = reason.find("for the requirement `")? + "for the requirement `".len();
    let rest = &reason[start..];
    let requirement = &rest[..rest.find('`')?];
    let (_, value) = requirement.split_once('=')?;
    Some(value.trim().trim_matches('"'))
}

/// A plain explanation when the fix is a breaking version of a crate other
/// crates pull in: Cargo's own message is sometimes misleading (`no matching
/// package named crypto-bigint found` when `elliptic-curve` asks for 0.5).
/// `None` when nothing but the workspace depends on the package, so Cargo's
/// reason stays.
fn explain_blocked(
    inventory: &Inventory,
    index: usize,
    patched_sets: &[Vec<String>],
    reason: &str,
    registry: &[PackageInfo],
) -> Option<String> {
    let package = &inventory.packages[index];
    let pooled: Vec<String> = patched_sets.iter().flatten().cloned().collect();
    let fix = candidates(&pooled, &package.version)
        .into_iter()
        .find(|version| fixes_all(version, patched_sets))?;
    let blockers = cargoscope_report::fix_blockers(inventory, index, &fix);
    if blockers.is_empty() {
        return None;
    }
    let label = |at: usize| {
        let blocker = &inventory.packages[at];
        format!("{} {}", blocker.name, blocker.version)
    };
    let who = match (blockers.as_slice(), refused_requirement(reason)) {
        ([only], Some(requirement)) => {
            format!("{} requires {} {requirement}", label(*only), package.name)
        }
        ([only], None) => format!("{} requires an older {}", label(*only), package.name),
        (many, _) => format!(
            "{} require an older {}",
            many.iter()
                .map(|&at| label(at))
                .collect::<Vec<_>>()
                .join(", "),
            package.name
        ),
    };
    let newer: Vec<String> = blockers
        .iter()
        .filter_map(|&at| {
            let blocker = &inventory.packages[at];
            let latest = registry.get(at)?.latest_version.as_deref()?;
            let is_newer = semver::Version::parse(latest)
                .ok()
                .zip(semver::Version::parse(&blocker.version).ok())
                .is_some_and(|(latest, current)| latest > current);
            let breaking = semver::Version::parse(latest)
                .ok()
                .zip(semver::Version::parse(&blocker.version).ok())
                .is_some_and(|(latest, current)| {
                    !cargoscope_core::is_semver_compatible(&current, &latest)
                });
            is_newer.then(|| {
                if breaking {
                    format!("{} {latest} (a breaking update)", blocker.name)
                } else {
                    format!("{} {latest}", blocker.name)
                }
            })
        })
        .collect();
    let names: Vec<&str> = blockers
        .iter()
        .map(|&at| inventory.packages[at].name.as_str())
        .collect();
    let next = if newer.is_empty() {
        format!(
            "it can move once a new {} release allows it",
            names.join(" or ")
        )
    } else {
        format!("a newer release may allow it: {}", newer.join(", "))
    };
    Some(format!("{who}, and the fix is {fix}; {next}"))
}

/// First line of the Markdown report: lets the GitHub Action find the pull
/// request it opened before.
pub const PR_MARKER: &str = "<!-- cargoscope-security-pr -->";

/// One vulnerable package and what happens to it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    name: String,
    from: String,
    ids: Vec<String>,
    step: Step,
}

/// A manifest in the scanned project.
pub(crate) struct Manifest {
    path: PathBuf,
    label: String,
    pub(crate) contents: String,
}

/// Restores manifests on disk when a dry-run probe finishes or fails.
struct Restore<'a>(Vec<(&'a Path, &'a str)>);

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        for (path, original) in &self.0 {
            let _ = std::fs::write(path, original);
        }
    }
}

pub(crate) fn read_manifests(root: &Path) -> Result<Vec<Manifest>, ExitCode> {
    let packages =
        cargoscope_cargo::project_packages(root).map_err(|error| execution_error(root, &error))?;
    let workspace_dependencies = packages.workspace_dependencies.as_ref();
    let canonical_root = root.canonicalize().ok();

    let mut queue: Vec<(PathBuf, String, Option<toml::Value>)> =
        vec![(root.to_path_buf(), "Cargo.toml".to_owned(), None)];
    for (dir, label, manifest) in packages.packages {
        queue.push((dir, label, Some(manifest)));
    }

    let mut seen = BTreeSet::new();
    let mut manifests = Vec::new();
    let mut index = 0;
    while index < queue.len() && manifests.len() < 4_096 {
        let (dir, label, parsed) = queue[index].clone();
        index += 1;
        let path = dir.join("Cargo.toml");
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if !seen.insert(canonical) {
            continue;
        }
        let contents = std::fs::read_to_string(&path).map_err(|error| {
            eprintln!("CargoScope could not read {}: {error}", path.display());
            ExitCode::from(2)
        })?;
        let manifest_value = parsed.or_else(|| toml::from_str::<toml::Value>(&contents).ok());
        if let Some(manifest_value) = manifest_value.as_ref() {
            for dependency in cargoscope_cargo::unused::declared_dependencies(
                manifest_value,
                workspace_dependencies,
            ) {
                let Some((dep_path, from_workspace)) = dependency.path else {
                    continue;
                };
                let base = if from_workspace { root } else { dir.as_path() };
                let candidate = base.join(dep_path);
                let Some(canonical_dir) = candidate.canonicalize().ok() else {
                    continue;
                };
                if let Some(ref root_dir) = canonical_root
                    && !canonical_dir.starts_with(root_dir)
                {
                    continue;
                }
                if !canonical_dir.join("Cargo.toml").is_file() {
                    continue;
                }
                let rel_label = canonical_root
                    .as_ref()
                    .and_then(|root_dir| canonical_dir.strip_prefix(root_dir).ok())
                    .map(|rel| {
                        let rel_str = rel.to_string_lossy().replace('\\', "/");
                        if rel_str.is_empty() {
                            "Cargo.toml".to_owned()
                        } else {
                            format!("{}/Cargo.toml", rel_str.trim_end_matches('/'))
                        }
                    })
                    .unwrap_or_else(|| format!("{}/Cargo.toml", candidate.display()));
                queue.push((canonical_dir, rel_label, None));
            }
        }
        manifests.push(Manifest {
            path,
            label,
            contents,
        });
    }
    Ok(manifests)
}

fn advisory_link(id: &str) -> String {
    if id.starts_with("RUSTSEC-") {
        format!("[{id}](https://rustsec.org/advisories/{id})")
    } else {
        format!("`{id}`")
    }
}

/// The report as Markdown, for the body of a pull request.
fn render_markdown(rows: &[Row]) -> String {
    use std::fmt::Write;
    let mut out = format!("{PR_MARKER}\n### CargoScope: security updates\n\n");
    let updates: Vec<&Row> = rows
        .iter()
        .filter(|row| matches!(row.step, Step::Update { .. }))
        .collect();
    let blocked: Vec<&Row> = rows
        .iter()
        .filter(|row| matches!(row.step, Step::Blocked(_)))
        .collect();
    let touches_manifests = updates
        .iter()
        .any(|row| matches!(&row.step, Step::Update { manifests, .. } if !manifests.is_empty()));
    if updates.is_empty() {
        out.push_str("No vulnerable package can be updated without a manifest change.\n\n");
    } else {
        out.push_str("This updates `Cargo.lock` to the smallest fixed version Cargo accepts:\n\n| Package | From | To | Advisories |\n|---|---|---|---|\n");
        for row in &updates {
            if let Step::Update {
                version,
                manifests,
                parents,
                ..
            } = &row.step
            {
                let ids: Vec<String> = row.ids.iter().map(|id| advisory_link(id)).collect();
                let to = if !parents.is_empty() {
                    format!("**{version}** (via `{}`)", parents.join("`, `"))
                } else if manifests.is_empty() {
                    format!("**{version}**")
                } else {
                    format!("**{version}** (in `{}`)", manifests.join("`, `"))
                };
                let _ = writeln!(
                    out,
                    "| `{}` | {} | {to} | {} |",
                    row.name,
                    row.from,
                    ids.join(", ")
                );
            }
        }
        out.push('\n');
    }
    if !blocked.is_empty() {
        let _ = writeln!(
            out,
            "**Still vulnerable: {}** (a manifest change or a newer dependent is needed)\n",
            blocked.len()
        );
        for row in &blocked {
            if let Step::Blocked(why) = &row.step {
                let ids: Vec<String> = row.ids.iter().map(|id| advisory_link(id)).collect();
                let _ = writeln!(
                    out,
                    "- `{} {}` ({}): {}",
                    row.name,
                    row.from,
                    ids.join(", "),
                    why.replace('\n', " ")
                );
            }
        }
        out.push('\n');
    }
    if touches_manifests {
        out.push_str("Made with `cargoscope fix --advisories --apply`: updates `Cargo.lock` and the listed manifests; review the build and tests before merging.\n");
    } else {
        out.push_str("Made with `cargoscope fix --advisories --apply`: only `Cargo.lock` changes; review the build and tests before merging.\n");
    }
    out
}

/// Checks whether updating direct or `[workspace.dependencies]` manifest
/// declarations of `package` matching `package.version` to `=version` lets
/// `cargo update --dry-run` replace `package.version`.
pub(crate) fn probe_manifest_update(
    root: &Path,
    package: &Package,
    version: &semver::Version,
    manifests: &[Manifest],
) -> Result<Option<Vec<String>>, String> {
    let version_str = version.to_string();
    let exact_req = format!("={version_str}");
    let spec = format!("{}@{}", package.name, package.version);
    let mut edited = Vec::new();
    let mut labels = Vec::new();
    for manifest in manifests {
        let (_, changed) = set_requirement_for_version(
            &manifest.contents,
            &package.name,
            Some(&package.version),
            &version_str,
        )?;
        if !changed {
            continue;
        }
        let (exact, _) = set_requirement_for_version(
            &manifest.contents,
            &package.name,
            Some(&package.version),
            &exact_req,
        )?;
        labels.push(manifest.label.clone());
        edited.push((manifest.path.as_path(), manifest.contents.as_str(), exact));
    }
    if edited.is_empty() {
        return Ok(None);
    }

    let mut restore = Restore(Vec::new());
    for (path, original, exact) in &edited {
        restore.0.push((*path, *original));
        std::fs::write(path, exact)
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    }
    let stderr = run_cargo_update(root, &spec, None, true)?;
    drop(restore);

    let clean = strip_ansi(&stderr);
    let removed_old = clean.contains(&format!("Updating {} v{}", package.name, package.version))
        || clean.contains(&format!("Removing {} v{}", package.name, package.version));
    if !removed_old {
        return Err(format!(
            "another dependency still requires {} {}",
            package.name, package.version
        ));
    }
    Ok(Some(labels))
}

/// Whether `version` is in a patched range of every advisory (an advisory
/// without any fixed version does not count).
fn fixes_all(version: &semver::Version, patched_sets: &[Vec<String>]) -> bool {
    patched_sets.iter().all(|patched| {
        patched.is_empty()
            || patched.iter().any(|range| {
                semver::VersionReq::parse(range)
                    .is_ok_and(|requirement| requirement.matches(version))
            })
    })
}

/// `patched_sets`: the patched ranges of each advisory of the package.
/// `vulnerable`: whether a version is affected by any vulnerability of the
/// database (a fix must not move to a version another advisory affects).
fn plan_package(
    root: &Path,
    package: &Package,
    patched_sets: &[Vec<String>],
    vulnerable: &dyn Fn(&semver::Version) -> bool,
    manifests: &mut Option<Vec<Manifest>>,
) -> Result<Step, ExitCode> {
    let spec = format!("{}@{}", package.name, package.version);
    let pooled: Vec<String> = patched_sets.iter().flatten().cloned().collect();
    let all = candidates(&pooled, &package.version);
    if all.is_empty() {
        return Ok(Step::Blocked(
            "no fixed version is published for this advisory".to_owned(),
        ));
    }
    // Only versions that fix every advisory of the package and bring none:
    // quinn-proto 0.11.15 fixes one of seven and is affected by another.
    let versions: Vec<semver::Version> = all
        .into_iter()
        .filter(|version| fixes_all(version, patched_sets) && !vulnerable(version))
        .collect();
    if versions.is_empty() {
        return Ok(Step::Blocked(
            "no published version fixes every advisory of this package without another one"
                .to_owned(),
        ));
    }

    let mut last_error = String::new();
    for version in &versions {
        match cargo_update(root, &spec, &version.to_string(), true) {
            Ok(()) => {
                return Ok(Step::Update {
                    spec,
                    version: version.to_string(),
                    manifests: Vec::new(),
                    parents: Vec::new(),
                });
            }
            Err(error) => last_error = reason(&error),
        }
    }

    let loaded = match manifests {
        Some(loaded) => loaded,
        None => manifests.insert(read_manifests(root)?),
    };
    for version in &versions {
        match probe_manifest_update(root, package, version, loaded) {
            Ok(Some(labels)) => {
                return Ok(Step::Update {
                    spec,
                    version: version.to_string(),
                    manifests: labels,
                    parents: Vec::new(),
                });
            }
            Ok(None) => {}
            Err(error) => last_error = reason(&error),
        }
    }
    Ok(Step::Blocked(last_error))
}

pub(crate) fn apply_manifest_update(
    root: &Path,
    name: &str,
    from: &str,
    version: &str,
    target_labels: &[String],
    manifests: &mut [Manifest],
) -> Result<(), ExitCode> {
    let exact_req = format!("={version}");
    let spec = format!("{name}@{from}");
    let mut originals = Vec::new();
    let mut final_edits = Vec::new();
    for (index, manifest) in manifests.iter().enumerate() {
        if !target_labels.contains(&manifest.label) {
            continue;
        }
        let (exact, _) =
            set_requirement_for_version(&manifest.contents, name, Some(from), &exact_req).map_err(
                |error| {
                    eprintln!(
                        "CargoScope could not edit {}: {error}",
                        manifest.path.display()
                    );
                    ExitCode::from(2)
                },
            )?;
        let (final_contents, _) =
            set_requirement_for_version(&manifest.contents, name, Some(from), version).map_err(
                |error| {
                    eprintln!(
                        "CargoScope could not edit {}: {error}",
                        manifest.path.display()
                    );
                    ExitCode::from(2)
                },
            )?;
        originals.push((index, exact));
        final_edits.push((index, final_contents));
    }

    let mut restore = Restore(Vec::new());
    for (index, exact) in &originals {
        let manifest = &manifests[*index];
        restore
            .0
            .push((manifest.path.as_path(), manifest.contents.as_str()));
        if let Err(error) = std::fs::write(&manifest.path, exact) {
            eprintln!(
                "CargoScope could not write {}: {error}",
                manifest.path.display()
            );
            return Err(ExitCode::from(2));
        }
    }
    if let Err(error) = run_cargo_update(root, &spec, None, false) {
        eprintln!("cargo update -p {spec} failed: {}", reason(&error));
        return Err(ExitCode::from(2));
    }
    std::mem::forget(restore);

    for (index, final_contents) in final_edits {
        let path = &manifests[index].path;
        if let Err(error) = std::fs::write(path, &final_contents) {
            eprintln!("CargoScope could not write {}: {error}", path.display());
            return Err(ExitCode::from(2));
        }
        manifests[index].contents = final_contents;
    }
    Ok(())
}

/// The versions of `name` in `Cargo.lock` now.
fn locked_versions(root: &Path, name: &str) -> Vec<String> {
    cargoscope_cargo::scan_cargo_project(root)
        .map(|inventory| {
            inventory
                .packages
                .into_iter()
                .filter(|package| package.name == name)
                .map(|package| package.version)
                .collect()
        })
        .unwrap_or_default()
}

/// The versions left of a package on the line of `target` (other major
/// lines kept by other dependents do not count), when the one it was
/// planned from (`from`) is gone and each of them is at least `target`: an
/// earlier update moved it already.
fn past_target(versions: &[String], from: &str, target: &str) -> Option<Vec<String>> {
    let target = semver::Version::parse(target).ok()?;
    let same_line: Vec<(String, semver::Version)> = versions
        .iter()
        .filter_map(|text| Some((text.clone(), semver::Version::parse(text).ok()?)))
        .filter(|(_, version)| cargoscope_core::is_semver_compatible(&target, version))
        .collect();
    (!versions.iter().any(|version| version == from)
        && !same_line.is_empty()
        && same_line.iter().all(|(_, version)| *version >= target))
    .then(|| same_line.into_iter().map(|(text, _)| text).collect())
}

fn moved_past(root: &Path, name: &str, from: &str, target: &str) -> Option<String> {
    past_target(&locked_versions(root, name), from, target).map(|versions| versions.join(", "))
}

/// Brings the planned packages that an update of another one moved past
/// their target back to that target, the smallest fixed version (`cargo
/// update -p rustls --precise 0.23.46` also moves `rustls-webpki` to its
/// newest compatible version, 0.103.17 where 0.103.16 fixes it). A package
/// Cargo refuses to move back stays where it is, with a note.
fn settle_moved_packages(root: &Path, rows: &[Row]) {
    for row in rows {
        let Step::Update {
            version, manifests, ..
        } = &row.step
        else {
            continue;
        };
        if !manifests.is_empty() {
            continue;
        }
        let Some(now) = past_target(&locked_versions(root, &row.name), &row.from, version) else {
            continue;
        };
        let [now] = now.as_slice() else {
            continue;
        };
        if now == version {
            continue;
        }
        match cargo_update(root, &format!("{}@{now}", row.name), version, false) {
            Ok(()) => eprintln!(
                "{} {now} -> {version}: back to the smallest fixed version",
                row.name
            ),
            Err(error) => eprintln!(
                "{} stays at {now}: Cargo refused {version}: {}",
                row.name,
                reason(&error)
            ),
        }
    }
}

fn apply_updates(
    root: &Path,
    rows: &[Row],
    manifests: &mut Option<Vec<Manifest>>,
) -> Result<(), ExitCode> {
    for row in rows {
        let Step::Update {
            spec,
            version,
            manifests: target_labels,
            parents,
        } = &row.step
        else {
            continue;
        };
        if !parents.is_empty() {
            if let Some(now) = moved_past(root, &row.name, &row.from, version) {
                eprintln!(
                    "{} {}: already at {now} after an earlier update",
                    row.name, row.from
                );
                continue;
            }
            let targets: Vec<&str> = parents.iter().map(String::as_str).collect();
            run_cargo_update_all(root, &targets, None, false).map_err(|error| {
                eprintln!(
                    "cargo update -p {} failed: {}",
                    parents.join(" -p "),
                    reason(&error)
                );
                ExitCode::from(2)
            })?;
            continue;
        }
        if target_labels.is_empty() {
            // An earlier update may have moved this package already
            // (rustls pulls a newer rustls-webpki): skip it when the version
            // it was planned from is gone and what replaced it is new enough.
            if let Some(now) = moved_past(root, &row.name, &row.from, version) {
                eprintln!(
                    "{} {}: already at {now} after an earlier update",
                    row.name, row.from
                );
                continue;
            }
            cargo_update(root, spec, version, false).map_err(|error| {
                eprintln!(
                    "cargo update -p {spec} --precise {version} failed: {}",
                    reason(&error)
                );
                ExitCode::from(2)
            })?;
            continue;
        }
        let loaded = match manifests {
            Some(loaded) => loaded,
            None => manifests.insert(read_manifests(root)?),
        };
        apply_manifest_update(root, &row.name, &row.from, version, target_labels, loaded)?;
    }
    settle_moved_packages(root, rows);
    Ok(())
}

fn print_step(name: &str, from: &str, ids: &[&str], step: &Step, paint: cargoscope_report::Paint) {
    println!(
        "{} {from} ({})",
        paint.bold(name),
        paint.yellow(&ids.join(", "))
    );
    match step {
        Step::Update {
            version,
            manifests: target_labels,
            parents,
            ..
        } => {
            if !parents.is_empty() {
                let names: Vec<&str> = parents
                    .iter()
                    .map(|spec| spec.split_once('@').map_or(spec.as_str(), |(name, _)| name))
                    .collect();
                println!(
                    "  {} {}",
                    paint.green(&format!("- update to {version}")),
                    paint.dim(&format!(
                        "(by updating {} within the range already required: cargo update -p {})",
                        names.join(", "),
                        parents.join(" -p ")
                    ))
                );
            } else if target_labels.is_empty() {
                println!("  {}", paint.green(&format!("- update to {version}")));
            } else {
                println!(
                    "  {} {}",
                    paint.green(&format!("- update to {version}")),
                    paint.dim(&format!("(in {})", target_labels.join(", ")))
                );
            }
        }
        Step::Blocked(why) => println!("  {} {why}", paint.yellow("= cannot update:")),
    }
}

fn print_summary(apply: bool, rows: &[Row], paint: cargoscope_report::Paint) {
    let updates = rows
        .iter()
        .filter(|row| matches!(row.step, Step::Update { .. }))
        .count();
    let blocked = rows.len() - updates;
    let manifest_count = rows
        .iter()
        .filter_map(|row| match &row.step {
            Step::Update { manifests, .. } => Some(manifests.iter().map(String::as_str)),
            Step::Blocked(_) => None,
        })
        .flatten()
        .collect::<BTreeSet<_>>()
        .len();
    if updates == 0 {
        println!(
            "\n{} none of the {blocked} vulnerable package(s) can move from Cargo.lock or the workspace manifests: each one waits on the crate that requires it (above). Nothing was changed.",
            paint.bold(if apply {
                "Nothing to update:"
            } else {
                "Dry run:"
            })
        );
        return;
    }
    if !apply {
        if manifest_count == 0 {
            println!(
                "\n{} Cargo.lock was not changed. Run `cargoscope fix --advisories --apply` to make {updates} update(s); {blocked} package(s) need a manifest change or a newer dependent.",
                paint.bold("Dry run:")
            );
        } else {
            println!(
                "\n{} nothing was changed. Run `cargoscope fix --advisories --apply` to make {updates} update(s) (and edit {manifest_count} manifest(s)); {blocked} package(s) still need a newer dependent.",
                paint.bold("Dry run:")
            );
        }
        return;
    }
    if manifest_count == 0 {
        println!(
            "\n{} {blocked} could not be updated without a manifest change. Run `cargoscope scan` to check the result.",
            paint.green(&format!("Updated {updates} package(s) in Cargo.lock;"))
        );
    } else {
        println!(
            "\n{} {blocked} could not be updated. Run `cargoscope scan` to check the result.",
            paint.green(&format!(
                "Updated {updates} package(s) in Cargo.lock and {manifest_count} manifest(s);"
            ))
        );
    }
}

/// Output of `fix --advisories`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    /// Human-readable lines, printed as each package is planned.
    #[default]
    Text,
    /// A pull request body, printed after the updates.
    Markdown,
    /// The plan as JSON, for scripts such as the GitHub Action.
    Json,
}

/// The plan as JSON: `updates` (package, from, to, advisories, manifests)
/// and `blocked` (package, from, advisories, reason).
fn render_json(rows: &[Row]) -> String {
    let mut updates = Vec::new();
    let mut blocked = Vec::new();
    for row in rows {
        match &row.step {
            Step::Update {
                version,
                manifests,
                parents,
                ..
            } => updates.push(serde_json::json!({
                "package": row.name, "from": row.from, "to": version,
                "advisories": row.ids, "manifests": manifests, "via": parents,
            })),
            Step::Blocked(reason) => blocked.push(serde_json::json!({
                "package": row.name, "from": row.from,
                "advisories": row.ids, "reason": reason,
            })),
        }
    }
    let mut text = serde_json::to_string_pretty(&serde_json::json!({
        "updates": updates,
        "blocked": blocked,
    }))
    .unwrap_or_default();
    text.push('\n');
    text
}

/// `cargoscope fix --advisories [PATH] [--apply] [--format text|markdown|json]
/// [--only NAMES]`. Markdown and JSON are printed after the updates; `only`
/// restricts the run to those packages.
///
/// # Errors
///
/// Returns an execution error exit code (`2`) when the project cannot be
/// scanned, manifests cannot be edited, or `cargo update` fails.
pub fn run(
    root: &Path,
    apply: bool,
    format: Format,
    only: Option<&[String]>,
    paint: cargoscope_report::Paint,
) -> Result<ExitCode, ExitCode> {
    let markdown = format != Format::Text;
    let inventory: Inventory = cargoscope_cargo::scan_cargo_project(root)
        .map_err(|error| execution_error(root, &error))?;
    let mut warnings = Vec::new();
    let (findings, _) = crate::scan::check_advisories(root, &inventory, false, &mut warnings)?;
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }

    let database = cargoscope_advisory::cache_dir()
        .ok()
        .and_then(|dir| cargoscope_advisory::AdvisoryDatabase::open(&dir).ok());

    let registry = cargoscope_advisory::cache_dir()
        .map(|dir| RegistryCache::open(&dir).info(&inventory))
        .unwrap_or_default();

    // One step per vulnerable package, ignored advisories left out.
    let mut seen = BTreeSet::new();
    let mut rows: Vec<Row> = Vec::new();
    let mut manifests: Option<Vec<Manifest>> = None;
    for finding in &findings {
        if finding.ignored.is_some()
            || !matches!(finding.kind, AdvisoryKind::Vulnerability)
            || !seen.insert(finding.package)
        {
            continue;
        }
        let package = &inventory.packages[finding.package];
        if only.is_some_and(|names| !names.contains(&package.name)) {
            continue;
        }
        let ids: Vec<&str> = findings
            .iter()
            .filter(|other| other.package == finding.package)
            .map(|other| other.id.as_str())
            .collect();
        let patched_sets: Vec<Vec<String>> = findings
            .iter()
            .filter(|other| {
                other.package == finding.package
                    && other.ignored.is_none()
                    && matches!(other.kind, AdvisoryKind::Vulnerability)
            })
            .map(|other| other.patched.clone())
            .collect();
        let ignored: BTreeSet<&str> = findings
            .iter()
            .filter(|other| other.ignored.is_some())
            .map(|other| other.id.as_str())
            .collect();
        let vulnerable = |version: &semver::Version| {
            database.as_ref().is_some_and(|database| {
                let probe = Inventory {
                    packages: vec![Package {
                        version: version.to_string(),
                        dependencies: Vec::new(),
                        ..package.clone()
                    }],
                };
                database.check(&probe).findings.iter().any(|found| {
                    matches!(found.kind, AdvisoryKind::Vulnerability)
                        && !ignored.contains(found.id.as_str())
                })
            })
        };
        let mut step = plan_package(root, package, &patched_sets, &vulnerable, &mut manifests)?;
        if matches!(step, Step::Blocked(_))
            && let Some(through) = probe_parents(
                root,
                &inventory,
                finding.package,
                &patched_sets,
                &vulnerable,
            )
        {
            step = through;
        }
        if let Step::Blocked(reason) = &step
            && let Some(explained) = explain_blocked(
                &inventory,
                finding.package,
                &patched_sets,
                reason,
                &registry,
            )
        {
            step = Step::Blocked(explained);
        }
        if !markdown {
            print_step(&package.name, &package.version, &ids, &step, paint);
        }
        rows.push(Row {
            name: package.name.clone(),
            from: package.version.clone(),
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            step,
        });
    }
    if rows.is_empty() {
        match format {
            Format::Text => println!("{}", paint.green("No vulnerable package to update.")),
            Format::Json => print!("{}", render_json(&rows)),
            Format::Markdown => {}
        }
        return Ok(ExitCode::SUCCESS);
    }
    if apply {
        apply_updates(root, &rows, &mut manifests)?;
    }
    match format {
        Format::Markdown => print!("{}", render_markdown(&rows)),
        Format::Json => print!("{}", render_json(&rows)),
        Format::Text => print_summary(apply, &rows, paint),
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::{candidates, fixes_all, past_target, reason};

    #[test]
    fn finds_packages_an_earlier_update_moved_past_their_target() {
        let versions = |list: &[&str]| list.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
        // rustls pulled rustls-webpki 0.103.13 to 0.103.17; the plan said 0.103.16.
        assert_eq!(
            past_target(&versions(&["0.103.17"]), "0.103.13", "0.103.16"),
            Some(versions(&["0.103.17"]))
        );
        // Still at the planned-from version: not moved.
        assert_eq!(
            past_target(&versions(&["0.103.13"]), "0.103.13", "0.103.16"),
            None
        );
        // Moved, but not far enough: the planned step still has to run.
        assert_eq!(
            past_target(&versions(&["0.103.14"]), "0.103.13", "0.103.16"),
            None
        );
        // Another major line kept by another dependent does not count.
        assert_eq!(
            past_target(&versions(&["0.26.11", "1.0.10"]), "1.0.7", "1.0.10"),
            Some(versions(&["1.0.10"]))
        );
        assert_eq!(
            past_target(&versions(&["0.26.11", "1.0.8"]), "1.0.7", "1.0.10"),
            None
        );
        assert_eq!(past_target(&[], "1.0.0", "1.0.1"), None);
    }

    #[test]
    fn a_fix_must_fix_every_advisory() {
        // quinn-proto 0.11.14: one advisory fixed in 0.11.15, others in 0.11.19.
        let sets = vec![
            vec![">= 0.11.15".to_owned()],
            vec![">= 0.11.19".to_owned()],
            vec![],
        ];
        let v = |text: &str| semver::Version::parse(text).expect("version");
        assert!(!fixes_all(&v("0.11.15"), &sets));
        assert!(fixes_all(&v("0.11.19"), &sets));
    }

    #[test]
    fn candidates_are_the_lower_bounds_of_patched_ranges() {
        let versions = |patched: &[&str], current: &str| -> Vec<String> {
            candidates(
                &patched.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>(),
                current,
            )
            .iter()
            .map(ToString::to_string)
            .collect()
        };
        assert_eq!(versions(&[">= 0.2.23"], "0.1.45"), vec!["0.2.23"]);
        assert_eq!(versions(&[">=0.4.20"], "0.4.19"), vec!["0.4.20"]);
        // A fix on the old line comes before the newer line.
        assert_eq!(
            versions(&["^1.1.4", ">= 1.3.1"], "1.1.0"),
            vec!["1.1.4", "1.3.1"]
        );
        assert_eq!(
            versions(&[">= 0.5.0, < 0.6.0", ">= 0.6.3"], "0.5.2"),
            vec!["0.6.3"]
        );
        assert!(versions(&[">= 1.0.0"], "2.0.0").is_empty());
        assert!(versions(&["not a range"], "1.0.0").is_empty());
    }

    #[test]
    fn reads_what_replaced_a_package_and_the_refused_requirement() {
        use super::{refused_requirement, replacement};
        let moved = "    Updating crates.io index\n     Locking 3 packages\n    Removing quick-xml v0.30.0\n      Adding quick-xml v0.41.0\n    Updating xcb v1.7.0 -> v1.7.1\n";
        assert_eq!(
            replacement(moved, "quick-xml", "0.30.0").as_deref(),
            Some("0.41.0")
        );
        assert_eq!(replacement(moved, "xcb", "1.7.0").as_deref(), Some("1.7.1"));
        // Added next to the old version, which stays: not a replacement.
        let kept = "      Adding quick-xml v0.41.0\n";
        assert_eq!(replacement(kept, "quick-xml", "0.30.0"), None);
        assert_eq!(
            refused_requirement(
                "error: failed to select a version for the requirement `quick-xml = \"^0.30.0\"` / required by package `xcb v1.7.0`"
            ),
            Some("^0.30.0")
        );
        assert_eq!(refused_requirement("error: no matching package"), None);
    }

    #[test]
    fn renders_the_plan_as_json() {
        use super::{Row, Step, render_json};
        let rows = vec![
            Row {
                name: "chrono".to_owned(),
                from: "0.4.19".to_owned(),
                ids: vec!["RUSTSEC-2020-0159".to_owned()],
                step: Step::Update {
                    spec: "chrono@0.4.19".to_owned(),
                    version: "0.4.20".to_owned(),
                    manifests: Vec::new(),
                    parents: Vec::new(),
                },
            },
            Row {
                name: "time".to_owned(),
                from: "0.1.45".to_owned(),
                ids: vec!["RUSTSEC-2020-0071".to_owned()],
                step: Step::Blocked("required by package `chrono v0.4.19`".to_owned()),
            },
        ];
        let value: serde_json::Value = serde_json::from_str(&render_json(&rows)).expect("JSON");
        assert_eq!(value["updates"][0]["package"], "chrono");
        assert_eq!(value["updates"][0]["to"], "0.4.20");
        assert_eq!(value["blocked"][0]["package"], "time");
        assert_eq!(
            value["blocked"][0]["reason"],
            "required by package `chrono v0.4.19`"
        );
    }

    #[test]
    fn renders_the_pull_request_body() {
        use super::{Row, Step, render_markdown};
        let rows = vec![
            Row {
                name: "chrono".to_owned(),
                from: "0.4.19".to_owned(),
                ids: vec!["RUSTSEC-2020-0159".to_owned()],
                step: Step::Update {
                    spec: "chrono@0.4.19".to_owned(),
                    version: "0.4.20".to_owned(),
                    manifests: Vec::new(),
                    parents: Vec::new(),
                },
            },
            Row {
                name: "time".to_owned(),
                from: "0.1.45".to_owned(),
                ids: vec!["RUSTSEC-2020-0071".to_owned()],
                step: Step::Blocked("required by package `chrono v0.4.19`".to_owned()),
            },
        ];
        let body = render_markdown(&rows);
        assert!(body.starts_with("<!-- cargoscope-security-pr -->\n"));
        assert!(body.contains(
            "| `chrono` | 0.4.19 | **0.4.20** | [RUSTSEC-2020-0159](https://rustsec.org/advisories/RUSTSEC-2020-0159) |"
        ));
        assert!(body.contains("**Still vulnerable: 1**"));
        assert!(body.contains("- `time 0.1.45` ([RUSTSEC-2020-0071](https://rustsec.org/advisories/RUSTSEC-2020-0071)): required by package `chrono v0.4.19`"));

        let with_manifest = vec![Row {
            name: "chrono".to_owned(),
            from: "0.4.19".to_owned(),
            ids: vec!["RUSTSEC-2020-0159".to_owned()],
            step: Step::Update {
                spec: "chrono@0.4.19".to_owned(),
                version: "0.4.20".to_owned(),
                manifests: vec!["Cargo.toml".to_owned()],
                parents: Vec::new(),
            },
        }];
        let manifest_body = render_markdown(&with_manifest);
        assert!(manifest_body.contains("**0.4.20** (in `Cargo.toml`)"));
        assert!(manifest_body.contains("updates `Cargo.lock` and the listed manifests"));
    }

    #[test]
    fn keeps_the_lines_that_explain_a_refusal() {
        let stderr = "    Updating crates.io index\nerror: failed to select a version for the requirement `time = \"^0.1.43\"`\ncandidate versions found which didn't match: 0.2.23\nlocation searched: crates.io index\nrequired by package `chrono v0.4.19`\n    ... which satisfies dependency `chrono = \"^0.4\"` of package `app v0.1.0`\n";
        let why = reason(stderr);
        assert_eq!(
            reason("\u{1b}[1m\u{1b}[91merror\u{1b}[0m: failed to select a version for `x`"),
            "error: failed to select a version for `x`"
        );
        assert!(
            why.contains("failed to select a version for the requirement `time = \"^0.1.43\"`")
        );
        assert!(why.contains("required by package `chrono v0.4.19`"));
    }
}
