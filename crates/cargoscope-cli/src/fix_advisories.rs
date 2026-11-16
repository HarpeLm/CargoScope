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

use cargoscope_cargo::fix::set_requirement;
use cargoscope_core::{AdvisoryKind, Inventory, Package};

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
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .current_dir(root)
        .args(["update", "--color", "never", "-p", target])
        .stdin(Stdio::null());
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
    contents: String,
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
    let candidates = std::iter::once((root.join("Cargo.toml"), "Cargo.toml".to_owned())).chain(
        packages
            .packages
            .into_iter()
            .map(|(dir, label, _)| (dir.join("Cargo.toml"), label)),
    );
    let mut seen = BTreeSet::new();
    let mut manifests = Vec::new();
    for (path, label) in candidates {
        if !seen.insert(path.clone()) {
            continue;
        }
        let contents = std::fs::read_to_string(&path).map_err(|error| {
            eprintln!("CargoScope could not read {}: {error}", path.display());
            ExitCode::from(2)
        })?;
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
                version, manifests, ..
            } = &row.step
            {
                let ids: Vec<String> = row.ids.iter().map(|id| advisory_link(id)).collect();
                let to = if manifests.is_empty() {
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

/// Checks whether updating direct manifest declarations of `package` to
/// `=version` lets `cargo update --dry-run` replace `package.version`.
pub(crate) fn probe_manifest_update(
    root: &Path,
    package: &Package,
    version: &semver::Version,
    manifests: &[Manifest],
) -> Result<Option<Vec<String>>, String> {
    let version_str = version.to_string();
    let exact_req = format!("={version_str}");
    let mut edited = Vec::new();
    let mut labels = Vec::new();
    for manifest in manifests {
        let (_, changed) = set_requirement(&manifest.contents, &package.name, &version_str)?;
        if !changed {
            continue;
        }
        let (exact, _) = set_requirement(&manifest.contents, &package.name, &exact_req)?;
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
    let stderr = run_cargo_update(root, &package.name, None, true)?;
    drop(restore);

    let clean = strip_ansi(&stderr);
    let stale_remains = clean.contains(&format!("Adding {} v{version_str}", package.name))
        && !clean.contains(&format!("Removing {} v{}", package.name, package.version));
    if stale_remains {
        return Err(format!(
            "another dependency still requires {} {}",
            package.name, package.version
        ));
    }
    Ok(Some(labels))
}

fn plan_package(
    root: &Path,
    package: &Package,
    patched: &[String],
    manifests: &mut Option<Vec<Manifest>>,
) -> Result<Step, ExitCode> {
    let spec = format!("{}@{}", package.name, package.version);
    let versions = candidates(patched, &package.version);
    if versions.is_empty() {
        return Ok(Step::Blocked(
            "no fixed version is published for this advisory".to_owned(),
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
                });
            }
            Err(error) => last_error = reason(&error),
        }
    }

    if !package.direct {
        return Ok(Step::Blocked(last_error));
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
    version: &str,
    target_labels: &[String],
    manifests: &mut [Manifest],
) -> Result<(), ExitCode> {
    let exact_req = format!("={version}");
    let mut originals = Vec::new();
    let mut final_edits = Vec::new();
    for (index, manifest) in manifests.iter().enumerate() {
        if !target_labels.contains(&manifest.label) {
            continue;
        }
        let (exact, _) =
            set_requirement(&manifest.contents, name, &exact_req).map_err(|error| {
                eprintln!(
                    "CargoScope could not edit {}: {error}",
                    manifest.path.display()
                );
                ExitCode::from(2)
            })?;
        let (final_contents, _) =
            set_requirement(&manifest.contents, name, version).map_err(|error| {
                eprintln!(
                    "CargoScope could not edit {}: {error}",
                    manifest.path.display()
                );
                ExitCode::from(2)
            })?;
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
    if let Err(error) = run_cargo_update(root, name, None, false) {
        eprintln!("cargo update -p {name} failed: {}", reason(&error));
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
        } = &row.step
        else {
            continue;
        };
        if target_labels.is_empty() {
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
        apply_manifest_update(root, &row.name, version, target_labels, loaded)?;
    }
    Ok(())
}

fn print_step(name: &str, from: &str, ids: &[&str], step: &Step) {
    println!("{name} {from} ({})", ids.join(", "));
    match step {
        Step::Update {
            version,
            manifests: target_labels,
            ..
        } => {
            if target_labels.is_empty() {
                println!("  - update to {version}");
            } else {
                println!("  - update to {version} (in {})", target_labels.join(", "));
            }
        }
        Step::Blocked(why) => println!("  = cannot update: {why}"),
    }
}

fn print_summary(apply: bool, rows: &[Row]) {
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
    if !apply {
        if manifest_count == 0 {
            println!(
                "\nDry run: Cargo.lock was not changed. Run `cargoscope fix --advisories --apply` to make {updates} update(s); {blocked} package(s) need a manifest change or a newer dependent."
            );
        } else {
            println!(
                "\nDry run: nothing was changed. Run `cargoscope fix --advisories --apply` to make {updates} update(s) (and edit {manifest_count} manifest(s)); {blocked} package(s) still need a newer dependent."
            );
        }
        return;
    }
    if manifest_count == 0 {
        println!(
            "\nUpdated {updates} package(s) in Cargo.lock; {blocked} could not be updated without a manifest change. Run `cargoscope scan` to check the result."
        );
    } else {
        println!(
            "\nUpdated {updates} package(s) in Cargo.lock and {manifest_count} manifest(s); {blocked} could not be updated. Run `cargoscope scan` to check the result."
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
                version, manifests, ..
            } => updates.push(serde_json::json!({
                "package": row.name, "from": row.from, "to": version,
                "advisories": row.ids, "manifests": manifests,
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
) -> Result<ExitCode, ExitCode> {
    let markdown = format != Format::Text;
    let inventory: Inventory = cargoscope_cargo::scan_cargo_project(root)
        .map_err(|error| execution_error(root, &error))?;
    let mut warnings = Vec::new();
    let (findings, _) = crate::scan::check_advisories(root, &inventory, &mut warnings)?;
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }

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
        let patched: Vec<String> = findings
            .iter()
            .filter(|other| other.package == finding.package)
            .flat_map(|other| other.patched.iter().cloned())
            .collect();
        let step = plan_package(root, package, &patched, &mut manifests)?;
        if !markdown {
            print_step(&package.name, &package.version, &ids, &step);
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
            Format::Text => println!("No vulnerable package to update."),
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
        Format::Text => print_summary(apply, &rows),
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::{candidates, reason};

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
