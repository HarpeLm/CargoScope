//! `cargoscope fix --advisories`: moves vulnerable packages to the smallest
//! fixed version that Cargo can resolve without changing any manifest.
//!
//! For each vulnerability with a fixed version, the lower bounds of its
//! patched ranges are tried in order with `cargo update --precise ...
//! --dry-run`: Cargo knows the version requirements of every dependent, so it
//! decides. The first accepted version is the plan; `--apply` runs the same
//! updates for real. When none is accepted, Cargo's explanation (which
//! dependency requires an older version) is shown.
//!
//! This is the only part of `fix` that runs Cargo. `cargo update` only
//! resolves versions (it may read the registry index over the network); it
//! compiles and runs nothing.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use cargoscope_core::{AdvisoryKind, Inventory};

use crate::execution_error;

/// What to do with one vulnerable package.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// Cargo accepts this version: `cargo update -p spec --precise version`.
    Update { spec: String, version: String },
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

/// Runs `cargo update -p spec --precise version` (with `--dry-run` unless
/// applying); returns Cargo's error output on failure.
fn cargo_update(root: &Path, spec: &str, version: &str, dry_run: bool) -> Result<(), String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .current_dir(root)
        .args(["update", "-p", spec, "--precise", version])
        .stdin(Stdio::null());
    if dry_run {
        command.arg("--dry-run");
    }
    let output = command
        .output()
        .map_err(|error| format!("could not run cargo: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

/// The useful part of Cargo's resolution error: the lines that name a
/// requirement and who requires it.
fn reason(stderr: &str) -> String {
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
    if updates.is_empty() {
        out.push_str("No vulnerable package can be updated without a manifest change.\n\n");
    } else {
        out.push_str("This updates `Cargo.lock` to the smallest fixed version Cargo accepts:\n\n| Package | From | To | Advisories |\n|---|---|---|---|\n");
        for row in &updates {
            if let Step::Update { version, .. } = &row.step {
                let ids: Vec<String> = row.ids.iter().map(|id| advisory_link(id)).collect();
                let _ = writeln!(
                    out,
                    "| `{}` | {} | **{version}** | {} |",
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
    out.push_str("Made with `cargoscope fix --advisories --apply`: only `Cargo.lock` changes; review the build and tests before merging.\n");
    out
}

/// `cargoscope fix --advisories [PATH] [--apply] [--format markdown]`. With
/// `markdown`, only the Markdown report is printed (after the updates).
pub fn run(root: &Path, apply: bool, markdown: bool) -> Result<ExitCode, ExitCode> {
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
    for finding in &findings {
        if finding.ignored.is_some()
            || !matches!(finding.kind, AdvisoryKind::Vulnerability)
            || !seen.insert(finding.package)
        {
            continue;
        }
        let package = &inventory.packages[finding.package];
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
        let spec = format!("{}@{}", package.name, package.version);
        let step = match candidates(&patched, &package.version).as_slice() {
            [] => Step::Blocked("no fixed version is published for this advisory".to_owned()),
            versions => {
                let mut last_error = String::new();
                let mut accepted = None;
                for version in versions {
                    match cargo_update(root, &spec, &version.to_string(), true) {
                        Ok(()) => {
                            accepted = Some(version.to_string());
                            break;
                        }
                        Err(error) => last_error = reason(&error),
                    }
                }
                match accepted {
                    Some(version) => Step::Update { spec, version },
                    None => Step::Blocked(last_error),
                }
            }
        };
        if !markdown {
            println!("{} {} ({})", package.name, package.version, ids.join(", "));
            match &step {
                Step::Update { version, .. } => println!("  - update to {version}"),
                Step::Blocked(why) => println!("  = cannot update: {why}"),
            }
        }
        rows.push(Row {
            name: package.name.clone(),
            from: package.version.clone(),
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            step,
        });
    }
    if rows.is_empty() {
        if !markdown {
            println!("No vulnerable package to update.");
        }
        return Ok(ExitCode::SUCCESS);
    }

    let updates: Vec<(&String, &String)> = rows
        .iter()
        .filter_map(|row| match &row.step {
            Step::Update { spec, version } => Some((spec, version)),
            Step::Blocked(_) => None,
        })
        .collect();
    let blocked = rows.len() - updates.len();
    if markdown {
        if apply {
            for (spec, version) in &updates {
                cargo_update(root, spec, version, false).map_err(|error| {
                    eprintln!(
                        "cargo update -p {spec} --precise {version} failed: {}",
                        reason(&error)
                    );
                    ExitCode::from(2)
                })?;
            }
        }
        print!("{}", render_markdown(&rows));
        return Ok(ExitCode::SUCCESS);
    }
    if !apply {
        println!(
            "\nDry run: Cargo.lock was not changed. Run `cargoscope fix --advisories --apply` to make {} update(s); {blocked} package(s) need a manifest change or a newer dependent.",
            updates.len()
        );
        return Ok(ExitCode::SUCCESS);
    }
    for (spec, version) in &updates {
        cargo_update(root, spec, version, false).map_err(|error| {
            eprintln!(
                "cargo update -p {spec} --precise {version} failed: {}",
                reason(&error)
            );
            ExitCode::from(2)
        })?;
    }
    println!(
        "\nUpdated {} package(s) in Cargo.lock; {blocked} could not be updated without a manifest change. Run `cargoscope scan` to check the result.",
        updates.len()
    );
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
    }

    #[test]
    fn keeps_the_lines_that_explain_a_refusal() {
        let stderr = "    Updating crates.io index\nerror: failed to select a version for the requirement `time = \"^0.1.43\"`\ncandidate versions found which didn't match: 0.2.23\nlocation searched: crates.io index\nrequired by package `chrono v0.4.19`\n    ... which satisfies dependency `chrono = \"^0.4\"` of package `app v0.1.0`\n";
        let why = reason(stderr);
        assert!(
            why.contains("failed to select a version for the requirement `time = \"^0.1.43\"`")
        );
        assert!(why.contains("required by package `chrono v0.4.19`"));
    }
}
