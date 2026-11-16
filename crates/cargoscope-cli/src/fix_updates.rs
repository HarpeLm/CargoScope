//! `cargoscope fix --updates`: moves direct dependencies to their newest
//! versions, as Dependabot version updates do.
//!
//! For each direct crates.io dependency with a newer version in the cached
//! crates.io data (`cargoscope update`):
//!
//! - the newest SemVer-compatible version is set in `Cargo.lock` with
//!   `cargo update -p name@version --precise new` (the manifests already allow
//!   it);
//! - with `--breaking`, the newest version of a newer major line is tried
//!   first: the requirement is raised in the manifests that declare the crate,
//!   and Cargo must accept it, else the compatible update is kept.
//!
//! Like `fix --advisories`, it only resolves versions: nothing is compiled.
//! A breaking update may need code changes; the pull request's CI says.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use cargoscope_core::{Inventory, Package, PackageInfo};

use crate::execution_error;
use crate::fix_advisories::{
    Format, Manifest, apply_manifest_update, cargo_update, probe_manifest_update, read_manifests,
    reason,
};

/// First line of the Markdown report: lets the GitHub Action recognise its
/// own pull requests.
pub const PR_MARKER: &str = "<!-- cargoscope-update-pr -->";

/// How far an update goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Within the requirement: only `Cargo.lock` changes.
    Compatible,
    /// A newer major line: the manifests change too.
    Breaking,
}

impl Kind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::Breaking => "breaking",
        }
    }
}

/// One direct dependency and what happens to it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    name: String,
    from: String,
    plan: Plan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    Update {
        spec: String,
        to: String,
        kind: Kind,
        /// Manifests whose requirement is raised (breaking updates only).
        manifests: Vec<String>,
        /// A newer major version Cargo refused, and why (when `--breaking`
        /// fell back to the compatible update).
        breaking_blocked: Option<(String, String)>,
    },
    Blocked {
        to: String,
        reason: String,
    },
}

/// The newest version on a newer major line (`2.0.0` from `1.4.0`, `0.9.1`
/// from `0.8.5`), if any.
fn breaking_target<'a>(info: &'a PackageInfo, current: &str) -> Option<&'a str> {
    let current = semver::Version::parse(current).ok()?;
    let latest = info.latest_version.as_deref()?;
    let parsed = semver::Version::parse(latest).ok()?;
    (parsed > current && !cargoscope_core::is_semver_compatible(&current, &parsed))
        .then_some(latest)
}

fn plan_package(
    root: &Path,
    package: &Package,
    info: &PackageInfo,
    breaking: bool,
    manifests: &mut Option<Vec<Manifest>>,
) -> Result<Option<Plan>, ExitCode> {
    let spec = format!("{}@{}", package.name, package.version);
    let compatible = info.compatible_upgrade(&package.version).map(str::to_owned);
    let mut breaking_blocked = None;

    if breaking && let Some(target) = breaking_target(info, &package.version) {
        let loaded = match manifests {
            Some(loaded) => loaded,
            None => manifests.insert(read_manifests(root)?),
        };
        // A requirement never carries build metadata (`1.2.1`, not
        // `1.2.1+spec-1.1.0`); it still matches that version.
        let mut version = semver::Version::parse(target).map_err(|_| ExitCode::from(2))?;
        version.build = semver::BuildMetadata::EMPTY;
        let target = version.to_string();
        match probe_manifest_update(root, package, &version, loaded) {
            Ok(Some(labels)) => {
                return Ok(Some(Plan::Update {
                    spec,
                    to: target.clone(),
                    kind: Kind::Breaking,
                    manifests: labels,
                    breaking_blocked: None,
                }));
            }
            Ok(None) => {
                breaking_blocked = Some((
                    target.clone(),
                    "no manifest of the project declares it".to_owned(),
                ));
            }
            Err(error) => breaking_blocked = Some((target, reason(&error))),
        }
    }

    let Some(to) = compatible else {
        return Ok(breaking_blocked.map(|(to, reason)| Plan::Blocked { to, reason }));
    };
    Ok(Some(match cargo_update(root, &spec, &to, true) {
        Ok(()) => Plan::Update {
            spec,
            to,
            kind: Kind::Compatible,
            manifests: Vec::new(),
            breaking_blocked,
        },
        Err(error) => Plan::Blocked {
            to,
            reason: reason(&error),
        },
    }))
}

fn apply(root: &Path, rows: &[Row], manifests: &mut Option<Vec<Manifest>>) -> Result<(), ExitCode> {
    for row in rows {
        let Plan::Update {
            spec,
            to,
            manifests: labels,
            ..
        } = &row.plan
        else {
            continue;
        };
        if labels.is_empty() {
            cargo_update(root, spec, to, false).map_err(|error| {
                eprintln!(
                    "cargo update -p {spec} --precise {to} failed: {}",
                    reason(&error)
                );
                ExitCode::from(2)
            })?;
        } else {
            let loaded = match manifests {
                Some(loaded) => loaded,
                None => manifests.insert(read_manifests(root)?),
            };
            apply_manifest_update(root, &row.name, to, labels, loaded)?;
        }
    }
    Ok(())
}

/// A title in the style of Dependabot: "Bump serde from 1.0.200 to 1.0.210",
/// or "Bump 3 dependencies".
fn title(rows: &[Row]) -> String {
    let updates: Vec<&Row> = rows
        .iter()
        .filter(|row| matches!(row.plan, Plan::Update { .. }))
        .collect();
    match updates.as_slice() {
        [] => "No dependency to update".to_owned(),
        [row] => match &row.plan {
            Plan::Update { to, .. } => format!("Bump {} from {} to {to}", row.name, row.from),
            Plan::Blocked { .. } => unreachable!("filtered above"),
        },
        many => format!("Bump {} dependencies", many.len()),
    }
}

fn render_markdown(rows: &[Row]) -> String {
    use std::fmt::Write;
    let mut out = format!("{PR_MARKER}\n### CargoScope: dependency updates\n\n");
    let updates: Vec<&Row> = rows
        .iter()
        .filter(|row| matches!(row.plan, Plan::Update { .. }))
        .collect();
    if updates.is_empty() {
        out.push_str("No dependency can be updated.\n\n");
    } else {
        out.push_str("| Package | From | To | Update | Changes |\n|---|---|---|---|---|\n");
        for row in &updates {
            if let Plan::Update {
                to,
                kind,
                manifests,
                ..
            } = &row.plan
            {
                let changes = if manifests.is_empty() {
                    "`Cargo.lock`".to_owned()
                } else {
                    format!("`Cargo.lock`, `{}`", manifests.join("`, `"))
                };
                let _ = writeln!(
                    out,
                    "| [`{name}`](https://crates.io/crates/{name}/{to}) | {} | **{to}** | {} | {changes} |",
                    row.from,
                    kind.as_str(),
                    name = row.name,
                );
            }
        }
        out.push('\n');
    }
    let refused: Vec<String> = rows
        .iter()
        .filter_map(|row| match &row.plan {
            Plan::Update {
                breaking_blocked: Some((to, why)),
                ..
            }
            | Plan::Blocked { to, reason: why } => Some(format!(
                "- `{}` {} → {to}: {}",
                row.name,
                row.from,
                why.replace('\n', " ")
            )),
            Plan::Update { .. } => None,
        })
        .collect();
    if !refused.is_empty() {
        let _ = writeln!(out, "**Not updated: {}**\n", refused.len());
        for line in refused {
            let _ = writeln!(out, "{line}");
        }
        out.push('\n');
    }
    if updates.iter().any(|row| {
        matches!(
            row.plan,
            Plan::Update {
                kind: Kind::Breaking,
                ..
            }
        )
    }) {
        out.push_str("Breaking updates raise the version requirement in the manifests: the code may need changes. ");
    }
    out.push_str("Made with `cargoscope fix --updates --apply`, which only resolves versions; review the build and tests before merging.\n");
    out
}

fn render_json(rows: &[Row]) -> String {
    let mut updates = Vec::new();
    let mut blocked = Vec::new();
    for row in rows {
        match &row.plan {
            Plan::Update {
                to,
                kind,
                manifests,
                breaking_blocked,
                ..
            } => updates.push(serde_json::json!({
                "package": row.name, "from": row.from, "to": to,
                "kind": kind.as_str(), "manifests": manifests,
                "breaking_blocked": breaking_blocked.as_ref().map(|(to, reason)| serde_json::json!({"to": to, "reason": reason})),
            })),
            Plan::Blocked { to, reason } => blocked.push(serde_json::json!({
                "package": row.name, "from": row.from, "to": to, "reason": reason,
            })),
        }
    }
    let mut text = serde_json::to_string_pretty(&serde_json::json!({
        "title": title(rows),
        "updates": updates,
        "blocked": blocked,
    }))
    .unwrap_or_default();
    text.push('\n');
    text
}

fn print_row(row: &Row) {
    match &row.plan {
        Plan::Update {
            to,
            kind,
            manifests,
            breaking_blocked,
            ..
        } => {
            let place = if manifests.is_empty() {
                String::new()
            } else {
                format!(" (in {})", manifests.join(", "))
            };
            println!(
                "{} {} -> {to} ({}){place}",
                row.name,
                row.from,
                kind.as_str()
            );
            if let Some((to, why)) = breaking_blocked {
                println!("  = {to} refused: {why}");
            }
        }
        Plan::Blocked { to, reason } => {
            println!("{} {} -> {to}: cannot update: {reason}", row.name, row.from);
        }
    }
}

/// `cargoscope fix --updates [PATH] [--breaking] [--apply] [--format
/// text|markdown|json] [--only NAMES]`.
///
/// # Errors
///
/// Returns an execution error exit code (`2`) when the project cannot be
/// scanned, manifests cannot be edited, or `cargo update` fails.
pub fn run(
    root: &Path,
    breaking: bool,
    apply_changes: bool,
    format: Format,
    only: Option<&[String]>,
) -> Result<ExitCode, ExitCode> {
    let inventory: Inventory = cargoscope_cargo::scan_cargo_project(root)
        .map_err(|error| execution_error(root, &error))?;
    let mut warnings = Vec::new();
    let (info, date) = crate::scan::registry_data(root, &inventory, &mut warnings);
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    if date.is_none() {
        eprintln!(
            "CargoScope needs crates.io data to find newer versions: run `cargoscope update` first."
        );
        return Err(ExitCode::from(2));
    }

    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    let mut manifests: Option<Vec<Manifest>> = None;
    for (package, info) in inventory.packages.iter().zip(&info) {
        if !package.direct
            || package.root
            || !info.outdated
            || !cargoscope_advisory::crates_io::is_crates_io(package.source.as_deref())
            || only.is_some_and(|names| !names.contains(&package.name))
            || !seen.insert((package.name.clone(), package.version.clone()))
        {
            continue;
        }
        if let Some(plan) = plan_package(root, package, info, breaking, &mut manifests)? {
            let row = Row {
                name: package.name.clone(),
                from: package.version.clone(),
                plan,
            };
            if format == Format::Text {
                print_row(&row);
            }
            rows.push(row);
        }
    }
    if apply_changes {
        apply(root, &rows, &mut manifests)?;
    }
    match format {
        Format::Markdown => print!("{}", render_markdown(&rows)),
        Format::Json => print!("{}", render_json(&rows)),
        Format::Text => {
            let updates = rows
                .iter()
                .filter(|row| matches!(row.plan, Plan::Update { .. }))
                .count();
            if rows.is_empty() {
                println!("Every direct dependency is up to date.");
            } else if apply_changes {
                println!("\nUpdated {updates} dependency(ies). Build and test before committing.");
            } else {
                println!(
                    "\nDry run: nothing was changed. Run `cargoscope fix --updates{} --apply` to make {updates} update(s).",
                    if breaking { " --breaking" } else { "" }
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::{Kind, Plan, Row, breaking_target, render_markdown, title};
    use cargoscope_core::PackageInfo;

    fn update(name: &str, from: &str, to: &str, kind: Kind) -> Row {
        Row {
            name: name.to_owned(),
            from: from.to_owned(),
            plan: Plan::Update {
                spec: format!("{name}@{from}"),
                to: to.to_owned(),
                kind,
                manifests: if kind == Kind::Breaking {
                    vec!["Cargo.toml".to_owned()]
                } else {
                    Vec::new()
                },
                breaking_blocked: None,
            },
        }
    }

    #[test]
    fn finds_the_newer_major_line() {
        let info = |latest: &str| PackageInfo {
            latest_version: Some(latest.to_owned()),
            outdated: true,
            ..PackageInfo::default()
        };
        assert_eq!(breaking_target(&info("2.0.1"), "1.4.0"), Some("2.0.1"));
        assert_eq!(breaking_target(&info("0.9.0"), "0.8.5"), Some("0.9.0"));
        assert_eq!(breaking_target(&info("1.5.0"), "1.4.0"), None);
        assert_eq!(breaking_target(&info("1.0.0"), "1.4.0"), None);
    }

    #[test]
    fn titles_and_bodies_look_like_dependabot() {
        let one = vec![update("serde", "1.0.200", "1.0.210", Kind::Compatible)];
        assert_eq!(title(&one), "Bump serde from 1.0.200 to 1.0.210");
        let many = vec![
            update("serde", "1.0.200", "1.0.210", Kind::Compatible),
            update("ureq", "2.12.1", "3.1.0", Kind::Breaking),
        ];
        assert_eq!(title(&many), "Bump 2 dependencies");
        let body = render_markdown(&many);
        assert!(body.starts_with(super::PR_MARKER));
        assert!(body.contains("| [`ureq`](https://crates.io/crates/ureq/3.1.0) | 2.12.1 | **3.1.0** | breaking | `Cargo.lock`, `Cargo.toml` |"), "{body}");
        assert!(body.contains("the code may need changes"));
    }
}
