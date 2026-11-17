//! `cargoscope fix --updates`: moves direct dependencies to their newest
//! versions, as Dependabot version updates do.
//!
//! For each direct crates.io dependency with a newer version in the cached
//! crates.io data (`cargoscope update`):
//!
//! - the newest SemVer-compatible version is set in `Cargo.lock` with
//!   `cargo update -p name@version --precise new` when the manifests already
//!   allow it, else by raising the requirement that holds it back (a pin such
//!   as `=0.4.19` stays a pin: `=0.4.45`);
//! - with `--breaking`, the newest version of a newer major line is tried
//!   first: the requirement is raised in the manifests that declare the crate,
//!   and Cargo must accept it, else the compatible update is kept.
//!
//! Like `fix --advisories`, it only resolves versions: nothing is compiled.
//! A breaking update may need code changes; the pull request's CI says.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use cargoscope_cargo::updates::{DependencyType, UpdateType, UpdatesConfig};
use cargoscope_core::{DependencyKind, Inventory, Package, PackageInfo};

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
    /// Declared only as a dev-dependency.
    dev: bool,
    /// Repository URL, when known (for links to release notes).
    repository: Option<String>,
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
    /// Skipped by `[updates] ignore` in cargoscope.toml.
    Ignored {
        to: String,
        reason: String,
    },
}

/// Why `[updates] ignore` skips moving `name` from `from` to `to`, if it does.
fn ignore_reason(config: &UpdatesConfig, name: &str, from: &str, to: &str) -> Option<String> {
    let update_type = UpdateType::between(from, to)?;
    let rule = config.ignored(name, to, update_type)?;
    Some(match &rule.reason {
        Some(reason) => format!("ignored in cargoscope.toml: {reason}"),
        None => format!("ignored in cargoscope.toml (`{}`)", rule.name),
    })
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
    config: &UpdatesConfig,
    manifests: &mut Option<Vec<Manifest>>,
) -> Result<Option<Plan>, ExitCode> {
    let spec = format!("{}@{}", package.name, package.version);
    let compatible = info.compatible_upgrade(&package.version).map(str::to_owned);
    let mut breaking_blocked = None;
    let mut ignored = None;

    let breaking_target = breaking_target(info, &package.version).filter(|target| {
        match ignore_reason(config, &package.name, &package.version, target) {
            Some(reason) => {
                ignored = Some(Plan::Ignored {
                    to: (*target).to_owned(),
                    reason,
                });
                false
            }
            None => true,
        }
    });
    if breaking && let Some(target) = breaking_target {
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
        return Ok(breaking_blocked
            .map(|(to, reason)| Plan::Blocked { to, reason })
            .or(ignored.filter(|_| breaking)));
    };
    if let Some(reason) = ignore_reason(config, &package.name, &package.version, &to) {
        return Ok(Some(Plan::Ignored { to, reason }));
    }
    let lock_error = match cargo_update(root, &spec, &to, true) {
        Ok(()) => {
            return Ok(Some(Plan::Update {
                spec,
                to,
                kind: Kind::Compatible,
                manifests: Vec::new(),
                breaking_blocked,
            }));
        }
        Err(error) => error,
    };
    // A requirement that holds the version back (`=0.4.19`, `~1.2.0`, `<1.5`):
    // raise it in the manifests, as Dependabot does; a pin stays a pin.
    let loaded = match manifests {
        Some(loaded) => loaded,
        None => manifests.insert(read_manifests(root)?),
    };
    let mut version = semver::Version::parse(&to).map_err(|_| ExitCode::from(2))?;
    version.build = semver::BuildMetadata::EMPTY;
    Ok(Some(
        match probe_manifest_update(root, package, &version, loaded) {
            Ok(Some(labels)) => Plan::Update {
                spec,
                to: version.to_string(),
                kind: Kind::Compatible,
                manifests: labels,
                breaking_blocked,
            },
            Ok(None) | Err(_) => Plan::Blocked {
                to,
                reason: reason(&lock_error),
            },
        },
    ))
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
            Plan::Blocked { .. } | Plan::Ignored { .. } => unreachable!("filtered above"),
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
        out.push_str(
            "| Package | From | To | Update | Changes | Links |\n|---|---|---|---|---|---|\n",
        );
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
                let update_type =
                    UpdateType::between(&row.from, to).map_or(kind.as_str(), UpdateType::as_str);
                let _ = writeln!(
                    out,
                    "| [`{name}`](https://crates.io/crates/{name}/{to}) | {} | **{to}** | {update_type} | {changes} | {} |",
                    row.from,
                    links(row, to),
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
            Plan::Update { .. } | Plan::Ignored { .. } => None,
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

/// Links to read before merging: the source diff between the two versions
/// on diff.rs, and the release notes when the repository is on GitHub.
fn links(row: &Row, to: &str) -> String {
    let mut links = vec![format!(
        "[diff](https://diff.rs/{name}/{from}/{to})",
        name = row.name,
        from = row.from
    )];
    if let Some(repository) = row
        .repository
        .as_deref()
        .map(|url| url.trim_end_matches('/').trim_end_matches(".git"))
        .filter(|url| url.starts_with("https://github.com/") && url.matches('/').count() == 4)
    {
        links.push(format!("[release notes]({repository}/releases)"));
    }
    links.join(", ")
}

/// One pull request to open: a group, or a single crate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PullRequest {
    /// Branch suffix: the group name, or the crate name.
    key: String,
    title: String,
    packages: Vec<String>,
    /// The largest update type in it, for auto-merge rules.
    update_type: UpdateType,
}

/// The pull requests for `rows`: one per `[updates] groups` entry with
/// updates (in configuration order), then one per remaining crate (by
/// name), at most `open-pull-requests-limit` in all.
fn pull_requests(rows: &[Row], config: &UpdatesConfig) -> Vec<PullRequest> {
    let mut grouped: Vec<(String, Vec<(&Row, UpdateType)>)> = config
        .groups
        .iter()
        .map(|group| (group.name.clone(), Vec::new()))
        .collect();
    let mut singles: Vec<(&Row, UpdateType)> = Vec::new();
    for row in rows {
        let Plan::Update { to, .. } = &row.plan else {
            continue;
        };
        let Some(update_type) = UpdateType::between(&row.from, to) else {
            continue;
        };
        let dependency_type = if row.dev {
            DependencyType::Development
        } else {
            DependencyType::Production
        };
        match config.group_of(&row.name, dependency_type, update_type) {
            Some(group) => {
                if let Some((_, members)) = grouped.iter_mut().find(|(name, _)| *name == group.name)
                {
                    members.push((row, update_type));
                }
            }
            None => singles.push((row, update_type)),
        }
    }
    singles.sort_by(|left, right| left.0.name.cmp(&right.0.name));
    let mut pulls = Vec::new();
    for (name, members) in grouped {
        let Some(update_type) = members.iter().map(|(_, update_type)| *update_type).max() else {
            continue;
        };
        let title = match members.as_slice() {
            [(row, _)] => single_title(row),
            _ => format!("Bump the {name} group with {} updates", members.len()),
        };
        pulls.push(PullRequest {
            key: name,
            title,
            packages: members.iter().map(|(row, _)| row.name.clone()).collect(),
            update_type,
        });
    }
    for (row, update_type) in singles {
        pulls.push(PullRequest {
            key: row.name.clone(),
            title: single_title(row),
            packages: vec![row.name.clone()],
            update_type,
        });
    }
    if let Some(limit) = config.open_pull_requests_limit {
        pulls.truncate(limit);
    }
    pulls
}

fn single_title(row: &Row) -> String {
    match &row.plan {
        Plan::Update { to, .. } => format!("Bump {} from {} to {to}", row.name, row.from),
        Plan::Blocked { .. } | Plan::Ignored { .. } => format!("Bump {}", row.name),
    }
}

fn render_json(rows: &[Row], config: &UpdatesConfig) -> String {
    let mut updates = Vec::new();
    let mut blocked = Vec::new();
    let mut ignored = Vec::new();
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
            Plan::Ignored { to, reason } => ignored.push(serde_json::json!({
                "package": row.name, "from": row.from, "to": to, "reason": reason,
            })),
        }
    }
    let pulls: Vec<serde_json::Value> = pull_requests(rows, config)
        .into_iter()
        .map(|pull| {
            serde_json::json!({
                "key": pull.key, "title": pull.title, "packages": pull.packages,
                "update_type": pull.update_type.as_str(),
            })
        })
        .collect();
    let mut text = serde_json::to_string_pretty(&serde_json::json!({
        "title": title(rows),
        "pull_requests": pulls,
        "updates": updates,
        "blocked": blocked,
        "ignored": ignored,
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
        Plan::Ignored { to, reason } => {
            println!("{} {} -> {to}: {reason}", row.name, row.from);
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

    let config =
        cargoscope_cargo::updates::load(root).map_err(|error| execution_error(root, &error))?;
    let kinds = cargoscope_cargo::direct_dependency_kinds(root).unwrap_or_default();
    let dev_only = |name: &str| {
        kinds
            .get(name)
            .is_some_and(|kinds| kinds.iter().all(|kind| *kind == DependencyKind::Dev))
    };
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    let mut manifests: Option<Vec<Manifest>> = None;
    for (package, info) in inventory.packages.iter().zip(&info) {
        if !package.direct
            || package.root
            || !info.outdated
            || !cargoscope_advisory::crates_io::is_crates_io(package.source.as_deref())
            || only.is_some_and(|names| !names.contains(&package.name))
            || (!config.include_dev && dev_only(&package.name))
            || !seen.insert((package.name.clone(), package.version.clone()))
        {
            continue;
        }
        if let Some(plan) = plan_package(root, package, info, breaking, &config, &mut manifests)? {
            let row = Row {
                name: package.name.clone(),
                from: package.version.clone(),
                plan,
                dev: dev_only(&package.name),
                repository: info.repository.clone(),
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
        Format::Json => print!("{}", render_json(&rows, &config)),
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
    use super::{
        Kind, Plan, Row, breaking_target, ignore_reason, pull_requests, render_markdown, title,
    };
    use cargoscope_cargo::updates::UpdateType;
    use cargoscope_core::PackageInfo;

    fn config(text: &str) -> cargoscope_cargo::updates::UpdatesConfig {
        cargoscope_cargo::updates::from_toml(text).expect("valid")
    }

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
            dev: false,
            repository: Some(format!("https://github.com/example/{name}")),
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
        assert!(body.contains("| [`ureq`](https://crates.io/crates/ureq/3.1.0) | 2.12.1 | **3.1.0** | major | `Cargo.lock`, `Cargo.toml` | [diff](https://diff.rs/ureq/2.12.1/3.1.0), [release notes](https://github.com/example/ureq/releases) |"), "{body}");
        assert!(body.contains("the code may need changes"));
    }

    #[test]
    fn groups_then_single_crates_up_to_the_limit() {
        let rows = vec![
            update("tokio", "1.40.0", "1.41.0", Kind::Compatible),
            update("serde", "1.0.200", "1.0.210", Kind::Compatible),
            update("serde_json", "1.0.120", "1.1.0", Kind::Compatible),
            Row {
                dev: true,
                ..update("tempfile", "3.10.0", "3.12.0", Kind::Compatible)
            },
            update("anyhow", "1.0.80", "1.0.90", Kind::Compatible),
        ];
        let config = config(
            "[updates]\ngroups = [\n  { name = \"serde\", patterns = [\"serde*\"] },\n  { name = \"dev\", dependency-type = \"development\" },\n  { name = \"empty\", patterns = [\"nothing*\"] },\n]\n",
        );
        let pulls = pull_requests(&rows, &config);
        let summary: Vec<(&str, &str, Vec<&str>, &str)> = pulls
            .iter()
            .map(|pull| {
                (
                    pull.key.as_str(),
                    pull.title.as_str(),
                    pull.packages.iter().map(String::as_str).collect(),
                    pull.update_type.as_str(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    "serde",
                    "Bump the serde group with 2 updates",
                    vec!["serde", "serde_json"],
                    "minor"
                ),
                (
                    "dev",
                    "Bump tempfile from 3.10.0 to 3.12.0",
                    vec!["tempfile"],
                    "minor"
                ),
                (
                    "anyhow",
                    "Bump anyhow from 1.0.80 to 1.0.90",
                    vec!["anyhow"],
                    "patch"
                ),
                (
                    "tokio",
                    "Bump tokio from 1.40.0 to 1.41.0",
                    vec!["tokio"],
                    "minor"
                ),
            ]
        );
        let limited = config_with_limit(2);
        assert_eq!(pull_requests(&rows, &limited).len(), 2);
    }

    fn config_with_limit(limit: usize) -> cargoscope_cargo::updates::UpdatesConfig {
        config(&format!("[updates]\nopen-pull-requests-limit = {limit}\n"))
    }

    #[test]
    fn ignore_rules_name_their_reason() {
        let config = config(
            "[updates]\nignore = [{ name = \"tokio\", update-types = [\"major\"], reason = \"migrating in Q3\" }, { name = \"aws-*\" }]\n",
        );
        assert_eq!(
            ignore_reason(&config, "tokio", "1.40.0", "2.0.0").as_deref(),
            Some("ignored in cargoscope.toml: migrating in Q3")
        );
        assert_eq!(ignore_reason(&config, "tokio", "1.40.0", "1.41.0"), None);
        assert_eq!(
            ignore_reason(&config, "aws-config", "1.0.0", "1.0.1").as_deref(),
            Some("ignored in cargoscope.toml (`aws-*`)")
        );
        assert_eq!(
            UpdateType::between("1.40.0", "2.0.0"),
            Some(UpdateType::Major)
        );
    }
}
