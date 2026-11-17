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

use cargoscope_advisory::crate_files::CrateFiles;
use cargoscope_cargo::updates::{DependencyType, UpdateType, UpdatesConfig};
use cargoscope_core::{DependencyKind, Inventory, MaintenanceConcern, Package, PackageInfo};

use crate::execution_error;
use crate::fix_advisories::{
    Format, Manifest, apply_manifest_update, cargo_update, probe_manifest_update, read_manifests,
    reason,
};
use crate::update_notes::{
    LockDiff, project_rust_version, release_notes, rust_version_key, sanitize_notes,
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
    /// What the pull request body says about it beyond the versions.
    details: Details,
}

/// Facts about one update, for the pull request body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Details {
    /// The target version as published, with its build metadata
    /// (`1.2.1+spec-1.1.0`, where requirements and the plan say `1.2.1`).
    published_version: Option<String>,
    /// Publication date of the target version.
    published: Option<String>,
    /// Maintenance concerns of the crate, in words.
    concerns: Vec<String>,
    /// `Cargo.toml` and changelog of the current and target versions.
    from_files: Option<CrateFiles>,
    to_files: Option<CrateFiles>,
    /// Release notes after the current version up to the target, and where
    /// they come from (`CHANGELOG.md`, GitHub releases).
    notes: Option<(String, String)>,
}

/// Facts about the whole pull request.
#[derive(Debug, Default)]
struct Body {
    /// The `[updates] groups` entry the updates belong to.
    group: Option<String>,
    /// The lowest `rust-version` the project declares.
    rust_version: Option<String>,
    /// What changes in `Cargo.lock` (known once applied).
    lock: Option<LockDiff>,
    /// Advisories the updates resolve, and the ones they bring: crate, ID.
    fixed: Vec<(String, String)>,
    introduced: Vec<(String, String)>,
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

fn update_type_of(row: &Row) -> Option<UpdateType> {
    match &row.plan {
        Plan::Update { to, .. } => UpdateType::between(&row.from, to),
        Plan::Blocked { .. } | Plan::Ignored { .. } => None,
    }
}

fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("{count} {word}")
    } else if let Some(stem) = word.strip_suffix('y') {
        format!("{count} {stem}ies")
    } else {
        format!("{count} {word}s")
    }
}

fn advisory_link(id: &str) -> String {
    format!("[{id}](https://rustsec.org/advisories/{id}.html)")
}

/// The opening sentence: what is updated, how far, and what it fixes.
fn summary_line(updates: &[&Row], body: &Body) -> String {
    let mut line = match updates {
        [row] => {
            let Plan::Update { to, manifests, .. } = &row.plan else {
                unreachable!("updates only")
            };
            let update_type = update_type_of(row).map_or("", UpdateType::as_str);
            let place = if manifests.is_empty() {
                "changes only `Cargo.lock`".to_owned()
            } else {
                format!("raises the requirement in `{}`", manifests.join("`, `"))
            };
            format!(
                "Bumps [`{name}`](https://crates.io/crates/{name}) from {} to **{to}**: a {update_type} update that {place}.",
                row.from,
                name = row.name,
            )
        }
        many => {
            let mut counts: Vec<String> = Vec::new();
            for update_type in [UpdateType::Major, UpdateType::Minor, UpdateType::Patch] {
                let count = many
                    .iter()
                    .filter(|row| update_type_of(row) == Some(update_type))
                    .count();
                if count > 0 {
                    counts.push(format!("{count} {}", update_type.as_str()));
                }
            }
            let what = body.group.as_ref().map_or_else(
                || format!("Bumps {}", plural(many.len(), "dependency")),
                |group| format!("Bumps the `{group}` group with {} updates", many.len()),
            );
            format!("{what}: {}.", counts.join(", "))
        }
    };
    if !body.fixed.is_empty() {
        let ids: BTreeSet<&str> = body.fixed.iter().map(|(_, id)| id.as_str()).collect();
        let links: Vec<String> = ids.iter().map(|id| advisory_link(id)).collect();
        let _ = std::fmt::Write::write_fmt(
            &mut line,
            format_args!(
                " It fixes {}: {}.",
                plural(ids.len(), "advisory"),
                links.join(", ")
            ),
        );
    }
    line
}

/// A license expression with its alternatives and parts in a fixed order:
/// `MIT/Apache-2.0` and `Apache-2.0 OR MIT` read the same.
fn canonical_license(expression: &cargoscope_core::license::Expression) -> String {
    use cargoscope_core::license::Expression;
    let joined = |parts: &[Expression], word: &str| {
        let mut parts: Vec<String> = parts.iter().map(canonical_license).collect();
        parts.sort();
        format!("({})", parts.join(word))
    };
    match expression {
        Expression::License { id, exception } => match exception {
            Some(exception) => format!(
                "{} WITH {}",
                id.to_ascii_lowercase(),
                exception.to_ascii_lowercase()
            ),
            None => id.to_ascii_lowercase(),
        },
        Expression::Or(parts) => joined(parts, " OR "),
        Expression::And(parts) => joined(parts, " AND "),
    }
}

fn same_license(before: &str, after: &str) -> bool {
    match (
        cargoscope_core::license::parse(before),
        cargoscope_core::license::parse(after),
    ) {
        (Ok(before), Ok(after)) => canonical_license(&before) == canonical_license(&after),
        _ => before.trim() == after.trim(),
    }
}

/// The checks of one update for the table, and the ones that need attention.
fn checks(row: &Row, body: &Body) -> (Vec<String>, Vec<String>) {
    let Plan::Update {
        to,
        kind,
        manifests,
        ..
    } = &row.plan
    else {
        return (Vec::new(), Vec::new());
    };
    let name = &row.name;
    let mut cells = Vec::new();
    let mut attention = Vec::new();
    if *kind == Kind::Breaking {
        attention.push(format!(
            "`{name}` {} → {to} is a new major version: the requirement is raised in `{}`, and the code may need changes.",
            row.from,
            manifests.join("`, `")
        ));
    }
    for (_, id) in body.fixed.iter().filter(|(package, _)| package == name) {
        cells.push(format!("fixes {}", advisory_link(id)));
    }
    for (_, id) in body
        .introduced
        .iter()
        .filter(|(package, _)| package == name)
    {
        cells.push(format!("⚠️ affected by {}", advisory_link(id)));
        attention.push(format!(
            "`{name}` {to} is affected by {}.",
            advisory_link(id)
        ));
    }
    let details = &row.details;
    let old = details.from_files.as_ref();
    let new = details.to_files.as_ref();
    if let (Some(before), Some(after)) = (
        old.and_then(|files| files.license.as_deref()),
        new.and_then(|files| files.license.as_deref()),
    ) && !same_license(before, after)
    {
        cells.push(format!("⚠️ license `{before}` → `{after}`"));
        attention.push(format!(
            "`{name}` {to} changes its license from `{before}` to `{after}`."
        ));
    }
    if let Some(needed) = new.and_then(|files| files.rust_version.as_deref()) {
        let before = old.and_then(|files| files.rust_version.as_deref());
        let too_new = body
            .rust_version
            .as_deref()
            .is_some_and(|project| rust_version_key(needed) > rust_version_key(project));
        if too_new {
            let project = body.rust_version.as_deref().unwrap_or_default();
            cells.push(format!("⚠️ needs Rust {needed}"));
            attention.push(format!(
                "`{name}` {to} needs Rust {needed}; this project declares `rust-version = \"{project}\"`."
            ));
        } else if before.is_some_and(|before| before != needed) {
            cells.push(format!("Rust {} → {needed}", before.unwrap_or_default()));
        }
    }
    cells.extend(details.concerns.iter().cloned());
    if cells.is_empty() {
        cells.push("✅ no issue found".to_owned());
    }
    (cells, attention)
}

fn render_markdown(rows: &[Row], body: &Body) -> String {
    use std::fmt::Write;
    let mut out = format!("{PR_MARKER}\n");
    let updates: Vec<&Row> = rows
        .iter()
        .filter(|row| matches!(row.plan, Plan::Update { .. }))
        .collect();
    if updates.is_empty() {
        out.push_str("No dependency can be updated.\n\n");
    } else {
        let _ = writeln!(out, "{}\n", summary_line(&updates, body));
        let mut table = String::from(
            "| Package | Version | Update | Published | Checks | Links |\n|---|---|---|---|---|---|\n",
        );
        let mut attention = Vec::new();
        for row in &updates {
            let Plan::Update { to, kind, .. } = &row.plan else {
                continue;
            };
            let (cells, needs) = checks(row, body);
            attention.extend(needs);
            let update_type = update_type_of(row).map_or(kind.as_str(), UpdateType::as_str);
            let _ = writeln!(
                table,
                "| [`{name}`](https://crates.io/crates/{name}/{to}) | {} → **{to}** | {update_type} | {} | {} | {} |",
                row.from,
                row.details.published.as_deref().unwrap_or("?"),
                cells.join("<br>"),
                links(row, to),
                name = row.name,
            );
        }
        if !attention.is_empty() {
            out.push_str("> [!WARNING]\n> **Needs attention**\n>\n");
            for line in &attention {
                let _ = writeln!(out, "> - {line}");
            }
            out.push('\n');
        }
        out.push_str(&table);
        out.push('\n');
    }

    if let Some(lock) = body.lock.as_ref().filter(|lock| lock.changes() > 0) {
        let mut parts = Vec::new();
        if !lock.added.is_empty() {
            parts.push(format!("+{} added", lock.added.len()));
        }
        if !lock.removed.is_empty() {
            parts.push(format!("−{} removed", lock.removed.len()));
        }
        if !lock.updated.is_empty() {
            parts.push(format!("{} updated", lock.updated.len()));
        }
        let _ = writeln!(
            out,
            "**`Cargo.lock`**: {} · {} → {} packages\n",
            parts.join(" · "),
            lock.before,
            lock.after
        );
        let _ = writeln!(
            out,
            "<details><summary>Cargo.lock changes ({})</summary>\n",
            lock.changes()
        );
        for (name, from, to) in &lock.updated {
            let _ = writeln!(out, "- `{name}` {from} → {to}");
        }
        for (name, version) in &lock.added {
            let _ = writeln!(out, "- added `{name}` {version}");
        }
        for (name, version) in &lock.removed {
            let _ = writeln!(out, "- removed `{name}` {version}");
        }
        out.push_str("\n</details>\n\n");
    }

    for row in &updates {
        let Plan::Update { to, .. } = &row.plan else {
            continue;
        };
        let Some((source, notes)) = &row.details.notes else {
            continue;
        };
        let notes = sanitize_notes(notes, row.repository.as_deref());
        let _ = writeln!(
            out,
            "<details><summary>Release notes of <code>{}</code>, after {} up to {to} (from {source})</summary>\n\n{notes}\n\n</details>\n",
            row.name, row.from
        );
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

    if !updates.is_empty() {
        out.push_str("<details><summary>Skip an update</summary>\n\nAdd a rule to `[updates] ignore` in `cargoscope.toml`; the pull request closes at the next run.\n\n```toml\n[updates]\nignore = [\n");
        for row in &updates {
            let Plan::Update { to, .. } = &row.plan else {
                continue;
            };
            let _ = writeln!(
                out,
                "  {{ name = \"{name}\", versions = [\"{to}\"] }},  # skip {to} only",
                name = row.name
            );
            if let Some(update_type) = update_type_of(row) {
                let _ = writeln!(
                    out,
                    "  {{ name = \"{name}\", update-types = [\"{kind}\"] }},  # skip every {kind} update",
                    name = row.name,
                    kind = update_type.as_str()
                );
            }
        }
        out.push_str("]\n```\n\n</details>\n\n");
    }
    out.push_str("Made with `cargoscope fix --updates --apply`, which only resolves versions: the checks of this pull request build and test them.\n");
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

/// Whether `published` (`1.2.1+spec-1.1.0`) is the version `to` (`1.2.1`).
fn same_version(published: Option<&str>, to: &str) -> bool {
    published.is_some_and(|published| published == to || published.split('+').next() == Some(to))
}

/// The version a plan moves to, as published on crates.io.
fn published_version(plan: &Plan, info: &PackageInfo) -> Option<String> {
    let Plan::Update { to, .. } = plan else {
        return None;
    };
    [
        info.latest_version.as_deref(),
        info.latest_compatible.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|candidate| same_version(Some(candidate), to))
    .map_or_else(|| Some(to.clone()), |version| Some(version.to_owned()))
}

/// The publication date of the version a plan moves to.
fn published(plan: &Plan, info: &PackageInfo) -> Option<String> {
    let Plan::Update { to, .. } = plan else {
        return None;
    };
    let date = if same_version(info.latest_version.as_deref(), to) {
        info.latest_published.as_deref()
    } else if same_version(info.latest_compatible.as_deref(), to) {
        info.compatible_published.as_deref()
    } else {
        None
    };
    date.map(|date| date.get(..10).unwrap_or(date).to_owned())
}

fn describe_concern(concern: MaintenanceConcern, info: &PackageInfo) -> String {
    match concern {
        MaintenanceConcern::Archived => "repository archived".to_owned(),
        MaintenanceConcern::Stale => format!(
            "no release since {}",
            info.last_release.as_deref().unwrap_or("?")
        ),
        MaintenanceConcern::SingleOwner => "single owner".to_owned(),
    }
}

/// Reads what the pull request body needs beyond the plan: the files of
/// both versions of each update (from Cargo's cache, else crates.io), the
/// project's `rust-version`, the `Cargo.lock` changes and the advisories the
/// updates fix or bring. A missing piece is only left out of the body.
fn body_facts(
    root: &Path,
    before: &Inventory,
    rows: &mut [Row],
    config: &UpdatesConfig,
    applied: bool,
) -> Result<Body, ExitCode> {
    let cache = cargoscope_advisory::cache_dir().ok();
    for row in rows.iter_mut() {
        let Plan::Update { to, .. } = &row.plan else {
            continue;
        };
        let Some(cache) = cache.as_deref() else {
            break;
        };
        let target = row
            .details
            .published_version
            .clone()
            .unwrap_or_else(|| to.clone());
        for (version, slot) in [
            (row.from.clone(), &mut row.details.from_files),
            (target, &mut row.details.to_files),
        ] {
            match cargoscope_advisory::crate_files::crate_files(cache, &row.name, &version) {
                Ok(files) => *slot = Some(files),
                Err(error) => eprintln!(
                    "warning: could not read {} {version} from crates.io: {error}",
                    row.name
                ),
            }
        }
        let to = to.clone();
        row.details.notes = row
            .details
            .to_files
            .as_ref()
            .and_then(|files| files.changelog.as_ref())
            .and_then(|(file, text)| {
                release_notes(text, &row.from, &to)
                    .map(|notes| (format!("<code>{file}</code>"), notes))
            })
            .or_else(|| {
                let repository = row.repository.as_deref()?;
                match cargoscope_advisory::crate_files::github_releases(repository, &row.name) {
                    Ok(text) => release_notes(&text, &row.from, &to)
                        .map(|notes| ("GitHub releases".to_owned(), notes)),
                    Err(error) => {
                        eprintln!(
                            "warning: could not read the GitHub releases of {}: {error}",
                            row.name
                        );
                        None
                    }
                }
            });
    }

    let manifests = read_manifests(root)?;
    let mut body = Body {
        rust_version: project_rust_version(manifests.iter().map(|m| m.contents.as_str())),
        ..Body::default()
    };
    let pulls = pull_requests(rows, config);
    if let [pull] = pulls.as_slice()
        && config.groups.iter().any(|group| group.name == pull.key)
    {
        body.group = Some(pull.key.clone());
    }

    // After the update: the lockfile as written, or, in a dry run, the same
    // packages with the new versions of the updated crates.
    let after = if applied {
        cargoscope_cargo::scan_cargo_project(root).ok()
    } else {
        let mut after = before.clone();
        for package in &mut after.packages {
            if let Some(Plan::Update { to, .. }) = rows
                .iter()
                .find(|row| row.name == package.name && row.from == package.version)
                .map(|row| &row.plan)
            {
                package.version.clone_from(to);
            }
        }
        Some(after)
    };
    let Some(after) = after else {
        return Ok(body);
    };
    if applied {
        body.lock = Some(LockDiff::between(before, &after));
    }
    if let Some(database) = cache
        .as_deref()
        .and_then(|dir| cargoscope_advisory::AdvisoryDatabase::open(dir).ok())
    {
        let ids = |inventory: &Inventory| -> BTreeSet<(String, String)> {
            database
                .check(inventory)
                .findings
                .into_iter()
                .map(|finding| (inventory.packages[finding.package].name.clone(), finding.id))
                .collect()
        };
        let (old, new) = (ids(before), ids(&after));
        body.fixed = old.difference(&new).cloned().collect();
        body.introduced = new.difference(&old).cloned().collect();
    }
    Ok(body)
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
                details: Details {
                    published_version: published_version(&plan, info),
                    published: published(&plan, info),
                    concerns: info
                        .maintenance_concerns()
                        .into_iter()
                        .map(|concern| describe_concern(concern, info))
                        .collect(),
                    ..Details::default()
                },
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
        Format::Markdown => {
            let body = body_facts(root, &inventory, &mut rows, &config, apply_changes)?;
            print!("{}", render_markdown(&rows, &body));
        }
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
        Body, Details, Kind, Plan, Row, breaking_target, ignore_reason, pull_requests,
        render_markdown, title,
    };
    use crate::update_notes::LockDiff;
    use cargoscope_advisory::crate_files::CrateFiles;
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
            details: Details {
                published: Some("2026-11-01".to_owned()),
                ..Details::default()
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
        let body = render_markdown(&many, &Body::default());
        assert!(body.starts_with(super::PR_MARKER));
        assert!(
            body.contains("Bumps 2 dependencies: 1 major, 1 patch.\n"),
            "{body}"
        );
        assert!(body.contains("| [`ureq`](https://crates.io/crates/ureq/3.1.0) | 2.12.1 → **3.1.0** | major | 2026-11-01 | ✅ no issue found | [diff](https://diff.rs/ureq/2.12.1/3.1.0), [release notes](https://github.com/example/ureq/releases) |"), "{body}");
        assert!(body.contains("> [!WARNING]\n> **Needs attention**\n>\n> - `ureq` 2.12.1 → 3.1.0 is a new major version: the requirement is raised in `Cargo.toml`, and the code may need changes.\n"), "{body}");
        assert!(body.contains("  { name = \"serde\", versions = [\"1.0.210\"] },  # skip 1.0.210 only\n  { name = \"serde\", update-types = [\"patch\"] },  # skip every patch update\n"), "{body}");
        let single = render_markdown(&one, &Body::default());
        assert!(single.contains("Bumps [`serde`](https://crates.io/crates/serde) from 1.0.200 to **1.0.210**: a patch update that changes only `Cargo.lock`.\n"), "{single}");
        assert!(!single.contains("[!WARNING]"));
    }

    #[test]
    fn licenses_compare_by_meaning() {
        assert!(super::same_license("MIT/Apache-2.0", "Apache-2.0 OR MIT"));
        assert!(super::same_license("mit", "MIT"));
        assert!(!super::same_license("MIT OR Apache-2.0", "MIT"));
        assert!(!super::same_license(
            "MIT AND Apache-2.0",
            "MIT OR Apache-2.0"
        ));
    }

    #[test]
    fn bodies_show_what_needs_attention() {
        let mut row = update("toml", "0.8.23", "0.8.30", Kind::Compatible);
        row.details.from_files = Some(CrateFiles {
            rust_version: Some("1.65".to_owned()),
            license: Some("MIT OR Apache-2.0".to_owned()),
            changelog: None,
        });
        row.details.to_files = Some(CrateFiles {
            rust_version: Some("1.80".to_owned()),
            license: Some("MIT".to_owned()),
            changelog: Some((
                "CHANGELOG.md".to_owned(),
                "## 0.8.30\n- faster\n\n## 0.8.23\n- old\n".to_owned(),
            )),
        });
        row.details.concerns = vec!["single owner".to_owned()];
        row.details.notes = Some((
            "<code>CHANGELOG.md</code>".to_owned(),
            "#### 0.8.30\n- faster".to_owned(),
        ));
        let mut lock = LockDiff::default();
        lock.updated
            .push(("toml".into(), "0.8.23".into(), "0.8.30".into()));
        lock.added.push(("winnow".into(), "0.7.0".into()));
        (lock.before, lock.after) = (10, 11);
        let body = Body {
            group: Some("serialization".to_owned()),
            rust_version: Some("1.75".to_owned()),
            lock: Some(lock),
            fixed: vec![("toml".into(), "RUSTSEC-2026-0001".into())],
            introduced: Vec::new(),
        };
        let text = render_markdown(&[row], &body);
        assert!(text.contains("a patch update that changes only `Cargo.lock`. It fixes 1 advisory: [RUSTSEC-2026-0001](https://rustsec.org/advisories/RUSTSEC-2026-0001.html).\n"), "{text}");
        assert!(text.contains("> - `toml` 0.8.30 changes its license from `MIT OR Apache-2.0` to `MIT`.\n> - `toml` 0.8.30 needs Rust 1.80; this project declares `rust-version = \"1.75\"`.\n"), "{text}");
        assert!(text.contains("| fixes [RUSTSEC-2026-0001](https://rustsec.org/advisories/RUSTSEC-2026-0001.html)<br>⚠️ license `MIT OR Apache-2.0` → `MIT`<br>⚠️ needs Rust 1.80<br>single owner |"), "{text}");
        assert!(
            text.contains("**`Cargo.lock`**: +1 added · 1 updated · 10 → 11 packages\n"),
            "{text}"
        );
        assert!(
            text.contains("- `toml` 0.8.23 → 0.8.30\n- added `winnow` 0.7.0\n"),
            "{text}"
        );
        assert!(text.contains("<details><summary>Release notes of <code>toml</code>, after 0.8.23 up to 0.8.30 (from <code>CHANGELOG.md</code>)</summary>\n\n#### 0.8.30\n- faster\n\n</details>"), "{text}");
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
