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
use cargoscope_advisory::crates_io::{RegistryCache, ReleaseTime};
use cargoscope_cargo::ecosystem_updates::{
    ActionUse, CandidateRelease, DockerFrom, EcosystemPlan, apply_action_updates,
    apply_docker_updates, find_action_uses, find_docker_froms, plan_action_update,
    plan_docker_update,
};
use cargoscope_cargo::updates::{DependencyType, UpdateType, UpdatesConfig, VersioningStrategy};
use cargoscope_core::{DependencyKind, Inventory, MaintenanceConcern, Package, PackageInfo};

use crate::execution_error;
use crate::fix_advisories::{
    Format, Manifest, apply_manifest_update_with_widen, cargo_update,
    probe_manifest_update_with_widen, read_manifests, reason, run_cargo_update, strip_ansi,
};
use crate::update_notes::{
    LockDiff, project_rust_version, release_notes, rust_version_key, sanitize_notes,
};

/// Command parsed from a comment on a CargoScope update pull request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrCommand {
    /// `/cargoscope rebase` or `@cargoscope rebase`.
    Rebase,
    /// `/cargoscope recreate` or `@cargoscope recreate`.
    Recreate,
    /// `/cargoscope ignore this version`.
    IgnoreVersion,
    /// `/cargoscope ignore this major version`.
    IgnoreMajor,
    /// `/cargoscope ignore this minor version`.
    IgnoreMinor,
    /// `/cargoscope ignore this dependency` (or `crate`).
    IgnoreDependency,
}

impl PrCommand {
    const fn action_name(self) -> &'static str {
        match self {
            Self::Rebase => "rebase",
            Self::Recreate => "recreate",
            Self::IgnoreVersion
            | Self::IgnoreMajor
            | Self::IgnoreMinor
            | Self::IgnoreDependency => "ignore",
        }
    }
}

/// Parses a PR comment looking for `/cargoscope <command>` or `@cargoscope <command>`.
#[must_use]
pub fn parse_pr_comment(comment: &str) -> Option<PrCommand> {
    for raw_line in comment.lines() {
        let trimmed = raw_line.trim();
        let rest = trimmed
            .strip_prefix("/cargoscope")
            .or_else(|| trimmed.strip_prefix("@cargoscope"))
            .or_else(|| trimmed.strip_prefix("/CARGOSCOPE"))
            .or_else(|| trimmed.strip_prefix("@CARGOSCOPE"));
        let Some(after) = rest else {
            continue;
        };
        if !after.is_empty() && !after.starts_with(char::is_whitespace) {
            continue;
        }
        let normalized: String = after
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        let parsed = match normalized.as_str() {
            "rebase" => Some(PrCommand::Rebase),
            "recreate" => Some(PrCommand::Recreate),
            "ignore this version" => Some(PrCommand::IgnoreVersion),
            "ignore this major version" => Some(PrCommand::IgnoreMajor),
            "ignore this minor version" => Some(PrCommand::IgnoreMinor),
            "ignore this dependency" | "ignore this crate" => Some(PrCommand::IgnoreDependency),
            _ => None,
        };
        if parsed.is_some() {
            return parsed;
        }
    }
    None
}

/// Extracts `(package, from, to)` rows from the Markdown table of a
/// CargoScope update pull request (`<!-- cargoscope-update-pr -->`).
#[must_use]
pub fn parse_pr_body_updates(body: &str) -> Vec<(String, String, String)> {
    let mut updates = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 {
            continue;
        }
        let pkg_cell = cells[1];
        let ver_cell = cells[2];
        let Some(pkg_start) = pkg_cell.find('`') else {
            continue;
        };
        let Some(pkg_rel_end) = pkg_cell[pkg_start + 1..].find('`') else {
            continue;
        };
        let name = pkg_cell[pkg_start + 1..pkg_start + 1 + pkg_rel_end].trim();
        let Some((from, to_raw)) = ver_cell.split_once('→') else {
            continue;
        };
        let from = from.trim();
        let to = to_raw.trim().trim_matches('*').trim();
        if !name.is_empty() && !from.is_empty() && !to.is_empty() {
            updates.push((name.to_owned(), from.to_owned(), to.to_owned()));
        }
    }
    updates
}

/// Executes a PR comment command against a `<!-- cargoscope-update-pr -->`
/// pull request body and prints a JSON summary on stdout.
///
/// # Errors
///
/// Returns exit code `2` when the PR body is unreadable or not a CargoScope
/// update PR, when the comment contains no supported command, or when
/// `cargoscope.toml` cannot be read or written.
pub fn run_comment_command(
    root: &Path,
    comment: &str,
    pr_body_path: &Path,
    apply_changes: bool,
    paint: cargoscope_report::Paint,
) -> Result<ExitCode, ExitCode> {
    let body = std::fs::read_to_string(pr_body_path).map_err(|error| {
        eprintln!(
            "CargoScope could not read {}: {error}",
            pr_body_path.display()
        );
        ExitCode::from(2)
    })?;
    if !body.trim_start().starts_with(PR_MARKER) {
        eprintln!("Pull request body is not a CargoScope update pull request.");
        return Err(ExitCode::from(2));
    }
    let Some(command) = parse_pr_comment(comment) else {
        eprintln!("Unsupported comment command: `{}`.", comment.trim());
        return Err(ExitCode::from(2));
    };
    let updates = parse_pr_body_updates(&body);
    if updates.is_empty() {
        eprintln!("No dependency updates found in pull request body.");
        return Err(ExitCode::from(2));
    }
    let mut packages: Vec<String> = updates.iter().map(|(name, _, _)| name.clone()).collect();
    packages.sort();
    packages.dedup();
    let has_major = body.contains(" | major | ");

    match command {
        PrCommand::Rebase | PrCommand::Recreate => {
            if apply_changes {
                return run(root, has_major, true, Format::Json, Some(&packages), paint);
            }
            let payload = serde_json::json!({
                "command": command.action_name(),
                "packages": packages,
                "breaking": has_major,
                "modified": false,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
            Ok(ExitCode::SUCCESS)
        }
        PrCommand::IgnoreVersion
        | PrCommand::IgnoreMajor
        | PrCommand::IgnoreMinor
        | PrCommand::IgnoreDependency => {
            let config_path = root.join(cargoscope_cargo::config::FILE_NAME);
            let existing = if config_path.exists() {
                std::fs::read_to_string(&config_path).map_err(|error| {
                    eprintln!(
                        "CargoScope could not read {}: {error}",
                        config_path.display()
                    );
                    ExitCode::from(2)
                })?
            } else {
                String::new()
            };
            let mut updated = existing.clone();
            let mut any_changed = false;
            for (name, _, to) in &updates {
                let versions = [to.clone()];
                let major = [UpdateType::Major];
                let minor = [UpdateType::Minor];
                let (next, changed) = match command {
                    PrCommand::IgnoreVersion => cargoscope_cargo::updates::add_ignore_rule(
                        &updated,
                        name,
                        Some(&versions),
                        None,
                        Some("ignored from pull request comment"),
                    ),
                    PrCommand::IgnoreMajor => cargoscope_cargo::updates::add_ignore_rule(
                        &updated,
                        name,
                        None,
                        Some(&major),
                        Some("ignored from pull request comment"),
                    ),
                    PrCommand::IgnoreMinor => cargoscope_cargo::updates::add_ignore_rule(
                        &updated,
                        name,
                        None,
                        Some(&minor),
                        Some("ignored from pull request comment"),
                    ),
                    PrCommand::IgnoreDependency => cargoscope_cargo::updates::add_ignore_rule(
                        &updated,
                        name,
                        None,
                        None,
                        Some("ignored from pull request comment"),
                    ),
                    PrCommand::Rebase | PrCommand::Recreate => unreachable!(),
                }
                .map_err(|error| execution_error(root, &error))?;
                updated = next;
                any_changed |= changed;
            }
            if apply_changes && any_changed {
                std::fs::write(&config_path, &updated).map_err(|error| {
                    eprintln!(
                        "CargoScope could not write {}: {error}",
                        config_path.display()
                    );
                    ExitCode::from(2)
                })?;
            }
            let rule_summary = match command {
                PrCommand::IgnoreVersion => "ignore this version",
                PrCommand::IgnoreMajor => "ignore this major version",
                PrCommand::IgnoreMinor => "ignore this minor version",
                PrCommand::IgnoreDependency => "ignore this dependency",
                PrCommand::Rebase | PrCommand::Recreate => "",
            };
            let payload = serde_json::json!({
                "command": "ignore",
                "rule": rule_summary,
                "packages": packages,
                "modified": any_changed,
                "breaking": has_major,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

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

/// Ecosystem owning a planned dependency update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum UpdateEcosystem {
    #[default]
    Cargo,
    GitHubActions,
    Docker,
}

impl UpdateEcosystem {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::GitHubActions => "github-actions",
            Self::Docker => "docker",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum EcosystemTarget {
    #[default]
    Cargo,
    Action {
        action: ActionUse,
        target_ref: String,
        display_tag: Option<String>,
    },
    Docker {
        from: DockerFrom,
        new_tag: String,
    },
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
    /// Ecosystem owning this entry (`cargo`, `github-actions`, or `docker`).
    ecosystem: UpdateEcosystem,
    /// Ecosystem-specific apply target (non-Cargo edits for `.github/workflows` / `Dockerfile`).
    target: EcosystemTarget,
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
        /// Manifests whose requirement is raised (breaking updates or `increase`/`widen`).
        manifests: Vec<String>,
        /// A newer major version Cargo refused, and why (when `--breaking`
        /// fell back to the compatible update).
        breaking_blocked: Option<(String, String)>,
        /// True when updating a `git+...` dependency (applied with `cargo update -p` without `--precise`).
        is_git: bool,
        /// Newer release skipped due to cooldown, when an older eligible release was chosen instead.
        cooldown_skipped: Option<String>,
    },
    Blocked {
        to: String,
        reason: String,
    },
    /// Skipped by `[updates] ignore` in cargoscope.toml or `.github/dependabot.yml`.
    Ignored {
        to: String,
        reason: String,
    },
    /// Held back by the release age cooldown (default 7 days).
    Cooldown {
        to: String,
        age_days: u64,
        required_days: u64,
    },
}

enum CooldownPick {
    Use {
        version: String,
        skipped_note: Option<String>,
    },
    Held {
        to: String,
        age_days: u64,
        required_days: u64,
    },
}

fn pick_with_cooldown(
    package: &str,
    current: &str,
    candidate: &str,
    compatible_only: bool,
    releases: Option<&[ReleaseTime]>,
    config: &UpdatesConfig,
    now_unix: u64,
) -> CooldownPick {
    let Some(update_type) = UpdateType::between(current, candidate) else {
        return CooldownPick::Use {
            version: candidate.to_owned(),
            skipped_note: None,
        };
    };
    let required_days = config.cooldown.days_for(package, update_type);
    if required_days == 0 {
        return CooldownPick::Use {
            version: candidate.to_owned(),
            skipped_note: None,
        };
    }
    let Some(releases) = releases else {
        return CooldownPick::Use {
            version: candidate.to_owned(),
            skipped_note: None,
        };
    };
    let pub_unix = releases
        .iter()
        .find(|r| r.version == candidate)
        .and_then(|r| r.published_unix);
    let Some(pub_ts) = pub_unix else {
        return CooldownPick::Use {
            version: candidate.to_owned(),
            skipped_note: None,
        };
    };
    let age_secs = now_unix.saturating_sub(pub_ts);
    let required_secs = required_days.saturating_mul(86_400);
    if age_secs >= required_secs {
        return CooldownPick::Use {
            version: candidate.to_owned(),
            skipped_note: None,
        };
    }
    let age_days = age_secs / 86_400;
    let cur_parsed = semver::Version::parse(current).ok();
    let best_older = cur_parsed.as_ref().and_then(|cur| {
        let mut eligible: Vec<(&str, semver::Version)> = releases
            .iter()
            .filter(|r| !r.yanked)
            .filter(|r| {
                r.published_unix
                    .is_some_and(|ts| now_unix.saturating_sub(ts) >= required_secs)
            })
            .filter_map(|r| {
                let v = semver::Version::parse(&r.version).ok()?;
                if v <= *cur {
                    return None;
                }
                if !v.pre.is_empty() && cur.pre.is_empty() {
                    return None;
                }
                if compatible_only && !cargoscope_core::is_semver_compatible(cur, &v) {
                    return None;
                }
                Some((r.version.as_str(), v))
            })
            .collect();
        eligible.sort_by(|(_, a), (_, b)| a.cmp(b));
        eligible.pop().map(|(s, _)| s.to_owned())
    });
    if let Some(version) = best_older {
        let note = format!(
            "{candidate} published {age_days}d ago (< {required_days}d cooldown; override with `--cooldown-for {package}=1` or `[updates.cooldown.overrides]`)"
        );
        CooldownPick::Use {
            version,
            skipped_note: Some(note),
        }
    } else {
        CooldownPick::Held {
            to: candidate.to_owned(),
            age_days,
            required_days,
        }
    }
}

/// Options controlling `cargoscope fix --updates`.
pub struct UpdateOptions<'a> {
    /// Also consider newer SemVer-breaking major/0.x lines.
    pub breaking: bool,
    /// Write changes to `Cargo.lock` and `Cargo.toml`.
    pub apply: bool,
    /// Output format (`Text`, `Markdown`, or `Json`).
    pub format: Format,
    /// Optional dependency name filter.
    pub only: Option<&'a [String]>,
    /// Override default cooldown days (7 by default).
    pub cooldown_days: Option<u64>,
    /// Per-dependency cooldown overrides `(crate, days)`.
    pub cooldown_overrides: &'a [(String, u64)],
    /// Manifest requirement update strategy override.
    pub versioning_strategy: Option<VersioningStrategy>,
    /// Optional ecosystems filter (`auto`, `all`, or subset of `cargo,github-actions,docker`).
    pub ecosystems: Option<&'a [String]>,
    /// Scan clock in Unix seconds (`None` uses system wall-clock).
    pub now: Option<u64>,
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

struct PlanContext<'a> {
    root: &'a Path,
    strategy: VersioningStrategy,
    breaking: bool,
    config: &'a UpdatesConfig,
    releases: Option<&'a [ReleaseTime]>,
    now_unix: u64,
}

fn plan_package(
    ctx: &PlanContext<'_>,
    package: &Package,
    info: &PackageInfo,
    manifests: &mut Option<Vec<Manifest>>,
) -> Result<Option<Plan>, ExitCode> {
    let root = ctx.root;
    let config = ctx.config;
    let strategy = ctx.strategy;
    let widen = strategy == VersioningStrategy::Widen;
    let allow_manifest_edit = strategy != VersioningStrategy::LockfileOnly;
    let always_edit_manifest = strategy == VersioningStrategy::Increase;
    let allow_breaking = ctx.breaking
        || matches!(
            strategy,
            VersioningStrategy::Increase | VersioningStrategy::Widen
        );

    let spec = format!("{}@{}", package.name, package.version);
    let compatible_raw = info.compatible_upgrade(&package.version).map(str::to_owned);
    let mut breaking_blocked = None;
    let mut ignored = None;
    let mut cooldown_held: Option<Plan> = None;

    let mut breaking_plan: Option<(String, Option<String>)> = None;
    if allow_breaking
        && allow_manifest_edit
        && let Some(target) = breaking_target(info, &package.version)
    {
        match pick_with_cooldown(
            &package.name,
            &package.version,
            target,
            false,
            ctx.releases,
            config,
            ctx.now_unix,
        ) {
            CooldownPick::Held {
                to,
                age_days,
                required_days,
            } => {
                cooldown_held = Some(Plan::Cooldown {
                    to,
                    age_days,
                    required_days,
                });
            }
            CooldownPick::Use {
                version,
                skipped_note,
            } => {
                if let Some(reason) =
                    ignore_reason(config, &package.name, &package.version, &version)
                {
                    ignored = Some(Plan::Ignored {
                        to: version,
                        reason,
                    });
                } else {
                    breaking_plan = Some((version, skipped_note));
                }
            }
        }
    }

    if let Some((target, cooldown_skipped)) = breaking_plan {
        let loaded = match manifests {
            Some(loaded) => loaded,
            None => manifests.insert(read_manifests(root)?),
        };
        let mut version = semver::Version::parse(&target).map_err(|_| ExitCode::from(2))?;
        version.build = semver::BuildMetadata::EMPTY;
        let target = version.to_string();
        match probe_manifest_update_with_widen(root, package, &version, loaded, widen) {
            Ok(Some(labels)) => {
                return Ok(Some(Plan::Update {
                    spec,
                    to: target,
                    kind: Kind::Breaking,
                    manifests: labels,
                    breaking_blocked: None,
                    is_git: false,
                    cooldown_skipped,
                }));
            }
            Ok(None) => {
                breaking_blocked =
                    Some((target, "no manifest of the project declares it".to_owned()));
            }
            Err(error) => breaking_blocked = Some((target, reason(&error))),
        }
    }

    let Some(compat_candidate) = compatible_raw else {
        return Ok(breaking_blocked
            .map(|(to, reason)| Plan::Blocked { to, reason })
            .or(ignored.filter(|_| allow_breaking))
            .or(cooldown_held));
    };

    let (to, cooldown_skipped) = match pick_with_cooldown(
        &package.name,
        &package.version,
        &compat_candidate,
        true,
        ctx.releases,
        config,
        ctx.now_unix,
    ) {
        CooldownPick::Held {
            to,
            age_days,
            required_days,
        } => {
            return Ok(Some(cooldown_held.unwrap_or(Plan::Cooldown {
                to,
                age_days,
                required_days,
            })));
        }
        CooldownPick::Use {
            version,
            skipped_note,
        } => (version, skipped_note),
    };

    if let Some(reason) = ignore_reason(config, &package.name, &package.version, &to) {
        return Ok(Some(Plan::Ignored { to, reason }));
    }

    if always_edit_manifest {
        let loaded = match manifests {
            Some(loaded) => loaded,
            None => manifests.insert(read_manifests(root)?),
        };
        let mut version = semver::Version::parse(&to).map_err(|_| ExitCode::from(2))?;
        version.build = semver::BuildMetadata::EMPTY;
        if let Ok(Some(labels)) =
            probe_manifest_update_with_widen(root, package, &version, loaded, false)
        {
            return Ok(Some(Plan::Update {
                spec,
                to: version.to_string(),
                kind: Kind::Compatible,
                manifests: labels,
                breaking_blocked,
                is_git: false,
                cooldown_skipped,
            }));
        }
    }

    let lock_error = match cargo_update(root, &spec, &to, true) {
        Ok(()) => {
            return Ok(Some(Plan::Update {
                spec,
                to,
                kind: Kind::Compatible,
                manifests: Vec::new(),
                breaking_blocked,
                is_git: false,
                cooldown_skipped,
            }));
        }
        Err(error) => error,
    };

    if !allow_manifest_edit {
        return Ok(Some(Plan::Blocked {
            to,
            reason: format!(
                "versioning-strategy is `lockfile-only`; {}",
                reason(&lock_error)
            ),
        }));
    }

    // A requirement that holds the version back (`=0.4.19`, `~1.2.0`, `<1.5`):
    // raise or widen it in the manifests, as Dependabot does.
    let loaded = match manifests {
        Some(loaded) => loaded,
        None => manifests.insert(read_manifests(root)?),
    };
    let mut version = semver::Version::parse(&to).map_err(|_| ExitCode::from(2))?;
    version.build = semver::BuildMetadata::EMPTY;
    Ok(Some(
        match probe_manifest_update_with_widen(root, package, &version, loaded, widen) {
            Ok(Some(labels)) => Plan::Update {
                spec,
                to: version.to_string(),
                kind: Kind::Compatible,
                manifests: labels,
                breaking_blocked,
                is_git: false,
                cooldown_skipped,
            },
            Ok(None) | Err(_) => Plan::Blocked {
                to,
                reason: reason(&lock_error),
            },
        },
    ))
}

/// Parses `cargo update -p <spec> --dry-run` output for a git or private-registry
/// dependency. Returns `(new_label, is_git)` when Cargo found an update.
fn parse_non_crates_io_update(
    stderr: &str,
    name: &str,
    from: &str,
    source: &str,
) -> Option<(String, bool)> {
    let prefix = format!("Updating {name} v{from}");
    for raw_line in stderr.lines() {
        let line = raw_line.trim();
        let Some(rest) = line.strip_prefix(&prefix) else {
            continue;
        };
        let Some((_, after)) = rest.split_once("->") else {
            continue;
        };
        let after = after.trim();
        if source.starts_with("git+") {
            let short = |s: &str| s.chars().take(7).collect::<String>();
            if let Some(hash) = after.rsplit('#').next() {
                let sha = hash.trim_end_matches(')');
                if after.starts_with('v')
                    && let Some((ver, _)) = after.split_once(' ')
                {
                    let ver = ver.trim_start_matches('v');
                    return Some((format!("{ver} (#{})", short(sha)), true));
                }
                return Some((format!("{from} (#{})", short(sha)), true));
            }
            return Some((after.trim_start_matches('v').to_owned(), true));
        }
        let target = after
            .split_whitespace()
            .next()
            .unwrap_or(after)
            .trim_start_matches('v');
        if !target.is_empty() && target != from {
            return Some((target.to_owned(), false));
        }
    }
    None
}

fn probe_non_crates_io_package(
    root: &Path,
    package: &Package,
    config: &UpdatesConfig,
) -> Option<Plan> {
    let source = package.source.as_deref()?;
    if !source.starts_with("git+") && !source.starts_with("registry+") {
        return None;
    }
    let spec = format!("{}@{}", package.name, package.version);
    let stderr = run_cargo_update(root, &spec, None, true).ok()?;
    let clean = strip_ansi(&stderr);
    let (to, is_git) = parse_non_crates_io_update(&clean, &package.name, &package.version, source)?;
    if let Some(reason) = ignore_reason(config, &package.name, &package.version, &to) {
        return Some(Plan::Ignored { to, reason });
    }
    Some(Plan::Update {
        spec,
        to,
        kind: Kind::Compatible,
        manifests: Vec::new(),
        breaking_blocked: None,
        is_git,
        cooldown_skipped: None,
    })
}

fn apply(
    root: &Path,
    rows: &[Row],
    widen: bool,
    manifests: &mut Option<Vec<Manifest>>,
) -> Result<(), ExitCode> {
    let mut action_edits: Vec<(&ActionUse, &str, Option<&str>)> = Vec::new();
    let mut docker_edits: Vec<(&DockerFrom, &str)> = Vec::new();
    for row in rows {
        let Plan::Update {
            spec,
            to,
            manifests: labels,
            is_git,
            ..
        } = &row.plan
        else {
            continue;
        };
        match &row.target {
            EcosystemTarget::Cargo => {
                if *is_git {
                    run_cargo_update(root, spec, None, false).map_err(|error| {
                        eprintln!("cargo update -p {spec} failed: {}", reason(&error));
                        ExitCode::from(2)
                    })?;
                } else if labels.is_empty() {
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
                    apply_manifest_update_with_widen(
                        root, &row.name, &row.from, to, labels, loaded, widen,
                    )?;
                }
            }
            EcosystemTarget::Action {
                action,
                target_ref,
                display_tag,
            } => {
                action_edits.push((action, target_ref.as_str(), display_tag.as_deref()));
            }
            EcosystemTarget::Docker { from, new_tag } => {
                docker_edits.push((from, new_tag.as_str()));
            }
        }
    }
    if !action_edits.is_empty() {
        apply_action_updates(root, &action_edits).map_err(|error| {
            eprintln!("CargoScope could not update workflow files: {error}");
            ExitCode::from(2)
        })?;
    }
    if !docker_edits.is_empty() {
        apply_docker_updates(root, &docker_edits).map_err(|error| {
            eprintln!("CargoScope could not update Dockerfile base images: {error}");
            ExitCode::from(2)
        })?;
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
            Plan::Blocked { .. } | Plan::Ignored { .. } | Plan::Cooldown { .. } => {
                unreachable!("filtered above")
            }
        },
        many => format!("Bump {} dependencies", many.len()),
    }
}

fn update_type_of(row: &Row) -> Option<UpdateType> {
    match &row.plan {
        Plan::Update { to, is_git, .. } => {
            if let (Some((v_from, _)), Some((v_to, _))) = (
                cargoscope_cargo::ecosystem_updates::parse_tag_version(&row.from),
                cargoscope_cargo::ecosystem_updates::parse_tag_version(
                    to.split_whitespace().next().unwrap_or(to),
                ),
            ) && row.ecosystem != UpdateEcosystem::Cargo
            {
                return UpdateType::between(&v_from.to_string(), &v_to.to_string());
            }
            UpdateType::between(&row.from, to).or((*is_git).then_some(UpdateType::Patch))
        }
        Plan::Blocked { .. } | Plan::Ignored { .. } | Plan::Cooldown { .. } => None,
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
            Plan::Update {
                cooldown_skipped: Some(note),
                ..
            } => Some(format!("- `{}`: {note}", row.name)),
            Plan::Update { .. } | Plan::Cooldown { .. } | Plan::Ignored { .. } => None,
        })
        .collect();
    if !refused.is_empty() {
        let _ = writeln!(out, "**Not updated: {}**\n", refused.len());
        for line in refused {
            let _ = writeln!(out, "{line}");
        }
        out.push('\n');
    }

    let held_cooldown: Vec<(&Row, &str, u64, u64)> = rows
        .iter()
        .filter_map(|row| match &row.plan {
            Plan::Cooldown {
                to,
                age_days,
                required_days,
            } => Some((row, to.as_str(), *age_days, *required_days)),
            _ => None,
        })
        .collect();
    if !held_cooldown.is_empty() {
        let _ = writeln!(out, "**Held by cooldown: {}**\n", held_cooldown.len());
        for (row, to, age_days, required_days) in &held_cooldown {
            let _ = writeln!(
                out,
                "- `{}` {} → {to}: published {age_days}d ago (cooldown {required_days}d)",
                row.name, row.from
            );
        }
        out.push_str("\n<details><summary>Override cooldown for a dependency</summary>\n\nAdd an entry under `[updates.cooldown.overrides]` in `cargoscope.toml` (or pass `--cooldown-for NAME=1`):\n\n```toml\n[updates.cooldown.overrides]\n");
        for (row, _, _, _) in &held_cooldown {
            let _ = writeln!(out, "{} = 1", row.name);
        }
        out.push_str("```\n\n</details>\n\n");
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
        out.push_str("]\n```\n\nComment on this pull request with `/cargoscope rebase`, `/cargoscope recreate`, `/cargoscope ignore this version`, `/cargoscope ignore this major version`, or `/cargoscope ignore this dependency`.\n\n</details>\n\n");
    }
    out.push_str("Made with `cargoscope fix --updates --apply`, which only resolves versions: the checks of this pull request build and test them.\n");
    out
}

/// Links to read before merging: the source diff between the two versions
/// on diff.rs, and the release notes when the repository is on GitHub.
fn links(row: &Row, to: &str) -> String {
    match row.ecosystem {
        UpdateEcosystem::GitHubActions => {
            let clean_to = to.split_whitespace().next().unwrap_or(to);
            return format!(
                "[compare](https://github.com/{name}/compare/{from}...{clean_to}), [releases](https://github.com/{name}/releases)",
                name = row.name,
                from = row.from
            );
        }
        UpdateEcosystem::Docker => {
            let (reg, repo) = cargoscope_advisory::ecosystems::normalize_docker_image(&row.name);
            return if reg == "docker.io" {
                let path = repo.strip_prefix("library/").map_or_else(
                    || format!("https://hub.docker.com/r/{repo}/tags"),
                    |official| format!("https://hub.docker.com/_/{official}/tags"),
                );
                format!("[tags]({path})")
            } else {
                format!("[registry](https://{reg}/{repo})")
            };
        }
        UpdateEcosystem::Cargo => {}
    }
    if matches!(row.plan, Plan::Update { is_git: true, .. }) {
        return row
            .repository
            .as_deref()
            .map(|url| format!("[repo]({})", url.trim_end_matches('/')))
            .unwrap_or_else(|| "—".to_owned());
    }
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
        let Plan::Update { .. } = &row.plan else {
            continue;
        };
        let Some(update_type) = update_type_of(row) else {
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
        Plan::Cooldown { .. } | Plan::Blocked { .. } | Plan::Ignored { .. } => {
            format!("Bump {}", row.name)
        }
    }
}

fn render_json(rows: &[Row], config: &UpdatesConfig) -> String {
    let mut updates = Vec::new();
    let mut cooldown = Vec::new();
    let mut blocked = Vec::new();
    let mut ignored = Vec::new();
    for row in rows {
        match &row.plan {
            Plan::Update {
                to,
                kind,
                manifests,
                breaking_blocked,
                is_git,
                cooldown_skipped,
                ..
            } => updates.push(serde_json::json!({
                "package": row.name, "ecosystem": row.ecosystem.as_str(), "from": row.from, "to": to,
                "kind": kind.as_str(), "manifests": manifests,
                "is_git": is_git,
                "cooldown_skipped": cooldown_skipped,
                "breaking_blocked": breaking_blocked.as_ref().map(|(to, reason)| serde_json::json!({"to": to, "reason": reason})),
            })),
            Plan::Cooldown {
                to,
                age_days,
                required_days,
            } => cooldown.push(serde_json::json!({
                "package": row.name,
                "ecosystem": row.ecosystem.as_str(),
                "from": row.from,
                "to": to,
                "age_days": age_days,
                "required_days": required_days,
            })),
            Plan::Blocked { to, reason } => blocked.push(serde_json::json!({
                "package": row.name, "ecosystem": row.ecosystem.as_str(), "from": row.from, "to": to, "reason": reason,
            })),
            Plan::Ignored { to, reason } => ignored.push(serde_json::json!({
                "package": row.name, "ecosystem": row.ecosystem.as_str(), "from": row.from, "to": to, "reason": reason,
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
        "cooldown": cooldown,
        "blocked": blocked,
        "ignored": ignored,
        "config": {
            "versioning_strategy": config.versioning_strategy.as_str(),
            "cooldown_default_days": config.cooldown.default_days,
            "labels": config.labels,
            "reviewers": config.reviewers,
            "commit_prefix": config.commit_prefix,
        },
    }))
    .unwrap_or_default();
    text.push('\n');
    text
}

fn print_row(row: &Row, paint: cargoscope_report::Paint) {
    match &row.plan {
        Plan::Update {
            to,
            kind,
            manifests,
            breaking_blocked,
            cooldown_skipped,
            ..
        } => {
            let place = if manifests.is_empty() {
                String::new()
            } else {
                paint.dim(&format!(" (in {})", manifests.join(", ")))
            };
            let kind_label = format!("({})", kind.as_str());
            let styled_kind = if *kind == Kind::Compatible {
                paint.blue(&kind_label)
            } else {
                paint.yellow(&kind_label)
            };
            println!(
                "{} {} -> {} {styled_kind}{place}",
                paint.bold(&row.name),
                paint.dim(&row.from),
                paint.green(to)
            );
            if let Some((to, why)) = breaking_blocked {
                println!("  {}", paint.yellow(&format!("= {to} refused: {why}")));
            }
            if let Some(note) = cooldown_skipped {
                println!("  {}", paint.dim(&format!("= skipped {note}")));
            }
        }
        Plan::Cooldown {
            to,
            age_days,
            required_days,
        } => {
            println!(
                "{} {} -> {to}: {}",
                paint.bold(&row.name),
                paint.dim(&row.from),
                paint.yellow(&format!(
                    "held by {required_days}d cooldown (published {age_days}d ago; override with --cooldown-for {}=1 or [updates.cooldown.overrides])",
                    row.name
                ))
            );
        }
        Plan::Blocked { to, reason } => {
            println!(
                "{} {} -> {to}: {}: {reason}",
                paint.bold(&row.name),
                paint.dim(&row.from),
                paint.yellow("cannot update")
            );
        }
        Plan::Ignored { to, reason } => {
            println!(
                "{} {} -> {to}: {}",
                paint.bold(&row.name),
                paint.dim(&row.from),
                paint.dim(reason)
            );
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
        let Plan::Update { to, is_git, .. } = &row.plan else {
            continue;
        };
        if *is_git || row.ecosystem != UpdateEcosystem::Cargo {
            continue;
        }
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
    paint: cargoscope_report::Paint,
) -> Result<ExitCode, ExitCode> {
    let options = UpdateOptions {
        breaking,
        apply: apply_changes,
        format,
        only,
        cooldown_days: None,
        cooldown_overrides: &[],
        versioning_strategy: None,
        ecosystems: None,
        now: None,
    };
    run_with_options(root, &options, paint)
}

fn selected_ecosystems(
    root: &Path,
    requested: Option<&[String]>,
    dependabot: &cargoscope_cargo::dependabot::DependabotConfigs,
) -> (bool, bool, bool) {
    let _ = root;
    let Some(list) = requested else {
        return (
            true,
            dependabot.github_actions.is_some(),
            dependabot.docker.is_some(),
        );
    };
    if list.iter().any(|s| s == "all") {
        return (true, true, true);
    }
    if list.iter().any(|s| s == "auto") {
        return (
            true,
            dependabot.github_actions.is_some(),
            dependabot.docker.is_some(),
        );
    }
    (
        list.iter().any(|s| s == "cargo"),
        list.iter().any(|s| s == "github-actions"),
        list.iter().any(|s| s == "docker"),
    )
}

fn apply_cooldown_cli_overrides(
    cfg: &mut UpdatesConfig,
    cooldown_days: Option<u64>,
    cooldown_overrides: &[(String, u64)],
) {
    if let Some(days) = cooldown_days {
        cfg.cooldown.default_days = days;
    }
    if !cooldown_overrides.is_empty() {
        let mut combined = cooldown_overrides.to_vec();
        combined.extend(std::mem::take(&mut cfg.cooldown.overrides));
        cfg.cooldown.overrides = combined;
    }
}

fn to_candidates(
    items: Vec<cargoscope_advisory::ecosystems::RemoteRelease>,
) -> Vec<CandidateRelease> {
    items
        .into_iter()
        .map(|r| CandidateRelease {
            tag: r.tag,
            published_unix: r.published_unix,
            sha: r.sha,
            digest: r.digest,
        })
        .collect()
}

/// Runs `cargoscope fix --updates` with cooldown, versioning-strategy, and
/// multi-ecosystem (`cargo`, `github-actions`, `docker`) options.
///
/// # Errors
///
/// Returns an execution error exit code (`2`) when the project cannot be
/// scanned, manifests cannot be edited, or `cargo update` fails.
pub fn run_with_options(
    root: &Path,
    options: &UpdateOptions<'_>,
    paint: cargoscope_report::Paint,
) -> Result<ExitCode, ExitCode> {
    let dependabot_all = cargoscope_cargo::dependabot::load_all(root);
    let (run_cargo, run_actions, run_docker) =
        selected_ecosystems(root, options.ecosystems, &dependabot_all);

    let inventory = if run_cargo {
        Some(
            cargoscope_cargo::scan_cargo_project(root)
                .map_err(|error| execution_error(root, &error))?,
        )
    } else {
        None
    };

    let mut config = if run_cargo {
        cargoscope_cargo::updates::load(root).map_err(|error| execution_error(root, &error))?
    } else {
        UpdatesConfig::default()
    };
    apply_cooldown_cli_overrides(
        &mut config,
        options.cooldown_days,
        options.cooldown_overrides,
    );
    if let Some(strategy) = options.versioning_strategy {
        config.versioning_strategy = strategy;
    }
    let strategy = config.versioning_strategy;
    let now_unix = options.now.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
    let cache_dir = cargoscope_advisory::cache_dir().ok();
    let registry_cache = cache_dir.as_deref().map(RegistryCache::open);
    let offline = std::env::var_os("CARGOSCOPE_OFFLINE").is_some_and(|v| v == "1" || v == "true");

    let mut rows = Vec::new();
    let mut manifests: Option<Vec<Manifest>> = None;

    if let Some(ref inventory) = inventory {
        let mut warnings = Vec::new();
        let (info, date) = crate::scan::registry_data(root, inventory, &mut warnings);
        for warning in &warnings {
            eprintln!("warning: {warning}");
        }
        let has_crates_io_direct = inventory.packages.iter().any(|package| {
            package.direct
                && !package.root
                && cargoscope_advisory::crates_io::is_crates_io(package.source.as_deref())
        });
        if has_crates_io_direct && date.is_none() {
            eprintln!(
                "CargoScope needs crates.io data to find newer versions: run `cargoscope update` first."
            );
            return Err(ExitCode::from(2));
        }
        let kinds = cargoscope_cargo::direct_dependency_kinds(root).unwrap_or_default();
        let dev_only = |name: &str| {
            kinds
                .get(name)
                .is_some_and(|kinds| kinds.iter().all(|kind| *kind == DependencyKind::Dev))
        };
        let mut seen = BTreeSet::new();
        for (package, info) in inventory.packages.iter().zip(&info) {
            if !package.direct
                || package.root
                || options
                    .only
                    .is_some_and(|names| !names.contains(&package.name))
                || (!config.include_dev && dev_only(&package.name))
                || !seen.insert((package.name.clone(), package.version.clone()))
            {
                continue;
            }
            let is_crates_io =
                cargoscope_advisory::crates_io::is_crates_io(package.source.as_deref());
            let plan = if is_crates_io {
                if !info.outdated {
                    continue;
                }
                let releases = registry_cache
                    .as_ref()
                    .and_then(|cache| cache.version_timestamps(&package.name));
                let ctx = PlanContext {
                    root,
                    strategy,
                    breaking: options.breaking,
                    config: &config,
                    releases: releases.as_deref(),
                    now_unix,
                };
                let Some(plan) = plan_package(&ctx, package, info, &mut manifests)? else {
                    continue;
                };
                plan
            } else if let Some(plan) = probe_non_crates_io_package(root, package, &config) {
                plan
            } else {
                continue;
            };

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
                ecosystem: UpdateEcosystem::Cargo,
                target: EcosystemTarget::Cargo,
            };
            if options.format == Format::Text {
                print_row(&row, paint);
            }
            rows.push(row);
        }
    }

    if run_actions && let Some(dir) = cache_dir.as_deref() {
        let mut gha_cfg = dependabot_all.github_actions.unwrap_or_default();
        apply_cooldown_cli_overrides(
            &mut gha_cfg,
            options.cooldown_days,
            options.cooldown_overrides,
        );
        let mut remote_cache: std::collections::BTreeMap<String, Vec<CandidateRelease>> =
            std::collections::BTreeMap::new();
        for action in find_action_uses(root) {
            if options
                .only
                .is_some_and(|names| !names.contains(&action.owner_repo))
            {
                continue;
            }
            let candidates = remote_cache
                .entry(action.owner_repo.clone())
                .or_insert_with(|| {
                    let raw = if offline {
                        cargoscope_advisory::ecosystems::cached_github_releases(
                            dir,
                            &action.owner_repo,
                        )
                    } else {
                        cargoscope_advisory::ecosystems::fetch_github_releases(
                            dir,
                            &action.owner_repo,
                            false,
                        )
                    };
                    raw.map(to_candidates).unwrap_or_default()
                });
            let Some(outcome) =
                plan_action_update(&action, candidates, &gha_cfg, options.breaking, now_unix)
            else {
                continue;
            };
            let from_str = action
                .comment_version
                .clone()
                .unwrap_or_else(|| action.raw_ref.clone());
            let (plan, target) = match outcome {
                EcosystemPlan::Update {
                    target_ref,
                    display_to,
                    update_type,
                    cooldown_skipped,
                    ..
                } => {
                    let kind = if update_type == UpdateType::Major {
                        Kind::Breaking
                    } else {
                        Kind::Compatible
                    };
                    let display_tag = display_to.split_whitespace().next().map(str::to_owned);
                    let file_label = vec![action.file.clone()];
                    (
                        Plan::Update {
                            spec: action.owner_repo.clone(),
                            to: display_to,
                            kind,
                            manifests: file_label,
                            breaking_blocked: None,
                            is_git: false,
                            cooldown_skipped,
                        },
                        EcosystemTarget::Action {
                            action: action.clone(),
                            target_ref,
                            display_tag,
                        },
                    )
                }
                EcosystemPlan::Cooldown {
                    to,
                    age_days,
                    required_days,
                } => (
                    Plan::Cooldown {
                        to,
                        age_days,
                        required_days,
                    },
                    EcosystemTarget::Cargo,
                ),
                EcosystemPlan::Ignored { to, reason } => {
                    (Plan::Ignored { to, reason }, EcosystemTarget::Cargo)
                }
            };
            let row = Row {
                name: action.owner_repo.clone(),
                from: from_str,
                plan,
                dev: false,
                repository: Some(format!("https://github.com/{}", action.owner_repo)),
                details: Details::default(),
                ecosystem: UpdateEcosystem::GitHubActions,
                target,
            };
            if options.format == Format::Text {
                print_row(&row, paint);
            }
            rows.push(row);
        }
    }

    if run_docker && let Some(dir) = cache_dir.as_deref() {
        let mut docker_cfg = dependabot_all.docker.unwrap_or_default();
        apply_cooldown_cli_overrides(
            &mut docker_cfg,
            options.cooldown_days,
            options.cooldown_overrides,
        );
        let mut remote_cache: std::collections::BTreeMap<String, Vec<CandidateRelease>> =
            std::collections::BTreeMap::new();
        for from in find_docker_froms(root) {
            if options
                .only
                .is_some_and(|names| !names.contains(&from.image))
            {
                continue;
            }
            let Some(ref raw_tag) = from.raw_tag else {
                continue;
            };
            let candidates = remote_cache.entry(from.image.clone()).or_insert_with(|| {
                let raw = if offline {
                    cargoscope_advisory::ecosystems::cached_docker_tags(dir, &from.image)
                } else {
                    cargoscope_advisory::ecosystems::fetch_docker_tags(dir, &from.image, false)
                };
                raw.map(to_candidates).unwrap_or_default()
            });
            let Some(outcome) =
                plan_docker_update(&from, candidates, &docker_cfg, options.breaking, now_unix)
            else {
                continue;
            };
            let (plan, target) = match outcome {
                EcosystemPlan::Update {
                    target_ref,
                    display_to,
                    update_type,
                    cooldown_skipped,
                    ..
                } => {
                    let kind = if update_type == UpdateType::Major {
                        Kind::Breaking
                    } else {
                        Kind::Compatible
                    };
                    (
                        Plan::Update {
                            spec: from.image.clone(),
                            to: display_to,
                            kind,
                            manifests: vec![from.file.clone()],
                            breaking_blocked: None,
                            is_git: false,
                            cooldown_skipped,
                        },
                        EcosystemTarget::Docker {
                            from: from.clone(),
                            new_tag: target_ref,
                        },
                    )
                }
                EcosystemPlan::Cooldown {
                    to,
                    age_days,
                    required_days,
                } => (
                    Plan::Cooldown {
                        to,
                        age_days,
                        required_days,
                    },
                    EcosystemTarget::Cargo,
                ),
                EcosystemPlan::Ignored { to, reason } => {
                    (Plan::Ignored { to, reason }, EcosystemTarget::Cargo)
                }
            };
            let row = Row {
                name: from.image.clone(),
                from: raw_tag.clone(),
                plan,
                dev: false,
                repository: None,
                details: Details::default(),
                ecosystem: UpdateEcosystem::Docker,
                target,
            };
            if options.format == Format::Text {
                print_row(&row, paint);
            }
            rows.push(row);
        }
    }
    if options.apply {
        apply(
            root,
            &rows,
            strategy == VersioningStrategy::Widen,
            &mut manifests,
        )?;
    }
    match options.format {
        Format::Markdown => {
            if let Some(ref inv) = inventory {
                let body = body_facts(root, inv, &mut rows, &config, options.apply)?;
                print!("{}", render_markdown(&rows, &body));
            } else {
                print!("{}", render_markdown(&rows, &Body::default()));
            }
        }
        Format::Json => print!("{}", render_json(&rows, &config)),
        Format::Text => {
            let updates = rows
                .iter()
                .filter(|row| matches!(row.plan, Plan::Update { .. }))
                .count();
            let held = rows
                .iter()
                .filter(|row| matches!(row.plan, Plan::Cooldown { .. }))
                .count();
            if rows.is_empty() {
                println!("{}", paint.green("Every direct dependency is up to date."));
            } else if options.apply {
                println!(
                    "\n{} Build and test before committing.",
                    paint.green(&format!("Updated {updates} dependency(ies)."))
                );
            } else {
                println!(
                    "\n{} nothing was changed. Run `cargoscope fix --updates{} --apply` to make {updates} update(s).",
                    paint.bold("Dry run:"),
                    if options.breaking { " --breaking" } else { "" }
                );
            }
            if held > 0 {
                println!(
                    "{}",
                    paint.dim(&format!(
                        "Note: {held} dependency(ies) held by cooldown (default {}d). Override per crate via `--cooldown-for CRATE=1` or `[updates.cooldown.overrides]` in `cargoscope.toml`.",
                        config.cooldown.default_days
                    ))
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
                is_git: false,
                cooldown_skipped: None,
            },
            dev: false,
            repository: Some(format!("https://github.com/example/{name}")),
            details: Details {
                published: Some("2026-11-01".to_owned()),
                ..Details::default()
            },
            ecosystem: super::UpdateEcosystem::Cargo,
            target: super::EcosystemTarget::Cargo,
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

    #[test]
    fn parses_pr_comment_commands_and_body_updates() {
        use super::{PrCommand, parse_pr_body_updates, parse_pr_comment};

        assert_eq!(
            parse_pr_comment("/cargoscope rebase"),
            Some(PrCommand::Rebase)
        );
        assert_eq!(
            parse_pr_comment("thanks!\n@cargoscope recreate\n"),
            Some(PrCommand::Recreate)
        );
        assert_eq!(
            parse_pr_comment("/cargoscope ignore   this version"),
            Some(PrCommand::IgnoreVersion)
        );
        assert_eq!(
            parse_pr_comment("@cargoscope ignore this major version"),
            Some(PrCommand::IgnoreMajor)
        );
        assert_eq!(
            parse_pr_comment("/cargoscope ignore this dependency"),
            Some(PrCommand::IgnoreDependency)
        );
        assert_eq!(parse_pr_comment("/cargoscope-other rebase"), None);
        assert_eq!(parse_pr_comment("looks good to me"), None);

        let body = format!(
            "{}\n| Package | Version | Update | Published | Checks | Links |\n|---|---|---|---|---|---|\n| [`serde`](https://crates.io/crates/serde/1.0.210) | 1.0.200 → **1.0.210** | patch | 2026-11-01 | ✅ | [diff](https://diff.rs/serde/1.0.200/1.0.210) |\n| [`ureq`](https://crates.io/crates/ureq/3.1.0) | 2.12.1 → **3.1.0** | major | 2026-11-01 | ✅ | [diff](https://diff.rs/ureq/2.12.1/3.1.0) |\n",
            super::PR_MARKER
        );
        assert_eq!(
            parse_pr_body_updates(&body),
            vec![
                (
                    "serde".to_owned(),
                    "1.0.200".to_owned(),
                    "1.0.210".to_owned()
                ),
                ("ureq".to_owned(), "2.12.1".to_owned(), "3.1.0".to_owned()),
            ]
        );
    }

    #[test]
    fn cooldown_picks_older_eligible_release_and_supports_overrides() {
        use super::{CooldownPick, pick_with_cooldown};
        use cargoscope_advisory::crates_io::ReleaseTime;

        let now = 2_000_000_000u64;
        let releases = vec![
            ReleaseTime {
                version: "1.0.0".to_owned(),
                yanked: false,
                published_unix: Some(now - 30 * 86_400),
            },
            ReleaseTime {
                version: "1.0.5".to_owned(),
                yanked: false,
                published_unix: Some(now - 10 * 86_400),
            },
            ReleaseTime {
                version: "1.0.9".to_owned(),
                yanked: false,
                published_unix: Some(now - 2 * 86_400),
            },
        ];

        let default_cfg = cargoscope_cargo::updates::UpdatesConfig::default();
        assert_eq!(default_cfg.cooldown.default_days, 7);
        match pick_with_cooldown(
            "serde",
            "1.0.0",
            "1.0.9",
            true,
            Some(&releases),
            &default_cfg,
            now,
        ) {
            CooldownPick::Use {
                version,
                skipped_note,
            } => {
                assert_eq!(version, "1.0.5");
                assert!(skipped_note.is_some());
            }
            CooldownPick::Held { .. } => panic!("expected older eligible release 1.0.5"),
        }

        // Only 1.0.9 is newer than 1.0.5 -> held by 7d cooldown.
        match pick_with_cooldown(
            "serde",
            "1.0.5",
            "1.0.9",
            true,
            Some(&releases),
            &default_cfg,
            now,
        ) {
            CooldownPick::Held {
                to,
                age_days,
                required_days,
            } => {
                assert_eq!(to, "1.0.9");
                assert_eq!(age_days, 2);
                assert_eq!(required_days, 7);
            }
            CooldownPick::Use { .. } => panic!("expected cooldown hold"),
        }

        // Per-crate 1-day override unlocks 1.0.9 immediately.
        let mut override_cfg = default_cfg;
        override_cfg
            .cooldown
            .overrides
            .push(("serde".to_owned(), 1));
        match pick_with_cooldown(
            "serde",
            "1.0.5",
            "1.0.9",
            true,
            Some(&releases),
            &override_cfg,
            now,
        ) {
            CooldownPick::Use { version, .. } => assert_eq!(version, "1.0.9"),
            CooldownPick::Held { .. } => panic!("expected override to allow 1.0.9"),
        }
    }

    #[test]
    fn parses_git_and_alternative_registry_cargo_update_lines() {
        use super::parse_non_crates_io_update;

        let git_stderr =
            "    Updating foo v0.1.0 (https://github.com/org/foo#11111111) -> #22222222\n";
        assert_eq!(
            parse_non_crates_io_update(
                git_stderr,
                "foo",
                "0.1.0",
                "git+https://github.com/org/foo#11111111"
            ),
            Some(("0.1.0 (#2222222)".to_owned(), true))
        );

        let reg_stderr = "    Updating private-crate v1.2.0 (registry `corp`) -> v1.3.0\n";
        assert_eq!(
            parse_non_crates_io_update(
                reg_stderr,
                "private-crate",
                "1.2.0",
                "registry+https://corp.example/index"
            ),
            Some(("1.3.0".to_owned(), false))
        );
    }
}
