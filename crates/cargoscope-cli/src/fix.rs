//! `cargoscope fix`: removes likely-unused dependencies from the manifests,
//! in steps: plan the removals, edit the manifests in memory, remove the
//! `[workspace.dependencies]` entries left unused, then write (with `--apply`)
//! or only report (dry run).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_cargo::fix::{
    Outcome, remove_dependencies, remove_workspace_dependencies, workspace_references,
};
use cargoscope_cargo::updates::VersioningStrategy;
use cargoscope_core::{UnusedConfidence, UnusedFinding};
use cargoscope_report::Paint;

use crate::scan::ColorChoice;
use crate::{execution_error, find_unused_dependencies};

#[derive(Debug, Default, PartialEq, Eq)]
struct FixOptions {
    path: Option<PathBuf>,
    /// Apply removals (`--apply`).
    apply: bool,
    /// Run `cargo check --workspace --all-targets` after applying changes and
    /// restore manifests if the build fails (`--verify`).
    verify: bool,
    include_uncertain: bool,
    precise: bool,
    only: Option<Vec<String>>,
    /// Update vulnerable packages instead of removing unused dependencies.
    advisories: bool,
    /// Update direct dependencies to their newest versions (`--updates`).
    updates: bool,
    /// With `--updates`, also move to newer major versions (`--breaking`).
    breaking: bool,
    /// `--format markdown|json`, with `--advisories` or `--updates`.
    format: crate::fix_advisories::Format,
    /// ANSI color preference for text output.
    color: ColorChoice,
    /// PR comment command to apply on an update pull request (`--comment-command`).
    comment_command: Option<String>,
    /// File containing the pull request Markdown body (`--pr-body`).
    pr_body: Option<PathBuf>,
    /// Override minimum release age in days before proposing `--updates` (default: 7).
    cooldown: Option<u64>,
    /// Per-dependency cooldown overrides (`CRATE=DAYS`, e.g. `serde=1`).
    cooldown_for: Vec<(String, u64)>,
    /// Manifest requirement update strategy (`--versioning-strategy`).
    versioning_strategy: Option<VersioningStrategy>,
}

fn parse_fix_options(arguments: impl Iterator<Item = String>) -> Result<FixOptions, String> {
    let mut options = FixOptions::default();
    let mut dry_run = false;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        if argument == "--only" || argument.starts_with("--only=") {
            let list = if argument == "--only" {
                arguments.next()
            } else {
                argument.strip_prefix("--only=").map(str::to_owned)
            };
            let list = list
                .filter(|list| !list.trim().is_empty())
                .ok_or("Missing value for --only.")?;
            options.only = Some(list.split(',').map(|name| name.trim().to_owned()).collect());
            continue;
        }
        if argument == "--color" || argument.starts_with("--color=") {
            let value = match argument.strip_prefix("--color=") {
                Some(value) => Some(value.to_owned()),
                None => arguments.next(),
            }
            .ok_or("Missing value for --color.")?;
            options.color = ColorChoice::parse(&value)?;
            continue;
        }
        if argument == "--comment-command" || argument.starts_with("--comment-command=") {
            let value = match argument.strip_prefix("--comment-command=") {
                Some(value) => Some(value.to_owned()),
                None => arguments.next(),
            }
            .filter(|val| !val.trim().is_empty())
            .ok_or("Missing value for --comment-command.")?;
            options.comment_command = Some(value);
            continue;
        }
        if argument == "--pr-body" || argument.starts_with("--pr-body=") {
            let value = match argument.strip_prefix("--pr-body=") {
                Some(value) => Some(value.to_owned()),
                None => arguments.next(),
            }
            .filter(|val| !val.trim().is_empty())
            .ok_or("Missing value for --pr-body.")?;
            options.pr_body = Some(PathBuf::from(value));
            continue;
        }
        if argument == "--cooldown" || argument.starts_with("--cooldown=") {
            let value = match argument.strip_prefix("--cooldown=") {
                Some(value) => Some(value.to_owned()),
                None => arguments.next(),
            }
            .ok_or("Missing value for --cooldown.")?;
            let stripped = value.trim().strip_suffix('d').unwrap_or(value.trim());
            let days = stripped.parse::<u64>().map_err(|_| {
                format!("Invalid --cooldown value `{value}`: expected days such as 7 or 0.")
            })?;
            options.cooldown = Some(days);
            continue;
        }
        if argument == "--cooldown-for" || argument.starts_with("--cooldown-for=") {
            let value = match argument.strip_prefix("--cooldown-for=") {
                Some(value) => Some(value.to_owned()),
                None => arguments.next(),
            }
            .filter(|val| !val.trim().is_empty())
            .ok_or("Missing value for --cooldown-for (expected CRATE=DAYS).")?;
            for item in value.split(',') {
                let (crate_name, days_raw) = item.trim().split_once('=').ok_or_else(|| {
                    format!("Invalid --cooldown-for `{item}`: expected CRATE=DAYS (e.g. serde=1).")
                })?;
                let crate_name = crate_name.trim();
                if crate_name.is_empty() {
                    return Err("Missing crate name in --cooldown-for.".to_owned());
                }
                let stripped = days_raw.trim().strip_suffix('d').unwrap_or(days_raw.trim());
                let days = stripped.parse::<u64>().map_err(|_| {
                    format!("Invalid days `{days_raw}` for `{crate_name}` in --cooldown-for.")
                })?;
                options.cooldown_for.push((crate_name.to_owned(), days));
            }
            continue;
        }
        if argument == "--versioning-strategy" || argument.starts_with("--versioning-strategy=") {
            let value = match argument.strip_prefix("--versioning-strategy=") {
                Some(value) => Some(value.to_owned()),
                None => arguments.next(),
            }
            .ok_or("Missing value for --versioning-strategy.")?;
            let strategy = VersioningStrategy::parse(&value).ok_or_else(|| {
                format!(
                    "Unsupported versioning strategy `{value}`. Use auto, lockfile-only, increase-if-necessary, increase, or widen."
                )
            })?;
            options.versioning_strategy = Some(strategy);
            continue;
        }
        match argument.as_str() {
            "--apply" => options.apply = true,
            "--dry-run" => dry_run = true,
            "--verify" => options.verify = true,
            "--include-uncertain" | "--show-uncertain" => options.include_uncertain = true,
            "--precise" => options.precise = true,
            "--advisories" => options.advisories = true,
            "--updates" => options.updates = true,
            "--breaking" => options.breaking = true,
            "--format" | "--format=text" | "--format=markdown" | "--format=json" => {
                let value = match argument.strip_prefix("--format=") {
                    Some(value) => Some(value.to_owned()),
                    None => arguments.next(),
                };
                options.format = match value.as_deref() {
                    Some("text") => crate::fix_advisories::Format::Text,
                    Some("markdown") => crate::fix_advisories::Format::Markdown,
                    Some("json") => crate::fix_advisories::Format::Json,
                    other => {
                        return Err(format!(
                            "Unsupported format for fix: {}. Use text, markdown or json.",
                            other.unwrap_or("(none)")
                        ));
                    }
                };
            }
            other if other.starts_with('-') => {
                return Err(format!("Unknown option for fix: {other}"));
            }
            _ if options.path.is_some() => return Err("fix takes a single PATH".to_owned()),
            _ => options.path = Some(PathBuf::from(argument)),
        }
    }
    if options.apply && dry_run {
        return Err("--apply and --dry-run cannot be combined".to_owned());
    }
    if options.format != crate::fix_advisories::Format::Text
        && !options.advisories
        && !options.updates
    {
        return Err("--format markdown and json need --advisories or --updates".to_owned());
    }
    if (options.advisories || options.updates) && options.precise {
        return Err("--advisories and --updates cannot be combined with --precise".to_owned());
    }
    if (options.advisories || options.updates) && options.verify {
        return Err("--advisories and --updates cannot be combined with --verify".to_owned());
    }
    if options.verify && !options.apply {
        return Err("--verify requires --apply".to_owned());
    }
    if (options.advisories || options.updates) && options.include_uncertain {
        return Err(
            "--advisories and --updates cannot be combined with --include-uncertain".to_owned(),
        );
    }
    if options.advisories && options.updates {
        return Err("--advisories and --updates cannot be combined".to_owned());
    }
    if options.breaking && !options.updates {
        return Err("--breaking needs --updates".to_owned());
    }
    if options.comment_command.is_some() != options.pr_body.is_some() {
        return Err("--comment-command and --pr-body must be used together".to_owned());
    }
    if options.comment_command.is_some() && !options.updates {
        return Err("--comment-command requires --updates".to_owned());
    }
    if (options.cooldown.is_some()
        || !options.cooldown_for.is_empty()
        || options.versioning_strategy.is_some())
        && !options.updates
    {
        return Err(
            "--cooldown, --cooldown-for, and --versioning-strategy require --updates".to_owned(),
        );
    }
    Ok(options)
}

/// Removals by manifest (relative to the project): `(section, key)` pairs.
type Plan<'a> = BTreeMap<&'a str, Vec<(&'a str, &'a str)>>;

/// Every manifest of the project: original and edited contents.
type Manifests = BTreeMap<PathBuf, (String, String)>;

/// `cargoscope fix [PATH] [--dry-run | --apply] [--only NAMES] [--precise]`.
pub fn fix_command(arguments: impl Iterator<Item = String>) -> ExitCode {
    let options = match parse_fix_options(arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\nRun cargoscope fix --help for usage.");
            return ExitCode::from(2);
        }
    };
    match run_fix(&options) {
        Ok(code) | Err(code) => code,
    }
}

fn run_fix(options: &FixOptions) -> Result<ExitCode, ExitCode> {
    let root = options.path.as_deref().unwrap_or(Path::new("."));
    let paint = Paint::new(options.color.enabled(false));
    if let (Some(comment), Some(pr_body)) = (&options.comment_command, &options.pr_body) {
        return crate::fix_updates::run_comment_command(
            root,
            comment,
            pr_body,
            options.apply,
            paint,
        );
    }
    if options.updates {
        return crate::fix_updates::run_with_options(
            root,
            &crate::fix_updates::UpdateOptions {
                breaking: options.breaking,
                apply: options.apply,
                format: options.format,
                only: options.only.as_deref(),
                cooldown_days: options.cooldown,
                cooldown_overrides: &options.cooldown_for,
                versioning_strategy: options.versioning_strategy,
                now: None,
            },
            paint,
        );
    }
    if options.advisories {
        return crate::fix_advisories::run(
            root,
            options.apply,
            options.format,
            options.only.as_deref(),
            paint,
        );
    }
    let inventory = cargoscope_cargo::scan_cargo_project(root)
        .map_err(|error| execution_error(root, &error))?;
    let (unused, _) = find_unused_dependencies(root, &inventory, options.precise)?;

    let plan = plan_removals(&unused, options.only.as_deref(), options.include_uncertain);
    if plan.is_empty() {
        println!("{}", paint.green("No likely-unused dependency to remove."));
        return Ok(ExitCode::SUCCESS);
    }
    let mut manifests = read_manifests(root, &plan)?;
    let inherited_before = inherited(&manifests, |(original, _)| original);
    let mut removed = edit_manifests(root, &plan, &mut manifests, paint)?;
    removed +=
        remove_orphaned_workspace_dependencies(root, &inherited_before, &mut manifests, paint)?;
    finish(
        root,
        &manifests,
        removed,
        options.apply,
        options.verify,
        paint,
    )?;
    Ok(ExitCode::SUCCESS)
}

/// Unused findings that are not ignored, grouped by manifest and restricted
/// to `only` when given (explicit `--only` targets both `likely-unused` and
/// `possibly-unused` findings; otherwise `possibly-unused` requires
/// `include_uncertain`); names of `only` that are not candidates are
/// reported.
fn plan_removals<'a>(
    unused: &'a [UnusedFinding],
    only: Option<&[String]>,
    include_uncertain: bool,
) -> Plan<'a> {
    let mut plan = Plan::new();
    for finding in unused {
        let eligible = finding.ignored.is_none()
            && match only {
                Some(names) => names.contains(&finding.dependency),
                None => finding.confidence == UnusedConfidence::Likely || include_uncertain,
            };
        if eligible {
            plan.entry(finding.manifest.as_str())
                .or_default()
                .push((finding.kind.section(), finding.dependency.as_str()));
        }
    }
    for name in only.unwrap_or_default() {
        if !plan.values().flatten().any(|(_, key)| key == name) {
            println!("`{name}` is not a likely-unused dependency: left alone.");
        }
    }
    plan
}

/// Reads the manifests of every package, of the workspace root and of the
/// plan, so that `[workspace.dependencies]` can be checked across members.
fn read_manifests(root: &Path, plan: &Plan<'_>) -> Result<Manifests, ExitCode> {
    let packages =
        cargoscope_cargo::project_packages(root).map_err(|error| execution_error(root, &error))?;
    let paths = packages
        .packages
        .iter()
        .map(|(dir, _, _)| dir.join("Cargo.toml"))
        .chain(std::iter::once(root.join("Cargo.toml")))
        .chain(plan.keys().map(|manifest| root.join(manifest)));
    let mut manifests = Manifests::new();
    for path in paths {
        if manifests.contains_key(&path) {
            continue;
        }
        let contents = std::fs::read_to_string(&path).map_err(|error| {
            eprintln!("CargoScope could not read {}: {error}", path.display());
            ExitCode::from(2)
        })?;
        manifests.insert(path, (contents.clone(), contents));
    }
    Ok(manifests)
}

/// Keys inherited with `workspace = true` in the chosen version of every
/// manifest.
fn inherited(
    manifests: &Manifests,
    version: impl Fn(&(String, String)) -> &String,
) -> BTreeSet<String> {
    manifests
        .values()
        .flat_map(|contents| workspace_references(version(contents)))
        .collect()
}

/// Applies the plan to the edited contents and prints it; returns the number
/// of dependencies removed.
fn edit_manifests(
    root: &Path,
    plan: &Plan<'_>,
    manifests: &mut Manifests,
    paint: Paint,
) -> Result<usize, ExitCode> {
    let mut removed = 0;
    for (manifest, removals) in plan {
        let path = root.join(manifest);
        let Some((_, current)) = manifests.get_mut(&path) else {
            continue;
        };
        let (new_contents, outcomes) = remove_dependencies(current, removals).map_err(|error| {
            eprintln!("CargoScope could not edit {}: {error}", path.display());
            ExitCode::from(2)
        })?;
        *current = new_contents;
        println!("{}", paint.bold(manifest));
        for ((section, key), outcome) in removals.iter().zip(&outcomes) {
            match outcome {
                Outcome::Removed(tables) => {
                    removed += 1;
                    println!(
                        "  {} `{}` from [{}]",
                        paint.green("- remove"),
                        paint.bold(key),
                        tables.join("], [")
                    );
                }
                Outcome::Skipped(reason) => println!(
                    "  {} `{}` [{section}]: {reason}",
                    paint.yellow("= keep"),
                    paint.bold(key)
                ),
            }
        }
    }
    Ok(removed)
}

/// Removes the `[workspace.dependencies]` entries that only the removed
/// lines inherited; returns how many were removed.
fn remove_orphaned_workspace_dependencies(
    root: &Path,
    inherited_before: &BTreeSet<String>,
    manifests: &mut Manifests,
    paint: Paint,
) -> Result<usize, ExitCode> {
    let inherited_after = inherited(manifests, |(_, current)| current);
    let orphans: Vec<&str> = inherited_before
        .difference(&inherited_after)
        .map(String::as_str)
        .collect();
    let Some((_, current)) = manifests
        .get_mut(&root.join("Cargo.toml"))
        .filter(|_| !orphans.is_empty())
    else {
        return Ok(0);
    };
    let (new_contents, gone) =
        remove_workspace_dependencies(current, &orphans).map_err(|error| {
            eprintln!("CargoScope could not edit the workspace manifest: {error}");
            ExitCode::from(2)
        })?;
    if gone.is_empty() {
        return Ok(0);
    }
    *current = new_contents;
    println!("{}", paint.bold("Cargo.toml"));
    for key in &gone {
        println!(
            "  {} `{}` from [workspace.dependencies]: no member uses it anymore",
            paint.green("- remove"),
            paint.bold(key)
        );
    }
    Ok(gone.len())
}

/// Writes the edited manifests with `--apply`, or only says what a run with
/// `--apply` would do. With `verify`, runs `cargo check --workspace
/// --all-targets` afterwards and restores the original manifests on failure.
fn finish(
    root: &Path,
    manifests: &Manifests,
    removed: usize,
    apply: bool,
    verify: bool,
    paint: Paint,
) -> Result<(), ExitCode> {
    let plural = if removed == 1 { "y" } else { "ies" };
    if !apply {
        println!(
            "\n{} nothing was written. Run `cargoscope fix --apply` to remove {removed} dependenc{plural}.",
            paint.bold("Dry run:")
        );
        return Ok(());
    }
    let mut written: Vec<(&Path, &str)> = Vec::new();
    for (path, (original, current)) in manifests {
        if original != current {
            std::fs::write(path, current).map_err(|error| {
                eprintln!("CargoScope could not write {}: {error}", path.display());
                ExitCode::from(2)
            })?;
            written.push((path.as_path(), original.as_str()));
        }
    }
    let edited = written.len();
    if verify && edited > 0 {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = std::process::Command::new(cargo)
            .current_dir(root)
            .args(["check", "--workspace", "--all-targets"])
            .output();
        match output {
            Ok(out) if out.status.success() => {
                println!(
                    "\n{} Verified with `cargo check --workspace --all-targets`.",
                    paint.green(&format!(
                        "Removed {removed} dependenc{plural} from {edited} manifest(s)."
                    ))
                );
                return Ok(());
            }
            Ok(out) => {
                for (path, original) in &written {
                    let _ = std::fs::write(path, original);
                }
                let stderr = String::from_utf8_lossy(&out.stderr);
                let tail: Vec<&str> = stderr.lines().rev().take(12).collect();
                for line in tail.into_iter().rev() {
                    eprintln!("{line}");
                }
                eprintln!(
                    "CargoScope restored the modified manifest(s) because `cargo check --workspace --all-targets` failed. Re-run with `--precise` to ask rustc first."
                );
                return Err(ExitCode::from(2));
            }
            Err(error) => {
                for (path, original) in &written {
                    let _ = std::fs::write(path, original);
                }
                eprintln!(
                    "CargoScope could not run `cargo check` ({error}); restored the modified manifest(s)."
                );
                return Err(ExitCode::from(2));
            }
        }
    }
    println!(
        "\n{} Run `cargo check --all-targets` to update Cargo.lock and confirm the build.",
        paint.green(&format!(
            "Removed {removed} dependenc{plural} from {edited} manifest(s)."
        ))
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FixOptions, parse_fix_options};
    use std::path::PathBuf;

    fn parse(arguments: &[&str]) -> Result<FixOptions, String> {
        parse_fix_options(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    #[test]
    fn parses_fix_options() {
        assert_eq!(parse(&[]), Ok(FixOptions::default()));
        let options =
            parse(&["proj", "--apply", "--only", "log, rand", "--precise"]).expect("valid");
        assert_eq!(options.path, Some(PathBuf::from("proj")));
        assert!(options.apply && options.precise);
        assert_eq!(
            options.only,
            Some(vec!["log".to_owned(), "rand".to_owned()])
        );
        assert_eq!(
            parse(&["--only=log"]).expect("valid").only,
            Some(vec!["log".to_owned()])
        );
        assert!(parse(&["--apply", "--dry-run"]).is_err());
        assert!(parse(&["--only"]).is_err());
        assert!(parse(&["a", "b"]).is_err());
        assert!(parse(&["--force"]).is_err());
        assert!(
            parse(&["--advisories", "--apply"])
                .expect("valid")
                .advisories
        );
        assert!(parse(&["--advisories", "--precise"]).is_err());
        let updates = parse(&["--updates", "--breaking", "--format", "markdown"]).expect("valid");
        assert!(updates.updates && updates.breaking);
        assert!(parse(&["--breaking"]).is_err());
        assert!(parse(&["--updates", "--advisories"]).is_err());
        let advisories =
            parse(&["--advisories", "--only", "chrono", "--format", "json"]).expect("valid");
        assert_eq!(advisories.only, Some(vec!["chrono".to_owned()]));
        assert_eq!(advisories.format, crate::fix_advisories::Format::Json);
        assert!(parse(&["--format", "json"]).is_err());
        assert_eq!(
            parse(&["--color", "always"]).expect("valid").color,
            super::ColorChoice::Always
        );
        assert!(
            parse(&["--include-uncertain"])
                .expect("valid")
                .include_uncertain
        );
        assert!(parse(&["--advisories", "--include-uncertain"]).is_err());
        assert!(parse(&["--updates", "--include-uncertain"]).is_err());
        let verified = parse(&["--apply", "--verify"]).expect("valid");
        assert!(verified.apply && verified.verify);
        assert!(parse(&["--verify"]).is_err());
        assert!(parse(&["--advisories", "--apply", "--verify"]).is_err());
        assert!(parse(&["--updates", "--apply", "--verify"]).is_err());

        let with_cd = parse(&[
            "--updates",
            "--cooldown",
            "3",
            "--cooldown-for",
            "serde=1,tokio=0",
            "--versioning-strategy",
            "widen",
        ])
        .expect("valid updates options");
        assert_eq!(with_cd.cooldown, Some(3));
        assert_eq!(
            with_cd.cooldown_for,
            vec![("serde".to_owned(), 1), ("tokio".to_owned(), 0)]
        );
        assert_eq!(
            with_cd.versioning_strategy,
            Some(super::VersioningStrategy::Widen)
        );
        assert!(parse(&["--cooldown", "1"]).is_err());
        assert!(parse(&["--updates", "--cooldown-for", "bad"]).is_err());
        assert!(parse(&["--updates", "--versioning-strategy", "bad"]).is_err());
    }
}
