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
use cargoscope_core::{UnusedConfidence, UnusedFinding};

use crate::{execution_error, find_unused_dependencies};

#[derive(Debug, Default, PartialEq, Eq)]
struct FixOptions {
    path: Option<PathBuf>,
    apply: bool,
    precise: bool,
    only: Option<Vec<String>>,
    /// Update vulnerable packages instead of removing unused dependencies.
    advisories: bool,
    /// `--format markdown|json`, with `--advisories`.
    format: crate::fix_advisories::Format,
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
        match argument.as_str() {
            "--apply" => options.apply = true,
            "--dry-run" => dry_run = true,
            "--precise" => options.precise = true,
            "--advisories" => options.advisories = true,
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
    if options.format != crate::fix_advisories::Format::Text && !options.advisories {
        return Err("--format markdown and json need --advisories".to_owned());
    }
    if options.advisories && options.precise {
        return Err("--advisories cannot be combined with --precise".to_owned());
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
    if options.advisories {
        return crate::fix_advisories::run(
            root,
            options.apply,
            options.format,
            options.only.as_deref(),
        );
    }
    let inventory = cargoscope_cargo::scan_cargo_project(root)
        .map_err(|error| execution_error(root, &error))?;
    let (unused, _) = find_unused_dependencies(root, &inventory, options.precise)?;

    let plan = plan_removals(&unused, options.only.as_deref());
    if plan.is_empty() {
        println!("No likely-unused dependency to remove.");
        return Ok(ExitCode::SUCCESS);
    }
    let mut manifests = read_manifests(root, &plan)?;
    let inherited_before = inherited(&manifests, |(original, _)| original);
    let mut removed = edit_manifests(root, &plan, &mut manifests)?;
    removed += remove_orphaned_workspace_dependencies(root, &inherited_before, &mut manifests)?;
    finish(&manifests, removed, options.apply)?;
    Ok(ExitCode::SUCCESS)
}

/// Likely-unused findings that are not ignored, grouped by manifest and
/// restricted to `only` when given; names of `only` that are not candidates
/// are reported.
fn plan_removals<'a>(unused: &'a [UnusedFinding], only: Option<&[String]>) -> Plan<'a> {
    let mut plan = Plan::new();
    for finding in unused {
        if finding.confidence == UnusedConfidence::Likely
            && finding.ignored.is_none()
            && only.is_none_or(|names| names.contains(&finding.dependency))
        {
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
        println!("{manifest}");
        for ((section, key), outcome) in removals.iter().zip(&outcomes) {
            match outcome {
                Outcome::Removed(tables) => {
                    removed += 1;
                    println!("  - remove `{key}` from [{}]", tables.join("], ["));
                }
                Outcome::Skipped(reason) => println!("  = keep `{key}` [{section}]: {reason}"),
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
    println!("Cargo.toml");
    for key in &gone {
        println!("  - remove `{key}` from [workspace.dependencies]: no member uses it anymore");
    }
    Ok(gone.len())
}

/// Writes the edited manifests with `--apply`, or only says what a run with
/// `--apply` would do.
fn finish(manifests: &Manifests, removed: usize, apply: bool) -> Result<(), ExitCode> {
    let plural = if removed == 1 { "y" } else { "ies" };
    if !apply {
        println!(
            "\nDry run: nothing was written. Run `cargoscope fix --apply` to remove {removed} dependenc{plural}."
        );
        return Ok(());
    }
    let mut edited = 0;
    for (path, (original, current)) in manifests {
        if original != current {
            std::fs::write(path, current).map_err(|error| {
                eprintln!("CargoScope could not write {}: {error}", path.display());
                ExitCode::from(2)
            })?;
            edited += 1;
        }
    }
    println!(
        "\nRemoved {removed} dependenc{plural} from {edited} manifest(s). Run `cargo check` to update Cargo.lock and confirm the build."
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
        let advisories =
            parse(&["--advisories", "--only", "chrono", "--format", "json"]).expect("valid");
        assert_eq!(advisories.only, Some(vec!["chrono".to_owned()]));
        assert_eq!(advisories.format, crate::fix_advisories::Format::Json);
        assert!(parse(&["--format", "json"]).is_err());
    }
}
