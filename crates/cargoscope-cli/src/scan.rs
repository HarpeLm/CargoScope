//! `cargoscope scan`: the report, built in steps (advisories, unused
//! dependencies, policy, registry data), rendered, then turned into an exit
//! code.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_advisory::AdvisoryDatabase;
use cargoscope_advisory::crates_io::{self, RegistryCache};
use cargoscope_core::policy::{Policy, Violation};
use cargoscope_core::{AdvisoryFinding, Checks, Inventory, PackageInfo, Report};
use cargoscope_report::sarif::SarifLocations;

use crate::{FailOn, execution_error, find_unused_dependencies, parse_fail_on, read_report};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ScanOptions {
    pub path: PathBuf,
    pub format: OutputFormat,
    pub output: Option<PathBuf>,
    pub fail_on: FailOn,
    pub show_uncertain: bool,
    pub verbose: bool,
    pub checks: Checks,
    pub baseline: Option<PathBuf>,
    pub precise: bool,
}

pub fn parse_scan_options(
    mut arguments: impl Iterator<Item = String>,
) -> Result<ScanOptions, String> {
    let mut options = ScanOptions {
        path: PathBuf::from("."),
        format: OutputFormat::Text,
        output: None,
        fail_on: FailOn::AnyVulnerability,
        show_uncertain: false,
        verbose: false,
        checks: Checks::ALL,
        baseline: None,
        precise: false,
    };
    let mut path_given = false;

    while let Some(argument) = arguments.next() {
        let (flag, inline_value) = match argument.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => {
                (flag.to_owned(), Some(value.to_owned()))
            }
            _ => (argument.clone(), None),
        };
        let mut value = || {
            inline_value
                .clone()
                .or_else(|| arguments.next())
                .ok_or_else(|| format!("Missing value for {flag}."))
        };
        match flag.as_str() {
            "--format" => options.format = parse_output_format(&value()?)?,
            "--output" | "-o" => options.output = Some(PathBuf::from(value()?)),
            "--baseline" => options.baseline = Some(PathBuf::from(value()?)),
            "--checks" => {
                options.checks = Checks::parse(&value()?).map_err(|unknown| {
                    format!(
                        "Unknown check: {unknown}. Use {}.",
                        Checks::NAMES.join(", ")
                    )
                })?;
            }
            "--fail-on" => options.fail_on = parse_fail_on(&value()?)?,
            "--show-uncertain" if inline_value.is_none() => options.show_uncertain = true,
            "--verbose" | "-v" if inline_value.is_none() => options.verbose = true,
            "--precise" if inline_value.is_none() => options.precise = true,
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            _ if path_given => return Err("Only one scan path may be provided.".to_owned()),
            _ => {
                options.path = PathBuf::from(argument);
                path_given = true;
            }
        }
    }
    Ok(options)
}

fn parse_output_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "sarif" => Ok(OutputFormat::Sarif),
        _ => Err(format!(
            "Unsupported output format: {value}. Use text, json or sarif."
        )),
    }
}

/// Marks findings ignored by `[advisories] ignore`, matching the advisory ID
/// or one of its aliases. Returns warnings for expired and unused entries.
pub fn apply_advisory_ignores(
    findings: &mut [AdvisoryFinding],
    ignores: &[cargoscope_cargo::config::AdvisoryIgnore],
    today: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for ignore in ignores {
        let matches = |finding: &AdvisoryFinding| {
            finding.id.eq_ignore_ascii_case(&ignore.id)
                || finding
                    .aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(&ignore.id))
        };
        if !findings.iter().any(&matches) {
            warnings.push(format!(
                "cargoscope.toml ignores {}, which matches no advisory of this project: remove it if it is no longer needed",
                ignore.id
            ));
            continue;
        }
        if let Some(until) = ignore.until.as_deref().filter(|until| *until < today) {
            warnings.push(format!(
                "the ignore of {} expired on {until}: the advisory counts again",
                ignore.id
            ));
            continue;
        }
        let reason = match &ignore.until {
            Some(until) => format!("{} (until {until})", ignore.reason),
            None => ignore.reason.clone(),
        };
        for finding in findings.iter_mut().filter(|finding| matches(finding)) {
            finding.ignored = Some(reason.clone());
        }
    }
    warnings
}

/// `cargoscope scan`. Every step returns the exit code to stop with on error.
pub fn scan(options: &ScanOptions) -> ExitCode {
    match run_scan(options) {
        Ok(code) | Err(code) => code,
    }
}

fn run_scan(options: &ScanOptions) -> Result<ExitCode, ExitCode> {
    let root = options.path.as_path();
    let inventory = cargoscope_cargo::scan_cargo_project(root)
        .map_err(|error| execution_error(root, &error))?;
    let checks = options.checks;
    let mut warnings = Vec::new();

    let (advisories, advisory_db_date) = if checks.advisories {
        check_advisories(root, &inventory, &mut warnings)?
    } else {
        (Vec::new(), None)
    };
    let unused = if checks.unused {
        let (unused, unused_warnings) =
            find_unused_dependencies(root, &inventory, options.precise)?;
        warnings.extend(unused_warnings);
        unused
    } else {
        Vec::new()
    };
    let policy = if checks.policy {
        load_policy(root)?
    } else {
        None
    };
    let needs_licenses = policy.as_ref().is_some_and(|policy| policy.check_licenses);
    let (mut package_info, registry_date) = if checks.licenses || checks.versions || needs_licenses
    {
        registry_data(root, &inventory, &mut warnings)
    } else {
        (vec![PackageInfo::default(); inventory.packages.len()], None)
    };
    let violations = policy.map(|policy| {
        check_policy(
            &policy,
            &inventory,
            &package_info,
            registry_date.as_deref(),
            &mut warnings,
        )
    });
    keep_checked_info(&mut package_info, checks);

    // Only labels in the report: a failure leaves the dependencies unlabelled.
    let direct_kinds = cargoscope_cargo::direct_dependency_kinds(root).unwrap_or_default();
    let report = Report {
        direct_kinds,
        checks,
        package_info,
        registry_date,
        inventory,
        advisories,
        unused,
        policy: violations,
        unused_precise: checks.unused && options.precise,
        advisory_db_date,
        warnings,
    };
    write_report(options, &report)?;
    exit_code(options, &report)
}

/// Matching advisories, with the `[advisories] ignore` entries applied, and
/// the date of the database.
fn check_advisories(
    root: &Path,
    inventory: &Inventory,
    warnings: &mut Vec<String>,
) -> Result<(Vec<AdvisoryFinding>, Option<String>), ExitCode> {
    let database = cargoscope_advisory::cache_dir()
        .and_then(|dir| AdvisoryDatabase::open(&dir))
        .map_err(|error| execution_error(root, &error))?;
    let check = database.check(inventory);
    if database.fetched_on.is_none() {
        warnings
            .push("the advisory database has no download date; run `cargoscope update`".to_owned());
    }
    if !check.unreadable.is_empty() {
        warnings.push(format!(
            "{} advisory file(s) could not be read; results may be incomplete",
            check.unreadable.len()
        ));
    }
    let mut findings = check.findings;
    let ignores = cargoscope_cargo::config::load_advisory_ignores(root).map_err(|error| {
        eprintln!("CargoScope could not read the advisory ignores: {error}");
        ExitCode::from(2)
    })?;
    warnings.extend(apply_advisory_ignores(
        &mut findings,
        &ignores,
        &cargoscope_advisory::utc_today(),
    ));
    Ok((findings, database.fetched_on))
}

fn load_policy(root: &Path) -> Result<Option<Policy>, ExitCode> {
    cargoscope_cargo::config::load_policy(root).map_err(|error| {
        eprintln!("CargoScope could not read the policy: {error}");
        ExitCode::from(2)
    })
}

/// crates.io data (licenses, latest versions, yanked status) of every package
/// and its download date, with warnings when it is missing or incomplete.
fn registry_data(
    root: &Path,
    inventory: &Inventory,
    warnings: &mut Vec<String>,
) -> (Vec<PackageInfo>, Option<String>) {
    let (mut package_info, mut registry_date) =
        (vec![PackageInfo::default(); inventory.packages.len()], None);
    if let Ok(dir) = cargoscope_advisory::cache_dir() {
        let registry = RegistryCache::open(&dir);
        package_info = registry.info(inventory);
        registry_date = registry.fetched_on;
    }
    if registry_date.is_none() {
        warnings.push(format!(
            "no crates.io data: licenses and latest versions are unknown; run `cargoscope update {}`",
            root.display()
        ));
    } else {
        let missing = package_info
            .iter()
            .zip(&inventory.packages)
            .filter(|(info, package)| {
                info.latest_version.is_none() && crates_io::is_crates_io(package.source.as_deref())
            })
            .count();
        if missing > 0 {
            warnings.push(format!(
                "{missing} crates.io package(s) have no cached data (added since the last update?); run `cargoscope update {}`",
                root.display()
            ));
        }
    }
    (package_info, registry_date)
}

fn check_policy(
    policy: &Policy,
    inventory: &Inventory,
    package_info: &[PackageInfo],
    registry_date: Option<&str>,
    warnings: &mut Vec<String>,
) -> Vec<Violation> {
    if policy.check_licenses && registry_date.is_none() {
        warnings.push("license rules of the policy were skipped: no crates.io data".to_owned());
    }
    policy.check(inventory, package_info, registry_date.is_some())
}

/// Clears the registry data of checks that did not run, so the report only
/// shows what was asked for.
fn keep_checked_info(package_info: &mut [PackageInfo], checks: Checks) {
    for info in package_info {
        if !checks.licenses {
            info.license = None;
        }
        if !checks.versions {
            *info = PackageInfo {
                license: info.license.take(),
                ..Default::default()
            };
        }
    }
}

/// Renders the report in the chosen format, to `--output` or standard output.
fn write_report(options: &ScanOptions, report: &Report) -> Result<(), ExitCode> {
    let root = options.path.as_path();
    let rendered = match options.format {
        OutputFormat::Text => cargoscope_report::render_text(
            root,
            report,
            cargoscope_report::TextOptions {
                show_uncertain: options.show_uncertain,
                verbose: options.verbose,
            },
        ),
        OutputFormat::Json => cargoscope_report::render_json(root, report),
        OutputFormat::Sarif => cargoscope_report::sarif::render_sarif(
            report,
            &sarif_locations(root, report),
            options.show_uncertain,
        ),
    };
    match &options.output {
        Some(path) => std::fs::write(path, rendered).map_err(|error| {
            eprintln!("CargoScope could not write {}: {error}", path.display());
            ExitCode::from(2)
        }),
        None => {
            print!("{rendered}");
            Ok(())
        }
    }
}

/// 1 when a policy violation or a new advisory reaches `--fail-on`;
/// advisories already in `--baseline` do not count.
fn exit_code(options: &ScanOptions, report: &Report) -> Result<ExitCode, ExitCode> {
    let known = match &options.baseline {
        Some(path) => read_report(path)
            .map(|baseline| cargoscope_report::compare::advisory_keys(&baseline))
            .map_err(|error| {
                eprintln!("CargoScope could not read the baseline: {error}");
                ExitCode::from(2)
            })?,
        None => std::collections::BTreeSet::new(),
    };
    let is_new = |finding: &&AdvisoryFinding| {
        let package = &report.inventory.packages[finding.package];
        !known.contains(&cargoscope_report::compare::AdvisoryKey {
            id: finding.id.clone(),
            package: package.name.clone(),
            version: package.version.clone(),
        })
    };
    let in_baseline = report
        .advisories
        .iter()
        .filter(|finding| !is_new(finding))
        .count();
    if in_baseline > 0 {
        eprintln!(
            "{in_baseline} advisory finding(s) are already in the baseline and do not fail the scan."
        );
    }
    let policy_fails = options.fail_on != FailOn::Never
        && report
            .policy
            .as_ref()
            .is_some_and(|violations| !violations.is_empty());
    let advisory_fails = report
        .advisories
        .iter()
        .filter(is_new)
        .any(|finding| options.fail_on.is_triggered_by(finding));
    Ok(if policy_fails || advisory_fails {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// Repository-relative URI with forward slashes, as SARIF consumers expect.
fn sarif_uri(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut text = text.as_str();
    while let Some(rest) = text.strip_prefix("./") {
        text = rest;
    }
    if path.is_absolute() {
        let text = text.trim_start_matches('/');
        return format!("file:///{text}");
    }
    text.to_owned()
}

fn sarif_locations(root: &Path, report: &Report) -> SarifLocations {
    use cargoscope_cargo::locations::{lockfile_lines, manifest_dependency_line};

    let lockfile = root.join("Cargo.lock");
    let lines = std::fs::read_to_string(&lockfile)
        .map(|text| lockfile_lines(&text))
        .unwrap_or_default();
    let package_lines = report
        .inventory
        .packages
        .iter()
        .map(|package| {
            lines
                .iter()
                .find(|((name, version), _)| *name == package.name && *version == package.version)
                .map(|(_, line)| *line)
        })
        .collect();
    let unused_locations = report
        .unused
        .iter()
        .map(|finding| {
            let manifest = root.join(&finding.manifest);
            let line = std::fs::read_to_string(&manifest).ok().and_then(|text| {
                manifest_dependency_line(&text, finding.kind.section(), &finding.dependency)
            });
            (sarif_uri(&manifest), line)
        })
        .collect();
    SarifLocations {
        lockfile_uri: sarif_uri(&lockfile),
        package_lines,
        unused_locations,
    }
}

#[cfg(test)]
mod tests {
    use super::{OutputFormat, parse_scan_options};
    use crate::FailOn;
    use cargoscope_core::{AdvisoryFinding, AdvisoryKind, Severity};
    use std::path::PathBuf;

    fn parse(arguments: &[&str]) -> Result<super::ScanOptions, String> {
        parse_scan_options(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    #[test]
    fn parses_options_before_or_after_path() {
        let before = parse(&["--format", "json", "--fail-on", "high", "."]).expect("valid");
        let after = parse(&[".", "--format=json", "--fail-on=high"]).expect("valid");
        assert_eq!(before, after);
        assert_eq!(before.path, PathBuf::from("."));
        assert_eq!(before.format, OutputFormat::Json);
        assert_eq!(before.fail_on, FailOn::AtLeast(Severity::High));
    }

    #[test]
    fn defaults_to_text_and_failing_on_any_vulnerability() {
        let options = parse(&[]).expect("valid");
        assert_eq!(options.format, OutputFormat::Text);
        assert_eq!(options.fail_on, FailOn::AnyVulnerability);
    }

    #[test]
    fn rejects_unknown_values() {
        assert!(parse(&["--fail-on", "severe"]).is_err());
        assert!(parse(&["--format"]).is_err());
        assert!(parse(&["a", "b"]).is_err());
    }

    fn finding(kind: AdvisoryKind, severity: Option<Severity>) -> AdvisoryFinding {
        AdvisoryFinding {
            package: 0,
            id: "TEST".to_owned(),
            aliases: Vec::new(),
            title: String::new(),
            date: String::new(),
            url: None,
            kind,
            severity,
            patched: Vec::new(),
            ignored: None,
        }
    }

    #[test]
    fn applies_advisory_ignores_by_id_or_alias_with_expiry() {
        use cargoscope_cargo::config::AdvisoryIgnore;
        let mut findings = vec![
            finding(AdvisoryKind::Vulnerability, Some(Severity::High)),
            finding(AdvisoryKind::Vulnerability, None),
        ];
        findings[0].id = "RUSTSEC-1".to_owned();
        findings[1].id = "RUSTSEC-2".to_owned();
        findings[1].aliases = vec!["CVE-9".to_owned()];
        let ignore = |id: &str, until: Option<&str>| AdvisoryIgnore {
            id: id.to_owned(),
            reason: "known".to_owned(),
            until: until.map(str::to_owned),
        };
        let warnings = super::apply_advisory_ignores(
            &mut findings,
            &[
                ignore("rustsec-1", None),
                ignore("CVE-9", Some("2026-01-01")),
                ignore("RUSTSEC-404", None),
            ],
            "2026-11-14",
        );
        assert_eq!(findings[0].ignored.as_deref(), Some("known"));
        assert_eq!(
            findings[1].ignored, None,
            "expired ignore no longer applies"
        );
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("expired on 2026-01-01"));
        assert!(warnings[1].contains("RUSTSEC-404, which matches no advisory"));
        assert!(!FailOn::AnyVulnerability.is_triggered_by(&findings[0]));
        assert!(FailOn::AnyVulnerability.is_triggered_by(&findings[1]));
    }

    #[test]
    fn applies_failure_thresholds() {
        let medium = finding(AdvisoryKind::Vulnerability, Some(Severity::Medium));
        let unscored = finding(AdvisoryKind::Vulnerability, None);
        let unmaintained = finding(AdvisoryKind::Informational("unmaintained".to_owned()), None);

        assert!(FailOn::AnyVulnerability.is_triggered_by(&medium));
        assert!(!FailOn::AnyVulnerability.is_triggered_by(&unmaintained));
        assert!(!FailOn::Never.is_triggered_by(&medium));
        assert!(FailOn::AtLeast(Severity::Medium).is_triggered_by(&medium));
        assert!(!FailOn::AtLeast(Severity::High).is_triggered_by(&medium));
        assert!(FailOn::AtLeast(Severity::Critical).is_triggered_by(&unscored));
    }
}
