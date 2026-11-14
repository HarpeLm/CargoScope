//! Command-line entry point for CargoScope.
//!
//! Exit codes (stable contract, see SPEC.md section 8):
//! `0` no finding at or above the threshold, `1` threshold reached,
//! `2` execution error.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_advisory::crates_io::{self, RegistryCache};
use cargoscope_advisory::{AdvisoryDatabase, DEFAULT_ARCHIVE_URL};
use cargoscope_core::{AdvisoryFinding, AdvisoryKind, Checks, Report, Severity, VERSION};
use cargoscope_report::sarif::SarifLocations;

const USAGE: &str = "Usage:
  cargoscope update [PATH]
      Download the RustSec advisory database and the crates.io data (versions,
      licenses) of the project at PATH. The only command that uses the network.
  cargoscope compare BASELINE CURRENT [--format text|json] [--fail-on THRESHOLD]
      Compare two JSON reports. Exit code 1 when new advisories reach the threshold.
  cargoscope scan [PATH] [--format text|json|sarif] [--output FILE] [--fail-on THRESHOLD] [--show-uncertain] [--verbose] [--precise]
      Report on a Cargo project, read-only and offline.

Options for scan:
  --format text|json|sarif
                       Output format (default: text).
  --output FILE        Write the report to FILE instead of standard output.
  --fail-on THRESHOLD  none, low, medium, high or critical.
                       Default: fail on any security vulnerability.
                       Vulnerabilities without a CVSS score always count.
                       Informational advisories (unmaintained, unsound) never fail.
                       Unused dependencies never fail. Policy violations
                       (cargoscope.toml) fail unless THRESHOLD is none.
  --show-uncertain     Also list possibly-unused dependencies.
  --precise            Confirm unused dependencies with rustc (cargo check, all
                       targets and features). COMPILES THE PROJECT: build
                       scripts and proc macros run. Never enabled by default.
  -v, --verbose        List every resolved package (text format).
  --baseline FILE      A previous JSON report: advisories already in it do not
                       fail the scan, so only new ones do.
  --checks LIST        Comma-separated checks to run (default: all):
                       inventory, advisories, unused, licenses, versions, policy.
                       Without advisories, no advisory database is needed.

Environment:
  CARGOSCOPE_CACHE_DIR  Directory for downloaded data.

Exit codes: 0 OK, 1 threshold reached, 2 execution error.";

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);

    match arguments.next().as_deref() {
        Some("scan") => match parse_scan_options(arguments) {
            Ok(options) => scan(&options),
            Err(error) => {
                eprintln!("{error}\nRun cargoscope --help for usage.");
                ExitCode::from(2)
            }
        },
        Some("compare") => compare_command(arguments),
        Some("update") => {
            let path = arguments.next().unwrap_or_else(|| ".".to_owned());
            if let Some(extra) = arguments.next() {
                eprintln!("Unexpected argument for update: {extra}");
                return ExitCode::from(2);
            }
            update(Path::new(&path))
        }
        Some("--version" | "-V") => {
            println!("cargoscope {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") | None => {
            println!("CargoScope {VERSION}\n\n{USAGE}");
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("Unknown command: {command}\nRun cargoscope --help for usage.");
            ExitCode::from(2)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

/// When advisory findings make the scan fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailOn {
    /// Any vulnerability, whatever its severity (default).
    AnyVulnerability,
    /// Never fail on findings.
    Never,
    /// Vulnerabilities at or above this severity, or without a score.
    AtLeast(Severity),
}

impl FailOn {
    fn is_triggered_by(self, finding: &AdvisoryFinding) -> bool {
        if finding.ignored.is_some() {
            return false;
        }
        self.triggers(
            matches!(finding.kind, AdvisoryKind::Vulnerability),
            finding.severity,
        )
    }

    fn triggers(self, vulnerability: bool, severity: Option<Severity>) -> bool {
        if !vulnerability {
            return false;
        }
        match self {
            Self::Never => false,
            Self::AnyVulnerability => true,
            Self::AtLeast(threshold) => severity.is_none_or(|severity| severity >= threshold),
        }
    }
}

/// Marks findings ignored by `[advisories] ignore`, matching the advisory ID
/// or one of its aliases. Returns warnings for expired and unused entries.
fn apply_advisory_ignores(
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

fn parse_severity(name: &str) -> Option<Severity> {
    Some(match name {
        "none" => Severity::None,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => return None,
    })
}

fn read_report(path: &Path) -> Result<serde_json::Value, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    cargoscope_report::compare::check_report(&value)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(value)
}

/// `cargoscope compare BASELINE CURRENT [--format text|json] [--fail-on THRESHOLD]`.
fn compare_command(arguments: impl Iterator<Item = String>) -> ExitCode {
    let mut files = Vec::new();
    let mut format = OutputFormat::Text;
    let mut fail_on = FailOn::AnyVulnerability;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        let (flag, inline) = match argument.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => {
                (flag.to_owned(), Some(value.to_owned()))
            }
            _ => (argument.clone(), None),
        };
        let value = |arguments: &mut std::iter::Peekable<_>| {
            inline.clone().or_else(|| Iterator::next(arguments))
        };
        let result = match flag.as_str() {
            "--format" => value(&mut arguments)
                .ok_or_else(|| "Missing value for --format.".to_owned())
                .and_then(|value: String| match value.as_str() {
                    "text" => Ok(OutputFormat::Text),
                    "json" => Ok(OutputFormat::Json),
                    other => Err(format!(
                        "Unsupported comparison format: {other}. Use text or json."
                    )),
                })
                .map(|parsed| format = parsed),
            "--fail-on" => value(&mut arguments)
                .ok_or_else(|| "Missing value for --fail-on.".to_owned())
                .and_then(|value: String| parse_fail_on(&value))
                .map(|parsed| fail_on = parsed),
            other if other.starts_with('-') => Err(format!("Unknown option: {other}")),
            _ => {
                files.push(PathBuf::from(argument));
                Ok(())
            }
        };
        if let Err(error) = result {
            eprintln!("{error}\nRun cargoscope --help for usage.");
            return ExitCode::from(2);
        }
    }
    let [baseline, current] = files.as_slice() else {
        eprintln!("compare needs two JSON reports: BASELINE CURRENT");
        return ExitCode::from(2);
    };
    let (baseline, current) = match (read_report(baseline), read_report(current)) {
        (Ok(baseline), Ok(current)) => (baseline, current),
        (Err(error), _) | (_, Err(error)) => {
            eprintln!("CargoScope could not compare: {error}");
            return ExitCode::from(2);
        }
    };
    let comparison = cargoscope_report::compare::compare(&baseline, &current);
    match format {
        OutputFormat::Json => print!(
            "{}",
            cargoscope_report::compare::render_comparison_json(&comparison)
        ),
        _ => print!(
            "{}",
            cargoscope_report::compare::render_comparison_text(&comparison)
        ),
    }
    let fails = comparison
        .new_advisories
        .iter()
        .any(|(_, severity, vulnerability, _)| {
            fail_on.triggers(*vulnerability, severity.as_deref().and_then(parse_severity))
        });
    if fails {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ScanOptions {
    path: PathBuf,
    format: OutputFormat,
    output: Option<PathBuf>,
    fail_on: FailOn,
    show_uncertain: bool,
    verbose: bool,
    checks: Checks,
    baseline: Option<PathBuf>,
    precise: bool,
}

fn parse_scan_options(mut arguments: impl Iterator<Item = String>) -> Result<ScanOptions, String> {
    let mut path = None;
    let mut format = OutputFormat::Text;
    let mut fail_on = FailOn::AnyVulnerability;
    let mut show_uncertain = false;
    let mut output = None;
    let mut checks = Checks::ALL;
    let mut verbose = false;
    let mut baseline = None;
    let mut precise = false;

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
            "--format" => format = parse_output_format(&value()?)?,
            "--output" | "-o" => output = Some(PathBuf::from(value()?)),
            "--baseline" => baseline = Some(PathBuf::from(value()?)),
            "--checks" => {
                checks = Checks::parse(&value()?).map_err(|unknown| {
                    format!(
                        "Unknown check: {unknown}. Use {}.",
                        Checks::NAMES.join(", ")
                    )
                })?;
            }
            "--fail-on" => fail_on = parse_fail_on(&value()?)?,
            "--show-uncertain" if inline_value.is_none() => show_uncertain = true,
            "--verbose" | "-v" if inline_value.is_none() => verbose = true,
            "--precise" if inline_value.is_none() => precise = true,
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            _ if path.is_some() => return Err("Only one scan path may be provided.".to_owned()),
            _ => path = Some(PathBuf::from(argument)),
        }
    }

    Ok(ScanOptions {
        path: path.unwrap_or_else(|| PathBuf::from(".")),
        format,
        output,
        fail_on,
        show_uncertain,
        verbose,
        checks,
        baseline,
        precise,
    })
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

fn parse_fail_on(value: &str) -> Result<FailOn, String> {
    Ok(match value {
        "none" => FailOn::Never,
        "low" => FailOn::AtLeast(Severity::Low),
        "medium" => FailOn::AtLeast(Severity::Medium),
        "high" => FailOn::AtLeast(Severity::High),
        "critical" => FailOn::AtLeast(Severity::Critical),
        _ => {
            return Err(format!(
                "Unsupported --fail-on value: {value}. Use none, low, medium, high or critical."
            ));
        }
    })
}

fn update(project_root: &Path) -> ExitCode {
    let cache = match cargoscope_advisory::cache_dir() {
        Ok(cache) => cache,
        Err(error) => {
            eprintln!("CargoScope could not update: {error}");
            return ExitCode::from(2);
        }
    };
    match cargoscope_advisory::update(&cache, DEFAULT_ARCHIVE_URL) {
        Ok(summary) => println!(
            "RustSec advisory database updated: {} advisories in {}",
            summary.advisories,
            summary.path.display()
        ),
        Err(error) => {
            eprintln!("CargoScope could not update the advisory database: {error}");
            return ExitCode::from(2);
        }
    }

    let inventory = match cargoscope_cargo::scan_cargo_project(project_root) {
        Ok(inventory) => inventory,
        Err(error) => {
            println!(
                "crates.io data not refreshed: no Cargo project read at {} ({error})",
                project_root.display()
            );
            return ExitCode::SUCCESS;
        }
    };
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .or_else(|| std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo")));
    println!(
        "Refreshing crates.io data for {} (licenses not found locally are fetched at most once per second)...",
        project_root.display()
    );
    match crates_io::refresh(&cache, &inventory, cargo_home.as_deref()) {
        Ok(summary) => {
            println!(
                "crates.io data updated: {} crates, {} licenses from local sources, {} from the crates.io API",
                summary.crates, summary.licenses_local, summary.licenses_api
            );
            for failure in &summary.failures {
                eprintln!("warning: {failure}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("CargoScope could not update crates.io data: {error}");
            ExitCode::from(2)
        }
    }
}

fn scan(options: &ScanOptions) -> ExitCode {
    let root = options.path.as_path();
    let inventory = match cargoscope_cargo::scan_cargo_project(root) {
        Ok(inventory) => inventory,
        Err(error) => return execution_error(root, &error),
    };
    let checks = options.checks;
    let mut warnings = Vec::new();

    let (advisories, advisory_db_date) = if checks.advisories {
        let database =
            match cargoscope_advisory::cache_dir().and_then(|dir| AdvisoryDatabase::open(&dir)) {
                Ok(database) => database,
                Err(error) => return execution_error(root, &error),
            };
        let check = database.check(&inventory);
        if database.fetched_on.is_none() {
            warnings.push(
                "the advisory database has no download date; run `cargoscope update`".to_owned(),
            );
        }
        if !check.unreadable.is_empty() {
            warnings.push(format!(
                "{} advisory file(s) could not be read; results may be incomplete",
                check.unreadable.len()
            ));
        }
        let mut findings = check.findings;
        match cargoscope_cargo::config::load_advisory_ignores(root) {
            Ok(ignores) => {
                warnings.extend(apply_advisory_ignores(
                    &mut findings,
                    &ignores,
                    &cargoscope_advisory::utc_today(),
                ));
            }
            Err(error) => {
                eprintln!("CargoScope could not read the advisory ignores: {error}");
                return ExitCode::from(2);
            }
        }
        (findings, database.fetched_on)
    } else {
        (Vec::new(), None)
    };

    let unused = if checks.unused {
        match cargoscope_cargo::find_unused(root, &inventory) {
            Ok((unused, unused_warnings)) => {
                warnings.extend(unused_warnings);
                unused
            }
            Err(error) => return execution_error(root, &error),
        }
    } else {
        Vec::new()
    };
    let unused = if checks.unused && options.precise {
        eprintln!(
            "--precise: running cargo check with all targets and features. This compiles the project, so build scripts and proc macros of the project and its dependencies are executed."
        );
        let packages = match cargoscope_cargo::project_packages(root) {
            Ok(packages) => packages,
            Err(error) => return execution_error(root, &error),
        };
        match cargoscope_cargo::precise::run(root) {
            Ok(compiler) => cargoscope_cargo::precise::refine(
                unused,
                &packages.packages,
                packages.workspace_dependencies.as_ref(),
                &compiler,
            ),
            Err(error) => return execution_error(root, &error),
        }
    } else {
        unused
    };

    let policy = if checks.policy {
        match cargoscope_cargo::config::load_policy(root) {
            Ok(policy) => policy,
            Err(error) => {
                eprintln!("CargoScope could not read the policy: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };
    let needs_licenses = policy.as_ref().is_some_and(|policy| policy.check_licenses);

    let (mut package_info, mut registry_date) =
        (vec![Default::default(); inventory.packages.len()], None);
    if checks.licenses || checks.versions || needs_licenses {
        if let Ok(dir) = cargoscope_advisory::cache_dir() {
            let registry = RegistryCache::open(&dir);
            package_info = registry.info(&inventory);
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
                    info.latest_version.is_none()
                        && crates_io::is_crates_io(package.source.as_deref())
                })
                .count();
            if missing > 0 {
                warnings.push(format!(
                    "{missing} crates.io package(s) have no cached data (added since the last update?); run `cargoscope update {}`",
                    root.display()
                ));
            }
        }
    }
    let violations = policy.map(|policy| {
        if policy.check_licenses && registry_date.is_none() {
            warnings.push("license rules of the policy were skipped: no crates.io data".to_owned());
        }
        policy.check(&inventory, &package_info, registry_date.is_some())
    });
    {
        for info in &mut package_info {
            if !checks.licenses {
                info.license = None;
            }
            if !checks.versions {
                *info = cargoscope_core::PackageInfo {
                    license: info.license.take(),
                    ..Default::default()
                };
            }
        }
    }

    let report = Report {
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
    let rendered = match options.format {
        OutputFormat::Text => cargoscope_report::render_text(
            root,
            &report,
            cargoscope_report::TextOptions {
                show_uncertain: options.show_uncertain,
                verbose: options.verbose,
            },
        ),
        OutputFormat::Json => cargoscope_report::render_json(root, &report),
        OutputFormat::Sarif => cargoscope_report::sarif::render_sarif(
            &report,
            &sarif_locations(root, &report),
            options.show_uncertain,
        ),
    };
    match &options.output {
        Some(path) => {
            if let Err(error) = std::fs::write(path, rendered) {
                eprintln!("CargoScope could not write {}: {error}", path.display());
                return ExitCode::from(2);
            }
        }
        None => print!("{rendered}"),
    }

    let known = match &options.baseline {
        Some(path) => match read_report(path) {
            Ok(baseline) => cargoscope_report::compare::advisory_keys(&baseline),
            Err(error) => {
                eprintln!("CargoScope could not read the baseline: {error}");
                return ExitCode::from(2);
            }
        },
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
    if policy_fails
        || report
            .advisories
            .iter()
            .filter(is_new)
            .any(|finding| options.fail_on.is_triggered_by(finding))
    {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
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

fn execution_error(root: &Path, error: &dyn std::fmt::Display) -> ExitCode {
    eprintln!("CargoScope could not scan {}: {error}", root.display());
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::{FailOn, OutputFormat, parse_scan_options};
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
