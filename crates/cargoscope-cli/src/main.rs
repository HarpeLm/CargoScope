//! Command-line entry point for CargoScope.
//!
//! Exit codes (stable contract, see SPEC.md section 8):
//! `0` no finding at or above the threshold, `1` threshold reached,
//! `2` execution error.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_advisory::crates_io::{self, RegistryCache};
use cargoscope_advisory::{AdvisoryDatabase, DEFAULT_ARCHIVE_URL};
use cargoscope_core::{AdvisoryFinding, AdvisoryKind, Report, Severity, VERSION};

const USAGE: &str = "Usage:
  cargoscope update [PATH]
      Download the RustSec advisory database and the crates.io data (versions,
      licenses) of the project at PATH. The only command that uses the network.
  cargoscope scan [PATH] [--format text|json] [--fail-on THRESHOLD] [--show-uncertain]
      Report on a Cargo project, read-only and offline.

Options for scan:
  --format text|json   Output format (default: text).
  --fail-on THRESHOLD  none, low, medium, high or critical.
                       Default: fail on any security vulnerability.
                       Vulnerabilities without a CVSS score always count.
                       Informational advisories (unmaintained, unsound) never fail.
                       Unused dependencies never fail.
  --show-uncertain     Also list possibly-unused dependencies.

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
        if !matches!(finding.kind, AdvisoryKind::Vulnerability) {
            return false;
        }
        match self {
            Self::Never => false,
            Self::AnyVulnerability => true,
            Self::AtLeast(threshold) => finding
                .severity
                .is_none_or(|severity| severity >= threshold),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ScanOptions {
    path: PathBuf,
    format: OutputFormat,
    fail_on: FailOn,
    show_uncertain: bool,
}

fn parse_scan_options(mut arguments: impl Iterator<Item = String>) -> Result<ScanOptions, String> {
    let mut path = None;
    let mut format = OutputFormat::Text;
    let mut fail_on = FailOn::AnyVulnerability;
    let mut show_uncertain = false;

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
            "--fail-on" => fail_on = parse_fail_on(&value()?)?,
            "--show-uncertain" if inline_value.is_none() => show_uncertain = true,
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            _ if path.is_some() => return Err("Only one scan path may be provided.".to_owned()),
            _ => path = Some(PathBuf::from(argument)),
        }
    }

    Ok(ScanOptions {
        path: path.unwrap_or_else(|| PathBuf::from(".")),
        format,
        fail_on,
        show_uncertain,
    })
}

fn parse_output_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        _ => Err(format!(
            "Unsupported output format: {value}. Use text or json."
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
    let database =
        match cargoscope_advisory::cache_dir().and_then(|dir| AdvisoryDatabase::open(&dir)) {
            Ok(database) => database,
            Err(error) => return execution_error(root, &error),
        };

    let check = database.check(&inventory);
    let (unused, mut warnings) = match cargoscope_cargo::find_unused(root, &inventory) {
        Ok(result) => result,
        Err(error) => return execution_error(root, &error),
    };
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

    let registry = cargoscope_advisory::cache_dir().map(|dir| RegistryCache::open(&dir));
    let (package_info, registry_date) = match registry {
        Ok(registry) => (registry.info(&inventory), registry.fetched_on),
        Err(_) => (vec![Default::default(); inventory.packages.len()], None),
    };
    if registry_date.is_none() {
        warnings.push(format!(
            "no crates.io data: licenses and latest versions are unknown; run `cargoscope update {}`",
            root.display()
        ));
    }

    let report = Report {
        package_info,
        registry_date,
        inventory,
        advisories: check.findings,
        unused,
        advisory_db_date: database.fetched_on,
        warnings,
    };
    let rendered = match options.format {
        OutputFormat::Text => cargoscope_report::render_text(root, &report, options.show_uncertain),
        OutputFormat::Json => cargoscope_report::render_json(root, &report),
    };
    print!("{rendered}");

    if report
        .advisories
        .iter()
        .any(|finding| options.fail_on.is_triggered_by(finding))
    {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
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
        }
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
