//! Command-line entry point for CargoScope.
//!
//! Exit codes (stable contract, see SPEC.md section 8):
//! `0` no finding at or above the threshold, `1` threshold reached,
//! `2` execution error.

mod audit_bin;
mod compare;
mod fix;
mod fix_advisories;
mod scan;
mod why;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_advisory::DEFAULT_ARCHIVE_URL;
use cargoscope_advisory::crates_io;
use cargoscope_core::{AdvisoryFinding, AdvisoryKind, Inventory, Severity, UnusedFinding, VERSION};

const UPDATE_USAGE: &str = "  cargoscope update [PATH]
      Download the RustSec advisory database and the crates.io data (versions,
      licenses) of the project at PATH. The only command that uses the network.";

const COMPARE_USAGE: &str = "  cargoscope compare BASELINE CURRENT [--format text|json|markdown] [--fail-on THRESHOLD]
      Compare two JSON reports (markdown: for a pull request comment). Exit code 1 when new advisories reach the threshold.";

const AUDIT_BIN_USAGE: &str =
    "  cargoscope audit-bin FILE... [--format text|json] [--fail-on THRESHOLD]
      Report the advisories of the crates compiled into Rust binaries. Exact
      with binaries built by `cargo auditable build`; otherwise the crates
      named by panic message paths only (incomplete). The files are only read.";

const WHY_USAGE: &str = "  cargoscope why CRATE[@VERSION] [PATH] [--format text|json]
      Show every dependency chain from the project's root packages to CRATE,
      its direct dependents, and how many packages would leave the tree
      without it. Offline and read-only.";

const FIX_USAGE: &str = "  cargoscope fix [PATH] [--dry-run | --apply] [--only NAMES] [--precise]
      Remove likely-unused dependencies from the Cargo.toml files, and the
      [workspace.dependencies] entries no member uses anymore. Without
      --apply, only shows what would be removed (dry run). --only limits it
      to a comma-separated list of dependencies. Possibly-unused and ignored
      dependencies are never removed. Formatting and comments of the
      manifests are kept; run cargo check afterwards.
  cargoscope fix --advisories [PATH] [--dry-run | --apply] [--format text|markdown]
      Update vulnerable packages to the smallest fixed version Cargo accepts
      (in Cargo.lock, and in Cargo.toml when a direct requirement blocks the
      fix), and say which dependency blocks the others. Runs cargo update,
      which may read the registry index; it compiles nothing.";

const SCAN_USAGE: &str = "  cargoscope scan [PATH] [--format text|json|sarif|cyclonedx|html] [--output FILE] [--fail-on THRESHOLD] [--show-uncertain] [--verbose] [--precise]
      Report on a Cargo project, read-only and offline.

Options for scan:
  --format text|json|sarif|cyclonedx|html
                       Output format (default: text; cyclonedx: CycloneDX 1.5 SBOM;
                       html: self-contained offline report).
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
                       Without advisories, no advisory database is needed.";

const FOOTER: &str = "Environment:
  CARGOSCOPE_CACHE_DIR  Directory for downloaded data.
  HTTPS_PROXY           HTTP proxy for https:// downloads in `update` (also HTTP_PROXY, ALL_PROXY).
  NO_PROXY              Comma-separated hosts bypassing the proxy (localhost always does).

Exit codes: 0 OK, 1 threshold reached, 2 execution error.";

/// Help for one subcommand, or for all of them.
fn usage(sections: &[&str]) -> String {
    format!(
        "CargoScope {VERSION}\n\nUsage:\n{}\n\n{FOOTER}",
        sections.join("\n")
    )
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next();
    let rest: Vec<String> = arguments.collect();
    let section = match command.as_deref() {
        Some("scan") => Some(SCAN_USAGE),
        Some("why") => Some(WHY_USAGE),
        Some("compare") => Some(COMPARE_USAGE),
        Some("fix") => Some(FIX_USAGE),
        Some("update") => Some(UPDATE_USAGE),
        Some("audit-bin") => Some(AUDIT_BIN_USAGE),
        _ => None,
    };
    if let Some(section) = section
        && rest
            .iter()
            .any(|argument| argument == "--help" || argument == "-h")
    {
        println!("{}", usage(&[section]));
        return ExitCode::SUCCESS;
    }

    match command.as_deref() {
        Some("scan") => match scan::parse_scan_options(rest.into_iter()) {
            Ok(options) => scan::scan(&options),
            Err(error) => {
                eprintln!("{error}\nRun cargoscope scan --help for usage.");
                ExitCode::from(2)
            }
        },
        Some("compare") => compare::compare_command(rest.into_iter()),
        Some("why") => why::why_command(rest.into_iter()),
        Some("fix") => fix::fix_command(rest.into_iter()),
        Some("audit-bin") => audit_bin::audit_bin_command(rest.into_iter()),
        Some("update") => match rest.as_slice() {
            [] => update(Path::new(".")),
            [path] => update(Path::new(path)),
            [_, extra, ..] => {
                eprintln!("Unexpected argument for update: {extra}");
                ExitCode::from(2)
            }
        },
        Some("--version" | "-V") => {
            println!("cargoscope {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") | None => {
            println!(
                "{}",
                usage(&[
                    UPDATE_USAGE,
                    COMPARE_USAGE,
                    FIX_USAGE,
                    AUDIT_BIN_USAGE,
                    WHY_USAGE,
                    SCAN_USAGE
                ])
            );
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("Unknown command: {command}\nRun cargoscope --help for usage.");
            ExitCode::from(2)
        }
    }
}

/// When advisory findings make the scan fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailOn {
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

fn execution_error(root: &Path, error: &dyn std::fmt::Display) -> ExitCode {
    eprintln!("CargoScope could not scan {}: {error}", root.display());
    ExitCode::from(2)
}

/// Unused-dependency findings of the project and their warnings, confirmed
/// with rustc when `precise` (which compiles the project).
fn find_unused_dependencies(
    root: &Path,
    inventory: &Inventory,
    precise: bool,
) -> Result<(Vec<UnusedFinding>, Vec<String>), ExitCode> {
    let (unused, warnings) = cargoscope_cargo::find_unused(root, inventory)
        .map_err(|error| execution_error(root, &error))?;
    if !precise {
        return Ok((unused, warnings));
    }
    eprintln!(
        "--precise: running cargo check with all targets and features. This compiles the project, so build scripts and proc macros of the project and its dependencies are executed."
    );
    let packages =
        cargoscope_cargo::project_packages(root).map_err(|error| execution_error(root, &error))?;
    let compiler =
        cargoscope_cargo::precise::run(root).map_err(|error| execution_error(root, &error))?;
    let unused = cargoscope_cargo::precise::refine(
        unused,
        &packages.packages,
        packages.workspace_dependencies.as_ref(),
        &compiler,
    );
    Ok((unused, warnings))
}
