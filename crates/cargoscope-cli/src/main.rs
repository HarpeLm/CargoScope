//! Command-line entry point for CargoScope.
//!
//! Exit codes (stable contract, see SPEC.md section 8):
//! `0` no finding at or above the threshold, `1` threshold reached,
//! `2` execution error.

mod aggregate;
mod audit_bin;
mod compare;
mod fix;
mod fix_advisories;
mod fix_updates;
mod init;
mod scan;
mod update_notes;
mod why;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_advisory::DEFAULT_ARCHIVE_URL;
use cargoscope_advisory::crates_io;
use cargoscope_core::{AdvisoryFinding, AdvisoryKind, Inventory, Severity, UnusedFinding, VERSION};

const UPDATE_USAGE: &str = "  cargoscope update [PATH] [--no-maintenance | --fast]
      Download the RustSec advisory database and the crates.io data (versions,
      licenses, maintenance) of the project at PATH. The only command that uses the network.
        --no-maintenance, --fast  Skip the 1 req/s crates.io maintenance requests.";

const INIT_USAGE: &str = "  cargoscope init [PATH] [--ci] [--policy] [--dry-run] [--force]
      Create cargoscope.toml (translating deny.toml and .cargo/audit.toml when
      present) and/or .github/workflows/cargoscope.yml (--ci). Without --ci or
      --policy, creates cargoscope.toml. Never overwrites existing files unless
      --force is given; --dry-run prints what would be written.";

const COMPARE_USAGE: &str = "  cargoscope compare BASELINE CURRENT [--format text|json|markdown] [--fail-on THRESHOLD] [--ignore-unlikely] [--color WHEN]
      Compare two JSON reports (markdown: for a pull request comment). Exit code 1 when new advisories reach the threshold.";

const AGGREGATE_USAGE: &str = "  cargoscope aggregate REPORT.json... [--format text|json|html] [--output FILE] [--fail-on THRESHOLD] [--ignore-unlikely] [--color WHEN]
      Merge JSON reports from several CargoScope scans into one shared view of advisories, licenses, outdated crates and unused dependencies.";

const AUDIT_BIN_USAGE: &str =
    "  cargoscope audit-bin FILE... [--format text|json|sarif|cyclonedx|html] [--output FILE] [--fail-on THRESHOLD] [--color WHEN] [--verbose]
      Report the advisories of the crates compiled into Rust binaries. Exact
      with binaries built by `cargo auditable build`; otherwise the crates
      named by panic message paths only (incomplete). The files are only read.
      --verbose lists every advisory in full and every crate found.";

const WHY_USAGE: &str =
    "  cargoscope why CRATE[@VERSION] [PATH] [--format text|json] [--color WHEN]
      Show every dependency chain from the project's root packages to CRATE,
      its direct dependents, and how many packages would leave the tree
      without it. Offline and read-only.";

const FIX_USAGE: &str =
    "  cargoscope fix [PATH] [--dry-run | --apply] [--only NAMES] [--include-uncertain] [--precise] [--color WHEN]
      Remove likely-unused dependencies from the Cargo.toml files, and the
      [workspace.dependencies] entries no member uses anymore. Without
      --apply, only shows what would be removed (dry run). --only limits it
      to a comma-separated list of dependencies (and may also target
      possibly-unused crates); --include-uncertain includes all possibly-unused
      dependencies. Ignored dependencies are never removed. Formatting and
      comments of the manifests are kept; run cargo check afterwards.
  cargoscope fix --advisories [PATH] [--dry-run | --apply] [--format text|markdown] [--color WHEN]
      Update vulnerable packages to the smallest fixed version Cargo accepts
      (in Cargo.lock, and in Cargo.toml when a direct requirement blocks the
      fix), and say which dependency blocks the others. Runs cargo update,
      which may read the registry index; it compiles nothing.
  cargoscope fix --updates [PATH] [--breaking] [--dry-run | --apply] [--only NAMES]
                 [--format text|markdown|json] [--color WHEN]
                 [--comment-command COMMENT --pr-body FILE]
      Update direct dependencies to their newest SemVer-compatible version in
      Cargo.lock, as Dependabot version updates do. With --breaking, try the
      newest major version first, raising the requirement in Cargo.toml.
      With --comment-command and --pr-body, interpret a PR comment such as
      `/cargoscope rebase` or `/cargoscope ignore this major version`.
      Needs the crates.io data of `cargoscope update`; compiles nothing.";

const SCAN_USAGE: &str = "  cargoscope scan [PATH] [--update] [--no-maintenance | --fast] [--format text|json|sarif|cyclonedx|html] [--output FILE] [--fail-on THRESHOLD] [--ignore-unlikely] [--rustsec-only] [--show-uncertain] [--verbose] [--precise] [--color WHEN]
      Report on a Cargo project, read-only and offline (unless --update is given).

Options for scan:
  --update             Download or refresh the advisory database and crates.io
                       data before scanning.
  --no-maintenance, --fast
                       With --update, skip the 1 req/s crates.io maintenance requests.
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
  --ignore-unlikely    Do not fail --fail-on for advisories ranked unlikely
                       (dev-only, mismatched [graph] target, or uncalled function).
  --rustsec-only       Report RustSec advisories only, as cargo-audit does, without
                       the GitHub and malicious-crate advisories that OSV adds.
  --show-uncertain     Also list possibly-unused dependencies.
  --precise            Confirm unused dependencies with rustc (cargo check, all
                       targets and features). COMPILES THE PROJECT: build
                       scripts and proc macros run. Never enabled by default.
  -v, --verbose        Full text report: every advisory in detail and every
                       resolved package.
  --color WHEN         auto, always or never (default: auto: colors only on a
                       terminal, without NO_COLOR, and not with --output).
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
        Some("aggregate") => Some(AGGREGATE_USAGE),
        Some("fix") => Some(FIX_USAGE),
        Some("init") => Some(INIT_USAGE),
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
        Some("aggregate") => aggregate::aggregate_command(rest.into_iter()),
        Some("why") => why::why_command(rest.into_iter()),
        Some("fix") => fix::fix_command(rest.into_iter()),
        Some("init") => init::init_command(rest.into_iter()),
        Some("audit-bin") => audit_bin::audit_bin_command(rest.into_iter()),
        Some("update") => match parse_update_options(rest.into_iter()) {
            Ok(options) => update(&options),
            Err(error) => {
                eprintln!("{error}\nRun cargoscope update --help for usage.");
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
                    INIT_USAGE,
                    UPDATE_USAGE,
                    COMPARE_USAGE,
                    AGGREGATE_USAGE,
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UpdateOptions {
    pub path: PathBuf,
    pub include_maintenance: bool,
}

pub(crate) fn parse_update_options(
    arguments: impl Iterator<Item = String>,
) -> Result<UpdateOptions, String> {
    let mut options = UpdateOptions {
        path: PathBuf::from("."),
        include_maintenance: true,
    };
    let mut path_given = false;
    for argument in arguments {
        match argument.as_str() {
            "--no-maintenance" | "--fast" => options.include_maintenance = false,
            other if other.starts_with('-') => {
                return Err(format!("Unknown option for update: {other}"));
            }
            _ if path_given => {
                return Err(format!("Unexpected argument for update: {argument}"));
            }
            _ => {
                options.path = PathBuf::from(argument);
                path_given = true;
            }
        }
    }
    Ok(options)
}

fn update(options: &UpdateOptions) -> ExitCode {
    match run_update(&options.path, None, options.include_maintenance, false) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

pub(crate) fn update_for_scan(
    project_root: &Path,
    inventory: &Inventory,
    include_maintenance: bool,
) -> Result<(), ExitCode> {
    run_update(project_root, Some(inventory), include_maintenance, true)
}

fn run_update(
    project_root: &Path,
    inventory: Option<&Inventory>,
    include_maintenance: bool,
    to_stderr: bool,
) -> Result<(), ExitCode> {
    let say = |line: &str| {
        if to_stderr {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };
    let cache = cargoscope_advisory::cache_dir().map_err(|error| {
        eprintln!("CargoScope could not update: {error}");
        ExitCode::from(2)
    })?;
    match cargoscope_advisory::update(&cache, DEFAULT_ARCHIVE_URL) {
        Ok(summary) => say(&format!(
            "RustSec advisory database updated: {} advisories in {}",
            summary.advisories,
            summary.path.display()
        )),
        Err(error) => {
            eprintln!("CargoScope could not update the advisory database: {error}");
            return Err(ExitCode::from(2));
        }
    }
    // OSV adds what RustSec lacks; without it, scans still have RustSec.
    match cargoscope_advisory::osv::update(&cache, cargoscope_advisory::osv::DEFAULT_OSV_URL) {
        Ok(summary) => say(&format!(
            "OSV advisories not in RustSec updated: {} (GitHub advisories and malicious crates)",
            summary.advisories
        )),
        Err(error) => eprintln!(
            "warning: OSV advisories not updated ({error}); scans use RustSec alone until the next update"
        ),
    }

    let loaded_inventory;
    let inventory = match inventory {
        Some(inventory) => inventory,
        None => match cargoscope_cargo::scan_cargo_project(project_root) {
            Ok(inventory) => {
                loaded_inventory = inventory;
                &loaded_inventory
            }
            Err(error) => {
                say(&format!(
                    "crates.io data not refreshed: no Cargo project read at {} ({error})",
                    project_root.display()
                ));
                return Ok(());
            }
        },
    };
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .or_else(|| std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo")));
    say(&format!(
        "Refreshing crates.io data for {} (licenses not found locally are fetched at most once per second)...",
        project_root.display()
    ));
    let direct = inventory
        .packages
        .iter()
        .filter(|package| {
            package.direct && !package.root && crates_io::is_crates_io(package.source.as_deref())
        })
        .map(|package| package.name.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if include_maintenance && direct > 30 {
        say(&format!(
            "Maintenance data of {direct} direct dependencies: up to {direct} s the first time (crates.io asks for one request per second; use --fast to skip), then kept for a week."
        ));
    }
    // A live counter on a terminal; nothing in pipes and CI logs.
    let live = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let mut shown = false;
    let mut progress = |event: crates_io::RefreshProgress| {
        let crates_io::RefreshProgress::Maintenance { done, total } = event;
        if !live {
            return;
        }
        if done < total {
            eprint!("\r\x1b[2KMaintenance data: {done}/{total} direct dependencies...");
            shown = true;
        } else if shown {
            eprint!("\r\x1b[2K");
        }
        let _ = std::io::Write::flush(&mut std::io::stderr());
    };
    let refreshed = crates_io::refresh_with_progress(
        &cache,
        inventory,
        cargo_home.as_deref(),
        include_maintenance,
        &mut progress,
    );
    match refreshed {
        Ok(summary) => {
            if include_maintenance {
                say(&format!(
                    "crates.io data updated: {} crates, {} licenses from local sources, {} from the crates.io API, maintenance data of {} direct dependencies",
                    summary.crates,
                    summary.licenses_local,
                    summary.licenses_api,
                    summary.maintenance
                ));
            } else {
                say(&format!(
                    "crates.io data updated: {} crates, {} licenses from local sources, {} from the crates.io API (maintenance skipped)",
                    summary.crates, summary.licenses_local, summary.licenses_api
                ));
            }
            for failure in &summary.failures {
                eprintln!("warning: {failure}");
            }
            Ok(())
        }
        Err(error) => {
            if live {
                eprint!("\r\x1b[2K");
            }
            eprintln!("CargoScope could not update crates.io data: {error}");
            Err(ExitCode::from(2))
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
