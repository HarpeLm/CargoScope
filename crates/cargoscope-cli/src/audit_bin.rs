//! `cargoscope audit-bin`: advisories of the crates compiled into a binary.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_advisory::AdvisoryDatabase;
use cargoscope_cargo::binary::{BinarySource, inventory_of};
use cargoscope_core::{Checks, PackageInfo, Report};

use crate::{FailOn, parse_fail_on};

#[derive(Debug, PartialEq, Eq)]
struct AuditBinOptions {
    files: Vec<PathBuf>,
    json: bool,
    fail_on: FailOn,
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<AuditBinOptions, String> {
    let mut options = AuditBinOptions {
        files: Vec::new(),
        json: false,
        fail_on: FailOn::AnyVulnerability,
    };
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        let (flag, inline) = match argument.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => {
                (flag.to_owned(), Some(value.to_owned()))
            }
            _ => (argument.clone(), None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| arguments.next())
                .ok_or_else(|| format!("Missing value for {flag}."))
        };
        match flag.as_str() {
            "--format" => {
                options.json = match value()?.as_str() {
                    "text" => false,
                    "json" => true,
                    other => {
                        return Err(format!(
                            "Unsupported output format: {other}. Use text or json."
                        ));
                    }
                };
            }
            "--fail-on" => options.fail_on = parse_fail_on(&value()?)?,
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            _ => options.files.push(PathBuf::from(argument)),
        }
    }
    if options.files.is_empty() {
        return Err("audit-bin needs at least one binary".to_owned());
    }
    Ok(options)
}

/// `cargoscope audit-bin FILE... [--format text|json] [--fail-on THRESHOLD]`.
pub fn audit_bin_command(arguments: impl Iterator<Item = String>) -> ExitCode {
    let options = match parse_options(arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\nRun cargoscope audit-bin --help for usage.");
            return ExitCode::from(2);
        }
    };
    let database =
        match cargoscope_advisory::cache_dir().and_then(|dir| AdvisoryDatabase::open(&dir)) {
            Ok(database) => database,
            Err(error) => {
                eprintln!("CargoScope could not open the advisory database: {error}");
                return ExitCode::from(2);
            }
        };
    let mut code = ExitCode::SUCCESS;
    for file in &options.files {
        match audit(file, &database, &options) {
            Ok(true) => code = ExitCode::from(1),
            Ok(false) => {}
            Err(error) => {
                eprintln!("CargoScope could not audit {}: {error}", file.display());
                return ExitCode::from(2);
            }
        }
    }
    code
}

/// Prints the report of one binary; returns whether it reaches `--fail-on`.
fn audit(
    file: &Path,
    database: &AdvisoryDatabase,
    options: &AuditBinOptions,
) -> Result<bool, String> {
    let bytes = std::fs::read(file).map_err(|error| error.to_string())?;
    let name = file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("binary");
    let found = inventory_of(&bytes, name).ok_or(
        "no dependency information found: not a Rust binary, or built without cargo-auditable and stripped of panic messages",
    )?;

    let mut warnings = Vec::new();
    if found.source == BinarySource::RegistryPaths {
        warnings.push(format!(
            "no cargo-auditable data in this binary: {} crate(s) were found from the source paths its panic messages keep. The list is incomplete (crates without such a message are missing) and has no dependency tree; build with `cargo auditable build` for an exact audit",
            found.inventory.packages.len() - 1
        ));
    }
    let check = database.check(&found.inventory);
    if database.fetched_on.is_none() {
        warnings
            .push("the advisory database has no download date; run `cargoscope update`".to_owned());
    }
    let report = Report {
        checks: Checks::parse("inventory,advisories").unwrap_or_default(),
        package_info: vec![PackageInfo::default(); found.inventory.packages.len()],
        registry_date: None,
        inventory: found.inventory,
        advisories: check.findings,
        unused: Vec::new(),
        policy: None,
        unused_precise: false,
        advisory_db_date: database.fetched_on.clone(),
        warnings,
        direct_kinds: std::collections::BTreeMap::new(),
    };
    let rendered = if options.json {
        cargoscope_report::render_json(file, &report)
    } else {
        cargoscope_report::render_text(file, &report, cargoscope_report::TextOptions::default())
    };
    print!("{rendered}");
    Ok(report
        .advisories
        .iter()
        .any(|finding| options.fail_on.is_triggered_by(finding)))
}

#[cfg(test)]
mod tests {
    use super::parse_options;

    #[test]
    fn needs_a_file_and_known_options() {
        let parse = |arguments: &[&str]| parse_options(arguments.iter().map(|a| (*a).to_owned()));
        let options = parse(&["a", "b", "--format=json", "--fail-on", "high"]).expect("valid");
        assert_eq!(options.files.len(), 2);
        assert!(options.json);
        assert!(parse(&[]).is_err());
        assert!(parse(&["a", "--format", "sarif"]).is_err());
    }
}
