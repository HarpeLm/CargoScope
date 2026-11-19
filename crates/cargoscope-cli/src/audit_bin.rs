//! `cargoscope audit-bin`: advisories of the crates compiled into a binary.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_advisory::AdvisoryDatabase;
use cargoscope_cargo::binary::{BinarySource, inventory_of};
use cargoscope_core::{Checks, PackageInfo, Report};
use cargoscope_report::sarif::SarifLocations;

use crate::scan::{ColorChoice, OutputFormat, parse_output_format, sarif_uri};
use crate::{FailOn, parse_fail_on};

#[derive(Debug, PartialEq, Eq)]
struct AuditBinOptions {
    files: Vec<PathBuf>,
    format: OutputFormat,
    output: Option<PathBuf>,
    verbose: bool,
    fail_on: FailOn,
    color: ColorChoice,
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<AuditBinOptions, String> {
    let mut options = AuditBinOptions {
        files: Vec::new(),
        format: OutputFormat::Text,
        output: None,
        verbose: false,
        fail_on: FailOn::AnyVulnerability,
        color: ColorChoice::Auto,
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
            "--format" => options.format = parse_output_format(&value()?)?,
            "--output" | "-o" => options.output = Some(PathBuf::from(value()?)),
            "--fail-on" => options.fail_on = parse_fail_on(&value()?)?,
            "--color" => options.color = ColorChoice::parse(&value()?)?,
            "--verbose" | "-v" if inline.is_none() => options.verbose = true,
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            _ => options.files.push(PathBuf::from(argument)),
        }
    }
    if options.files.is_empty() {
        return Err("audit-bin needs at least one binary".to_owned());
    }
    if options.files.len() > 1 && options.output.is_some() {
        return Err("--output cannot be used with multiple binaries.".to_owned());
    }
    Ok(options)
}

/// `cargoscope audit-bin FILE... [--format text|json|sarif|cyclonedx|html] [--output FILE] [--fail-on THRESHOLD] [--color WHEN]`.
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
        unsafe_code: Vec::new(),
    };
    let rendered = match options.format {
        OutputFormat::Text => cargoscope_report::render_text(
            file,
            &report,
            cargoscope_report::TextOptions {
                verbose: options.verbose,
                color: options.color.enabled(options.output.is_some()),
                width: crate::scan::terminal_width(options.output.is_some()),
                ..cargoscope_report::TextOptions::default()
            },
        ),
        OutputFormat::Json => cargoscope_report::render_json(file, &report),
        OutputFormat::Sarif => cargoscope_report::sarif::render_sarif(
            &report,
            &SarifLocations {
                lockfile_uri: sarif_uri(file),
                package_lines: vec![None; report.inventory.packages.len()],
                unused_locations: Vec::new(),
            },
            false,
        ),
        OutputFormat::CycloneDx => cargoscope_report::cyclonedx::render_cyclonedx(file, &report),
        OutputFormat::Html => cargoscope_report::html::render_html(file, &report, false, None),
    };
    match &options.output {
        Some(path) => std::fs::write(path, rendered).map_err(|error| error.to_string())?,
        None => print!("{rendered}"),
    }
    Ok(report
        .advisories
        .iter()
        .any(|finding| options.fail_on.is_triggered_by(finding)))
}

#[cfg(test)]
mod tests {
    use super::parse_options;
    use crate::scan::{ColorChoice, OutputFormat};

    #[test]
    fn needs_a_file_and_known_options() {
        let parse = |arguments: &[&str]| parse_options(arguments.iter().map(|a| (*a).to_owned()));
        let options = parse(&["a", "b", "--format=json", "--fail-on", "high"]).expect("valid");
        assert_eq!(options.files.len(), 2);
        assert_eq!(options.format, OutputFormat::Json);
        assert_eq!(options.color, ColorChoice::Auto);
        assert_eq!(
            parse(&["a", "--format", "sarif", "--color", "always"])
                .expect("valid")
                .format,
            OutputFormat::Sarif
        );
        assert_eq!(
            parse(&["a", "--format", "cyclonedx"])
                .expect("valid")
                .format,
            OutputFormat::CycloneDx
        );
        assert_eq!(
            parse(&["a", "--format", "html", "--output", "out.html"])
                .expect("valid")
                .format,
            OutputFormat::Html
        );
        assert!(parse(&["a", "b", "--output", "out.json"]).is_err());
        assert!(parse(&[]).is_err());
        assert!(parse(&["a", "--format", "xml"]).is_err());
    }
}
