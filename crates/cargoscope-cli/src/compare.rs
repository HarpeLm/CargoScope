//! `cargoscope compare`: what changed between two JSON reports.

use std::path::PathBuf;
use std::process::ExitCode;

use crate::scan::ColorChoice;
use crate::{FailOn, parse_fail_on, parse_severity, read_report};

/// Output formats of `cargoscope compare`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompareFormat {
    Text,
    Json,
    Markdown,
}

#[derive(Debug)]
struct CompareOptions {
    files: Vec<PathBuf>,
    format: CompareFormat,
    fail_on: FailOn,
    ignore_unlikely: bool,
    color: ColorChoice,
}

fn parse_compare_options(
    arguments: impl Iterator<Item = String>,
) -> Result<CompareOptions, String> {
    let mut options = CompareOptions {
        files: Vec::new(),
        format: CompareFormat::Text,
        fail_on: FailOn::AnyVulnerability,
        ignore_unlikely: false,
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
            "--format" => {
                options.format = match value()?.as_str() {
                    "text" => CompareFormat::Text,
                    "json" => CompareFormat::Json,
                    "markdown" => CompareFormat::Markdown,
                    other => {
                        return Err(format!(
                            "Unsupported comparison format: {other}. Use text, json or markdown."
                        ));
                    }
                };
            }
            "--fail-on" => options.fail_on = parse_fail_on(&value()?)?,
            "--color" => options.color = ColorChoice::parse(&value()?)?,
            "--ignore-unlikely" if inline.is_none() => options.ignore_unlikely = true,
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            _ => options.files.push(PathBuf::from(argument)),
        }
    }
    Ok(options)
}

/// `cargoscope compare BASELINE CURRENT [--format text|json|markdown] [--fail-on THRESHOLD]`.
pub fn compare_command(arguments: impl Iterator<Item = String>) -> ExitCode {
    let options = match parse_compare_options(arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\nRun cargoscope compare --help for usage.");
            return ExitCode::from(2);
        }
    };
    let [baseline, current] = options.files.as_slice() else {
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
    let rendered = match options.format {
        CompareFormat::Json => cargoscope_report::compare::render_comparison_json(&comparison),
        CompareFormat::Markdown => {
            cargoscope_report::compare::render_comparison_markdown(&comparison)
        }
        CompareFormat::Text => cargoscope_report::compare::render_comparison_text_colored(
            &comparison,
            options.color.enabled(false),
        ),
    };
    print!("{rendered}");

    let fails = comparison
        .new_advisories
        .iter()
        .any(|(_, severity, kind, _, relevance, _)| {
            (!options.ignore_unlikely || relevance.as_deref() != Some("unlikely"))
                && options.fail_on.triggers(
                    kind == "vulnerability",
                    severity.as_deref().and_then(parse_severity),
                )
        });
    if fails {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
