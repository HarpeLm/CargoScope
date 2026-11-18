//! `cargoscope aggregate`: consolidate JSON reports of several projects.

use std::path::PathBuf;
use std::process::ExitCode;

use crate::scan::ColorChoice;
use crate::{FailOn, parse_fail_on, parse_severity, read_report};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AggregateFormat {
    Text,
    Json,
    Html,
}

#[derive(Debug, PartialEq, Eq)]
struct AggregateOptions {
    files: Vec<PathBuf>,
    format: AggregateFormat,
    output: Option<PathBuf>,
    fail_on: FailOn,
    ignore_unlikely: bool,
    color: ColorChoice,
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<AggregateOptions, String> {
    let mut options = AggregateOptions {
        files: Vec::new(),
        format: AggregateFormat::Text,
        output: None,
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
                    "text" => AggregateFormat::Text,
                    "json" => AggregateFormat::Json,
                    "html" => AggregateFormat::Html,
                    other => {
                        return Err(format!(
                            "Unsupported aggregate format: {other}. Use text, json or html."
                        ));
                    }
                };
            }
            "--output" | "-o" => options.output = Some(PathBuf::from(value()?)),
            "--fail-on" => options.fail_on = parse_fail_on(&value()?)?,
            "--color" => options.color = ColorChoice::parse(&value()?)?,
            "--ignore-unlikely" if inline.is_none() => options.ignore_unlikely = true,
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            _ => options.files.push(PathBuf::from(argument)),
        }
    }
    if options.files.is_empty() {
        return Err("aggregate needs at least one JSON report".to_owned());
    }
    Ok(options)
}

/// `cargoscope aggregate REPORT.json... [--format text|json|html] [--output FILE] [--fail-on THRESHOLD] [--ignore-unlikely] [--color WHEN]`.
pub fn aggregate_command(arguments: impl Iterator<Item = String>) -> ExitCode {
    let options = match parse_options(arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\nRun cargoscope aggregate --help for usage.");
            return ExitCode::from(2);
        }
    };
    let mut loaded = Vec::with_capacity(options.files.len());
    for path in &options.files {
        match read_report(path) {
            Ok(report) => loaded.push((path.display().to_string(), report)),
            Err(error) => {
                eprintln!("CargoScope could not aggregate: {error}");
                return ExitCode::from(2);
            }
        }
    }
    let report = cargoscope_report::aggregate::aggregate(&loaded);
    let rendered = match options.format {
        AggregateFormat::Text => cargoscope_report::aggregate::render_aggregate_text(
            &report,
            options.color.enabled(options.output.is_some()),
        ),
        AggregateFormat::Json => cargoscope_report::aggregate::render_aggregate_json(&report),
        AggregateFormat::Html => cargoscope_report::aggregate::render_aggregate_html(&report),
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
    let fails = report.advisories.iter().any(|advisory| {
        (!options.ignore_unlikely || advisory.relevance != "unlikely")
            && options.fail_on.triggers(
                advisory.kind == "vulnerability",
                advisory.severity.as_deref().and_then(parse_severity),
            )
    });
    if fails {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::{AggregateFormat, parse_options};
    use crate::FailOn;
    use crate::scan::ColorChoice;

    #[test]
    fn parses_aggregate_options() {
        let parse = |arguments: &[&str]| parse_options(arguments.iter().map(|a| (*a).to_owned()));
        let opts = parse(&[
            "a.json",
            "b.json",
            "--format=html",
            "--output",
            "out.html",
            "--fail-on",
            "high",
            "--ignore-unlikely",
            "--color",
            "always",
        ])
        .expect("valid");
        assert_eq!(opts.files.len(), 2);
        assert_eq!(opts.format, AggregateFormat::Html);
        assert_eq!(
            opts.fail_on,
            FailOn::AtLeast(cargoscope_core::Severity::High)
        );
        assert!(opts.ignore_unlikely);
        assert_eq!(opts.color, ColorChoice::Always);
        assert!(parse(&[]).is_err());
        assert!(parse(&["a.json", "--format", "sarif"]).is_err());
    }
}
