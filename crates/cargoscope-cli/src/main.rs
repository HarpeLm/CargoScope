//! Command-line entry point for CargoScope.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);

    match arguments.next().as_deref() {
        Some("scan") => match parse_scan_options(arguments) {
            Ok((path, output_format)) => scan(Path::new(&path), output_format),
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        Some("--version") | Some("-V") => {
            println!("cargoscope {}", cargoscope_core::VERSION);
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") | None => {
            println!(
                "CargoScope {}\n\nUsage:\n  cargoscope scan [PATH] [--format text|json]",
                cargoscope_core::VERSION
            );
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("Unknown command: {command}\nRun cargoscope --help for usage.");
            ExitCode::from(2)
        }
    }
}

#[derive(Clone, Copy)]
enum OutputFormat {
    Text,
    Json,
}

fn parse_scan_options(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(String, OutputFormat), String> {
    let mut path = None;
    let mut output_format = OutputFormat::Text;

    while let Some(argument) = arguments.next() {
        let arg_str: &str = &argument;
        match arg_str {
            "--format" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "Missing value for --format.".to_owned())?;
                output_format = parse_output_format(&value)?;
            }
            s if s.starts_with("--format=") => {
                output_format = parse_output_format(s.trim_start_matches("--format="))?;
            }
            s if s.starts_with('-') => return Err(format!("Unknown option: {s}")),
            _ if path.is_some() => {
                return Err("Only one scan path may be provided.".to_owned());
            }
            _ => {
                path = Some(argument);
            }
        }
    }

    Ok((path.unwrap_or_else(|| ".".to_owned()), output_format))
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

fn scan(project_root: &Path, output_format: OutputFormat) -> ExitCode {
    match cargoscope_cargo::scan_cargo_project(project_root) {
        Ok(inventory) => {
            let report = match output_format {
                OutputFormat::Text => cargoscope_report::render_text(project_root, &inventory),
                OutputFormat::Json => cargoscope_report::render_json(project_root, &inventory),
            };
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "CargoScope could not scan {}: {error}",
                project_root.display()
            );
            // Exit code 2 = execution error (see SPEC.md, section 8).
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OutputFormat, parse_scan_options};

    #[test]
    fn parses_json_output_before_or_after_path() {
        let before_path =
            parse_scan_options(["--format", "json", "."].into_iter().map(str::to_owned))
                .expect("options are valid");
        let after_path = parse_scan_options([".", "--format=json"].into_iter().map(str::to_owned))
            .expect("options are valid");

        assert_eq!(before_path.0, ".");
        assert!(matches!(before_path.1, OutputFormat::Json));
        assert_eq!(after_path.0, ".");
        assert!(matches!(after_path.1, OutputFormat::Json));
    }
}
