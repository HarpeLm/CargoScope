//! `cargoscope why`: explain why a crate is in `Cargo.lock`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use cargoscope_core::{DependencyKind, Inventory, Package};
use cargoscope_report::Paint;
use serde_json::json;

use crate::execution_error;
use crate::scan::ColorChoice;

const MAX_PATHS: usize = 25;

#[derive(Debug, PartialEq, Eq)]
struct WhyOptions {
    crate_spec: String,
    path: PathBuf,
    json: bool,
    color: ColorChoice,
}

fn parse_why_options(arguments: impl Iterator<Item = String>) -> Result<WhyOptions, String> {
    let mut crate_spec: Option<String> = None;
    let mut path: Option<PathBuf> = None;
    let mut json = false;
    let mut color = ColorChoice::Auto;
    let mut arguments = arguments.peekable();

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
            "--format" => {
                json = match value()?.as_str() {
                    "text" => false,
                    "json" => true,
                    other => {
                        return Err(format!(
                            "Unsupported output format: {other}. Use text or json."
                        ));
                    }
                };
            }
            "--color" => color = ColorChoice::parse(&value()?)?,
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            _ if crate_spec.is_none() => crate_spec = Some(argument),
            _ if path.is_none() => path = Some(PathBuf::from(argument)),
            _ => return Err("why takes CRATE[@VERSION] and an optional PATH.".to_owned()),
        }
    }

    let crate_spec =
        crate_spec.ok_or_else(|| "why needs a crate name (CRATE[@VERSION]).".to_owned())?;
    Ok(WhyOptions {
        crate_spec,
        path: path.unwrap_or_else(|| PathBuf::from(".")),
        json,
        color,
    })
}

/// `cargoscope why CRATE[@VERSION] [PATH] [--format text|json] [--color WHEN]`.
pub fn why_command(arguments: impl Iterator<Item = String>) -> ExitCode {
    let options = match parse_why_options(arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\nRun cargoscope why --help for usage.");
            return ExitCode::from(2);
        }
    };
    let root = options.path.as_path();
    let inventory = match cargoscope_cargo::scan_cargo_project(root) {
        Ok(inventory) => inventory,
        Err(error) => return execution_error(root, &error),
    };
    let matches = match_packages(&inventory, &options.crate_spec);
    if matches.is_empty() {
        eprintln!("Crate `{}` is not in Cargo.lock.", options.crate_spec);
        return ExitCode::from(1);
    }

    let direct_kinds = cargoscope_cargo::direct_dependency_kinds(root).unwrap_or_default();
    let rendered = if options.json {
        render_json(&inventory, &matches, &options.crate_spec)
    } else {
        render_text(
            &inventory,
            &matches,
            &direct_kinds,
            Paint::new(options.color.enabled(false)),
        )
    };
    print!("{rendered}");
    ExitCode::SUCCESS
}

fn match_packages(inventory: &Inventory, crate_spec: &str) -> Vec<usize> {
    let (name, version) = match crate_spec.split_once('@') {
        Some((name, version)) if !version.is_empty() => (name, Some(version)),
        _ => (crate_spec, None),
    };
    let collect_with = |target_name: &str| -> Vec<usize> {
        inventory
            .packages
            .iter()
            .enumerate()
            .filter(|(_, package)| {
                package.name == target_name && version.is_none_or(|ver| package.version == ver)
            })
            .map(|(index, _)| index)
            .collect()
    };
    let exact = collect_with(name);
    if !exact.is_empty() {
        return exact;
    }
    let hyphenated = name.replace('_', "-");
    if hyphenated != name {
        let found = collect_with(&hyphenated);
        if !found.is_empty() {
            return found;
        }
    }
    let underscored = name.replace('-', "_");
    if underscored != name {
        return collect_with(&underscored);
    }
    Vec::new()
}

fn scope(package: &Package) -> &'static str {
    if package.root {
        "root"
    } else if package.direct {
        "direct"
    } else {
        "transitive"
    }
}

fn kind_note(
    direct_kinds: &BTreeMap<String, BTreeSet<DependencyKind>>,
    name: &str,
) -> &'static str {
    let Some(kinds) = direct_kinds.get(name) else {
        return "";
    };
    let dev = kinds.contains(&DependencyKind::Dev);
    let build = kinds.contains(&DependencyKind::Build);
    match (kinds.contains(&DependencyKind::Normal), dev, build) {
        (false, true, false) => " (dev)",
        (false, false, true) => " (build)",
        (false, true, true) => " (dev, build)",
        _ => "",
    }
}

fn render_text(
    inventory: &Inventory,
    matches: &[usize],
    direct_kinds: &BTreeMap<String, BTreeSet<DependencyKind>>,
    paint: Paint,
) -> String {
    let mut out = String::new();
    for (position, &index) in matches.iter().enumerate() {
        if position > 0 {
            out.push('\n');
        }
        let package = &inventory.packages[index];
        let header_note = if package.direct && !package.root {
            kind_note(direct_kinds, &package.name)
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "{} {} {}{}",
            paint.bold(&package.name),
            package.version,
            paint.dim(&format!("[{}]", scope(package))),
            paint.dim(header_note)
        );

        let dependents = inventory.dependents_of(index);
        if !package.root {
            let (exclusive, tree) = inventory.package_weight(index);
            let _ = writeln!(
                out,
                "  {} {} of {tree} package{} in its subtree",
                paint.bold("weight:"),
                paint.yellow(&format!("{exclusive} exclusive")),
                if tree == 1 { "" } else { "s" }
            );
        }

        if dependents.is_empty() {
            let _ = writeln!(out, "  {} none", paint.bold("dependents (0):"));
        } else {
            let names: Vec<String> = dependents
                .iter()
                .map(|&dep| {
                    let pkg = &inventory.packages[dep];
                    format!("{} {}", pkg.name, pkg.version)
                })
                .collect();
            let _ = writeln!(
                out,
                "  {} {}",
                paint.bold(&format!("dependents ({}):", dependents.len())),
                names.join(", ")
            );
        }

        if !package.root {
            let paths = inventory.paths_to(index, MAX_PATHS);
            if paths.is_empty() {
                let _ = writeln!(
                    out,
                    "  {} not reachable from any root package",
                    paint.bold("paths from root (0):")
                );
            } else {
                let _ = writeln!(
                    out,
                    "  {}",
                    paint.bold(&format!("paths from root ({}):", paths.len()))
                );
                let arrow = paint.dim(" -> ");
                for path in paths {
                    let chain: Vec<String> = path
                        .iter()
                        .map(|&step| {
                            let pkg = &inventory.packages[step];
                            let label = format!("{} {}", pkg.name, pkg.version);
                            if step == index {
                                paint.bold(&label)
                            } else {
                                label
                            }
                        })
                        .collect();
                    let note = path.get(1).map_or("", |&first| {
                        kind_note(direct_kinds, &inventory.packages[first].name)
                    });
                    let _ = writeln!(out, "    {}{}", chain.join(&arrow), paint.dim(note));
                }
            }
        }
    }
    out
}

fn render_json(inventory: &Inventory, matches: &[usize], query: &str) -> String {
    let items: Vec<serde_json::Value> = matches
        .iter()
        .map(|&index| {
            let package = &inventory.packages[index];
            let (exclusive, tree) = if package.root {
                (0, 0)
            } else {
                inventory.package_weight(index)
            };
            let dependents: Vec<serde_json::Value> = inventory
                .dependents_of(index)
                .into_iter()
                .map(|dep| {
                    let pkg = &inventory.packages[dep];
                    json!({ "name": pkg.name, "version": pkg.version })
                })
                .collect();
            let paths: Vec<Vec<serde_json::Value>> = inventory
                .paths_to(index, MAX_PATHS)
                .into_iter()
                .map(|path| {
                    path.into_iter()
                        .map(|step| {
                            let pkg = &inventory.packages[step];
                            json!({ "name": pkg.name, "version": pkg.version })
                        })
                        .collect()
                })
                .collect();
            json!({
                "name": package.name,
                "version": package.version,
                "scope": scope(package),
                "direct": package.direct,
                "source": package.source,
                "exclusive": exclusive,
                "tree": tree,
                "dependents": dependents,
                "paths": paths,
            })
        })
        .collect();
    let payload = json!({
        "query": query,
        "matches": items,
    });
    let mut text = serde_json::to_string_pretty(&payload).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{WhyOptions, parse_why_options};
    use crate::scan::ColorChoice;

    fn parse(arguments: &[&str]) -> Result<WhyOptions, String> {
        parse_why_options(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    #[test]
    fn parses_crate_path_and_format() {
        assert_eq!(
            parse(&["serde_json"]).expect("valid"),
            WhyOptions {
                crate_spec: "serde_json".to_owned(),
                path: PathBuf::from("."),
                json: false,
                color: ColorChoice::Auto,
            }
        );
        assert_eq!(
            parse(&[
                "--format=json",
                "--color=always",
                "bitflags@1.3.2",
                "tests/fixtures/multi-version"
            ])
            .expect("valid"),
            WhyOptions {
                crate_spec: "bitflags@1.3.2".to_owned(),
                path: PathBuf::from("tests/fixtures/multi-version"),
                json: true,
                color: ColorChoice::Always,
            }
        );
        assert!(parse(&[]).is_err());
        assert!(parse(&["a", "b", "c"]).is_err());
        assert!(parse(&["serde", "--format", "sarif"]).is_err());
    }
}
