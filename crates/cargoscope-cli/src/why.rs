//! `cargoscope why`: explain why a crate is in `Cargo.lock`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_advisory::AdvisoryDatabase;
use cargoscope_advisory::crates_io::RegistryCache;
use cargoscope_core::{AdvisoryFinding, AdvisoryKind, DependencyKind, Inventory, Package};
use cargoscope_report::Paint;
use serde_json::json;

use crate::execution_error;
use crate::scan::{ColorChoice, check_advisories};

/// Paths listed in JSON without `--all-paths`.
const MAX_PATHS: usize = 25;
/// Paths listed with `--all-paths`.
const ALL_PATHS: usize = 500;
/// Direct dependencies shown, each with its shortest path.
const MAX_ROUTES: usize = 8;

#[derive(Debug, PartialEq, Eq)]
struct WhyOptions {
    crate_spec: String,
    path: PathBuf,
    json: bool,
    color: ColorChoice,
    all_paths: bool,
}

fn parse_why_options(arguments: impl Iterator<Item = String>) -> Result<WhyOptions, String> {
    let mut crate_spec: Option<String> = None;
    let mut path: Option<PathBuf> = None;
    let mut json = false;
    let mut color = ColorChoice::Auto;
    let mut all_paths = false;
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
            "--all-paths" => all_paths = true,
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
        all_paths,
    })
}

/// `cargoscope why CRATE[@VERSION] [PATH] [--all-paths] [--format text|json] [--color WHEN]`.
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

    let advisories = load_advisories(root, &inventory);
    let yanked: Vec<bool> = cargoscope_advisory::cache_dir()
        .map(|dir| {
            RegistryCache::open(&dir)
                .info(&inventory)
                .into_iter()
                .map(|info| info.yanked == Some(true))
                .collect()
        })
        .unwrap_or_default();
    let direct_kinds = cargoscope_cargo::direct_dependency_kinds(root).unwrap_or_default();
    let rendered = if options.json {
        render_json(
            &inventory,
            &matches,
            &options.crate_spec,
            advisories.as_deref(),
            &yanked,
            options.all_paths,
        )
    } else {
        render_text(
            &inventory,
            &matches,
            &direct_kinds,
            advisories.as_deref(),
            &yanked,
            options.all_paths,
            Paint::new(options.color.enabled(false)),
        )
    };
    print!("{rendered}");
    ExitCode::SUCCESS
}

/// Advisories of the resolved packages, with the project's ignores applied;
/// `None` when the advisory database was never downloaded.
fn load_advisories(root: &Path, inventory: &Inventory) -> Option<Vec<AdvisoryFinding>> {
    cargoscope_advisory::cache_dir()
        .and_then(|dir| AdvisoryDatabase::open(&dir))
        .ok()?;
    let mut warnings = Vec::new();
    let (findings, _) = check_advisories(root, inventory, false, &mut warnings).ok()?;
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    Some(findings)
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

fn label(finding: &AdvisoryFinding) -> String {
    match (&finding.kind, finding.severity) {
        (AdvisoryKind::Informational(kind), _) => kind.clone(),
        (AdvisoryKind::Vulnerability, Some(severity)) => severity.as_str().to_owned(),
        (AdvisoryKind::Vulnerability, None) => "unknown severity".to_owned(),
    }
}

/// How the vulnerabilities of a package get fixed.
enum Fix {
    /// No released version fixes all of them.
    None,
    /// A version inside the SemVer range already asked for: `cargo update`.
    Update(semver::Version),
    /// A breaking version the workspace itself asks for: edit Cargo.toml.
    Requirement(semver::Version),
    /// A breaking version other crates have to accept first.
    Blocked(semver::Version, Vec<usize>),
}

fn fix_for(inventory: &Inventory, index: usize, findings: &[&AdvisoryFinding]) -> Option<Fix> {
    let vulnerabilities: Vec<&AdvisoryFinding> = findings
        .iter()
        .copied()
        .filter(|finding| finding.kind == AdvisoryKind::Vulnerability && finding.ignored.is_none())
        .collect();
    if vulnerabilities.is_empty() {
        return None;
    }
    let package = &inventory.packages[index];
    let (fix, _) = cargoscope_report::crate_fix(&vulnerabilities, &package.version);
    let Some(version) = fix else {
        return Some(Fix::None);
    };
    let compatible = semver::Version::parse(&package.version)
        .is_ok_and(|current| cargoscope_core::is_semver_compatible(&current, &version));
    if compatible {
        return Some(Fix::Update(version));
    }
    let blockers = cargoscope_report::fix_blockers(inventory, index, &version);
    Some(if blockers.is_empty() {
        Fix::Requirement(version)
    } else {
        Fix::Blocked(version, blockers)
    })
}

fn label_of(inventory: &Inventory, index: usize) -> String {
    let package = &inventory.packages[index];
    format!("{} {}", package.name, package.version)
}

fn names(inventory: &Inventory, indices: &[usize]) -> String {
    indices
        .iter()
        .map(|&index| inventory.packages[index].name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_text(
    inventory: &Inventory,
    matches: &[usize],
    direct_kinds: &BTreeMap<String, BTreeSet<DependencyKind>>,
    advisories: Option<&[AdvisoryFinding]>,
    yanked: &[bool],
    all_paths: bool,
    paint: Paint,
) -> String {
    let members = inventory
        .packages
        .iter()
        .filter(|package| package.root)
        .count();
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

        if yanked.get(index).copied().unwrap_or(false) {
            let _ = writeln!(
                out,
                "  {} {}",
                paint.red_bold("yanked:"),
                paint.dim(&format!(
                    "this version was withdrawn from crates.io; cargo update -p {}@{} should move off it",
                    package.name, package.version
                ))
            );
        }
        render_advisories(&mut out, inventory, index, advisories, paint);

        let dependents = inventory.dependents_of(index);
        if dependents.is_empty() {
            let _ = writeln!(out, "  {} none", paint.bold("dependents (0):"));
        } else {
            let labels: Vec<String> = dependents
                .iter()
                .map(|&dep| label_of(inventory, dep))
                .collect();
            let _ = writeln!(
                out,
                "  {} {}",
                paint.bold(&format!("dependents ({}):", dependents.len())),
                labels.join(", ")
            );
        }

        if package.root {
            continue;
        }
        let reaching = inventory.members_reaching(index);
        if members > 1 && !reaching.is_empty() {
            let _ = writeln!(
                out,
                "  {} {}",
                paint.bold("used by members:"),
                names(inventory, &reaching)
            );
        }
        render_paths(&mut out, inventory, index, direct_kinds, all_paths, paint);
    }
    out
}

fn render_advisories(
    out: &mut String,
    inventory: &Inventory,
    index: usize,
    advisories: Option<&[AdvisoryFinding]>,
    paint: Paint,
) {
    let Some(advisories) = advisories else {
        let _ = writeln!(
            out,
            "  {} {}",
            paint.bold("advisories:"),
            paint.dim("not checked (run cargoscope update)")
        );
        return;
    };
    let findings: Vec<&AdvisoryFinding> = advisories
        .iter()
        .filter(|finding| finding.package == index)
        .collect();
    if findings.is_empty() {
        let _ = writeln!(out, "  {} none known", paint.bold("advisories:"));
        return;
    }
    let listed: Vec<String> = findings
        .iter()
        .map(|finding| {
            let name = label(finding).to_uppercase();
            if finding.ignored.is_some() {
                paint.dim(&format!("{name} {} (ignored)", finding.id))
            } else if finding.kind == AdvisoryKind::Vulnerability {
                format!("{} {}", paint.red_bold(&name), finding.id)
            } else {
                format!("{} {}", paint.yellow(&name), finding.id)
            }
        })
        .collect();
    let _ = writeln!(
        out,
        "  {} {}",
        paint.bold(&format!("advisories ({}):", findings.len())),
        listed.join(", ")
    );
    let package = &inventory.packages[index];
    let line = match fix_for(inventory, index, &findings) {
        None => return,
        Some(Fix::None) => paint.yellow("no released version fixes every vulnerability yet"),
        Some(Fix::Update(version)) => format!(
            "{}{}",
            paint.green(&version.to_string()),
            paint.dim(&format!(
                ", within the range already required: cargo update -p {}@{}",
                package.name, package.version
            ))
        ),
        Some(Fix::Requirement(version)) => format!(
            "{}{}",
            paint.green(&version.to_string()),
            paint.dim(", a breaking update: raise the requirement in Cargo.toml")
        ),
        Some(Fix::Blocked(version, blockers)) => {
            let labels: Vec<String> = blockers
                .iter()
                .map(|&blocker| label_of(inventory, blocker))
                .collect();
            let (verb, who) = if blockers.len() == 1 {
                (
                    "does",
                    format!("a new {} release has", inventory.packages[blockers[0]].name),
                )
            } else {
                ("do", "their new releases have".to_owned())
            };
            format!(
                "{}{}",
                paint.yellow(&version.to_string()),
                paint.dim(&format!(
                    ", which {} {verb} not accept yet: {who} to allow it first",
                    labels.join(", ")
                ))
            )
        }
    };
    let _ = writeln!(out, "  {} {line}", paint.bold("fix:"));
}

fn render_paths(
    out: &mut String,
    inventory: &Inventory,
    index: usize,
    direct_kinds: &BTreeMap<String, BTreeSet<DependencyKind>>,
    all_paths: bool,
    paint: Paint,
) {
    let routes = inventory.routes_to(index);
    let total = routes
        .iter()
        .fold(0u64, |sum, route| sum.saturating_add(route.count));
    if routes.is_empty() {
        let _ = writeln!(
            out,
            "  {} not reachable from any root package",
            paint.bold("paths from root (0):")
        );
        return;
    }
    let arrow = paint.dim(" -> ");
    let chain = |path: &[usize]| -> String {
        let steps: Vec<String> = path
            .iter()
            .map(|&step| {
                let label = label_of(inventory, step);
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
        format!("{}{}", steps.join(&arrow), paint.dim(note))
    };

    if all_paths {
        let paths = inventory.member_paths_to(index, ALL_PATHS);
        let _ = writeln!(
            out,
            "  {}",
            paint.bold(&format!("paths from root ({total}):"))
        );
        for path in &paths {
            let _ = writeln!(out, "    {}", chain(path));
        }
        let shown = paths.len() as u64;
        if total > shown {
            let _ = writeln!(
                out,
                "    {}",
                paint.dim(&format!("+ {} more not listed", total - shown))
            );
        }
        return;
    }

    let heading = if routes.len() == 1 {
        format!("paths from root ({total}):")
    } else {
        format!(
            "paths from root ({total}, through {} direct dependencies, shortest of each):",
            routes.len()
        )
    };
    let _ = writeln!(out, "  {}", paint.bold(&heading));
    for route in routes.iter().take(MAX_ROUTES) {
        let mut extra = String::new();
        if route.count > 1 {
            extra.push_str(&format!("  +{} more", route.count - 1));
        }
        if route.members.len() > 1 {
            extra.push_str(&format!(
                "  also from {}",
                names(inventory, &route.members[1..])
            ));
        }
        let _ = writeln!(out, "    {}{}", chain(&route.path), paint.dim(&extra));
    }
    if routes.len() > MAX_ROUTES {
        let _ = writeln!(
            out,
            "    {}",
            paint.dim(&format!(
                "+ {} more direct dependencies",
                routes.len() - MAX_ROUTES
            ))
        );
    }
    if total > routes.len().min(MAX_ROUTES) as u64 {
        let _ = writeln!(out, "  {}", paint.dim("--all-paths lists every path"));
    }
}

fn step_json(inventory: &Inventory, index: usize) -> serde_json::Value {
    let package = &inventory.packages[index];
    json!({ "name": package.name, "version": package.version })
}

fn render_json(
    inventory: &Inventory,
    matches: &[usize],
    query: &str,
    advisories: Option<&[AdvisoryFinding]>,
    yanked: &[bool],
    all_paths: bool,
) -> String {
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
                .map(|dep| step_json(inventory, dep))
                .collect();
            let path_json = |path: &[usize]| -> Vec<serde_json::Value> {
                path.iter().map(|&step| step_json(inventory, step)).collect()
            };
            let limit = if all_paths { ALL_PATHS } else { MAX_PATHS };
            let paths: Vec<Vec<serde_json::Value>> = inventory
                .member_paths_to(index, limit)
                .iter()
                .map(|path| path_json(path))
                .collect();
            let routes = inventory.routes_to(index);
            let path_count = routes
                .iter()
                .fold(0u64, |sum, route| sum.saturating_add(route.count));
            let routes: Vec<serde_json::Value> = routes
                .iter()
                .map(|route| {
                    json!({
                        "via": step_json(inventory, route.path[1]),
                        "members": route.members.iter().map(|&m| inventory.packages[m].name.clone()).collect::<Vec<_>>(),
                        "shortest": path_json(&route.path),
                        "paths": route.count,
                    })
                })
                .collect();
            let members: Vec<&str> = inventory
                .members_reaching(index)
                .into_iter()
                .map(|member| inventory.packages[member].name.as_str())
                .collect();
            let (advisories_json, fix_json) = advisories.map_or(
                (serde_json::Value::Null, serde_json::Value::Null),
                |advisories| {
                    let findings: Vec<&AdvisoryFinding> = advisories
                        .iter()
                        .filter(|finding| finding.package == index)
                        .collect();
                    let listed: Vec<serde_json::Value> = findings
                        .iter()
                        .map(|finding| {
                            json!({
                                "id": finding.id,
                                "kind": match &finding.kind {
                                    AdvisoryKind::Vulnerability => "vulnerability",
                                    AdvisoryKind::Informational(kind) => kind.as_str(),
                                },
                                "severity": finding.severity.map(cargoscope_core::Severity::as_str),
                                "title": finding.title,
                                "ignored": finding.ignored,
                            })
                        })
                        .collect();
                    let fix = match fix_for(inventory, index, &findings) {
                        None => serde_json::Value::Null,
                        Some(Fix::None) => json!({ "version": null }),
                        Some(Fix::Update(version)) => {
                            json!({ "version": version.to_string(), "action": "cargo-update" })
                        }
                        Some(Fix::Requirement(version)) => {
                            json!({ "version": version.to_string(), "action": "raise-requirement" })
                        }
                        Some(Fix::Blocked(version, blockers)) => json!({
                            "version": version.to_string(),
                            "action": "blocked",
                            "blocked_by": blockers.iter().map(|&b| step_json(inventory, b)).collect::<Vec<_>>(),
                        }),
                    };
                    (serde_json::Value::Array(listed), fix)
                },
            );
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
                "path_count": path_count,
                "routes": routes,
                "members": members,
                "yanked": yanked.get(index).copied().unwrap_or(false),
                "advisories": advisories_json,
                "fix": fix_json,
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
                all_paths: false,
            }
        );
        assert_eq!(
            parse(&[
                "--format=json",
                "--color=always",
                "bitflags@1.3.2",
                "--all-paths",
                "tests/fixtures/multi-version"
            ])
            .expect("valid"),
            WhyOptions {
                crate_spec: "bitflags@1.3.2".to_owned(),
                path: PathBuf::from("tests/fixtures/multi-version"),
                json: true,
                color: ColorChoice::Always,
                all_paths: true,
            }
        );
        assert!(parse(&[]).is_err());
        assert!(parse(&["a", "b", "c"]).is_err());
        assert!(parse(&["serde", "--format", "sarif"]).is_err());
    }
}
