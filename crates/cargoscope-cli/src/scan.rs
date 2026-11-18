//! `cargoscope scan`: the report, built in steps (advisories, unused
//! dependencies, policy, registry data), rendered, then turned into an exit
//! code.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_advisory::AdvisoryDatabase;
use cargoscope_advisory::crates_io::{self, RegistryCache};
use cargoscope_core::policy::{
    ActivePackages, GraphContext, LintLevel, Policy, Violation, ViolationLevel,
};
use cargoscope_core::{
    AdvisoryFinding, AdvisoryRelevance, Checks, DependencyKind, Inventory, PackageInfo, Report,
};
use cargoscope_report::sarif::SarifLocations;

use crate::{FailOn, execution_error, find_unused_dependencies, parse_fail_on, read_report};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    CycloneDx,
    Html,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ScanOptions {
    pub path: PathBuf,
    pub format: OutputFormat,
    pub output: Option<PathBuf>,
    pub fail_on: FailOn,
    pub show_uncertain: bool,
    pub verbose: bool,
    pub checks: Checks,
    pub baseline: Option<PathBuf>,
    pub precise: bool,
    pub color: ColorChoice,
    pub update: bool,
    pub include_maintenance: bool,
}

/// When the text report uses colors (`--color`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            other => Err(format!(
                "Unknown color choice: {other}. Use auto, always or never."
            )),
        }
    }

    /// Colors for `auto` only on a terminal, without `NO_COLOR`, and not into a file.
    pub(crate) fn enabled(self, writes_to_file: bool) -> bool {
        use std::io::IsTerminal;
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => {
                !writes_to_file
                    && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
                    && std::io::stdout().is_terminal()
            }
        }
    }
}

pub fn parse_scan_options(
    mut arguments: impl Iterator<Item = String>,
) -> Result<ScanOptions, String> {
    let mut options = ScanOptions {
        path: PathBuf::from("."),
        format: OutputFormat::Text,
        output: None,
        fail_on: FailOn::AnyVulnerability,
        show_uncertain: false,
        verbose: false,
        checks: Checks::ALL,
        baseline: None,
        precise: false,
        color: ColorChoice::Auto,
        update: false,
        include_maintenance: true,
    };
    let mut path_given = false;

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
            "--format" => options.format = parse_output_format(&value()?)?,
            "--output" | "-o" => options.output = Some(PathBuf::from(value()?)),
            "--baseline" => options.baseline = Some(PathBuf::from(value()?)),
            "--checks" => {
                options.checks = Checks::parse(&value()?).map_err(|unknown| {
                    format!(
                        "Unknown check: {unknown}. Use {}.",
                        Checks::NAMES.join(", ")
                    )
                })?;
            }
            "--color" => options.color = ColorChoice::parse(&value()?)?,
            "--fail-on" => options.fail_on = parse_fail_on(&value()?)?,
            "--show-uncertain" if inline_value.is_none() => options.show_uncertain = true,
            "--verbose" | "-v" if inline_value.is_none() => options.verbose = true,
            "--precise" if inline_value.is_none() => options.precise = true,
            "--update" if inline_value.is_none() => options.update = true,
            "--no-maintenance" | "--fast" if inline_value.is_none() => {
                options.include_maintenance = false;
            }
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            _ if path_given => return Err("Only one scan path may be provided.".to_owned()),
            _ => {
                options.path = PathBuf::from(argument);
                path_given = true;
            }
        }
    }
    Ok(options)
}

fn parse_output_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "sarif" => Ok(OutputFormat::Sarif),
        "cyclonedx" => Ok(OutputFormat::CycloneDx),
        "html" => Ok(OutputFormat::Html),
        _ => Err(format!(
            "Unsupported output format: {value}. Use text, json, sarif, cyclonedx or html."
        )),
    }
}

/// Marks findings ignored by `[advisories] ignore`, matching the advisory ID
/// or one of its aliases. Returns warnings for expired and unused entries.
pub fn apply_advisory_ignores(
    findings: &mut [AdvisoryFinding],
    ignores: &[cargoscope_cargo::config::AdvisoryIgnore],
    today: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for ignore in ignores {
        let matches = |finding: &AdvisoryFinding| {
            finding.id.eq_ignore_ascii_case(&ignore.id)
                || finding
                    .aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(&ignore.id))
        };
        if !findings.iter().any(&matches) {
            warnings.push(format!(
                "{} ignores {}, which matches no advisory of this project: remove it if it is no longer needed",
                ignore.source, ignore.id
            ));
            continue;
        }
        if let Some(until) = ignore.until.as_deref().filter(|until| *until < today) {
            warnings.push(format!(
                "the ignore of {} expired on {until}: the advisory counts again",
                ignore.id
            ));
            continue;
        }
        let reason = match &ignore.until {
            Some(until) => format!("{} (until {until})", ignore.reason),
            None => ignore.reason.clone(),
        };
        for finding in findings.iter_mut().filter(|finding| matches(finding)) {
            finding.ignored = Some(reason.clone());
        }
    }
    warnings
}

/// `cargoscope scan`. Every step returns the exit code to stop with on error.
pub fn scan(options: &ScanOptions) -> ExitCode {
    match run_scan(options) {
        Ok(code) | Err(code) => code,
    }
}

fn run_scan(options: &ScanOptions) -> Result<ExitCode, ExitCode> {
    let root = options.path.as_path();
    let inventory = cargoscope_cargo::scan_cargo_project(root)
        .map_err(|error| execution_error(root, &error))?;
    if options.update {
        crate::update_for_scan(root, &inventory, options.include_maintenance)?;
    }
    let checks = options.checks;
    let mut warnings = Vec::new();

    let (mut advisories, advisory_db_date) = if checks.advisories {
        check_advisories(root, &inventory, &mut warnings)?
    } else {
        (Vec::new(), None)
    };
    let unused = if checks.unused {
        let (unused, unused_warnings) =
            find_unused_dependencies(root, &inventory, options.precise)?;
        warnings.extend(unused_warnings);
        unused
    } else {
        Vec::new()
    };
    if checks.policy || checks.advisories {
        warnings.extend(cargoscope_cargo::config::deny_notes(root));
    }
    let policy = if checks.policy {
        load_policy(root)?
    } else {
        None
    };
    let needs_licenses = policy.as_ref().is_some_and(|policy| policy.check_licenses);
    let (mut package_info, registry_date) = if checks.licenses || checks.versions || needs_licenses
    {
        registry_data(root, &inventory, &mut warnings)
    } else {
        (vec![PackageInfo::default(); inventory.packages.len()], None)
    };
    // Clarified licenses (verified against on-disk license-files hashes when
    // specified) replace the registry's everywhere in the report.
    let (violations, policy_active, policy_non_dev, policy_targets) = match &policy {
        Some(policy) => {
            let (verified_clarifications, clarify_warnings) =
                cargoscope_cargo::crate_sources::verify_clarifications(
                    root,
                    &inventory,
                    &policy.license_clarifications,
                );
            warnings.extend(clarify_warnings);
            policy.clarify_verified(&inventory, &mut package_info, &verified_clarifications);
            // Licenses of the project's own packages, git and other registries,
            // and of crates without a usable `license` field (from LICENSE files).
            let gathered = cargoscope_cargo::licenses::gather(
                root,
                &inventory,
                policy,
                &package_info,
                &verified_clarifications,
            );
            for ((info, facts), license) in package_info
                .iter_mut()
                .zip(&gathered.facts)
                .zip(gathered.licenses)
            {
                if facts.known {
                    info.license = license;
                }
            }
            warnings.extend(gathered.warnings);
            let checked = check_policy(
                root,
                policy,
                &inventory,
                &package_info,
                registry_date.as_deref(),
                &verified_clarifications,
                &gathered.facts,
                &mut warnings,
            )?;
            (
                Some(checked.violations),
                checked.active,
                checked.non_dev_active,
                policy.targets.clone(),
            )
        }
        None => (None, None, None, Vec::new()),
    };
    keep_checked_info(&mut package_info, checks);

    // Only labels in the report: a failure leaves the dependencies unlabelled.
    let direct_kinds = cargoscope_cargo::direct_dependency_kinds(root).unwrap_or_default();
    if !advisories.is_empty() {
        let ident_tokens = if advisories
            .iter()
            .any(|finding| !finding.affected_functions.is_empty())
        {
            cargoscope_cargo::project_ident_tokens(root)
        } else {
            BTreeSet::new()
        };
        evaluate_advisory_relevance(
            &inventory,
            &direct_kinds,
            &policy_targets,
            policy_active.as_ref(),
            policy_non_dev.as_ref(),
            &ident_tokens,
            &mut advisories,
        );
    }
    let report = Report {
        direct_kinds,
        checks,
        package_info,
        registry_date,
        inventory,
        advisories,
        unused,
        policy: violations,
        unused_precise: checks.unused && options.precise,
        advisory_db_date,
        warnings,
    };
    write_report(options, &report)?;
    exit_code(options, &report)
}

/// Matching advisories, with the `[advisories] ignore` entries applied, and
/// the date of the database.
pub(crate) fn check_advisories(
    root: &Path,
    inventory: &Inventory,
    warnings: &mut Vec<String>,
) -> Result<(Vec<AdvisoryFinding>, Option<String>), ExitCode> {
    let database = cargoscope_advisory::cache_dir()
        .and_then(|dir| AdvisoryDatabase::open(&dir))
        .map_err(|error| execution_error(root, &error))?;
    let check = database.check(inventory);
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
    let mut findings = check.findings;
    let ignores = cargoscope_cargo::config::load_advisory_ignores(root).map_err(|error| {
        eprintln!("CargoScope could not read the advisory ignores: {error}");
        ExitCode::from(2)
    })?;
    warnings.extend(apply_advisory_ignores(
        &mut findings,
        &ignores,
        &cargoscope_advisory::utc_today(),
    ));
    Ok((findings, database.fetched_on))
}

fn load_policy(root: &Path) -> Result<Option<Policy>, ExitCode> {
    cargoscope_cargo::config::load_policy(root).map_err(|error| {
        eprintln!("CargoScope could not read the policy: {error}");
        ExitCode::from(2)
    })
}

/// crates.io data (licenses, latest versions, yanked status) of every package
/// and its download date, with warnings when it is missing or incomplete.
pub(crate) fn registry_data(
    root: &Path,
    inventory: &Inventory,
    warnings: &mut Vec<String>,
) -> (Vec<PackageInfo>, Option<String>) {
    let (mut package_info, mut registry_date) =
        (vec![PackageInfo::default(); inventory.packages.len()], None);
    if let Ok(dir) = cargoscope_advisory::cache_dir() {
        let registry = RegistryCache::open(&dir);
        package_info = registry.info(inventory);
        registry_date = registry.fetched_on;
    }
    if registry_date.is_none() {
        warnings.push(format!(
            "no crates.io data: licenses and latest versions are unknown; run `cargoscope update {}`",
            root.display()
        ));
    } else {
        let missing = package_info
            .iter()
            .zip(&inventory.packages)
            .filter(|(info, package)| {
                info.latest_version.is_none() && crates_io::is_crates_io(package.source.as_deref())
            })
            .count();
        if missing > 0 {
            warnings.push(format!(
                "{missing} crates.io package(s) have no cached data (added since the last update?); run `cargoscope update {}`",
                root.display()
            ));
        }
    }
    (package_info, registry_date)
}

struct PolicyOutcome {
    violations: Vec<Violation>,
    active: Option<ActivePackages>,
    non_dev_active: Option<ActivePackages>,
}

#[allow(clippy::too_many_arguments)] // each argument is a separate input of the policy
fn check_policy(
    root: &Path,
    policy: &Policy,
    inventory: &Inventory,
    package_info: &[PackageInfo],
    registry_date: Option<&str>,
    verified_clarifications: &[Option<usize>],
    license_facts: &[cargoscope_core::policy::LicenseFacts],
    warnings: &mut Vec<String>,
) -> Result<PolicyOutcome, ExitCode> {
    if policy.check_licenses && registry_date.is_none() {
        warnings.push("license rules of the policy were skipped: no crates.io data".to_owned());
    }
    warnings.extend(policy.unused_license_entries(inventory));
    // `[graph]` and `[bans] features`: limit rules or collect enabled features.
    let graph_set = !policy.targets.is_empty()
        || policy.features.is_some()
        || policy.exclude_dev
        || policy.exclude_unpublished
        || policy.root_package_only;
    let checks_duplicates = policy.multiple_versions != LintLevel::Allow
        || !policy.deny_multiple_versions_of.is_empty();
    let needs_non_dev = ((policy.duplicates_exclude_dev && checks_duplicates)
        || (policy.licenses_exclude_dev && policy.check_licenses))
        && !policy.exclude_dev;
    let needs_features = !policy.feature_bans.is_empty()
        || policy.build_inspection.as_ref().is_some_and(|inspection| {
            inspection
                .bypass
                .iter()
                .any(|bypass| !bypass.required_features.is_empty())
        });
    let failed = |error: String| {
        eprintln!(
            "CargoScope could not limit the policy to its [graph]: {error}. Check the target and feature names and run `cargo fetch` first, or remove them from [graph]."
        );
        ExitCode::from(2)
    };
    let excluded = if policy.exclude_unpublished {
        cargoscope_cargo::targets::unpublished_members(root).map_err(failed)?
    } else {
        Vec::new()
    };
    let graph = |exclude_dev: bool| {
        cargoscope_cargo::targets::active_packages(
            root,
            &policy.targets,
            policy.features.as_ref(),
            exclude_dev,
            &excluded,
            policy.root_package_only,
        )
    };
    let (active, enabled_features) = if graph_set || needs_features {
        let (packages, features) = graph(policy.exclude_dev).map_err(failed)?;
        (
            graph_set.then_some(packages),
            needs_features.then_some(features),
        )
    } else {
        (None, None)
    };
    // Duplicates and licenses may leave out dev-dependencies (as cargo-deny does).
    let non_dev_active = if needs_non_dev {
        Some(
            cargoscope_cargo::targets::non_dev_packages(
                root,
                &policy.targets,
                policy.features.as_ref(),
                &excluded,
                policy.root_package_only,
            )
            .map_err(failed)?,
        )
    } else {
        active.clone()
    };
    let build_scripts = if policy.allow_build_scripts.is_some() {
        let (scripts, build_warnings) = cargoscope_cargo::crate_sources::detect_build_scripts(
            root,
            inventory,
            active.as_ref(),
            policy.build_include_workspace,
        );
        warnings.extend(build_warnings);
        Some(scripts)
    } else {
        None
    };
    let context = GraphContext {
        active: active.as_ref(),
        non_dev_active: non_dev_active.as_ref(),
        enabled_features: enabled_features.as_ref(),
        build_scripts: build_scripts.as_ref(),
        verified_clarifications: Some(verified_clarifications),
        license_facts: Some(license_facts),
    };
    let mut violations =
        policy.check_with_context(inventory, package_info, registry_date.is_some(), &context);
    // Executables and scripts inside the crates that run code at build time.
    let inspected = cargoscope_cargo::build_inspect::inspect(
        root,
        inventory,
        policy,
        active.as_ref(),
        enabled_features.as_ref(),
    );
    violations.extend(inspected.violations);
    warnings.extend(inspected.warnings);
    Ok(PolicyOutcome {
        violations,
        active,
        non_dev_active,
    })
}

fn target_matches_os(triple: &str, os: &str) -> bool {
    if os.eq_ignore_ascii_case("macos") {
        return triple.contains("-apple-darwin")
            || triple.split('-').any(|part| part.eq_ignore_ascii_case(os));
    }
    triple.split('-').any(|part| {
        part.eq_ignore_ascii_case(os)
            || (os.eq_ignore_ascii_case("wasi") && part.to_ascii_lowercase().starts_with("wasi"))
    })
}

fn target_matches_arch(triple: &str, arch: &str) -> bool {
    triple
        .split('-')
        .next()
        .is_some_and(|head| head.eq_ignore_ascii_case(arch))
}

fn format_platforms(os: &[String], arch: &[String]) -> String {
    match (os.is_empty(), arch.is_empty()) {
        (false, true) => os.join(", "),
        (true, false) => arch.join(", "),
        (false, false) => format!("{} ({})", os.join(", "), arch.join(", ")),
        (true, true) => String::new(),
    }
}

fn short_function_name(path: &str) -> &str {
    path.trim()
        .trim_end_matches("()")
        .rsplit("::")
        .next()
        .unwrap_or(path)
}

fn format_functions(functions: &[String]) -> String {
    let mut shown: Vec<String> = functions
        .iter()
        .take(2)
        .map(|path| format!("`{}()`", short_function_name(path)))
        .collect();
    if functions.len() > 2 {
        shown.push(format!("+{} more", functions.len() - 2));
    }
    shown.join(", ")
}

/// Evaluates how likely each advisory is to affect the scanned project's shipped
/// code (not built, dev-only, target platform mismatch, uncalled functions).
pub(crate) fn evaluate_advisory_relevance(
    inventory: &Inventory,
    direct_kinds: &BTreeMap<String, BTreeSet<DependencyKind>>,
    targets: &[String],
    active: Option<&ActivePackages>,
    non_dev_active: Option<&ActivePackages>,
    ident_tokens: &BTreeSet<String>,
    findings: &mut [AdvisoryFinding],
) {
    let non_dev_lockfile = inventory.non_dev_reachable(direct_kinds);
    for finding in findings {
        let Some(pkg) = inventory.packages.get(finding.package) else {
            continue;
        };
        let pkg_key = (pkg.name.clone(), pkg.version.clone());

        if active.is_some_and(|set| !set.contains(&pkg_key)) {
            finding.relevance = AdvisoryRelevance::Unlikely;
            finding.relevance_reason = Some(if targets.is_empty() {
                format!("{} is not built by workspace targets or features", pkg.name)
            } else {
                format!(
                    "{} is not built by the configured [graph] targets or features",
                    pkg.name
                )
            });
            continue;
        }

        if non_dev_active.is_some_and(|set| !set.contains(&pkg_key))
            || !non_dev_lockfile
                .get(finding.package)
                .copied()
                .unwrap_or(true)
        {
            finding.relevance = AdvisoryRelevance::Unlikely;
            finding.relevance_reason =
                Some("only used by dev-dependencies (tests or benchmarks)".to_owned());
            continue;
        }

        if !finding.affected_os.is_empty() || !finding.affected_arch.is_empty() {
            let platform_list = format_platforms(&finding.affected_os, &finding.affected_arch);
            if !targets.is_empty() {
                let matches_any = targets.iter().any(|triple| {
                    (finding.affected_os.is_empty()
                        || finding
                            .affected_os
                            .iter()
                            .any(|os| target_matches_os(triple, os)))
                        && (finding.affected_arch.is_empty()
                            || finding
                                .affected_arch
                                .iter()
                                .any(|arch| target_matches_arch(triple, arch)))
                });
                if !matches_any {
                    finding.relevance = AdvisoryRelevance::Unlikely;
                    finding.relevance_reason = Some(format!(
                        "only affects {platform_list}, not configured targets ({})",
                        targets.join(", ")
                    ));
                    continue;
                }
            } else {
                finding.relevance = AdvisoryRelevance::Possibly;
                finding.relevance_reason = Some(format!("only affects {platform_list}"));
                continue;
            }
        }

        if !finding.affected_functions.is_empty() && !ident_tokens.is_empty() {
            let any_called = finding
                .affected_functions
                .iter()
                .map(|path| short_function_name(path))
                .any(|name| ident_tokens.contains(name));
            if !any_called {
                let used_by_other_dep = inventory
                    .dependents_of(finding.package)
                    .into_iter()
                    .any(|idx| !inventory.packages[idx].root);
                let list = format_functions(&finding.affected_functions);
                if pkg.direct && !used_by_other_dep {
                    finding.relevance = AdvisoryRelevance::Unlikely;
                    finding.relevance_reason =
                        Some(format!("{list} is never called in project sources"));
                } else {
                    finding.relevance = AdvisoryRelevance::Possibly;
                    finding.relevance_reason = Some(format!(
                        "{list} is not called directly in project sources (used transitively)"
                    ));
                }
            }
        }
    }
}

/// Clears the registry data of checks that did not run, so the report only
/// shows what was asked for.
fn keep_checked_info(package_info: &mut [PackageInfo], checks: Checks) {
    for info in package_info {
        if !checks.licenses {
            info.license = None;
        }
        if !checks.versions {
            *info = PackageInfo {
                license: info.license.take(),
                ..Default::default()
            };
        }
    }
}

/// Renders the report in the chosen format, to `--output` or standard output.
fn write_report(options: &ScanOptions, report: &Report) -> Result<(), ExitCode> {
    let root = options.path.as_path();
    let rendered = match options.format {
        OutputFormat::Text => cargoscope_report::render_text(
            root,
            report,
            cargoscope_report::TextOptions {
                show_uncertain: options.show_uncertain,
                verbose: options.verbose,
                color: options.color.enabled(options.output.is_some()),
                next_steps: true,
            },
        ),
        OutputFormat::Json => cargoscope_report::render_json(root, report),
        OutputFormat::Sarif => cargoscope_report::sarif::render_sarif(
            report,
            &sarif_locations(root, report),
            options.show_uncertain,
        ),
        OutputFormat::CycloneDx => cargoscope_report::cyclonedx::render_cyclonedx(root, report),
        OutputFormat::Html => {
            cargoscope_report::html::render_html(root, report, options.show_uncertain)
        }
    };
    match &options.output {
        Some(path) => std::fs::write(path, rendered).map_err(|error| {
            eprintln!("CargoScope could not write {}: {error}", path.display());
            ExitCode::from(2)
        }),
        None => {
            print!("{rendered}");
            Ok(())
        }
    }
}

/// 1 when a policy violation or a new advisory reaches `--fail-on`;
/// advisories already in `--baseline` do not count.
fn exit_code(options: &ScanOptions, report: &Report) -> Result<ExitCode, ExitCode> {
    let known = match &options.baseline {
        Some(path) => read_report(path)
            .map(|baseline| cargoscope_report::compare::advisory_keys(&baseline))
            .map_err(|error| {
                eprintln!("CargoScope could not read the baseline: {error}");
                ExitCode::from(2)
            })?,
        None => std::collections::BTreeSet::new(),
    };
    let is_new = |finding: &&AdvisoryFinding| {
        let package = &report.inventory.packages[finding.package];
        !known.contains(&cargoscope_report::compare::AdvisoryKey {
            id: finding.id.clone(),
            package: package.name.clone(),
            version: package.version.clone(),
        })
    };
    let in_baseline = report
        .advisories
        .iter()
        .filter(|finding| !is_new(finding))
        .count();
    if in_baseline > 0 {
        eprintln!(
            "{in_baseline} advisory finding(s) are already in the baseline and do not fail the scan."
        );
    }
    let policy_fails = options.fail_on != FailOn::Never
        && report.policy.as_ref().is_some_and(|violations| {
            violations
                .iter()
                .any(|violation| violation.level == ViolationLevel::Error)
        });
    let advisory_fails = report
        .advisories
        .iter()
        .filter(is_new)
        .any(|finding| options.fail_on.is_triggered_by(finding));
    Ok(if policy_fails || advisory_fails {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// Repository-relative URI with forward slashes, as SARIF consumers expect.
fn sarif_uri(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut text = text.as_str();
    while let Some(rest) = text.strip_prefix("./") {
        text = rest;
    }
    if path.is_absolute() {
        let text = text.trim_start_matches('/');
        return format!("file:///{text}");
    }
    text.to_owned()
}

fn sarif_locations(root: &Path, report: &Report) -> SarifLocations {
    use cargoscope_cargo::locations::{lockfile_lines, manifest_dependency_line};

    let lockfile = root.join("Cargo.lock");
    let lines = std::fs::read_to_string(&lockfile)
        .map(|text| lockfile_lines(&text))
        .unwrap_or_default();
    let package_lines = report
        .inventory
        .packages
        .iter()
        .map(|package| {
            lines
                .iter()
                .find(|((name, version), _)| *name == package.name && *version == package.version)
                .map(|(_, line)| *line)
        })
        .collect();
    let unused_locations = report
        .unused
        .iter()
        .map(|finding| {
            let manifest = root.join(&finding.manifest);
            let line = std::fs::read_to_string(&manifest).ok().and_then(|text| {
                manifest_dependency_line(&text, finding.kind.section(), &finding.dependency)
            });
            (sarif_uri(&manifest), line)
        })
        .collect();
    SarifLocations {
        lockfile_uri: sarif_uri(&lockfile),
        package_lines,
        unused_locations,
    }
}

#[cfg(test)]
mod tests {
    use super::{ActivePackages, OutputFormat, parse_scan_options};
    use crate::FailOn;
    use cargoscope_core::{AdvisoryFinding, AdvisoryKind, Inventory, Severity};
    use std::collections::{BTreeMap, BTreeSet};
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
        let cyclonedx = parse(&["--format", "cyclonedx", "."]).expect("valid");
        assert_eq!(cyclonedx.format, OutputFormat::CycloneDx);
        let html = parse(&["--format", "html", "."]).expect("valid");
        assert_eq!(html.format, OutputFormat::Html);
        let updated = parse(&["--update", "--fast", "."]).expect("valid");
        assert!(updated.update);
        assert!(!updated.include_maintenance);
        let no_maint = parse(&["--update", "--no-maintenance"]).expect("valid");
        assert!(no_maint.update);
        assert!(!no_maint.include_maintenance);
    }

    #[test]
    fn parses_update_command_options() {
        let defaults = crate::parse_update_options(std::iter::empty()).expect("valid");
        assert_eq!(defaults.path, PathBuf::from("."));
        assert!(defaults.include_maintenance);
        let fast =
            crate::parse_update_options(["crates/app", "--fast"].into_iter().map(str::to_owned))
                .expect("valid");
        assert_eq!(fast.path, PathBuf::from("crates/app"));
        assert!(!fast.include_maintenance);
        let no_maint =
            crate::parse_update_options(["--no-maintenance", "."].into_iter().map(str::to_owned))
                .expect("valid");
        assert!(!no_maint.include_maintenance);
        assert!(crate::parse_update_options(["--nope"].into_iter().map(str::to_owned)).is_err());
        assert!(crate::parse_update_options(["a", "b"].into_iter().map(str::to_owned)).is_err());
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
            affected_arch: Vec::new(),
            affected_os: Vec::new(),
            affected_functions: Vec::new(),
            relevance: cargoscope_core::AdvisoryRelevance::AffectsYou,
            relevance_reason: None,
            ignored: None,
        }
    }

    #[test]
    fn applies_advisory_ignores_by_id_or_alias_with_expiry() {
        use cargoscope_cargo::config::AdvisoryIgnore;
        let mut findings = vec![
            finding(AdvisoryKind::Vulnerability, Some(Severity::High)),
            finding(AdvisoryKind::Vulnerability, None),
        ];
        findings[0].id = "RUSTSEC-1".to_owned();
        findings[1].id = "RUSTSEC-2".to_owned();
        findings[1].aliases = vec!["CVE-9".to_owned()];
        let ignore = |id: &str, until: Option<&str>| AdvisoryIgnore {
            id: id.to_owned(),
            reason: "known".to_owned(),
            until: until.map(str::to_owned),
            source: "cargoscope.toml",
        };
        let warnings = super::apply_advisory_ignores(
            &mut findings,
            &[
                ignore("rustsec-1", None),
                ignore("CVE-9", Some("2026-01-01")),
                ignore("RUSTSEC-404", None),
            ],
            "2026-11-14",
        );
        assert_eq!(findings[0].ignored.as_deref(), Some("known"));
        assert_eq!(
            findings[1].ignored, None,
            "expired ignore no longer applies"
        );
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("expired on 2026-01-01"));
        assert!(warnings[1].contains("RUSTSEC-404, which matches no advisory"));
        assert!(!FailOn::AnyVulnerability.is_triggered_by(&findings[0]));
        assert!(FailOn::AnyVulnerability.is_triggered_by(&findings[1]));
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

    #[test]
    fn evaluates_advisory_relevance_for_unbuilt_dev_platform_and_uncalled_functions() {
        use cargoscope_core::{AdvisoryRelevance, DependencyKind, Package};
        let inventory = Inventory {
            packages: vec![
                Package {
                    name: "app".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: false,
                    dependencies: vec![1, 2, 3, 4],
                },
                Package {
                    name: "unbuilt".to_owned(),
                    version: "1.0.0".to_owned(),
                    source: None,
                    root: false,
                    direct: true,
                    dependencies: Vec::new(),
                },
                Package {
                    name: "dev_only".to_owned(),
                    version: "1.0.0".to_owned(),
                    source: None,
                    root: false,
                    direct: true,
                    dependencies: Vec::new(),
                },
                Package {
                    name: "wasm_only".to_owned(),
                    version: "1.0.0".to_owned(),
                    source: None,
                    root: false,
                    direct: true,
                    dependencies: Vec::new(),
                },
                Package {
                    name: "zip_like".to_owned(),
                    version: "1.0.0".to_owned(),
                    source: None,
                    root: false,
                    direct: true,
                    dependencies: Vec::new(),
                },
            ],
        };
        let mut direct_kinds = BTreeMap::new();
        direct_kinds.insert(
            "unbuilt".to_owned(),
            BTreeSet::from([DependencyKind::Normal]),
        );
        direct_kinds.insert("dev_only".to_owned(), BTreeSet::from([DependencyKind::Dev]));
        direct_kinds.insert(
            "wasm_only".to_owned(),
            BTreeSet::from([DependencyKind::Normal]),
        );
        direct_kinds.insert(
            "zip_like".to_owned(),
            BTreeSet::from([DependencyKind::Normal]),
        );

        let active = ActivePackages::from([
            ("app".to_owned(), "0.1.0".to_owned()),
            ("dev_only".to_owned(), "1.0.0".to_owned()),
            ("wasm_only".to_owned(), "1.0.0".to_owned()),
            ("zip_like".to_owned(), "1.0.0".to_owned()),
        ]);
        let non_dev = ActivePackages::from([
            ("app".to_owned(), "0.1.0".to_owned()),
            ("wasm_only".to_owned(), "1.0.0".to_owned()),
            ("zip_like".to_owned(), "1.0.0".to_owned()),
        ]);
        let idents = BTreeSet::from(["used_fn".to_owned()]);

        let mut f_unbuilt = finding(AdvisoryKind::Vulnerability, Some(Severity::High));
        f_unbuilt.package = 1;
        let mut f_dev = finding(AdvisoryKind::Vulnerability, Some(Severity::High));
        f_dev.package = 2;
        let mut f_wasm = finding(AdvisoryKind::Vulnerability, Some(Severity::High));
        f_wasm.package = 3;
        f_wasm.affected_arch = vec!["wasm32".to_owned()];
        let mut f_uncalled = finding(AdvisoryKind::Vulnerability, Some(Severity::High));
        f_uncalled.package = 4;
        f_uncalled.affected_functions = vec!["zip_like::Archive::extract".to_owned()];
        let mut f_called = finding(AdvisoryKind::Vulnerability, Some(Severity::High));
        f_called.package = 4;
        f_called.affected_functions = vec!["zip_like::used_fn".to_owned()];

        let mut findings = vec![f_unbuilt, f_dev, f_wasm.clone(), f_uncalled, f_called];
        super::evaluate_advisory_relevance(
            &inventory,
            &direct_kinds,
            &["x86_64-unknown-linux-gnu".to_owned()],
            Some(&active),
            Some(&non_dev),
            &idents,
            &mut findings,
        );
        assert_eq!(findings[0].relevance, AdvisoryRelevance::Unlikely);
        assert_eq!(findings[1].relevance, AdvisoryRelevance::Unlikely);
        assert_eq!(findings[2].relevance, AdvisoryRelevance::Unlikely);
        assert!(
            findings[2]
                .relevance_reason
                .as_deref()
                .is_some_and(|r| r.contains("wasm32"))
        );
        assert_eq!(findings[3].relevance, AdvisoryRelevance::Unlikely);
        assert_eq!(findings[4].relevance, AdvisoryRelevance::AffectsYou);

        // Without configured targets, arch/os constraints rank as Possibly.
        let mut no_targets = vec![f_wasm];
        super::evaluate_advisory_relevance(
            &inventory,
            &direct_kinds,
            &[],
            None,
            None,
            &idents,
            &mut no_targets,
        );
        assert_eq!(no_targets[0].relevance, AdvisoryRelevance::Possibly);
    }
}
