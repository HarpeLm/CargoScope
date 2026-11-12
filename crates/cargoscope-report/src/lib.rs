//! Report rendering: text, JSON and SARIF.

pub mod compare;
pub mod sarif;

use std::fmt::Write;
use std::path::Path;

use cargoscope_core::{
    AdvisoryFinding, AdvisoryKind, Inventory, Package, Report, UnusedConfidence, UnusedFinding,
    VERSION,
};

/// Version of the JSON report format.
pub const JSON_FORMAT_VERSION: u32 = 1;

/// Options of the text report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TextOptions {
    /// Also list possibly-unused dependencies.
    pub show_uncertain: bool,
    /// List every resolved package with its path, license and versions.
    pub verbose: bool,
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

fn label(finding: &AdvisoryFinding) -> &str {
    match (&finding.kind, finding.severity) {
        (AdvisoryKind::Informational(kind), _) => kind,
        (AdvisoryKind::Vulnerability, Some(severity)) => severity.as_str(),
        (AdvisoryKind::Vulnerability, None) => "unknown severity",
    }
}

fn chain(inventory: &Inventory, index: usize) -> Option<String> {
    let path = inventory.path_to(index)?;
    let names: Vec<&str> = path
        .iter()
        .map(|&step| inventory.packages[step].name.as_str())
        .collect();
    Some(names.join(" -> "))
}

/// Renders a human-readable report: advisories first, then the inventory.
///
/// Every advisory and every transitive package shows the shortest dependency
/// chain that pulls the package in.
#[must_use]
///
/// Possibly-unused dependencies are listed only with `show_uncertain`, and
/// the full package list only with `verbose`; otherwise only counts are shown.
pub fn render_text(project_root: &Path, report: &Report, options: TextOptions) -> String {
    let inventory = &report.inventory;
    let mut out = String::new();
    // Writing to a String cannot fail.
    let _ = writeln!(out, "CargoScope {VERSION}");
    let _ = writeln!(out, "Target: {}", project_root.display());
    let _ = writeln!(out, "Summary: {}", summary(report));

    if report.checks.advisories {
        render_advisories_text(&mut out, report);
    } else {
        out.push_str("\nAdvisories: not checked\n");
    }
    if report.checks.unused {
        render_unused_text(&mut out, &report.unused, options.show_uncertain);
    } else {
        out.push_str("\nUnused dependencies: not checked\n");
    }
    render_registry_text(&mut out, report);

    if options.verbose {
        let _ = writeln!(out, "\nResolved packages: {}", inventory.packages.len());
        render_inventory_text(&mut out, report);
    } else {
        let _ = writeln!(
            out,
            "\nResolved packages: {} (use --verbose to list them)",
            inventory.packages.len()
        );
    }

    for warning in &report.warnings {
        let _ = writeln!(out, "\nwarning: {warning}");
    }

    out
}

/// One-line overview of the findings of the checks that ran.
#[must_use]
pub fn summary(report: &Report) -> String {
    let plural = |count: usize, word: &str| {
        if count == 1 {
            format!("{count} {word}")
        } else {
            format!("{count} {word}s")
        }
    };
    let mut parts = Vec::new();
    if report.checks.advisories {
        let vulnerabilities = report
            .advisories
            .iter()
            .filter(|finding| matches!(finding.kind, AdvisoryKind::Vulnerability))
            .count();
        parts.push(format!(
            "{} ({} informational)",
            if vulnerabilities == 1 {
                "1 vulnerability".to_owned()
            } else {
                format!("{vulnerabilities} vulnerabilities")
            },
            report.advisories.len() - vulnerabilities
        ));
    }
    if report.checks.unused {
        let likely = report
            .unused
            .iter()
            .filter(|finding| {
                finding.ignored.is_none() && finding.confidence == UnusedConfidence::Likely
            })
            .count();
        parts.push(format!("{likely} likely-unused"));
    }
    if report.checks.versions {
        let yanked = report
            .package_info
            .iter()
            .filter(|info| info.yanked == Some(true))
            .count();
        let outdated_direct = report
            .package_info
            .iter()
            .zip(&report.inventory.packages)
            .filter(|(info, package)| info.outdated && package.direct)
            .count();
        parts.push(format!("{yanked} yanked"));
        parts.push(format!("{outdated_direct} outdated direct"));
    }
    parts.push(plural(report.inventory.packages.len(), "package"));
    parts.join(", ")
}

fn render_advisories_text(out: &mut String, report: &Report) {
    let inventory = &report.inventory;
    let date = report.advisory_db_date.as_deref().unwrap_or("unknown date");
    let _ = writeln!(
        out,
        "\nAdvisories: {} (RustSec database downloaded {date})",
        report.advisories.len()
    );
    for finding in &report.advisories {
        let package = &inventory.packages[finding.package];
        let _ = writeln!(
            out,
            "- {} [{}] {} {}: {}",
            finding.id,
            label(finding),
            package.name,
            package.version,
            finding.title
        );
        if let Some(chain) = chain(inventory, finding.package) {
            let _ = writeln!(out, "    via {chain}");
        }
        if finding.patched.is_empty() {
            out.push_str("    fix: no fixed version available\n");
        } else {
            let _ = writeln!(out, "    fix: upgrade to {}", finding.patched.join(" or "));
        }
        if let Some(url) = &finding.url {
            let _ = writeln!(out, "    {url}");
        }
    }
    if report.advisories.is_empty() {
        out.push_str("No known advisory found. This does not mean the dependencies are safe.\n");
    }
}

fn render_inventory_text(out: &mut String, report: &Report) {
    let inventory = &report.inventory;
    for (index, package) in inventory.packages.iter().enumerate() {
        let _ = write!(
            out,
            "- {} {} [{}]",
            package.name,
            package.version,
            scope(package)
        );
        if let Some(source) = &package.source {
            let _ = write!(out, " ({source})");
        }
        if let Some(info) = report.package_info.get(index) {
            if let Some(license) = &info.license {
                let _ = write!(out, " {license}");
            }
            if info.yanked == Some(true) {
                out.push_str(" YANKED");
            }
            if info.outdated {
                if let Some(latest) = &info.latest_version {
                    let _ = write!(out, " -> {latest} available");
                }
            }
        }
        out.push('\n');

        if package.root || package.direct {
            continue;
        }
        match chain(inventory, index) {
            Some(chain) => {
                let _ = writeln!(out, "    via {chain}");
            }
            None => out.push_str("    not reachable from any root package\n"),
        }
    }
}

fn render_unused_text(out: &mut String, unused: &[UnusedFinding], show_uncertain: bool) {
    let active = || unused.iter().filter(|finding| finding.ignored.is_none());
    let likely = active()
        .filter(|finding| finding.confidence == UnusedConfidence::Likely)
        .count();
    let possibly = active().count() - likely;
    let _ = writeln!(
        out,
        "\nLikely-unused dependencies: {likely} (static analysis: candidates to verify)"
    );
    for finding in active() {
        if finding.confidence == UnusedConfidence::Possibly && !show_uncertain {
            continue;
        }
        let renamed = if finding.package == finding.dependency {
            String::new()
        } else {
            format!(" (package `{}`)", finding.package)
        };
        let _ = writeln!(
            out,
            "- {}{renamed} [{}] in [{}] of {}",
            finding.dependency,
            finding.confidence.as_str(),
            finding.kind.section(),
            finding.manifest
        );
        for evidence in &finding.evidence {
            let _ = writeln!(out, "    {evidence}");
        }
    }
    if possibly > 0 && !show_uncertain {
        let _ = writeln!(
            out,
            "{possibly} possibly-unused dependenc{} hidden; use --show-uncertain to list {}",
            if possibly == 1 { "y" } else { "ies" },
            if possibly == 1 { "it" } else { "them" }
        );
    }
    for finding in unused.iter().filter(|finding| finding.ignored.is_some()) {
        let _ = writeln!(
            out,
            "- {} ignored in {}, reason: {}",
            finding.dependency,
            finding.manifest,
            finding.ignored.as_deref().unwrap_or_default()
        );
    }
}

fn render_registry_text(out: &mut String, report: &Report) {
    let date = report.registry_date.as_deref().unwrap_or("never");
    let registry_packages: Vec<(usize, &cargoscope_core::PackageInfo)> = report
        .package_info
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            report.inventory.packages[*index]
                .source
                .as_deref()
                .is_some_and(|source| {
                    source.starts_with("registry+") || source.starts_with("sparse+")
                })
        })
        .collect();

    if report.checks.licenses {
        render_licenses_text(out, &registry_packages, date);
    } else {
        out.push_str("\nLicenses: not checked\n");
    }
    if report.checks.versions {
        render_versions_text(out, report, &registry_packages);
    } else {
        out.push_str("\nVersions: not checked\n");
    }
}

type RegistryPackages<'a> = [(usize, &'a cargoscope_core::PackageInfo)];

fn render_licenses_text(out: &mut String, registry_packages: &RegistryPackages<'_>, date: &str) {
    let mut licenses: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for (_, info) in registry_packages {
        *licenses
            .entry(info.license.as_deref().unwrap_or("unknown"))
            .or_default() += 1;
    }
    let mut by_count: Vec<(&str, usize)> = licenses.into_iter().collect();
    by_count.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(right.0)));
    let _ = writeln!(
        out,
        "\nLicenses of {} registry packages (crates.io data downloaded {date}):",
        registry_packages.len()
    );
    for (license, count) in by_count {
        let _ = writeln!(out, "- {license}: {count}");
    }
}

fn render_versions_text(
    out: &mut String,
    report: &Report,
    registry_packages: &RegistryPackages<'_>,
) {
    let yanked: Vec<usize> = registry_packages
        .iter()
        .filter(|(_, info)| info.yanked == Some(true))
        .map(|(index, _)| *index)
        .collect();
    if !yanked.is_empty() {
        let _ = writeln!(out, "\nYanked versions in use: {}", yanked.len());
        for index in yanked {
            let package = &report.inventory.packages[index];
            let _ = writeln!(out, "- {} {}", package.name, package.version);
            if let Some(chain) = chain(&report.inventory, index) {
                let _ = writeln!(out, "    via {chain}");
            }
        }
    }

    let outdated = registry_packages
        .iter()
        .filter(|(_, info)| info.outdated)
        .count();
    let direct_outdated: Vec<(usize, &cargoscope_core::PackageInfo)> = registry_packages
        .iter()
        .filter(|(index, info)| info.outdated && report.inventory.packages[*index].direct)
        .copied()
        .collect();
    let _ = writeln!(
        out,
        "\nOutdated packages: {outdated} ({} direct)",
        direct_outdated.len()
    );
    for (index, info) in direct_outdated {
        let package = &report.inventory.packages[index];
        let published = info
            .latest_published
            .as_deref()
            .map(|date| format!(", published {date}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "- {} {} -> {}{published}",
            package.name,
            package.version,
            info.latest_version.as_deref().unwrap_or("?")
        );
    }
}

/// Renders a versioned JSON report, terminated by a newline.
///
/// Each package and each advisory carries a `path`: the shortest chain of
/// `{name, version}` from a root package, or `null` when unreachable.
#[must_use]
pub fn render_json(project_root: &Path, report: &Report) -> String {
    let inventory = &report.inventory;
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\"format_version\":{JSON_FORMAT_VERSION},\"tool_version\":\"{}\",\"target\":\"{}\",",
        json_escape(VERSION),
        json_escape(&project_root.display().to_string())
    );
    let _ = write!(
        out,
        "\"checks\":{},",
        json_string_array(
            &report
                .checks
                .enabled()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        )
    );
    let _ = write!(
        out,
        "\"advisory_database\":{{\"source\":\"RustSec\",\"downloaded_on\":{}}},",
        json_string_or_null(report.advisory_db_date.as_deref())
    );
    let _ = write!(
        out,
        "\"registry\":{{\"source\":\"crates.io\",\"downloaded_on\":{}}},",
        json_string_or_null(report.registry_date.as_deref())
    );

    out.push_str("\"advisories\":[");
    for (position, finding) in report.advisories.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        let package = &inventory.packages[finding.package];
        let (kind, informational) = match &finding.kind {
            AdvisoryKind::Vulnerability => ("vulnerability", None),
            AdvisoryKind::Informational(kind) => ("informational", Some(kind.as_str())),
        };
        let _ = write!(
            out,
            "{{\"id\":\"{}\",\"aliases\":{},\"title\":\"{}\",\"date\":\"{}\",\"url\":{},\"kind\":\"{kind}\",\"informational\":{},\"severity\":{},\"package\":{{\"name\":\"{}\",\"version\":\"{}\"}},\"patched\":{},\"path\":",
            json_escape(&finding.id),
            json_string_array(&finding.aliases),
            json_escape(&finding.title),
            json_escape(&finding.date),
            json_string_or_null(finding.url.as_deref()),
            json_string_or_null(informational),
            json_string_or_null(finding.severity.map(|severity| severity.as_str())),
            json_escape(&package.name),
            json_escape(&package.version),
            json_string_array(&finding.patched),
        );
        write_path(&mut out, inventory, finding.package);
        out.push('}');
    }
    out.push_str("],");

    out.push_str("\"packages\":[");
    for (index, package) in inventory.packages.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"name\":\"{}\",\"version\":\"{}\",\"scope\":\"{}\",\"direct\":{},\"source\":{},\"path\":",
            json_escape(&package.name),
            json_escape(&package.version),
            scope(package),
            package.direct,
            json_string_or_null(package.source.as_deref()),
        );
        write_path(&mut out, inventory, index);
        let info = report.package_info.get(index).cloned().unwrap_or_default();
        let _ = write!(
            out,
            ",\"license\":{},\"latest_version\":{},\"latest_published\":{},\"outdated\":{},\"yanked\":{}}}",
            json_string_or_null(info.license.as_deref()),
            json_string_or_null(info.latest_version.as_deref()),
            json_string_or_null(info.latest_published.as_deref()),
            info.outdated,
            info.yanked
                .map_or("null", |yanked| if yanked { "true" } else { "false" }),
        );
    }
    out.push_str("],");

    out.push_str("\"unused\":[");
    for (position, finding) in report.unused.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"dependency\":\"{}\",\"package\":\"{}\",\"section\":\"{}\",\"declared_by\":\"{}\",\"manifest\":\"{}\",\"confidence\":\"{}\",\"evidence\":{},\"ignored_reason\":{}}}",
            json_escape(&finding.dependency),
            json_escape(&finding.package),
            finding.kind.section(),
            json_escape(&finding.declared_by),
            json_escape(&finding.manifest),
            finding.confidence.as_str(),
            json_string_array(&finding.evidence),
            json_string_or_null(finding.ignored.as_deref()),
        );
    }
    out.push_str("],");

    let _ = writeln!(
        out,
        "\"warnings\":{}}}",
        json_string_array(&report.warnings)
    );
    out
}

fn write_path(out: &mut String, inventory: &Inventory, index: usize) {
    let Some(path) = inventory.path_to(index) else {
        out.push_str("null");
        return;
    };
    out.push('[');
    for (position, &step) in path.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        let step = &inventory.packages[step];
        let _ = write!(
            out,
            "{{\"name\":\"{}\",\"version\":\"{}\"}}",
            json_escape(&step.name),
            json_escape(&step.version)
        );
    }
    out.push(']');
}

fn json_string_or_null(value: Option<&str>) -> String {
    value.map_or_else(
        || "null".to_owned(),
        |value| format!("\"{}\"", json_escape(value)),
    )
}

fn json_string_array(values: &[String]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|value| format!("\"{}\"", json_escape(value)))
        .collect();
    format!("[{}]", items.join(","))
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", u32::from(character));
            }
            character => escaped.push(character),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::{TextOptions, json_escape, render_json, render_text};

    const VERBOSE: TextOptions = TextOptions {
        show_uncertain: false,
        verbose: true,
    };
    use cargoscope_core::{
        AdvisoryFinding, AdvisoryKind, Checks, DependencyKind, Inventory, Package, PackageInfo,
        Report, Severity, UnusedConfidence, UnusedFinding,
    };
    use std::path::Path;

    fn package(
        name: &str,
        source: Option<&str>,
        root: bool,
        direct: bool,
        deps: Vec<usize>,
    ) -> Package {
        Package {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            source: source.map(str::to_owned),
            root,
            direct,
            dependencies: deps,
        }
    }

    // 0 app (root) -> 1 alpha (direct) -> 2 beta (transitive); 3 orphan
    fn sample(advisories: Vec<AdvisoryFinding>) -> Report {
        Report {
            checks: Checks::ALL,
            inventory: Inventory {
                packages: vec![
                    package("app", None, true, false, vec![1]),
                    package(
                        "alpha",
                        Some("registry+https://example.test"),
                        false,
                        true,
                        vec![2],
                    ),
                    package("beta", None, false, false, vec![]),
                    package("orphan", None, false, false, vec![]),
                ],
            },
            advisories,
            unused: Vec::new(),
            policy: None,
            package_info: Vec::new(),
            registry_date: None,
            advisory_db_date: Some("2026-01-02".to_owned()),
            warnings: Vec::new(),
        }
    }

    fn finding(kind: AdvisoryKind, patched: Vec<String>) -> AdvisoryFinding {
        AdvisoryFinding {
            package: 2,
            id: "TEST-0001".to_owned(),
            aliases: vec!["CVE-TEST".to_owned()],
            title: "Beta is broken".to_owned(),
            date: "2025-05-05".to_owned(),
            url: Some("https://example.test/report".to_owned()),
            kind,
            severity: Some(Severity::High),
            patched,
        }
    }

    #[test]
    fn text_report_lists_scope_source_and_path() {
        let text = render_text(Path::new("."), &sample(Vec::new()), VERBOSE);
        assert!(text.contains("Resolved packages: 4\n"));
        assert!(text.contains("- app 1.0.0 [root]\n"));
        assert!(text.contains("- alpha 1.0.0 [direct] (registry+https://example.test)\n"));
        assert!(text.contains("- beta 1.0.0 [transitive]\n    via app -> alpha -> beta\n"));
        assert!(
            text.contains("- orphan 1.0.0 [transitive]\n    not reachable from any root package\n")
        );
        assert!(text.contains("Advisories: 0 (RustSec database downloaded 2026-01-02)\n"));
        assert!(text.contains("This does not mean the dependencies are safe."));
    }

    #[test]
    fn text_report_explains_advisories() {
        let report = sample(vec![finding(
            AdvisoryKind::Vulnerability,
            vec![">= 1.2.0".to_owned()],
        )]);
        let text = render_text(Path::new("."), &report, VERBOSE);
        assert!(text.contains(
            "- TEST-0001 [high] beta 1.0.0: Beta is broken\n    via app -> alpha -> beta\n    fix: upgrade to >= 1.2.0\n    https://example.test/report\n"
        ));
    }

    #[test]
    fn text_report_labels_informational_and_unfixed_advisories() {
        let report = sample(vec![finding(
            AdvisoryKind::Informational("unmaintained".to_owned()),
            Vec::new(),
        )]);
        let text = render_text(Path::new("."), &report, VERBOSE);
        assert!(text.contains("[unmaintained] beta 1.0.0"));
        assert!(text.contains("fix: no fixed version available"));
    }

    #[test]
    fn json_report_includes_scope_path_and_advisories() {
        let report = sample(vec![finding(
            AdvisoryKind::Vulnerability,
            vec![">= 1.2.0".to_owned()],
        )]);
        let json = render_json(Path::new("."), &report);
        assert!(json.starts_with("{\"format_version\":1,"));
        assert!(json.contains(
            "\"advisory_database\":{\"source\":\"RustSec\",\"downloaded_on\":\"2026-01-02\"}"
        ));
        assert!(json.contains(
            "{\"id\":\"TEST-0001\",\"aliases\":[\"CVE-TEST\"],\"title\":\"Beta is broken\",\"date\":\"2025-05-05\",\"url\":\"https://example.test/report\",\"kind\":\"vulnerability\",\"informational\":null,\"severity\":\"high\",\"package\":{\"name\":\"beta\",\"version\":\"1.0.0\"},\"patched\":[\">= 1.2.0\"],\"path\":[{\"name\":\"app\",\"version\":\"1.0.0\"},{\"name\":\"alpha\",\"version\":\"1.0.0\"},{\"name\":\"beta\",\"version\":\"1.0.0\"}]}"
        ));
        assert!(json.contains(
            "{\"name\":\"orphan\",\"version\":\"1.0.0\",\"scope\":\"transitive\",\"direct\":false,\"source\":null,\"path\":null,\"license\":null,\"latest_version\":null,\"latest_published\":null,\"outdated\":false,\"yanked\":null}"
        ));
        assert!(json.ends_with("\"unused\":[],\"warnings\":[]}\n"));
    }

    fn unused(
        dependency: &str,
        confidence: UnusedConfidence,
        ignored: Option<&str>,
    ) -> UnusedFinding {
        UnusedFinding {
            declared_by: "app".to_owned(),
            manifest: "Cargo.toml".to_owned(),
            dependency: dependency.to_owned(),
            package: dependency.to_owned(),
            kind: DependencyKind::Normal,
            confidence,
            evidence: vec!["no reference".to_owned()],
            ignored: ignored.map(str::to_owned),
        }
    }

    fn with_unused() -> Report {
        let mut report = sample(Vec::new());
        report.unused = vec![
            unused("log", UnusedConfidence::Likely, None),
            unused("openssl-sys", UnusedConfidence::Possibly, None),
            unused(
                "once_cell",
                UnusedConfidence::Likely,
                Some("generated code"),
            ),
        ];
        report
    }

    #[test]
    fn text_report_hides_uncertain_unused_by_default() {
        let text = render_text(Path::new("."), &with_unused(), VERBOSE);
        assert!(
            text.contains(
                "Likely-unused dependencies: 1 (static analysis: candidates to verify)\n"
            )
        );
        assert!(
            text.contains(
                "- log [likely-unused] in [dependencies] of Cargo.toml\n    no reference\n"
            )
        );
        assert!(!text.contains("- openssl-sys"));
        assert!(
            text.contains("1 possibly-unused dependency hidden; use --show-uncertain to list it\n")
        );
        assert!(text.contains("- once_cell ignored in Cargo.toml, reason: generated code\n"));
    }

    #[test]
    fn text_report_shows_uncertain_unused_on_request() {
        let text = render_text(
            Path::new("."),
            &with_unused(),
            TextOptions {
                show_uncertain: true,
                verbose: true,
            },
        );
        assert!(text.contains("- openssl-sys [possibly-unused] in [dependencies] of Cargo.toml\n"));
        assert!(!text.contains("hidden"));
    }

    #[test]
    fn json_report_lists_every_unused_finding() {
        let json = render_json(Path::new("."), &with_unused());
        assert!(json.contains("{\"dependency\":\"log\",\"package\":\"log\",\"section\":\"dependencies\",\"declared_by\":\"app\",\"manifest\":\"Cargo.toml\",\"confidence\":\"likely-unused\",\"evidence\":[\"no reference\"],\"ignored_reason\":null}"));
        assert!(json.contains("\"confidence\":\"possibly-unused\""));
        assert!(json.contains("\"ignored_reason\":\"generated code\""));
    }

    #[test]
    fn reports_licenses_outdated_and_yanked_packages() {
        let mut report = sample(Vec::new());
        report.registry_date = Some("2026-02-03".to_owned());
        report.package_info = vec![
            PackageInfo::default(),
            PackageInfo {
                license: Some("MIT".to_owned()),
                latest_version: Some("2.0.0".to_owned()),
                latest_published: Some("2026-01-01".to_owned()),
                yanked: Some(true),
                outdated: true,
            },
            PackageInfo::default(),
            PackageInfo::default(),
        ];
        let text = render_text(Path::new("."), &report, VERBOSE);
        assert!(text.contains(
            "Licenses of 1 registry packages (crates.io data downloaded 2026-02-03):\n- MIT: 1\n"
        ));
        assert!(text.contains("Yanked versions in use: 1\n- alpha 1.0.0\n    via app -> alpha\n"));
        assert!(text.contains(
            "Outdated packages: 1 (1 direct)\n- alpha 1.0.0 -> 2.0.0, published 2026-01-01\n"
        ));
        assert!(text.contains(
            "- alpha 1.0.0 [direct] (registry+https://example.test) MIT YANKED -> 2.0.0 available\n"
        ));

        let json = render_json(Path::new("."), &report);
        assert!(
            json.contains(
                "\"registry\":{\"source\":\"crates.io\",\"downloaded_on\":\"2026-02-03\"}"
            )
        );
        assert!(json.contains("\"license\":\"MIT\",\"latest_version\":\"2.0.0\",\"latest_published\":\"2026-01-01\",\"outdated\":true,\"yanked\":true}"));
    }

    #[test]
    fn summary_counts_findings_of_checks_that_ran() {
        let mut report = with_unused();
        report.advisories = vec![
            finding(AdvisoryKind::Vulnerability, Vec::new()),
            finding(
                AdvisoryKind::Informational("unmaintained".to_owned()),
                Vec::new(),
            ),
        ];
        assert_eq!(
            super::summary(&report),
            "1 vulnerability (1 informational), 1 likely-unused, 0 yanked, 0 outdated direct, 4 packages"
        );
        report.checks = Checks {
            advisories: false,
            unused: false,
            licenses: false,
            versions: false,
            policy: false,
        };
        assert_eq!(super::summary(&report), "4 packages");
        assert!(render_text(Path::new("."), &report, VERBOSE).contains("\nSummary: 4 packages\n"));
    }

    #[test]
    fn package_list_is_shown_only_when_verbose() {
        let report = sample(Vec::new());
        let short = render_text(Path::new("."), &report, TextOptions::default());
        assert!(short.contains("Resolved packages: 4 (use --verbose to list them)\n"));
        assert!(!short.contains("- app 1.0.0 [root]"));
        assert!(render_text(Path::new("."), &report, VERBOSE).contains("- app 1.0.0 [root]"));
    }

    #[test]
    fn escapes_quotes_backslashes_and_control_characters() {
        assert_eq!(json_escape("a\"b\\c\n\u{1}"), "a\\\"b\\\\c\\n\\u0001");
    }
}
