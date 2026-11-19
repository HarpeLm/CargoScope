//! Self-contained standalone HTML report output.
//!
//! Renders a single offline HTML5 document with inline CSS, inline SVG status
//! badge, and optional vanilla JS search/section filtering (no external network
//! requests).

use std::fmt::Write;
use std::path::Path;

use cargoscope_core::policy::ViolationLevel;
use cargoscope_core::{
    AdvisoryKind, AdvisoryRelevance, OutdatedKind, Report, UnusedConfidence, VERSION,
};

use crate::{
    chain, format_outdated_targets, kind_names, kind_note, label, registry_packages, scope,
    sorted_heavy_weights, sorted_license_counts, summary,
};

/// Escapes HTML special characters for safe interpolation into text nodes and
/// quoted attribute values.
#[must_use]
pub fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn safe_http_url(url: Option<&str>) -> Option<&str> {
    url.filter(|u| u.starts_with("https://") || u.starts_with("http://"))
}

fn is_crates_io(pkg: &cargoscope_core::Package) -> bool {
    pkg.source.as_deref().is_some_and(|source| {
        source == "registry+https://github.com/rust-lang/crates.io-index"
            || source.starts_with("sparse+https://index.crates.io")
    })
}

/// A package's name, linked to its crates.io page when it comes from
/// crates.io, with a `data-direct` marker the quick filters read.
fn crate_name_html(pkg: &cargoscope_core::Package) -> String {
    let name = escape_html(&pkg.name);
    let direct = if pkg.direct { "true" } else { "false" };
    if is_crates_io(pkg) {
        format!(
            "<a class=\"crate\" data-direct=\"{direct}\" href=\"https://crates.io/crates/{name}/{}\" target=\"_blank\" rel=\"noopener noreferrer\"><code>{name}</code></a>",
            escape_html(&pkg.version)
        )
    } else {
        format!("<code class=\"crate\" data-direct=\"{direct}\">{name}</code>")
    }
}

/// A package's linked name and its version.
fn package_cell(pkg: &cargoscope_core::Package) -> String {
    format!(
        "{} <span class=\"muted\">{}</span>",
        crate_name_html(pkg),
        escape_html(&pkg.version)
    )
}

/// `to` as a link to the source diff from the resolved version on diff.rs.
fn diff_link(pkg: &cargoscope_core::Package, to: &str) -> String {
    if !is_crates_io(pkg) || to == "-" || to == "?" {
        return format!("<code>{}</code>", escape_html(to));
    }
    format!(
        "<a href=\"https://diff.rs/{}/{}/{}\" target=\"_blank\" rel=\"noopener noreferrer\" title=\"What changed since {}\"><code>{}</code></a>",
        escape_html(&pkg.name),
        escape_html(&pkg.version),
        escape_html(to),
        escape_html(&pkg.version),
        escape_html(to)
    )
}

struct ReportCounts {
    active_vulnerabilities: usize,
    informational_advisories: usize,
    ignored_advisories: usize,
    policy_errors: usize,
    policy_warnings: usize,
    likely_unused: usize,
    possibly_unused: usize,
    ignored_unused: usize,
    yanked: usize,
    outdated_total: usize,
    outdated_direct: usize,
    duplicates: usize,
    packages: usize,
}

impl ReportCounts {
    fn from_report(report: &Report) -> Self {
        let ignored_advisories = report
            .advisories
            .iter()
            .filter(|f| f.ignored.is_some())
            .count();
        let active_vulnerabilities = report
            .advisories
            .iter()
            .filter(|f| f.ignored.is_none() && matches!(f.kind, AdvisoryKind::Vulnerability))
            .count();
        let informational_advisories = report
            .advisories
            .iter()
            .filter(|f| f.ignored.is_none() && matches!(f.kind, AdvisoryKind::Informational(_)))
            .count();

        let (policy_errors, policy_warnings) = match &report.policy {
            Some(violations) => {
                let errors = violations
                    .iter()
                    .filter(|v| v.level == ViolationLevel::Error)
                    .count();
                (errors, violations.len() - errors)
            }
            None => (0, 0),
        };

        let active_unused: Vec<_> = report
            .unused
            .iter()
            .filter(|f| f.ignored.is_none())
            .collect();
        let likely_unused = active_unused
            .iter()
            .filter(|f| f.confidence == UnusedConfidence::Likely)
            .count();
        let possibly_unused = active_unused.len() - likely_unused;
        let ignored_unused = report.unused.len() - active_unused.len();

        let yanked = report
            .package_info
            .iter()
            .filter(|info| info.yanked == Some(true))
            .count();
        let outdated_total = report
            .package_info
            .iter()
            .filter(|info| info.outdated)
            .count();
        let outdated_direct = report
            .package_info
            .iter()
            .zip(&report.inventory.packages)
            .filter(|(info, package)| info.outdated && package.direct)
            .count();

        Self {
            active_vulnerabilities,
            informational_advisories,
            ignored_advisories,
            policy_errors,
            policy_warnings,
            likely_unused,
            possibly_unused,
            ignored_unused,
            yanked,
            outdated_total,
            outdated_direct,
            duplicates: report.inventory.duplicates().len(),
            packages: report.inventory.packages.len(),
        }
    }
}

/// Renders the scan report as a self-contained HTML5 document, terminated by a
/// newline.
#[must_use]
///
/// `now` (Unix seconds) is the scan time, to list versions published shortly
/// before it; `None` lists none.
pub fn render_html(
    project_root: &Path,
    report: &Report,
    show_uncertain: bool,
    now: Option<u64>,
) -> String {
    let counts = ReportCounts::from_report(report);
    // `.` names nothing: show the project's real directory.
    let target = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf())
        .display()
        .to_string();
    let escaped_target = escape_html(&target);
    let mut out = String::with_capacity(16 * 1024);

    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    let _ = writeln!(
        out,
        "<title>CargoScope Report &mdash; {escaped_target}</title>"
    );
    out.push_str("<style>\n");
    out.push_str(STYLE_CSS);
    out.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

    render_header(&mut out, &escaped_target, report, &counts);
    render_kpi_grid(&mut out, report, &counts);
    render_actions(&mut out, report, now);
    render_controls(&mut out);
    render_warnings(&mut out, &report.warnings);

    out.push_str("<main>\n");
    render_advisories_section(&mut out, report);
    render_policy_section(&mut out, report);
    render_unused_section(&mut out, report, show_uncertain, &counts);
    render_versions_licenses_section(&mut out, report, &counts);
    render_supply_chain_section(&mut out, report, now);
    render_graph_section(&mut out, report);
    render_inventory_section(&mut out, report);
    out.push_str("</main>\n");

    let _ = writeln!(
        out,
        "<footer>Generated locally by CargoScope {} &middot; offline, no data uploaded.</footer>",
        escape_html(VERSION)
    );
    out.push_str("</div>\n<script>\n");
    out.push_str(FILTER_JS);
    out.push_str("</script>\n</body>\n</html>\n");
    out
}

fn render_header(out: &mut String, escaped_target: &str, report: &Report, counts: &ReportCounts) {
    let (status, tone) = if counts.active_vulnerabilities > 0 {
        let n = counts.active_vulnerabilities;
        (
            format!(
                "{n} {}",
                if n == 1 {
                    "vulnerability"
                } else {
                    "vulnerabilities"
                }
            ),
            "danger",
        )
    } else if counts.policy_errors > 0 {
        let n = counts.policy_errors;
        (
            format!(
                "{n} {}",
                if n == 1 {
                    "policy error"
                } else {
                    "policy errors"
                }
            ),
            "danger",
        )
    } else if counts.likely_unused > 0 || counts.yanked > 0 || counts.policy_warnings > 0 {
        ("needs attention".to_owned(), "warn")
    } else {
        ("all clear".to_owned(), "ok")
    };
    let advisory_date = report.advisory_db_date.as_deref().unwrap_or("never");
    let registry_date = report.registry_date.as_deref().unwrap_or("never");
    let name = escaped_target
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(escaped_target);

    out.push_str("<header class=\"report-header\">\n<div class=\"brand\">");
    out.push_str(LOGO_SVG);
    let _ = writeln!(
        out,
        "<span>CargoScope</span><span class=\"ver\">{}</span></div>",
        escape_html(VERSION)
    );
    let _ = writeln!(
        out,
        "<div class=\"title-row\"><h1>{name}</h1><span class=\"status status-{tone}\"><span class=\"dot\"></span>{}</span></div>",
        escape_html(&status)
    );
    let _ = writeln!(out, "<p class=\"path\"><code>{escaped_target}</code></p>");
    let _ = writeln!(
        out,
        "<p class=\"summary-line\">{}</p>",
        escape_html(&summary(report))
    );
    let _ = write!(
        out,
        "<p class=\"meta\">RustSec {} &middot; crates.io {} &middot; checks: {}",
        escape_html(advisory_date),
        escape_html(registry_date),
        escape_html(&report.checks.enabled().join(", "))
    );
    if report.unused_precise {
        out.push_str(" &middot; unused confirmed with <code>--precise</code>");
    }
    out.push_str("</p>\n</header>\n");
}

const LOGO_SVG: &str = "<svg width=\"22\" height=\"22\" viewBox=\"0 0 96 96\" aria-hidden=\"true\"><circle cx=\"48\" cy=\"48\" r=\"38\" fill=\"none\" stroke=\"#E2622B\" stroke-width=\"7\"/><path d=\"M48 2v16M48 78v16M2 48h16M78 48h16\" stroke=\"#E2622B\" stroke-width=\"7\" stroke-linecap=\"round\"/><rect x=\"35\" y=\"35\" width=\"26\" height=\"26\" rx=\"3\" fill=\"#E2622B\"/></svg>";

/// A shell command with a copy button.
fn command_html(command: &str, note: &str) -> String {
    let escaped = escape_html(command);
    format!(
        "<div class=\"cmd\"><code>{escaped}</code><button class=\"copy\" type=\"button\" data-copy=\"{escaped}\">Copy</button></div><p class=\"cmd-note muted small\">{}</p>",
        escape_html(note)
    )
}

/// What to do about the findings, most urgent first, with the commands
/// that do it.
fn render_actions(out: &mut String, report: &Report, now: Option<u64>) {
    let mut items: Vec<String> = Vec::new();

    // Vulnerable crates: the version that fixes all their advisories.
    let mut vulnerable: std::collections::BTreeMap<usize, Vec<&cargoscope_core::AdvisoryFinding>> =
        std::collections::BTreeMap::new();
    for finding in &report.advisories {
        if finding.ignored.is_none() && matches!(finding.kind, AdvisoryKind::Vulnerability) {
            vulnerable.entry(finding.package).or_default().push(finding);
        }
    }
    if !vulnerable.is_empty() {
        let mut crates: Vec<(usize, Vec<&cargoscope_core::AdvisoryFinding>)> =
            vulnerable.into_iter().collect();
        crates.sort_by_key(|(_, findings)| {
            (
                findings.iter().map(|f| f.relevance).min(),
                std::cmp::Reverse(findings.iter().map(|f| severity_rank(f)).max()),
            )
        });
        let mut lines = String::new();
        for (index, findings) in crates.iter().take(6) {
            let pkg = &report.inventory.packages[*index];
            let worst = findings.iter().filter_map(|f| f.severity).max();
            let worst = worst.map_or("unknown severity", |severity| match severity {
                cargoscope_core::Severity::Critical => "critical",
                cargoscope_core::Severity::High => "high",
                cargoscope_core::Severity::Medium => "medium",
                cargoscope_core::Severity::Low => "low",
                cargoscope_core::Severity::None => "no severity",
            });
            let count = findings.len();
            let advisories = format!(
                "{count} {} advisor{}",
                worst,
                if count == 1 { "y" } else { "ies" }
            );
            let unlikely = if findings
                .iter()
                .all(|f| f.relevance == AdvisoryRelevance::Unlikely)
            {
                " <span class=\"badge badge-muted\">unlikely</span>"
            } else {
                ""
            };
            let (fix, _) = crate::terminal::crate_fix(findings, &pkg.version);
            let line = match fix {
                Some(version) => format!(
                    "Update {} {} &rarr; {}: fixes {advisories}{unlikely}",
                    crate_name_html(pkg),
                    escape_html(&pkg.version),
                    diff_link(pkg, &version.to_string())
                ),
                None => format!(
                    "No fixed version of {} {} yet ({advisories}){unlikely}: consider replacing it",
                    crate_name_html(pkg),
                    escape_html(&pkg.version)
                ),
            };
            let _ = write!(lines, "<li>{line}</li>");
        }
        if crates.len() > 6 {
            let _ = write!(
                lines,
                "<li class=\"muted\">and {} more in Security advisories</li>",
                crates.len() - 6
            );
        }
        items.push(format!(
            "<div class=\"action action-danger\"><h3>Fix {} vulnerable crate{}</h3><ul>{lines}</ul>{}</div>",
            crates.len(),
            if crates.len() == 1 { "" } else { "s" },
            command_html("cargoscope fix --advisories", "preview; add --apply to write")
        ));
    }

    let yanked: Vec<&cargoscope_core::Package> = report
        .package_info
        .iter()
        .zip(&report.inventory.packages)
        .filter(|(info, _)| info.yanked == Some(true))
        .map(|(_, pkg)| pkg)
        .collect();
    if !yanked.is_empty() {
        let names: Vec<String> = yanked.iter().map(|pkg| package_cell(pkg)).collect();
        let command = format!(
            "cargo update {}",
            yanked
                .iter()
                .map(|pkg| format!("-p {}@{}", pkg.name, pkg.version))
                .collect::<Vec<_>>()
                .join(" ")
        );
        items.push(format!(
            "<div class=\"action action-danger\"><h3>Replace {} yanked version{}</h3><p>{}</p>{}</div>",
            yanked.len(),
            if yanked.len() == 1 { "" } else { "s" },
            names.join(", "),
            command_html(&command, "moves to the next published version")
        ));
    }

    let unused: Vec<&cargoscope_core::UnusedFinding> = report
        .unused
        .iter()
        .filter(|f| f.ignored.is_none() && f.confidence == UnusedConfidence::Likely)
        .collect();
    if !unused.is_empty() {
        let names: Vec<String> = unused
            .iter()
            .map(|f| {
                format!(
                    "<code>{}</code> <span class=\"muted\">in {}</span>",
                    escape_html(&f.dependency),
                    escape_html(&f.manifest)
                )
            })
            .collect();
        items.push(format!(
            "<div class=\"action action-warn\"><h3>Remove {} unused dependenc{}</h3><p>{}</p>{}</div>",
            unused.len(),
            if unused.len() == 1 { "y" } else { "ies" },
            names.join(", "),
            command_html("cargoscope fix", "preview; add --apply to write")
        ));
    }

    let recent = crate::recent_releases(report, now);
    if !recent.is_empty() {
        let names: Vec<String> = recent
            .iter()
            .map(|&(index, hours)| {
                format!(
                    "{} <span class=\"muted\">{}</span>",
                    package_cell(&report.inventory.packages[index]),
                    escape_html(&crate::describe_age(hours))
                )
            })
            .collect();
        items.push(format!(
            "<div class=\"action action-warn\"><h3>Review {} recent release{}</h3><p>{}</p><p class=\"muted small\">Compromised releases are usually caught within days.</p></div>",
            recent.len(),
            if recent.len() == 1 { "" } else { "s" },
            names.join(", ")
        ));
    }

    let outdated: Vec<(&cargoscope_core::Package, &cargoscope_core::PackageInfo)> = report
        .inventory
        .packages
        .iter()
        .zip(&report.package_info)
        .filter(|(pkg, info)| info.outdated && pkg.direct)
        .collect();
    if !outdated.is_empty() {
        let compatible = outdated
            .iter()
            .filter(|(pkg, info)| info.compatible_upgrade(&pkg.version).is_some())
            .count();
        items.push(format!(
            "<div class=\"action\"><h3>Update {} outdated direct dependenc{}</h3><p class=\"muted\">{compatible} with a compatible update; details in Versions and licenses.</p>{}</div>",
            outdated.len(),
            if outdated.len() == 1 { "y" } else { "ies" },
            command_html("cargoscope fix --updates", "preview; add --apply to write")
        ));
    }

    out.push_str("<section class=\"actions\" aria-label=\"What to do\">\n<h2>What to do</h2>\n");
    if items.is_empty() {
        out.push_str("<p class=\"empty empty-ok\">Nothing to do: no vulnerable, yanked, unused or outdated dependency.</p>\n");
    } else {
        out.push_str("<div class=\"action-grid\">\n");
        for item in items {
            out.push_str(&item);
            out.push('\n');
        }
        out.push_str("</div>\n");
    }
    out.push_str("</section>\n");
}

fn render_kpi_grid(out: &mut String, report: &Report, counts: &ReportCounts) {
    out.push_str("<section class=\"kpi-grid\" aria-label=\"Summary metrics\">\n");
    render_kpi_card(
        out,
        "#advisories",
        "Security advisories",
        if !report.checks.advisories {
            "skipped".to_owned()
        } else {
            counts.active_vulnerabilities.to_string()
        },
        &format!(
            "{} informational &middot; {} ignored",
            counts.informational_advisories, counts.ignored_advisories
        ),
        if counts.active_vulnerabilities > 0 {
            "kpi-danger"
        } else {
            "kpi-ok"
        },
    );
    let policy_detail = if report.policy.is_none() {
        "no policy file".to_owned()
    } else {
        format!("{} warning(s)", counts.policy_warnings)
    };
    render_kpi_card(
        out,
        "#policy",
        "Policy violations",
        if !report.checks.policy {
            "skipped".to_owned()
        } else if report.policy.is_none() {
            "none".to_owned()
        } else {
            counts.policy_errors.to_string()
        },
        &policy_detail,
        if counts.policy_errors > 0 {
            "kpi-danger"
        } else if counts.policy_warnings > 0 {
            "kpi-warn"
        } else {
            "kpi-ok"
        },
    );
    render_kpi_card(
        out,
        "#unused",
        "Likely unused",
        if !report.checks.unused {
            "skipped".to_owned()
        } else {
            counts.likely_unused.to_string()
        },
        &format!(
            "{} possibly-unused &middot; {} ignored",
            counts.possibly_unused, counts.ignored_unused
        ),
        if counts.likely_unused > 0 {
            "kpi-warn"
        } else {
            "kpi-ok"
        },
    );
    render_kpi_card(
        out,
        "#versions",
        "Versions",
        if !report.checks.versions {
            "skipped".to_owned()
        } else {
            format!("{} yanked", counts.yanked)
        },
        &format!(
            "{} outdated direct ({} total)",
            counts.outdated_direct, counts.outdated_total
        ),
        if counts.yanked > 0 {
            "kpi-danger"
        } else if counts.outdated_direct > 0 {
            "kpi-warn"
        } else {
            "kpi-ok"
        },
    );
    render_kpi_card(
        out,
        "#graph",
        "Packages",
        counts.packages.to_string(),
        &format!("{} multi-version crate(s)", counts.duplicates),
        if counts.duplicates > 0 {
            "kpi-info"
        } else {
            "kpi-ok"
        },
    );
    out.push_str("</section>\n");
}

fn render_kpi_card(
    out: &mut String,
    href: &str,
    label_text: &str,
    value_text: String,
    detail_html: &str,
    tone_class: &str,
) {
    let _ = writeln!(
        out,
        "<a class=\"kpi-card {tone_class}\" href=\"{href}\">\
<div class=\"kpi-label\">{label_text}</div>\
<div class=\"kpi-value\">{}</div>\
<div class=\"kpi-detail\">{detail_html}</div></a>",
        escape_html(&value_text)
    );
}

fn render_controls(out: &mut String) {
    out.push_str(
        "<div class=\"controls\" role=\"search\">\n\
<input id=\"search-input\" type=\"search\" placeholder=\"Filter findings, crates, licenses, paths...\" aria-label=\"Filter report rows\">\n\
<div class=\"tabs\" role=\"tablist\" aria-label=\"Sections\">\n\
<button class=\"tab is-active\" data-section=\"all\" type=\"button\">All</button>\n\
<button class=\"tab\" data-section=\"advisories\" type=\"button\">Advisories</button>\n\
<button class=\"tab\" data-section=\"policy\" type=\"button\">Policy</button>\n\
<button class=\"tab\" data-section=\"unused\" type=\"button\">Unused</button>\n\
<button class=\"tab\" data-section=\"versions\" type=\"button\">Versions and licenses</button>\n\
<button class=\"tab\" data-section=\"supply-chain\" type=\"button\">Supply chain</button>\n\
<button class=\"tab\" data-section=\"graph\" type=\"button\">Graph</button>\n\
<button class=\"tab\" data-section=\"inventory\" type=\"button\">Inventory</button>\n\
</div>\n\
<div class=\"toggles\" aria-label=\"Quick filters\">\n\
<label><input type=\"checkbox\" data-filter=\"vulnerabilities\"> Vulnerabilities only</label>\n\
<label><input type=\"checkbox\" data-filter=\"likely\"> Hide unlikely</label>\n\
<label><input type=\"checkbox\" data-filter=\"direct\"> Direct dependencies only</label>\n\
</div>\n</div>\n",
    );
}

fn render_warnings(out: &mut String, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    out.push_str(
        "<aside class=\"alert-box alert-warn\" role=\"alert\">\n<strong>Warnings</strong>\n<ul>\n",
    );
    for warning in warnings {
        let _ = writeln!(out, "<li>{}</li>", escape_html(warning));
    }
    out.push_str("</ul>\n</aside>\n");
}

/// Sort key of a severity cell: worst first when sorted descending.
fn severity_rank(finding: &cargoscope_core::AdvisoryFinding) -> u8 {
    if finding.ignored.is_some() || !matches!(finding.kind, AdvisoryKind::Vulnerability) {
        return 0;
    }
    match finding.severity {
        Some(cargoscope_core::Severity::Critical) => 5,
        Some(cargoscope_core::Severity::High) => 4,
        Some(cargoscope_core::Severity::Medium) => 3,
        Some(cargoscope_core::Severity::Low) => 2,
        Some(cargoscope_core::Severity::None) | None => 1,
    }
}

fn render_advisories_section(out: &mut String, report: &Report) {
    out.push_str(
        "<section id=\"advisories\" class=\"report-section\" data-section=\"advisories\">\n",
    );
    let _ = writeln!(
        out,
        "<h2>Security advisories <span class=\"count-pill\">{}</span></h2>",
        report.advisories.len()
    );
    if !report.checks.advisories {
        out.push_str("<p class=\"empty\">Advisories check was skipped.</p>\n</section>\n");
        return;
    }
    if report.advisories.is_empty() {
        out.push_str("<p class=\"empty empty-ok\">No known advisory found. This does not mean the dependencies are safe.</p>\n</section>\n");
        return;
    }

    out.push_str(
        "<div class=\"table-wrap\"><table>\n<thead><tr>\
<th>ID</th><th>Severity</th><th>Package</th><th>Title and chain</th><th>Fix</th>\
</tr></thead>\n<tbody>\n",
    );
    // Vulnerabilities first, worst first; then notices; ignored ones last.
    let mut ordered: Vec<&cargoscope_core::AdvisoryFinding> = report.advisories.iter().collect();
    ordered.sort_by_key(|finding| {
        (
            finding.ignored.is_some(),
            !matches!(finding.kind, cargoscope_core::AdvisoryKind::Vulnerability),
            finding.relevance,
            std::cmp::Reverse(finding.severity),
        )
    });
    for finding in ordered {
        let package = &report.inventory.packages[finding.package];
        let sev_text = label(finding);
        let sev_class = if finding.ignored.is_some() {
            "badge-muted"
        } else {
            match sev_text {
                "critical" | "high" => "badge-danger",
                "medium" | "unsound" => "badge-warn",
                "unknown severity" => "badge-warn",
                _ => "badge-info",
            }
        };
        let id_escaped = escape_html(&finding.id);
        let id_cell = match safe_http_url(finding.url.as_deref()) {
            Some(url) => format!(
                "<a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\"><code>{id_escaped}</code></a>",
                escape_html(url)
            ),
            None => format!("<code>{id_escaped}</code>"),
        };
        let aliases_html = if finding.aliases.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"muted small\">{}</div>",
                escape_html(&finding.aliases.join(", "))
            )
        };
        let chain_html = chain(&report.inventory, finding.package).map_or_else(String::new, |c| {
            format!(
                "<div class=\"chain\">via <code>{}</code></div>",
                escape_html(&c)
            )
        });
        let relevance_html = if finding.relevance != AdvisoryRelevance::AffectsYou {
            let badge_class = match finding.relevance {
                AdvisoryRelevance::AffectsYou => "badge-danger",
                AdvisoryRelevance::Possibly => "badge-info",
                AdvisoryRelevance::Unlikely => "badge-muted",
            };
            let reason = finding
                .relevance_reason
                .as_deref()
                .map(|r| format!(" <span class=\"muted\">{}</span>", escape_html(r)))
                .unwrap_or_default();
            format!(
                "<div class=\"small\"><span class=\"badge {badge_class}\">{}</span>{reason}</div>",
                escape_html(finding.relevance.as_str())
            )
        } else {
            String::new()
        };
        let fix_html = if let Some(reason) = &finding.ignored {
            format!(
                "<span class=\"badge badge-muted\">ignored</span> <span class=\"small\">{}</span>",
                escape_html(reason)
            )
        } else if finding.patched.is_empty() {
            "<span class=\"muted\">no fixed version available</span>".to_owned()
        } else {
            format!(
                "upgrade to <code>{}</code>",
                escape_html(&finding.patched.join(" or "))
            )
        };
        let _ = writeln!(
            out,
            "<tr class=\"filter-row\" data-relevance=\"{}\" data-kind=\"{}\">\
<td>{id_cell}{aliases_html}</td>\
<td data-sort=\"{}\"><span class=\"badge {sev_class}\">{}</span></td>\
<td>{}</td>\
<td>{}{chain_html}{relevance_html}</td>\
<td>{fix_html}</td>\
</tr>",
            finding.relevance.as_str(),
            if matches!(finding.kind, AdvisoryKind::Vulnerability) {
                "vulnerability"
            } else {
                "notice"
            },
            severity_rank(finding),
            escape_html(sev_text),
            package_cell(package),
            escape_html(&finding.title),
        );
    }
    out.push_str("</tbody></table></div>\n</section>\n");
}

fn render_policy_section(out: &mut String, report: &Report) {
    out.push_str("<section id=\"policy\" class=\"report-section\" data-section=\"policy\">\n");
    if !report.checks.policy {
        out.push_str("<h2>Policy violations</h2>\n<p class=\"empty\">Policy check was skipped.</p>\n</section>\n");
        return;
    }
    let Some(violations) = &report.policy else {
        out.push_str("<h2>Policy violations</h2>\n<p class=\"empty\">No cargoscope.toml or deny.toml policy configured.</p>\n</section>\n");
        return;
    };
    let _ = writeln!(
        out,
        "<h2>Policy violations <span class=\"count-pill\">{}</span></h2>",
        violations.len()
    );
    if violations.is_empty() {
        out.push_str(
            "<p class=\"empty empty-ok\">All configured policy rules passed.</p>\n</section>\n",
        );
        return;
    }

    out.push_str(
        "<div class=\"table-wrap\"><table>\n<thead><tr>\
<th>Rule</th><th>Level</th><th>Package</th><th>Message and chain</th>\
</tr></thead>\n<tbody>\n",
    );
    for violation in violations {
        let package = &report.inventory.packages[violation.package];
        let level_class = match violation.level {
            ViolationLevel::Error => "badge-danger",
            ViolationLevel::Warning => "badge-warn",
        };
        let chain_html =
            chain(&report.inventory, violation.package).map_or_else(String::new, |c| {
                format!(
                    "<div class=\"chain\">via <code>{}</code></div>",
                    escape_html(&c)
                )
            });
        let _ = writeln!(
            out,
            "<tr class=\"filter-row\">\
<td><code>{}</code></td>\
<td><span class=\"badge {level_class}\">{}</span></td>\
<td>{}</td>\
<td>{}{chain_html}</td>\
</tr>",
            escape_html(violation.rule.as_str()),
            escape_html(violation.level.as_str()),
            package_cell(package),
            escape_html(&violation.message),
        );
    }
    out.push_str("</tbody></table></div>\n</section>\n");
}

fn render_unused_section(
    out: &mut String,
    report: &Report,
    show_uncertain: bool,
    counts: &ReportCounts,
) {
    out.push_str("<section id=\"unused\" class=\"report-section\" data-section=\"unused\">\n");
    let _ = writeln!(
        out,
        "<h2>Unused dependencies <span class=\"count-pill\">{} likely</span></h2>",
        counts.likely_unused
    );
    if !report.checks.unused {
        out.push_str("<p class=\"empty\">Unused-dependency check was skipped.</p>\n</section>\n");
        return;
    }

    let visible: Vec<_> = report
        .unused
        .iter()
        .filter(|f| {
            f.ignored.is_none() && (show_uncertain || f.confidence == UnusedConfidence::Likely)
        })
        .collect();
    let ignored: Vec<_> = report
        .unused
        .iter()
        .filter(|f| f.ignored.is_some())
        .collect();

    if visible.is_empty() {
        out.push_str("<p class=\"empty empty-ok\">No active unused dependencies reported in this mode.</p>\n");
    } else {
        out.push_str(
            "<div class=\"table-wrap\"><table>\n<thead><tr>\
<th>Dependency</th><th>Confidence</th><th>Section and manifest</th><th>Evidence</th>\
</tr></thead>\n<tbody>\n",
        );
        for finding in visible {
            let conf_class = match finding.confidence {
                UnusedConfidence::Likely => "badge-warn",
                UnusedConfidence::Possibly => "badge-info",
            };
            let renamed_html = if finding.package == finding.dependency {
                String::new()
            } else {
                format!(
                    " <span class=\"muted\">(package <code>{}</code>)</span>",
                    escape_html(&finding.package)
                )
            };
            let mut evidence_html = String::from("<ul class=\"evidence\">");
            for item in &finding.evidence {
                let _ = write!(evidence_html, "<li>{}</li>", escape_html(item));
            }
            evidence_html.push_str("</ul>");
            let _ = writeln!(
                out,
                "<tr class=\"filter-row\">\
<td><code>{}</code>{renamed_html}</td>\
<td><span class=\"badge {conf_class}\">{}</span></td>\
<td><code>[{}]</code> in <code>{}</code> <span class=\"muted\">({})</span></td>\
<td>{evidence_html}</td>\
</tr>",
                escape_html(&finding.dependency),
                escape_html(finding.confidence.as_str()),
                escape_html(finding.kind.section()),
                escape_html(&finding.manifest),
                escape_html(&finding.declared_by),
            );
        }
        out.push_str("</tbody></table></div>\n");
    }

    if counts.possibly_unused > 0 && !show_uncertain {
        let noun = if counts.possibly_unused == 1 {
            "dependency"
        } else {
            "dependencies"
        };
        let _ = writeln!(
            out,
            "<p class=\"muted note\">{} possibly-unused {noun} hidden; re-run with <code>--show-uncertain</code> to include them.</p>",
            counts.possibly_unused
        );
    }

    if !ignored.is_empty() {
        let _ = writeln!(
            out,
            "<details class=\"sub-details\"><summary>Ignored unused dependencies ({})</summary>\n<ul>",
            ignored.len()
        );
        for finding in ignored {
            let _ = writeln!(
                out,
                "<li><code>{}</code> in <code>{}</code> &mdash; {}</li>",
                escape_html(&finding.dependency),
                escape_html(&finding.manifest),
                escape_html(finding.ignored.as_deref().unwrap_or_default())
            );
        }
        out.push_str("</ul>\n</details>\n");
    }
    out.push_str("</section>\n");
}

fn render_versions_licenses_section(out: &mut String, report: &Report, counts: &ReportCounts) {
    out.push_str("<section id=\"versions\" class=\"report-section\" data-section=\"versions\">\n");
    out.push_str("<h2>Versions and licenses</h2>\n<div class=\"split-grid\">\n");

    let reg_pkgs = registry_packages(report);
    out.push_str("<div class=\"panel\">\n<h3>Licenses</h3>\n");
    if !report.checks.licenses {
        out.push_str("<p class=\"empty\">Licenses check was skipped.</p>\n");
    } else if reg_pkgs.is_empty() {
        out.push_str("<p class=\"empty\">No registry packages in lockfile.</p>\n");
    } else {
        out.push_str(
            "<div class=\"table-wrap\"><table>\n<thead><tr><th>License</th><th>Packages</th></tr></thead>\n<tbody>\n",
        );
        for (license, count) in sorted_license_counts(&reg_pkgs) {
            let _ = writeln!(
                out,
                "<tr class=\"filter-row\"><td><code>{}</code></td><td>{count}</td></tr>",
                escape_html(license)
            );
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</div>\n");

    out.push_str("<div class=\"panel\">\n<h3>Yanked and outdated direct dependencies</h3>\n");
    if !report.checks.versions {
        out.push_str("<p class=\"empty\">Versions check was skipped.</p>\n");
    } else {
        let yanked: Vec<usize> = reg_pkgs
            .iter()
            .filter(|(_, info)| info.yanked == Some(true))
            .map(|(index, _)| *index)
            .collect();
        if !yanked.is_empty() {
            out.push_str("<div class=\"alert-box alert-danger\"><strong>Yanked versions in use</strong><ul>\n");
            for index in yanked {
                let pkg = &report.inventory.packages[index];
                let via = chain(&report.inventory, index).map_or_else(String::new, |c| {
                    format!(
                        " <span class=\"muted\">via <code>{}</code></span>",
                        escape_html(&c)
                    )
                });
                let _ = writeln!(
                    out,
                    "<li><code>{}</code> {}{via}</li>",
                    escape_html(&pkg.name),
                    escape_html(&pkg.version)
                );
            }
            out.push_str("</ul></div>\n");
        }

        let direct_outdated: Vec<_> = reg_pkgs
            .iter()
            .filter(|(index, info)| info.outdated && report.inventory.packages[*index].direct)
            .copied()
            .collect();
        if direct_outdated.is_empty() {
            let _ = writeln!(
                out,
                "<p class=\"empty empty-ok\">0 outdated direct dependencies ({} total outdated).</p>",
                counts.outdated_total
            );
        } else {
            let _ = writeln!(
                out,
                "<p class=\"muted small\">{} direct outdated ({} total outdated across graph)</p>",
                direct_outdated.len(),
                counts.outdated_total
            );
            out.push_str(
                "<div class=\"table-wrap\"><table>\n<thead><tr><th>Package</th><th>Current</th><th>Compatible</th><th>Latest</th><th>Kind</th><th>Published</th></tr></thead>\n<tbody>\n",
            );
            for (index, info) in direct_outdated {
                let pkg = &report.inventory.packages[index];
                let kind = info.outdated_kind(&pkg.version);
                let kind_class = match kind {
                    OutdatedKind::Compatible => "badge-ok",
                    OutdatedKind::Breaking => "badge-danger",
                    OutdatedKind::Both => "badge-warn",
                    OutdatedKind::None => "badge-muted",
                };
                let compat_text = info.compatible_upgrade(&pkg.version).unwrap_or("-");
                let _ = writeln!(
                    out,
                    "<tr class=\"filter-row\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><span class=\"badge {kind_class}\">{}</span></td><td>{}</td></tr>",
                    crate_name_html(pkg),
                    escape_html(&pkg.version),
                    diff_link(pkg, compat_text),
                    diff_link(pkg, info.latest_version.as_deref().unwrap_or("?")),
                    escape_html(kind.as_str()),
                    escape_html(info.latest_published.as_deref().unwrap_or("-"))
                );
            }
            out.push_str("</tbody></table></div>\n");
        }
        render_maintenance_panel(out, report);
    }
    out.push_str("</div>\n</div>\n</section>\n");
}

fn render_maintenance_panel(out: &mut String, report: &Report) {
    let rows = crate::maintenance_rows(report);
    out.push_str("<h3>Maintenance of direct dependencies</h3>\n");
    if rows.is_empty() {
        out.push_str("<p class=\"empty empty-ok\">No archived, stale or single-owner direct dependency found.</p>\n");
        return;
    }
    out.push_str(
        "<div class=\"table-wrap\"><table>\n<thead><tr><th>Package</th><th>Concerns</th></tr></thead>\n<tbody>\n",
    );
    for (index, concerns) in rows {
        let pkg = &report.inventory.packages[index];
        let info = &report.package_info[index];
        let badges: Vec<String> = concerns
            .iter()
            .map(|&concern| {
                format!(
                    "<span class=\"badge badge-warn\">{}</span> {}",
                    escape_html(concern.as_str()),
                    escape_html(&crate::describe_concern(concern, info))
                )
            })
            .collect();
        let _ = writeln!(
            out,
            "<tr class=\"filter-row\"><td>{}</td><td>{}</td></tr>",
            package_cell(pkg),
            badges.join("<br>")
        );
    }
    out.push_str("</tbody></table></div>\n");
}

/// Recent releases, published audits and `unsafe` code.
fn render_supply_chain_section(out: &mut String, report: &Report, now: Option<u64>) {
    out.push_str(
        "<section id=\"supply-chain\" class=\"report-section\" data-section=\"supply-chain\">\n",
    );
    out.push_str("<h2>Supply chain</h2>\n<div class=\"split-grid\">\n");

    let recent = crate::recent_releases(report, now);
    let _ = writeln!(
        out,
        "<div class=\"panel\">\n<h3>Recent releases <span class=\"muted\">(last {} hours)</span></h3>",
        cargoscope_core::RECENT_RELEASE_HOURS
    );
    if !report.checks.versions || now.is_none() {
        out.push_str("<p class=\"empty\">Not checked.</p>\n");
    } else if recent.is_empty() {
        out.push_str("<p class=\"empty empty-ok\">No resolved version was published in the last 72 hours.</p>\n");
    } else {
        out.push_str("<p class=\"muted\">Compromised releases are usually caught within days: review these before relying on them.</p>\n");
        out.push_str(
            "<div class=\"table-wrap\"><table>\n<thead><tr><th>Package</th><th>Published</th><th>Pulled in by</th></tr></thead>\n<tbody>\n",
        );
        for (index, hours) in recent {
            let pkg = &report.inventory.packages[index];
            let via = chain(&report.inventory, index).unwrap_or_default();
            let _ = writeln!(
                out,
                "<tr class=\"filter-row\"><td>{}</td><td><span class=\"badge badge-warn\">{}</span></td><td><code>{}</code></td></tr>",
                package_cell(pkg),
                escape_html(&crate::describe_age(hours)),
                escape_html(&via)
            );
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</div>\n");

    out.push_str("<div class=\"panel\">\n<h3>Published audits <span class=\"muted\">(cargo-vet)</span></h3>\n");
    match crate::audit_coverage(report) {
        None => out.push_str(
            "<p class=\"empty\">No published audits downloaded; run <code>cargoscope update</code>.</p>\n",
        ),
        Some(coverage) => {
            let _ = writeln!(
                out,
                "<p><strong>{}</strong> of {} crates.io packages reviewed by an organisation, {} <span class=\"badge badge-ok\">safe-to-deploy</span>{}</p>",
                coverage.audited,
                coverage.counted,
                coverage.deploy,
                if coverage.organisations.is_empty() {
                    String::new()
                } else {
                    format!(
                        " <span class=\"muted\">&middot; {}</span>",
                        escape_html(&coverage.organisations.join(", "))
                    )
                }
            );
            let direct: Vec<usize> = report
                .package_info
                .iter()
                .enumerate()
                .filter(|(index, info)| {
                    let package = &report.inventory.packages[*index];
                    info.audits.is_some() && package.direct && !package.root
                })
                .map(|(index, _)| index)
                .collect();
            let mut direct = direct;
            direct.sort_by_key(|&index| {
                report.package_info[index]
                    .audits
                    .as_deref()
                    .is_none_or(<[cargoscope_core::Audit]>::is_empty)
            });
            if !direct.is_empty() {
                out.push_str(
                    "<div class=\"table-wrap\"><table>\n<thead><tr><th>Direct dependency</th><th>Audit of the version in use</th></tr></thead>\n<tbody>\n",
                );
                for index in direct {
                    let pkg = &report.inventory.packages[index];
                    let audits = report.package_info[index]
                        .audits
                        .as_deref()
                        .unwrap_or_default();
                    let cell = if audits.is_empty() {
                        "<span class=\"badge badge-warn\">not audited</span>".to_owned()
                    } else {
                        let best = audits.iter().map(|audit| audit.criteria).max();
                        let class = if best == Some(cargoscope_core::AuditCriteria::SafeToDeploy) {
                            "badge-ok"
                        } else {
                            "badge-warn"
                        };
                        let text = crate::describe_audits(audits);
                        let (criteria, by) = text.split_once(' ').unwrap_or((text.as_str(), ""));
                        format!(
                            "<span class=\"badge {class}\">{}</span> <span class=\"muted\">{}</span>",
                            escape_html(criteria),
                            escape_html(by)
                        )
                    };
                    let _ = writeln!(
                        out,
                        "<tr class=\"filter-row\"><td>{}</td><td>{cell}</td></tr>",
                        package_cell(pkg)
                    );
                }
                out.push_str("</tbody></table></div>\n");
            }
        }
    }
    out.push_str("</div>\n</div>\n");

    let (rows, counted) = crate::unsafe_rows(report);
    out.push_str("<div class=\"panel\">\n<h3>Unsafe code</h3>\n");
    if counted == 0 {
        out.push_str(
            "<p class=\"empty\">No dependency sources on disk; run <code>cargo fetch</code>.</p>\n",
        );
    } else if rows.is_empty() {
        let _ = writeln!(
            out,
            "<p class=\"empty empty-ok\">None of the {counted} dependencies with sources on disk uses <code>unsafe</code>.</p>"
        );
    } else {
        let _ = writeln!(
            out,
            "<p class=\"muted\">{} of {counted} dependencies with sources on disk use <code>unsafe</code>, counted from their sources.</p>",
            rows.len()
        );
        out.push_str(
            "<div class=\"table-wrap\"><table>\n<thead><tr><th>Package</th><th>Kind</th><th>Uses</th><th>Breakdown</th></tr></thead>\n<tbody>\n",
        );
        for (index, count) in rows {
            let pkg = &report.inventory.packages[index];
            let _ = writeln!(
                out,
                "<tr class=\"filter-row\"><td>{}</td><td>{}</td><td><strong>{}</strong></td><td>{}</td></tr>",
                package_cell(pkg),
                if pkg.direct { "direct" } else { "transitive" },
                count.total(),
                escape_html(&crate::describe_unsafe(&count))
            );
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</div>\n</section>\n");
}

/// An interactive map of the dependency graph: one dot per package, sized by
/// how many packages depend on it, laid out by the script in the page.
fn render_dependency_map(out: &mut String, report: &Report) {
    let packages = &report.inventory.packages;
    if packages.len() < 2 {
        return;
    }
    let mut dependents = vec![0usize; packages.len()];
    let mut edges = Vec::new();
    for (from, pkg) in packages.iter().enumerate() {
        for &to in &pkg.dependencies {
            if to < packages.len() && to != from {
                dependents[to] += 1;
                edges.push(format!("[{from},{to}]"));
            }
        }
    }
    let vulnerable: std::collections::BTreeSet<usize> = report
        .advisories
        .iter()
        .filter(|f| f.ignored.is_none() && matches!(f.kind, AdvisoryKind::Vulnerability))
        .map(|f| f.package)
        .collect();
    let nodes: Vec<String> = packages
        .iter()
        .enumerate()
        .map(|(index, pkg)| {
            let kind = if pkg.root {
                0
            } else if pkg.direct {
                1
            } else {
                2
            };
            format!(
                "[{},{},{kind},{},{}]",
                json_string(&pkg.name),
                json_string(&pkg.version),
                dependents[index],
                u8::from(vulnerable.contains(&index))
            )
        })
        .collect();
    out.push_str("<div class=\"panel map-panel\">\n<div class=\"map-head\"><h3>Dependency map</h3>\
<span class=\"muted small\">Each dot is a package, bigger when more packages depend on it. Scroll to zoom, drag to move, click a dot to see what it depends on and what depends on it.</span>\
<input id=\"map-search\" type=\"search\" placeholder=\"Find a crate\" aria-label=\"Find a crate in the map\"></div>\n\
<div class=\"map-wrap\"><canvas id=\"dep-map\" aria-label=\"Dependency map\"></canvas><div id=\"map-tip\" hidden></div></div>\n\
<div class=\"map-legend small muted\"><span><i class=\"lg lg-root\"></i>project</span><span><i class=\"lg lg-direct\"></i>direct</span><span><i class=\"lg lg-trans\"></i>transitive</span><span><i class=\"lg lg-vuln\"></i>vulnerable</span></div>\n");
    let _ = writeln!(
        out,
        "<script type=\"application/json\" id=\"graph-data\">{{\"nodes\":[{}],\"edges\":[{}]}}</script>\n</div>",
        nodes.join(","),
        edges.join(",")
    );
}

/// A JSON string that is also safe inside a `<script>` element.
fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn render_graph_section(out: &mut String, report: &Report) {
    out.push_str("<section id=\"graph\" class=\"report-section\" data-section=\"graph\">\n");
    out.push_str("<h2>Dependency graph</h2>\n");
    render_dependency_map(out, report);
    out.push_str("<div class=\"split-grid\">\n");

    let heavy = sorted_heavy_weights(report);
    out.push_str("<div class=\"panel\">\n<h3>Heaviest direct dependencies</h3>\n");
    if heavy.is_empty() {
        out.push_str("<p class=\"empty\">No direct dependency exclusively pulls extra transitive packages.</p>\n");
    } else {
        out.push_str(
            "<div class=\"table-wrap\"><table>\n<thead><tr><th>Package</th><th>Kinds</th><th>Exclusive / tree</th></tr></thead>\n<tbody>\n",
        );
        for (index, exclusive, tree) in heavy {
            let pkg = &report.inventory.packages[index];
            let kinds = kind_names(report, &pkg.name);
            let kinds_text = if kinds.is_empty() {
                "normal".to_owned()
            } else {
                kinds.join(", ")
            };
            let _ = writeln!(
                out,
                "<tr class=\"filter-row\"><td>{}</td><td>{}</td><td><strong>{exclusive}</strong> / {tree}</td></tr>",
                package_cell(pkg),
                escape_html(&kinds_text)
            );
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</div>\n");

    let duplicates = report.inventory.duplicates();
    out.push_str("<div class=\"panel\">\n<h3>Crates in several versions</h3>\n");
    if duplicates.is_empty() {
        out.push_str(
            "<p class=\"empty empty-ok\">No duplicate crate versions in Cargo.lock.</p>\n",
        );
    } else {
        out.push_str(
            "<div class=\"table-wrap\"><table>\n<thead><tr><th>Crate</th><th>Versions and the chains that pull older ones</th></tr></thead>\n<tbody>\n",
        );
        for (name, indices) in duplicates {
            let versions: Vec<&str> = indices
                .iter()
                .map(|&idx| report.inventory.packages[idx].version.as_str())
                .collect();
            let mut chains_html = String::new();
            for &idx in &indices[..indices.len() - 1] {
                if let Some(c) = chain(&report.inventory, idx) {
                    let note = report
                        .inventory
                        .path_to(idx)
                        .and_then(|path| path.get(1).copied())
                        .map_or("", |first| {
                            kind_note(report, &report.inventory.packages[first].name)
                        });
                    let _ = write!(
                        chains_html,
                        "<div class=\"chain\">{} via <code>{}</code>{}</div>",
                        escape_html(&report.inventory.packages[idx].version),
                        escape_html(&c),
                        escape_html(note)
                    );
                }
            }
            let _ = writeln!(
                out,
                "<tr class=\"filter-row\"><td><code>{}</code></td><td><code>{}</code>{chains_html}</td></tr>",
                escape_html(&name),
                escape_html(&versions.join(", "))
            );
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</div>\n</div>\n</section>\n");
}

fn render_inventory_section(out: &mut String, report: &Report) {
    out.push_str(
        "<section id=\"inventory\" class=\"report-section\" data-section=\"inventory\">\n",
    );
    let _ = writeln!(
        out,
        "<h2>Resolved packages <span class=\"count-pill\">{}</span></h2>",
        report.inventory.packages.len()
    );
    out.push_str(
        "<div class=\"table-wrap\"><table>\n<thead><tr>\
<th>Package</th><th>Version</th><th>Scope</th><th>License</th><th>Status</th><th>Path from root</th>\
</tr></thead>\n<tbody>\n",
    );
    for (index, pkg) in report.inventory.packages.iter().enumerate() {
        let pkg_scope = scope(pkg);
        let scope_class = match pkg_scope {
            "root" => "badge-info",
            "direct" => "badge-ok",
            _ => "badge-muted",
        };
        let info = report.package_info.get(index);
        let license = info.and_then(|i| i.license.as_deref()).unwrap_or("-");
        let mut status_parts = Vec::new();
        if info.is_some_and(|i| i.yanked == Some(true)) {
            status_parts.push("<span class=\"badge badge-danger\">YANKED</span>".to_owned());
        }
        if let Some(info) = info
            && let Some(targets) = format_outdated_targets(&pkg.version, info)
        {
            status_parts.push(format!("&rarr; <code>{}</code>", escape_html(&targets)));
        }
        let status_html = if status_parts.is_empty() {
            "<span class=\"muted\">-</span>".to_owned()
        } else {
            status_parts.join(" ")
        };
        let path_html = if pkg.root {
            "<span class=\"muted\">root</span>".to_owned()
        } else if let Some(c) = chain(&report.inventory, index) {
            format!("<code>{}</code>", escape_html(&c))
        } else {
            "<span class=\"muted\">unreachable</span>".to_owned()
        };
        let _ = writeln!(
            out,
            "<tr class=\"filter-row\">\
<td>{}</td>\
<td>{}</td>\
<td><span class=\"badge {scope_class}\">{pkg_scope}</span></td>\
<td><code>{}</code></td>\
<td>{status_html}</td>\
<td>{path_html}</td>\
</tr>",
            crate_name_html(pkg),
            escape_html(&pkg.version),
            escape_html(license),
        );
    }
    out.push_str("</tbody></table></div>\n</section>\n");
}

const STYLE_CSS: &str = r#":root {
  --bg: #fafaf9;
  --surface: #ffffff;
  --surface-alt: #f2f1ef;
  --border: #e6e4e0;
  --text: #1c1b19;
  --muted: #6f6c66;
  --accent: #c2541f;
  --danger: #c4314b;
  --danger-bg: rgba(196, 49, 75, 0.1);
  --warn: #9a6400;
  --warn-bg: rgba(178, 120, 0, 0.12);
  --ok: #2f7d46;
  --ok-bg: rgba(47, 125, 70, 0.1);
  --info: #3b6fb6;
  --info-bg: rgba(59, 111, 182, 0.1);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0c0d0f;
    --surface: #131417;
    --surface-alt: #1b1d21;
    --border: #24272c;
    --text: #e8e6e3;
    --muted: #8b8f97;
    --accent: #e8743b;
    --danger: #f2706b;
    --danger-bg: rgba(242, 112, 107, 0.12);
    --warn: #e2b54f;
    --warn-bg: rgba(226, 181, 79, 0.12);
    --ok: #7fcb8f;
    --ok-bg: rgba(127, 203, 143, 0.1);
    --info: #8ab4f0;
    --info-bg: rgba(138, 180, 240, 0.1);
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
  font-variant-numeric: tabular-nums;
}
.container { max-width: 1180px; margin: 0 auto; padding: 40px 24px 64px; }
.report-header { padding: 0 0 28px; margin-bottom: 28px; border-bottom: 1px solid var(--border); }
.brand { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; font-weight: 600; color: var(--muted); letter-spacing: 0.01em; }
.brand svg { flex: none; }
.ver { font-weight: 400; }
.title-row { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; margin-top: 18px; }
h1 { margin: 0; font-size: 2rem; font-weight: 600; letter-spacing: -0.02em; }
.status { display: inline-flex; align-items: center; gap: 7px; padding: 4px 12px; border-radius: 999px; font-size: 0.82rem; font-weight: 600; }
.status .dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.status-danger { background: var(--danger-bg); color: var(--danger); }
.status-warn { background: var(--warn-bg); color: var(--warn); }
.status-ok { background: var(--ok-bg); color: var(--ok); }
.path { margin: 6px 0 0; color: var(--muted); font-size: 0.85rem; word-break: break-all; }
.summary-line { margin: 14px 0 0; font-size: 0.98rem; }
.meta { margin: 6px 0 0; color: var(--muted); font-size: 0.82rem; }
.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1px; margin-bottom: 28px; background: var(--border); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
.kpi-card { display: block; text-decoration: none; color: inherit; padding: 18px 20px; background: var(--surface); position: relative; }
.kpi-card:hover { background: var(--surface-alt); text-decoration: none; }
.kpi-label { font-size: 0.8rem; color: var(--muted); display: flex; align-items: center; gap: 7px; }
.kpi-label::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
.kpi-danger .kpi-label::before { background: var(--danger); }
.kpi-warn .kpi-label::before { background: var(--warn); }
.kpi-ok .kpi-label::before { background: var(--ok); }
.kpi-info .kpi-label::before { background: var(--info); }
.kpi-value { font-size: 1.7rem; font-weight: 600; letter-spacing: -0.02em; margin: 6px 0 2px; }
.kpi-detail { font-size: 0.8rem; color: var(--muted); }
.controls {
  position: sticky;
  top: 0;
  z-index: 10;
  background: var(--bg);
  padding: 12px 0;
  margin-bottom: 20px;
  display: flex;
  flex-wrap: wrap;
  gap: 12px 20px;
  align-items: center;
  border-bottom: 1px solid var(--border);
}
#search-input {
  flex: 1 1 240px;
  padding: 8px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  font-size: 0.9rem;
}
#search-input:focus { outline: none; border-color: var(--accent); }
.tabs { display: flex; flex-wrap: wrap; gap: 2px; }
.tab {
  border: 0;
  background: transparent;
  color: var(--muted);
  padding: 6px 10px;
  border-radius: 6px;
  font-size: 0.85rem;
  cursor: pointer;
}
.tab:hover { color: var(--text); background: var(--surface-alt); }
.tab.is-active { color: var(--text); background: var(--surface-alt); box-shadow: inset 0 -2px 0 var(--accent); }
.alert-box { padding: 12px 16px; border-radius: 10px; margin-bottom: 20px; border: 1px solid var(--border); font-size: 0.9rem; }
.alert-warn { background: var(--warn-bg); }
.alert-danger { background: var(--danger-bg); }
.report-section { padding: 0; margin-bottom: 44px; }
h2 { margin: 0 0 14px; font-size: 1.2rem; font-weight: 600; letter-spacing: -0.01em; display: flex; align-items: center; gap: 10px; }
h3 { margin: 0 0 12px; font-size: 0.95rem; font-weight: 600; }
.count-pill {
  font-size: 0.75rem;
  font-weight: 600;
  padding: 1px 8px;
  border-radius: 999px;
  background: var(--surface-alt);
  color: var(--muted);
}
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; margin-bottom: 16px; min-width: 0; }
.split-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 16px; }
.split-grid .panel { margin-bottom: 0; }
.report-section > .table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 4px 8px; }
.table-wrap { overflow-x: auto; }
.panel .table-wrap { max-height: 460px; overflow: auto; margin: 0 -8px; padding: 0 8px; }
.panel thead th { position: sticky; top: 0; background: var(--surface); z-index: 1; }
table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: var(--surface-alt); }
th { color: var(--muted); font-weight: 500; font-size: 0.78rem; }
td:first-child a { white-space: nowrap; }
code { font-family: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.86em; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.badge {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 5px;
  font-size: 0.74rem;
  font-weight: 600;
  white-space: nowrap;
}
.badge-danger { background: var(--danger-bg); color: var(--danger); }
.badge-warn { background: var(--warn-bg); color: var(--warn); }
.badge-ok { background: var(--ok-bg); color: var(--ok); }
.badge-info { background: var(--info-bg); color: var(--info); }
.badge-muted { background: var(--surface-alt); color: var(--muted); }
.muted { color: var(--muted); }
.small { font-size: 0.82rem; }
.chain { font-size: 0.82rem; color: var(--muted); margin-top: 4px; word-break: break-word; }
.evidence { margin: 0; padding-left: 18px; }
.empty { color: var(--muted); margin: 4px 0; }
.empty-ok { color: var(--ok); }
.note { margin-top: 10px; font-size: 0.86rem; }
.sub-details { margin-top: 12px; }
footer { color: var(--muted); font-size: 0.8rem; margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border); }
.actions { margin-bottom: 28px; }
.action-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 12px; }
.action { background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--border); border-radius: 0 10px 10px 0; padding: 14px 16px; min-width: 0; }
.action-danger { border-left-color: var(--danger); }
.action-warn { border-left-color: var(--warn); }
.action h3 { margin-bottom: 8px; }
.action ul { margin: 0 0 10px; padding-left: 18px; font-size: 0.88rem; }
.action li { margin: 3px 0; }
.action p { margin: 0 0 10px; font-size: 0.88rem; }
.cmd { display: flex; align-items: center; gap: 10px; background: var(--surface-alt); border-radius: 8px; padding: 6px 6px 6px 12px; flex-wrap: wrap; }
.cmd code { font-size: 0.85rem; }
.cmd code { flex: 1; }
.cmd-note { margin: 6px 0 0 !important; }
.copy { border: 1px solid var(--border); background: var(--surface); color: var(--text); border-radius: 6px; padding: 3px 10px; font-size: 0.78rem; cursor: pointer; }
.copy:hover { border-color: var(--accent); }
.copy.done { color: var(--ok); border-color: var(--ok); }
a.crate code { color: var(--text); }
a.crate:hover code { color: var(--accent); }
.toggles { display: flex; flex-wrap: wrap; gap: 14px; width: 100%; font-size: 0.82rem; color: var(--muted); }
.toggles label { display: inline-flex; align-items: center; gap: 6px; cursor: pointer; }
.toggles input { accent-color: var(--accent); }
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--text); }
th.sort-asc::after { content: " \2191"; }
th.sort-desc::after { content: " \2193"; }
.map-panel { padding-bottom: 12px; }
.map-head { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; }
.map-head h3 { margin: 0; }
.map-head .muted { flex: 1; min-width: 220px; }
#map-search { padding: 5px 10px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); color: var(--text); font-size: 0.85rem; }
.map-wrap { position: relative; height: 560px; border-radius: 8px; background: var(--surface-alt); overflow: hidden; }
#dep-map { width: 100%; height: 100%; display: block; cursor: grab; }
#dep-map.dragging { cursor: grabbing; }
#map-tip { position: absolute; pointer-events: none; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 6px 9px; font-size: 0.8rem; white-space: nowrap; }
.map-legend { display: flex; gap: 16px; margin-top: 8px; }
.lg { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; vertical-align: -1px; }
.lg-root { background: var(--accent); }
.lg-direct { background: var(--info); }
.lg-trans { background: var(--muted); }
.lg-vuln { background: var(--danger); }
@media print {
  .controls { display: none; }
  .report-header, .report-section, .kpi-card { break-inside: avoid; }
}
"#;

const FILTER_JS: &str = r#"(function () {
  var search = document.getElementById('search-input');
  var tabs = document.querySelectorAll('.tab');
  var sections = document.querySelectorAll('.report-section');
  var toggles = document.querySelectorAll('.toggles input');
  var activeSection = 'all';

  function on(name) {
    var box = document.querySelector('.toggles input[data-filter="' + name + '"]');
    return box && box.checked;
  }

  function applyFilters() {
    var q = search ? search.value.trim().toLowerCase() : '';
    var vulnOnly = on('vulnerabilities'), hideUnlikely = on('likely'), directOnly = on('direct');
    sections.forEach(function (sec) {
      var name = sec.getAttribute('data-section');
      sec.hidden = activeSection !== 'all' && name !== activeSection;
      sec.querySelectorAll('.filter-row').forEach(function (row) {
        var text = (row.textContent || '').toLowerCase();
        var hide = q.length > 0 && text.indexOf(q) === -1;
        if (vulnOnly && row.getAttribute('data-kind') === 'notice') hide = true;
        if (hideUnlikely && row.getAttribute('data-relevance') === 'unlikely') hide = true;
        if (directOnly) {
          var marker = row.querySelector('[data-direct]');
          if (marker && marker.getAttribute('data-direct') === 'false') hide = true;
        }
        row.hidden = hide;
      });
    });
  }

  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      activeSection = tab.getAttribute('data-section') || 'all';
      tabs.forEach(function (t) { t.classList.remove('is-active'); });
      tab.classList.add('is-active');
      applyFilters();
    });
  });
  if (search) search.addEventListener('input', applyFilters);
  toggles.forEach(function (box) { box.addEventListener('change', applyFilters); });

  // Click a column title to sort; numbers sort as numbers.
  function cellKey(cell) {
    if (!cell) return '';
    var key = cell.getAttribute('data-sort');
    if (key !== null) return Number(key);
    var text = (cell.textContent || '').trim();
    var number = text.replace(/[,\s]/g, '').match(/^-?\d+(\.\d+)?/);
    return number && /^[\d,.\s-]/.test(text) && !/^\d+\.\d+\.\d+/.test(text) ? Number(number[0]) : text.toLowerCase();
  }
  document.querySelectorAll('table').forEach(function (table) {
    var heads = table.querySelectorAll('thead th');
    heads.forEach(function (th, column) {
      th.classList.add('sortable');
      th.addEventListener('click', function () {
        var body = table.tBodies[0];
        if (!body) return;
        var descending = !th.classList.contains('sort-desc');
        heads.forEach(function (h) { h.classList.remove('sort-asc', 'sort-desc'); });
        th.classList.add(descending ? 'sort-desc' : 'sort-asc');
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(function (a, b) {
          var x = cellKey(a.cells[column]), y = cellKey(b.cells[column]);
          var order = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
          return descending ? -order : order;
        });
        rows.forEach(function (row) { body.appendChild(row); });
      });
    });
  });

  // Copy buttons.
  document.querySelectorAll('.copy').forEach(function (button) {
    button.addEventListener('click', function () {
      var text = button.getAttribute('data-copy') || '';
      function done() { button.textContent = 'Copied'; button.classList.add('done'); setTimeout(function () { button.textContent = 'Copy'; button.classList.remove('done'); }, 1500); }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallback(); });
      } else { fallback(); }
      function fallback() {
        var area = document.createElement('textarea');
        area.value = text; document.body.appendChild(area); area.select();
        try { document.execCommand('copy'); done(); } catch (e) {}
        document.body.removeChild(area);
      }
    });
  });

  // Dependency map: force layout on a canvas, no library.
  var dataNode = document.getElementById('graph-data');
  var canvas = document.getElementById('dep-map');
  if (!dataNode || !canvas) return;
  var data = JSON.parse(dataNode.textContent);
  var tip = document.getElementById('map-tip');
  var mapSearch = document.getElementById('map-search');
  var styles = getComputedStyle(document.documentElement);
  function css(name) { return styles.getPropertyValue(name).trim(); }
  var colors = { root: css('--accent'), direct: css('--info'), trans: css('--muted'), vuln: css('--danger'), edge: css('--muted'), text: css('--text') };
  var labelFrom = data.nodes.map(function (d) { return d[3]; }).sort(function (a, b) { return b - a; })[Math.min(24, data.nodes.length - 1)] || 1;
  var n = data.nodes.length;
  var nodes = data.nodes.map(function (d, i) {
    return { i: i, name: d[0], version: d[1], kind: d[2], dependents: d[3], vuln: d[4] === 1, x: 0, y: 0, vx: 0, vy: 0, out: [], inn: [],
      r: d[2] === 0 ? 10 : 2 + 2.6 * Math.sqrt(d[3]) };
  });
  var edges = [];
  for (var e = 0; e < data.edges.length; e++) {
    var a = data.edges[e][0], b = data.edges[e][1];
    edges.push([a, b]); nodes[a].out.push(b); nodes[b].inn.push(a);
  }
  // Start on rings by depth from the project, so the layout settles fast.
  var depth = new Array(n).fill(-1), queue = [];
  nodes.forEach(function (node) { if (node.kind === 0) { depth[node.i] = 0; queue.push(node.i); } });
  if (!queue.length) { depth[0] = 0; queue.push(0); }
  for (var q = 0; q < queue.length; q++) {
    nodes[queue[q]].out.forEach(function (next) { if (depth[next] < 0) { depth[next] = depth[queue[q]] + 1; queue.push(next); } });
  }
  var byDepth = {};
  nodes.forEach(function (node) { var d = depth[node.i] < 0 ? 6 : depth[node.i]; (byDepth[d] = byDepth[d] || []).push(node); });
  Object.keys(byDepth).forEach(function (d) {
    var ring = byDepth[d];
    ring.forEach(function (node, k) {
      var angle = (k / ring.length) * Math.PI * 2 + d * 0.7;
      var radius = d * 110 + Math.random() * 30;
      node.x = Math.cos(angle) * radius; node.y = Math.sin(angle) * radius;
    });
  });

  var view = { x: 0, y: 0, k: 0.6 }, ctx = canvas.getContext('2d'), focus = null, hover = null, ticks = 0, maxTicks = 320;
  function resize() {
    var ratio = window.devicePixelRatio || 1;
    canvas.width = canvas.clientWidth * ratio; canvas.height = canvas.clientHeight * ratio;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    draw();
  }
  function step() {
    var cell = 70, grid = {}, alpha = Math.max(0.02, 1 - ticks / maxTicks);
    nodes.forEach(function (node) {
      var key = Math.floor(node.x / cell) + ',' + Math.floor(node.y / cell);
      (grid[key] = grid[key] || []).push(node);
    });
    nodes.forEach(function (node) {
      var gx = Math.floor(node.x / cell), gy = Math.floor(node.y / cell);
      for (var dx = -1; dx <= 1; dx++) for (var dy = -1; dy <= 1; dy++) {
        var bucket = grid[(gx + dx) + ',' + (gy + dy)];
        if (!bucket) continue;
        for (var m = 0; m < bucket.length; m++) {
          var other = bucket[m];
          if (other === node) continue;
          var x = node.x - other.x, y = node.y - other.y, dist2 = x * x + y * y + 0.01;
          if (dist2 > cell * cell) continue;
          var push = (260 + 40 * (node.r + other.r)) / dist2 * alpha;
          node.vx += x * push * 0.05; node.vy += y * push * 0.05;
        }
      }
      node.vx -= node.x * 0.0009 * alpha; node.vy -= node.y * 0.0009 * alpha;
    });
    edges.forEach(function (edge) {
      var a = nodes[edge[0]], b = nodes[edge[1]];
      var x = b.x - a.x, y = b.y - a.y, dist = Math.sqrt(x * x + y * y) + 0.01;
      var pull = (dist - (22 + a.r + b.r)) * 0.03 * alpha;
      var fx = x / dist * pull, fy = y / dist * pull;
      a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
    });
    nodes.forEach(function (node) {
      node.vx *= 0.82; node.vy *= 0.82;
      node.x += node.vx; node.y += node.vy;
    });
    ticks++;
  }
  function related(node) {
    var set = {};
    set[node.i] = true;
    node.out.forEach(function (i) { set[i] = true; });
    node.inn.forEach(function (i) { set[i] = true; });
    return set;
  }
  function color(node) {
    if (node.vuln) return colors.vuln;
    return node.kind === 0 ? colors.root : node.kind === 1 ? colors.direct : colors.trans;
  }
  function draw() {
    var w = canvas.clientWidth, h = canvas.clientHeight;
    ctx.clearRect(0, 0, w, h);
    ctx.save();
    ctx.translate(w / 2 + view.x, h / 2 + view.y);
    ctx.scale(view.k, view.k);
    var near = focus ? related(focus) : null;
    ctx.lineWidth = 0.6 / view.k;
    ctx.strokeStyle = colors.edge;
    ctx.globalAlpha = near ? 0.06 : 0.16;
    ctx.beginPath();
    edges.forEach(function (edge) {
      var a = nodes[edge[0]], b = nodes[edge[1]];
      ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
    });
    ctx.stroke();
    if (focus) {
      ctx.globalAlpha = 1;
      ctx.lineWidth = 1.4 / view.k;
      ctx.strokeStyle = colors.root;
      ctx.beginPath();
      focus.out.forEach(function (i) { ctx.moveTo(focus.x, focus.y); ctx.lineTo(nodes[i].x, nodes[i].y); });
      ctx.stroke();
      ctx.strokeStyle = colors.direct;
      ctx.beginPath();
      focus.inn.forEach(function (i) { ctx.moveTo(focus.x, focus.y); ctx.lineTo(nodes[i].x, nodes[i].y); });
      ctx.stroke();
    }
    nodes.forEach(function (node) {
      ctx.globalAlpha = near && !near[node.i] ? 0.15 : 1;
      ctx.fillStyle = color(node);
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      ctx.fill();
    });
    ctx.globalAlpha = 1;
    ctx.fillStyle = colors.text;
    ctx.font = (11 / view.k) + 'px ui-sans-serif, system-ui, sans-serif';
    nodes.forEach(function (node) {
      var big = node.kind === 0 || node.vuln || (node.dependents >= labelFrom && node.dependents > 1) || node.r * view.k > 16;
      if ((near && near[node.i]) || (!near && big) || node === hover) {
        ctx.fillText(node.name, node.x + node.r + 3 / view.k, node.y + 4 / view.k);
      }
    });
    ctx.restore();
  }
  function animate() {
    for (var s = 0; s < 4 && ticks < maxTicks; s++) step();
    draw();
    if (ticks < maxTicks) requestAnimationFrame(animate);
    else if (!fitted) { fit(); draw(); }
  }
  var fitted = false;
  function fit() {
    fitted = true;
    var xs = nodes.map(function (node) { return node.x; }).sort(function (a, b) { return a - b; });
    var ys = nodes.map(function (node) { return node.y; }).sort(function (a, b) { return a - b; });
    // Ignore the farthest 2% so a few strays do not shrink everything.
    var lo = Math.floor(n * 0.02), hi = Math.max(lo, n - 1 - lo);
    var width = xs[hi] - xs[lo] + 80, height = ys[hi] - ys[lo] + 80;
    view.k = Math.min(3, Math.max(0.1, Math.min(canvas.clientWidth / width, canvas.clientHeight / height)));
    view.x = -((xs[hi] + xs[lo]) / 2) * view.k;
    view.y = -((ys[hi] + ys[lo]) / 2) * view.k;
  }
  function toWorld(event) {
    var box = canvas.getBoundingClientRect();
    return { x: (event.clientX - box.left - canvas.clientWidth / 2 - view.x) / view.k, y: (event.clientY - box.top - canvas.clientHeight / 2 - view.y) / view.k };
  }
  function pick(event) {
    var p = toWorld(event), best = null, bestDist = Infinity;
    nodes.forEach(function (node) {
      var x = node.x - p.x, y = node.y - p.y, d = x * x + y * y, r = Math.max(node.r, 5 / view.k);
      if (d < r * r && d < bestDist) { best = node; bestDist = d; }
    });
    return best;
  }
  var drag = null;
  canvas.addEventListener('mousedown', function (event) { drag = { x: event.clientX, y: event.clientY, vx: view.x, vy: view.y, moved: false }; canvas.classList.add('dragging'); });
  window.addEventListener('mouseup', function (event) {
    if (drag && !drag.moved && event.target === canvas) { var node = pick(event); focus = node && node !== focus ? node : null; draw(); }
    drag = null; canvas.classList.remove('dragging');
  });
  canvas.addEventListener('mousemove', function (event) {
    if (drag) {
      var dx = event.clientX - drag.x, dy = event.clientY - drag.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
      view.x = drag.vx + dx; view.y = drag.vy + dy; draw(); return;
    }
    var node = pick(event);
    hover = node;
    if (node) {
      var box = canvas.getBoundingClientRect();
      tip.hidden = false;
      tip.textContent = node.name + ' ' + node.version + ' · ' + node.dependents + ' dependent' + (node.dependents === 1 ? '' : 's') + ' · ' + node.out.length + ' dependenc' + (node.out.length === 1 ? 'y' : 'ies') + (node.vuln ? ' · vulnerable' : '');
      tip.style.left = (event.clientX - box.left + 12) + 'px';
      tip.style.top = (event.clientY - box.top + 12) + 'px';
    } else { tip.hidden = true; }
    draw();
  });
  canvas.addEventListener('mouseleave', function () { tip.hidden = true; hover = null; draw(); });
  canvas.addEventListener('wheel', function (event) {
    event.preventDefault();
    var box = canvas.getBoundingClientRect();
    var mx = event.clientX - box.left - canvas.clientWidth / 2, my = event.clientY - box.top - canvas.clientHeight / 2;
    var factor = Math.exp(-event.deltaY * 0.0015), k = Math.min(6, Math.max(0.08, view.k * factor));
    view.x = mx - (mx - view.x) * (k / view.k); view.y = my - (my - view.y) * (k / view.k); view.k = k;
    draw();
  }, { passive: false });
  if (mapSearch) {
    mapSearch.addEventListener('input', function () {
      var q = mapSearch.value.trim().toLowerCase();
      var found = q ? nodes.filter(function (node) { return node.name.toLowerCase() === q; })[0] || nodes.filter(function (node) { return node.name.toLowerCase().indexOf(q) === 0; })[0] : null;
      focus = found || null;
      if (found) { view.x = -found.x * view.k; view.y = -found.y * view.k; }
      draw();
    });
  }
  window.addEventListener('resize', resize);
  resize();
  animate();
})();
"#;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use cargoscope_core::policy::{Rule, Violation, ViolationLevel};
    use cargoscope_core::{
        AdvisoryFinding, AdvisoryKind, AdvisoryRelevance, Checks, DependencyKind, Inventory,
        Package, PackageInfo, Report, Severity, UnusedConfidence, UnusedFinding,
    };

    use super::{escape_html, render_html};

    fn sample_report() -> Report {
        let inventory = Inventory {
            packages: vec![
                Package {
                    name: "my-app".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: false,
                    dependencies: vec![1],
                },
                Package {
                    name: "serde_json".to_owned(),
                    version: "1.0.100".to_owned(),
                    source: Some(
                        "registry+https://github.com/rust-lang/crates.io-index".to_owned(),
                    ),
                    root: false,
                    direct: true,
                    dependencies: vec![2],
                },
                Package {
                    name: "itoa".to_owned(),
                    version: "1.0.11".to_owned(),
                    source: Some(
                        "registry+https://github.com/rust-lang/crates.io-index".to_owned(),
                    ),
                    root: false,
                    direct: false,
                    dependencies: Vec::new(),
                },
            ],
        };
        let mut direct_kinds = BTreeMap::new();
        direct_kinds.insert(
            "serde_json".to_owned(),
            BTreeSet::from([DependencyKind::Normal]),
        );

        Report {
            inventory,
            unsafe_code: Vec::new(),
            checks: Checks::ALL,
            advisories: vec![
                AdvisoryFinding {
                    package: 1,
                    id: "RUSTSEC-2026-0001".to_owned(),
                    aliases: vec!["CVE-2026-1000".to_owned()],
                    title: "Unsafe <script>alert(1)</script> issue".to_owned(),
                    date: "2026-01-10".to_owned(),
                    url: Some("https://rustsec.org/advisories/RUSTSEC-2026-0001.html".to_owned()),
                    kind: AdvisoryKind::Vulnerability,
                    severity: Some(Severity::High),
                    patched: vec!["^1.0.128".to_owned()],
                    affected_arch: Vec::new(),
                    affected_os: Vec::new(),
                    affected_functions: Vec::new(),
                    relevance: AdvisoryRelevance::AffectsYou,
                    relevance_reason: None,
                    ignored: None,
                },
                AdvisoryFinding {
                    package: 2,
                    id: "RUSTSEC-2026-0002".to_owned(),
                    aliases: Vec::new(),
                    title: "Untrusted scheme test".to_owned(),
                    date: "2026-02-01".to_owned(),
                    url: Some("javascript:alert(1)".to_owned()),
                    kind: AdvisoryKind::Informational("unmaintained".to_owned()),
                    severity: None,
                    patched: Vec::new(),
                    affected_arch: Vec::new(),
                    affected_os: Vec::new(),
                    affected_functions: Vec::new(),
                    relevance: AdvisoryRelevance::AffectsYou,
                    relevance_reason: None,
                    ignored: Some("tracked upstream".to_owned()),
                },
            ],
            advisory_db_date: Some("2026-11-15".to_owned()),
            package_info: vec![
                PackageInfo::default(),
                PackageInfo {
                    license: Some("MIT OR Apache-2.0".to_owned()),
                    latest_version: Some("1.0.130".to_owned()),
                    latest_published: Some("2026-10-01".to_owned()),
                    latest_compatible: Some("1.0.130".to_owned()),
                    compatible_published: Some("2026-10-01".to_owned()),
                    outdated: true,
                    yanked: Some(true),
                    ..PackageInfo::default()
                },
                PackageInfo {
                    license: Some("MIT".to_owned()),
                    ..PackageInfo::default()
                },
            ],
            registry_date: Some("2026-11-15".to_owned()),
            policy: Some(vec![Violation {
                package: 1,
                rule: Rule::Ban,
                level: ViolationLevel::Warning,
                message: "warn on serde_json & <tag>".to_owned(),
            }]),
            unused: vec![
                UnusedFinding {
                    dependency: "dead_dep".to_owned(),
                    package: "dead-dep".to_owned(),
                    kind: DependencyKind::Normal,
                    declared_by: "my-app".to_owned(),
                    manifest: "Cargo.toml".to_owned(),
                    confidence: UnusedConfidence::Likely,
                    evidence: vec!["no reference found in src/".to_owned()],
                    ignored: None,
                },
                UnusedFinding {
                    dependency: "maybe_dep".to_owned(),
                    package: "maybe_dep".to_owned(),
                    kind: DependencyKind::Dev,
                    declared_by: "my-app".to_owned(),
                    manifest: "Cargo.toml".to_owned(),
                    confidence: UnusedConfidence::Possibly,
                    evidence: vec!["macro heuristic".to_owned()],
                    ignored: None,
                },
            ],
            unused_precise: false,
            direct_kinds,
            warnings: vec!["cache note <test>".to_owned()],
        }
    }

    #[test]
    fn shows_recent_releases_audits_and_unsafe_code() {
        use cargoscope_core::{Audit, AuditCriteria, UnsafeCount};
        let mut report = sample_report();
        report.package_info[1].published = Some("2026-11-19T02:00:00Z".to_owned());
        report.package_info[1].audits = Some(vec![Audit {
            by: "mozilla".to_owned(),
            criteria: AuditCriteria::SafeToDeploy,
        }]);
        report.package_info[2].audits = Some(Vec::new());
        report.unsafe_code = vec![
            None,
            Some(UnsafeCount {
                blocks: 3,
                ..UnsafeCount::default()
            }),
            Some(UnsafeCount::default()),
        ];
        let now = cargoscope_core::unix_seconds("2026-11-19T08:30:00Z");
        let html = render_html(Path::new("."), &report, false, now);
        assert!(html.contains("data-section=\"supply-chain\" type=\"button\">Supply chain"));
        assert!(html.contains("<code>serde_json</code></a> <span class=\"muted\">1.0.100</span></td><td><span class=\"badge badge-warn\">6 h ago</span>"), "{html}");

        // What to do: the recent release to review, with links.
        assert!(html.contains("<h2>What to do</h2>"));
        assert!(html.contains("<h3>Review 1 recent release</h3>"));
        assert!(html.contains(
            "<a class=\"crate\" data-direct=\"true\" href=\"https://crates.io/crates/serde_json/1.0.100\""
        ));
        // Quick filters, and the map's data for its three packages.
        assert!(html.contains("data-filter=\"direct\""));
        assert!(html.contains(
            "<script type=\"application/json\" id=\"graph-data\">{\"nodes\":[[\"my-app\""
        ));
        assert!(
            html.contains("<strong>1</strong> of 2 crates.io packages reviewed by an organisation")
        );
        assert!(html.contains("<span class=\"badge badge-ok\">safe-to-deploy</span> <span class=\"muted\">(mozilla)</span>"));
        assert!(html.contains("1 of 2 dependencies with sources on disk use <code>unsafe</code>"));
        assert!(html.contains("<td>direct</td><td><strong>3</strong></td><td>3 blocks</td>"));

        // Without a scan time, audits or sources, each panel says why it is empty.
        let bare = render_html(Path::new("."), &sample_report(), false, None);
        assert!(bare.contains("No published audits downloaded"));
        assert!(bare.contains("No dependency sources on disk"));
    }

    #[test]
    fn lists_fixes_with_commands_and_diff_links() {
        let report = sample_report();
        let html = render_html(Path::new("."), &report, false, None);
        // The sample's serde_json advisory is fixed in ^1.0.128.
        assert!(html.contains("<h3>Fix 1 vulnerable crate</h3>"), "{html}");
        assert!(
            html.contains("&rarr; <a href=\"https://diff.rs/serde_json/1.0.100/1.0.128\""),
            "{html}"
        );
        assert!(html.contains("data-copy=\"cargoscope fix --advisories\">Copy</button>"));
        assert!(html.contains("data-relevance=\"affects-you\" data-kind=\"vulnerability\""));
        assert_eq!(
            super::json_string("a\"<b>&"),
            "\"a\\\"\\u003cb\\u003e\\u0026\""
        );
    }

    #[test]
    fn escapes_html_characters_and_blocks_non_http_urls() {
        assert_eq!(escape_html("<a&\"'>"), "&lt;a&amp;&quot;&#39;&gt;");

        let html = render_html(Path::new("/work/<app>"), &sample_report(), false, None);
        assert!(html.starts_with("<!DOCTYPE html>\n"));
        assert!(html.contains("&lt;app&gt;"));
        assert!(html.contains("Unsafe &lt;script&gt;alert(1)&lt;/script&gt; issue"));
        assert!(html.contains("warn on serde_json &amp; &lt;tag&gt;"));
        assert!(html.contains("cache note &lt;test&gt;"));
        assert!(html.contains("href=\"https://rustsec.org/advisories/RUSTSEC-2026-0001.html\""));
        assert!(!html.contains("href=\"javascript:"));
    }

    #[test]
    fn respects_show_uncertain_and_renders_all_sections() {
        let report = sample_report();
        let default_html = render_html(Path::new("."), &report, false, None);
        assert!(default_html.contains("dead_dep"));
        assert!(!default_html.contains("maybe_dep"));
        assert!(default_html.contains("1 possibly-unused dependency hidden"));
        assert!(default_html.contains("RUSTSEC-2026-0001"));
        assert!(default_html.contains("YANKED"));
        assert!(default_html.contains("1.0.130"));
        assert!(default_html.contains("MIT OR Apache-2.0"));
        assert!(default_html.contains("2</strong> / 2"));

        let uncertain_html = render_html(Path::new("."), &report, true, None);
        assert!(uncertain_html.contains("maybe_dep"));
        assert!(!uncertain_html.contains("possibly-unused dependency hidden"));
    }
}
