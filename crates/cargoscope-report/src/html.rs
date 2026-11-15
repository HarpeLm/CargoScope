//! Self-contained standalone HTML report output.
//!
//! Renders a single offline HTML5 document with inline CSS, inline SVG status
//! badge, and optional vanilla JS search/section filtering (no external network
//! requests).

use std::fmt::Write;
use std::path::Path;

use cargoscope_core::policy::ViolationLevel;
use cargoscope_core::{AdvisoryKind, OutdatedKind, Report, UnusedConfidence, VERSION};

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
pub fn render_html(project_root: &Path, report: &Report, show_uncertain: bool) -> String {
    let counts = ReportCounts::from_report(report);
    let target = project_root.display().to_string();
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
    render_controls(&mut out);
    render_warnings(&mut out, &report.warnings);

    out.push_str("<main>\n");
    render_advisories_section(&mut out, report);
    render_policy_section(&mut out, report);
    render_unused_section(&mut out, report, show_uncertain, &counts);
    render_versions_licenses_section(&mut out, report, &counts);
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
    let (badge_label, badge_color) = if counts.active_vulnerabilities > 0 {
        let n = counts.active_vulnerabilities;
        let noun = if n == 1 {
            "vulnerability"
        } else {
            "vulnerabilities"
        };
        (format!("{n} {noun}"), "#cf222e")
    } else if counts.policy_errors > 0 {
        let n = counts.policy_errors;
        let noun = if n == 1 {
            "policy error"
        } else {
            "policy errors"
        };
        (format!("{n} {noun}"), "#cf222e")
    } else if counts.likely_unused > 0 || counts.yanked > 0 || counts.policy_warnings > 0 {
        ("warnings".to_owned(), "#bf8700")
    } else {
        ("clean".to_owned(), "#1a7f37")
    };

    let advisory_date = report.advisory_db_date.as_deref().unwrap_or("unknown");
    let registry_date = report.registry_date.as_deref().unwrap_or("never");
    let checks = report.checks.enabled().join(", ");

    out.push_str("<header class=\"report-header\">\n<div class=\"header-top\">\n<div>\n");
    let _ = writeln!(
        out,
        "<h1>CargoScope <span class=\"ver\">{}</span></h1>",
        escape_html(VERSION)
    );
    let _ = writeln!(
        out,
        "<p class=\"subtitle\">Target: <code>{escaped_target}</code></p>"
    );
    let _ = writeln!(
        out,
        "<p class=\"summary-line\">{}</p>",
        escape_html(&summary(report))
    );
    out.push_str("</div>\n<div class=\"header-badge\">");
    render_badge_svg(out, &badge_label, badge_color);
    out.push_str("</div>\n</div>\n<div class=\"meta-pills\">\n");
    let _ = writeln!(
        out,
        "<span class=\"pill\">Checks: {}</span>",
        escape_html(&checks)
    );
    let _ = writeln!(
        out,
        "<span class=\"pill\">RustSec DB: {}</span>",
        escape_html(advisory_date)
    );
    let _ = writeln!(
        out,
        "<span class=\"pill\">crates.io cache: {}</span>",
        escape_html(registry_date)
    );
    if report.unused_precise {
        out.push_str("<span class=\"pill pill-info\">Unused mode: --precise</span>\n");
    }
    out.push_str("</div>\n</header>\n");
}

fn render_badge_svg(out: &mut String, right_text: &str, right_color: &str) {
    let left = "CargoScope";
    let left_w = 84;
    let right_w = (right_text.len() * 7 + 20).max(58);
    let total_w = left_w + right_w;
    let right_x = left_w + right_w / 2;
    let safe_right = escape_html(right_text);
    let _ = writeln!(
        out,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{total_w}\" height=\"22\" role=\"img\" aria-label=\"CargoScope: {safe_right}\">\
<clipPath id=\"r\"><rect width=\"{total_w}\" height=\"22\" rx=\"4\" fill=\"#fff\"/></clipPath>\
<g clip-path=\"url(#r)\"><rect width=\"{left_w}\" height=\"22\" fill=\"#24292f\"/>\
<rect x=\"{left_w}\" width=\"{right_w}\" height=\"22\" fill=\"{right_color}\"/></g>\
<g fill=\"#fff\" text-anchor=\"middle\" font-family=\"ui-sans-serif,system-ui,sans-serif\" font-size=\"11\" font-weight=\"600\">\
<text x=\"{}\" y=\"15\">{left}</text><text x=\"{right_x}\" y=\"15\">{safe_right}</text></g></svg>",
        left_w / 2
    );
}

fn render_kpi_grid(out: &mut String, report: &Report, counts: &ReportCounts) {
    out.push_str("<section class=\"kpi-grid\" aria-label=\"Summary metrics\">\n");
    render_kpi_card(
        out,
        "#advisories",
        "Security Advisories",
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
        "Policy Violations",
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
        "Likely Unused",
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
        "Versions Health",
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
        "Graph &amp; Packages",
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
<button class=\"tab\" data-section=\"versions\" type=\"button\">Versions &amp; Licenses</button>\n\
<button class=\"tab\" data-section=\"graph\" type=\"button\">Graph</button>\n\
<button class=\"tab\" data-section=\"inventory\" type=\"button\">Inventory</button>\n\
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

fn render_advisories_section(out: &mut String, report: &Report) {
    out.push_str(
        "<section id=\"advisories\" class=\"report-section\" data-section=\"advisories\">\n",
    );
    let _ = writeln!(
        out,
        "<h2>Security Advisories <span class=\"count-pill\">{}</span></h2>",
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
<th>ID</th><th>Severity</th><th>Package</th><th>Title &amp; Chain</th><th>Fix / Status</th>\
</tr></thead>\n<tbody>\n",
    );
    for finding in &report.advisories {
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
            "<tr class=\"filter-row\">\
<td>{id_cell}{aliases_html}</td>\
<td><span class=\"badge {sev_class}\">{}</span></td>\
<td><code>{}</code> <span class=\"muted\">{}</span></td>\
<td>{}{chain_html}</td>\
<td>{fix_html}</td>\
</tr>",
            escape_html(sev_text),
            escape_html(&package.name),
            escape_html(&package.version),
            escape_html(&finding.title),
        );
    }
    out.push_str("</tbody></table></div>\n</section>\n");
}

fn render_policy_section(out: &mut String, report: &Report) {
    out.push_str("<section id=\"policy\" class=\"report-section\" data-section=\"policy\">\n");
    if !report.checks.policy {
        out.push_str("<h2>Policy Violations</h2>\n<p class=\"empty\">Policy check was skipped.</p>\n</section>\n");
        return;
    }
    let Some(violations) = &report.policy else {
        out.push_str("<h2>Policy Violations</h2>\n<p class=\"empty\">No cargoscope.toml or deny.toml policy configured.</p>\n</section>\n");
        return;
    };
    let _ = writeln!(
        out,
        "<h2>Policy Violations <span class=\"count-pill\">{}</span></h2>",
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
<th>Rule</th><th>Level</th><th>Package</th><th>Message &amp; Chain</th>\
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
<td><code>{}</code> <span class=\"muted\">{}</span></td>\
<td>{}{chain_html}</td>\
</tr>",
            escape_html(violation.rule.as_str()),
            escape_html(violation.level.as_str()),
            escape_html(&package.name),
            escape_html(&package.version),
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
        "<h2>Unused Dependencies <span class=\"count-pill\">{} likely</span></h2>",
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
<th>Dependency</th><th>Confidence</th><th>Section &amp; Manifest</th><th>Evidence</th>\
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
    out.push_str("<h2>Versions &amp; Licenses</h2>\n<div class=\"split-grid\">\n");

    let reg_pkgs = registry_packages(report);
    out.push_str("<div class=\"panel\">\n<h3>Licenses</h3>\n");
    if !report.checks.licenses {
        out.push_str("<p class=\"empty\">Licenses check was skipped.</p>\n");
    } else if reg_pkgs.is_empty() {
        out.push_str("<p class=\"empty\">No registry packages in lockfile.</p>\n");
    } else {
        out.push_str(
            "<div class=\"table-wrap\"><table>\n<thead><tr><th>SPDX License</th><th>Packages</th></tr></thead>\n<tbody>\n",
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

    out.push_str("<div class=\"panel\">\n<h3>Yanked &amp; Outdated Direct</h3>\n");
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
                    "<tr class=\"filter-row\"><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td><span class=\"badge {kind_class}\">{}</span></td><td>{}</td></tr>",
                    escape_html(&pkg.name),
                    escape_html(&pkg.version),
                    escape_html(compat_text),
                    escape_html(info.latest_version.as_deref().unwrap_or("?")),
                    escape_html(kind.as_str()),
                    escape_html(info.latest_published.as_deref().unwrap_or("-"))
                );
            }
            out.push_str("</tbody></table></div>\n");
        }
    }
    out.push_str("</div>\n</div>\n</section>\n");
}

fn render_graph_section(out: &mut String, report: &Report) {
    out.push_str("<section id=\"graph\" class=\"report-section\" data-section=\"graph\">\n");
    out.push_str("<h2>Dependency Graph Insights</h2>\n<div class=\"split-grid\">\n");

    let heavy = sorted_heavy_weights(report);
    out.push_str("<div class=\"panel\">\n<h3>Heaviest Direct Dependencies</h3>\n");
    if heavy.is_empty() {
        out.push_str("<p class=\"empty\">No direct dependency exclusively pulls extra transitive packages.</p>\n");
    } else {
        out.push_str(
            "<div class=\"table-wrap\"><table>\n<thead><tr><th>Package</th><th>Kinds</th><th>Exclusive / Tree</th></tr></thead>\n<tbody>\n",
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
                "<tr class=\"filter-row\"><td><code>{}</code> <span class=\"muted\">{}</span></td><td>{}</td><td><strong>{exclusive}</strong> / {tree}</td></tr>",
                escape_html(&pkg.name),
                escape_html(&pkg.version),
                escape_html(&kinds_text)
            );
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</div>\n");

    let duplicates = report.inventory.duplicates();
    out.push_str("<div class=\"panel\">\n<h3>Crates in Several Versions</h3>\n");
    if duplicates.is_empty() {
        out.push_str(
            "<p class=\"empty empty-ok\">No duplicate crate versions in Cargo.lock.</p>\n",
        );
    } else {
        out.push_str(
            "<div class=\"table-wrap\"><table>\n<thead><tr><th>Crate</th><th>Versions &amp; Chains Pulling Older Versions</th></tr></thead>\n<tbody>\n",
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
        "<h2>Resolved Packages <span class=\"count-pill\">{}</span></h2>",
        report.inventory.packages.len()
    );
    out.push_str(
        "<div class=\"table-wrap\"><table>\n<thead><tr>\
<th>Package</th><th>Version</th><th>Scope</th><th>License</th><th>Status</th><th>Path from Root</th>\
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
<td><code>{}</code></td>\
<td>{}</td>\
<td><span class=\"badge {scope_class}\">{pkg_scope}</span></td>\
<td><code>{}</code></td>\
<td>{status_html}</td>\
<td>{path_html}</td>\
</tr>",
            escape_html(&pkg.name),
            escape_html(&pkg.version),
            escape_html(license),
        );
    }
    out.push_str("</tbody></table></div>\n</section>\n");
}

const STYLE_CSS: &str = r#":root {
  --bg: #f6f8fa;
  --surface: #ffffff;
  --surface-alt: #f0f3f6;
  --border: #d0d7de;
  --text: #1f2328;
  --muted: #656d76;
  --accent: #0969da;
  --danger: #cf222e;
  --danger-bg: #ffebe9;
  --warn: #9a6700;
  --warn-bg: #fff8c5;
  --ok: #1a7f37;
  --ok-bg: #dafbe1;
  --info: #0969da;
  --info-bg: #ddf4ff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --surface-alt: #21262d;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
    --danger: #f85149;
    --danger-bg: rgba(248, 81, 73, 0.16);
    --warn: #d29922;
    --warn-bg: rgba(210, 153, 34, 0.16);
    --ok: #3fb950;
    --ok-bg: rgba(63, 185, 80, 0.16);
    --info: #58a6ff;
    --info-bg: rgba(88, 166, 255, 0.16);
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
.container { max-width: 1220px; margin: 0 auto; padding: 24px 16px 48px; }
.report-header, .report-section, .kpi-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
}
.report-header { padding: 20px 24px; margin-bottom: 16px; }
.header-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; }
h1 { margin: 0 0 6px; font-size: 1.55rem; }
.ver { font-weight: 400; color: var(--muted); font-size: 1rem; }
.subtitle { margin: 0 0 6px; color: var(--muted); }
.summary-line { margin: 0; font-weight: 500; }
.meta-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
.pill {
  font-size: 0.8rem;
  padding: 2px 10px;
  border-radius: 999px;
  background: var(--surface-alt);
  border: 1px solid var(--border);
}
.pill-info { background: var(--info-bg); color: var(--info); border-color: transparent; }
.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px; }
.kpi-card {
  display: block;
  text-decoration: none;
  color: inherit;
  padding: 14px 16px;
  border-top: 3px solid var(--border);
}
.kpi-card:hover { border-color: var(--accent); }
.kpi-danger { border-top-color: var(--danger); }
.kpi-warn { border-top-color: var(--warn); }
.kpi-ok { border-top-color: var(--ok); }
.kpi-info { border-top-color: var(--info); }
.kpi-label { font-size: 0.82rem; color: var(--muted); font-weight: 600; }
.kpi-value { font-size: 1.45rem; font-weight: 700; margin: 4px 0; }
.kpi-detail { font-size: 0.8rem; color: var(--muted); }
.controls {
  position: sticky;
  top: 0;
  z-index: 10;
  background: var(--bg);
  padding: 10px 0 14px;
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}
#search-input {
  flex: 1 1 260px;
  padding: 8px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  font-size: 0.92rem;
}
.tabs { display: flex; flex-wrap: wrap; gap: 6px; }
.tab {
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  padding: 6px 12px;
  border-radius: 999px;
  font-size: 0.82rem;
  cursor: pointer;
}
.tab.is-active { background: var(--accent); color: #fff; border-color: var(--accent); }
.alert-box { padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; border: 1px solid var(--border); }
.alert-warn { background: var(--warn-bg); }
.alert-danger { background: var(--danger-bg); }
.report-section { padding: 18px 20px; margin-bottom: 16px; }
h2 { margin: 0 0 12px; font-size: 1.15rem; display: flex; align-items: center; gap: 8px; }
h3 { margin: 0 0 10px; font-size: 0.98rem; }
.count-pill {
  font-size: 0.78rem;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 999px;
  background: var(--surface-alt);
  color: var(--muted);
}
.split-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 16px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.86em; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 0.76rem;
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
footer { text-align: center; color: var(--muted); font-size: 0.82rem; margin-top: 24px; }
@media print {
  .controls { display: none; }
  .report-header, .report-section, .kpi-card { break-inside: avoid; }
}
"#;

const FILTER_JS: &str = r#"(function () {
  var search = document.getElementById('search-input');
  var tabs = document.querySelectorAll('.tab');
  var sections = document.querySelectorAll('.report-section');
  var activeSection = 'all';

  function applyFilters() {
    var q = search ? search.value.trim().toLowerCase() : '';
    sections.forEach(function (sec) {
      var name = sec.getAttribute('data-section');
      sec.hidden = activeSection !== 'all' && name !== activeSection;
      sec.querySelectorAll('.filter-row').forEach(function (row) {
        var text = (row.textContent || '').toLowerCase();
        row.hidden = q.length > 0 && text.indexOf(q) === -1;
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

  if (search) {
    search.addEventListener('input', applyFilters);
  }
})();
"#;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use cargoscope_core::policy::{Rule, Violation, ViolationLevel};
    use cargoscope_core::{
        AdvisoryFinding, AdvisoryKind, Checks, DependencyKind, Inventory, Package, PackageInfo,
        Report, Severity, UnusedConfidence, UnusedFinding,
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
    fn escapes_html_characters_and_blocks_non_http_urls() {
        assert_eq!(escape_html("<a&\"'>"), "&lt;a&amp;&quot;&#39;&gt;");

        let html = render_html(Path::new("/work/<app>"), &sample_report(), false);
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
        let default_html = render_html(Path::new("."), &report, false);
        assert!(default_html.contains("dead_dep"));
        assert!(!default_html.contains("maybe_dep"));
        assert!(default_html.contains("1 possibly-unused dependency hidden"));
        assert!(default_html.contains("RUSTSEC-2026-0001"));
        assert!(default_html.contains("YANKED"));
        assert!(default_html.contains("1.0.130"));
        assert!(default_html.contains("MIT OR Apache-2.0"));
        assert!(default_html.contains("2</strong> / 2"));

        let uncertain_html = render_html(Path::new("."), &report, true);
        assert!(uncertain_html.contains("maybe_dep"));
        assert!(!uncertain_html.contains("possibly-unused dependency hidden"));
    }
}
