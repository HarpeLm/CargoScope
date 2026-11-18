//! Multi-project aggregation of CargoScope JSON reports (`cargoscope aggregate`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use serde_json::{Value, json};

use crate::Paint;
use crate::html::escape_html;

/// Version of the aggregated JSON report format.
pub const AGGREGATE_FORMAT_VERSION: u32 = 1;

/// Summary metrics for one scanned project report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSummary {
    /// Human-readable project name (root crate name(s), or report target/path).
    pub name: String,
    /// `target` field from the JSON report.
    pub target: String,
    /// Number of resolved packages in the report.
    pub packages: usize,
    /// Active (non-ignored) vulnerability findings in the project.
    pub vulnerabilities: usize,
    /// Active likely-unused dependency findings in the project.
    pub likely_unused: usize,
}

/// An advisory aggregated across one or more projects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedAdvisory {
    /// Advisory identifier (`RUSTSEC-...`).
    pub id: String,
    /// Crate name.
    pub package: String,
    /// `vulnerability`, `informational`, or `ignored`.
    pub kind: String,
    /// Severity string (`critical`, `high`, `medium`, `low`, `none`), if scored.
    pub severity: Option<String>,
    /// Short advisory title.
    pub title: String,
    /// Advisory URL, if present.
    pub url: Option<String>,
    /// Patched version requirements.
    pub patched: Vec<String>,
    /// Highest urgency relevance across affected projects (`affects-you` < `possibly` < `unlikely`).
    pub relevance: String,
    /// Representative relevance reason when not `affects-you`.
    pub relevance_reason: Option<String>,
    /// Affected projects as `(project_name, package_version, relevance)`.
    pub projects: Vec<(String, String, String)>,
}

/// One license expression observed across one or more projects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedLicense {
    /// License expression or `"unknown"`.
    pub expression: String,
    /// Projects where the license appears.
    pub projects: Vec<String>,
    /// Total resolved non-root package occurrences carrying this license.
    pub packages: usize,
}

/// One project's usage of an outdated dependency:
/// `(project_name, current_version, compatible_version, latest_version)`.
pub type OutdatedUsage = (String, String, Option<String>, Option<String>);

/// One outdated direct dependency observed across one or more projects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedOutdated {
    /// Direct crate name.
    pub name: String,
    /// `(project_name, current_version, compatible_version, latest_version)`.
    pub projects: Vec<OutdatedUsage>,
}

/// One likely-unused dependency finding in an aggregated report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedUnused {
    /// Project name.
    pub project: String,
    /// Manifest path within that project.
    pub manifest: String,
    /// Dependency table section.
    pub section: String,
    /// Declared dependency name.
    pub dependency: String,
}

/// Consolidated view over multiple CargoScope JSON reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AggregatedReport {
    /// Per-project summary rows.
    pub projects: Vec<ProjectSummary>,
    /// Advisories merged across projects, ordered by relevance then severity.
    pub advisories: Vec<AggregatedAdvisory>,
    /// License expressions merged across projects, heaviest first.
    pub licenses: Vec<AggregatedLicense>,
    /// Outdated direct dependencies grouped by crate name.
    pub outdated: Vec<AggregatedOutdated>,
    /// Likely-unused dependencies across all projects.
    pub unused: Vec<AggregatedUnused>,
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn project_name(label: &str, report: &Value, used: &mut BTreeSet<String>) -> String {
    let mut roots: Vec<&str> = array(report, "packages")
        .iter()
        .filter(|pkg| str_field(pkg, "scope") == "root")
        .map(|pkg| str_field(pkg, "name"))
        .filter(|name| !name.is_empty())
        .collect();
    roots.sort_unstable();
    roots.dedup();
    let base = if !roots.is_empty() {
        roots.join(", ")
    } else {
        let target = str_field(report, "target");
        if target.is_empty() || target == "." {
            label.to_owned()
        } else {
            target.to_owned()
        }
    };
    if used.insert(base.clone()) {
        base
    } else {
        let candidate = format!("{base} ({label})");
        used.insert(candidate.clone());
        candidate
    }
}

fn relevance_rank(relevance: &str) -> u8 {
    match relevance {
        "affects-you" => 0,
        "possibly" => 1,
        "unlikely" => 2,
        _ => 3,
    }
}

fn severity_rank(severity: Option<&str>) -> u8 {
    match severity {
        Some("critical") => 0,
        Some("high") => 1,
        Some("medium") => 2,
        Some("low") => 3,
        Some("none") => 4,
        None => 1,
        Some(_) => 5,
    }
}

/// Aggregates multiple version-1 JSON reports (`(label, json)`) into one consolidated view.
#[must_use]
pub fn aggregate(reports: &[(String, Value)]) -> AggregatedReport {
    let mut out = AggregatedReport::default();
    let mut used_names = BTreeSet::new();
    let mut advisory_map: BTreeMap<(String, String, String), AggregatedAdvisory> = BTreeMap::new();
    let mut license_map: BTreeMap<String, (BTreeSet<String>, usize)> = BTreeMap::new();
    let mut outdated_map: BTreeMap<String, Vec<OutdatedUsage>> = BTreeMap::new();

    for (label, report) in reports {
        let name = project_name(label, report, &mut used_names);
        let target = str_field(report, "target").to_owned();
        let packages = array(report, "packages");
        let advisories = array(report, "advisories");
        let unused = array(report, "unused");

        let mut active_vulns = 0;
        for advisory in advisories {
            let ignored = advisory
                .get("ignored_reason")
                .is_some_and(|reason| !reason.is_null());
            let raw_kind = str_field(advisory, "kind");
            let kind = if ignored {
                "ignored".to_owned()
            } else if raw_kind == "vulnerability" {
                active_vulns += 1;
                "vulnerability".to_owned()
            } else {
                "informational".to_owned()
            };
            let id = str_field(advisory, "id").to_owned();
            let pkg_obj = advisory.get("package");
            let pkg_name = pkg_obj
                .map(|p| str_field(p, "name"))
                .unwrap_or_default()
                .to_owned();
            let pkg_version = pkg_obj
                .map(|p| str_field(p, "version"))
                .unwrap_or_default()
                .to_owned();
            let rel = advisory
                .get("relevance")
                .and_then(Value::as_str)
                .unwrap_or("affects-you")
                .to_owned();
            let rel_reason = advisory
                .get("relevance_reason")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let severity = advisory
                .get("severity")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let url = advisory
                .get("url")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let patched = array(advisory, "patched")
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();

            let key = (id.clone(), pkg_name.clone(), kind.clone());
            let entry = advisory_map
                .entry(key)
                .or_insert_with(|| AggregatedAdvisory {
                    id,
                    package: pkg_name,
                    kind,
                    severity,
                    title: str_field(advisory, "title").to_owned(),
                    url,
                    patched,
                    relevance: rel.clone(),
                    relevance_reason: rel_reason.clone(),
                    projects: Vec::new(),
                });
            if relevance_rank(&rel) < relevance_rank(&entry.relevance) {
                entry.relevance.clone_from(&rel);
                entry.relevance_reason = rel_reason;
            } else if entry.relevance_reason.is_none() {
                entry.relevance_reason = rel_reason;
            }
            entry.projects.push((name.clone(), pkg_version, rel));
        }

        for package in packages {
            let scope = str_field(package, "scope");
            if scope != "root" {
                let expr = package
                    .get("license")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                let lic_entry = license_map.entry(expr).or_default();
                lic_entry.0.insert(name.clone());
                lic_entry.1 += 1;
            }
            if package.get("direct").and_then(Value::as_bool) == Some(true)
                && package.get("outdated").and_then(Value::as_bool) == Some(true)
            {
                let pkg_name = str_field(package, "name").to_owned();
                let current = str_field(package, "version").to_owned();
                let compatible = package
                    .get("latest_compatible")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let latest = package
                    .get("latest_version")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                outdated_map.entry(pkg_name).or_default().push((
                    name.clone(),
                    current,
                    compatible,
                    latest,
                ));
            }
        }

        let mut active_unused = 0;
        for finding in unused {
            if str_field(finding, "confidence") == "likely-unused"
                && finding.get("ignored_reason").is_none_or(Value::is_null)
            {
                active_unused += 1;
                out.unused.push(AggregatedUnused {
                    project: name.clone(),
                    manifest: str_field(finding, "manifest").to_owned(),
                    section: str_field(finding, "section").to_owned(),
                    dependency: str_field(finding, "dependency").to_owned(),
                });
            }
        }

        out.projects.push(ProjectSummary {
            name,
            target,
            packages: packages.len(),
            vulnerabilities: active_vulns,
            likely_unused: active_unused,
        });
    }

    let mut advisories: Vec<AggregatedAdvisory> = advisory_map.into_values().collect();
    advisories.sort_by(|left, right| {
        let kind_rank = |k: &str| match k {
            "vulnerability" => 0,
            "informational" => 1,
            _ => 2,
        };
        kind_rank(&left.kind)
            .cmp(&kind_rank(&right.kind))
            .then(relevance_rank(&left.relevance).cmp(&relevance_rank(&right.relevance)))
            .then(
                severity_rank(left.severity.as_deref())
                    .cmp(&severity_rank(right.severity.as_deref())),
            )
            .then(right.projects.len().cmp(&left.projects.len()))
            .then(left.id.cmp(&right.id))
    });
    out.advisories = advisories;

    let mut licenses: Vec<AggregatedLicense> = license_map
        .into_iter()
        .map(|(expression, (projects, packages))| AggregatedLicense {
            expression,
            projects: projects.into_iter().collect(),
            packages,
        })
        .collect();
    licenses.sort_by(|left, right| {
        right
            .projects
            .len()
            .cmp(&left.projects.len())
            .then(right.packages.cmp(&left.packages))
            .then(left.expression.cmp(&right.expression))
    });
    out.licenses = licenses;

    out.outdated = outdated_map
        .into_iter()
        .map(|(name, projects)| AggregatedOutdated { name, projects })
        .collect();
    out.outdated.sort_by(|left, right| {
        right
            .projects
            .len()
            .cmp(&left.projects.len())
            .then(left.name.cmp(&right.name))
    });

    out
}

/// Renders an aggregated report as terminal or plain text.
#[must_use]
pub fn render_aggregate_text(report: &AggregatedReport, color: bool) -> String {
    let paint = Paint::new(color);
    let mut out = format!(
        "{} ({} project{})\n",
        paint.bold("CargoScope aggregate"),
        report.projects.len(),
        if report.projects.len() == 1 { "" } else { "s" }
    );

    let _ = writeln!(
        out,
        "\n{}: {}",
        paint.bold("Projects"),
        report.projects.len()
    );
    for project in &report.projects {
        let _ = writeln!(
            out,
            "- {}: {} packages, {} vulnerabilities, {} likely-unused",
            paint.bold(&project.name),
            project.packages,
            project.vulnerabilities,
            project.likely_unused
        );
    }

    let _ = writeln!(
        out,
        "\n{}: {}",
        paint.bold("Advisories"),
        report.advisories.len()
    );
    for adv in &report.advisories {
        let label = if adv.kind == "vulnerability" {
            adv.severity.as_deref().unwrap_or("unknown severity")
        } else {
            adv.kind.as_str()
        };
        let styled_label = if adv.kind == "vulnerability" {
            match adv.severity.as_deref() {
                Some("critical" | "high") => paint.red(&format!("[{label}]")),
                _ => paint.yellow(&format!("[{label}]")),
            }
        } else {
            paint.dim(&format!("[{label}]"))
        };
        let projects: Vec<String> = adv
            .projects
            .iter()
            .map(|(project, version, _)| format!("{project} ({version})"))
            .collect();
        let rel_note = if adv.relevance != "affects-you" {
            paint.dim(&format!(
                " ({}{})",
                adv.relevance,
                adv.relevance_reason
                    .as_deref()
                    .map(|r| format!(": {r}"))
                    .unwrap_or_default()
            ))
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "- {} {styled_label} {}: {}{rel_note}",
            adv.id,
            paint.bold(&adv.package),
            adv.title
        );
        let _ = writeln!(out, "    projects: {}", projects.join(", "));
        if !adv.patched.is_empty() {
            let _ = writeln!(out, "    fix: upgrade to {}", adv.patched.join(" or "));
        }
    }

    let _ = writeln!(
        out,
        "\n{}: {}",
        paint.bold("Licenses"),
        report.licenses.len()
    );
    for lic in &report.licenses {
        let _ = writeln!(
            out,
            "- {}: {} package(s) across {} project(s) ({})",
            lic.expression,
            lic.packages,
            lic.projects.len(),
            lic.projects.join(", ")
        );
    }

    let _ = writeln!(
        out,
        "\n{}: {}",
        paint.bold("Outdated direct dependencies"),
        report.outdated.len()
    );
    for dep in &report.outdated {
        let usages: Vec<String> = dep
            .projects
            .iter()
            .map(|(project, current, compatible, latest)| {
                let target = compatible.as_deref().or(latest.as_deref()).unwrap_or("?");
                format!("{project} {current} -> {target}")
            })
            .collect();
        let _ = writeln!(out, "- {}: {}", paint.bold(&dep.name), usages.join(", "));
    }

    let _ = writeln!(
        out,
        "\n{}: {}",
        paint.bold("Likely-unused dependencies"),
        report.unused.len()
    );
    for item in &report.unused {
        let _ = writeln!(
            out,
            "- {} ({} [{}]): {}",
            paint.bold(&item.project),
            item.manifest,
            item.section,
            item.dependency
        );
    }
    out
}

/// Renders an aggregated report as JSON.
#[must_use]
pub fn render_aggregate_json(report: &AggregatedReport) -> String {
    let value = json!({
        "aggregate_format_version": AGGREGATE_FORMAT_VERSION,
        "projects": report.projects.iter().map(|p| json!({
            "name": p.name,
            "target": p.target,
            "packages": p.packages,
            "vulnerabilities": p.vulnerabilities,
            "likely_unused": p.likely_unused,
        })).collect::<Vec<_>>(),
        "advisories": report.advisories.iter().map(|a| json!({
            "id": a.id,
            "package": a.package,
            "kind": a.kind,
            "severity": a.severity,
            "title": a.title,
            "url": a.url,
            "patched": a.patched,
            "relevance": a.relevance,
            "relevance_reason": a.relevance_reason,
            "projects": a.projects.iter().map(|(project, version, relevance)| json!({
                "name": project,
                "version": version,
                "relevance": relevance,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "licenses": report.licenses.iter().map(|l| json!({
            "expression": l.expression,
            "projects": l.projects,
            "packages": l.packages,
        })).collect::<Vec<_>>(),
        "outdated": report.outdated.iter().map(|o| json!({
            "name": o.name,
            "projects": o.projects.iter().map(|(project, current, compatible, latest)| json!({
                "name": project,
                "current": current,
                "latest_compatible": compatible,
                "latest_version": latest,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "unused": report.unused.iter().map(|u| json!({
            "project": u.project,
            "manifest": u.manifest,
            "section": u.section,
            "dependency": u.dependency,
        })).collect::<Vec<_>>(),
    });
    let mut text = serde_json::to_string_pretty(&value).unwrap_or_default();
    text.push('\n');
    text
}

/// Renders a standalone HTML report aggregating multiple projects.
#[must_use]
pub fn render_aggregate_html(report: &AggregatedReport) -> String {
    let total_vulns: usize = report
        .advisories
        .iter()
        .filter(|a| a.kind == "vulnerability")
        .count();
    let mut out = String::from(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>CargoScope Aggregate Report</title>\n\
<style>\n\
:root { color-scheme: light dark; --bg: #ffffff; --fg: #18181b; --muted: #52525b; --card: #f4f4f5; --border: #e4e4e7; --red: #dc2626; --amber: #d97706; --green: #16a34a; --blue: #2563eb; }\n\
@media (prefers-color-scheme: dark) { :root { --bg: #09090b; --fg: #f4f4f5; --muted: #a1a1aa; --card: #18181b; --border: #27272a; } }\n\
body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--fg); max-width: 1120px; margin: 2rem auto; padding: 0 1.25rem; line-height: 1.5; }\n\
h1, h2 { margin-top: 2rem; }\n\
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: .75rem; margin: 1.25rem 0; }\n\
.card { background: var(--card); border: 1px solid var(--border); border-radius: .5rem; padding: .85rem 1rem; }\n\
.card .num { font-size: 1.5rem; font-weight: 700; }\n\
.card .lbl { color: var(--muted); font-size: .85rem; }\n\
table { width: 100%; border-collapse: collapse; margin-top: .75rem; font-size: .92rem; }\n\
th, td { text-align: left; padding: .5rem .65rem; border-bottom: 1px solid var(--border); vertical-align: top; }\n\
th { color: var(--muted); font-weight: 600; }\n\
.badge { display: inline-block; padding: .1rem .45rem; border-radius: .35rem; font-size: .78rem; font-weight: 600; background: var(--card); border: 1px solid var(--border); }\n\
.crit, .high { color: var(--red); border-color: var(--red); }\n\
.med { color: var(--amber); border-color: var(--amber); }\n\
.low { color: var(--blue); }\n\
.muted { color: var(--muted); font-size: .85rem; }\n\
code { font-family: ui-monospace, monospace; font-size: .88em; }\n\
</style>\n</head>\n<body>\n<h1>CargoScope Aggregate Report</h1>\n",
    );

    let _ = writeln!(
        out,
        "<div class=\"cards\">\
<div class=\"card\"><div class=\"num\">{}</div><div class=\"lbl\">Projects</div></div>\
<div class=\"card\"><div class=\"num\">{}</div><div class=\"lbl\">Distinct vulnerabilities</div></div>\
<div class=\"card\"><div class=\"num\">{}</div><div class=\"lbl\">License expressions</div></div>\
<div class=\"card\"><div class=\"num\">{}</div><div class=\"lbl\">Outdated crates</div></div>\
<div class=\"card\"><div class=\"num\">{}</div><div class=\"lbl\">Likely-unused deps</div></div>\
</div>",
        report.projects.len(),
        total_vulns,
        report.licenses.len(),
        report.outdated.len(),
        report.unused.len()
    );

    out.push_str("<h2>Projects</h2>\n<table><thead><tr><th>Project</th><th>Packages</th><th>Vulnerabilities</th><th>Likely unused</th></tr></thead><tbody>\n");
    for p in &report.projects {
        let _ = writeln!(
            out,
            "<tr><td><strong>{}</strong><div class=\"muted\"><code>{}</code></div></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&p.name),
            escape_html(&p.target),
            p.packages,
            p.vulnerabilities,
            p.likely_unused
        );
    }
    out.push_str("</tbody></table>\n");

    out.push_str("<h2>Advisories</h2>\n");
    if report.advisories.is_empty() {
        out.push_str("<p class=\"muted\">No known advisories across projects.</p>\n");
    } else {
        out.push_str("<table><thead><tr><th>Advisory</th><th>Package</th><th>Relevance</th><th>Projects</th><th>Details</th></tr></thead><tbody>\n");
        for a in &report.advisories {
            let sev = a.severity.as_deref().unwrap_or(a.kind.as_str());
            let class = match sev {
                "critical" | "high" => "crit",
                "medium" => "med",
                _ => "low",
            };
            let id_html = match a
                .url
                .as_deref()
                .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
            {
                Some(url) => format!(
                    "<a href=\"{}\"><code>{}</code></a>",
                    escape_html(url),
                    escape_html(&a.id)
                ),
                None => format!("<code>{}</code>", escape_html(&a.id)),
            };
            let projs = a
                .projects
                .iter()
                .map(|(proj, ver, _)| format!("{} ({ver})", escape_html(proj)))
                .collect::<Vec<_>>()
                .join(", ");
            let reason_html = a
                .relevance_reason
                .as_deref()
                .map(|r| format!("<div class=\"muted\">{}</div>", escape_html(r)))
                .unwrap_or_default();
            let fix_html = if a.patched.is_empty() {
                String::new()
            } else {
                format!(
                    "<div class=\"muted\">Fix: <code>{}</code></div>",
                    escape_html(&a.patched.join(" or "))
                )
            };
            let _ = writeln!(
                out,
                "<tr><td>{id_html} <span class=\"badge {class}\">{}</span></td><td><code>{}</code></td><td><span class=\"badge\">{}</span>{reason_html}</td><td>{projs}</td><td>{}{fix_html}</td></tr>",
                escape_html(sev),
                escape_html(&a.package),
                escape_html(&a.relevance),
                escape_html(&a.title)
            );
        }
        out.push_str("</tbody></table>\n");
    }

    out.push_str("<h2>Licenses</h2>\n<table><thead><tr><th>License</th><th>Projects</th><th>Packages</th></tr></thead><tbody>\n");
    for l in &report.licenses {
        let _ = writeln!(
            out,
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            escape_html(&l.expression),
            escape_html(&l.projects.join(", ")),
            l.packages
        );
    }
    out.push_str("</tbody></table>\n");

    out.push_str("<h2>Outdated Direct Dependencies</h2>\n<table><thead><tr><th>Crate</th><th>Projects</th></tr></thead><tbody>\n");
    for o in &report.outdated {
        let projs = o
            .projects
            .iter()
            .map(|(proj, cur, comp, lat)| {
                let tgt = comp.as_deref().or(lat.as_deref()).unwrap_or("?");
                format!(
                    "{} (<code>{} &rarr; {}</code>)",
                    escape_html(proj),
                    escape_html(cur),
                    escape_html(tgt)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "<tr><td><code>{}</code></td><td>{projs}</td></tr>",
            escape_html(&o.name)
        );
    }
    out.push_str("</tbody></table>\n");

    out.push_str("<h2>Likely-Unused Dependencies</h2>\n<table><thead><tr><th>Project</th><th>Manifest</th><th>Dependency</th></tr></thead><tbody>\n");
    for u in &report.unused {
        let _ = writeln!(
            out,
            "<tr><td>{}</td><td><code>{} [{}]</code></td><td><code>{}</code></td></tr>",
            escape_html(&u.project),
            escape_html(&u.manifest),
            escape_html(&u.section),
            escape_html(&u.dependency)
        );
    }
    out.push_str("</tbody></table>\n</body>\n</html>\n");
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{aggregate, render_aggregate_html, render_aggregate_json, render_aggregate_text};

    #[test]
    fn merges_advisories_licenses_outdated_and_unused_across_projects() {
        let rep_a = json!({
            "format_version": 1,
            "target": "/work/alpha",
            "advisories": [
                {
                    "id": "RUSTSEC-2026-0001",
                    "title": "Shared vuln",
                    "url": "https://rustsec.org/advisories/RUSTSEC-2026-0001",
                    "kind": "vulnerability",
                    "severity": "high",
                    "package": { "name": "shared", "version": "1.0.0" },
                    "patched": [">= 1.0.1"],
                    "ignored_reason": null,
                    "relevance": "unlikely",
                    "relevance_reason": "only used by dev-dependencies"
                }
            ],
            "packages": [
                { "name": "alpha", "version": "0.1.0", "scope": "root", "direct": false, "license": null, "outdated": false },
                { "name": "shared", "version": "1.0.0", "scope": "direct", "direct": true, "license": "MIT", "outdated": true, "latest_compatible": "1.0.2", "latest_version": "2.0.0" }
            ],
            "unused": [
                { "manifest": "Cargo.toml", "section": "dependencies", "dependency": "log", "confidence": "likely-unused", "ignored_reason": null }
            ]
        });
        let rep_b = json!({
            "format_version": 1,
            "target": "/work/beta",
            "advisories": [
                {
                    "id": "RUSTSEC-2026-0001",
                    "title": "Shared vuln",
                    "url": "https://rustsec.org/advisories/RUSTSEC-2026-0001",
                    "kind": "vulnerability",
                    "severity": "high",
                    "package": { "name": "shared", "version": "1.0.0" },
                    "patched": [">= 1.0.1"],
                    "ignored_reason": null,
                    "relevance": "affects-you",
                    "relevance_reason": null
                }
            ],
            "packages": [
                { "name": "beta", "version": "0.2.0", "scope": "root", "direct": false, "license": null, "outdated": false },
                { "name": "shared", "version": "1.0.0", "scope": "direct", "direct": true, "license": "MIT", "outdated": false }
            ],
            "unused": []
        });

        let aggregated = aggregate(&[("a.json".to_owned(), rep_a), ("b.json".to_owned(), rep_b)]);
        assert_eq!(aggregated.projects.len(), 2);
        assert_eq!(aggregated.advisories.len(), 1);
        assert_eq!(aggregated.advisories[0].relevance, "affects-you");
        assert_eq!(aggregated.advisories[0].projects.len(), 2);
        assert_eq!(aggregated.licenses[0].expression, "MIT");
        assert_eq!(aggregated.licenses[0].packages, 2);
        assert_eq!(aggregated.outdated[0].name, "shared");
        assert_eq!(aggregated.unused.len(), 1);

        let text = render_aggregate_text(&aggregated, false);
        assert!(text.contains("CargoScope aggregate (2 projects)"), "{text}");
        assert!(text.contains("alpha (1.0.0), beta (1.0.0)"), "{text}");
        let colored = render_aggregate_text(&aggregated, true);
        assert!(colored.contains("\u{1b}["));

        let parsed: serde_json::Value =
            serde_json::from_str(&render_aggregate_json(&aggregated)).expect("valid JSON");
        assert_eq!(parsed["aggregate_format_version"], 1);
        assert_eq!(
            parsed["advisories"][0]["projects"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let html = render_aggregate_html(&aggregated);
        assert!(html.contains("CargoScope Aggregate Report"), "{html}");
        assert!(html.contains("RUSTSEC-2026-0001"), "{html}");
    }
}
