//! SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers.
//!
//! Results: one per advisory, per yanked version in use, and per
//! likely-unused dependency (possibly-unused ones only on request). Ignored
//! unused dependencies are never reported.

use std::collections::BTreeMap;

use cargoscope_core::{AdvisoryFinding, AdvisoryKind, Report, Severity, UnusedConfidence, VERSION};
use serde_json::{Value, json};

/// SARIF rule ID for unused dependencies.
pub const UNUSED_RULE: &str = "cargoscope/unused-dependency";
/// SARIF rule ID for yanked versions in use.
pub const YANKED_RULE: &str = "cargoscope/yanked-version";

/// Where findings are located in the scanned project.
#[derive(Debug, Clone, Default)]
pub struct SarifLocations {
    /// URI of `Cargo.lock`, relative to the repository root (forward slashes).
    pub lockfile_uri: String,
    /// 1-based line of each package in `Cargo.lock`, in inventory order.
    pub package_lines: Vec<Option<u32>>,
    /// URI and 1-based line of the declaration of each unused finding, in
    /// `Report::unused` order.
    pub unused_locations: Vec<(String, Option<u32>)>,
}

fn level(finding: &AdvisoryFinding) -> &'static str {
    match (&finding.kind, finding.severity) {
        (AdvisoryKind::Informational(_), _) => "note",
        (_, Some(Severity::High | Severity::Critical)) => "error",
        (_, Some(Severity::Low | Severity::None)) => "note",
        _ => "warning",
    }
}

/// Representative score for GitHub's `security-severity` property, which
/// sorts alerts into critical (≥ 9.0), high (≥ 7.0), medium (≥ 4.0) and low.
fn security_severity(severity: Option<Severity>) -> &'static str {
    match severity {
        Some(Severity::Critical) => "9.5",
        Some(Severity::High) => "8.0",
        Some(Severity::Medium) | None => "5.5",
        Some(Severity::Low) => "2.0",
        Some(Severity::None) => "0.0",
    }
}

fn location(uri: &str, line: Option<u32>) -> Value {
    let mut physical = json!({ "artifactLocation": { "uri": uri } });
    if let Some(line) = line {
        physical["region"] = json!({ "startLine": line });
    }
    json!({ "physicalLocation": physical })
}

fn chain(report: &Report, index: usize) -> Option<String> {
    let path = report.inventory.path_to(index)?;
    let names: Vec<&str> = path
        .iter()
        .map(|&step| report.inventory.packages[step].name.as_str())
        .collect();
    Some(names.join(" -> "))
}

/// Renders the report as a SARIF 2.1.0 log, terminated by a newline.
#[must_use]
pub fn render_sarif(report: &Report, locations: &SarifLocations, show_uncertain: bool) -> String {
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut results = Vec::new();
    let package_line = |index: usize| locations.package_lines.get(index).copied().flatten();

    for finding in &report.advisories {
        let package = &report.inventory.packages[finding.package];
        let mut tags = vec!["security".to_owned(), "dependency".to_owned()];
        let mut properties = json!({});
        match &finding.kind {
            AdvisoryKind::Vulnerability => {
                tags.push("vulnerability".to_owned());
                properties["security-severity"] = json!(security_severity(finding.severity));
            }
            AdvisoryKind::Informational(kind) => tags.push(kind.clone()),
        }
        properties["tags"] = json!(tags);
        let mut rule = json!({
            "id": finding.id,
            "name": finding.id,
            "shortDescription": { "text": finding.title },
            "fullDescription": { "text": format!("{} affects the `{}` crate.", finding.id, package.name) },
            "defaultConfiguration": { "level": level(finding) },
            "properties": properties,
        });
        if let Some(url) = &finding.url {
            rule["helpUri"] = json!(url);
        }
        rules.entry(finding.id.clone()).or_insert(rule);

        let via = chain(report, finding.package)
            .map(|chain| format!(" Introduced via {chain}."))
            .unwrap_or_default();
        let fix = if finding.patched.is_empty() {
            " No fixed version is available.".to_owned()
        } else {
            format!(" Fix: upgrade to {}.", finding.patched.join(" or "))
        };
        let mut result = json!({
            "ruleId": finding.id,
            "level": level(finding),
            "message": { "text": format!("{} {} is affected by {}: {}.{via}{fix}", package.name, package.version, finding.id, finding.title) },
            "locations": [location(&locations.lockfile_uri, package_line(finding.package))],
        });
        // Ignored advisories are kept as suppressed results, so that code
        // scanning shows them as dismissed with the reason.
        if let Some(reason) = &finding.ignored {
            result["suppressions"] = json!([{ "kind": "external", "justification": reason }]);
        }
        results.push(result);
    }

    for (index, info) in report.package_info.iter().enumerate() {
        if info.yanked != Some(true) {
            continue;
        }
        let package = &report.inventory.packages[index];
        rules.entry(YANKED_RULE.to_owned()).or_insert_with(|| {
            json!({
                "id": YANKED_RULE,
                "name": "YankedVersion",
                "shortDescription": { "text": "A yanked crate version is in use" },
                "fullDescription": { "text": "The resolved version was yanked from crates.io, usually because it is broken or insecure." },
                "defaultConfiguration": { "level": "warning" },
                "properties": { "tags": ["dependency", "yanked"] },
            })
        });
        let via = chain(report, index)
            .map(|chain| format!(" Introduced via {chain}."))
            .unwrap_or_default();
        results.push(json!({
            "ruleId": YANKED_RULE,
            "level": "warning",
            "message": { "text": format!("{} {} has been yanked from crates.io.{via}", package.name, package.version) },
            "locations": [location(&locations.lockfile_uri, package_line(index))],
        }));
    }

    for violation in report.policy.iter().flatten() {
        let package = &report.inventory.packages[violation.package];
        let rule_id = format!("cargoscope/policy-{}", violation.rule.as_str());
        rules.entry(rule_id.clone()).or_insert_with(|| {
            json!({
                "id": rule_id,
                "name": format!("Policy{}", violation.rule.as_str()),
                "shortDescription": { "text": format!("A dependency breaks the {} policy of cargoscope.toml", violation.rule.as_str()) },
                "defaultConfiguration": { "level": "error" },
                "properties": { "tags": ["dependency", "policy"] },
            })
        });
        let via = chain(report, violation.package)
            .map(|chain| format!(" Introduced via {chain}."))
            .unwrap_or_default();
        results.push(json!({
            "ruleId": rule_id,
            "level": "error",
            "message": { "text": format!("{} {}: {}.{via}", package.name, package.version, violation.message) },
            "locations": [location(&locations.lockfile_uri, package_line(violation.package))],
        }));
    }

    for (index, finding) in report.unused.iter().enumerate() {
        let wanted = finding.confidence == UnusedConfidence::Likely || show_uncertain;
        if finding.ignored.is_some() || !wanted {
            continue;
        }
        rules.entry(UNUSED_RULE.to_owned()).or_insert_with(|| {
            json!({
                "id": UNUSED_RULE,
                "name": "UnusedDependency",
                "shortDescription": { "text": "A declared dependency seems unused" },
                "fullDescription": { "text": "No reference to the dependency was found in the package sources (static analysis: a candidate to verify)." },
                "defaultConfiguration": { "level": "note" },
                "properties": { "tags": ["dependency", "maintainability"] },
            })
        });
        let (uri, line) = locations
            .unused_locations
            .get(index)
            .cloned()
            .unwrap_or_else(|| (finding.manifest.clone(), None));
        results.push(json!({
            "ruleId": UNUSED_RULE,
            "level": "note",
            "message": { "text": format!(
                "`{}` in [{}] is {}: {}.",
                finding.dependency,
                finding.kind.section(),
                finding.confidence.as_str(),
                finding.evidence.join("; ")
            ) },
            "locations": [location(&uri, line)],
            "properties": { "confidence": finding.confidence.as_str() },
        }));
    }

    let log = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "CargoScope",
                "version": VERSION,
                "semanticVersion": VERSION,
                "informationUri": "https://github.com/HarpeLm/CargoScope",
                "rules": rules.into_values().collect::<Vec<_>>(),
            } },
            "results": results,
        }],
    });
    let mut text = serde_json::to_string_pretty(&log).unwrap_or_default();
    text.push('\n');
    text
}
