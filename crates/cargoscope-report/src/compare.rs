//! Comparison of two JSON reports (`cargoscope compare`), and the baseline
//! used by `cargoscope scan --baseline`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use serde_json::{Value, json};

/// Version of the JSON comparison format.
pub const COMPARISON_FORMAT_VERSION: u32 = 1;

/// An advisory as it appears in a JSON report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdvisoryKey {
    /// Advisory ID.
    pub id: String,
    /// Affected package name.
    pub package: String,
    /// Affected package version.
    pub version: String,
}

/// What changed between two reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Comparison {
    /// Advisories present now and not in the baseline, with their severity
    /// (`None` when unscored) and whether they are vulnerabilities.
    pub new_advisories: Vec<(AdvisoryKey, Option<String>, bool, String)>,
    /// Advisories of the baseline that no longer appear.
    pub resolved_advisories: Vec<AdvisoryKey>,
    /// Packages (`name version`) added.
    pub added_packages: Vec<String>,
    /// Packages (`name version`) removed.
    pub removed_packages: Vec<String>,
    /// Crates whose resolved versions changed: name, before, after.
    pub changed_versions: Vec<(String, Vec<String>, Vec<String>)>,
    /// Likely-unused dependencies that are new (`manifest [section] dependency`).
    pub new_unused: Vec<String>,
    /// Likely-unused dependencies that disappeared.
    pub resolved_unused: Vec<String>,
    /// Yanked versions in use that are new (`name version`).
    pub new_yanked: Vec<String>,
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn array<'a>(report: &'a Value, key: &str) -> &'a [Value] {
    report
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Advisories of a JSON report.
#[must_use]
pub fn advisory_keys(report: &Value) -> BTreeSet<AdvisoryKey> {
    array(report, "advisories")
        .iter()
        .map(|advisory| AdvisoryKey {
            id: text(advisory, "id"),
            package: advisory
                .get("package")
                .map(|package| text(package, "name"))
                .unwrap_or_default(),
            version: advisory
                .get("package")
                .map(|package| text(package, "version"))
                .unwrap_or_default(),
        })
        .collect()
}

fn packages(report: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let mut packages: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in array(report, "packages") {
        packages
            .entry(text(package, "name"))
            .or_default()
            .insert(text(package, "version"));
    }
    packages
}

fn likely_unused(report: &Value) -> BTreeSet<String> {
    array(report, "unused")
        .iter()
        .filter(|finding| text(finding, "confidence") == "likely-unused")
        .filter(|finding| finding.get("ignored_reason").is_none_or(Value::is_null))
        .map(|finding| {
            format!(
                "{} [{}] {}",
                text(finding, "manifest"),
                text(finding, "section"),
                text(finding, "dependency")
            )
        })
        .collect()
}

fn yanked(report: &Value) -> BTreeSet<String> {
    array(report, "packages")
        .iter()
        .filter(|package| package.get("yanked").and_then(Value::as_bool) == Some(true))
        .map(|package| format!("{} {}", text(package, "name"), text(package, "version")))
        .collect()
}

/// Checks that a value looks like a CargoScope JSON report.
///
/// # Errors
///
/// Returns a message naming what is missing.
pub fn check_report(report: &Value) -> Result<(), String> {
    match report.get("format_version").and_then(Value::as_u64) {
        Some(1) => Ok(()),
        Some(other) => Err(format!("unsupported report format_version {other}")),
        None => Err("not a CargoScope JSON report (no format_version)".to_owned()),
    }
}

/// Compares a baseline report with a current one.
#[must_use]
pub fn compare(baseline: &Value, current: &Value) -> Comparison {
    let before = advisory_keys(baseline);
    let new_advisories: Vec<_> = array(current, "advisories")
        .iter()
        .filter_map(|advisory| {
            let key = AdvisoryKey {
                id: text(advisory, "id"),
                package: advisory
                    .get("package")
                    .map(|p| text(p, "name"))
                    .unwrap_or_default(),
                version: advisory
                    .get("package")
                    .map(|p| text(p, "version"))
                    .unwrap_or_default(),
            };
            (!before.contains(&key)).then(|| {
                let severity = advisory
                    .get("severity")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let vulnerability = text(advisory, "kind") == "vulnerability";
                (key, severity, vulnerability, text(advisory, "title"))
            })
        })
        .collect();
    let mut new_advisories: Vec<(AdvisoryKey, Option<String>, bool, String)> = new_advisories;
    new_advisories.sort_by(|left, right| left.0.cmp(&right.0));
    let after = advisory_keys(current);
    let resolved_advisories = before.difference(&after).cloned().collect();

    let old_packages = packages(baseline);
    let new_packages = packages(current);
    let mut added_packages = Vec::new();
    let mut removed_packages = Vec::new();
    let mut changed_versions = Vec::new();
    let names: BTreeSet<&String> = old_packages.keys().chain(new_packages.keys()).collect();
    for name in names {
        match (old_packages.get(name), new_packages.get(name)) {
            (None, Some(versions)) => {
                added_packages.extend(versions.iter().map(|version| format!("{name} {version}")));
            }
            (Some(versions), None) => {
                removed_packages.extend(versions.iter().map(|version| format!("{name} {version}")));
            }
            (Some(old), Some(new)) if old != new => changed_versions.push((
                name.clone(),
                old.iter().cloned().collect(),
                new.iter().cloned().collect(),
            )),
            _ => {}
        }
    }

    let old_unused = likely_unused(baseline);
    let new_unused_set = likely_unused(current);
    let old_yanked = yanked(baseline);

    Comparison {
        new_advisories,
        resolved_advisories,
        added_packages,
        removed_packages,
        changed_versions,
        new_unused: new_unused_set.difference(&old_unused).cloned().collect(),
        resolved_unused: old_unused.difference(&new_unused_set).cloned().collect(),
        new_yanked: yanked(current).difference(&old_yanked).cloned().collect(),
    }
}

fn section(out: &mut String, title: &str, items: &[String]) {
    let _ = writeln!(out, "\n{title}: {}", items.len());
    for item in items {
        let _ = writeln!(out, "- {item}");
    }
}

/// Renders a comparison as text.
#[must_use]
pub fn render_comparison_text(comparison: &Comparison) -> String {
    let mut out = String::from("CargoScope comparison (baseline -> current)\n");
    let new: Vec<String> = comparison
        .new_advisories
        .iter()
        .map(|(key, severity, vulnerability, title)| {
            let label = if *vulnerability {
                severity
                    .clone()
                    .unwrap_or_else(|| "unknown severity".to_owned())
            } else {
                "informational".to_owned()
            };
            format!(
                "{} [{label}] {} {}: {title}",
                key.id, key.package, key.version
            )
        })
        .collect();
    section(&mut out, "New advisories", &new);
    let resolved: Vec<String> = comparison
        .resolved_advisories
        .iter()
        .map(|key| format!("{} {} {}", key.id, key.package, key.version))
        .collect();
    section(&mut out, "Resolved advisories", &resolved);
    section(
        &mut out,
        "New yanked versions in use",
        &comparison.new_yanked,
    );
    section(
        &mut out,
        "New likely-unused dependencies",
        &comparison.new_unused,
    );
    section(
        &mut out,
        "Resolved likely-unused dependencies",
        &comparison.resolved_unused,
    );
    let changed: Vec<String> = comparison
        .changed_versions
        .iter()
        .map(|(name, before, after)| {
            format!("{name} {} -> {}", before.join(", "), after.join(", "))
        })
        .collect();
    section(&mut out, "Changed versions", &changed);
    section(&mut out, "Added packages", &comparison.added_packages);
    section(&mut out, "Removed packages", &comparison.removed_packages);
    out
}

/// Renders a comparison as JSON, terminated by a newline.
#[must_use]
pub fn render_comparison_json(comparison: &Comparison) -> String {
    let key = |key: &AdvisoryKey| json!({ "id": key.id, "package": { "name": key.package, "version": key.version } });
    let value = json!({
        "comparison_format_version": COMPARISON_FORMAT_VERSION,
        "new_advisories": comparison.new_advisories.iter().map(|(k, severity, vulnerability, title)| {
            let mut entry = key(k);
            entry["severity"] = json!(severity);
            entry["kind"] = json!(if *vulnerability { "vulnerability" } else { "informational" });
            entry["title"] = json!(title);
            entry
        }).collect::<Vec<_>>(),
        "resolved_advisories": comparison.resolved_advisories.iter().map(key).collect::<Vec<_>>(),
        "new_yanked": comparison.new_yanked,
        "new_unused": comparison.new_unused,
        "resolved_unused": comparison.resolved_unused,
        "changed_versions": comparison.changed_versions.iter().map(|(name, before, after)| json!({ "name": name, "before": before, "after": after })).collect::<Vec<_>>(),
        "added_packages": comparison.added_packages,
        "removed_packages": comparison.removed_packages,
    });
    let mut text = serde_json::to_string_pretty(&value).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::{compare, render_comparison_text};
    use serde_json::json;

    fn report(
        advisories: serde_json::Value,
        packages: serde_json::Value,
        unused: serde_json::Value,
    ) -> serde_json::Value {
        json!({ "format_version": 1, "advisories": advisories, "packages": packages, "unused": unused })
    }

    #[test]
    fn finds_new_and_resolved_findings_and_version_changes() {
        let baseline = report(
            json!([{ "id": "OLD-1", "kind": "vulnerability", "severity": "high", "title": "old", "package": { "name": "a", "version": "1.0.0" } }]),
            json!([{ "name": "a", "version": "1.0.0" }, { "name": "gone", "version": "0.1.0" }, { "name": "y", "version": "1.0.0", "yanked": false }]),
            json!([{ "manifest": "Cargo.toml", "section": "dependencies", "dependency": "log", "confidence": "likely-unused", "ignored_reason": null }]),
        );
        let current = report(
            json!([{ "id": "NEW-1", "kind": "vulnerability", "severity": null, "title": "new", "package": { "name": "a", "version": "2.0.0" } }]),
            json!([{ "name": "a", "version": "2.0.0" }, { "name": "fresh", "version": "3.0.0" }, { "name": "y", "version": "1.0.0", "yanked": true }]),
            json!([{ "manifest": "Cargo.toml", "section": "dependencies", "dependency": "rand", "confidence": "likely-unused", "ignored_reason": null }]),
        );
        let comparison = compare(&baseline, &current);
        assert_eq!(comparison.new_advisories.len(), 1);
        assert_eq!(comparison.new_advisories[0].0.id, "NEW-1");
        assert_eq!(comparison.resolved_advisories[0].id, "OLD-1");
        assert_eq!(comparison.added_packages, vec!["fresh 3.0.0"]);
        assert_eq!(comparison.removed_packages, vec!["gone 0.1.0"]);
        assert_eq!(
            comparison.changed_versions,
            vec![(
                "a".to_owned(),
                vec!["1.0.0".to_owned()],
                vec!["2.0.0".to_owned()]
            )]
        );
        assert_eq!(
            comparison.new_unused,
            vec!["Cargo.toml [dependencies] rand"]
        );
        assert_eq!(
            comparison.resolved_unused,
            vec!["Cargo.toml [dependencies] log"]
        );
        assert_eq!(comparison.new_yanked, vec!["y 1.0.0"]);
        let text = render_comparison_text(&comparison);
        assert!(text.contains("New advisories: 1\n- NEW-1 [unknown severity] a 2.0.0: new\n"));
    }

    #[test]
    fn identical_reports_have_no_changes() {
        let value = report(
            json!([]),
            json!([{ "name": "a", "version": "1.0.0" }]),
            json!([]),
        );
        assert_eq!(compare(&value, &value), super::Comparison::default());
    }
}
