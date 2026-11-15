//! CycloneDX 1.5 JSON SBOM output.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cargoscope_core::{
    AdvisoryFinding, AdvisoryKind, Inventory, Package, Report, Severity, VERSION,
};
use serde_json::{Map, Value, json};

/// CycloneDX JSON schema URL for specification version 1.5.
pub const SCHEMA_URL: &str = "http://cyclonedx.org/schema/bom-1.5.schema.json";

/// Renders the scan report as a CycloneDX 1.5 JSON SBOM, terminated by a newline.
#[must_use]
pub fn render_cyclonedx(project_root: &Path, report: &Report) -> String {
    let inventory = &report.inventory;
    let refs = build_bom_refs(inventory);
    let roots: Vec<usize> = inventory
        .packages
        .iter()
        .enumerate()
        .filter_map(|(index, package)| package.root.then_some(index))
        .collect();

    let (metadata_component, components) = if roots.len() == 1 {
        let root_index = roots[0];
        let components: Vec<Value> = (0..inventory.packages.len())
            .filter(|&index| index != root_index)
            .map(|index| component_json(inventory, report, &refs, index))
            .collect();
        (
            component_json(inventory, report, &refs, root_index),
            components,
        )
    } else {
        let metadata_component = json!({
            "type": "application",
            "bom-ref": "workspace",
            "name": workspace_name(project_root),
        });
        let components: Vec<Value> = (0..inventory.packages.len())
            .map(|index| component_json(inventory, report, &refs, index))
            .collect();
        (metadata_component, components)
    };

    let mut dependencies = Vec::new();
    if roots.len() != 1 {
        let root_refs: Vec<&str> = roots.iter().map(|&index| refs[index].as_str()).collect();
        dependencies.push(json!({
            "ref": "workspace",
            "dependsOn": root_refs,
        }));
    }
    for (index, package) in inventory.packages.iter().enumerate() {
        dependencies.push(dependency_json(package, &refs, index));
    }

    let mut bom = Map::new();
    bom.insert("$schema".to_owned(), json!(SCHEMA_URL));
    bom.insert("bomFormat".to_owned(), json!("CycloneDX"));
    bom.insert("specVersion".to_owned(), json!("1.5"));
    bom.insert("version".to_owned(), json!(1));
    bom.insert(
        "metadata".to_owned(),
        json!({
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "CargoScope",
                    "version": VERSION,
                    "externalReferences": [{
                        "type": "website",
                        "url": "https://github.com/HarpeLm/CargoScope",
                    }],
                }],
            },
            "component": metadata_component,
        }),
    );
    bom.insert("components".to_owned(), Value::Array(components));
    bom.insert("dependencies".to_owned(), Value::Array(dependencies));
    if report.checks.advisories {
        let vulnerabilities: Vec<Value> = report
            .advisories
            .iter()
            .map(|finding| vulnerability_json(finding, &refs))
            .collect();
        bom.insert("vulnerabilities".to_owned(), Value::Array(vulnerabilities));
    }

    let mut text = serde_json::to_string_pretty(&Value::Object(bom)).unwrap_or_default();
    text.push('\n');
    text
}

fn build_bom_refs(inventory: &Inventory) -> Vec<String> {
    let mut counts: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for package in &inventory.packages {
        *counts
            .entry((package.name.as_str(), package.version.as_str()))
            .or_default() += 1;
    }
    inventory
        .packages
        .iter()
        .enumerate()
        .map(|(index, package)| {
            let key = (package.name.as_str(), package.version.as_str());
            if counts.get(&key).copied().unwrap_or(0) > 1 {
                format!("pkg:cargo/{}@{}#{index}", package.name, package.version)
            } else {
                format!("pkg:cargo/{}@{}", package.name, package.version)
            }
        })
        .collect()
}

fn workspace_name(project_root: &Path) -> &str {
    project_root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .unwrap_or("workspace")
}

fn component_json(inventory: &Inventory, report: &Report, refs: &[String], index: usize) -> Value {
    let package = &inventory.packages[index];
    let mut object = Map::new();
    object.insert(
        "type".to_owned(),
        json!(if package.root {
            "application"
        } else {
            "library"
        }),
    );
    object.insert("bom-ref".to_owned(), json!(refs[index]));
    object.insert("name".to_owned(), json!(package.name));
    object.insert("version".to_owned(), json!(package.version));
    object.insert(
        "purl".to_owned(),
        json!(format!("pkg:cargo/{}@{}", package.name, package.version)),
    );
    object.insert("scope".to_owned(), json!("required"));
    if let Some(expression) = report
        .package_info
        .get(index)
        .and_then(|info| info.license.as_deref())
    {
        object.insert("licenses".to_owned(), json!([{ "expression": expression }]));
    }
    if let Some(source) = &package.source {
        object.insert(
            "externalReferences".to_owned(),
            json!([{ "type": "distribution", "url": source }]),
        );
    }
    Value::Object(object)
}

fn dependency_json(package: &Package, refs: &[String], index: usize) -> Value {
    let mut seen = BTreeSet::new();
    let mut depends_on = Vec::new();
    for &dep in &package.dependencies {
        if let Some(dep_ref) = refs.get(dep)
            && seen.insert(dep_ref.as_str())
        {
            depends_on.push(dep_ref.as_str());
        }
    }
    json!({
        "ref": refs[index],
        "dependsOn": depends_on,
    })
}

fn vulnerability_json(finding: &AdvisoryFinding, refs: &[String]) -> Value {
    let severity = match &finding.kind {
        AdvisoryKind::Vulnerability => finding.severity.map_or("unknown", Severity::as_str),
        AdvisoryKind::Informational(_) => "info",
    };
    let mut object = Map::new();
    object.insert("id".to_owned(), json!(finding.id));
    object.insert(
        "source".to_owned(),
        json!({ "name": "RustSec", "url": "https://rustsec.org" }),
    );
    object.insert("description".to_owned(), json!(finding.title));
    object.insert(
        "ratings".to_owned(),
        json!([{
            "source": { "name": "RustSec" },
            "severity": severity,
        }]),
    );
    if is_iso_date(&finding.date) {
        object.insert(
            "published".to_owned(),
            json!(format!("{}T00:00:00Z", finding.date)),
        );
    }
    if let Some(url) = &finding.url {
        object.insert("advisories".to_owned(), json!([{ "url": url }]));
    }
    if !finding.patched.is_empty() {
        object.insert(
            "recommendation".to_owned(),
            json!(format!("Upgrade to {}", finding.patched.join(" or "))),
        );
    }
    if let Some(target_ref) = refs.get(finding.package) {
        object.insert("affects".to_owned(), json!([{ "ref": target_ref }]));
    }
    if let Some(reason) = &finding.ignored {
        object.insert(
            "analysis".to_owned(),
            json!({
                "state": "not_affected",
                "detail": reason,
            }),
        );
    }
    Value::Object(object)
}

fn is_iso_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    bytes.len() == 10 && bytes[4] == b'-' && bytes[7] == b'-'
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use cargoscope_core::{
        AdvisoryFinding, AdvisoryKind, Checks, Inventory, Package, PackageInfo, Report, Severity,
    };

    use super::{SCHEMA_URL, render_cyclonedx};

    fn base_report(packages: Vec<Package>, package_info: Vec<PackageInfo>) -> Report {
        Report {
            checks: Checks::ALL,
            inventory: Inventory { packages },
            advisories: Vec::new(),
            package_info,
            registry_date: Some("2026-11-15".to_owned()),
            unused: Vec::new(),
            advisory_db_date: Some("2026-11-15".to_owned()),
            unused_precise: false,
            policy: None,
            warnings: Vec::new(),
            direct_kinds: BTreeMap::new(),
        }
    }

    #[test]
    fn renders_single_root_components_graph_and_vulnerabilities() {
        let mut report = base_report(
            vec![
                Package {
                    name: "app".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: false,
                    dependencies: vec![1],
                },
                Package {
                    name: "serde_json".to_owned(),
                    version: "1.0.128".to_owned(),
                    source: Some(
                        "registry+https://github.com/rust-lang/crates.io-index".to_owned(),
                    ),
                    root: false,
                    direct: true,
                    dependencies: vec![],
                },
            ],
            vec![
                PackageInfo::default(),
                PackageInfo {
                    license: Some("MIT OR Apache-2.0".to_owned()),
                    ..Default::default()
                },
            ],
        );
        report.advisories = vec![
            AdvisoryFinding {
                package: 1,
                id: "RUSTSEC-2026-0001".to_owned(),
                aliases: vec!["CVE-2026-0001".to_owned()],
                title: "Example vulnerability".to_owned(),
                date: "2026-01-10".to_owned(),
                url: Some("https://rustsec.org/advisories/RUSTSEC-2026-0001".to_owned()),
                kind: AdvisoryKind::Vulnerability,
                severity: Some(Severity::High),
                patched: vec![">= 1.0.200".to_owned()],
                ignored: Some("unreachable code path".to_owned()),
            },
            AdvisoryFinding {
                package: 1,
                id: "RUSTSEC-2026-0002".to_owned(),
                aliases: vec![],
                title: "Notice".to_owned(),
                date: "2026-02-01".to_owned(),
                url: None,
                kind: AdvisoryKind::Informational("unmaintained".to_owned()),
                severity: None,
                patched: vec![],
                ignored: None,
            },
        ];

        let rendered = render_cyclonedx(Path::new("/tmp/app"), &report);
        assert!(rendered.ends_with('\n'));
        let bom: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(bom["$schema"], SCHEMA_URL);
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.5");
        assert_eq!(bom["version"], 1);
        assert_eq!(bom["metadata"]["component"]["name"], "app");
        assert_eq!(bom["metadata"]["component"]["purl"], "pkg:cargo/app@0.1.0");

        let components = bom["components"].as_array().expect("components");
        assert_eq!(components.len(), 1);
        assert_eq!(components[0]["type"], "library");
        assert_eq!(components[0]["purl"], "pkg:cargo/serde_json@1.0.128");
        assert_eq!(
            components[0]["licenses"][0]["expression"],
            "MIT OR Apache-2.0"
        );
        assert_eq!(
            components[0]["externalReferences"][0]["url"],
            "registry+https://github.com/rust-lang/crates.io-index"
        );

        let deps = bom["dependencies"].as_array().expect("dependencies");
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0]["ref"], "pkg:cargo/app@0.1.0");
        assert_eq!(deps[0]["dependsOn"][0], "pkg:cargo/serde_json@1.0.128");

        let vulns = bom["vulnerabilities"].as_array().expect("vulnerabilities");
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0]["id"], "RUSTSEC-2026-0001");
        assert_eq!(vulns[0]["ratings"][0]["severity"], "high");
        assert_eq!(vulns[0]["published"], "2026-01-10T00:00:00Z");
        assert_eq!(vulns[0]["recommendation"], "Upgrade to >= 1.0.200");
        assert_eq!(
            vulns[0]["affects"][0]["ref"],
            "pkg:cargo/serde_json@1.0.128"
        );
        assert_eq!(vulns[0]["analysis"]["state"], "not_affected");
        assert_eq!(vulns[0]["analysis"]["detail"], "unreachable code path");
        assert_eq!(vulns[1]["ratings"][0]["severity"], "info");
    }

    #[test]
    fn renders_multi_root_workspace_and_disambiguates_duplicate_bom_refs() {
        let mut report = base_report(
            vec![
                Package {
                    name: "cli".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: false,
                    dependencies: vec![2],
                },
                Package {
                    name: "core".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: false,
                    dependencies: vec![3],
                },
                Package {
                    name: "dup".to_owned(),
                    version: "1.0.0".to_owned(),
                    source: Some("registry+a".to_owned()),
                    root: false,
                    direct: true,
                    dependencies: vec![],
                },
                Package {
                    name: "dup".to_owned(),
                    version: "1.0.0".to_owned(),
                    source: Some("git+b".to_owned()),
                    root: false,
                    direct: true,
                    dependencies: vec![],
                },
            ],
            vec![PackageInfo::default(); 4],
        );
        report.checks.advisories = false;

        let bom: serde_json::Value =
            serde_json::from_str(&render_cyclonedx(Path::new("/work/my-ws"), &report))
                .expect("valid JSON");
        assert_eq!(bom["metadata"]["component"]["bom-ref"], "workspace");
        assert_eq!(bom["metadata"]["component"]["name"], "my-ws");
        assert_eq!(bom["components"].as_array().expect("components").len(), 4);
        assert_ne!(
            bom["components"][2]["bom-ref"],
            bom["components"][3]["bom-ref"]
        );
        let deps = bom["dependencies"].as_array().expect("dependencies");
        assert_eq!(deps[0]["ref"], "workspace");
        assert_eq!(deps[0]["dependsOn"].as_array().expect("roots").len(), 2);
        assert!(bom.get("vulnerabilities").is_none());
    }
}
