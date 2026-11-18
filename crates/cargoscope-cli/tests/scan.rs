//! End-to-end tests running the `cargoscope` binary on the fixtures in `tests/fixtures`.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn scan(name: &str, extra: &[&str]) -> Output {
    scan_with_cache(name, extra, &fixture("advisory-cache"))
}

fn scan_with_cache(name: &str, extra: &[&str], cache: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", cache)
        // An empty Cargo home: results must not depend on the crates this
        // machine happens to have downloaded.
        .env("CARGO_HOME", fixture("empty-cargo-home"))
        .arg("scan")
        // Most tests check the package list, which the text report shows only
        // in verbose mode; the flag has no effect on JSON and SARIF.
        .arg("--verbose")
        .arg(fixture(name))
        .args(extra)
        .output()
        .expect("cargoscope binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

#[test]
fn simple_project_marks_direct_and_transitive_packages() {
    let output = scan("simple", &["--fail-on", "none"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("Resolved packages: 4\n"));
    assert!(text.contains("- simple 0.1.0 [root]\n"));
    assert!(text.contains("- serde_json 1.0.128 [direct]"));
    assert!(text.contains("- serde 1.0.210 [transitive]"));
    assert!(text.contains("    via simple -> serde_json -> serde\n"));
    assert!(text.contains("    via simple -> serde_json -> itoa\n"));
}

#[test]
fn workspace_members_contribute_direct_dependencies() {
    let text = stdout(&scan("workspace", &[]));
    assert!(text.contains("- anyhow 1.0.89 [direct]"));
    assert!(text.contains("- memchr 2.7.4 [direct]"));
    assert!(text.contains("- app 0.1.0 [root]\n"));
    assert!(text.contains("- lib 0.1.0 [root]\n"));
}

#[test]
fn renamed_dev_and_build_dependencies_are_direct() {
    let text = stdout(&scan("renamed", &[]));
    assert!(text.contains("- serde_json 1.0.128 [direct]"));
    assert!(text.contains("- tempfile 3.13.0 [direct]"));
    assert!(text.contains("- cc 1.1.30 [direct]"));
}

#[test]
fn json_output_is_versioned() {
    let output = scan("simple", &["--format", "json", "--fail-on", "none"]);
    assert_eq!(output.status.code(), Some(0));
    let json = stdout(&output);
    assert!(json.starts_with("{\"format_version\":1,"));
    assert!(json.contains(
        "\"name\":\"serde_json\",\"version\":\"1.0.128\",\"scope\":\"direct\",\"direct\":true"
    ));
}

#[test]
fn json_output_includes_dependency_path() {
    let json = stdout(&scan("simple", &["--format", "json"]));
    assert!(json.contains(
        "\"name\":\"itoa\",\"version\":\"1.0.11\",\"scope\":\"transitive\",\"direct\":false,\"source\":\"registry+https://github.com/rust-lang/crates.io-index\",\"path\":[{\"name\":\"simple\",\"version\":\"0.1.0\"},{\"name\":\"serde_json\",\"version\":\"1.0.128\"},{\"name\":\"itoa\",\"version\":\"1.0.11\"}]"
    ));
}

#[test]
fn distinguishes_two_versions_of_the_same_crate() {
    let text = stdout(&scan("multi-version", &[]));
    assert!(text.contains("- bitflags 2.6.0 [direct]"));
    assert!(text.contains("- bitflags 1.3.2 [transitive]"));
    assert!(text.contains("    via multi-version -> old-wrapper -> bitflags\n"));
}

#[test]
fn missing_lockfile_is_an_execution_error() {
    let output = scan("no-lockfile", &[]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no Cargo.lock found"));
}

#[test]
fn unknown_option_is_an_execution_error() {
    assert_eq!(scan("simple", &["--nope"]).status.code(), Some(2));
}

#[test]
fn reports_matching_advisories_with_path_and_fix() {
    let output = scan("simple", &[]);
    let text = stdout(&output);
    assert!(text.contains("Advisories: 2 (RustSec database downloaded 2026-01-01)\n"));
    assert!(text.contains(
        "- CARGOSCOPE-TEST-0001 [high] serde_json 1.0.128: Fake vulnerability used by CargoScope tests\n    via simple -> serde_json\n    fix: upgrade to >= 1.0.200\n"
    ));
    assert!(text.contains(
        "- CARGOSCOPE-TEST-0003 [unmaintained] itoa 1.0.11: Fake unmaintained notice used by CargoScope tests\n    via simple -> serde_json -> itoa\n    fix: no fixed version available\n"
    ));
    assert!(
        !text.contains("CARGOSCOPE-TEST-0002"),
        "withdrawn advisory reported"
    );
}

#[test]
fn unaffected_versions_are_not_reported() {
    let output = scan("workspace", &[]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("Advisories: 0"));
    assert!(text.contains("This does not mean the dependencies are safe."));
}

#[test]
fn fail_on_threshold_controls_exit_code() {
    assert_eq!(scan("simple", &[]).status.code(), Some(1));
    assert_eq!(
        scan("simple", &["--fail-on", "high"]).status.code(),
        Some(1)
    );
    assert_eq!(
        scan("simple", &["--fail-on", "critical"]).status.code(),
        Some(0)
    );
    assert_eq!(
        scan("simple", &["--fail-on", "none"]).status.code(),
        Some(0)
    );
}

#[test]
fn json_output_includes_advisories() {
    let json = stdout(&scan("simple", &["--format", "json"]));
    assert!(json.contains(
        "\"advisory_database\":{\"source\":\"RustSec\",\"downloaded_on\":\"2026-01-01\"}"
    ));
    assert!(json.contains("\"id\":\"CARGOSCOPE-TEST-0001\""));
    assert!(json.contains("\"informational\":\"unmaintained\""));
}

#[test]
fn missing_advisory_database_is_an_execution_error() {
    let empty = std::env::temp_dir().join(format!("cargoscope-empty-cache-{}", std::process::id()));
    let output = scan_with_cache("simple", &[], &empty);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("run `cargoscope update` first"));
}

#[test]
fn reports_likely_unused_dependencies_only_by_default() {
    let output = scan("unused", &["--fail-on", "none"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(
        text.contains("Likely-unused dependencies: 5 (static analysis: candidates to verify)\n")
    );
    for likely in [
        "- log [likely-unused] in [dependencies]",
        "- regex [likely-unused] in [dependencies]",
        "- rand [likely-unused] in [dependencies]",
        "- pretty_assertions [likely-unused] in [dev-dependencies]",
        "- pkg-config [likely-unused] in [build-dependencies]",
    ] {
        assert!(text.contains(likely), "missing: {likely}");
    }
    let unused_section = text
        .split("Likely-unused dependencies")
        .nth(1)
        .and_then(|rest| rest.split("\nLicenses of").next())
        .expect("unused section present");
    for used in [
        "serde_json",
        "anyhow",
        "tokio",
        "json5x",
        "unicode-width",
        "tempfile",
        "- cc ",
    ] {
        assert!(
            !unused_section.contains(used),
            "used dependency reported: {used}"
        );
    }
    assert!(
        text.contains("3 possibly-unused dependencies hidden; use --show-uncertain to list them\n")
    );
    assert!(
        text.contains("- once_cell ignored in Cargo.toml, reason: kept for an upcoming feature\n")
    );
}

#[test]
fn show_uncertain_lists_possibly_unused_with_reasons() {
    let text = stdout(&scan("unused", &["--fail-on", "none", "--show-uncertain"]));
    assert!(text.contains("- chrono [possibly-unused]"));
    assert!(text.contains("optional dependency: may only be used to forward a feature"));
    assert!(text.contains("- openssl-sys [possibly-unused]"));
    assert!(text.contains("- idna [possibly-unused]"));
    assert!(
        text.contains("also a transitive dependency: may be declared only to select its features")
    );
    assert!(!text.contains("hidden"));
}

#[test]
fn unused_dependencies_never_fail_the_scan() {
    // The fixture's only advisory is "high"; above that threshold, only
    // unused dependencies remain, and they must not change the exit code.
    assert_eq!(
        scan("unused", &["--fail-on", "critical"]).status.code(),
        Some(0)
    );
}

#[test]
fn json_output_includes_unused_dependencies() {
    let json = stdout(&scan("unused", &["--format", "json", "--fail-on", "none"]));
    assert!(json.contains("{\"dependency\":\"log\",\"package\":\"log\",\"section\":\"dependencies\",\"declared_by\":\"unused-demo\",\"manifest\":\"Cargo.toml\",\"confidence\":\"likely-unused\""));
    assert!(json.contains("\"dependency\":\"chrono\",\"package\":\"chrono\",\"section\":\"dependencies\",\"declared_by\":\"unused-demo\",\"manifest\":\"Cargo.toml\",\"confidence\":\"possibly-unused\""));
    assert!(json.contains("\"ignored_reason\":\"kept for an upcoming feature\""));
    assert!(!json.contains("\"dependency\":\"serde_json\""));
}

#[test]
fn reports_licenses_versions_and_yanked_packages() {
    let text = stdout(&scan("simple", &["--fail-on", "none"]));
    assert!(text.contains(
        "Licenses of 3 registry packages (crates.io data downloaded 2026-01-01):\n- MIT OR Apache-2.0: 2\n- unknown: 1\n"
    ));
    assert!(text.contains(
        "Yanked versions in use: 1\n- itoa 1.0.11\n    via simple -> serde_json -> itoa\n"
    ));
    // 1.0.300 is yanked and 2.0.0-alpha.1 is a pre-release: the latest is 1.0.200 (compatible).
    assert!(text.contains(
        "Outdated packages: 1 (1 direct)\n- serde_json 1.0.128 -> 1.0.200 (compatible), published 2025-12-01\n"
    ));
    assert!(text.contains("- serde_json 1.0.128 [direct] (registry+https://github.com/rust-lang/crates.io-index) MIT OR Apache-2.0 -> 1.0.200 (compatible) available\n"));
    assert!(text.contains("- itoa 1.0.11 [transitive] (registry+https://github.com/rust-lang/crates.io-index) YANKED\n"));
    assert!(!text.contains("no crates.io data"));
}

#[test]
fn json_output_includes_registry_data() {
    let json = stdout(&scan("simple", &["--format", "json", "--fail-on", "none"]));
    assert!(
        json.contains("\"registry\":{\"source\":\"crates.io\",\"downloaded_on\":\"2026-01-01\"}")
    );
    assert!(json.contains("\"license\":\"MIT OR Apache-2.0\",\"latest_version\":\"1.0.200\",\"latest_published\":\"2025-12-01\",\"latest_compatible\":\"1.0.200\",\"compatible_published\":\"2025-12-01\",\"outdated\":true,\"outdated_kind\":\"compatible\",\"yanked\":false,\"last_release\":\"2025-12-20\",\"owners\":[\"dtolnay\"],\"repository\":\"https://github.com/serde-rs/json\",\"archived\":false,\"maintenance\":[\"single-owner\"]}"));
}

#[test]
fn text_report_lists_direct_dependencies_to_watch() {
    let text = stdout(&scan("simple", &["--fail-on", "none"]));
    assert!(text.contains("1 direct to watch"), "{text}");
    assert!(
        text.contains("Maintenance: 1 of 1 direct dependencies to watch\n- serde_json 1.0.128: single owner (dtolnay)\n"),
        "{text}"
    );
    let html = stdout(&scan("simple", &["--format", "html", "--fail-on", "none"]));
    assert!(
        html.contains(
            "<span class=\"badge badge-warn\">single-owner</span> single owner (dtolnay)"
        )
    );
}

#[test]
fn distinguishes_semver_compatible_and_breaking_updates() {
    let cache = std::env::temp_dir().join(format!("cargoscope-semver-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cache);
    let versions_dir = cache.join("crates-io/versions");
    std::fs::create_dir_all(&versions_dir).expect("create versions cache");
    std::fs::write(cache.join("crates-io/fetched-at"), "1767225600\n").expect("fetched-at");
    // serde_json is 1.0.128: has both compatible 1.0.200 and breaking 2.0.0.
    std::fs::write(
        versions_dir.join("serde_json"),
        "1.0.128\tfalse\t2024-09-01\n1.0.200\tfalse\t2025-12-01\n2.0.0\tfalse\t2026-01-01\n",
    )
    .expect("serde_json versions");
    // serde is 1.0.210: only breaking 2.0.0 exists.
    std::fs::write(
        versions_dir.join("serde"),
        "1.0.210\tfalse\t2024-09-01\n2.0.0\tfalse\t2026-01-01\n",
    )
    .expect("serde versions");

    let text = stdout(&scan_with_cache(
        "simple",
        &[
            "--checks",
            "inventory,versions,licenses",
            "--fail-on",
            "none",
        ],
        &cache,
    ));
    assert!(text.contains(
        "- serde_json 1.0.128 -> 1.0.200 (compatible), 2.0.0 (breaking), published 2026-01-01\n"
    ));
    assert!(text.contains("serde 1.0.210 [transitive]"));
    assert!(text.contains("-> 2.0.0 (breaking) available\n"));

    let json: serde_json::Value = serde_json::from_slice(
        &scan_with_cache(
            "simple",
            &[
                "--checks",
                "inventory,versions,licenses",
                "--format",
                "json",
                "--fail-on",
                "none",
            ],
            &cache,
        )
        .stdout,
    )
    .expect("json parses");
    let packages = json["packages"].as_array().expect("packages");
    let serde_json = packages
        .iter()
        .find(|p| p["name"] == "serde_json")
        .expect("serde_json");
    assert_eq!(serde_json["latest_compatible"], "1.0.200");
    assert_eq!(serde_json["latest_version"], "2.0.0");
    assert_eq!(serde_json["outdated_kind"], "both");
    let serde = packages
        .iter()
        .find(|p| p["name"] == "serde")
        .expect("serde");
    assert_eq!(serde["latest_compatible"], "1.0.210");
    assert_eq!(serde["latest_version"], "2.0.0");
    assert_eq!(serde["outdated_kind"], "breaking");

    let html = stdout(&scan_with_cache(
        "simple",
        &[
            "--checks",
            "inventory,versions,licenses",
            "--format",
            "html",
            "--fail-on",
            "none",
        ],
        &cache,
    ));
    assert!(html.contains(">both<"));
    assert!(html.contains("1.0.200"));
    assert!(html.contains("2.0.0 (breaking)"));

    let _ = std::fs::remove_dir_all(&cache);
}

#[test]
fn missing_registry_data_is_a_warning_not_an_error() {
    let cache = std::env::temp_dir().join(format!("cargoscope-no-registry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cache);
    let db = cache.join("advisory-db/crates");
    std::fs::create_dir_all(&db).expect("create cache");
    let output = scan_with_cache("simple", &["--fail-on", "none"], &cache);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        stdout(&output).contains("no crates.io data: licenses and latest versions are unknown")
    );
    let _ = std::fs::remove_dir_all(&cache);
}

fn json_of(name: &str) -> serde_json::Value {
    let output = scan(name, &["--format", "json", "--fail-on", "none"]);
    serde_json::from_slice(&output.stdout).expect("JSON output parses")
}

#[test]
fn json_reports_match_the_published_schema() {
    let schema_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/schema/report-v1.json");
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(schema_path).expect("schema file"))
            .expect("schema parses");
    let validator = jsonschema::validator_for(&schema).expect("schema is valid");
    for fixture in ["simple", "workspace", "renamed", "multi-version", "unused"] {
        let report = json_of(fixture);
        let errors: Vec<String> = validator
            .iter_errors(&report)
            .map(|error| error.to_string())
            .collect();
        assert!(errors.is_empty(), "{fixture}: {errors:?}");
    }
}

#[test]
fn output_option_writes_the_report_to_a_file() {
    let file = std::env::temp_dir().join(format!("cargoscope-output-{}.json", std::process::id()));
    let output = scan(
        "simple",
        &[
            "--format",
            "json",
            "--fail-on",
            "none",
            "--output",
            file.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).expect("file written"))
            .expect("valid JSON");
    assert_eq!(written["format_version"], 1);
    let _ = std::fs::remove_file(&file);
}

fn sarif_of(name: &str, extra: &[&str]) -> serde_json::Value {
    let mut args = vec!["--format", "sarif", "--fail-on", "none"];
    args.extend_from_slice(extra);
    serde_json::from_slice(&scan(name, &args).stdout).expect("SARIF output parses")
}

#[test]
fn sarif_reports_advisories_yanked_versions_and_unused_dependencies() {
    let sarif = sarif_of("simple", &[]);
    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "CargoScope");
    let results = run["results"].as_array().expect("results");

    let advisory = results
        .iter()
        .find(|result| result["ruleId"] == "CARGOSCOPE-TEST-0001")
        .expect("advisory result");
    assert_eq!(advisory["level"], "error");
    let location = &advisory["locations"][0]["physicalLocation"];
    assert!(
        location["artifactLocation"]["uri"]
            .as_str()
            .expect("uri")
            .ends_with("tests/fixtures/simple/Cargo.lock")
    );
    // `name = "serde_json"` is on line 14 of the fixture lockfile.
    assert_eq!(location["region"]["startLine"], 14);
    assert!(
        advisory["message"]["text"]
            .as_str()
            .expect("text")
            .contains("Fix: upgrade to >= 1.0.200.")
    );

    let informational = results
        .iter()
        .find(|result| result["ruleId"] == "CARGOSCOPE-TEST-0003")
        .expect("informational result");
    assert_eq!(informational["level"], "note");
    assert!(
        results
            .iter()
            .any(|result| result["ruleId"] == "cargoscope/yanked-version")
    );

    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    let rule = rules
        .iter()
        .find(|rule| rule["id"] == "CARGOSCOPE-TEST-0001")
        .expect("rule");
    assert_eq!(rule["properties"]["security-severity"], "8.0");
    assert_eq!(rule["helpUri"], "https://example.test/advisories/0001");
    for result in results {
        let id = result["ruleId"].as_str().expect("ruleId");
        assert!(
            rules.iter().any(|rule| rule["id"] == id),
            "no rule for {id}"
        );
    }
}

#[test]
fn sarif_points_unused_dependencies_at_their_manifest_line() {
    let sarif = sarif_of("unused", &[]);
    let results = sarif["runs"][0]["results"].as_array().expect("results");
    let unused: Vec<&serde_json::Value> = results
        .iter()
        .filter(|result| result["ruleId"] == "cargoscope/unused-dependency")
        .collect();
    assert_eq!(unused.len(), 5, "only likely-unused, never ignored ones");
    let log = unused
        .iter()
        .find(|result| {
            result["message"]["text"]
                .as_str()
                .expect("text")
                .starts_with("`log`")
        })
        .expect("log result");
    let location = &log["locations"][0]["physicalLocation"];
    assert!(
        location["artifactLocation"]["uri"]
            .as_str()
            .expect("uri")
            .ends_with("tests/fixtures/unused/Cargo.toml")
    );
    // `log = "0.4"` is on line 12 of the fixture manifest.
    assert_eq!(location["region"]["startLine"], 12);
    assert!(!results.iter().any(|result| {
        result["message"]["text"]
            .as_str()
            .is_some_and(|text| text.contains("once_cell"))
    }));

    let uncertain = sarif_of("unused", &["--show-uncertain"]);
    let count = uncertain["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter(|result| result["ruleId"] == "cargoscope/unused-dependency")
        .count();
    assert_eq!(count, 8);
}

#[test]
fn cyclonedx_exports_components_licenses_dependencies_and_vulnerabilities() {
    let bom: serde_json::Value = serde_json::from_slice(
        &scan("simple", &["--format", "cyclonedx", "--fail-on", "none"]).stdout,
    )
    .expect("CycloneDX output parses");
    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.5");
    assert_eq!(bom["metadata"]["component"]["name"], "simple");
    assert_eq!(
        bom["metadata"]["component"]["purl"],
        "pkg:cargo/simple@0.1.0"
    );

    let components = bom["components"].as_array().expect("components");
    let serde_json = components
        .iter()
        .find(|component| component["name"] == "serde_json")
        .expect("serde_json component");
    assert_eq!(serde_json["version"], "1.0.128");
    assert_eq!(serde_json["purl"], "pkg:cargo/serde_json@1.0.128");
    assert_eq!(serde_json["licenses"][0]["expression"], "MIT OR Apache-2.0");

    let dependencies = bom["dependencies"].as_array().expect("dependencies");
    let root_edge = dependencies
        .iter()
        .find(|entry| entry["ref"] == "pkg:cargo/simple@0.1.0")
        .expect("root dependency edge");
    assert_eq!(root_edge["dependsOn"][0], "pkg:cargo/serde_json@1.0.128");

    let vuln = bom["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities")
        .iter()
        .find(|entry| entry["id"] == "CARGOSCOPE-TEST-0001")
        .expect("CARGOSCOPE-TEST-0001 present");
    assert_eq!(vuln["affects"][0]["ref"], "pkg:cargo/serde_json@1.0.128");
    assert_eq!(vuln["ratings"][0]["severity"], "high");

    let ignored_bom: serde_json::Value =
        serde_json::from_slice(&scan("ignore-advisory", &["--format", "cyclonedx"]).stdout)
            .expect("ignored CycloneDX parses");
    let ignored_vuln = ignored_bom["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities")
        .iter()
        .find(|entry| entry["id"] == "CARGOSCOPE-TEST-0001")
        .expect("ignored vulnerability kept with VEX analysis");
    assert_eq!(ignored_vuln["analysis"]["state"], "not_affected");
    assert_eq!(
        ignored_vuln["analysis"]["detail"],
        "the vulnerable function is never called"
    );

    let ws_bom: serde_json::Value =
        serde_json::from_slice(&scan("workspace", &["--format", "cyclonedx"]).stdout)
            .expect("workspace CycloneDX parses");
    assert_eq!(ws_bom["metadata"]["component"]["bom-ref"], "workspace");
    assert_eq!(ws_bom["metadata"]["component"]["name"], "workspace");
}

#[test]
fn html_exports_self_contained_report_with_findings_and_output_file() {
    let report_path =
        std::env::temp_dir().join(format!("cargoscope-html-{}.html", std::process::id()));
    let output = scan(
        "simple",
        &[
            "--format",
            "html",
            "--fail-on",
            "none",
            "--output",
            report_path.to_str().expect("utf8 path"),
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).is_empty());

    let html = std::fs::read_to_string(&report_path).expect("written html file");
    let _ = std::fs::remove_file(&report_path);
    assert!(html.starts_with("<!DOCTYPE html>\n"));
    assert!(html.contains("<style>"));
    assert!(html.contains("<svg "));
    assert!(html.contains("CARGOSCOPE-TEST-0001"));
    assert!(html.contains("serde_json"));
    assert!(html.contains("MIT OR Apache-2.0"));

    fn unused_section(doc: &str) -> &str {
        let start = doc.find("<section id=\"unused\"").expect("unused section");
        let rest = &doc[start..];
        let end = rest.find("</section>").expect("closing unused section");
        &rest[..end]
    }

    let unused_default = stdout(&scan("unused", &["--format", "html", "--fail-on", "none"]));
    assert!(unused_section(&unused_default).contains("possibly-unused"));
    assert!(unused_section(&unused_default).contains("log"));
    assert!(unused_section(&unused_default).contains("kept for an upcoming feature"));
    assert!(!unused_section(&unused_default).contains("chrono"));

    let unused_uncertain = stdout(&scan(
        "unused",
        &["--format", "html", "--show-uncertain", "--fail-on", "none"],
    ));
    assert!(unused_section(&unused_uncertain).contains("chrono"));

    let policy_html = stdout(&scan("policy", &["--format", "html", "--fail-on", "none"]));
    assert!(policy_html.contains("Policy Violations"));
}

#[test]
fn inventory_only_scan_needs_no_advisory_database() {
    let empty =
        std::env::temp_dir().join(format!("cargoscope-inventory-only-{}", std::process::id()));
    let output = scan_with_cache("simple", &["--checks", "inventory"], &empty);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("- serde_json 1.0.128 [direct]"));
    assert!(!text.contains("CARGOSCOPE-TEST-0001"));
    assert!(!text.contains("no crates.io data"));
}

#[test]
fn unknown_check_is_an_execution_error() {
    let output = scan("simple", &["--checks", "inventory,typo"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown check: typo"));
}

#[test]
fn skipped_checks_leave_their_data_empty() {
    let json: serde_json::Value = serde_json::from_slice(
        &scan(
            "unused",
            &["--format", "json", "--checks", "inventory,licenses"],
        )
        .stdout,
    )
    .expect("valid JSON");
    assert_eq!(json["advisories"], serde_json::json!([]));
    assert_eq!(json["unused"], serde_json::json!([]));
    let serde_json = json["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "serde_json")
        .expect("serde_json");
    assert_eq!(serde_json["license"], "MIT OR Apache-2.0");
    assert_eq!(serde_json["latest_version"], serde_json::Value::Null);
}

#[test]
fn skipped_checks_are_reported_as_not_checked() {
    let empty = std::env::temp_dir().join(format!("cargoscope-not-checked-{}", std::process::id()));
    let text = stdout(&scan_with_cache(
        "simple",
        &["--checks", "inventory"],
        &empty,
    ));
    for section in [
        "Advisories: not checked",
        "Unused dependencies: not checked",
        "Licenses: not checked",
        "Versions: not checked",
    ] {
        assert!(text.contains(section), "missing: {section}");
    }
    assert!(!text.contains("No known advisory found"));

    let json: serde_json::Value = serde_json::from_slice(
        &scan_with_cache(
            "simple",
            &["--format", "json", "--checks", "inventory"],
            &empty,
        )
        .stdout,
    )
    .expect("valid JSON");
    assert_eq!(json["checks"], serde_json::json!(["inventory"]));
}

#[test]
fn glob_workspace_members_are_scanned_and_excludes_respected() {
    let text = stdout(&scan("workspace-glob", &["--fail-on", "none"]));
    assert!(text.contains("- app 0.1.0 [root]\n"));
    assert!(text.contains("- util 0.1.0 [root]\n"));
    assert!(text.contains("- memchr 2.7.4 [direct]"));
    // util never uses memchr: found because the glob member is analyzed.
    assert!(text.contains("- memchr [likely-unused] in [dependencies] of crates/util/Cargo.toml"));
    // The excluded member's unused `regex` must not be reported.
    assert!(!text.contains("regex"));
}

#[test]
fn package_list_is_hidden_without_verbose() {
    let output = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
        .args(["scan", "--fail-on", "none"])
        .arg(fixture("simple"))
        .output()
        .expect("cargoscope binary runs");
    let text = stdout(&output);
    assert!(text.starts_with("CargoScope "));
    assert!(
        text.contains(" · 4 packages · data from 2026-01-01\n"),
        "{text}"
    );
    assert!(text.contains("  ✖ 1 vulnerable crate   ⚠ 1 notice   ✔ no unused dependency"));
    assert!(text.contains("\nVulnerabilities\n  ✖ serde_json 1.0.128  high: "));
    assert!(text.contains("  fix: 1.0.200\n      via simple › serde_json\n"));
    assert!(text.contains("\nNotices (not vulnerabilities)\n  unmaintained  itoa\n"));
    assert!(text.contains("\nNext steps\n  › cargoscope fix --advisories"));
    // Not a terminal: no ANSI codes.
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("Resolved packages: 4 (use --verbose to list them)\n"));
    assert!(!text.contains("- simple 0.1.0 [root]"));
}

#[test]
fn packages_missing_from_the_registry_cache_are_reported() {
    // The fake cache has data for serde_json, serde and itoa only.
    let text = stdout(&scan("workspace", &["--fail-on", "none"]));
    assert!(text.contains("2 crates.io package(s) have no cached data"));
    assert!(!stdout(&scan("simple", &["--fail-on", "none"])).contains("no cached data"));
}

#[test]
fn dependency_used_by_a_sibling_macro_is_only_possibly_unused() {
    let text = stdout(&scan(
        "workspace-macro",
        &["--fail-on", "none", "--show-uncertain"],
    ));
    assert!(text.contains("- log [likely-unused] in [dependencies] of app/Cargo.toml"));
    assert!(text.contains("- rust-embed [possibly-unused] in [dependencies] of app/Cargo.toml"));
    assert!(
        text.contains("may be used through a macro of workspace crate `common`, which mentions it")
    );
}

#[test]
fn library_names_that_differ_from_package_names_are_recognised() {
    let text = stdout(&scan(
        "workspace-macro",
        &["--fail-on", "none", "--show-uncertain"],
    ));
    // `[lib] name = "vt"` of a path dependency: definitely used.
    assert!(!text.contains("- vt-fork ["));
    // Unknown library name, but `bip39::` is used: only possibly unused.
    assert!(text.contains("- tiny-bip39 [possibly-unused]"));
    assert!(text.contains(
        "`bip39::` is used: the library name of `tiny-bip39` may differ from its package name"
    ));
}

fn write_report(name: &str, fixture_name: &str) -> PathBuf {
    let file = std::env::temp_dir().join(format!("cargoscope-{name}-{}.json", std::process::id()));
    let output = scan(
        fixture_name,
        &[
            "--format",
            "json",
            "--fail-on",
            "none",
            "--output",
            file.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    file
}

fn compare(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .arg("compare")
        .args(arguments)
        .output()
        .expect("cargoscope binary runs")
}

#[test]
fn compare_lists_new_advisories_and_fails_on_them() {
    let baseline = write_report("baseline", "workspace");
    let current = write_report("current", "simple");
    let output = compare(&[
        baseline.to_str().expect("utf-8"),
        current.to_str().expect("utf-8"),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(
        text.contains("New advisories: 2\n- CARGOSCOPE-TEST-0001 [high] serde_json 1.0.128"),
        "{text}"
    );
    assert!(text.contains("- CARGOSCOPE-TEST-0003 [informational] itoa 1.0.11"));
    assert!(text.contains("New yanked versions in use: 1\n- itoa 1.0.11\n"));
    assert!(text.contains("Removed packages: "));

    let same = compare(&[
        current.to_str().expect("utf-8"),
        current.to_str().expect("utf-8"),
    ]);
    assert_eq!(same.status.code(), Some(0));
    assert!(stdout(&same).contains("New advisories: 0\n"));

    let json = compare(&[
        "--format",
        "json",
        "--fail-on",
        "critical",
        baseline.to_str().expect("utf-8"),
        current.to_str().expect("utf-8"),
    ]);
    assert_eq!(json.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).expect("valid JSON");
    assert_eq!(value["comparison_format_version"], 1);
    assert_eq!(value["new_advisories"][0]["id"], "CARGOSCOPE-TEST-0001");

    let markdown = compare(&[
        "--format=markdown",
        baseline.to_str().expect("utf-8"),
        current.to_str().expect("utf-8"),
    ]);
    // Same exit code as the text format: new vulnerabilities fail.
    assert_eq!(markdown.status.code(), Some(1));
    let markdown = stdout(&markdown);
    assert!(
        markdown.starts_with("<!-- cargoscope-pr-comment -->\n"),
        "{markdown}"
    );
    assert!(markdown.contains("| CARGOSCOPE-TEST-0001 | high | `serde_json 1.0.128` |"));
    assert!(markdown.contains("**New yanked versions in use: 1**\n\n- `itoa 1.0.11`\n"));
    let _ = std::fs::remove_file(baseline);
    let _ = std::fs::remove_file(current);
}

#[test]
fn compare_rejects_files_that_are_not_reports() {
    let bogus = std::env::temp_dir().join(format!("cargoscope-bogus-{}.json", std::process::id()));
    std::fs::write(&bogus, "{\"hello\": 1}").expect("write");
    let output = compare(&[
        bogus.to_str().expect("utf-8"),
        bogus.to_str().expect("utf-8"),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a CargoScope JSON report"));
    let _ = std::fs::remove_file(bogus);
}

#[test]
fn baseline_lets_known_advisories_pass() {
    let baseline = write_report("known", "simple");
    let output = scan("simple", &["--baseline", baseline.to_str().expect("utf-8")]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "known advisories must not fail"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("already in the baseline"));
    let empty = write_report("empty", "workspace");
    assert_eq!(
        scan("simple", &["--baseline", empty.to_str().expect("utf-8")])
            .status
            .code(),
        Some(1)
    );
    let _ = std::fs::remove_file(baseline);
    let _ = std::fs::remove_file(empty);
}

#[test]
fn policy_violations_are_reported_and_fail_the_scan() {
    let output = scan("policy", &["--fail-on", "critical"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "violations fail even above the advisory threshold"
    );
    let text = stdout(&output);
    assert!(text.contains("Policy violations: 5\n"), "{text}");
    assert!(text.contains("- [source] forked 0.1.0: git source https://github.com/someone/forked is not in [sources] allow-git\n"));
    assert!(text.contains("- [license] itoa 1.0.11: license is unknown"));
    assert!(text.contains("- [ban] serde 1.0.210: `serde` <2 is banned: testing bans\n    via policy-demo -> serde_json -> serde\n"));
    assert!(text.contains(
        "- [license] serde_json 1.0.128: license `MIT OR Apache-2.0` is not allowed by the policy\n"
    ));
    assert!(text.contains("5 policy violations"));
    assert_eq!(
        scan("policy", &["--fail-on", "none"]).status.code(),
        Some(0)
    );
}

#[test]
fn policy_graph_targets_limit_the_rules_to_packages_the_target_builds() {
    let dir = std::env::temp_dir().join(format!("cargoscope-graph-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);
    let policy = std::fs::read_to_string(dir.join("cargoscope.toml")).expect("policy");
    std::fs::write(
        dir.join("cargoscope.toml"),
        format!("[graph]\ntargets = [\"x86_64-unknown-linux-gnu\"]\n\n{policy}"),
    )
    .expect("write policy");

    // A fake cargo answers `cargo tree --target`: the target builds
    // policy-demo, serde_json and serde, but not itoa nor forked.
    let fake_src = dir.join("fake_cargo.rs");
    let fake_bin = dir.join(format!("fake-cargo{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(
        &fake_src,
        r##"fn main() {
    let args: Vec<String> = std::env::args().collect();
    if std::env::var_os("FAKE_CARGO_FAIL").is_some() {
        eprintln!("error: failed to download `serde v1.0.210`");
        std::process::exit(101);
    }
    let target = args.windows(2).find(|w| w[0] == "--target").map(|w| w[1].clone());
    assert!(args.iter().any(|a| a == "tree") && args.iter().any(|a| a == "--locked") && args.iter().any(|a| a == "--workspace"), "{args:?}");
    assert_eq!(target.as_deref(), Some("x86_64-unknown-linux-gnu"));
    println!("policy-demo v0.1.0 (/work/policy-demo)\nserde_json v1.0.128\nserde v1.0.210\nserde v1.0.210 (*)");
}
"##,
    )
    .expect("write fake cargo");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiled = Command::new(rustc)
        .arg(&fake_src)
        .arg("-o")
        .arg(&fake_bin)
        .output()
        .expect("rustc runs");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let run = |fail: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cargoscope"));
        command
            .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
            .env("CARGO_HOME", fixture("empty-cargo-home"))
            .env("CARGO", &fake_bin)
            .args(["scan", "--verbose", "--fail-on", "none"])
            .arg(&dir);
        if fail {
            command.env("FAKE_CARGO_FAIL", "1");
        }
        command.output().expect("cargoscope binary runs")
    };

    let scoped = run(false);
    assert_eq!(scoped.status.code(), Some(0));
    let text = stdout(&scoped);
    assert!(text.contains("Policy violations: 3\n"), "{text}");
    assert!(text.contains("- [ban] serde 1.0.210:"), "{text}");
    assert!(text.contains("- [license] serde_json 1.0.128:"), "{text}");
    assert!(!text.contains("- [source] forked"), "{text}");
    assert!(!text.contains("- [license] itoa"), "{text}");

    // When Cargo cannot say which packages a target builds, the scan stops
    // instead of silently checking everything (or nothing).
    let failed = run(true);
    assert_eq!(failed.status.code(), Some(2));
    let message = String::from_utf8_lossy(&failed.stderr);
    assert!(
        message.contains("could not limit the policy to its [graph]"),
        "{message}"
    );
    assert!(
        message.contains("failed to download `serde v1.0.210`"),
        "{message}"
    );
}

#[test]
fn policy_check_can_be_skipped_and_appears_in_json_and_sarif() {
    let output = scan(
        "policy",
        &["--checks", "inventory", "--fail-on", "critical"],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("Policy: not checked"));
    let json: serde_json::Value =
        serde_json::from_slice(&scan("policy", &["--format", "json", "--fail-on", "none"]).stdout)
            .expect("valid JSON");
    assert_eq!(json["policy"].as_array().expect("violations").len(), 5);
    assert_eq!(json["policy"][0]["rule"], "source");
    let sarif: serde_json::Value =
        serde_json::from_slice(&scan("policy", &["--format", "sarif", "--fail-on", "none"]).stdout)
            .expect("valid SARIF");
    let results = sarif["runs"][0]["results"].as_array().expect("results");
    assert!(results.iter().any(|result| result["ruleId"] == "cargoscope/policy-ban" && result["level"] == "error"));
    assert!(
        stdout(&scan("simple", &["--fail-on", "none"]))
            .contains("Policy: no cargoscope.toml policy")
    );
}

#[test]
fn invalid_policy_is_an_execution_error() {
    let dir = std::env::temp_dir().join(format!("cargoscope-bad-policy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    for file in ["Cargo.toml", "Cargo.lock"] {
        std::fs::copy(fixture("simple").join(file), dir.join(file)).expect("copy");
    }
    std::fs::write(
        dir.join("cargoscope.toml"),
        "[licenses]\nalow = [\"MIT\"]\n",
    )
    .expect("write");
    let output = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
        .arg("scan")
        .arg(&dir)
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown key `alow`"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ignored_advisories_stay_visible_but_do_not_fail() {
    let output = scan("ignore-advisory", &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the only vulnerability is ignored"
    );
    let text = stdout(&output);
    assert!(
        text.contains("Summary: 0 vulnerabilities (1 informational, 1 ignored)"),
        "{text}"
    );
    assert!(text.contains("- CARGOSCOPE-TEST-0001 [high] serde_json 1.0.128"));
    assert!(
        text.contains("    ignored in cargoscope.toml: the vulnerable function is never called\n")
    );
    assert!(text.contains("cargoscope.toml ignores RUSTSEC-0000-9999, which matches no advisory"));

    let json: serde_json::Value =
        serde_json::from_slice(&scan("ignore-advisory", &["--format", "json"]).stdout)
            .expect("valid JSON");
    let advisory = json["advisories"]
        .as_array()
        .expect("advisories")
        .iter()
        .find(|advisory| advisory["id"] == "CARGOSCOPE-TEST-0001")
        .expect("ignored advisory kept");
    assert_eq!(
        advisory["ignored_reason"],
        "the vulnerable function is never called"
    );

    let sarif: serde_json::Value =
        serde_json::from_slice(&scan("ignore-advisory", &["--format", "sarif"]).stdout)
            .expect("valid SARIF");
    let result = sarif["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .find(|result| result["ruleId"] == "CARGOSCOPE-TEST-0001")
        .expect("suppressed result kept");
    assert_eq!(result["suppressions"][0]["kind"], "external");
}

#[test]
fn expired_ignores_count_again_and_invalid_ones_are_errors() {
    let dir = std::env::temp_dir().join(format!("cargoscope-expired-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    for file in ["Cargo.toml", "Cargo.lock"] {
        std::fs::copy(fixture("ignore-advisory").join(file), dir.join(file)).expect("copy");
    }
    let run = |dir: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
            .env("CARGO_HOME", fixture("empty-cargo-home"))
            .arg("scan")
            .arg(dir)
            .output()
            .expect("runs")
    };
    std::fs::write(
        dir.join("cargoscope.toml"),
        "[advisories]\nignore = [{ id = \"CARGOSCOPE-TEST-0001\", reason = \"temporary\", until = \"2020-01-01\" }]\n",
    )
    .expect("write");
    let output = run(&dir);
    assert_eq!(
        output.status.code(),
        Some(1),
        "expired ignore no longer applies"
    );
    assert!(stdout(&output).contains("the ignore of CARGOSCOPE-TEST-0001 expired on 2020-01-01"));

    std::fs::write(
        dir.join("cargoscope.toml"),
        "[advisories]\nignore = [{ id = \"X\" }]\n",
    )
    .expect("write");
    let output = run(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("needs a non-empty `reason`"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("create");
    for entry in std::fs::read_dir(from).expect("read fixture") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy");
        }
    }
}

fn fix(dir: &std::path::Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .arg("fix")
        .arg(dir)
        .args(extra)
        .output()
        .expect("cargoscope binary runs")
}

#[test]
fn fix_shows_then_removes_only_likely_unused_dependencies() {
    let dir = std::env::temp_dir().join(format!("cargoscope-fix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("unused"), &dir);
    let original = std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest");

    // Dry run by default: the plan is shown, nothing is written.
    let dry = fix(&dir, &[]);
    assert_eq!(dry.status.code(), Some(0));
    let plan = stdout(&dry);
    assert!(
        plan.contains("  - remove `log` from [dependencies]\n"),
        "{plan}"
    );
    assert!(plan.contains("  - remove `pretty_assertions` from [dev-dependencies]\n"));
    assert!(plan.contains("  - remove `pkg-config` from [build-dependencies]\n"));
    assert!(plan.contains("Dry run: nothing was written."));
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest"),
        original
    );
    assert_eq!(fix(&dir, &["--dry-run"]).stdout, dry.stdout);

    let applied = fix(&dir, &["--apply"]);
    assert_eq!(applied.status.code(), Some(0));
    assert!(stdout(&applied).contains("Removed 5 dependencies from 1 manifest(s)."));
    let edited = std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest");
    for removed in [
        "log = ",
        "regex = ",
        "rand = ",
        "pretty_assertions = ",
        "pkg-config = ",
    ] {
        assert!(!edited.contains(removed), "{removed} still in:\n{edited}");
    }
    // Possibly-unused, ignored and used dependencies stay, with their comments.
    for kept in [
        "openssl-sys = \"0.9\"                               # unused, but a -sys crate",
        "chrono = { version = \"0.4\", optional = true }",
        "once_cell = \"1\"",
        "serde_json = \"1\"                                  # used: plain path",
        "[package.metadata.cargoscope]",
    ] {
        assert!(edited.contains(kept), "{kept} missing from:\n{edited}");
    }
    assert!(stdout(&fix(&dir, &[])).contains("No likely-unused dependency to remove."));

    assert_eq!(fix(&dir, &["--apply", "--dry-run"]).status.code(), Some(2));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn fix_removes_workspace_dependencies_no_member_uses_anymore_and_honours_only() {
    let dir = std::env::temp_dir().join(format!("cargoscope-fix-ws-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("a/src")).expect("create");
    let root_manifest = "[workspace]\nmembers = [\"a\"]\n\n[workspace.dependencies]\nlog = \"0.4\"\nregex = \"1\" # shared regex\nrand = \"0.8\"\n";
    std::fs::write(dir.join("Cargo.toml"), root_manifest).expect("write");
    std::fs::write(
        dir.join("a/Cargo.toml"),
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nlog.workspace = true\nregex = { workspace = true }\nrand.workspace = true\n",
    )
    .expect("write");
    std::fs::write(
        dir.join("a/src/lib.rs"),
        "pub fn f() -> regex::Regex { todo!() }\n",
    )
    .expect("write");
    let registry = "source = \"registry+https://github.com/rust-lang/crates.io-index\"";
    std::fs::write(
        dir.join("Cargo.lock"),
        format!("version = 4\n\n[[package]]\nname = \"a\"\nversion = \"0.1.0\"\ndependencies = [\"log\", \"rand\", \"regex\"]\n\n[[package]]\nname = \"log\"\nversion = \"0.4.22\"\n{registry}\n\n[[package]]\nname = \"rand\"\nversion = \"0.8.5\"\n{registry}\n\n[[package]]\nname = \"regex\"\nversion = \"1.11.0\"\n{registry}\n"),
    )
    .expect("write");

    // --only: just `log`, and a note for a name that is not a candidate.
    let only = fix(&dir, &["--only", "log,regex", "--apply"]);
    assert_eq!(only.status.code(), Some(0));
    let text = stdout(&only);
    assert!(
        text.contains("`regex` is not a likely-unused dependency: left alone."),
        "{text}"
    );
    assert!(
        text.contains("  - remove `log` from [dependencies]\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "  - remove `log` from [workspace.dependencies]: no member uses it anymore\n"
        )
    );
    assert!(!text.contains("rand"), "{text}");
    let root = std::fs::read_to_string(dir.join("Cargo.toml")).expect("root");
    assert_eq!(root, root_manifest.replace("log = \"0.4\"\n", ""));

    // Then the rest: rand goes from the member and the workspace; regex stays.
    let rest = fix(&dir, &["--apply"]);
    assert!(
        stdout(&rest).contains("Removed 2 dependencies from 2 manifest(s)."),
        "{}",
        stdout(&rest)
    );
    let root = std::fs::read_to_string(dir.join("Cargo.toml")).expect("root");
    assert_eq!(
        root,
        "[workspace]\nmembers = [\"a\"]\n\n[workspace.dependencies]\nregex = \"1\" # shared regex\n"
    );
    let member = std::fs::read_to_string(dir.join("a/Cargo.toml")).expect("member");
    assert!(
        member.ends_with("[dependencies]\nregex = { workspace = true }\n"),
        "{member}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn multiple_versions_rule_fails_the_scan_unless_the_crate_is_skipped() {
    let dir = std::env::temp_dir().join(format!("cargoscope-dups-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("multi-version"), &dir);
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
            .env("CARGO_HOME", fixture("empty-cargo-home"))
            .arg("scan")
            .arg(&dir)
            .args(["--checks", "inventory,policy"])
            .args(extra)
            .output()
            .expect("cargoscope binary runs")
    };

    std::fs::write(
        dir.join("cargoscope.toml"),
        "[bans]\nmultiple-versions = \"deny\"\n",
    )
    .expect("write");
    let denied = run(&[]);
    assert_eq!(denied.status.code(), Some(1));
    let text = stdout(&denied);
    assert!(
        text.contains("- [multiple-versions] bitflags 1.3.2: `bitflags` is resolved in 2 versions (1.3.2, 2.6.0)"),
        "{text}"
    );
    assert!(text.contains("    via multi-version -> old-wrapper -> bitflags\n"));
    let sarif: serde_json::Value =
        serde_json::from_slice(&run(&["--format", "sarif"]).stdout).expect("valid SARIF");
    assert_eq!(
        sarif["runs"][0]["results"][0]["ruleId"],
        "cargoscope/policy-multiple-versions"
    );
    assert_eq!(run(&["--fail-on", "none"]).status.code(), Some(0));

    std::fs::write(
        dir.join("cargoscope.toml"),
        "[bans]\nmultiple-versions = \"deny\"\nskip-multiple-versions = [\"bitflags\"]\n",
    )
    .expect("write");
    let skipped = run(&[]);
    assert_eq!(skipped.status.code(), Some(0), "{}", stdout(&skipped));
    assert!(stdout(&skipped).contains("Policy violations: 0"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn every_subcommand_has_its_own_help() {
    let help = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .args(arguments)
            .output()
            .expect("cargoscope binary runs")
    };
    for (command, expected, absent) in [
        ("scan", "--show-uncertain", "cargoscope fix"),
        ("why", "CRATE[@VERSION]", "cargoscope scan"),
        ("fix", "--only NAMES", "--show-uncertain"),
        ("init", "--ci", "cargoscope compare"),
        ("compare", "--format text|json|markdown", "cargoscope scan"),
        (
            "update",
            "The only command that uses the network",
            "cargoscope compare",
        ),
    ] {
        for flag in ["--help", "-h"] {
            let output = help(&[command, flag]);
            assert_eq!(output.status.code(), Some(0), "{command} {flag}");
            let text = stdout(&output);
            assert!(text.contains(&format!("cargoscope {command}")), "{text}");
            assert!(text.contains(expected), "{command}: {text}");
            assert!(
                !text.contains(absent),
                "{command} help shows another command: {text}"
            );
            assert!(text.contains("Exit codes:"));
        }
    }
    // The flag counts anywhere after the subcommand.
    assert_eq!(
        help(&["fix", ".", "--apply", "--help"]).status.code(),
        Some(0)
    );
    let all = stdout(&help(&["--help"]));
    for command in ["init", "scan", "fix", "compare", "update"] {
        assert!(all.contains(&format!("cargoscope {command}")), "{all}");
    }
    let wrong = help(&["fix", "--force"]);
    assert_eq!(wrong.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("Run cargoscope fix --help for usage.")
    );
    let update_help = stdout(&help(&["update", "--help"]));
    assert!(update_help.contains("--fast"), "{update_help}");
    assert!(update_help.contains("--no-maintenance"), "{update_help}");
    let scan_help = stdout(&help(&["scan", "--help"]));
    assert!(scan_help.contains("--update"), "{scan_help}");
    assert!(scan_help.contains("--fast"), "{scan_help}");
    let bad_update = help(&["update", "--nope"]);
    assert_eq!(bad_update.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&bad_update.stderr)
            .contains("Run cargoscope update --help for usage.")
    );
}

fn audit_bin(file: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
        .arg("audit-bin")
        .arg(fixture("binary").join(file))
        .args(extra)
        .output()
        .expect("cargoscope binary runs")
}

#[test]
fn audit_bin_reads_cargo_auditable_data_and_falls_back_to_registry_paths() {
    let short = stdout(&audit_bin("auditable.bin", &[]));
    assert!(short.contains("  ✖ serde_json 1.0.128  high: "), "{short}");
    assert!(!short.contains("cargoscope fix"), "{short}");
    assert!(!short.contains("not checked"), "{short}");
    let exact = audit_bin("auditable.bin", &["--verbose"]);
    assert_eq!(exact.status.code(), Some(1));
    let text = stdout(&exact);
    assert!(
        text.contains("- CARGOSCOPE-TEST-0001 [high] serde_json 1.0.128"),
        "{text}"
    );
    assert!(text.contains("    via app -> serde_json\n"));
    assert!(!text.contains("no cargo-auditable data"));
    assert_eq!(
        audit_bin("auditable.bin", &["--fail-on", "none"])
            .status
            .code(),
        Some(0)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&audit_bin("auditable.bin", &["--format", "json"]).stdout)
            .expect("valid JSON");
    assert_eq!(json["advisories"][0]["id"], "CARGOSCOPE-TEST-0001");

    let partial = audit_bin("paths.bin", &["--fail-on", "none", "--verbose"]);
    assert_eq!(partial.status.code(), Some(0));
    let text = stdout(&partial);
    assert!(
        text.contains("CARGOSCOPE-TEST-0001 [high] serde_json 1.0.128"),
        "{text}"
    );
    assert!(text.contains("no cargo-auditable data in this binary: 2 crate(s)"));

    let not_rust = audit_bin("not-rust.bin", &[]);
    assert_eq!(not_rust.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&not_rust.stderr).contains("no dependency information found"));
}

#[test]
fn fix_advisories_updates_pinned_manifest_when_lockfile_alone_fails() {
    let dir = std::env::temp_dir().join(format!("cargoscope-fix-adv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("simple"), &dir);

    let pinned = "[package]\nname = \"simple\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde_json = \"=1.0.128\"\n";
    std::fs::write(dir.join("Cargo.toml"), pinned).expect("write manifest");

    let fake_src = dir.join("fake_cargo.rs");
    let fake_bin = dir.join(format!("fake-cargo{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(
        &fake_src,
        r#"fn main() {
    let manifest = std::fs::read_to_string("Cargo.toml").unwrap();
    let dry_run = std::env::args().any(|a| a == "--dry-run");
    if manifest.contains("\"=1.0.128\"") {
        eprintln!("error: failed to select a version for the requirement `serde_json = \"=1.0.128\"`\nrequired by package `simple v0.1.0`");
        std::process::exit(1);
    }
    if manifest.contains("\"=1.0.200\"") {
        if std::env::var_os("FAKE_CARGO_STALE").is_some() {
            eprintln!("Adding serde_json v1.0.200");
            return;
        }
        eprintln!("Updating serde_json v1.0.128 -> v1.0.200");
        if !dry_run {
            let lock = std::fs::read_to_string("Cargo.lock").unwrap();
            std::fs::write(
                "Cargo.lock",
                lock.replace("version = \"1.0.128\"", "version = \"1.0.200\""),
            )
            .unwrap();
        }
        return;
    }
    eprintln!("unexpected manifest:\n{manifest}");
    std::process::exit(1);
}
"#,
    )
    .expect("write fake cargo");

    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiled = Command::new(rustc)
        .arg(&fake_src)
        .arg("-o")
        .arg(&fake_bin)
        .output()
        .expect("rustc runs");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let run = |extra: &[&str], stale: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cargoscope"));
        command
            .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
            .env("CARGO_HOME", fixture("empty-cargo-home"))
            .env("CARGO", &fake_bin)
            .args(["fix", "--advisories"])
            .arg(&dir)
            .args(extra);
        if stale {
            command.env("FAKE_CARGO_STALE", "1");
        }
        command.output().expect("cargoscope binary runs")
    };

    // If another dependency still keeps the vulnerable version, refuse the edit.
    let stale = run(&[], true);
    assert_eq!(stale.status.code(), Some(0));
    let stale_text = stdout(&stale);
    assert!(
        stale_text
            .contains("= cannot update: another dependency still requires serde_json 1.0.128"),
        "{stale_text}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest"),
        pinned
    );

    // Dry run announces the manifest edit and leaves disk untouched.
    let dry = run(&[], false);
    assert_eq!(dry.status.code(), Some(0));
    let dry_text = stdout(&dry);
    assert!(
        dry_text.contains("serde_json 1.0.128 (CARGOSCOPE-TEST-0001)"),
        "{dry_text}"
    );
    assert!(
        dry_text.contains("  - update to 1.0.200 (in Cargo.toml)\n"),
        "{dry_text}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest"),
        pinned
    );

    // --apply locks 1.0.200 via `=1.0.200`, then writes `"1.0.200"` to Cargo.toml.
    let applied = run(&["--apply"], false);
    assert_eq!(
        applied.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let updated_manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest");
    // The pin is moved, not removed.
    assert!(
        updated_manifest.contains("serde_json = \"=1.0.200\"\n"),
        "{updated_manifest}"
    );
    let updated_lock = std::fs::read_to_string(dir.join("Cargo.lock")).expect("lock");
    assert!(
        updated_lock.contains("version = \"1.0.200\""),
        "{updated_lock}"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn license_exceptions_and_clarifications_remove_violations() {
    let dir = std::env::temp_dir().join(format!("cargoscope-clarify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);
    std::fs::write(
        dir.join("cargoscope.toml"),
        r#"[licenses]
allow = ["BSD-3-Clause"]
exceptions = [{ name = "serde_json", allow = ["MIT"], reason = "approved by legal" }]
clarify = [
  { name = "itoa", version = "^1", expression = "BSD-3-Clause", reason = "LICENSE file checked" },
  { name = "gone", expression = "MIT", reason = "left over" },
]
"#,
    )
    .expect("write");
    let output = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
        .env("CARGO_HOME", fixture("empty-cargo-home"))
        .args([
            "scan",
            "--checks",
            "inventory,licenses,policy",
            "--fail-on",
            "none",
            "--verbose",
        ])
        .arg(&dir)
        .output()
        .expect("cargoscope binary runs");
    let text = stdout(&output);
    assert!(!text.contains("[license] serde_json"), "{text}");
    assert!(!text.contains("[license] itoa"), "{text}");
    assert!(
        text.contains("- BSD-3-Clause: "),
        "clarified license is listed: {text}"
    );
    assert!(
        text.contains("cargoscope.toml clarifies the license of gone, which matches no package")
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn policy_graph_features_limit_the_rules_to_the_selected_features() {
    let dir = std::env::temp_dir().join(format!("cargoscope-features-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);
    let policy = std::fs::read_to_string(dir.join("cargoscope.toml")).expect("policy");
    std::fs::write(
        dir.join("cargoscope.toml"),
        format!("[graph]\nno-default-features = true\nfeatures = [\"extra\"]\n\n{policy}"),
    )
    .expect("write policy");

    // A fake cargo checks the feature flags (and that no platform is
    // filtered), and answers a graph without serde, which only a default
    // feature would pull in.
    let fake_src = dir.join("fake_cargo.rs");
    let fake_bin = dir.join(format!("fake-cargo{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(
        &fake_src,
        r##"fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.iter().any(|a| a == "--no-default-features"), "{args:?}");
    assert!(args.windows(2).any(|w| w[0] == "--features" && w[1] == "extra"), "{args:?}");
    assert!(args.windows(2).any(|w| w[0] == "--target" && w[1] == "all"), "{args:?}");
    assert!(!args.iter().any(|a| a == "--all-features"), "{args:?}");
    println!("policy-demo v0.1.0 (/work/policy-demo)\nserde_json v1.0.128\nitoa v1.0.11\nforked v0.1.0 (https://github.com/someone/forked?rev=abc#abc)");
}
"##,
    )
    .expect("write fake cargo");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiled = Command::new(rustc)
        .arg(&fake_src)
        .arg("-o")
        .arg(&fake_bin)
        .output()
        .expect("rustc runs");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
        .env("CARGO_HOME", fixture("empty-cargo-home"))
        .env("CARGO", &fake_bin)
        .args(["scan", "--fail-on", "none"])
        .arg(&dir)
        .output()
        .expect("cargoscope binary runs");
    let text = stdout(&output);
    assert!(!text.contains("- [ban] serde 1.0.210"), "{text}");
    assert!(text.contains("- [license] serde_json 1.0.128:"), "{text}");
    assert!(text.contains("- [source] forked 0.1.0:"), "{text}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_deny_toml_is_used_without_a_cargoscope_toml() {
    let dir = std::env::temp_dir().join(format!("cargoscope-deny-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);
    std::fs::remove_file(dir.join("cargoscope.toml")).expect("remove");
    std::fs::write(
        dir.join("deny.toml"),
        r#"[licenses]
allow = ["BSD-3-Clause"]
confidence-threshold = 0.9

[bans]
deny = [{ crate = "serde", reason = "testing bans", wrappers = ["serde_json"] }]

[sources]
unknown-git = "deny"
allow-git = ["https://github.com/myorg/"]
"#,
    )
    .expect("write");
    // cargo-deny checks the default-feature graph, so CargoScope asks
    // `cargo tree`: a fake one lists every package of the fixture.
    let fake_src = dir.join("fake_cargo.rs");
    let fake_bin = dir.join(format!("fake-cargo{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(
        &fake_src,
        r##"fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.iter().any(|a| a == "tree"), "{args:?}");
    println!("policy-demo v0.1.0 (/work)\nserde_json v1.0.128\nserde v1.0.210\nitoa v1.0.11\nforked v0.1.0 (https://github.com/someone/forked?rev=abc#abc)");
}
"##,
    )
    .expect("write fake cargo");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiled = Command::new(rustc)
        .arg(&fake_src)
        .arg("-o")
        .arg(&fake_bin)
        .output()
        .expect("rustc runs");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
            .env("CARGO_HOME", fixture("empty-cargo-home"))
            .env("CARGO", &fake_bin)
            .args(["scan", "--fail-on", "none"])
            .arg(&dir)
            .output()
            .expect("cargoscope binary runs")
    };
    let text = stdout(&run());
    // serde is only used by serde_json, its allowed wrapper: no ban.
    assert!(!text.contains("- [ban] serde"), "{text}");
    assert!(text.contains("- [source] forked 0.1.0:"), "{text}");
    assert!(text.contains("- [license] serde_json 1.0.128:"), "{text}");
    assert!(
        text.contains("no cargoscope.toml: the rules of deny.toml (cargo-deny) are used"),
        "{text}"
    );
    // As in cargo-deny: an allowed license no package uses is a warning.
    assert!(
        text.contains("- [license] [warning] policy-demo 0.1.0: license `BSD-3-Clause` is allowed but no checked package uses it (unused-allowed-license)"),
        "{text}"
    );
    assert!(!text.contains("confidence-threshold"), "{text}");

    // Without the wrapper, the ban applies.
    let deny = std::fs::read_to_string(dir.join("deny.toml")).expect("read");
    std::fs::write(
        dir.join("deny.toml"),
        deny.replace(", wrappers = [\"serde_json\"]", ""),
    )
    .expect("write");
    assert!(stdout(&run()).contains("- [ban] serde 1.0.210:"));

    // A cargoscope.toml takes over, with no note about deny.toml.
    std::fs::write(dir.join("cargoscope.toml"), "[bans]\n").expect("write");
    let text = stdout(&run());
    assert!(!text.contains("deny.toml"), "{text}");
    assert!(!text.contains("- [ban] serde"), "{text}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn bans_features_report_banned_unallowed_and_missing_features() {
    let dir = std::env::temp_dir().join(format!("cargoscope-feat-bans-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);
    std::fs::remove_file(dir.join("cargoscope.toml")).expect("remove");
    std::fs::write(
        dir.join("deny.toml"),
        "[[bans.features]]\ncrate = \"serde\"\ndeny = [\"std\"]\nallow = [\"default\"]\nexact = true\n",
    )
    .expect("write deny.toml");

    let fake_src = dir.join("fake_cargo.rs");
    let fake_bin = dir.join(format!("fake-cargo{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(
        &fake_src,
        r##"fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.windows(2).any(|w| w[0] == "--format" && w[1] == "{p} [{f}]"), "{args:?}");
    let feats = std::env::var("FAKE_SERDE_FEATURES").unwrap_or_else(|_| "std".to_owned());
    println!("policy-demo v0.1.0 (/work) []\nserde_json v1.0.128 [default]\nserde v1.0.210 [{feats}]\nitoa v1.0.11 []\nforked v0.1.0 (https://github.com/someone/forked?rev=abc#abc) []");
}
"##,
    )
    .expect("write fake cargo");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiled = Command::new(rustc)
        .arg(&fake_src)
        .arg("-o")
        .arg(&fake_bin)
        .output()
        .expect("rustc runs");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let run = |feats: &str| {
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
            .env("CARGO_HOME", fixture("empty-cargo-home"))
            .env("CARGO", &fake_bin)
            .env("FAKE_SERDE_FEATURES", feats)
            .args(["scan", "--checks", "inventory,policy", "--fail-on", "none"])
            .arg(&dir)
            .output()
            .expect("cargoscope binary runs")
    };

    // With `std` enabled and `default` missing: banned `std` + exact missing `default`.
    let bad = stdout(&run("std"));
    assert!(
        bad.contains("- [ban] serde 1.0.210: feature `std` is banned: from deny.toml"),
        "{bad}"
    );
    assert!(
        bad.contains("- [ban] serde 1.0.210: exact feature set required, missing feature `default`: from deny.toml"),
        "{bad}"
    );

    // With an unexpected feature `alloc` and `default` enabled: unallowed `alloc`.
    let extra = stdout(&run("alloc,default"));
    assert!(
        extra.contains(
            "- [ban] serde 1.0.210: feature `alloc` is not in the allow list: from deny.toml"
        ),
        "{extra}"
    );

    // With exactly `default`: passes with 0 violations, even via cargoscope.toml.
    let ok = stdout(&run("default"));
    assert!(ok.contains("Policy violations: 0"), "{ok}");

    std::fs::write(
        dir.join("cargoscope.toml"),
        "[bans]\nfeatures = [{ name = \"serde\", deny = [\"std\"], reason = \"no_std only\" }]\n",
    )
    .expect("write cargoscope.toml");
    let blocked = stdout(&run("default,std"));
    assert!(
        blocked.contains("- [ban] serde 1.0.210: feature `std` is banned: no_std only"),
        "{blocked}"
    );
    assert!(stdout(&run("default")).contains("Policy violations: 0"));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn why_shows_reverse_paths_dependents_and_pruning_weight() {
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .arg("why")
            .args(args)
            .output()
            .expect("cargoscope binary runs")
    };

    let text_output = run(&[
        "bitflags",
        fixture("multi-version").to_str().expect("utf-8"),
    ]);
    assert_eq!(text_output.status.code(), Some(0));
    let text = stdout(&text_output);
    assert!(text.contains("bitflags 1.3.2 [transitive]"), "{text}");
    assert!(
        text.contains("weight: 1 exclusive of 1 package in its subtree"),
        "{text}"
    );
    assert!(text.contains("dependents (1): old-wrapper 1.0.0"), "{text}");
    assert!(
        text.contains("    multi-version 0.1.0 -> old-wrapper 1.0.0 -> bitflags 1.3.2"),
        "{text}"
    );
    assert!(text.contains("bitflags 2.6.0 [direct]"), "{text}");
    assert!(
        text.contains("dependents (1): multi-version 0.1.0"),
        "{text}"
    );
    assert!(
        text.contains("    multi-version 0.1.0 -> bitflags 2.6.0"),
        "{text}"
    );

    let json_output = run(&[
        "bitflags@1.3.2",
        fixture("multi-version").to_str().expect("utf-8"),
        "--format",
        "json",
    ]);
    assert_eq!(json_output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&json_output.stdout).expect("valid JSON");
    let matches = json["matches"].as_array().expect("matches");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["version"], "1.3.2");
    assert_eq!(matches[0]["exclusive"], 1);
    assert_eq!(matches[0]["tree"], 1);
    assert_eq!(matches[0]["dependents"][0]["name"], "old-wrapper");
    assert_eq!(
        matches[0]["paths"][0]
            .as_array()
            .expect("path steps")
            .iter()
            .map(|step| step["name"].as_str().expect("name"))
            .collect::<Vec<_>>(),
        vec!["multi-version", "old-wrapper", "bitflags"]
    );

    let missing = run(&["nonexistent", fixture("simple").to_str().expect("utf-8")]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("is not in Cargo.lock"));
}

fn compile_fake_cargo_tree(dir: &std::path::Path, tree_output: &str) -> std::path::PathBuf {
    let fake_src = dir.join("fake_cargo.rs");
    let fake_bin = dir.join(format!("fake-cargo{}", std::env::consts::EXE_SUFFIX));
    let escaped = tree_output.replace('\\', "\\\\").replace('"', "\\\"");
    std::fs::write(
        &fake_src,
        format!(
            "fn main() {{\n    let args: Vec<String> = std::env::args().collect();\n    assert!(args.iter().any(|a| a == \"tree\"), \"{{args:?}}\");\n    print!(\"{escaped}\");\n}}\n"
        ),
    )
    .expect("write fake cargo");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiled = Command::new(rustc)
        .arg(&fake_src)
        .arg("-o")
        .arg(&fake_bin)
        .output()
        .expect("rustc runs");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    fake_bin
}

#[test]
fn bans_build_scripts_flag_disallowed_registry_and_workspace_crates() {
    let dir = std::env::temp_dir().join(format!("cargoscope-build-bans-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);

    let cargo_home = dir.join("cargo-home");
    let serde_dir = cargo_home.join("registry/src/index.crates.io-test/serde-1.0.210");
    std::fs::create_dir_all(&serde_dir).expect("mkdir serde src");
    std::fs::write(
        serde_dir.join("Cargo.toml"),
        "[package]\nname = \"serde\"\nversion = \"1.0.210\"\n",
    )
    .expect("serde manifest");
    std::fs::write(serde_dir.join("build.rs"), "fn main() {}\n").expect("serde build.rs");

    let serde_json_dir = cargo_home.join("registry/src/index.crates.io-test/serde_json-1.0.128");
    std::fs::create_dir_all(&serde_json_dir).expect("mkdir serde_json src");
    std::fs::write(
        serde_json_dir.join("Cargo.toml"),
        "[package]\nname = \"serde_json\"\nversion = \"1.0.128\"\n",
    )
    .expect("serde_json manifest");
    std::fs::write(serde_json_dir.join("build.rs"), "fn main() {}\n").expect("serde_json build.rs");

    // Workspace root also has a build.rs.
    std::fs::write(dir.join("build.rs"), "fn main() {}\n").expect("root build.rs");
    std::fs::remove_file(dir.join("cargoscope.toml")).expect("rm cargoscope.toml");
    std::fs::write(
        dir.join("deny.toml"),
        "[bans.build]\nallow-build-scripts = [\"serde\"]\ninclude-workspace = true\n",
    )
    .expect("write deny.toml");
    let fake_bin = compile_fake_cargo_tree(
        &dir,
        "policy-demo v0.1.0 (/work)\nserde_json v1.0.128\nserde v1.0.210\nitoa v1.0.11\nforked v0.1.0 (https://github.com/someone/forked?rev=abc#abc)\n",
    );

    let out = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO", &fake_bin)
        .args(["scan", "--checks", "inventory,policy"])
        .arg(&dir)
        .output()
        .expect("cargoscope binary runs");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    assert!(
        text.contains("- [ban] policy-demo 0.1.0: build script of `policy-demo` is not in [bans.build] allow-build-scripts"),
        "{text}"
    );
    assert!(
        text.contains("- [ban] serde_json 1.0.128: build script of `serde_json` is not in [bans.build] allow-build-scripts"),
        "{text}"
    );
    assert!(!text.contains("build script of `serde`"), "{text}");

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn clarify_license_files_hash_accepts_match_and_rejects_mismatch() {
    let dir = std::env::temp_dir().join(format!("cargoscope-clarify-hash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);

    let cargo_home = dir.join("cargo-home");
    let itoa_dir = cargo_home.join("registry/src/index.crates.io-test/itoa-1.0.11");
    std::fs::create_dir_all(&itoa_dir).expect("mkdir itoa");
    std::fs::write(
        itoa_dir.join("Cargo.toml"),
        "[package]\nname = \"itoa\"\nversion = \"1.0.11\"\n",
    )
    .expect("itoa manifest");
    std::fs::write(itoa_dir.join("LICENSE"), "MIT\r\n").expect("itoa LICENSE");
    let matching_hash =
        cargoscope_cargo::crate_sources::hash_license_reader(std::io::Cursor::new(b"MIT\n"))
            .expect("hash");

    std::fs::remove_file(dir.join("cargoscope.toml")).expect("rm cargoscope.toml");
    let fake_bin = compile_fake_cargo_tree(
        &dir,
        "policy-demo v0.1.0 (/work)\nserde_json v1.0.128\nserde v1.0.210\nitoa v1.0.11\nforked v0.1.0 (https://github.com/someone/forked#0123456789abcdef0123456789abcdef01234567)\n",
    );
    let deny_for_hash = |hash: u32| {
        format!(
            "[licenses]\nallow = [\"MIT\", \"Apache-2.0\"]\n[[licenses.clarify]]\ncrate = \"itoa\"\nexpression = \"MIT\"\nlicense-files = [{{ path = \"LICENSE\", hash = {hash} }}]\n"
        )
    };

    std::fs::write(dir.join("deny.toml"), deny_for_hash(matching_hash)).expect("write deny.toml");
    let ok = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO", &fake_bin)
        .args(["scan", "--checks", "inventory,licenses,policy"])
        .arg(&dir)
        .output()
        .expect("cargoscope binary runs");
    assert_eq!(
        ok.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        stdout(&ok),
        String::from_utf8_lossy(&ok.stderr)
    );
    let ok_text = stdout(&ok);
    assert!(ok_text.contains("Policy violations: 0"), "{ok_text}");

    std::fs::write(dir.join("deny.toml"), deny_for_hash(matching_hash ^ 1))
        .expect("write bad hash");
    let bad = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO", &fake_bin)
        .args(["scan", "--checks", "inventory,licenses,policy"])
        .arg(&dir)
        .output()
        .expect("cargoscope binary runs");
    assert_eq!(bad.status.code(), Some(1), "{}", stdout(&bad));
    let bad_text = stdout(&bad);
    assert!(
        bad_text.contains("license clarification for itoa 1.0.11 rejected"),
        "{bad_text}"
    );
    assert!(
        bad_text.contains("- [license] itoa 1.0.11: license is unknown"),
        "{bad_text}"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn licenses_are_detected_from_license_files_when_the_field_is_missing() {
    let dir = std::env::temp_dir().join(format!("cargoscope-detect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);
    std::fs::remove_file(dir.join("cargoscope.toml")).expect("rm cargoscope.toml");
    // itoa has no license in the crates.io data, only a LICENSE file.
    let cargo_home = dir.join("cargo-home");
    let itoa_dir = cargo_home.join("registry/src/index.crates.io-test/itoa-1.0.11");
    std::fs::create_dir_all(&itoa_dir).expect("mkdir itoa");
    std::fs::write(
        itoa_dir.join("Cargo.toml"),
        "[package]\nname = \"itoa\"\nversion = \"1.0.11\"\n",
    )
    .expect("itoa manifest");
    let mit =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../LICENSE"))
            .expect("the repository's MIT license");
    std::fs::write(itoa_dir.join("LICENSE-MIT"), mit).expect("itoa LICENSE");
    let fake_bin = compile_fake_cargo_tree(
        &dir,
        "policy-demo v0.1.0 (/work)\nserde_json v1.0.128\nserde v1.0.210\nitoa v1.0.11\n",
    );
    let run = |allow: &str| {
        std::fs::write(
            dir.join("deny.toml"),
            format!("[licenses]\nallow = [{allow}]\n"),
        )
        .expect("write deny.toml");
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
            .env("CARGO_HOME", &cargo_home)
            .env("CARGO", &fake_bin)
            .args(["scan", "--checks", "inventory,licenses,policy"])
            .arg(&dir)
            .output()
            .expect("cargoscope binary runs")
    };
    let ok = run("\"MIT\", \"Apache-2.0\"");
    assert_eq!(ok.status.code(), Some(0), "{}", stdout(&ok));
    assert!(
        stdout(&ok).contains("Policy violations: 0"),
        "{}",
        stdout(&ok)
    );

    let bad = run("\"Apache-2.0\"");
    let text = stdout(&bad);
    assert_eq!(bad.status.code(), Some(1), "{text}");
    assert!(
        text.contains("- [license] itoa 1.0.11: license `MIT` (detected in LICENSE-MIT) is not allowed by the policy"),
        "{text}"
    );
    // The project's own license is checked too, as in cargo-deny.
    assert!(
        text.contains("- [license] policy-demo 0.1.0: license `MIT` is not allowed by the policy"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn executables_in_build_time_crates_are_reported() {
    let dir = std::env::temp_dir().join(format!("cargoscope-exes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);
    std::fs::remove_file(dir.join("cargoscope.toml")).expect("rm cargoscope.toml");
    // itoa gets a build script, a prebuilt ELF and a shell script.
    let cargo_home = dir.join("cargo-home");
    let itoa_dir = cargo_home.join("registry/src/index.crates.io-test/itoa-1.0.11");
    std::fs::create_dir_all(itoa_dir.join("bin")).expect("mkdir itoa");
    std::fs::write(
        itoa_dir.join("Cargo.toml"),
        "[package]\nname = \"itoa\"\nversion = \"1.0.11\"\nlicense = \"MIT\"\n",
    )
    .expect("itoa manifest");
    std::fs::write(itoa_dir.join("build.rs"), "fn main() {}\n").expect("build.rs");
    let mut elf = b"\x7fELF\x02\x01\x01".to_vec();
    elf.resize(64, 0);
    std::fs::write(itoa_dir.join("bin/tool"), elf).expect("elf");
    std::fs::write(itoa_dir.join("gen.sh"), "#!/bin/sh\necho generating code\n").expect("script");
    let fake_bin = compile_fake_cargo_tree(
        &dir,
        "policy-demo v0.1.0 (/work)\nserde_json v1.0.128\nserde v1.0.210\nitoa v1.0.11\n",
    );
    let run = |build: &str| {
        std::fs::write(dir.join("deny.toml"), format!("[bans.build]\n{build}")).expect("deny.toml");
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
            .env("CARGO_HOME", &cargo_home)
            .env("CARGO", &fake_bin)
            .args(["scan", "--checks", "inventory,policy"])
            .arg(&dir)
            .output()
            .expect("cargoscope binary runs")
    };
    let out = run("");
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(
        text.contains("- [ban] itoa 1.0.11: `bin/tool` in `itoa` is an executable (elf), and `itoa` runs code at build time"),
        "{text}"
    );
    assert!(
        !text.contains("gen.sh"),
        "scripts are allowed by default: {text}"
    );

    let text = stdout(&run(
        "interpreted = \"warn\"\nbypass = [{ crate = \"itoa\", allow = [{ path = \"bin/tool\" }] }]\n",
    ));
    assert!(!text.contains("bin/tool"), "{text}");
    assert!(
        text.contains("- [ban] [warning] itoa 1.0.11: `gen.sh` in `itoa` is a sh script"),
        "{text}"
    );

    let text = stdout(&run("script-extensions = [\"sh\"]\n"));
    assert!(
        text.contains("`gen.sh` in `itoa` matches the script extension `*.sh`"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn warn_level_policies_emit_warnings_without_failing_scan() {
    let dir = std::env::temp_dir().join(format!("cargoscope-warn-level-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("multi-version"), &dir);
    let fake_bin = compile_fake_cargo_tree(
        &dir,
        "multi-version v0.1.0 (/work)\nold-wrapper v1.0.0\nbitflags v1.3.2\nbitflags v2.6.0\n",
    );
    std::fs::write(
        dir.join("deny.toml"),
        "[bans]\nmultiple-versions = \"warn\"\nmultiple-versions-include-dev = true\n[sources]\nunknown-git = \"warn\"\nunknown-registry = \"warn\"\n",
    )
    .expect("write deny.toml");

    let run = |format: &str| {
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
            .env("CARGO_HOME", fixture("empty-cargo-home"))
            .env("CARGO", &fake_bin)
            .args(["scan", "--checks", "inventory,policy", "--format", format])
            .arg(&dir)
            .output()
            .expect("cargoscope binary runs")
    };

    let text_out = run("text");
    assert_eq!(
        text_out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        stdout(&text_out),
        String::from_utf8_lossy(&text_out.stderr)
    );
    let text = stdout(&text_out);
    assert!(text.contains("Policy violations: 0 (1 warning)"), "{text}");
    assert!(
        text.contains("- [multiple-versions] [warning] bitflags"),
        "{text}"
    );

    let json: serde_json::Value = serde_json::from_slice(&run("json").stdout).expect("json");
    assert_eq!(json["policy"][0]["level"], "warning");
    assert_eq!(json["policy"][0]["rule"], "multiple-versions");

    let sarif: serde_json::Value = serde_json::from_slice(&run("sarif").stdout).expect("sarif");
    assert_eq!(sarif["runs"][0]["results"][0]["level"], "warning");

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn init_creates_policy_from_deny_toml_and_ci_workflow() {
    let dir = std::env::temp_dir().join(format!("cargoscope-init-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("policy"), &dir);
    std::fs::remove_file(dir.join("cargoscope.toml")).expect("remove");
    std::fs::create_dir_all(dir.join(".cargo")).expect("mkdir .cargo");
    std::fs::write(
        dir.join("deny.toml"),
        r#"[licenses]
allow = ["MIT", "Apache-2.0"]

[bans]
deny = [{ crate = "itoa", reason = "test ban from deny.toml" }]

[sources]
unknown-git = "deny"

[advisories]
ignore = [{ id = "RUSTSEC-2020-0071", reason = "from deny" }]
"#,
    )
    .expect("write deny.toml");
    std::fs::write(
        dir.join(".cargo/audit.toml"),
        "[advisories]\nignore = [\"CARGOSCOPE-TEST-0001\"]\n",
    )
    .expect("write audit.toml");

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .arg("init")
            .args(args)
            .arg(&dir)
            .output()
            .expect("cargoscope binary runs")
    };

    // --dry-run previews without writing files.
    let dry = run(&["--dry-run"]);
    assert_eq!(dry.status.code(), Some(0));
    assert!(!dir.join("cargoscope.toml").exists());
    let dry_text = stdout(&dry);
    assert!(dry_text.contains("[licenses]"), "{dry_text}");
    assert!(dry_text.contains("CARGOSCOPE-TEST-0001"), "{dry_text}");

    // --ci --policy writes both cargoscope.toml and .github/workflows/cargoscope.yml.
    let init = run(&["--ci", "--policy"]);
    assert_eq!(
        init.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        stdout(&init),
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(dir.join("cargoscope.toml").is_file());
    let workflow = std::fs::read_to_string(dir.join(".github/workflows/cargoscope.yml"))
        .expect("workflow written");
    assert!(workflow.contains("HarpeLm/CargoScope@v0.7.6"));

    // Refuses to overwrite without --force, overwrites with --force.
    let second = run(&[]);
    assert_eq!(second.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&second.stderr).contains("already exists"));
    assert_eq!(run(&["--force"]).status.code(), Some(0));

    // Scans using the generated cargoscope.toml without deny.toml fallback warnings.
    let scan = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", fixture("advisory-cache"))
        .env("CARGO_HOME", fixture("empty-cargo-home"))
        .args([
            "scan",
            "--checks",
            "inventory,licenses,policy",
            "--fail-on",
            "none",
        ])
        .arg(&dir)
        .output()
        .expect("cargoscope scan runs");
    assert_eq!(scan.status.code(), Some(0));
    let scan_text = stdout(&scan);
    assert!(!scan_text.contains("no cargoscope.toml"), "{scan_text}");
    assert!(scan_text.contains("- [ban] itoa"), "{scan_text}");
    assert!(scan_text.contains("- [source] forked"), "{scan_text}");

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ranks_advisories_by_dev_platform_and_uncalled_functions() {
    let dir = std::env::temp_dir().join(format!("cargoscope-relevance-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture("renamed"), &dir);

    std::fs::create_dir_all(dir.join("src")).expect("mkdir src");
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn parse() {\n    let _ = json::from_str::<()>(\"null\");\n}\n",
    )
    .expect("write lib.rs");

    let cache = dir.join("cache");
    copy_dir(
        &fixture("advisory-cache/crates-io"),
        &cache.join("crates-io"),
    );
    let adv_db = cache.join("advisory-db");
    std::fs::create_dir_all(adv_db.join("crates/serde_json")).expect("mkdir serde_json adv");
    std::fs::create_dir_all(adv_db.join("crates/cc")).expect("mkdir cc adv");
    std::fs::create_dir_all(adv_db.join("crates/tempfile")).expect("mkdir tempfile adv");
    std::fs::write(adv_db.join("fetched-at"), "2026-01-01\n").expect("write fetched-at");

    std::fs::write(
        adv_db.join("crates/serde_json/CARGOSCOPE-REL-0001.md"),
        "```toml\n[advisory]\nid = \"CARGOSCOPE-REL-0001\"\npackage = \"serde_json\"\ndate = \"2025-01-01\"\ncvss = \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L\"\n\n[versions]\npatched = [\">= 2.0.0\"]\n```\n\n# Direct advisory\n",
    )
    .expect("adv 1");
    std::fs::write(
        adv_db.join("crates/serde_json/CARGOSCOPE-REL-0002.md"),
        "```toml\n[advisory]\nid = \"CARGOSCOPE-REL-0002\"\npackage = \"serde_json\"\ndate = \"2025-01-02\"\ncvss = \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N\"\n\n[versions]\npatched = [\">= 2.0.0\"]\n\n[affected.functions]\n\"serde_json::from_reader\" = [\"< 2.0.0\"]\n```\n\n# Uncalled function\n",
    )
    .expect("adv 2");
    std::fs::write(
        adv_db.join("crates/cc/CARGOSCOPE-REL-0003.md"),
        "```toml\n[advisory]\nid = \"CARGOSCOPE-REL-0003\"\npackage = \"cc\"\ndate = \"2025-01-03\"\ncvss = \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N\"\n\n[versions]\npatched = [\">= 2.0.0\"]\n\n[affected]\nos = [\"plan9\"]\n```\n\n# Wrong platform\n",
    )
    .expect("adv 3");
    std::fs::write(
        adv_db.join("crates/tempfile/CARGOSCOPE-REL-0004.md"),
        "```toml\n[advisory]\nid = \"CARGOSCOPE-REL-0004\"\npackage = \"tempfile\"\ndate = \"2025-01-04\"\ncvss = \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N\"\n\n[versions]\npatched = [\">= 4.0.0\"]\n```\n\n# Dev-only\n",
    )
    .expect("adv 4");

    // 1. JSON mode without [graph]: validates schema, relevance signals, and --fail-on behavior.
    let json_out = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", &cache)
        .env("CARGO_HOME", fixture("empty-cargo-home"))
        .args([
            "scan",
            "--checks",
            "inventory,advisories",
            "--format",
            "json",
            "--fail-on",
            "high",
        ])
        .arg(&dir)
        .output()
        .expect("cargoscope json scan");
    assert_eq!(
        json_out.status.code(),
        Some(1),
        "unlikely high advisory must still fail --fail-on high: {}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("valid JSON output");

    let schema_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/schema/report-v1.json");
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(schema_path).expect("schema file"))
            .expect("schema parses");
    let validator = jsonschema::validator_for(&schema).expect("schema is valid");
    let errors: Vec<String> = validator
        .iter_errors(&report)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");

    let advisories = report["advisories"].as_array().expect("advisories array");
    let by_id = |id: &str| {
        advisories
            .iter()
            .find(|item| item["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("missing advisory {id}: {advisories:?}"))
    };
    assert_eq!(by_id("CARGOSCOPE-REL-0001")["relevance"], "affects-you");
    assert!(by_id("CARGOSCOPE-REL-0001")["relevance_reason"].is_null());

    assert_eq!(by_id("CARGOSCOPE-REL-0002")["relevance"], "unlikely");
    assert!(
        by_id("CARGOSCOPE-REL-0002")["relevance_reason"]
            .as_str()
            .is_some_and(|r| r.contains("`from_reader()` is never called in project sources")),
        "{}",
        by_id("CARGOSCOPE-REL-0002")
    );

    assert_eq!(by_id("CARGOSCOPE-REL-0003")["relevance"], "possibly");
    assert!(
        by_id("CARGOSCOPE-REL-0003")["relevance_reason"]
            .as_str()
            .is_some_and(|r| r.contains("only affects plan9")),
        "{}",
        by_id("CARGOSCOPE-REL-0003")
    );

    assert_eq!(by_id("CARGOSCOPE-REL-0004")["relevance"], "unlikely");
    assert!(
        by_id("CARGOSCOPE-REL-0004")["relevance_reason"]
            .as_str()
            .is_some_and(|r| r.contains("only used by dev-dependencies")),
        "{}",
        by_id("CARGOSCOPE-REL-0004")
    );

    // Terminal mode without [graph]: sorts crates affects-you -> possibly -> unlikely.
    let text_no_graph = stdout(
        &Command::new(env!("CARGO_BIN_EXE_cargoscope"))
            .env("CARGOSCOPE_CACHE_DIR", &cache)
            .env("CARGO_HOME", fixture("empty-cargo-home"))
            .args([
                "scan",
                "--checks",
                "inventory,advisories",
                "--fail-on",
                "none",
            ])
            .arg(&dir)
            .output()
            .expect("cargoscope text scan without graph"),
    );
    let vuln_section = text_no_graph
        .split("Vulnerabilities")
        .nth(1)
        .expect("Vulnerabilities section");
    let pos_serde_json = vuln_section
        .find("serde_json")
        .expect("serde_json in terminal output");
    let pos_cc = vuln_section.find("cc").expect("cc in terminal output");
    let pos_tempfile = vuln_section
        .find("tempfile")
        .expect("tempfile in terminal output");
    assert!(
        pos_serde_json < pos_cc && pos_cc < pos_tempfile,
        "unexpected crate order (expected affects-you -> possibly -> unlikely):\n{vuln_section}"
    );
    assert!(
        vuln_section.contains("possibly: only affects plan9"),
        "{vuln_section}"
    );
    assert!(
        vuln_section.contains("unlikely: only used by dev-dependencies (tests or benchmarks)"),
        "{vuln_section}"
    );

    // 2. Verbose + HTML with [graph]: unbuilt crate detection and configured target mismatch.
    std::fs::write(
        adv_db.join("crates/serde_json/CARGOSCOPE-REL-0005.md"),
        "```toml\n[advisory]\nid = \"CARGOSCOPE-REL-0005\"\npackage = \"serde_json\"\ndate = \"2025-01-05\"\ncvss = \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L\"\n\n[versions]\npatched = [\">= 2.0.0\"]\n\n[affected]\nos = [\"plan9\"]\n```\n\n# Configured target mismatch\n",
    )
    .expect("adv 5");
    std::fs::write(
        dir.join("cargoscope.toml"),
        "[graph]\ntargets = [\"x86_64-unknown-linux-gnu\"]\n\n[bans]\n",
    )
    .expect("write cargoscope.toml");
    let fake_cargo = compile_fake_cargo_tree(
        &dir,
        "renamed v0.1.0 (/work)\nserde_json v1.0.128\ntempfile v3.13.0\n",
    );
    let text_out = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", &cache)
        .env("CARGO_HOME", fixture("empty-cargo-home"))
        .env("CARGO", &fake_cargo)
        .args([
            "scan",
            "--verbose",
            "--checks",
            "inventory,advisories,policy",
            "--fail-on",
            "none",
        ])
        .arg(&dir)
        .output()
        .expect("cargoscope verbose scan");
    assert_eq!(text_out.status.code(), Some(0));
    let text = stdout(&text_out);
    assert!(
        text.contains("relevance: unlikely (`from_reader()` is never called in project sources)"),
        "{text}"
    );
    assert!(
        text.contains(
            "relevance: unlikely (cc is not built by the configured [graph] targets or features)"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "relevance: unlikely (only affects plan9, not configured targets (x86_64-unknown-linux-gnu))"
        ),
        "{text}"
    );

    let html_out = Command::new(env!("CARGO_BIN_EXE_cargoscope"))
        .env("CARGOSCOPE_CACHE_DIR", &cache)
        .env("CARGO_HOME", fixture("empty-cargo-home"))
        .env("CARGO", &fake_cargo)
        .args([
            "scan",
            "--checks",
            "inventory,advisories,policy",
            "--format",
            "html",
            "--fail-on",
            "none",
        ])
        .arg(&dir)
        .output()
        .expect("cargoscope html scan");
    assert_eq!(html_out.status.code(), Some(0));
    let html = stdout(&html_out);
    assert!(html.contains("unlikely"), "{html}");
    assert!(
        html.contains("only used by dev-dependencies (tests or benchmarks)"),
        "{html}"
    );

    let _ = std::fs::remove_dir_all(dir);
}
