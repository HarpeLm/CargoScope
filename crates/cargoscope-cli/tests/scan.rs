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
        .arg("scan")
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
    // 1.0.300 is yanked and 2.0.0-alpha.1 is a pre-release: the latest is 1.0.200.
    assert!(text.contains(
        "Outdated packages: 1 (1 direct)\n- serde_json 1.0.128 -> 1.0.200, published 2025-12-01\n"
    ));
    assert!(text.contains("- serde_json 1.0.128 [direct] (registry+https://github.com/rust-lang/crates.io-index) MIT OR Apache-2.0 -> 1.0.200 available\n"));
    assert!(text.contains("- itoa 1.0.11 [transitive] (registry+https://github.com/rust-lang/crates.io-index) YANKED\n"));
    assert!(!text.contains("no crates.io data"));
}

#[test]
fn json_output_includes_registry_data() {
    let json = stdout(&scan("simple", &["--format", "json", "--fail-on", "none"]));
    assert!(
        json.contains("\"registry\":{\"source\":\"crates.io\",\"downloaded_on\":\"2026-01-01\"}")
    );
    assert!(json.contains("\"license\":\"MIT OR Apache-2.0\",\"latest_version\":\"1.0.200\",\"latest_published\":\"2025-12-01\",\"outdated\":true,\"yanked\":false}"));
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
