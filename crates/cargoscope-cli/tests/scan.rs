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
    assert!(text.contains("Summary: 1 vulnerability (1 informational), 0 likely-unused, 1 yanked, 1 outdated direct, 4 packages\n"));
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
