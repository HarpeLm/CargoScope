//! End-to-end tests running the `cargoscope` binary on the fixtures in `tests/fixtures`.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn scan(name: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cargoscope"))
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
    let output = scan("simple", &[]);
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
    let output = scan("simple", &["--format", "json"]);
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
