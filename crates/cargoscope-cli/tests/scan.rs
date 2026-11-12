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
    assert!(text.contains("- serde_json 1.0.128 [direct]"));
    assert!(text.contains("- serde 1.0.210 [transitive]"));
    assert!(text.contains("- itoa 1.0.11 [transitive]"));
}

#[test]
fn workspace_members_contribute_direct_dependencies() {
    let text = stdout(&scan("workspace", &[]));
    assert!(text.contains("- anyhow 1.0.89 [direct]"));
    assert!(text.contains("- memchr 2.7.4 [direct]"));
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
    assert!(json.contains("\"name\":\"serde_json\",\"version\":\"1.0.128\",\"direct\":true"));
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
