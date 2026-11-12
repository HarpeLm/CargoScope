//! Opt-in, compiler-accurate unused-dependency detection (`scan --precise`).
//!
//! Runs `cargo check --workspace --all-targets --all-features` with rustc's
//! `unused_crate_dependencies` lint and reads Cargo's JSON messages. A
//! dependency is unused when rustc reports it unused in every compiled target
//! that receives it.
//!
//! **This compiles the project: build scripts and proc macros of the project
//! and of its dependencies run.** It is never enabled by default.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use cargoscope_core::{DependencyKind, UnusedConfidence, UnusedFinding};

/// Directory, inside the project's `target/`, used for the precise build so
/// that the regular build cache is not invalidated by the extra lint flag.
pub const TARGET_SUBDIR: &str = "cargoscope-precise";

/// Which dependencies a compiled target receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Receives {
    /// Normal dependencies only (library, binary).
    Normal,
    /// Normal and dev-dependencies (tests, benches, examples, test builds).
    NormalAndDev,
    /// Build dependencies (build script).
    Build,
}

#[derive(Debug, Default)]
struct Target {
    receives: BTreeSet<Receives>,
    unused: BTreeSet<String>,
}

/// What the compiler reported, per manifest path.
#[derive(Debug, Default)]
pub struct CompilerReport {
    targets: BTreeMap<PathBuf, BTreeMap<(String, String), Target>>,
}

impl CompilerReport {
    /// `Some(true)` when rustc reports `ident` unused in every compiled
    /// target of `manifest` that receives a dependency of `kind`,
    /// `Some(false)` when one of them uses it, `None` when no such target was
    /// compiled (for example a dependency of another platform).
    #[must_use]
    pub fn is_unused(&self, manifest: &Path, kind: DependencyKind, ident: &str) -> Option<bool> {
        let targets = self.targets.get(&canonical(manifest))?;
        let relevant: Vec<&Target> = targets
            .values()
            .filter(|target| {
                target.receives.iter().any(|receives| match kind {
                    DependencyKind::Normal => {
                        matches!(receives, Receives::Normal | Receives::NormalAndDev)
                    }
                    DependencyKind::Dev => *receives == Receives::NormalAndDev,
                    DependencyKind::Build => *receives == Receives::Build,
                })
            })
            .collect();
        if relevant.is_empty() {
            return None;
        }
        Some(relevant.iter().all(|target| target.unused.contains(ident)))
    }

    /// Crates rustc reports unused somewhere in `manifest`.
    #[must_use]
    pub fn reported(&self, manifest: &Path) -> BTreeSet<String> {
        self.targets
            .get(&canonical(manifest))
            .into_iter()
            .flat_map(|targets| targets.values())
            .flat_map(|target| target.unused.iter().cloned())
            .collect()
    }
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn target_key(message: &serde_json::Value) -> Option<(PathBuf, (String, String))> {
    let manifest = message.get("manifest_path")?.as_str()?;
    let target = message.get("target")?;
    let kind = target.get("kind")?.to_string();
    let name = target.get("name")?.as_str()?.to_owned();
    Some((canonical(Path::new(manifest)), (kind, name)))
}

/// Reads Cargo's `--message-format=json` output.
#[must_use]
pub fn parse_messages(output: &str) -> CompilerReport {
    let mut report = CompilerReport::default();
    for line in output.lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some((manifest, key)) = target_key(&message) else {
            continue;
        };
        let entry = report
            .targets
            .entry(manifest)
            .or_default()
            .entry(key)
            .or_default();
        match message.get("reason").and_then(serde_json::Value::as_str) {
            Some("compiler-artifact") => {
                let kinds: Vec<&str> = message
                    .get("target")
                    .and_then(|target| target.get("kind"))
                    .and_then(serde_json::Value::as_array)
                    .map(|kinds| kinds.iter().filter_map(serde_json::Value::as_str).collect())
                    .unwrap_or_default();
                let test_profile = message
                    .get("profile")
                    .and_then(|profile| profile.get("test"))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                let receives = if kinds.contains(&"custom-build") {
                    Receives::Build
                } else if test_profile
                    || kinds
                        .iter()
                        .any(|kind| matches!(*kind, "test" | "bench" | "example"))
                {
                    Receives::NormalAndDev
                } else {
                    Receives::Normal
                };
                entry.receives.insert(receives);
            }
            Some("compiler-message") => {
                let inner = message.get("message");
                let code = inner
                    .and_then(|inner| inner.get("code"))
                    .and_then(|code| code.get("code"))
                    .and_then(serde_json::Value::as_str);
                if code != Some("unused_crate_dependencies") {
                    continue;
                }
                // "extern crate `serde_json` is unused in crate `app`"
                let text = inner
                    .and_then(|inner| inner.get("message"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if let Some(name) = text.split('`').nth(1) {
                    entry.unused.insert(name.to_owned());
                }
            }
            _ => {}
        }
    }
    report
}

/// Runs the precise build of `project_root`.
///
/// # Errors
///
/// Returns Cargo's error output when the build cannot run or fails.
pub fn run(project_root: &Path) -> Result<CompilerReport, String> {
    let flags = std::env::var("RUSTFLAGS").unwrap_or_default();
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .current_dir(project_root)
        .env(
            "RUSTFLAGS",
            format!("{flags} -W unused-crate-dependencies").trim(),
        )
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args([
            "check",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--message-format=json",
            "--target-dir",
        ])
        .arg(project_root.join("target").join(TARGET_SUBDIR))
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not run cargo: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(15).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        return Err(format!("cargo check failed:\n{}", tail.join("\n")));
    }
    Ok(parse_messages(&stdout))
}

/// Replaces static findings with the compiler's answer where it has one.
///
/// - Confirmed unused: kept as `likely-unused`, with the compiler as evidence.
/// - Used according to the compiler: removed.
/// - Not compiled (another platform, say): the static finding stays.
/// - Unused for the compiler but not found statically: added.
#[must_use]
pub fn refine(
    findings: Vec<UnusedFinding>,
    packages: &[(PathBuf, String, toml::Value)],
    workspace_dependencies: Option<&toml::Value>,
    compiler: &CompilerReport,
) -> Vec<UnusedFinding> {
    let mut refined = Vec::new();
    let mut seen = BTreeSet::new();
    for mut finding in findings {
        let Some((dir, _, _)) = packages
            .iter()
            .find(|(_, label, _)| *label == finding.manifest)
        else {
            refined.push(finding);
            continue;
        };
        let manifest = dir.join("Cargo.toml");
        let ident = finding.dependency.replace('-', "_");
        seen.insert((
            finding.manifest.clone(),
            finding.kind,
            finding.dependency.clone(),
        ));
        match compiler.is_unused(&manifest, finding.kind, &ident) {
            Some(true) => {
                finding.confidence = UnusedConfidence::Likely;
                finding.evidence = vec![
                    "confirmed by rustc's unused_crate_dependencies lint in every compiled target that receives it (--precise, all features, this platform)".to_owned(),
                ];
                refined.push(finding);
            }
            Some(false) => {}
            None => {
                finding.evidence.push(
                    "not compiled by --precise on this platform: static result kept".to_owned(),
                );
                refined.push(finding);
            }
        }
    }

    for (dir, label, manifest) in packages {
        let path = dir.join("Cargo.toml");
        let reported = compiler.reported(&path);
        let name = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            .unwrap_or("unknown");
        for dependency in crate::unused::declared_dependencies(manifest, workspace_dependencies) {
            let ident = dependency.key.replace('-', "_");
            if !reported.contains(&ident)
                || seen.contains(&(label.clone(), dependency.kind, dependency.key.clone()))
                || compiler.is_unused(&path, dependency.kind, &ident) != Some(true)
            {
                continue;
            }
            refined.push(UnusedFinding {
                declared_by: name.to_owned(),
                manifest: label.clone(),
                dependency: dependency.key.clone(),
                package: dependency.package.clone(),
                kind: dependency.kind,
                confidence: UnusedConfidence::Likely,
                evidence: vec![
                    "reported by rustc's unused_crate_dependencies lint in every compiled target that receives it (--precise), although the static analysis found a reference".to_owned(),
                ],
                ignored: None,
            });
        }
    }
    refined
}

#[cfg(test)]
mod tests {
    use super::parse_messages;
    use cargoscope_core::DependencyKind;
    use std::path::Path;

    fn artifact(manifest: &str, kind: &str, name: &str, test: bool) -> String {
        format!(
            r#"{{"reason":"compiler-artifact","manifest_path":"{manifest}","target":{{"kind":["{kind}"],"name":"{name}"}},"profile":{{"test":{test}}}}}"#
        )
    }

    fn unused(manifest: &str, kind: &str, name: &str, krate: &str) -> String {
        format!(
            r#"{{"reason":"compiler-message","manifest_path":"{manifest}","target":{{"kind":["{kind}"],"name":"{name}"}},"message":{{"code":{{"code":"unused_crate_dependencies"}},"message":"extern crate `{krate}` is unused in crate `{name}`"}}}}"#
        )
    }

    #[test]
    fn a_dependency_is_unused_only_when_every_receiving_target_says_so() {
        let m = "/nonexistent/app/Cargo.toml";
        let output = [
            artifact(m, "lib", "app", false),
            artifact(m, "lib", "app", true),
            artifact(m, "test", "it", true),
            artifact(m, "custom-build", "build-script-build", false),
            // `log` unused everywhere; `serde` used by the library only.
            unused(m, "lib", "app", "log"),
            unused(m, "test", "it", "log"),
            unused(m, "test", "it", "serde"),
            // `tempfile` (dev) unused in the integration test and the lib test build.
            unused(m, "test", "it", "tempfile"),
            unused(m, "lib", "app", "tempfile"),
            unused(m, "custom-build", "build-script-build", "cc"),
            "not json".to_owned(),
        ]
        .join("\n");
        let report = parse_messages(&output);
        let path = Path::new(m);
        assert_eq!(
            report.is_unused(path, DependencyKind::Normal, "log"),
            Some(true)
        );
        assert_eq!(
            report.is_unused(path, DependencyKind::Normal, "serde"),
            Some(false)
        );
        assert_eq!(
            report.is_unused(path, DependencyKind::Dev, "tempfile"),
            Some(true)
        );
        assert_eq!(
            report.is_unused(path, DependencyKind::Build, "cc"),
            Some(true)
        );
        assert_eq!(
            report.is_unused(
                Path::new("/other/Cargo.toml"),
                DependencyKind::Normal,
                "log"
            ),
            None
        );
    }
}
