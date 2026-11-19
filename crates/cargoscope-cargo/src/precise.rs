//! Opt-in, compiler-accurate unused-dependency detection (`scan --precise`).
//!
//! Runs `cargo check --workspace --all-targets --all-features` with rustc's
//! `unused_crate_dependencies` lint and reads Cargo's JSON messages. A
//! dependency is unused when rustc reports it unused in every compiled target
//! that receives it.
//!
//! From Rust 1.100, Cargo turns that lint into its own `unused_dependencies`
//! lint: it prints one warning per unused normal or build dependency on its
//! error output, and rustc's JSON messages no longer carry it. CargoScope
//! then reads Cargo's warnings; dev-dependencies, which that lint does not
//! check, keep their static result.
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
    /// With Cargo 1.100 or later: the dependencies Cargo's
    /// `unused_dependencies` lint reports, by manifest, as `(kind, ident)`.
    cargo_lint: Option<BTreeMap<PathBuf, BTreeSet<(DependencyKind, String)>>>,
}

impl CompilerReport {
    /// `Some(true)` when rustc reports `ident` unused in every compiled
    /// target of `manifest` that receives a dependency of `kind`,
    /// `Some(false)` when one of them uses it, `None` when no such target was
    /// compiled (for example a dependency of another platform).
    #[must_use]
    pub fn is_unused(&self, manifest: &Path, kind: DependencyKind, ident: &str) -> Option<bool> {
        if !self.checks(kind) {
            return None;
        }
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
        if let Some(lint) = &self.cargo_lint {
            return Some(
                lint.get(&canonical(manifest))
                    .is_some_and(|unused| unused.contains(&(kind, ident.to_owned()))),
            );
        }
        Some(relevant.iter().all(|target| target.unused.contains(ident)))
    }

    /// Whether the compiler checks dependencies of `kind`: Cargo's lint does
    /// not check dev-dependencies.
    #[must_use]
    pub fn checks(&self, kind: DependencyKind) -> bool {
        self.cargo_lint.is_none() || kind != DependencyKind::Dev
    }

    /// The lint the answers come from, for evidence.
    #[must_use]
    pub fn source(&self) -> &'static str {
        if self.cargo_lint.is_some() {
            "Cargo's unused_dependencies lint"
        } else {
            "rustc's unused_crate_dependencies lint in every compiled target that receives it"
        }
    }

    /// Crates the compiler reports unused somewhere in `manifest`.
    #[must_use]
    pub fn reported(&self, manifest: &Path) -> BTreeSet<String> {
        if let Some(lint) = &self.cargo_lint {
            return lint
                .get(&canonical(manifest))
                .into_iter()
                .flatten()
                .map(|(_, ident)| ident.clone())
                .collect();
        }
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

/// Section of the dependency declared at 1-based `line` of a manifest: the
/// kind named by the nearest table header above it (or on it, for the
/// `[dependencies.name]` form).
fn section_at(manifest: &str, line: usize) -> Option<DependencyKind> {
    manifest
        .lines()
        .take(line)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(str::trim)
        .find(|text| text.starts_with('['))
        .map(|header| {
            let header = header
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or("");
            if header.contains("dev-dependencies") || header.contains("dev_dependencies") {
                DependencyKind::Dev
            } else if header.contains("build-dependencies") || header.contains("build_dependencies")
            {
                DependencyKind::Build
            } else {
                DependencyKind::Normal
            }
        })
}

/// Reads the warnings of Cargo's `unused_dependencies` lint (Cargo 1.100 or
/// later) from its error output:
///
/// ```text
/// warning: unused dependency `cfg-if`
///  --> crates/app/Cargo.toml:6:1
/// ```
///
/// Paths are relative to `project_root`, where Cargo ran.
#[must_use]
pub fn parse_cargo_lint(
    stderr: &str,
    project_root: &Path,
) -> BTreeMap<PathBuf, BTreeSet<(DependencyKind, String)>> {
    let mut unused: BTreeMap<PathBuf, BTreeSet<(DependencyKind, String)>> = BTreeMap::new();
    let mut pending: Option<String> = None;
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("warning: unused dependency `") {
            pending = rest.split('`').next().map(str::to_owned);
            continue;
        }
        let Some(location) = line.trim_start().strip_prefix("--> ") else {
            continue;
        };
        let Some(name) = pending.take() else {
            continue;
        };
        // `path:line:column`, from the right: Windows paths contain `:`.
        let mut parts = location.trim().rsplitn(3, ':');
        let (Some(_column), Some(number), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let Ok(number) = number.parse::<usize>() else {
            continue;
        };
        let manifest = project_root.join(path);
        let Some(kind) = std::fs::read_to_string(&manifest)
            .ok()
            .and_then(|text| section_at(&text, number))
        else {
            continue;
        };
        unused
            .entry(canonical(&manifest))
            .or_default()
            .insert((kind, name.replace('-', "_")));
    }
    unused
}

/// Whether this Cargo reports unused dependencies itself (1.100 or later).
fn cargo_has_unused_dependencies_lint(cargo: &std::ffi::OsStr) -> bool {
    let Ok(output) = Command::new(cargo).arg("--version").output() else {
        return false;
    };
    // "cargo 1.100.0 (3acc79c0c 2026-11-05)"
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .nth(1)
        .and_then(|version| version.split('.').nth(1)?.parse::<u32>().ok())
        .is_some_and(|minor| minor >= 100)
}

/// Runs the precise build of `project_root`.
///
/// # Errors
///
/// Returns Cargo's error output when the build cannot run or fails.
pub fn run(project_root: &Path) -> Result<CompilerReport, String> {
    let flags = std::env::var("RUSTFLAGS").unwrap_or_default();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let cargo_lint = cargo_has_unused_dependencies_lint(&cargo);
    let output = Command::new(&cargo)
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let tail: Vec<&str> = stderr.lines().rev().take(15).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        return Err(format!("cargo check failed:\n{}", tail.join("\n")));
    }
    let mut report = parse_messages(&stdout);
    if cargo_lint {
        report.cargo_lint = Some(parse_cargo_lint(&stderr, project_root));
    }
    Ok(report)
}

/// Replaces static findings with the compiler's answer where it has one.
///
/// - Confirmed unused: kept (or promoted from `possibly-unused`) as
///   `likely-unused`, with the compiler as evidence.
/// - Used according to the compiler: removed.
/// - Not compiled (another platform, or dev-dependencies under Cargo 1.100+):
///   the static finding stays.
/// - Unused for the compiler but not found statically (meaning static analysis
///   saw a source or doctest reference): added as `possibly-unused`, because
///   `cargo check --all-targets --all-features` skips doctests and disables
///   mutually-exclusive `#[cfg(not(feature = ...))]` branches.
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
                finding.evidence = vec![format!(
                    "confirmed by {} (--precise, all features, this platform)",
                    compiler.source()
                )];
                refined.push(finding);
            }
            Some(false) => {}
            None => {
                finding.evidence.push(if compiler.checks(finding.kind) {
                    "not compiled by --precise on this platform: static result kept".to_owned()
                } else {
                    "Cargo's unused_dependencies lint does not check dev-dependencies: static result kept".to_owned()
                });
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
                confidence: UnusedConfidence::Possibly,
                evidence: vec![format!(
                    "reported by {} (--precise), although the static analysis found a reference (may be doctest-only or behind a mutually-exclusive feature)",
                    compiler.source()
                )],
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

    #[test]
    fn reads_cargo_unused_dependencies_warnings() {
        let root = std::env::temp_dir().join(format!("cargoscope-lint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("crates/app")).expect("dirs");
        std::fs::write(
            root.join("crates/app/Cargo.toml"),
            "[package]\nname = \"app\"\n\n[dependencies]\ncfg-if = \"1\"\nitoa = \"1\"\n\n[build-dependencies]\nshlex = \"1\"\n\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n",
        )
        .expect("write");
        let stderr = "    Checking app v0.1.0\nwarning: unused dependency `cfg-if`\n --> crates/app/Cargo.toml:5:1\n  |\n5 | cfg-if = \"1\"\n  |\nwarning: unused dependency `shlex`\n --> crates/app/Cargo.toml:9:1\nwarning: unused dependency `libc`\n --> crates/app/Cargo.toml:12:1\nwarning: unused variable `x`\n --> crates/app/src/lib.rs:1:5\nwarning: `app` (manifest) generated 3 warnings\n";
        let lint = super::parse_cargo_lint(stderr, &root);
        let manifest = root
            .join("crates/app/Cargo.toml")
            .canonicalize()
            .expect("exists");
        let found: Vec<(DependencyKind, String)> = lint[&manifest].iter().cloned().collect();
        assert_eq!(
            found,
            vec![
                (DependencyKind::Normal, "cfg_if".to_owned()),
                (DependencyKind::Normal, "libc".to_owned()),
                (DependencyKind::Build, "shlex".to_owned()),
            ]
        );

        // With Cargo's lint, compiled targets answer for normal and build
        // dependencies; dev-dependencies are not checked.
        // Messages built with serde_json, so Windows paths are escaped as Cargo does.
        let artifact = |kind: &str, name: &str, test: bool| {
            serde_json::json!({
                "reason": "compiler-artifact",
                "manifest_path": manifest,
                "target": { "kind": [kind], "name": name },
                "profile": { "test": test },
            })
            .to_string()
        };
        let mut report = parse_messages(
            &[
                artifact("lib", "app", false),
                artifact("lib", "app", true),
                artifact("custom-build", "build-script-build", false),
            ]
            .join("\n"),
        );
        report.cargo_lint = Some(lint);
        assert_eq!(
            report.is_unused(&manifest, DependencyKind::Normal, "cfg_if"),
            Some(true)
        );
        assert_eq!(
            report.is_unused(&manifest, DependencyKind::Normal, "itoa"),
            Some(false)
        );
        assert_eq!(
            report.is_unused(&manifest, DependencyKind::Build, "shlex"),
            Some(true)
        );
        assert_eq!(
            report.is_unused(&manifest, DependencyKind::Dev, "itoa"),
            None
        );
        assert!(!report.checks(DependencyKind::Dev));
        assert!(report.source().starts_with("Cargo's"));
        assert!(report.reported(&manifest).contains("libc"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refine_promotes_confirmed_and_keeps_compiler_only_disagreements_uncertain() {
        use cargoscope_core::{UnusedConfidence, UnusedFinding};
        let root = std::env::temp_dir().join(format!("cargoscope-refine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("dir");
        let manifest_text = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nconfirmed = \"1\"\nused_by_macro = \"1\"\nno_std_only = \"1\"\n";
        let manifest_path = root.join("Cargo.toml");
        std::fs::write(&manifest_path, manifest_text).expect("manifest");
        let parsed: toml::Value = toml::from_str(manifest_text).expect("toml");
        let m = manifest_path
            .canonicalize()
            .expect("canonical")
            .to_string_lossy()
            .into_owned();

        // Compiler sees `confirmed` and `no_std_only` unused, and `used_by_macro` used.
        let output = [
            artifact(&m, "lib", "demo", false),
            unused(&m, "lib", "demo", "confirmed"),
            unused(&m, "lib", "demo", "no_std_only"),
        ]
        .join("\n");
        let compiler = parse_messages(&output);

        // Static analysis flagged `confirmed` (possibly-unused) and `used_by_macro` (likely-unused),
        // and did NOT flag `no_std_only` because it saw a reference in source/doctests.
        let static_findings = vec![
            UnusedFinding {
                declared_by: "demo".to_owned(),
                manifest: "Cargo.toml".to_owned(),
                dependency: "confirmed".to_owned(),
                package: "confirmed".to_owned(),
                kind: DependencyKind::Normal,
                confidence: UnusedConfidence::Possibly,
                evidence: vec!["static".to_owned()],
                ignored: None,
            },
            UnusedFinding {
                declared_by: "demo".to_owned(),
                manifest: "Cargo.toml".to_owned(),
                dependency: "used_by_macro".to_owned(),
                package: "used_by_macro".to_owned(),
                kind: DependencyKind::Normal,
                confidence: UnusedConfidence::Likely,
                evidence: vec!["static".to_owned()],
                ignored: None,
            },
        ];

        let refined = super::refine(
            static_findings,
            &[(root.clone(), "Cargo.toml".to_owned(), parsed)],
            None,
            &compiler,
        );
        // `used_by_macro` was eliminated, `confirmed` promoted to Likely, `no_std_only` added as Possible.
        assert_eq!(refined.len(), 2, "{refined:?}");
        let confirmed = refined
            .iter()
            .find(|f| f.dependency == "confirmed")
            .expect("confirmed");
        assert_eq!(confirmed.confidence, UnusedConfidence::Likely);
        let no_std = refined
            .iter()
            .find(|f| f.dependency == "no_std_only")
            .expect("no_std_only");
        assert_eq!(no_std.confidence, UnusedConfidence::Possibly);

        let _ = std::fs::remove_dir_all(&root);
    }
}
