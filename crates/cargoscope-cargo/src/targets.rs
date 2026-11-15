//! Which packages a target platform builds, from `cargo metadata`.
//!
//! `Cargo.lock` lists the dependencies of every platform, and records no
//! `cfg(...)`: the packages one target needs can only come from Cargo, which
//! reads the manifests of the dependencies (so their sources must be
//! downloaded; `cargo fetch` does it). Nothing is compiled or run.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};

use cargoscope_core::policy::{ActivePackages, Features};

/// Names and versions of the packages in the dependency graph of `json`
/// (the output of `cargo metadata --filter-platform <target>`).
///
/// # Errors
///
/// Returns a message when the output is not Cargo's metadata or has no
/// resolved graph.
pub fn parse_metadata(json: &str) -> Result<BTreeSet<(String, String)>, String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| format!("cargo metadata did not return JSON: {error}"))?;
    let nodes = value
        .get("resolve")
        .and_then(|resolve| resolve.get("nodes"))
        .and_then(serde_json::Value::as_array)
        .ok_or("cargo metadata has no resolved dependency graph")?;
    let ids: BTreeSet<&str> = nodes
        .iter()
        .filter_map(|node| node.get("id").and_then(serde_json::Value::as_str))
        .collect();
    let packages = value
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or("cargo metadata lists no packages")?;
    Ok(packages
        .iter()
        .filter(|package| {
            package
                .get("id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| ids.contains(id))
        })
        .filter_map(|package| {
            let field = |key: &str| {
                package
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            };
            Some((field("name")?, field("version")?))
        })
        .collect())
}

/// Packages in the graph of at least one of `targets` (every platform when
/// empty), with the given features (Cargo's defaults when `None`), from
/// `cargo metadata --locked` run in `root`.
///
/// # Errors
///
/// Returns Cargo's explanation when it cannot produce the metadata (sources
/// not downloaded, outdated lockfile, unknown target or feature).
pub fn active_packages(
    root: &Path,
    targets: &[String],
    features: Option<&Features>,
) -> Result<ActivePackages, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut active = ActivePackages::new();
    let platforms: Vec<Option<&String>> = if targets.is_empty() {
        vec![None]
    } else {
        targets.iter().map(Some).collect()
    };
    for target in platforms {
        let mut args: Vec<String> = [
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--color",
            "never",
        ]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
        if let Some(target) = target {
            args.push("--filter-platform".to_owned());
            args.push(target.clone());
        }
        args.extend(features.map(Features::cargo_args).unwrap_or_default());
        let target = target.map_or("every platform", String::as_str);
        let output = Command::new(&cargo)
            .current_dir(root)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("could not run cargo: {error}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let why = stderr
                .lines()
                .map(str::trim)
                .find(|line| line.starts_with("error:"))
                .or_else(|| stderr.lines().map(str::trim).rfind(|line| !line.is_empty()))
                .unwrap_or("cargo metadata failed");
            return Err(format!("`cargo metadata` for {target}: {why}"));
        }
        active.extend(
            parse_metadata(&String::from_utf8_lossy(&output.stdout))
                .map_err(|error| format!("{target}: {error}"))?,
        );
    }
    Ok(active)
}

#[cfg(test)]
mod tests {
    use super::parse_metadata;

    #[test]
    fn keeps_only_the_packages_of_the_resolved_graph() {
        let json = r#"{
            "packages": [
                {"id": "registry+x#serde@1.0.0", "name": "serde", "version": "1.0.0"},
                {"id": "registry+x#windows-sys@0.52.0", "name": "windows-sys", "version": "0.52.0"}
            ],
            "resolve": {"nodes": [{"id": "registry+x#serde@1.0.0"}], "root": null}
        }"#;
        let found = parse_metadata(json).expect("valid metadata");
        assert_eq!(
            found.into_iter().collect::<Vec<_>>(),
            vec![("serde".to_owned(), "1.0.0".to_owned())]
        );
        assert!(parse_metadata("not json").is_err());
        assert!(parse_metadata(r#"{"packages": []}"#).is_err());
    }
}
