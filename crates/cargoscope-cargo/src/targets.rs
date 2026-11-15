//! Which packages a build of the project uses, from `cargo tree` (`[graph]`
//! in `cargoscope.toml`).
//!
//! `Cargo.lock` lists the dependencies of every platform and every feature,
//! and records no `cfg(...)` or feature: only Cargo's feature resolver knows
//! what a given set of targets and features builds. `cargo tree --workspace`
//! runs it (it reads the manifests of the dependencies, so their sources must
//! be downloaded; `cargo fetch` does it). Nothing is compiled or run.
//!
//! `cargo metadata` is not used: its resolved graph ignores the feature flags
//! (`--no-default-features` gives the same graph) and keeps optional
//! dependencies that no build uses.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Command, Stdio};

use cargoscope_core::policy::{ActivePackages, EnabledFeatures, Features};

/// Names, versions and enabled features of `cargo tree --prefix none
/// --format "{p} [{f}]"` output (one `name vVERSION (source) [features]` per
/// line, with `(*)` on repeated ones and section headers such as
/// `[dev-dependencies]` skipped; lines without `[features]` are still read).
#[must_use]
pub fn parse_tree_features(output: &str) -> (ActivePackages, EnabledFeatures) {
    let mut packages = BTreeSet::new();
    let mut features: EnabledFeatures = BTreeMap::new();
    for line in output.lines() {
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else {
            continue;
        };
        let Some(version) = words.next().and_then(|word| word.strip_prefix('v')) else {
            continue;
        };
        if name.starts_with('[') || semver::Version::parse(version).is_err() {
            continue;
        }
        let key = (name.to_owned(), version.to_owned());
        packages.insert(key.clone());
        let entry = features.entry(key).or_default();
        let trimmed = line.trim_end();
        let without_repeat = trimmed.strip_suffix("(*)").map_or(trimmed, str::trim_end);
        if let Some(body) = without_repeat.strip_suffix(']')
            && let Some(open) = body.rfind('[')
        {
            for feature in body[open + 1..]
                .split(',')
                .map(str::trim)
                .filter(|feature| !feature.is_empty())
            {
                entry.insert(feature.to_owned());
            }
        }
    }
    (packages, features)
}

/// Names and versions of the packages of `cargo tree --prefix none --format
/// {p}` output: one `name vVERSION (source)` per line, with `(*)` on repeated
/// ones and headers such as `[dev-dependencies]` skipped.
#[must_use]
pub fn parse_tree(output: &str) -> ActivePackages {
    parse_tree_features(output).0
}

/// The `cargo tree` arguments for `targets` (every platform when empty),
/// `features` (Cargo's defaults when `None`), `exclude_dev`,
/// `excluded_members`, and whether to root only at the root `[package]`
/// (`root_package_only`, unless `--exclude` requires `--workspace`).
#[must_use]
pub fn tree_args(
    targets: &[String],
    features: Option<&Features>,
    exclude_dev: bool,
    excluded_members: &[String],
    root_package_only: bool,
) -> Vec<String> {
    let mut args = vec!["tree".to_owned()];
    if !root_package_only || !excluded_members.is_empty() {
        args.push("--workspace".to_owned());
    }
    args.extend(
        [
            "--locked",
            "--color",
            "never",
            "--prefix",
            "none",
            "--format",
            "{p} [{f}]",
            "--edges",
        ]
        .iter()
        .map(|arg| (*arg).to_owned()),
    );
    args.push(
        if exclude_dev {
            "normal,build"
        } else {
            "normal,build,dev"
        }
        .to_owned(),
    );
    if targets.is_empty() {
        args.extend(["--target".to_owned(), "all".to_owned()]);
    }
    for target in targets {
        args.extend(["--target".to_owned(), target.clone()]);
    }
    args.extend(features.map(Features::cargo_args).unwrap_or_default());
    for member in excluded_members {
        args.extend(["--exclude".to_owned(), member.clone()]);
    }
    args
}

/// Workspace members with `publish = false` (or an empty `publish` list),
/// from `cargo metadata --no-deps`.
///
/// # Errors
///
/// Returns Cargo's explanation when it cannot read the workspace.
pub fn unpublished_members(root: &Path) -> Result<Vec<String>, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
        .current_dir(root)
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--locked",
            "--color",
            "never",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not run cargo: {error}"))?;
    if !output.status.success() {
        return Err("`cargo metadata --no-deps` failed".to_owned());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cargo metadata did not return JSON: {error}"))?;
    Ok(unpublished_in(&value))
}

/// Names of the packages whose `publish` is an empty list (`publish = false`).
fn unpublished_in(metadata: &serde_json::Value) -> Vec<String> {
    metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|package| {
            package
                .get("publish")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty)
        })
        .filter_map(|package| package.get("name").and_then(serde_json::Value::as_str))
        .map(str::to_owned)
        .collect()
}

/// Packages a build of the project at `root` uses for `targets` (every
/// platform when empty), with `features` (Cargo's defaults when `None`),
/// without the dev-dependencies of the project when `exclude_dev`.
///
/// # Errors
///
/// Returns Cargo's explanation when it cannot build the tree (sources not
/// downloaded, outdated lockfile, unknown target or feature).
pub fn active_packages(
    root: &Path,
    targets: &[String],
    features: Option<&Features>,
    exclude_dev: bool,
    excluded_members: &[String],
    root_package_only: bool,
) -> Result<(ActivePackages, EnabledFeatures), String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
        .current_dir(root)
        .args(tree_args(
            targets,
            features,
            exclude_dev,
            excluded_members,
            root_package_only,
        ))
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
            .unwrap_or("cargo tree failed");
        return Err(format!("`cargo tree`: {why}"));
    }
    let (packages, enabled_features) =
        parse_tree_features(&String::from_utf8_lossy(&output.stdout));
    if packages.is_empty() {
        return Err("`cargo tree` listed no package".to_owned());
    }
    Ok((packages, enabled_features))
}

#[cfg(test)]
mod tests {
    use super::{parse_tree, parse_tree_features, tree_args};
    use cargoscope_core::policy::Features;

    #[test]
    fn reads_the_packages_of_cargo_tree_output() {
        let output = "app v0.1.0 (/work/app) []\nserde v1.0.210 [alloc,default,derive,std]\nserde_derive v1.0.210 (proc-macro) [default]\nserde v1.0.210 [alloc,default,derive,std] (*)\n\n[dev-dependencies]\nwasi v0.11.0+wasi-snapshot-preview1\nforked v0.1.0 (https://github.com/x/forked?rev=abc#abc) [extra]\n";
        let (packages, features) = parse_tree_features(output);
        let found: Vec<(String, String)> = packages.into_iter().collect();
        let names: Vec<&str> = found.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            vec!["app", "forked", "serde", "serde_derive", "wasi"]
        );
        assert!(found.contains(&(
            "wasi".to_owned(),
            "0.11.0+wasi-snapshot-preview1".to_owned()
        )));
        assert_eq!(
            features[&("serde".to_owned(), "1.0.210".to_owned())]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["alloc", "default", "derive", "std"]
        );
        assert!(features[&("app".to_owned(), "0.1.0".to_owned())].is_empty());
        assert_eq!(
            features[&("forked".to_owned(), "0.1.0".to_owned())]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["extra"]
        );
        assert!(parse_tree("error: something\n").is_empty());
    }

    #[test]
    fn builds_the_cargo_tree_arguments() {
        let joined = |args: Vec<String>| args.join(" ");
        assert!(
            joined(tree_args(&[], None, false, &[], false))
                .ends_with("--format {p} [{f}] --edges normal,build,dev --target all")
        );
        assert!(
            joined(tree_args(&[], None, false, &["xtask".to_owned()], false))
                .ends_with("--target all --exclude xtask")
        );
        let root_only = joined(tree_args(&[], None, false, &[], true));
        assert!(
            root_only.starts_with("tree --locked") && !root_only.contains("--workspace"),
            "{root_only}"
        );
        let metadata = serde_json::json!({"packages": [
            {"name": "app", "publish": null},
            {"name": "xtask", "publish": []},
            {"name": "internal", "publish": ["my-registry"]}
        ]});
        assert_eq!(super::unpublished_in(&metadata), vec!["xtask"]);
        let features = Features {
            list: vec!["tls".to_owned()],
            all: false,
            no_default: true,
        };
        let args = joined(tree_args(
            &[
                "x86_64-unknown-linux-gnu".to_owned(),
                "aarch64-apple-darwin".to_owned(),
            ],
            Some(&features),
            true,
            &[],
            false,
        ));
        assert!(args.starts_with("tree --workspace --locked"), "{args}");
        assert!(args.ends_with("--edges normal,build --target x86_64-unknown-linux-gnu --target aarch64-apple-darwin --no-default-features --features tls"), "{args}");
    }
}
