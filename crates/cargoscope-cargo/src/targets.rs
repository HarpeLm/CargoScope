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

type PackageKey = (String, String);
type DeadEdges = BTreeSet<(PackageKey, PackageKey)>;

fn parse_package_line(line: &str) -> Option<(PackageKey, Vec<String>)> {
    let mut words = line.split_whitespace();
    let name = words.next()?;
    let version = words.next().and_then(|word| word.strip_prefix('v'))?;
    if name.starts_with('[') || semver::Version::parse(version).is_err() {
        return None;
    }
    let key = (name.to_owned(), version.to_owned());
    let mut features = Vec::new();
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
            features.push(feature.to_owned());
        }
    }
    Some((key, features))
}

/// Names, versions and enabled features of `cargo tree --prefix none
/// --format "{p} [{f}]"` output (one `name vVERSION (source) [features]` per
/// line, with `(*)` on repeated ones and section headers such as
/// `[dev-dependencies]` skipped; lines without `[features]` are still read).
#[must_use]
pub fn parse_tree_features(output: &str) -> (ActivePackages, EnabledFeatures) {
    let mut packages = BTreeSet::new();
    let mut features: EnabledFeatures = BTreeMap::new();
    for line in output.lines() {
        let Some((key, line_features)) = parse_package_line(line) else {
            continue;
        };
        packages.insert(key.clone());
        features.entry(key).or_default().extend(line_features);
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

fn parse_depth_line(line: &str) -> Option<(usize, PackageKey, Vec<String>)> {
    let digits_len = line.bytes().take_while(u8::is_ascii_digit).count();
    if digits_len == 0 {
        return None;
    }
    let depth: usize = line[..digits_len].parse().ok()?;
    let (key, features) = parse_package_line(&line[digits_len..])?;
    Some((depth, key, features))
}

/// Filters `cargo tree --prefix depth --format "{p} [{f}]"` output by
/// pruning `excluded_members` and `dead_edges` only after Cargo has resolved
/// workspace features across all members. Falls back to [`parse_tree_features`]
/// when the output uses no depth prefixes.
fn filter_depth_tree(
    output: &str,
    excluded_members: &[String],
    dead_edges: &DeadEdges,
    only_root: Option<&str>,
) -> (bool, ActivePackages, EnabledFeatures) {
    let excluded: BTreeSet<&str> = excluded_members.iter().map(String::as_str).collect();
    let mut roots = BTreeSet::new();
    let mut edges: BTreeMap<PackageKey, BTreeSet<PackageKey>> = BTreeMap::new();
    let mut all_features: EnabledFeatures = BTreeMap::new();
    let mut stack: Vec<PackageKey> = Vec::new();
    let mut saw_depth_line = false;

    for line in output.lines() {
        let Some((depth, key, feats)) = parse_depth_line(line) else {
            continue;
        };
        saw_depth_line = true;
        all_features.entry(key.clone()).or_default().extend(feats);
        if depth == 0
            && !excluded.contains(key.0.as_str())
            && only_root.is_none_or(|root| root == key.0)
        {
            roots.insert(key.clone());
        }
        while stack.len() > depth {
            stack.pop();
        }
        if let Some(parent) = stack.last() {
            edges.entry(parent.clone()).or_default().insert(key.clone());
        }
        if stack.len() == depth {
            stack.push(key);
        }
    }

    if !saw_depth_line {
        let (mut packages, mut features) = parse_tree_features(output);
        if packages.is_empty() {
            return (false, packages, features);
        }
        if !excluded.is_empty() {
            packages.retain(|(name, _)| !excluded.contains(name.as_str()));
            features.retain(|(name, _), _| !excluded.contains(name.as_str()));
        }
        return (true, packages, features);
    }

    let mut visited = BTreeSet::new();
    let mut queue: Vec<PackageKey> = roots.into_iter().collect();
    while let Some(node) = queue.pop() {
        if !visited.insert(node.clone()) {
            continue;
        }
        if let Some(children) = edges.get(&node) {
            for next in children {
                if excluded.contains(next.0.as_str())
                    || dead_edges.contains(&(node.clone(), next.clone()))
                {
                    continue;
                }
                if !visited.contains(next) {
                    queue.push(next.clone());
                }
            }
        }
    }
    all_features.retain(|key, _| visited.contains(key));
    (true, visited, all_features)
}

/// The `cargo tree` arguments for `targets` (every platform when empty),
/// `features` (Cargo's defaults when `None`), `exclude_dev`, and whether to
/// root only at the root `[package]` (`root_package_only`).
///
/// Uses `--prefix depth` without `--exclude` so excluded workspace members
/// still participate in workspace feature unification before being pruned.
#[must_use]
pub fn tree_args(
    targets: &[String],
    features: Option<&Features>,
    exclude_dev: bool,
    root_package_only: bool,
) -> Vec<String> {
    let mut args = vec!["tree".to_owned()];
    if !root_package_only {
        args.push("--workspace".to_owned());
    }
    args.extend(
        [
            "--locked",
            "--color",
            "never",
            "--prefix",
            "depth",
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

fn is_impossible_cfg(target: &str) -> bool {
    let normalized: String = target
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    matches!(normalized.as_str(), "cfg(any())" | "cfg(not(all()))")
}

/// Dependency edges in `cargo metadata` whose matching `dep_kinds` are all
/// gated on an impossible target expression such as `cfg(any())`.
fn dead_edges_in(metadata: &serde_json::Value, exclude_dev: bool) -> DeadEdges {
    let mut keys: BTreeMap<&str, PackageKey> = BTreeMap::new();
    for package in metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let (Some(id), Some(name), Some(version)) = (
            package.get("id").and_then(serde_json::Value::as_str),
            package.get("name").and_then(serde_json::Value::as_str),
            package.get("version").and_then(serde_json::Value::as_str),
        ) {
            keys.insert(id, (name.to_owned(), version.to_owned()));
        }
    }
    let mut dead = BTreeSet::new();
    for node in metadata
        .get("resolve")
        .and_then(|resolve| resolve.get("nodes"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(parent) = node
            .get("id")
            .and_then(serde_json::Value::as_str)
            .and_then(|id| keys.get(id))
        else {
            continue;
        };
        for dep in node
            .get("deps")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(child) = dep
                .get("pkg")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| keys.get(id))
            else {
                continue;
            };
            let kinds: Vec<&serde_json::Value> = dep
                .get("dep_kinds")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter(|kind| {
                    !exclude_dev
                        || kind.get("kind").and_then(serde_json::Value::as_str) != Some("dev")
                })
                .collect();
            if !kinds.is_empty()
                && kinds.iter().all(|kind| {
                    kind.get("target")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(is_impossible_cfg)
                })
            {
                dead.insert((parent.clone(), child.clone()));
            }
        }
    }
    dead
}

fn dead_edges(cargo: &std::ffi::OsStr, root: &Path, exclude_dev: bool) -> DeadEdges {
    let Ok(output) = Command::new(cargo)
        .current_dir(root)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--color",
            "never",
        ])
        .stdin(Stdio::null())
        .output()
    else {
        return BTreeSet::new();
    };
    if !output.status.success() {
        return BTreeSet::new();
    }
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .map(|metadata| dead_edges_in(&metadata, exclude_dev))
        .unwrap_or_default()
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
        .args(tree_args(targets, features, exclude_dev, root_package_only))
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
    let dead = if targets.is_empty() {
        dead_edges(&cargo, root, exclude_dev)
    } else {
        BTreeSet::new()
    };
    // Without `--workspace`, `cargo tree` starts from every default member;
    // cargo-deny starts from the root package alone.
    let root_name = if root_package_only {
        std::fs::read_to_string(root.join("Cargo.toml"))
            .ok()
            .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
            .and_then(|manifest| {
                manifest
                    .get("package")?
                    .get("name")?
                    .as_str()
                    .map(str::to_owned)
            })
    } else {
        None
    };
    let (saw_any, packages, enabled_features) = filter_depth_tree(
        &String::from_utf8_lossy(&output.stdout),
        excluded_members,
        &dead,
        root_name.as_deref(),
    );
    if !saw_any {
        return Err("`cargo tree` listed no package".to_owned());
    }
    Ok((packages, enabled_features))
}

#[cfg(test)]
mod tests {
    use super::{dead_edges_in, filter_depth_tree, parse_tree, parse_tree_features, tree_args};
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
            joined(tree_args(&[], None, false, false)).ends_with(
                "--prefix depth --format {p} [{f}] --edges normal,build,dev --target all"
            )
        );
        let root_only = joined(tree_args(&[], None, false, true));
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
            false,
        ));
        assert!(args.starts_with("tree --workspace --locked"), "{args}");
        assert!(args.ends_with("--edges normal,build --target x86_64-unknown-linux-gnu --target aarch64-apple-darwin --no-default-features --features tls"), "{args}");
    }

    #[test]
    fn prunes_excluded_members_and_impossible_cfg_edges_after_unification() {
        let tree = "\
0example-app v0.1.0 (/work/examples/app) []
1example-only v1.0.0 []
1tower-http v0.7.1 (/work/tower-http) [default,full]
2async-compression v0.4.52 [zstd]
3zstd-sys v2.1.3 []
0tower-http v0.7.1 (/work/tower-http) [default,full] (*)
";
        let metadata = serde_json::json!({
            "packages": [
                {"id": "p#serde_core@1.0.229", "name": "serde_core", "version": "1.0.229"},
                {"id": "p#serde_derive@1.0.229", "name": "serde_derive", "version": "1.0.229"},
                {"id": "p#ok@1.0.0", "name": "ok", "version": "1.0.0"}
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "p#serde_core@1.0.229",
                        "deps": [
                            {"pkg": "p#serde_derive@1.0.229", "dep_kinds": [{"kind": null, "target": "cfg(any())"}]},
                            {"pkg": "p#ok@1.0.0", "dep_kinds": [{"kind": "dev", "target": "cfg(any())"}, {"kind": null, "target": null}]}
                        ]
                    }
                ]
            }
        });
        let dead = dead_edges_in(&metadata, false);
        assert!(dead.contains(&(
            ("serde_core".to_owned(), "1.0.229".to_owned()),
            ("serde_derive".to_owned(), "1.0.229".to_owned()),
        )));
        assert!(!dead.contains(&(
            ("serde_core".to_owned(), "1.0.229".to_owned()),
            ("ok".to_owned(), "1.0.0".to_owned()),
        )));

        let (saw_any, packages, features) =
            filter_depth_tree(tree, &["example-app".to_owned()], &dead, None);
        assert!(saw_any);
        let names: Vec<&str> = packages.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["async-compression", "tower-http", "zstd-sys"]);
        assert!(features[&("tower-http".to_owned(), "0.7.1".to_owned())].contains("full"));
        assert!(!features.contains_key(&("example-only".to_owned(), "1.0.0".to_owned())));

        // Rooted at the root package alone, other default members drop out
        // the same way.
        let (_, rooted, _) = filter_depth_tree(tree, &[], &dead, Some("tower-http"));
        assert_eq!(rooted, packages);
    }
}
