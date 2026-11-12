//! Cargo manifest and lockfile parsing.
//!
//! Files are read directly; this crate never invokes `cargo` or runs project code.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

use cargoscope_core::{Inventory, Package, UnusedFinding};

pub mod locations;
pub mod unused;
pub mod workspace;

/// An error while reading or interpreting a Cargo project.
#[derive(Debug)]
pub enum ScanError {
    /// The target does not contain a lockfile.
    MissingLockfile { path: std::path::PathBuf },
    /// CargoScope could not read the lockfile.
    ReadLockfile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// CargoScope could not read the manifest.
    ReadManifest {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// CargoScope could not parse the manifest.
    ParseManifest {
        path: std::path::PathBuf,
        source: toml::de::Error,
    },
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLockfile { path } => {
                write!(formatter, "no Cargo.lock found at {}", path.display())
            }
            Self::ReadLockfile { path, source } => {
                write!(formatter, "could not read {}: {source}", path.display())
            }
            Self::ReadManifest { path, source } => {
                write!(formatter, "could not read {}: {source}", path.display())
            }
            Self::ParseManifest { path, source } => {
                write!(formatter, "could not parse {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingLockfile { .. } => None,
            Self::ReadLockfile { source, .. } => Some(source),
            Self::ReadManifest { source, .. } => Some(source),
            Self::ParseManifest { source, .. } => Some(source),
        }
    }
}

/// Reads a project's `Cargo.lock` and manifests and returns its resolved
/// package inventory, including dependency edges and root packages.
pub fn scan_cargo_project(project_root: &Path) -> Result<Inventory, ScanError> {
    let lockfile = project_root.join("Cargo.lock");

    if !lockfile.is_file() {
        return Err(ScanError::MissingLockfile { path: lockfile });
    }

    let contents = fs::read_to_string(&lockfile).map_err(|source| ScanError::ReadLockfile {
        path: lockfile,
        source,
    })?;

    let manifest = project_root.join("Cargo.toml");
    let manifest_contents = read_manifest(&manifest)?;
    let mut root_names = BTreeSet::new();
    root_names.extend(parse_package_name(&manifest_contents).map_err(|source| {
        ScanError::ParseManifest {
            path: manifest.clone(),
            source,
        }
    })?);
    let root_manifest: toml::Value =
        toml::from_str(&manifest_contents).map_err(|source| ScanError::ParseManifest {
            path: manifest,
            source,
        })?;
    let (workspace_members, _) = workspace::members(project_root, &root_manifest);

    for member in workspace_members {
        let member_manifest = project_root.join(member).join("Cargo.toml");
        let member_contents = read_manifest(&member_manifest)?;
        root_names.extend(parse_package_name(&member_contents).map_err(|source| {
            ScanError::ParseManifest {
                path: member_manifest,
                source,
            }
        })?);
    }

    let mut inventory = parse_cargo_lock(&contents);
    mark_roots(&mut inventory, &root_names);
    Ok(inventory)
}

/// Looks for likely-unused dependencies in the root package and explicit
/// workspace members of a project (SPEC.md section 5.2).
///
/// Returns the findings, sorted by package then dependency, and warnings.
pub fn find_unused(
    project_root: &Path,
    inventory: &Inventory,
) -> Result<(Vec<UnusedFinding>, Vec<String>), ScanError> {
    let root_manifest_path = project_root.join("Cargo.toml");
    let root_contents = read_manifest(&root_manifest_path)?;
    let parse = |path: &Path, contents: &str| {
        toml::from_str::<toml::Value>(contents).map_err(|source| ScanError::ParseManifest {
            path: path.to_path_buf(),
            source,
        })
    };
    let root_manifest = parse(&root_manifest_path, &root_contents)?;
    let workspace_dependencies = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"));

    let mut packages = Vec::new();
    if root_manifest.get("package").is_some() {
        packages.push((
            project_root.to_path_buf(),
            "Cargo.toml".to_owned(),
            root_manifest.clone(),
        ));
    }
    let (members, mut warnings) = workspace::members(project_root, &root_manifest);
    for member in members {
        let dir = project_root.join(&member);
        let path = dir.join("Cargo.toml");
        let manifest = parse(&path, &read_manifest(&path)?)?;
        if manifest.get("package").is_some() {
            packages.push((
                dir,
                format!("{}/Cargo.toml", member.trim_end_matches('/')),
                manifest,
            ));
        }
    }

    let mut workspace_macros = unused::WorkspaceMacros::default();
    for (dir, _, manifest) in &packages {
        if let Some(name) = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
        {
            let names = unused::macro_references(dir, manifest);
            if !names.is_empty() {
                workspace_macros
                    .macro_rules
                    .insert(name.replace('-', "_"), names);
            }
            if unused::is_proc_macro(manifest) {
                workspace_macros.proc_macros.insert(
                    name.replace('-', "_"),
                    unused::proc_macro_generated(dir, manifest),
                );
            }
        }
    }

    let mut findings = Vec::new();
    for (dir, label, manifest) in &packages {
        let name = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            .unwrap_or("unknown");
        let (mut package_findings, package_warnings) = unused::check_package(
            &unused::PackageToCheck {
                name,
                dir,
                manifest_label: label,
                manifest,
                workspace_root: project_root,
            },
            workspace_dependencies,
            inventory,
            &workspace_macros,
        );
        findings.append(&mut package_findings);
        warnings.extend(package_warnings);
    }
    Ok((findings, warnings))
}

fn read_manifest(path: &Path) -> Result<String, ScanError> {
    fs::read_to_string(path).map_err(|source| ScanError::ReadManifest {
        path: path.to_path_buf(),
        source,
    })
}

/// Marks root packages (local packages whose name is in `root_names`) and the
/// packages they depend on directly.
///
/// When no root name matches, local packages that nothing depends on are used
/// as roots, so paths can still be computed.
pub fn mark_roots(inventory: &mut Inventory, root_names: &BTreeSet<String>) {
    let mut has_root = false;
    for package in &mut inventory.packages {
        package.root = package.source.is_none() && root_names.contains(&package.name);
        has_root |= package.root;
    }

    if !has_root {
        let mut depended_on = vec![false; inventory.packages.len()];
        for package in &inventory.packages {
            for &dependency in &package.dependencies {
                depended_on[dependency] = true;
            }
        }
        for (package, depended_on) in inventory.packages.iter_mut().zip(depended_on) {
            package.root = package.source.is_none() && !depended_on;
        }
    }

    let mut direct = vec![false; inventory.packages.len()];
    for package in inventory.packages.iter().filter(|package| package.root) {
        for &dependency in &package.dependencies {
            direct[dependency] = true;
        }
    }
    for (package, direct) in inventory.packages.iter_mut().zip(direct) {
        package.direct = direct && !package.root;
    }
}

/// Parses the package sections of a Cargo lockfile, including dependency edges.
///
/// Dependency entries use Cargo's lockfile forms: `"name"`, `"name version"`
/// or `"name version (source)"`. Entries that match no package are ignored.
#[must_use]
pub fn parse_cargo_lock(contents: &str) -> Inventory {
    let mut builders = Vec::new();
    let mut current: Option<PackageBuilder> = None;
    let mut in_dependencies = false;

    for raw_line in contents.lines() {
        let line = raw_line.trim();

        if line.starts_with('[') && !in_dependencies {
            if let Some(package) = current.take() {
                builders.push(package);
            }
            if line == "[[package]]" {
                current = Some(PackageBuilder::default());
            }
            continue;
        }

        let Some(package) = current.as_mut() else {
            continue;
        };

        if in_dependencies {
            collect_quoted(line, &mut package.dependencies);
            if line.contains(']') {
                in_dependencies = false;
            }
        } else if let Some(rest) = line
            .strip_prefix("dependencies")
            .and_then(|rest| rest.trim_start().strip_prefix('='))
        {
            collect_quoted(rest, &mut package.dependencies);
            in_dependencies = !rest.contains(']');
        } else if let Some(value) = quoted_value(line, "name") {
            package.name = Some(value);
        } else if let Some(value) = quoted_value(line, "version") {
            package.version = Some(value);
        } else if let Some(value) = quoted_value(line, "source") {
            package.source = Some(value);
        }
    }

    if let Some(package) = current {
        builders.push(package);
    }

    let mut complete: Vec<(Package, Vec<String>)> = builders
        .into_iter()
        .filter_map(|builder| {
            Some((
                Package {
                    name: builder.name?,
                    version: builder.version?,
                    source: builder.source,
                    root: false,
                    direct: false,
                    dependencies: Vec::new(),
                },
                builder.dependencies,
            ))
        })
        .collect();
    complete.sort_by(|(left, _), (right, _)| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.version.cmp(&right.version))
    });

    let (mut packages, specs): (Vec<Package>, Vec<Vec<String>>) = complete.into_iter().unzip();
    for (index, specs) in specs.iter().enumerate() {
        let mut resolved: Vec<usize> = specs
            .iter()
            .filter_map(|spec| resolve_dependency(&packages, spec))
            .collect();
        resolved.sort_unstable();
        resolved.dedup();
        packages[index].dependencies = resolved;
    }

    Inventory { packages }
}

fn resolve_dependency(packages: &[Package], spec: &str) -> Option<usize> {
    let mut parts = spec.splitn(3, ' ');
    let name = parts.next()?;
    let version = parts.next();
    let source = parts
        .next()
        .and_then(|rest| rest.strip_prefix('('))
        .and_then(|rest| rest.strip_suffix(')'));

    let mut candidates = packages.iter().enumerate().filter(|(_, package)| {
        package.name == name
            && version.is_none_or(|version| package.version == version)
            && source.is_none_or(|source| package.source.as_deref() == Some(source))
    });
    let first = candidates.next()?.0;
    // An unqualified name must be unambiguous.
    candidates.next().is_none().then_some(first)
}

fn collect_quoted(text: &str, out: &mut Vec<String>) {
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            return;
        };
        out.push(after[..end].to_owned());
        rest = &after[end + 1..];
    }
}

#[derive(Default)]
struct PackageBuilder {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    dependencies: Vec<String>,
}

/// Returns the `[package]` name of a Cargo manifest, if it has one.
pub fn parse_package_name(contents: &str) -> Result<Option<String>, toml::de::Error> {
    let manifest: toml::Value = toml::from_str(contents)?;
    Ok(manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned))
}

/// Returns declared package names from dependency sections of a Cargo manifest.
pub fn parse_manifest_dependencies(contents: &str) -> Result<BTreeSet<String>, toml::de::Error> {
    let manifest: toml::Value = toml::from_str(contents)?;
    let mut dependencies = BTreeSet::new();

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(entries) = manifest.get(section).and_then(toml::Value::as_table) else {
            continue;
        };

        for (declared_name, specification) in entries {
            let package_name = specification
                .as_table()
                .and_then(|table| table.get("package"))
                .and_then(toml::Value::as_str)
                .unwrap_or(declared_name);
            dependencies.insert(package_name.to_owned());
        }
    }

    Ok(dependencies)
}

/// Returns explicit workspace member paths from a Cargo manifest.
///
/// Glob patterns are ignored until workspace discovery gains filesystem
/// expansion and exclusion support.
pub fn parse_workspace_members(contents: &str) -> Result<Vec<String>, toml::de::Error> {
    let manifest: toml::Value = toml::from_str(contents)?;
    let Some(members) = manifest
        .get("workspace")
        .and_then(toml::Value::as_table)
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
    else {
        return Ok(Vec::new());
    };

    Ok(members
        .iter()
        .filter_map(toml::Value::as_str)
        .filter(|member| !member.contains('*') && !member.contains('?') && !member.contains('['))
        .map(str::to_owned)
        .collect())
}

fn quoted_value(line: &str, key: &str) -> Option<String> {
    let remainder = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    let value = remainder.strip_prefix('"')?.strip_suffix('"')?;
    Some(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        mark_roots, parse_cargo_lock, parse_manifest_dependencies, parse_package_name,
        parse_workspace_members,
    };
    use cargoscope_core::Package;
    use std::collections::BTreeSet;

    #[test]
    fn parses_and_sorts_resolved_packages() {
        let inventory = parse_cargo_lock(
            r#"
                version = 4

                [[package]]
                name = "zeta"
                version = "2.0.0"

                [[package]]
                name = "alpha"
                version = "1.0.0"
                source = "registry+https://github.com/rust-lang/crates.io-index"
            "#,
        );

        assert_eq!(
            inventory.packages,
            vec![
                Package {
                    name: "alpha".to_owned(),
                    version: "1.0.0".to_owned(),
                    source: Some(
                        "registry+https://github.com/rust-lang/crates.io-index".to_owned()
                    ),
                    root: false,
                    direct: false,
                    dependencies: vec![],
                },
                Package {
                    name: "zeta".to_owned(),
                    version: "2.0.0".to_owned(),
                    source: None,
                    root: false,
                    direct: false,
                    dependencies: vec![],
                },
            ]
        );
    }

    #[test]
    fn ignores_incomplete_package_sections() {
        let inventory = parse_cargo_lock(
            r#"
                [[package]]
                name = "incomplete"

                [[package]]
                name = "complete"
                version = "1.0.0"
            "#,
        );

        assert_eq!(inventory.packages.len(), 1);
        assert_eq!(inventory.packages[0].name, "complete");
    }

    #[test]
    fn identifies_normal_dev_build_and_renamed_dependencies() {
        let dependencies = parse_manifest_dependencies(
            r#"
                [dependencies]
                serde = "1"
                serde_json = { package = "serde_json", version = "1" }

                [dev-dependencies]
                insta = "1"

                [build-dependencies]
                renamed = { package = "real-package", version = "1" }
            "#,
        )
        .expect("manifest is valid TOML");

        assert_eq!(
            dependencies.into_iter().collect::<Vec<_>>(),
            vec!["insta", "real-package", "serde", "serde_json"]
        );
    }

    #[test]
    fn identifies_explicit_workspace_members() {
        let members = parse_workspace_members(
            r#"
                [workspace]
                members = ["crates/core", "crates/cli", "crates/*"]
            "#,
        )
        .expect("manifest is valid TOML");

        assert_eq!(members, vec!["crates/core", "crates/cli"]);
    }

    #[test]
    fn resolves_plain_versioned_and_sourced_dependency_entries() {
        let inventory = parse_cargo_lock(
            r#"
                version = 4

                [[package]]
                name = "app"
                version = "0.1.0"
                dependencies = [
                 "bitflags 1.3.2",
                 "bitflags 2.6.0 (registry+https://github.com/rust-lang/crates.io-index)",
                 "log",
                 "missing",
                ]

                [[package]]
                name = "bitflags"
                version = "1.3.2"
                source = "registry+https://github.com/rust-lang/crates.io-index"

                [[package]]
                name = "bitflags"
                version = "2.6.0"
                source = "registry+https://github.com/rust-lang/crates.io-index"

                [[package]]
                name = "log"
                version = "0.4.22"
                source = "registry+https://github.com/rust-lang/crates.io-index"

                [metadata]
                ignored = "yes"
            "#,
        );

        let names: Vec<String> = inventory
            .packages
            .iter()
            .map(|package| format!("{} {}", package.name, package.version))
            .collect();
        assert_eq!(
            names,
            vec![
                "app 0.1.0",
                "bitflags 1.3.2",
                "bitflags 2.6.0",
                "log 0.4.22"
            ]
        );
        assert_eq!(inventory.packages[0].dependencies, vec![1, 2, 3]);
    }

    #[test]
    fn ambiguous_unqualified_dependency_is_not_resolved() {
        let inventory = parse_cargo_lock(
            r#"
                [[package]]
                name = "app"
                version = "0.1.0"
                dependencies = ["dup"]

                [[package]]
                name = "dup"
                version = "1.0.0"

                [[package]]
                name = "dup"
                version = "2.0.0"
            "#,
        );
        assert!(inventory.packages[0].dependencies.is_empty());
    }

    #[test]
    fn marks_roots_by_name_and_their_direct_dependencies() {
        let mut inventory = parse_cargo_lock(
            r#"
                [[package]]
                name = "app"
                version = "0.1.0"
                dependencies = ["lib"]

                [[package]]
                name = "deep"
                version = "1.0.0"
                source = "registry+https://example.test"

                [[package]]
                name = "lib"
                version = "1.0.0"
                source = "registry+https://example.test"
                dependencies = ["deep"]
            "#,
        );
        mark_roots(&mut inventory, &BTreeSet::from(["app".to_owned()]));

        let flags: Vec<(bool, bool)> = inventory
            .packages
            .iter()
            .map(|package| (package.root, package.direct))
            .collect();
        assert_eq!(flags, vec![(true, false), (false, false), (false, true)]);
        assert_eq!(inventory.path_to(1), Some(vec![0, 2, 1]));
    }

    #[test]
    fn falls_back_to_unreferenced_local_packages_as_roots() {
        let mut inventory = parse_cargo_lock(
            r#"
                [[package]]
                name = "app"
                version = "0.1.0"
                dependencies = ["lib"]

                [[package]]
                name = "lib"
                version = "1.0.0"
                source = "registry+https://example.test"
            "#,
        );
        mark_roots(&mut inventory, &BTreeSet::new());
        assert!(inventory.packages[0].root);
        assert!(inventory.packages[1].direct);
    }

    #[test]
    fn reads_package_name() {
        assert_eq!(
            parse_package_name("[package]\nname = \"demo\"\n").expect("valid"),
            Some("demo".to_owned())
        );
        assert_eq!(parse_package_name("[workspace]\n").expect("valid"), None);
    }
}
