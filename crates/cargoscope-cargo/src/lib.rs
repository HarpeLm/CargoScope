//! Cargo manifest and lockfile parsing.
//!
//! Files are read directly; this crate never invokes `cargo` or runs project code.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

use cargoscope_core::{Inventory, Package};

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

/// Reads a project's \`Cargo.lock\` and returns its resolved package inventory.
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
    let manifest_contents =
        fs::read_to_string(&manifest).map_err(|source| ScanError::ReadManifest {
            path: manifest.clone(),
            source,
        })?;
    let mut direct_dependencies =
        parse_manifest_dependencies(&manifest_contents).map_err(|source| {
            ScanError::ParseManifest {
                path: manifest.clone(),
                source,
            }
        })?;
    let workspace_members =
        parse_workspace_members(&manifest_contents).map_err(|source| ScanError::ParseManifest {
            path: manifest,
            source,
        })?;

    for member in workspace_members {
        let member_manifest = project_root.join(member).join("Cargo.toml");
        let member_contents =
            fs::read_to_string(&member_manifest).map_err(|source| ScanError::ReadManifest {
                path: member_manifest.clone(),
                source,
            })?;
        let member_dependencies =
            parse_manifest_dependencies(&member_contents).map_err(|source| {
                ScanError::ParseManifest {
                    path: member_manifest,
                    source,
                }
            })?;
        direct_dependencies.extend(member_dependencies);
    }

    let mut inventory = parse_cargo_lock(&contents);
    for package in &mut inventory.packages {
        package.direct = direct_dependencies.contains(&package.name);
    }
    Ok(inventory)
}

/// Parses the package sections of a Cargo lockfile.
///
/// CargoScope intentionally reads only package identity and source at this
/// stage; dependency edges are added in a later milestone.
pub fn parse_cargo_lock(contents: &str) -> Inventory {
    let mut packages = Vec::new();
    let mut current = None;

    for raw_line in contents.lines() {
        let line = raw_line.trim();

        if line == "[[package]]" {
            push_package(&mut packages, current.take());
            current = Some(PackageBuilder::default());
            continue;
        }

        let Some(package) = current.as_mut() else {
            continue;
        };

        if let Some(value) = quoted_value(line, "name") {
            package.name = Some(value);
        } else if let Some(value) = quoted_value(line, "version") {
            package.version = Some(value);
        } else if let Some(value) = quoted_value(line, "source") {
            package.source = Some(value);
        }
    }

    push_package(&mut packages, current);
    packages.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.version.cmp(&right.version))
    });

    Inventory { packages }
}

#[derive(Default)]
struct PackageBuilder {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
}

fn push_package(packages: &mut Vec<Package>, package: Option<PackageBuilder>) {
    let Some(PackageBuilder {
        name: Some(name),
        version: Some(version),
        source,
    }) = package
    else {
        return;
    };

    packages.push(Package {
        name,
        version,
        source,
        direct: false,
    });
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
    use super::{parse_cargo_lock, parse_manifest_dependencies, parse_workspace_members};
    use cargoscope_core::Package;

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
                    direct: false,
                },
                Package {
                    name: "zeta".to_owned(),
                    version: "2.0.0".to_owned(),
                    source: None,
                    direct: false,
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
}
