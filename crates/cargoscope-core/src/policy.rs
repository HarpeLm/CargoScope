//! Dependency policies (licenses, sources, banned crates), checked against
//! an inventory. Configured in `cargoscope.toml` (see docs/policy.md).

use std::collections::{BTreeMap, BTreeSet};

use crate::{Inventory, PackageInfo, license};

/// crates.io sources, accepted under the alias `crates.io`.
const CRATES_IO: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// What to do with a package whose license is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownLicense {
    /// Report it as a violation (default).
    #[default]
    Deny,
    /// Accept it.
    Allow,
}

/// A crate that must not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    /// Crate name.
    pub name: String,
    /// Optional version requirement; without one, every version is banned.
    pub version: Option<String>,
    /// Why it is banned.
    pub reason: String,
    /// Crates allowed to depend on it (cargo-deny's `wrappers`): the ban
    /// does not apply when every crate that depends on it is listed.
    pub wrappers: Vec<String>,
}

/// Enabled features of each `(name, version)` package in the active build graph.
pub type EnabledFeatures = BTreeMap<(String, String), BTreeSet<String>>;

/// Per-crate feature ban or allowlist (`[bans] features`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureBan {
    /// Crate name.
    pub name: String,
    /// Optional version requirement; without one, every version.
    pub version: Option<String>,
    /// Allowed features; when non-empty (or when `exact` is true), any other
    /// enabled feature is a violation.
    pub allow: Vec<String>,
    /// Banned features.
    pub deny: Vec<String>,
    /// Require the enabled features to match `allow` with nothing missing or
    /// extra.
    pub exact: bool,
    /// Why these features are restricted.
    pub reason: String,
}

/// Licenses allowed for one crate only (`[licenses] exceptions`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseException {
    /// Crate name.
    pub name: String,
    /// Optional version requirement; without one, every version.
    pub version: Option<String>,
    /// Licenses allowed for this crate, even when `deny` lists them.
    pub allow: Vec<String>,
    /// Why.
    pub reason: String,
}

/// The license of a crate whose metadata is wrong or missing
/// (`[licenses] clarify`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseClarification {
    /// Crate name.
    pub name: String,
    /// Optional version requirement; without one, every version.
    pub version: Option<String>,
    /// SPDX expression that replaces the crate's own.
    pub expression: String,
    /// Why, such as where the license was checked.
    pub reason: String,
}

/// Whether `version` matches an optional requirement (an unreadable
/// requirement or version matches, as for bans).
fn version_matches(requirement: Option<&str>, version: &str) -> bool {
    match requirement {
        None => true,
        Some(requirement) => match (
            semver::VersionReq::parse(requirement),
            semver::Version::parse(version),
        ) {
            (Ok(requirement), Ok(version)) => requirement.matches(&version),
            _ => true,
        },
    }
}

/// A dependency policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Allowed licenses; empty means any license that is not denied.
    pub allow_licenses: Vec<String>,
    /// Denied licenses.
    pub deny_licenses: Vec<String>,
    /// Treatment of unknown licenses.
    pub unknown_license: UnknownLicense,
    /// Whether license rules are configured at all.
    pub check_licenses: bool,
    /// Allowed registries (`crates.io` or a registry URL); `None` disables
    /// the source rule.
    pub allow_registries: Option<Vec<String>>,
    /// Allowed git repository URL prefixes.
    pub allow_git: Vec<String>,
    /// Banned crates.
    pub bans: Vec<Ban>,
    /// Licenses allowed for one crate only.
    pub license_exceptions: Vec<LicenseException>,
    /// Licenses declared for crates whose metadata is wrong or missing.
    pub license_clarifications: Vec<LicenseClarification>,
    /// Whether a crate resolved in several versions is a violation.
    pub deny_multiple_versions: bool,
    /// Crates allowed in several versions even when they are denied.
    pub skip_multiple_versions: Vec<String>,
    /// Crates whose duplicates are denied even when `deny_multiple_versions`
    /// is off (cargo-deny's `deny-multiple-versions` on a crate).
    pub deny_multiple_versions_of: Vec<String>,
    /// Crates whose whole dependency tree is allowed in several versions,
    /// with an optional depth (cargo-deny's `skip-tree`).
    pub skip_multiple_versions_trees: Vec<(String, Option<usize>)>,
    /// Target triples (`[graph] targets`) the rules are limited to: a package
    /// that no listed target builds is not checked. Empty checks every
    /// package of the lockfile.
    pub targets: Vec<String>,
    /// `[graph] exclude-dev`: packages only the project's dev-dependencies
    /// pull in are not checked.
    pub exclude_dev: bool,
    /// `[graph] exclude-unpublished`: workspace members with
    /// `publish = false` and what only they pull in are not checked.
    pub exclude_unpublished: bool,
    /// Whether duplicates pulled in only by dev-dependencies count for
    /// `multiple-versions` (cargo-deny's `multiple-versions-include-dev`,
    /// off by default there). `cargoscope.toml` counts them.
    pub duplicates_exclude_dev: bool,
    /// Whether licenses of packages pulled in only by dev-dependencies are
    /// left out (cargo-deny's `[licenses] include-dev`, off by default there).
    /// `cargoscope.toml` checks them.
    pub licenses_exclude_dev: bool,
    /// When the root `Cargo.toml` defines `[package]` alongside `[workspace]`,
    /// cargo-deny checks only the root package's graph (not `--workspace`).
    pub root_package_only: bool,
    /// Per-crate feature bans and allowlists (`[bans] features`).
    pub feature_bans: Vec<FeatureBan>,
    /// Features of the project (`[graph] features`, `all-features`,
    /// `no-default-features`) the rules are limited to; `None` checks the
    /// packages of every feature.
    pub features: Option<Features>,
}

/// The features the dependency graph is computed with, as Cargo's
/// `--features`, `--all-features` and `--no-default-features` flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Features {
    /// Features to enable (`member/feature` in a virtual workspace).
    pub list: Vec<String>,
    /// Enable every feature.
    pub all: bool,
    /// Disable the default features.
    pub no_default: bool,
}

impl Features {
    /// The matching `cargo` arguments.
    #[must_use]
    pub fn cargo_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.all {
            args.push("--all-features".to_owned());
        }
        if self.no_default {
            args.push("--no-default-features".to_owned());
        }
        if !self.list.is_empty() {
            args.push("--features".to_owned());
            args.push(self.list.join(","));
        }
        args
    }
}

/// Packages (name and version) in the dependency graph the policy's
/// `[graph]` selects (targets and features), as computed by `cargo metadata`.
pub type ActivePackages = BTreeSet<(String, String)>;

/// Rule a violation breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// License not allowed, denied or unknown.
    License,
    /// Package from a source that is not allowed.
    Source,
    /// Banned crate.
    Ban,
    /// Crate resolved in several versions.
    MultipleVersions,
}

impl Rule {
    /// Name used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::License => "license",
            Self::Source => "source",
            Self::Ban => "ban",
            Self::MultipleVersions => "multiple-versions",
        }
    }
}

/// A package that breaks the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Index of the package in [`Inventory::packages`].
    pub package: usize,
    /// Broken rule.
    pub rule: Rule,
    /// Explanation.
    pub message: String,
}

fn registry_allowed(source: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|entry| {
        if entry == "crates.io" {
            CRATES_IO.contains(&source)
        } else {
            let url = source
                .strip_prefix("registry+")
                .or_else(|| source.strip_prefix("sparse+"))
                .unwrap_or(source);
            url.trim_end_matches('/') == entry.trim_end_matches('/')
        }
    })
}

impl Policy {
    /// Checks every non-local package of `inventory`. `info` holds license
    /// data in inventory order; `licenses_known` says whether registry data
    /// was available at all (without it, license rules are skipped).
    #[must_use]
    pub fn check(
        &self,
        inventory: &Inventory,
        info: &[PackageInfo],
        licenses_known: bool,
    ) -> Vec<Violation> {
        self.check_scoped(inventory, info, licenses_known, None)
    }

    /// The clarification that applies to a package, if any.
    #[must_use]
    pub fn clarification(&self, name: &str, version: &str) -> Option<&LicenseClarification> {
        self.license_clarifications.iter().find(|clarification| {
            clarification.name == name && version_matches(clarification.version.as_deref(), version)
        })
    }

    /// Replaces the license of every clarified package in `info` (inventory
    /// order), so reports show the clarified license.
    pub fn clarify(&self, inventory: &Inventory, info: &mut [PackageInfo]) {
        for (package, info) in inventory.packages.iter().zip(info.iter_mut()) {
            if let Some(clarification) = self.clarification(&package.name, &package.version) {
                info.license = Some(clarification.expression.clone());
            }
        }
    }

    /// Names of the crates in the `skip_multiple_versions_trees`: the roots and
    /// their dependencies, down to the given depth.
    fn skipped_trees<'a>(&self, inventory: &'a Inventory) -> BTreeSet<&'a str> {
        let mut names = BTreeSet::new();
        for (root, depth) in &self.skip_multiple_versions_trees {
            let mut frontier: Vec<usize> = inventory
                .packages
                .iter()
                .enumerate()
                .filter(|(_, package)| &package.name == root)
                .map(|(index, _)| index)
                .collect();
            let mut seen: BTreeSet<usize> = frontier.iter().copied().collect();
            let mut level = 0;
            while !frontier.is_empty() {
                for &index in &frontier {
                    names.insert(inventory.packages[index].name.as_str());
                }
                if depth.is_some_and(|depth| level >= depth) {
                    break;
                }
                frontier = frontier
                    .iter()
                    .flat_map(|&index| inventory.packages[index].dependencies.iter().copied())
                    .filter(|next| seen.insert(*next))
                    .collect();
                level += 1;
            }
        }
        names
    }

    /// Warnings for license exceptions and clarifications that match no
    /// package of the inventory: they may be left over.
    #[must_use]
    pub fn unused_license_entries(&self, inventory: &Inventory) -> Vec<String> {
        let matches = |name: &str, version: Option<&str>| {
            inventory
                .packages
                .iter()
                .any(|package| package.name == name && version_matches(version, &package.version))
        };
        let label = |name: &str, version: Option<&str>| match version {
            Some(version) => format!("{name} {version}"),
            None => name.to_owned(),
        };
        let mut warnings = Vec::new();
        for exception in &self.license_exceptions {
            if !matches(&exception.name, exception.version.as_deref()) {
                warnings.push(format!(
                    "cargoscope.toml has a license exception for {}, which matches no package: remove it if it is no longer needed",
                    label(&exception.name, exception.version.as_deref())
                ));
            }
        }
        for clarification in &self.license_clarifications {
            if !matches(&clarification.name, clarification.version.as_deref()) {
                warnings.push(format!(
                    "cargoscope.toml clarifies the license of {}, which matches no package: remove it if it is no longer needed",
                    label(&clarification.name, clarification.version.as_deref())
                ));
            }
        }
        warnings
    }

    /// Like [`Policy::check`], limited to the packages in `active` (the ones
    /// the policy's `targets` build); `None` checks every package.
    #[must_use]
    pub fn check_scoped(
        &self,
        inventory: &Inventory,
        info: &[PackageInfo],
        licenses_known: bool,
        active: Option<&ActivePackages>,
    ) -> Vec<Violation> {
        self.check_graphs(inventory, info, licenses_known, active, active, None)
    }

    fn check_feature_bans(
        &self,
        package: &crate::Package,
        pkg_features: &BTreeSet<String>,
        push: &mut impl FnMut(Rule, String),
    ) {
        for ban in &self.feature_bans {
            if ban.name != package.name
                || !version_matches(ban.version.as_deref(), &package.version)
            {
                continue;
            }
            for denied in &ban.deny {
                if pkg_features.contains(denied) {
                    push(
                        Rule::Ban,
                        format!("feature `{denied}` is banned: {}", ban.reason),
                    );
                }
            }
            if !ban.allow.is_empty() || ban.exact {
                for enabled in pkg_features {
                    if !ban.deny.contains(enabled) && !ban.allow.contains(enabled) {
                        push(
                            Rule::Ban,
                            format!(
                                "feature `{enabled}` is not in the allow list: {}",
                                ban.reason
                            ),
                        );
                    }
                }
            }
            if ban.exact {
                for allowed in &ban.allow {
                    if !pkg_features.contains(allowed) && !ban.deny.contains(allowed) {
                        push(
                            Rule::Ban,
                            format!(
                                "exact feature set required, missing feature `{allowed}`: {}",
                                ban.reason
                            ),
                        );
                    }
                }
            }
        }
    }

    /// Like [`Policy::check_scoped`], with a separate non-dev package set
    /// (for `duplicates_exclude_dev` and `licenses_exclude_dev`) and enabled
    /// package features (for `[bans] features`).
    #[must_use]
    pub fn check_graphs(
        &self,
        inventory: &Inventory,
        info: &[PackageInfo],
        licenses_known: bool,
        active: Option<&ActivePackages>,
        non_dev_active: Option<&ActivePackages>,
        enabled_features: Option<&EnabledFeatures>,
    ) -> Vec<Violation> {
        let in_set = |set: Option<&ActivePackages>, index: usize| {
            set.is_none_or(|set| {
                let package = &inventory.packages[index];
                set.contains(&(package.name.clone(), package.version.clone()))
            })
        };
        let is_active = |index: usize| in_set(active, index);
        let licenses_set = if self.licenses_exclude_dev {
            non_dev_active
        } else {
            active
        };
        let duplicates_set = if self.duplicates_exclude_dev {
            non_dev_active
        } else {
            active
        };
        let empty_features = BTreeSet::new();
        let mut violations = Vec::new();
        for (index, package) in inventory.packages.iter().enumerate() {
            let Some(source) = package.source.as_deref() else {
                continue;
            };
            if !is_active(index) {
                continue;
            }
            let mut push = |rule, message: String| {
                violations.push(Violation {
                    package: index,
                    rule,
                    message,
                });
            };

            for ban in &self.bans {
                if ban.name != package.name {
                    continue;
                }
                if !ban.wrappers.is_empty() {
                    let mut dependents = inventory
                        .packages
                        .iter()
                        .filter(|parent| parent.dependencies.contains(&index))
                        .peekable();
                    if dependents.peek().is_some()
                        && dependents.all(|parent| ban.wrappers.contains(&parent.name))
                    {
                        continue;
                    }
                }
                if version_matches(ban.version.as_deref(), &package.version) {
                    let versions = ban
                        .version
                        .as_deref()
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default();
                    push(
                        Rule::Ban,
                        format!("`{}`{versions} is banned: {}", ban.name, ban.reason),
                    );
                }
            }

            if let Some(features_map) = enabled_features {
                let pkg_features = features_map
                    .get(&(package.name.clone(), package.version.clone()))
                    .unwrap_or(&empty_features);
                self.check_feature_bans(package, pkg_features, &mut push);
            }

            if let Some(allowed) = &self.allow_registries {
                if let Some(url) = source.strip_prefix("git+") {
                    if !self
                        .allow_git
                        .iter()
                        .any(|prefix| url.starts_with(prefix.as_str()))
                    {
                        let repository = url.split(['?', '#']).next().unwrap_or(url);
                        push(
                            Rule::Source,
                            format!("git source {repository} is not in [sources] allow-git"),
                        );
                    }
                } else if !registry_allowed(source, allowed) {
                    push(
                        Rule::Source,
                        format!("source {source} is not in [sources] allow-registries"),
                    );
                }
            }

            let clarified = self.clarification(&package.name, &package.version);
            if self.check_licenses
                && in_set(licenses_set, index)
                && (clarified.is_some() || (licenses_known && CRATES_IO.contains(&source)))
            {
                // A clarification replaces the crate's license; exceptions
                // allow more licenses for this crate only.
                let license = clarified
                    .map(|clarification| clarification.expression.as_str())
                    .or_else(|| info.get(index).and_then(|info| info.license.as_deref()));
                let excepted: Vec<&String> = self
                    .license_exceptions
                    .iter()
                    .filter(|exception| {
                        exception.name == package.name
                            && version_matches(exception.version.as_deref(), &package.version)
                    })
                    .flat_map(|exception| exception.allow.iter())
                    .collect();
                let mut allow = self.allow_licenses.clone();
                if !allow.is_empty() {
                    allow.extend(excepted.iter().map(|license| (*license).clone()));
                }
                let deny: Vec<String> = self
                    .deny_licenses
                    .iter()
                    .filter(|denied| {
                        !excepted
                            .iter()
                            .any(|license| license.eq_ignore_ascii_case(denied))
                    })
                    .cloned()
                    .collect();
                let note = if clarified.is_some() {
                    " (clarified in cargoscope.toml)"
                } else {
                    ""
                };
                match license {
                    None => {
                        if self.unknown_license == UnknownLicense::Deny {
                            push(
                                Rule::License,
                                "license is unknown (set `unknown = \"allow\"` to accept)"
                                    .to_owned(),
                            );
                        }
                    }
                    Some(expression) => match license::is_allowed(expression, &allow, &deny) {
                        Ok(true) => {}
                        Ok(false) => push(
                            Rule::License,
                            format!("license `{expression}`{note} is not allowed by the policy"),
                        ),
                        Err(error) => push(
                            Rule::License,
                            format!("license `{expression}` cannot be read: {error}"),
                        ),
                    },
                }
            }
        }
        if self.deny_multiple_versions || !self.deny_multiple_versions_of.is_empty() {
            let skipped_trees = self.skipped_trees(inventory);
            for (name, indices) in inventory.duplicates() {
                if (!self.deny_multiple_versions && !self.deny_multiple_versions_of.contains(&name))
                    || self.skip_multiple_versions.contains(&name)
                    || skipped_trees.contains(name.as_str())
                {
                    continue;
                }
                // Only the versions a target builds count as duplicates.
                let mut indices: Vec<usize> = indices
                    .into_iter()
                    .filter(|&i| in_set(duplicates_set, i))
                    .collect();
                if indices.len() > 1 {
                    // Ignore a version whose only active dependents are other
                    // versions of the same crate (semver trick), as cargo-deny does.
                    indices.retain(|&i| {
                        let mut has_dependent = false;
                        let mut all_same_crate = true;
                        for (parent_index, parent) in inventory.packages.iter().enumerate() {
                            if in_set(duplicates_set, parent_index)
                                && parent.dependencies.contains(&i)
                            {
                                has_dependent = true;
                                if parent.name != *name {
                                    all_same_crate = false;
                                    break;
                                }
                            }
                        }
                        !(has_dependent && all_same_crate)
                    });
                }
                let distinct: BTreeSet<&str> = indices
                    .iter()
                    .map(|&index| inventory.packages[index].version.as_str())
                    .collect();
                if distinct.len() < 2 {
                    continue;
                }
                let versions: Vec<&str> = indices
                    .iter()
                    .map(|&index| inventory.packages[index].version.as_str())
                    .collect();
                // Reported on the oldest version, the one to remove.
                violations.push(Violation {
                    package: indices[0],
                    rule: Rule::MultipleVersions,
                    message: format!(
                        "`{name}` is resolved in {} versions ({}); add it to [bans] skip-multiple-versions to accept",
                        versions.len(),
                        versions.join(", ")
                    ),
                });
            }
        }
        violations
    }
}

#[cfg(test)]
mod multiple_versions_tests {
    use super::{Policy, Rule};
    use crate::{Inventory, Package};

    #[test]
    fn denies_crates_in_several_versions_unless_skipped() {
        let package = |name: &str, version: &str, root: bool| Package {
            name: name.to_owned(),
            version: version.to_owned(),
            source: (!root)
                .then(|| "registry+https://github.com/rust-lang/crates.io-index".to_owned()),
            root,
            direct: false,
            dependencies: Vec::new(),
        };
        let inventory = Inventory {
            packages: vec![
                package("app", "0.1.0", true),
                package("syn", "1.0.109", false),
                package("syn", "2.0.87", false),
                package("windows-sys", "0.52.0", false),
                package("windows-sys", "0.59.0", false),
            ],
        };
        let mut policy = Policy::default();
        assert!(policy.check(&inventory, &[], false).is_empty());
        policy.deny_multiple_versions = true;
        policy.skip_multiple_versions = vec!["windows-sys".to_owned()];
        let violations = policy.check(&inventory, &[], false);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, Rule::MultipleVersions);
        assert_eq!(violations[0].package, 1);
        assert!(
            violations[0]
                .message
                .starts_with("`syn` is resolved in 2 versions (1.0.109, 2.0.87)")
        );

        // A version no target builds is not a duplicate.
        let active: super::ActivePackages = [("syn", "2.0.87"), ("windows-sys", "0.59.0")]
            .into_iter()
            .map(|(name, version)| (name.to_owned(), version.to_owned()))
            .collect();
        assert!(
            policy
                .check_scoped(&inventory, &[], false, Some(&active))
                .is_empty()
        );
    }

    #[test]
    fn multiple_versions_ignores_semver_trick_reexport() {
        let package = |name: &str, version: &str, root: bool, dependencies: Vec<usize>| Package {
            name: name.to_owned(),
            version: version.to_owned(),
            source: (!root)
                .then(|| "registry+https://github.com/rust-lang/crates.io-index".to_owned()),
            root,
            direct: false,
            dependencies,
        };
        // app (0) -> ndk-sys (1) -> jni-sys 0.3.1 (2) -> jni-sys 0.4.1 (3),
        // plus dev-only jni (4) -> jni-sys 0.4.1 (3).
        let inventory = Inventory {
            packages: vec![
                package("app", "0.1.0", true, vec![1, 4]),
                package("ndk-sys", "0.6.0", false, vec![2]),
                package("jni-sys", "0.3.1", false, vec![3]),
                package("jni-sys", "0.4.1", false, vec![]),
                package("jni", "0.22.4", false, vec![3]),
            ],
        };
        let mut policy = Policy {
            deny_multiple_versions: true,
            ..Default::default()
        };

        // With `jni` active, `jni-sys 0.4.1` has an external dependent -> duplicate reported.
        assert_eq!(policy.check(&inventory, &[], false).len(), 1);

        // When `jni` is excluded (`duplicates_exclude_dev = true`), `jni-sys 0.4.1` is
        // only depended on by `jni-sys 0.3.1` -> ignored as a semver-trick reexport.
        policy.duplicates_exclude_dev = true;
        let non_dev: super::ActivePackages = [
            ("app", "0.1.0"),
            ("ndk-sys", "0.6.0"),
            ("jni-sys", "0.3.1"),
            ("jni-sys", "0.4.1"),
        ]
        .into_iter()
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .collect();
        assert!(
            policy
                .check_graphs(&inventory, &[], false, None, Some(&non_dev), None)
                .is_empty()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{Ban, Policy, Rule, UnknownLicense};
    use crate::{Inventory, Package, PackageInfo};

    fn package(name: &str, version: &str, source: Option<&str>) -> Package {
        Package {
            name: name.to_owned(),
            version: version.to_owned(),
            source: source.map(str::to_owned),
            root: source.is_none(),
            direct: false,
            dependencies: Vec::new(),
        }
    }

    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn sample() -> (Inventory, Vec<PackageInfo>) {
        let inventory = Inventory {
            packages: vec![
                package("app", "0.1.0", None),
                package("good", "1.0.0", Some(CRATES_IO)),
                package("copyleft", "1.0.0", Some(CRATES_IO)),
                package("mystery", "1.0.0", Some(CRATES_IO)),
                package("openssl", "0.9.0", Some(CRATES_IO)),
                package(
                    "forked",
                    "0.1.0",
                    Some("git+https://github.com/someone/forked?rev=abc#abc"),
                ),
                package(
                    "private",
                    "1.0.0",
                    Some("registry+https://registry.example.com/index"),
                ),
            ],
        };
        let license = |text: &str| PackageInfo {
            license: Some(text.to_owned()),
            ..PackageInfo::default()
        };
        let info = vec![
            PackageInfo::default(),
            license("MIT OR Apache-2.0"),
            license("GPL-3.0-only"),
            PackageInfo::default(),
            license("Apache-2.0"),
            PackageInfo::default(),
            PackageInfo::default(),
        ];
        (inventory, info)
    }

    fn policy() -> Policy {
        Policy {
            allow_licenses: vec!["MIT".to_owned(), "Apache-2.0".to_owned()],
            deny_licenses: Vec::new(),
            unknown_license: UnknownLicense::Deny,
            check_licenses: true,
            allow_registries: Some(vec!["crates.io".to_owned()]),
            allow_git: vec!["https://github.com/myorg/".to_owned()],
            bans: vec![Ban {
                name: "openssl".to_owned(),
                version: Some("<0.10".to_owned()),
                reason: "use rustls".to_owned(),
                wrappers: Vec::new(),
            }],
            ..Policy::default()
        }
    }

    #[test]
    fn reports_each_rule() {
        let (inventory, info) = sample();
        let violations = policy().check(&inventory, &info, true);
        let found: Vec<(&str, Rule)> = violations
            .iter()
            .map(|violation| {
                (
                    inventory.packages[violation.package].name.as_str(),
                    violation.rule,
                )
            })
            .collect();
        assert_eq!(
            found,
            vec![
                ("copyleft", Rule::License),
                ("mystery", Rule::License),
                ("openssl", Rule::Ban),
                ("forked", Rule::Source),
                ("private", Rule::Source),
            ]
        );
        assert!(
            violations[3]
                .message
                .contains("https://github.com/someone/forked is not in")
        );
    }

    #[test]
    fn license_exceptions_and_clarifications_apply_to_one_crate() {
        use super::{LicenseClarification, LicenseException};
        let (inventory, mut info) = sample();
        let mut policy = Policy {
            deny_licenses: vec!["GPL-3.0-only".to_owned()],
            ..policy()
        };
        policy.bans.clear();
        policy.allow_registries = None;
        policy.license_exceptions = vec![LicenseException {
            name: "copyleft".to_owned(),
            version: Some("^1".to_owned()),
            allow: vec!["GPL-3.0-only".to_owned()],
            reason: "only used by a build tool".to_owned(),
        }];
        policy.license_clarifications = vec![
            LicenseClarification {
                name: "mystery".to_owned(),
                version: None,
                expression: "MIT".to_owned(),
                reason: "LICENSE file checked".to_owned(),
            },
            LicenseClarification {
                name: "openssl".to_owned(),
                version: Some("<0.9".to_owned()),
                expression: "OpenSSL".to_owned(),
                reason: "older versions only".to_owned(),
            },
        ];
        // The exception lifts both the allow list and the deny list for
        // copyleft only; the clarification gives mystery a known license.
        assert!(policy.check(&inventory, &info, true).is_empty());

        // An exception for another version no longer applies.
        policy.license_exceptions[0].version = Some("^2".to_owned());
        let violations = policy.check(&inventory, &info, true);
        assert_eq!(violations.len(), 1);
        assert_eq!(inventory.packages[violations[0].package].name, "copyleft");

        // A clarified license that is not allowed is reported as clarified,
        // even without registry data.
        policy.license_clarifications[0].expression = "BSL-1.0".to_owned();
        let violations = policy.check(&inventory, &info, false);
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0]
                .message
                .contains("`BSL-1.0` (clarified in cargoscope.toml) is not allowed")
        );

        policy.clarify(&inventory, &mut info);
        assert_eq!(info[3].license.as_deref(), Some("BSL-1.0"));
        assert_eq!(
            info[4].license.as_deref(),
            Some("Apache-2.0"),
            "0.9.0 is not < 0.9"
        );
        let warnings = policy.unused_license_entries(&inventory);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("license exception for copyleft ^2"));
        assert!(warnings[1].contains("clarifies the license of openssl <0.9"));
    }

    #[test]
    fn license_rules_wait_for_registry_data_and_bans_respect_versions() {
        let (mut inventory, info) = sample();
        let without_data = policy().check(&inventory, &info, false);
        assert!(
            without_data
                .iter()
                .all(|violation| violation.rule != Rule::License)
        );
        inventory.packages[4].version = "0.10.5".to_owned();
        let violations = policy().check(&inventory, &info, true);
        assert!(
            violations
                .iter()
                .all(|violation| violation.rule != Rule::Ban)
        );
    }

    #[test]
    fn rules_only_apply_to_packages_a_target_builds() {
        let (inventory, info) = sample();
        let everything = policy().check(&inventory, &info, true);
        assert_eq!(everything.len(), 5);

        // Only `good` and `openssl` are built for the target: the copyleft
        // and unknown licenses and both foreign sources are out of scope.
        let active: super::ActivePackages = [("good", "1.0.0"), ("openssl", "0.9.0")]
            .into_iter()
            .map(|(name, version)| (name.to_owned(), version.to_owned()))
            .collect();
        let scoped = policy().check_scoped(&inventory, &info, true, Some(&active));
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].rule, Rule::Ban);
        assert_eq!(inventory.packages[scoped[0].package].name, "openssl");

        let nothing = policy().check_scoped(&inventory, &info, true, Some(&Default::default()));
        assert!(nothing.is_empty());
    }

    #[test]
    fn feature_bans_enforce_deny_allow_and_exact() {
        let inventory = Inventory {
            packages: vec![
                package("app", "0.1.0", None),
                package("derive_more", "1.0.0", Some(CRATES_IO)),
                package("getrandom", "0.2.15", Some(CRATES_IO)),
            ],
        };
        let mut features = super::EnabledFeatures::new();
        features.insert(
            ("derive_more".to_owned(), "1.0.0".to_owned()),
            ["default", "error", "from"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        );
        features.insert(
            ("getrandom".to_owned(), "0.2.15".to_owned()),
            ["std"].into_iter().map(str::to_owned).collect(),
        );

        let policy = Policy {
            feature_bans: vec![
                super::FeatureBan {
                    name: "derive_more".to_owned(),
                    version: None,
                    allow: vec!["default".to_owned()],
                    deny: vec!["error".to_owned()],
                    exact: false,
                    reason: "keep errors minimal".to_owned(),
                },
                super::FeatureBan {
                    name: "getrandom".to_owned(),
                    version: Some("^0.2".to_owned()),
                    allow: vec!["std".to_owned(), "js".to_owned()],
                    deny: Vec::new(),
                    exact: true,
                    reason: "wasm needs js".to_owned(),
                },
            ],
            ..Default::default()
        };

        let violations = policy.check_graphs(&inventory, &[], false, None, None, Some(&features));
        assert_eq!(violations.len(), 3, "{violations:?}");
        assert!(
            violations
                .iter()
                .all(|violation| violation.rule == Rule::Ban)
        );
        assert!(violations[0].message.contains("feature `error` is banned"));
        assert!(
            violations[1]
                .message
                .contains("feature `from` is not in the allow list")
        );
        assert!(
            violations[2]
                .message
                .contains("exact feature set required, missing feature `js`")
        );
    }

    #[test]
    fn licenses_exclude_dev_skips_dev_only_packages() {
        let (inventory, info) = sample();
        let non_dev: super::ActivePackages = [("good", "1.0.0")]
            .into_iter()
            .map(|(name, version)| (name.to_owned(), version.to_owned()))
            .collect();
        let policy = Policy {
            check_licenses: true,
            allow_licenses: vec!["MIT".to_owned()],
            licenses_exclude_dev: true,
            ..Default::default()
        };

        // `copyleft` and `mystery` are not in `non_dev`, so licenses_exclude_dev skips them;
        // `good` (MIT) passes.
        assert!(
            policy
                .check_graphs(&inventory, &info, true, None, Some(&non_dev), None)
                .is_empty()
        );
    }
}
