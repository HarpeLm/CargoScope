//! Dependency policies (licenses, sources, banned crates), checked against
//! an inventory. Configured in `cargoscope.toml` (see docs/policy.md).

use std::collections::{BTreeMap, BTreeSet};

use crate::{Inventory, PackageInfo, license};

/// crates.io sources, accepted under the alias `crates.io`.
const CRATES_IO: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// Enforcement level for a configurable policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LintLevel {
    /// Accept without a violation.
    #[default]
    Allow,
    /// Emit a warning violation without failing the scan.
    Warn,
    /// Emit an error violation that fails the scan.
    Deny,
}

impl LintLevel {
    fn to_violation_level(self) -> Option<ViolationLevel> {
        match self {
            Self::Allow => None,
            Self::Warn => Some(ViolationLevel::Warning),
            Self::Deny => Some(ViolationLevel::Error),
        }
    }
}

/// Severity of a policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ViolationLevel {
    /// Fails the scan (default).
    #[default]
    Error,
    /// Reported without failing the scan.
    Warning,
}

impl ViolationLevel {
    /// Level name used in JSON and SARIF reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

/// What to do with a package whose license is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownLicense {
    /// Report it as a violation (default).
    #[default]
    Deny,
    /// Accept it.
    Allow,
}

/// A crate allowed to run a custom `build.rs` script (`[bans.build]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildScriptAllow {
    /// Crate name.
    pub name: String,
    /// Optional version requirement; without one, every version is allowed.
    pub version: Option<String>,
}

/// Expected file path and optional 32-bit xxHash checksum under a crate's
/// source directory (`[licenses] clarify.license-files`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseFileHash {
    /// Path relative to the crate root (e.g. `LICENSE`).
    pub path: String,
    /// Expected 32-bit xxHash checksum (seed `0`, `\r\n` normalized to `\n`),
    /// matching cargo-deny. `None` checks only that the file exists.
    pub hash: Option<u32>,
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
    /// License files and checksums that must match before applying the
    /// clarification; empty skips disk verification.
    pub license_files: Vec<LicenseFileHash>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Enforcement level for packages from unlisted registries.
    pub registry_source_level: LintLevel,
    /// Enforcement level for packages from unlisted git repositories.
    pub git_source_level: LintLevel,
    /// Banned crates.
    pub bans: Vec<Ban>,
    /// Allowed crates with custom build scripts (`[bans.build] allow-build-scripts`).
    /// `None` disables build-script checking; `Some(vec![])` forbids all build scripts.
    pub allow_build_scripts: Option<Vec<BuildScriptAllow>>,
    /// Whether `[bans.build]` also checks workspace members (off by default).
    pub build_include_workspace: bool,
    /// Licenses allowed for one crate only.
    pub license_exceptions: Vec<LicenseException>,
    /// Licenses declared for crates whose metadata is wrong or missing.
    pub license_clarifications: Vec<LicenseClarification>,
    /// Enforcement level for crates resolved in several versions.
    pub multiple_versions: LintLevel,
    /// Crates allowed in several versions even when they are flagged.
    pub skip_multiple_versions: Vec<String>,
    /// Crates whose duplicates are denied even when `multiple_versions`
    /// is not `Deny` (cargo-deny's `deny-multiple-versions` on a crate).
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
    /// Whether the licenses of the project's own packages (workspace members
    /// and path dependencies) are checked too, as cargo-deny does.
    pub licenses_include_workspace: bool,
    /// `[licenses.private] ignore`: skip the licenses of unpublished packages
    /// (`publish = false`, or published only to `private_registries`).
    pub private_ignore: bool,
    /// `[licenses.private] registries`: registries counted as private.
    pub private_registries: Vec<String>,
    /// `[licenses.private] ignore-sources`: registry URLs whose packages'
    /// licenses are not checked (with `private_ignore`).
    pub private_ignore_sources: Vec<String>,
    /// Minimum score (in thousandths) for a license text found in a
    /// `LICENSE*`/`COPYING*` file to count, when a package declares no
    /// usable license expression (`confidence-threshold`, 0.8 by default).
    pub confidence_threshold: u16,
    /// Level of the finding for allowed licenses no checked package uses.
    pub unused_allowed_license: LintLevel,
    /// Whether an empty `allow_licenses` rejects every license (cargo-deny)
    /// instead of accepting any license that is not denied.
    pub empty_allow_denies_all: bool,
    /// Features of the project (`[graph] features`, `all-features`,
    /// `no-default-features`) the rules are limited to; `None` checks the
    /// packages of every feature.
    pub features: Option<Features>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_licenses: Vec::new(),
            deny_licenses: Vec::new(),
            unknown_license: UnknownLicense::default(),
            check_licenses: false,
            allow_registries: None,
            allow_git: Vec::new(),
            registry_source_level: LintLevel::Deny,
            git_source_level: LintLevel::Deny,
            bans: Vec::new(),
            allow_build_scripts: None,
            build_include_workspace: false,
            license_exceptions: Vec::new(),
            license_clarifications: Vec::new(),
            multiple_versions: LintLevel::Allow,
            skip_multiple_versions: Vec::new(),
            deny_multiple_versions_of: Vec::new(),
            skip_multiple_versions_trees: Vec::new(),
            targets: Vec::new(),
            exclude_dev: false,
            exclude_unpublished: false,
            duplicates_exclude_dev: false,
            licenses_exclude_dev: false,
            root_package_only: false,
            feature_bans: Vec::new(),
            features: None,
            licenses_include_workspace: false,
            private_ignore: false,
            private_registries: Vec::new(),
            private_ignore_sources: Vec::new(),
            confidence_threshold: 800,
            unused_allowed_license: LintLevel::Allow,
            empty_allow_denies_all: false,
        }
    }
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

/// Resolved dependency graph and on-disk package facts passed to
/// [`Policy::check_with_context`].
#[derive(Debug, Clone, Default)]
pub struct GraphContext<'a> {
    /// Packages in the active dependency graph (`[graph]` targets/features/exclude-dev).
    pub active: Option<&'a ActivePackages>,
    /// Non-dev packages in the active dependency graph.
    pub non_dev_active: Option<&'a ActivePackages>,
    /// Enabled features per `(name, version)` package.
    pub enabled_features: Option<&'a EnabledFeatures>,
    /// Packages `(name, version)` whose unpacked source declares a custom `build.rs` script.
    pub build_scripts: Option<&'a ActivePackages>,
    /// Verified clarification index (into [`Policy::license_clarifications`])
    /// per package in `inventory` order.
    pub verified_clarifications: Option<&'a [Option<usize>]>,
    /// License facts gathered from disk, per package in `inventory` order.
    pub license_facts: Option<&'a [LicenseFacts]>,
}

/// What the scan found on disk about the license of one package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LicenseFacts {
    /// The license in [`PackageInfo::license`] comes from the package itself
    /// (its manifest or its license files): check it even without crates.io
    /// data. With no license, the package is unlicensed.
    pub known: bool,
    /// Leave the package's license unchecked (`[licenses.private] ignore`).
    pub skip: bool,
    /// Where the license was found, when it was not the `license` field
    /// (for example "detected in LICENSE-MIT").
    pub origin: Option<String>,
}

/// A package that breaks the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Index of the package in [`Inventory::packages`].
    pub package: usize,
    /// Broken rule.
    pub rule: Rule,
    /// Severity level (`Error` or `Warning`).
    pub level: ViolationLevel,
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

    /// Replaces the license of each package whose clarification was verified
    /// against disk license files (where `verified[index]` holds the index
    /// into [`Self::license_clarifications`]).
    pub fn clarify_verified(
        &self,
        inventory: &Inventory,
        info: &mut [PackageInfo],
        verified: &[Option<usize>],
    ) {
        for ((index, _), info) in inventory.packages.iter().enumerate().zip(info.iter_mut()) {
            if let Some(clarification) = verified
                .get(index)
                .copied()
                .flatten()
                .and_then(|clarify_idx| self.license_clarifications.get(clarify_idx))
            {
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
        push: &mut impl FnMut(Rule, ViolationLevel, String),
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
                        ViolationLevel::Error,
                        format!("feature `{denied}` is banned: {}", ban.reason),
                    );
                }
            }
            if !ban.allow.is_empty() || ban.exact {
                for enabled in pkg_features {
                    if !ban.deny.contains(enabled) && !ban.allow.contains(enabled) {
                        push(
                            Rule::Ban,
                            ViolationLevel::Error,
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
                            ViolationLevel::Error,
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
        self.check_with_context(
            inventory,
            info,
            licenses_known,
            &GraphContext {
                active,
                non_dev_active,
                enabled_features,
                build_scripts: None,
                verified_clarifications: None,
                license_facts: None,
            },
        )
    }

    /// Checks `inventory` using the full [`GraphContext`] (active sets, enabled
    /// features, detected custom build scripts and verified clarifications).
    #[must_use]
    pub fn check_with_context(
        &self,
        inventory: &Inventory,
        info: &[PackageInfo],
        licenses_known: bool,
        context: &GraphContext<'_>,
    ) -> Vec<Violation> {
        let in_set = |set: Option<&ActivePackages>, index: usize| {
            set.is_none_or(|set| {
                let package = &inventory.packages[index];
                set.contains(&(package.name.clone(), package.version.clone()))
            })
        };
        let is_active = |index: usize| in_set(context.active, index);
        let licenses_set = if self.licenses_exclude_dev {
            context.non_dev_active
        } else {
            context.active
        };
        let duplicates_set = if self.duplicates_exclude_dev {
            context.non_dev_active
        } else {
            context.active
        };
        let empty_features = BTreeSet::new();
        let mut violations = Vec::new();
        let mut used_licenses: BTreeSet<String> = BTreeSet::new();
        for (index, package) in inventory.packages.iter().enumerate() {
            if !is_active(index) {
                continue;
            }
            let mut push = |rule, level, message: String| {
                violations.push(Violation {
                    package: index,
                    rule,
                    level,
                    message,
                });
            };

            if let Some(allowed) = &self.allow_build_scripts
                && (!package.root || self.build_include_workspace)
                && let Some(scripts) = context.build_scripts
                && scripts.contains(&(package.name.clone(), package.version.clone()))
            {
                let is_allowed = allowed.iter().any(|entry| {
                    entry.name == package.name
                        && version_matches(entry.version.as_deref(), &package.version)
                });
                if !is_allowed {
                    push(
                        Rule::Ban,
                        ViolationLevel::Error,
                        format!(
                            "build script of `{}` is not in [bans.build] allow-build-scripts",
                            package.name
                        ),
                    );
                }
            }

            let clarified = match context.verified_clarifications {
                Some(verified) => verified
                    .get(index)
                    .copied()
                    .flatten()
                    .and_then(|clarify_idx| self.license_clarifications.get(clarify_idx)),
                None => self.clarification(&package.name, &package.version),
            };
            let facts = context.license_facts.and_then(|facts| facts.get(index));
            let local = package.source.is_none();
            let has_data = clarified.is_some()
                || facts.is_some_and(|facts| facts.known)
                || (licenses_known
                    && package
                        .source
                        .as_deref()
                        .is_some_and(|source| CRATES_IO.contains(&source)));
            if self.check_licenses
                && in_set(licenses_set, index)
                && (!local || self.licenses_include_workspace)
                && !facts.is_some_and(|facts| facts.skip)
                && has_data
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
                if !allow.is_empty() || self.empty_allow_denies_all {
                    allow.extend(excepted.iter().map(|license| (*license).clone()));
                }
                let rejects_all = allow.is_empty() && self.empty_allow_denies_all;
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
                    " (clarified in cargoscope.toml)".to_owned()
                } else {
                    facts
                        .and_then(|facts| facts.origin.as_deref())
                        .map(|origin| format!(" ({origin})"))
                        .unwrap_or_default()
                };
                match license {
                    None => {
                        if self.unknown_license == UnknownLicense::Deny {
                            push(
                                Rule::License,
                                ViolationLevel::Error,
                                "license is unknown (set `unknown = \"allow\"` to accept)"
                                    .to_owned(),
                            );
                        }
                    }
                    Some(expression) => {
                        // An allowed license counts as used when it appears in
                        // a checked expression, unless the crate's own
                        // exception covers it (as in cargo-deny).
                        for id in license::ids(expression) {
                            let base = id.strip_suffix('+').unwrap_or(&id);
                            if !excepted
                                .iter()
                                .any(|license| license.eq_ignore_ascii_case(base))
                            {
                                used_licenses.insert(base.to_ascii_lowercase());
                            }
                        }
                        match license::is_allowed(expression, &allow, &deny) {
                            Ok(true) if !rejects_all => {}
                            Ok(_) => push(
                                Rule::License,
                                ViolationLevel::Error,
                                format!(
                                    "license `{expression}`{note} is not allowed by the policy"
                                ),
                            ),
                            Err(error) => push(
                                Rule::License,
                                ViolationLevel::Error,
                                format!("license `{expression}` cannot be read: {error}"),
                            ),
                        }
                    }
                }
            }

            let Some(source) = package.source.as_deref() else {
                continue;
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
                        ViolationLevel::Error,
                        format!("`{}`{versions} is banned: {}", ban.name, ban.reason),
                    );
                }
            }

            if let Some(features_map) = context.enabled_features {
                let pkg_features = features_map
                    .get(&(package.name.clone(), package.version.clone()))
                    .unwrap_or(&empty_features);
                self.check_feature_bans(package, pkg_features, &mut push);
            }

            if let Some(allowed) = &self.allow_registries {
                if let Some(url) = source.strip_prefix("git+") {
                    if let Some(level) = self.git_source_level.to_violation_level()
                        && !self
                            .allow_git
                            .iter()
                            .any(|prefix| url.starts_with(prefix.as_str()))
                    {
                        let repository = url.split(['?', '#']).next().unwrap_or(url);
                        push(
                            Rule::Source,
                            level,
                            format!("git source {repository} is not in [sources] allow-git"),
                        );
                    }
                } else if let Some(level) = self.registry_source_level.to_violation_level()
                    && !registry_allowed(source, allowed)
                {
                    push(
                        Rule::Source,
                        level,
                        format!("source {source} is not in [sources] allow-registries"),
                    );
                }
            }
        }
        if self.check_licenses
            && licenses_known
            && let Some(level) = self.unused_allowed_license.to_violation_level()
        {
            // Attached to the project itself: no package is at fault.
            let project = inventory
                .packages
                .iter()
                .position(|package| package.root)
                .unwrap_or(0);
            for allowed in &self.allow_licenses {
                if !used_licenses.contains(&allowed.to_ascii_lowercase())
                    && project < inventory.packages.len()
                {
                    violations.push(Violation {
                        package: project,
                        rule: Rule::License,
                        level,
                        message: format!(
                            "license `{allowed}` is allowed but no checked package uses it (unused-allowed-license)"
                        ),
                    });
                }
            }
        }
        let default_mv_level = self.multiple_versions.to_violation_level();
        if default_mv_level.is_some() || !self.deny_multiple_versions_of.is_empty() {
            let skipped_trees = self.skipped_trees(inventory);
            for (name, indices) in inventory.duplicates() {
                let level = if self.deny_multiple_versions_of.contains(&name) {
                    ViolationLevel::Error
                } else if let Some(level) = default_mv_level {
                    level
                } else {
                    continue;
                };
                if self.skip_multiple_versions.contains(&name)
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
                    level,
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
        policy.multiple_versions = super::LintLevel::Deny;
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
            multiple_versions: super::LintLevel::Deny,
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
    fn workspace_licenses_private_crates_facts_and_unused_allowed_licenses() {
        use super::{GraphContext, LicenseFacts, LintLevel, Violation, ViolationLevel};
        let (inventory, mut info) = sample();
        let mut policy = policy();
        policy.bans.clear();
        policy.allow_registries = None;
        policy.allow_licenses.push("ISC".to_owned());
        policy.unknown_license = UnknownLicense::Allow;
        info[2] = PackageInfo::default();
        // `app` (the project) is unlicensed: checked only with include-workspace.
        let names = |violations: &[Violation]| -> Vec<String> {
            violations
                .iter()
                .map(|v| format!("{}: {}", inventory.packages[v.package].name, v.message))
                .collect()
        };
        let mut facts = vec![LicenseFacts::default(); inventory.packages.len()];
        facts[0] = LicenseFacts {
            known: true,
            ..LicenseFacts::default()
        };
        // `forked` comes from git: its license was read from its manifest.
        info[5].license = Some("GPL-2.0-only".to_owned());
        facts[5] = LicenseFacts {
            known: true,
            skip: false,
            origin: Some("detected in LICENSE".to_owned()),
        };
        let context = GraphContext {
            license_facts: Some(&facts),
            ..GraphContext::default()
        };
        assert_eq!(
            names(&policy.check_with_context(&inventory, &info, true, &context)),
            vec![
                "forked: license `GPL-2.0-only` (detected in LICENSE) is not allowed by the policy"
            ]
        );

        policy.unknown_license = UnknownLicense::Deny;
        policy.licenses_include_workspace = true;
        policy.unused_allowed_license = LintLevel::Warn;
        facts[5].skip = true;
        let context = GraphContext {
            license_facts: Some(&facts),
            ..GraphContext::default()
        };
        let violations = policy.check_with_context(&inventory, &info, true, &context);
        assert_eq!(
            names(&violations),
            vec![
                "app: license is unknown (set `unknown = \"allow\"` to accept)",
                "copyleft: license is unknown (set `unknown = \"allow\"` to accept)",
                "mystery: license is unknown (set `unknown = \"allow\"` to accept)",
                "app: license `ISC` is allowed but no checked package uses it (unused-allowed-license)",
            ]
        );
        assert_eq!(violations[3].level, ViolationLevel::Warning);
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
                license_files: Vec::new(),
            },
            LicenseClarification {
                name: "openssl".to_owned(),
                version: Some("<0.9".to_owned()),
                expression: "OpenSSL".to_owned(),
                reason: "older versions only".to_owned(),
                license_files: Vec::new(),
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

    #[test]
    fn allow_build_scripts_checks_external_and_optional_workspace_crates() {
        let inventory = Inventory {
            packages: vec![
                package("app", "0.1.0", None),
                package("cc", "1.0.90", Some(CRATES_IO)),
                package("ring", "0.17.8", Some(CRATES_IO)),
            ],
        };
        let build_scripts: super::ActivePackages =
            [("app", "0.1.0"), ("cc", "1.0.90"), ("ring", "0.17.8")]
                .into_iter()
                .map(|(n, v)| (n.to_owned(), v.to_owned()))
                .collect();
        let mut policy = Policy {
            allow_build_scripts: Some(vec![super::BuildScriptAllow {
                name: "cc".to_owned(),
                version: None,
            }]),
            ..Default::default()
        };

        let ctx = super::GraphContext {
            build_scripts: Some(&build_scripts),
            ..Default::default()
        };
        let violations = policy.check_with_context(&inventory, &[], false, &ctx);
        assert_eq!(violations.len(), 1);
        assert_eq!(inventory.packages[violations[0].package].name, "ring");
        assert_eq!(violations[0].rule, Rule::Ban);
        assert_eq!(violations[0].level, super::ViolationLevel::Error);

        policy.build_include_workspace = true;
        let violations = policy.check_with_context(&inventory, &[], false, &ctx);
        assert_eq!(violations.len(), 2);
        assert_eq!(inventory.packages[violations[0].package].name, "app");
        assert_eq!(inventory.packages[violations[1].package].name, "ring");
    }

    #[test]
    fn warn_levels_emit_warning_violations_for_sources_and_duplicates() {
        let (mut inventory, info) = sample();
        inventory
            .packages
            .push(package("good", "2.0.0", Some(CRATES_IO)));
        let policy = Policy {
            allow_registries: Some(vec!["crates.io".to_owned()]),
            allow_git: Vec::new(),
            registry_source_level: super::LintLevel::Warn,
            git_source_level: super::LintLevel::Deny,
            multiple_versions: super::LintLevel::Warn,
            ..Default::default()
        };
        let violations = policy.check(&inventory, &info, false);
        assert_eq!(violations.len(), 3, "{violations:?}");
        assert_eq!(inventory.packages[violations[0].package].name, "forked");
        assert_eq!(violations[0].level, super::ViolationLevel::Error);
        assert_eq!(inventory.packages[violations[1].package].name, "private");
        assert_eq!(violations[1].level, super::ViolationLevel::Warning);
        assert_eq!(violations[2].rule, Rule::MultipleVersions);
        assert_eq!(violations[2].level, super::ViolationLevel::Warning);
    }
}
