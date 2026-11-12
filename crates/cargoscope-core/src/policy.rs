//! Dependency policies (licenses, sources, banned crates), checked against
//! an inventory. Configured in `cargoscope.toml` (see docs/policy.md).

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
}

/// Rule a violation breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// License not allowed, denied or unknown.
    License,
    /// Package from a source that is not allowed.
    Source,
    /// Banned crate.
    Ban,
}

impl Rule {
    /// Name used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::License => "license",
            Self::Source => "source",
            Self::Ban => "ban",
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
        let mut violations = Vec::new();
        for (index, package) in inventory.packages.iter().enumerate() {
            let Some(source) = package.source.as_deref() else {
                continue;
            };
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
                let matches = match &ban.version {
                    None => true,
                    Some(requirement) => match (
                        semver::VersionReq::parse(requirement),
                        semver::Version::parse(&package.version),
                    ) {
                        (Ok(requirement), Ok(version)) => requirement.matches(&version),
                        _ => true,
                    },
                };
                if matches {
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

            if self.check_licenses && licenses_known && CRATES_IO.contains(&source) {
                match info.get(index).and_then(|info| info.license.as_deref()) {
                    None => {
                        if self.unknown_license == UnknownLicense::Deny {
                            push(
                                Rule::License,
                                "license is unknown (set `unknown = \"allow\"` to accept)"
                                    .to_owned(),
                            );
                        }
                    }
                    Some(expression) => match license::is_allowed(
                        expression,
                        &self.allow_licenses,
                        &self.deny_licenses,
                    ) {
                        Ok(true) => {}
                        Ok(false) => push(
                            Rule::License,
                            format!("license `{expression}` is not allowed by the policy"),
                        ),
                        Err(error) => push(
                            Rule::License,
                            format!("license `{expression}` cannot be read: {error}"),
                        ),
                    },
                }
            }
        }
        violations
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
            }],
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
}
