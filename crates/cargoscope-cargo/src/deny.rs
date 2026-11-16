//! Reads a cargo-deny configuration (`deny.toml`) as a CargoScope policy, so
//! that a project that uses cargo-deny can try CargoScope without writing a
//! `cargoscope.toml`.
//!
//! The translation is tolerant, unlike `cargoscope.toml`: a setting CargoScope
//! has no equivalent for is reported in a note, never an error, and never
//! silently dropped. Rules that would become stricter (a ban with wrappers,
//! applied everywhere) say so too.

use std::path::{Path, PathBuf};

use cargoscope_core::policy::{
    Ban, BuildScriptAllow, FeatureBan, Features, LicenseClarification, LicenseException,
    LicenseFileHash, LintLevel, Policy, UnknownLicense,
};

use crate::config::AdvisoryIgnore;

/// Where cargo-deny looks for its configuration in a project.
pub const FILE_NAMES: [&str; 3] = ["deny.toml", ".deny.toml", ".cargo/deny.toml"];

/// Reason given to entries that have none in `deny.toml`.
const NO_REASON: &str = "from deny.toml";

/// crates.io's index, as cargo-deny's `allow-registry` usually lists it.
const CRATES_IO_INDEX: &str = "https://github.com/rust-lang/crates.io-index";

/// A `deny.toml` read as a CargoScope policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Translation {
    /// The file read.
    pub path: PathBuf,
    /// The policy (`None` when the file sets no license, ban or source rule).
    pub policy: Option<Policy>,
    /// `[advisories] ignore`.
    pub ignores: Vec<AdvisoryIgnore>,
    /// What could not be translated, or was translated approximately.
    pub notes: Vec<String>,
}

/// The `deny.toml` of `project_root`, if any.
#[must_use]
pub fn find(project_root: &Path) -> Option<PathBuf> {
    FILE_NAMES
        .iter()
        .map(|name| project_root.join(name))
        .find(|path| std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file()))
}

/// Reads and translates the `deny.toml` of `project_root`, if any.
///
/// # Errors
///
/// Returns a message when the file cannot be read or is not TOML.
pub fn load(project_root: &Path) -> Result<Option<Translation>, String> {
    let Some(path) = find(project_root) else {
        return Ok(None);
    };
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let (mut policy, ignores, notes) =
        translate(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    if let Some(policy) = &mut policy {
        policy.root_package_only = has_root_package(project_root);
    }
    Ok(Some(Translation {
        path,
        policy,
        ignores,
        notes,
    }))
}

fn has_root_package(project_root: &Path) -> bool {
    std::fs::read_to_string(project_root.join("Cargo.toml"))
        .ok()
        .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
        .is_some_and(|table| table.contains_key("package") && table.contains_key("workspace"))
}

/// A crate named by cargo-deny: `"name"`, `"name@version"`, `"name:req"`,
/// or a table with `crate` (one of those) or `name` and `version`. The
/// version becomes a requirement (`=1.2.3` for an exact version, `None` for
/// any).
pub(crate) fn crate_spec(value: &toml::Value) -> Option<(String, Option<String>)> {
    let (spec, version) = match value {
        toml::Value::String(spec) => (spec.clone(), None),
        toml::Value::Table(table) => {
            let text = |key: &str| {
                table
                    .get(key)
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
            };
            (text("crate").or_else(|| text("name"))?, text("version"))
        }
        _ => return None,
    };
    let (name, inline) = match spec.split_once(['@', ':']) {
        Some((name, version)) => (name.to_owned(), Some(version.to_owned())),
        None => (spec, None),
    };
    let requirement = inline.or(version).and_then(|version| {
        let version = version.trim();
        if version.is_empty() || version == "*" {
            None
        } else if semver::Version::parse(version).is_ok() {
            Some(format!("={version}"))
        } else {
            semver::VersionReq::parse(version)
                .is_ok()
                .then(|| version.to_owned())
        }
    });
    (!name.is_empty()).then_some((name, requirement))
}

fn strings(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn reason(value: &toml::Value) -> String {
    value
        .get("reason")
        .and_then(toml::Value::as_str)
        .filter(|reason| !reason.trim().is_empty())
        .unwrap_or(NO_REASON)
        .to_owned()
}

/// The policy, the advisory ignores and the notes read from a `deny.toml`.
pub type Translated = (Option<Policy>, Vec<AdvisoryIgnore>, Vec<String>);

/// Translates the text of a `deny.toml`: the policy, the advisory ignores,
/// and notes on what could not be translated.
///
/// # Errors
///
/// Returns a message when the text is not TOML.
pub fn translate(text: &str) -> Result<Translated, String> {
    let value: toml::Table = toml::from_str(text).map_err(|error| error.to_string())?;
    let mut notes = Vec::new();
    let mut policy = Policy::default();
    let mut has_rules = false;
    let table = |key: &str| value.get(key).and_then(toml::Value::as_table);
    let unsupported =
        |notes: &mut Vec<String>, section: &str, table: &toml::Table, known: &[&str]| {
            let ignored: Vec<&str> = table
                .keys()
                .map(String::as_str)
                .filter(|key| !known.contains(key))
                .collect();
            if !ignored.is_empty() {
                notes.push(format!(
                    "deny.toml: [{section}] {} not supported by CargoScope, ignored",
                    ignored.join(", ")
                ));
            }
        };

    if let Some(graph) = table("graph") {
        for target in graph
            .get("targets")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let triple = target
                .as_str()
                .or_else(|| target.get("triple").and_then(toml::Value::as_str));
            if let Some(triple) = triple {
                policy.targets.push(triple.to_owned());
            }
            if target.get("features").is_some() {
                notes.push("deny.toml: [graph] target features (cfg features of a target) are not supported, ignored".to_owned());
            }
        }
        let flag = |key: &str| {
            graph
                .get(key)
                .and_then(toml::Value::as_bool)
                .unwrap_or(false)
        };
        let features = strings(graph, "features");
        if graph.contains_key("features")
            || graph.contains_key("all-features")
            || graph.contains_key("no-default-features")
        {
            policy.features = Some(Features {
                list: features,
                all: flag("all-features"),
                no_default: flag("no-default-features"),
            });
        }
        policy.exclude_dev = flag("exclude-dev");
        policy.exclude_unpublished = flag("exclude-unpublished");
        unsupported(
            &mut notes,
            "graph",
            graph,
            &[
                "targets",
                "features",
                "all-features",
                "no-default-features",
                "exclude-dev",
                "exclude-unpublished",
            ],
        );
    }

    // cargo-deny always checks the graph of the default features (on every
    // platform, dev-dependencies included) unless told otherwise.
    if policy.features.is_none() {
        policy.features = Some(Features::default());
    }

    if let Some(licenses) = table("licenses") {
        has_rules = true;
        policy.check_licenses = true;
        policy.unknown_license = UnknownLicense::Deny;
        // cargo-deny leaves licenses of dev-dependencies out by default.
        policy.licenses_exclude_dev =
            licenses.get("include-dev").and_then(toml::Value::as_bool) != Some(true);
        // cargo-deny checks every crate of the graph, the project's own too.
        policy.licenses_include_workspace = true;
        policy.empty_allow_denies_all = true;
        if let Some(value) = licenses.get("confidence-threshold") {
            match crate::config::confidence_threshold(value) {
                Some(threshold) => policy.confidence_threshold = threshold,
                None => notes.push(
                    "deny.toml: [licenses] confidence-threshold is not a number from 0.0 to 1.0, 0.8 used"
                        .to_owned(),
                ),
            }
        }
        // cargo-deny warns about allowed licenses no crate uses by default.
        policy.unused_allowed_license = match licenses
            .get("unused-allowed-license")
            .and_then(toml::Value::as_str)
        {
            Some("allow") => LintLevel::Allow,
            Some("deny") => LintLevel::Deny,
            _ => LintLevel::Warn,
        };
        if let Some(private) = licenses.get("private").and_then(toml::Value::as_table) {
            policy.private_ignore =
                private.get("ignore").and_then(toml::Value::as_bool) == Some(true);
            policy.private_registries = strings(private, "registries");
            policy.private_ignore_sources = strings(private, "ignore-sources");
        }
        let valid = |license: &String, notes: &mut Vec<String>| {
            let ok = cargoscope_core::license::parse(license).is_ok();
            if !ok {
                notes.push(format!(
                    "deny.toml: license `{license}` cannot be read, ignored"
                ));
            }
            ok
        };
        policy.allow_licenses = strings(licenses, "allow")
            .into_iter()
            .filter(|license| valid(license, &mut notes))
            .collect();
        policy.deny_licenses = strings(licenses, "deny")
            .into_iter()
            .filter(|license| valid(license, &mut notes))
            .collect();
        if policy.allow_licenses.is_empty() {
            notes.push(
                "deny.toml: [licenses] allow is empty: every license is rejected, as in cargo-deny"
                    .to_owned(),
            );
        }
        for entry in licenses
            .get("exceptions")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some((name, version)) = crate_spec(entry) else {
                notes.push(
                    "deny.toml: a license exception without a crate name was ignored".to_owned(),
                );
                continue;
            };
            let allow: Vec<String> = entry
                .get("allow")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .filter(|license| valid(license, &mut notes))
                .collect();
            policy.license_exceptions.push(LicenseException {
                name,
                version,
                allow,
                reason: reason(entry),
            });
        }
        for entry in licenses
            .get("clarify")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some((name, version)), Some(expression)) = (
                crate_spec(entry),
                entry.get("expression").and_then(toml::Value::as_str),
            ) else {
                notes.push("deny.toml: a license clarification without a crate or an expression was ignored".to_owned());
                continue;
            };
            if cargoscope_core::license::parse(expression).is_err() {
                notes.push(format!("deny.toml: the clarification of `{name}` (`{expression}`) cannot be read, ignored"));
                continue;
            }
            let mut license_files = Vec::new();
            for file in entry
                .get("license-files")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(path) = file.get("path").and_then(toml::Value::as_str) else {
                    notes.push(format!(
                        "deny.toml: a license-files entry for `{name}` without a `path` was ignored"
                    ));
                    continue;
                };
                let hash = match file.get("hash") {
                    None => None,
                    Some(toml::Value::Integer(value)) => match u32::try_from(*value) {
                        Ok(hash) => Some(hash),
                        Err(_) => {
                            notes.push(format!(
                                "deny.toml: license-files hash for `{name}` (`{path}`) is out of 32-bit range, ignored"
                            ));
                            None
                        }
                    },
                    Some(_) => {
                        notes.push(format!(
                            "deny.toml: license-files hash for `{name}` (`{path}`) is not an integer, ignored"
                        ));
                        None
                    }
                };
                license_files.push(LicenseFileHash {
                    path: path.to_owned(),
                    hash,
                });
            }
            policy.license_clarifications.push(LicenseClarification {
                name,
                version,
                expression: expression.to_owned(),
                reason: reason(entry),
                license_files,
            });
        }
        unsupported(
            &mut notes,
            "licenses",
            licenses,
            &[
                "allow",
                "deny",
                "exceptions",
                "clarify",
                "version",
                "include-dev",
                "unused-allowed-license",
                "confidence-threshold",
                "private",
            ],
        );
    }

    if let Some(bans) = table("bans") {
        has_rules = true;
        for entry in bans
            .get("deny")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some((name, version)) = crate_spec(entry) else {
                continue;
            };
            // `{ crate = "x", deny-multiple-versions = true }` denies the
            // duplicates of x, not x itself.
            if entry
                .get("deny-multiple-versions")
                .and_then(toml::Value::as_bool)
                == Some(true)
            {
                policy.deny_multiple_versions_of.push(name);
                continue;
            }
            let wrappers = entry
                .as_table()
                .map(|table| strings(table, "wrappers"))
                .unwrap_or_default()
                .iter()
                .filter_map(|wrapper| crate_spec(&toml::Value::String(wrapper.clone())))
                .map(|(wrapper, _)| wrapper)
                .collect();
            policy.bans.push(Ban {
                name,
                version,
                reason: reason(entry),
                wrappers,
            });
        }
        // cargo-deny leaves duplicates of dev-dependencies out by default.
        policy.duplicates_exclude_dev = bans
            .get("multiple-versions-include-dev")
            .and_then(toml::Value::as_bool)
            != Some(true);
        match bans.get("multiple-versions").and_then(toml::Value::as_str) {
            Some("deny") => policy.multiple_versions = LintLevel::Deny,
            Some("warn") => policy.multiple_versions = LintLevel::Warn,
            _ => {}
        }
        policy.skip_multiple_versions = bans
            .get("skip")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(crate_spec)
            .map(|(name, _)| name)
            .collect();
        policy.skip_multiple_versions_trees = bans
            .get("skip-tree")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let depth = entry
                    .get("depth")
                    .and_then(toml::Value::as_integer)
                    .and_then(|depth| usize::try_from(depth).ok());
                crate_spec(entry).map(|(name, _)| (name, depth))
            })
            .collect();
        for entry in bans
            .get("features")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some((name, version)) = crate_spec(entry) else {
                continue;
            };
            let Some(entry_table) = entry.as_table() else {
                continue;
            };
            policy.feature_bans.push(FeatureBan {
                name,
                version,
                allow: strings(entry_table, "allow"),
                deny: strings(entry_table, "deny"),
                exact: entry_table
                    .get("exact")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false),
                reason: reason(entry),
            });
        }
        if let Some(build) = bans.get("build").and_then(toml::Value::as_table) {
            policy.build_include_workspace = build
                .get("include-workspace")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            if let Some(allow) = build
                .get("allow-build-scripts")
                .and_then(toml::Value::as_array)
            {
                policy.allow_build_scripts = Some(
                    allow
                        .iter()
                        .filter_map(|entry| {
                            crate_spec(entry)
                                .map(|(name, version)| BuildScriptAllow { name, version })
                        })
                        .collect(),
                );
            }
            match crate::config::build_inspection(build) {
                Ok(inspection) => policy.build_inspection = Some(inspection),
                Err(error) => notes.push(format!(
                    "deny.toml: {error}; executables and scripts in crates are not inspected"
                )),
            }
            unsupported(
                &mut notes,
                "bans.build",
                build,
                &[
                    "allow-build-scripts",
                    "include-workspace",
                    "executables",
                    "interpreted",
                    "script-extensions",
                    "enable-builtin-globs",
                    "include-dependencies",
                    "include-archives",
                    "bypass",
                ],
            );
        }
        unsupported(
            &mut notes,
            "bans",
            bans,
            &[
                "deny",
                "features",
                "build",
                "multiple-versions",
                "skip",
                "skip-tree",
                "multiple-versions-include-dev",
                "wildcards",
                "highlight",
                "allow-wildcard-paths",
            ],
        );
    }

    if let Some(sources) = table("sources") {
        has_rules = true;
        let level = |key: &str| match sources
            .get(key)
            .and_then(toml::Value::as_str)
            .unwrap_or("warn")
        {
            "allow" => LintLevel::Allow,
            "deny" => LintLevel::Deny,
            _ => LintLevel::Warn,
        };
        let (registry, git) = (level("unknown-registry"), level("unknown-git"));
        if registry != LintLevel::Allow || git != LintLevel::Allow {
            policy.allow_registries = Some(
                strings(sources, "allow-registry")
                    .into_iter()
                    .map(|url| {
                        if url.trim_end_matches('/') == CRATES_IO_INDEX {
                            "crates.io".to_owned()
                        } else {
                            url
                        }
                    })
                    .chain(std::iter::once("crates.io".to_owned()))
                    .collect(),
            );
            policy.allow_git = strings(sources, "allow-git");
            if let Some(orgs) = sources.get("allow-org").and_then(toml::Value::as_table) {
                for (host, url) in [
                    ("github", "https://github.com/"),
                    ("gitlab", "https://gitlab.com/"),
                    ("bitbucket", "https://bitbucket.org/"),
                ] {
                    policy.allow_git.extend(
                        strings(orgs, host)
                            .into_iter()
                            .map(|org| format!("{url}{org}/")),
                    );
                }
            }
            policy.registry_source_level = registry;
            policy.git_source_level = git;
        }
        unsupported(
            &mut notes,
            "sources",
            sources,
            &[
                "unknown-registry",
                "unknown-git",
                "allow-registry",
                "allow-git",
                "allow-org",
                "required-git-spec",
            ],
        );
    }

    let mut ignores = Vec::new();
    if let Some(advisories) = table("advisories") {
        for entry in advisories
            .get("ignore")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = entry
                .as_str()
                .or_else(|| entry.get("id").and_then(toml::Value::as_str));
            match id {
                Some(id) => ignores.push(AdvisoryIgnore {
                    id: id.to_owned(),
                    reason: reason(entry),
                    until: None,
                    source: "deny.toml",
                }),
                None => notes.push("deny.toml: an advisory ignore that names a crate instead of an advisory ID is not supported, ignored".to_owned()),
            }
        }
        unsupported(
            &mut notes,
            "advisories",
            advisories,
            &[
                "ignore",
                "version",
                "db-path",
                "db-urls",
                "git-fetch-with-cli",
                "yanked",
            ],
        );
    }

    Ok((has_rules.then_some(policy), ignores, notes))
}

#[cfg(test)]
mod tests {
    use super::{crate_spec, translate};

    #[test]
    fn reads_crate_specs_in_every_form() {
        let spec = |text: &str| crate_spec(&toml::Value::String(text.to_owned()));
        assert_eq!(spec("openssl"), Some(("openssl".to_owned(), None)));
        assert_eq!(
            spec("time@0.1.45"),
            Some(("time".to_owned(), Some("=0.1.45".to_owned())))
        );
        assert_eq!(
            spec("time:<0.2"),
            Some(("time".to_owned(), Some("<0.2".to_owned())))
        );
        let table: toml::Value = toml::from_str::<toml::Table>("name = \"ring\"\nversion = \"*\"")
            .unwrap()
            .into();
        assert_eq!(crate_spec(&table), Some(("ring".to_owned(), None)));
    }

    #[test]
    fn translates_a_cargo_deny_configuration() {
        let text = r#"
[graph]
targets = ["x86_64-unknown-linux-gnu", { triple = "aarch64-apple-darwin" }]
all-features = true
exclude-dev = true

[advisories]
ignore = ["RUSTSEC-2020-0071", { id = "RUSTSEC-2021-0145", reason = "only on Windows" }]
unmaintained = "workspace"

[licenses]
allow = ["MIT", "Apache-2.0"]
confidence-threshold = 0.8
exceptions = [{ allow = ["Zlib"], crate = "adler32" }]
[[licenses.clarify]]
crate = "ring"
expression = "MIT AND ISC AND OpenSSL"
license-files = [{ path = "LICENSE", hash = 0xbd0eed23 }]

[bans]
multiple-versions = "deny"
deny = ["openssl", { crate = "git2@0.18", reason = "use gix", wrappers = ["tool"] }, { name = "ahash", deny-multiple-versions = true }]
skip = [{ crate = "windows-sys@0.45", reason = "old" }]
skip-tree = ["criterion"]
features = [{ crate = "derive_more", deny = ["error"], allow = ["default"], exact = true }]
workspace-default-features = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = ["https://github.com/me/fork"]
[sources.allow-org]
github = ["myorg"]
"#;
        let (policy, ignores, notes) = translate(text).expect("valid TOML");
        let policy = policy.expect("rules");
        assert_eq!(
            policy.targets,
            vec!["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]
        );
        assert!(
            policy
                .features
                .as_ref()
                .is_some_and(|features| features.all)
        );
        assert!(policy.exclude_dev);
        assert_eq!(policy.allow_licenses, vec!["MIT", "Apache-2.0"]);
        assert_eq!(policy.license_exceptions[0].name, "adler32");
        assert_eq!(policy.license_exceptions[0].reason, "from deny.toml");
        assert_eq!(
            policy.license_clarifications[0].expression,
            "MIT AND ISC AND OpenSSL"
        );
        assert_eq!(
            policy.license_clarifications[0].license_files[0].path,
            "LICENSE"
        );
        assert_eq!(
            policy.license_clarifications[0].license_files[0].hash,
            Some(0xbd0e_ed23)
        );
        assert_eq!(
            policy.multiple_versions,
            cargoscope_core::policy::LintLevel::Deny
        );
        assert_eq!(policy.bans.len(), 2);
        assert_eq!(policy.bans[1].version.as_deref(), Some("0.18"));
        assert_eq!(policy.skip_multiple_versions, vec!["windows-sys"]);
        assert_eq!(policy.deny_multiple_versions_of, vec!["ahash"]);
        assert_eq!(
            policy.allow_registries,
            Some(vec!["crates.io".to_owned(), "crates.io".to_owned()])
        );
        assert_eq!(
            policy.allow_git,
            vec!["https://github.com/me/fork", "https://github.com/myorg/"]
        );
        assert_eq!(ignores.len(), 2);
        assert_eq!(ignores[1].reason, "only on Windows");

        let notes = notes.join("\n");
        assert!(!notes.contains("confidence-threshold"), "{notes}");
        assert_eq!(policy.confidence_threshold, 800);
        assert!(policy.licenses_include_workspace);
        assert_eq!(
            policy.unused_allowed_license,
            cargoscope_core::policy::LintLevel::Warn
        );
        assert!(!notes.contains("license-files hashes"), "{notes}");
        assert_eq!(policy.bans[1].wrappers, vec!["tool"]);
        assert_eq!(
            policy.skip_multiple_versions_trees,
            vec![("criterion".to_owned(), None)]
        );
        assert!(policy.features.is_some(), "default features, as cargo-deny");
        assert!(
            policy.licenses_exclude_dev,
            "include-dev defaults to false in cargo-deny"
        );
        assert_eq!(policy.feature_bans.len(), 1);
        assert_eq!(policy.feature_bans[0].name, "derive_more");
        assert_eq!(policy.feature_bans[0].deny, vec!["error"]);
        assert_eq!(policy.feature_bans[0].allow, vec!["default"]);
        assert!(policy.feature_bans[0].exact);
        assert_eq!(policy.feature_bans[0].reason, "from deny.toml");
        assert!(
            notes.contains("[bans] workspace-default-features not supported"),
            "{notes}"
        );
        assert!(
            notes.contains("[advisories] unmaintained not supported"),
            "{notes}"
        );
    }

    #[test]
    fn licenses_include_dev_and_root_package_only() {
        let (policy, _, _) =
            translate("[licenses]\nallow = [\"MIT\"]\ninclude-dev = true\n").expect("valid");
        let policy = policy.expect("policy");
        assert!(!policy.licenses_exclude_dev);

        let dir = std::env::temp_dir().join(format!("cargoscope-deny-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(
            dir.join("deny.toml"),
            "[bans]\nmultiple-versions = \"deny\"\n",
        )
        .expect("deny.toml");

        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[workspace]\nmembers = [\"other\"]\n",
        )
        .expect("Cargo.toml");
        let loaded = super::load(&dir)
            .expect("load")
            .expect("translation")
            .policy
            .expect("policy");
        assert!(loaded.root_package_only);

        std::fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers = [\"a\"]\n")
            .expect("virtual Cargo.toml");
        let loaded = super::load(&dir)
            .expect("load")
            .expect("translation")
            .policy
            .expect("policy");
        assert!(!loaded.root_package_only);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn warn_levels_and_build_scripts_translate_cleanly() {
        use cargoscope_core::policy::LintLevel;
        let (policy, _, notes) = translate(
            "[sources]\nunknown-registry = \"warn\"\nunknown-git = \"allow\"\n[bans]\nmultiple-versions = \"warn\"\n[bans.build]\nallow-build-scripts = [\"cc\", \"ring@0.17.8\"]\ninclude-workspace = true\nexecutables = \"deny\"\n",
        )
        .expect("valid");
        let policy = policy.expect("rules");
        assert_eq!(policy.allow_registries, Some(vec!["crates.io".to_owned()]));
        assert_eq!(policy.registry_source_level, LintLevel::Warn);
        assert_eq!(policy.git_source_level, LintLevel::Allow);
        assert_eq!(policy.multiple_versions, LintLevel::Warn);
        assert!(policy.build_include_workspace);
        assert_eq!(policy.allow_build_scripts.as_ref().map(Vec::len), Some(2));
        assert!(
            !notes.iter().any(|note| note.contains("bans.build")),
            "{notes:?}"
        );
        let inspection = policy.build_inspection.as_ref().expect("[bans.build]");
        assert_eq!(inspection.executables, LintLevel::Deny);
        assert_eq!(inspection.interpreted, LintLevel::Allow);
        let (bypass, _, _) = translate(
            "[bans.build]\ninterpreted = \"warn\"\nscript-extensions = [\"sh\"]\nbypass = [{ crate = \"ring\", allow-globs = [\"tests/**\"], allow = [{ path = \"x.bin\", checksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\" }] }]\n",
        )
        .expect("valid");
        let inspection = bypass
            .expect("rules")
            .build_inspection
            .expect("[bans.build]");
        assert_eq!(inspection.interpreted, LintLevel::Warn);
        assert_eq!(inspection.script_extensions, vec!["sh"]);
        assert_eq!(inspection.bypass[0].name, "ring");
        assert_eq!(inspection.bypass[0].allow_globs, vec!["tests/**"]);
        assert_eq!(inspection.bypass[0].allow[0].0, "x.bin");
        let (none, ignores, _) =
            translate("[advisories]\nignore = [\"RUSTSEC-1\"]\n").expect("valid");
        assert!(none.is_none());
        assert_eq!(ignores.len(), 1);
        assert!(translate("not = [toml").is_err());
    }
}
