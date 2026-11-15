//! `cargoscope.toml`, the project configuration file (see docs/policy.md).

use std::path::Path;

use cargoscope_core::policy::{Ban, Policy, UnknownLicense};

/// File name, looked up in the scanned directory.
pub const FILE_NAME: &str = "cargoscope.toml";

fn strings(table: &toml::Table, key: &str, context: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("[{context}] {key} must contain strings"))
            })
            .collect(),
        Some(_) => Err(format!("[{context}] {key} must be an array of strings")),
    }
}

fn check_keys(table: &toml::Table, context: &str, known: &[&str]) -> Result<(), String> {
    match table.keys().find(|key| !known.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "unknown key `{key}` in [{context}]; expected one of: {}",
            known.join(", ")
        )),
        None => Ok(()),
    }
}

/// Reads `[graph] targets`: target triples the policy is limited to.
/// `[graph]`: targets, the feature keys (`features`, `all-features`,
/// `no-default-features`; `None` when no feature key is set) and
/// `exclude-dev`.
type Graph = (Vec<String>, Option<cargoscope_core::policy::Features>, bool);

fn parse_graph(value: &toml::Table) -> Result<Graph, String> {
    let Some(graph) = value.get("graph") else {
        return Ok((Vec::new(), None, false));
    };
    let graph = graph
        .as_table()
        .ok_or_else(|| "[graph] must be a table".to_owned())?;
    check_keys(
        graph,
        "graph",
        &[
            "targets",
            "features",
            "all-features",
            "no-default-features",
            "exclude-dev",
        ],
    )?;
    let flag = |key: &str| match graph.get(key) {
        None => Ok(false),
        Some(toml::Value::Boolean(value)) => Ok(*value),
        Some(_) => Err(format!("[graph] {key} must be true or false")),
    };
    let list = strings(graph, "features", "graph")?;
    for feature in &list {
        let valid = !feature.is_empty()
            && !feature.starts_with('-')
            && feature
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '+' | '.'));
        if !valid {
            return Err(format!(
                "[graph] features: `{feature}` is not a feature name (use `member/feature` in a workspace)"
            ));
        }
    }
    let features = ["features", "all-features", "no-default-features"]
        .iter()
        .any(|key| graph.contains_key(*key))
        .then(|| -> Result<_, String> {
            Ok(cargoscope_core::policy::Features {
                list,
                all: flag("all-features")?,
                no_default: flag("no-default-features")?,
            })
        })
        .transpose()?;
    let targets = strings(graph, "targets", "graph")?;
    for target in &targets {
        let valid = !target.is_empty()
            && !target.starts_with('-')
            && target
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if !valid {
            return Err(format!(
                "[graph] targets: `{target}` is not a target triple such as x86_64-unknown-linux-gnu"
            ));
        }
    }
    let exclude_dev = flag("exclude-dev")?;
    Ok((targets, features, exclude_dev))
}

/// Parses the text of a `cargoscope.toml`. Returns `None` when it defines
/// no policy section.
///
/// # Errors
///
/// Returns a message for invalid TOML, unknown keys or wrong value types,
/// so that a typo never silently disables a rule.
pub fn parse_policy(text: &str) -> Result<Option<Policy>, String> {
    let value: toml::Table = toml::from_str(text).map_err(|error| error.to_string())?;
    check_keys(
        &value,
        "top level",
        &["licenses", "sources", "bans", "advisories", "graph"],
    )?;
    let (targets, features, exclude_dev) = parse_graph(&value)?;
    if !["licenses", "sources", "bans"]
        .iter()
        .any(|key| value.contains_key(*key))
    {
        return Ok(None);
    }
    let table = |key: &str| -> Result<Option<&toml::Table>, String> {
        match value.get(key) {
            None => Ok(None),
            Some(toml::Value::Table(table)) => Ok(Some(table)),
            Some(_) => Err(format!("[{key}] must be a table")),
        }
    };
    let mut policy = Policy {
        targets,
        features,
        exclude_dev,
        ..Policy::default()
    };

    if let Some(licenses) = table("licenses")? {
        check_keys(
            licenses,
            "licenses",
            &["allow", "deny", "unknown", "exceptions", "clarify"],
        )?;
        policy.check_licenses = true;
        policy.allow_licenses = strings(licenses, "allow", "licenses")?;
        policy.deny_licenses = strings(licenses, "deny", "licenses")?;
        policy.unknown_license = match licenses.get("unknown").map(|value| value.as_str()) {
            None | Some(Some("deny")) => UnknownLicense::Deny,
            Some(Some("allow")) => UnknownLicense::Allow,
            _ => return Err("[licenses] unknown must be \"deny\" or \"allow\"".to_owned()),
        };
        for license in policy.allow_licenses.iter().chain(&policy.deny_licenses) {
            cargoscope_core::license::parse(license)
                .map_err(|error| format!("[licenses] `{license}`: {error}"))?;
        }
        for entry in crate_entries(
            licenses,
            "exceptions",
            &["name", "version", "allow", "reason"],
        )? {
            let allow = strings(entry.table, "allow", "licenses.exceptions")?;
            if allow.is_empty() {
                return Err(format!(
                    "[licenses] exception for `{}` needs a non-empty `allow` list",
                    entry.name
                ));
            }
            for license in &allow {
                cargoscope_core::license::parse(license).map_err(|error| {
                    format!(
                        "[licenses] exception for `{}`: `{license}`: {error}",
                        entry.name
                    )
                })?;
            }
            policy
                .license_exceptions
                .push(cargoscope_core::policy::LicenseException {
                    name: entry.name,
                    version: entry.version,
                    allow,
                    reason: entry.reason,
                });
        }
        for entry in crate_entries(
            licenses,
            "clarify",
            &["name", "version", "expression", "reason"],
        )? {
            let expression = entry
                .table
                .get("expression")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "[licenses] clarify for `{}` needs an `expression`",
                        entry.name
                    )
                })?
                .to_owned();
            cargoscope_core::license::parse(&expression).map_err(|error| {
                format!(
                    "[licenses] clarify for `{}`: `{expression}`: {error}",
                    entry.name
                )
            })?;
            policy
                .license_clarifications
                .push(cargoscope_core::policy::LicenseClarification {
                    name: entry.name,
                    version: entry.version,
                    expression,
                    reason: entry.reason,
                });
        }
    }

    if let Some(sources) = table("sources")? {
        check_keys(sources, "sources", &["allow-registries", "allow-git"])?;
        let registries = strings(sources, "allow-registries", "sources")?;
        policy.allow_registries = Some(if sources.contains_key("allow-registries") {
            registries
        } else {
            vec!["crates.io".to_owned()]
        });
        policy.allow_git = strings(sources, "allow-git", "sources")?;
    }

    if let Some(bans) = table("bans")? {
        check_keys(
            bans,
            "bans",
            &["deny", "multiple-versions", "skip-multiple-versions"],
        )?;
        policy.deny_multiple_versions =
            match bans.get("multiple-versions").map(|value| value.as_str()) {
                None | Some(Some("allow")) => false,
                Some(Some("deny")) => true,
                _ => {
                    return Err("[bans] multiple-versions must be \"deny\" or \"allow\"".to_owned());
                }
            };
        policy.skip_multiple_versions = strings(bans, "skip-multiple-versions", "bans")?;
        let entries = match bans.get("deny") {
            None => Vec::new(),
            Some(toml::Value::Array(entries)) => entries.clone(),
            Some(_) => return Err("[bans] deny must be an array of tables".to_owned()),
        };
        for entry in entries {
            let entry = entry.as_table().ok_or(
                "[bans] deny entries must be tables such as { name = \"...\", reason = \"...\" }",
            )?;
            check_keys(entry, "bans.deny", &["name", "version", "reason"])?;
            let field = |key: &str| {
                entry
                    .get(key)
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
            };
            let name = field("name").ok_or("[bans] deny entries need a `name`")?;
            let reason = field("reason")
                .filter(|reason| !reason.trim().is_empty())
                .ok_or_else(|| format!("[bans] `{name}` needs a non-empty `reason`"))?;
            let version = field("version");
            if let Some(requirement) = &version {
                semver::VersionReq::parse(requirement)
                    .map_err(|error| format!("[bans] `{name}` version `{requirement}`: {error}"))?;
            }
            policy.bans.push(Ban {
                name,
                version,
                reason,
            });
        }
    }

    Ok(Some(policy))
}

/// One `{ name, version, reason, ... }` table of a crate list.
struct CrateEntry<'a> {
    name: String,
    version: Option<String>,
    reason: String,
    table: &'a toml::Table,
}

/// Reads `[licenses] KEY = [{ name = "...", reason = "...", ... }]`: every
/// entry needs a `name` and a non-empty `reason`; `version`, when given, must
/// be a valid requirement.
fn crate_entries<'a>(
    section: &'a toml::Table,
    key: &str,
    known: &[&str],
) -> Result<Vec<CrateEntry<'a>>, String> {
    let entries = match section.get(key) {
        None => return Ok(Vec::new()),
        Some(toml::Value::Array(entries)) => entries,
        Some(_) => return Err(format!("[licenses] {key} must be an array of tables")),
    };
    entries
        .iter()
        .map(|entry| {
            let table = entry.as_table().ok_or_else(|| {
                format!("[licenses] {key} entries must be tables such as {{ name = \"...\", reason = \"...\" }}")
            })?;
            check_keys(table, &format!("licenses.{key}"), known)?;
            let field = |name: &str| table.get(name).and_then(toml::Value::as_str).map(str::to_owned);
            let name = field("name").ok_or_else(|| format!("[licenses] {key} entries need a `name`"))?;
            let reason = field("reason")
                .filter(|reason| !reason.trim().is_empty())
                .ok_or_else(|| format!("[licenses] {key} for `{name}` needs a non-empty `reason`"))?;
            let version = field("version");
            if let Some(requirement) = &version {
                semver::VersionReq::parse(requirement).map_err(|error| {
                    format!("[licenses] {key} for `{name}` version `{requirement}`: {error}")
                })?;
            }
            Ok(CrateEntry { name, version, reason, table })
        })
        .collect()
}

/// An advisory to ignore, from `[advisories] ignore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryIgnore {
    /// Advisory ID or alias (`RUSTSEC-...`, `CVE-...`, `GHSA-...`).
    pub id: String,
    /// Why it is ignored; required.
    pub reason: String,
    /// Last day (`YYYY-MM-DD`) the ignore applies, if limited.
    pub until: Option<String>,
}

fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
}

/// Parses `[advisories] ignore = [{ id, reason, until }]`.
///
/// # Errors
///
/// Returns a message for unknown keys, a missing `id` or `reason`, or an
/// `until` that is not a `YYYY-MM-DD` date.
pub fn parse_advisory_ignores(text: &str) -> Result<Vec<AdvisoryIgnore>, String> {
    let value: toml::Table = toml::from_str(text).map_err(|error| error.to_string())?;
    let Some(advisories) = value.get("advisories") else {
        return Ok(Vec::new());
    };
    let advisories = advisories
        .as_table()
        .ok_or("[advisories] must be a table")?;
    check_keys(advisories, "advisories", &["ignore"])?;
    let entries = match advisories.get("ignore") {
        None => return Ok(Vec::new()),
        Some(toml::Value::Array(entries)) => entries,
        Some(_) => return Err("[advisories] ignore must be an array of tables".to_owned()),
    };
    let mut ignores = Vec::new();
    for entry in entries {
        let entry = entry.as_table().ok_or(
            "[advisories] ignore entries must be tables such as { id = \"RUSTSEC-...\", reason = \"...\" }",
        )?;
        check_keys(entry, "advisories.ignore", &["id", "reason", "until"])?;
        let field = |key: &str| {
            entry
                .get(key)
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };
        let id = field("id").ok_or("[advisories] ignore entries need an `id`")?;
        let reason = field("reason")
            .filter(|reason| !reason.trim().is_empty())
            .ok_or_else(|| format!("[advisories] `{id}` needs a non-empty `reason`"))?;
        let until = field("until");
        if let Some(date) = &until
            && !is_date(date)
        {
            return Err(format!(
                "[advisories] `{id}` until must be a YYYY-MM-DD date, not `{date}`"
            ));
        }
        ignores.push(AdvisoryIgnore { id, reason, until });
    }
    Ok(ignores)
}

fn read_config(project_root: &Path) -> Result<Option<String>, String> {
    let path = project_root.join(FILE_NAME);
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return Ok(None);
    };
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(format!(
            "{} must be a regular file under 1 MiB",
            path.display()
        ));
    }
    std::fs::read_to_string(&path)
        .map(Some)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Reads `[advisories] ignore` from `project_root/cargoscope.toml`, or,
/// without one, from cargo-deny's `deny.toml`.
///
/// # Errors
///
/// Returns a message naming the file for unreadable or invalid content.
pub fn load_advisory_ignores(project_root: &Path) -> Result<Vec<AdvisoryIgnore>, String> {
    match read_config(project_root)? {
        None => Ok(crate::deny::load(project_root)?
            .map(|translation| translation.ignores)
            .unwrap_or_default()),
        Some(text) => parse_advisory_ignores(&text)
            .map_err(|error| format!("{}: {error}", project_root.join(FILE_NAME).display())),
    }
}

/// Reads `cargoscope.toml` from `project_root`, or, without one, the rules
/// of cargo-deny's `deny.toml` (see [`crate::deny`]).
///
/// # Errors
///
/// Returns a message naming the file for unreadable or invalid content.
pub fn load_policy(project_root: &Path) -> Result<Option<Policy>, String> {
    let path = project_root.join(FILE_NAME);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Ok(crate::deny::load(project_root)?.and_then(|translation| translation.policy));
        }
    };
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(format!(
            "{} must be a regular file under 1 MiB",
            path.display()
        ));
    }
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    parse_policy(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Notes for the report when `deny.toml` stands in for a missing
/// `cargoscope.toml`: which file is used and what it could not translate.
#[must_use]
pub fn deny_notes(project_root: &Path) -> Vec<String> {
    if std::fs::symlink_metadata(project_root.join(FILE_NAME)).is_ok() {
        return Vec::new();
    }
    match crate::deny::load(project_root) {
        Ok(Some(translation)) => {
            let name = translation
                .path
                .strip_prefix(project_root)
                .unwrap_or(&translation.path)
                .display()
                .to_string();
            std::iter::once(format!(
                "no cargoscope.toml: the rules of {name} (cargo-deny) are used; write a cargoscope.toml to replace them"
            ))
            .chain(translation.notes)
            .collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_policy;
    use cargoscope_core::policy::UnknownLicense;

    #[test]
    fn parses_every_section() {
        let policy = parse_policy(
            r#"
            [licenses]
            allow = ["MIT", "Apache-2.0"]
            unknown = "allow"
            [sources]
            allow-git = ["https://github.com/myorg/"]
            [bans]
            deny = [{ name = "openssl", version = "<0.10", reason = "use rustls" }]
            multiple-versions = "deny"
            skip-multiple-versions = ["windows-sys"]
            "#,
        )
        .expect("valid")
        .expect("has a policy");
        assert_eq!(policy.allow_licenses, vec!["MIT", "Apache-2.0"]);
        assert_eq!(policy.unknown_license, UnknownLicense::Allow);
        assert_eq!(policy.allow_registries, Some(vec!["crates.io".to_owned()]));
        assert_eq!(policy.bans[0].version.as_deref(), Some("<0.10"));
        assert!(policy.deny_multiple_versions);
        assert_eq!(policy.skip_multiple_versions, vec!["windows-sys"]);
        assert!(
            parse_policy("[bans]\nmultiple-versions = \"warn\"\n")
                .unwrap_err()
                .contains("must be \"deny\" or \"allow\"")
        );
    }

    #[test]
    fn parses_graph_targets_and_rejects_anything_else() {
        let policy = parse_policy(
            "[graph]\ntargets = [\"x86_64-unknown-linux-gnu\", \"aarch64-apple-darwin\"]\n[licenses]\nallow = [\"MIT\"]\n",
        )
        .expect("valid")
        .expect("has a policy");
        assert_eq!(
            policy.targets,
            vec!["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]
        );
        // [graph] alone sets no rule, hence no policy.
        assert!(
            parse_policy("[graph]\ntargets = [\"x86_64-unknown-linux-gnu\"]\n")
                .expect("valid")
                .is_none()
        );
        for bad in [
            "[graph]\ntargets = [\"--manifest-path\"]\n",
            "[graph]\ntargets = [\"\"]\n",
            "[graph]\ntargets = [\"linux gnu\"]\n",
        ] {
            let text = format!("{bad}[bans]\nmultiple-versions = \"deny\"\n");
            assert!(
                parse_policy(&text)
                    .unwrap_err()
                    .contains("not a target triple"),
                "{bad}"
            );
        }
        assert!(
            parse_policy("[graph]\ntarget = []\n[bans]\n")
                .unwrap_err()
                .contains("unknown key")
        );
    }

    #[test]
    fn parses_graph_features() {
        let policy = |text: &str| parse_policy(text).expect("valid").expect("policy");
        assert!(policy("[graph]\nexclude-dev = true\n[bans]\n").exclude_dev);
        let none = policy("[graph]\ntargets = [\"x86_64-unknown-linux-gnu\"]\n[bans]\n");
        assert_eq!(none.features, None);
        let some = policy(
            "[graph]\nfeatures = [\"app/extra\", \"tls\"]\nno-default-features = true\n[bans]\n",
        );
        let features = some.features.expect("features");
        assert_eq!(features.list, vec!["app/extra", "tls"]);
        assert!(features.no_default && !features.all);
        assert_eq!(
            features.cargo_args(),
            vec!["--no-default-features", "--features", "app/extra,tls"]
        );
        let all = policy("[graph]\nall-features = true\n[licenses]\n")
            .features
            .expect("features");
        assert_eq!(all.cargo_args(), vec!["--all-features"]);

        let error = |text: &str| parse_policy(text).expect_err("invalid");
        assert!(
            error("[graph]\nall-features = \"yes\"\n[bans]\n").contains("must be true or false")
        );
        assert!(error("[graph]\nfeatures = [\"a b\"]\n[bans]\n").contains("is not a feature name"));
    }

    #[test]
    fn parses_license_exceptions_and_clarifications() {
        let policy = parse_policy(
            r#"
            [licenses]
            allow = ["MIT"]
            exceptions = [{ name = "ring", version = "^0.17", allow = ["ISC", "OpenSSL"], reason = "reviewed" }]
            clarify = [{ name = "webpki", expression = "ISC", reason = "LICENSE file checked" }]
            "#,
        )
        .expect("valid")
        .expect("policy");
        assert_eq!(policy.license_exceptions[0].name, "ring");
        assert_eq!(
            policy.license_exceptions[0].version.as_deref(),
            Some("^0.17")
        );
        assert_eq!(policy.license_exceptions[0].allow, vec!["ISC", "OpenSSL"]);
        assert_eq!(policy.license_clarifications[0].expression, "ISC");

        let error = |text: &str| parse_policy(text).expect_err("invalid");
        assert!(
            error("[licenses]\nexceptions = [{ name = \"a\", allow = [\"MIT\"] }]\n")
                .contains("needs a non-empty `reason`")
        );
        assert!(
            error("[licenses]\nexceptions = [{ name = \"a\", allow = [], reason = \"r\" }]\n")
                .contains("non-empty `allow`")
        );
        assert!(
            error("[licenses]\nclarify = [{ name = \"a\", reason = \"r\" }]\n")
                .contains("needs an `expression`")
        );
        assert!(error("[licenses]\nclarify = [{ name = \"a\", expression = \"MIT AND\", reason = \"r\" }]\n").contains("clarify for `a`"));
        assert!(error("[licenses]\nclarify = [{ name = \"a\", expression = \"MIT\", reason = \"r\", hash = 1 }]\n").contains("unknown key `hash`"));
        assert!(error("[licenses]\nexceptions = [{ name = \"a\", version = \"one\", allow = [\"MIT\"], reason = \"r\" }]\n").contains("version `one`"));
    }

    #[test]
    fn parses_advisory_ignores_and_rejects_bad_entries() {
        let ignores = super::parse_advisory_ignores(
            r#"
            [advisories]
            ignore = [
              { id = "RUSTSEC-2020-0071", reason = "time is only used in a build tool" },
              { id = "CVE-2024-1234", reason = "not reachable", until = "2027-01-31" },
            ]
            "#,
        )
        .expect("valid");
        assert_eq!(ignores.len(), 2);
        assert_eq!(ignores[1].until.as_deref(), Some("2027-01-31"));
        assert!(
            super::parse_advisory_ignores("[advisories]\nignore = [{ id = \"X\" }]\n")
                .unwrap_err()
                .contains("non-empty `reason`")
        );
        assert!(
            super::parse_advisory_ignores(
                "[advisories]\nignore = [{ id = \"X\", reason = \"r\", until = \"soon\" }]\n"
            )
            .unwrap_err()
            .contains("YYYY-MM-DD")
        );
        assert!(
            super::parse_advisory_ignores("[advisories]\nignores = []\n")
                .unwrap_err()
                .contains("unknown key")
        );
        // A file with only [advisories] defines no policy.
        assert_eq!(parse_policy("[advisories]\nignore = []\n"), Ok(None));
    }

    #[test]
    fn rejects_typos_and_missing_reasons() {
        assert!(
            parse_policy("[licenses]\nalow = [\"MIT\"]\n")
                .unwrap_err()
                .contains("unknown key `alow`")
        );
        assert!(
            parse_policy("[lisences]\n")
                .unwrap_err()
                .contains("unknown key `lisences`")
        );
        assert!(
            parse_policy("[bans]\ndeny = [{ name = \"x\" }]\n")
                .unwrap_err()
                .contains("non-empty `reason`")
        );
        assert!(
            parse_policy(
                "[bans]\ndeny = [{ name = \"x\", reason = \"r\", version = \"not a req\" }]\n"
            )
            .is_err()
        );
        assert!(parse_policy("[licenses]\nallow = [\"MIT OR\"]\n").is_err());
        assert_eq!(parse_policy(""), Ok(None));
    }
}
