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
        &["licenses", "sources", "bans", "advisories"],
    )?;
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
    let mut policy = Policy::default();

    if let Some(licenses) = table("licenses")? {
        check_keys(licenses, "licenses", &["allow", "deny", "unknown"])?;
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
        check_keys(bans, "bans", &["deny"])?;
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
        if let Some(date) = &until {
            if !is_date(date) {
                return Err(format!(
                    "[advisories] `{id}` until must be a YYYY-MM-DD date, not `{date}`"
                ));
            }
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

/// Reads `[advisories] ignore` from `project_root/cargoscope.toml`, if present.
///
/// # Errors
///
/// Returns a message naming the file for unreadable or invalid content.
pub fn load_advisory_ignores(project_root: &Path) -> Result<Vec<AdvisoryIgnore>, String> {
    match read_config(project_root)? {
        None => Ok(Vec::new()),
        Some(text) => parse_advisory_ignores(&text)
            .map_err(|error| format!("{}: {error}", project_root.join(FILE_NAME).display())),
    }
}

/// Reads `cargoscope.toml` from `project_root`, if present.
///
/// # Errors
///
/// Returns a message naming the file for unreadable or invalid content.
pub fn load_policy(project_root: &Path) -> Result<Option<Policy>, String> {
    let path = project_root.join(FILE_NAME);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(None),
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
            "#,
        )
        .expect("valid")
        .expect("has a policy");
        assert_eq!(policy.allow_licenses, vec!["MIT", "Apache-2.0"]);
        assert_eq!(policy.unknown_license, UnknownLicense::Allow);
        assert_eq!(policy.allow_registries, Some(vec!["crates.io".to_owned()]));
        assert_eq!(policy.bans[0].version.as_deref(), Some("<0.10"));
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
