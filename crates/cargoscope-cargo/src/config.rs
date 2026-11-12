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
    check_keys(&value, "top level", &["licenses", "sources", "bans"])?;
    if value.is_empty() {
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
