//! `[updates]` of `cargoscope.toml`: which version updates `cargoscope fix
//! --updates` and the GitHub Action propose, and how they are grouped into
//! pull requests. The keys follow Dependabot's `dependabot.yml`.
//!
//! ```toml
//! [updates]
//! open-pull-requests-limit = 5   # at most this many update pull requests
//! include-dev = true             # also update dev-dependencies (default)
//! ignore = [
//!   { name = "tokio", update-types = ["major"], reason = "migrating later" },
//!   { name = "aws-*" },                          # every update of these crates
//!   { name = "regex", versions = [">= 2"] },
//! ]
//! groups = [
//!   { name = "serde", patterns = ["serde*"] },
//!   { name = "patches", update-types = ["patch"], dependency-type = "production" },
//! ]
//! ```

use std::path::Path;

/// How far an update moves, by the SemVer component that changes
/// (Dependabot's `version-update:semver-*`): `0.8.1 -> 0.9.0` is a minor
/// update even though Cargo treats it as breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpdateType {
    /// Only the patch number changes.
    Patch,
    /// The minor number changes.
    Minor,
    /// The major number changes.
    Major,
}

impl UpdateType {
    /// The name used in `cargoscope.toml` and JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "patch" => Some(Self::Patch),
            "minor" => Some(Self::Minor),
            "major" => Some(Self::Major),
            _ => None,
        }
    }

    /// The update type from `from` to `to`, if both are versions and `to`
    /// is newer.
    #[must_use]
    pub fn between(from: &str, to: &str) -> Option<Self> {
        let from = semver::Version::parse(from).ok()?;
        let to = semver::Version::parse(to).ok()?;
        if to.cmp_precedence(&from) != std::cmp::Ordering::Greater {
            return None;
        }
        Some(if to.major != from.major {
            Self::Major
        } else if to.minor != from.minor {
            Self::Minor
        } else {
            Self::Patch
        })
    }
}

/// Which dependencies a group takes (Dependabot's `dependency-type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyType {
    /// Normal and build dependencies.
    Production,
    /// Dev-dependencies.
    Development,
}

/// An `ignore` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreRule {
    /// Crate name, with `*` wildcards.
    pub name: String,
    /// Target versions to skip; empty with no `update_types` skips them all.
    pub versions: Vec<semver::VersionReq>,
    /// Update types to skip.
    pub update_types: Vec<UpdateType>,
    /// Why, shown in the pull request when an update is skipped.
    pub reason: Option<String>,
}

/// A `groups` entry: matching updates share one pull request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Group name, in the branch and the pull request title.
    pub name: String,
    /// Crate names (with `*`) the group takes; empty takes every crate.
    pub patterns: Vec<String>,
    /// Crate names (with `*`) the group leaves out.
    pub exclude_patterns: Vec<String>,
    /// Only production or only development dependencies.
    pub dependency_type: Option<DependencyType>,
    /// Only these update types; empty takes them all.
    pub update_types: Vec<UpdateType>,
}

/// The `[updates]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatesConfig {
    /// Updates to skip.
    pub ignore: Vec<IgnoreRule>,
    /// Groups, first match wins.
    pub groups: Vec<Group>,
    /// At most this many pull requests (groups first, then crates by name).
    pub open_pull_requests_limit: Option<usize>,
    /// Whether dev-dependencies are updated too.
    pub include_dev: bool,
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self {
            ignore: Vec::new(),
            groups: Vec::new(),
            open_pull_requests_limit: None,
            include_dev: true,
        }
    }
}

/// `*` matches any text (crate names have no other special characters).
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let mut rest = name;
    for (index, part) in parts.iter().enumerate() {
        if index == 0 {
            let Some(stripped) = rest.strip_prefix(part) else {
                return false;
            };
            rest = stripped;
        } else if index == parts.len() - 1 {
            return rest.ends_with(part);
        } else if let Some(position) = rest.find(part) {
            rest = &rest[position + part.len()..];
        } else {
            return false;
        }
    }
    true
}

impl UpdatesConfig {
    /// The rule that skips updating `name` to `to`, an update of type
    /// `update_type`, if any.
    #[must_use]
    pub fn ignored(&self, name: &str, to: &str, update_type: UpdateType) -> Option<&IgnoreRule> {
        let version = semver::Version::parse(to).ok();
        self.ignore.iter().find(|rule| {
            if !wildcard_match(&rule.name, name) {
                return false;
            }
            if rule.versions.is_empty() && rule.update_types.is_empty() {
                return true;
            }
            rule.update_types.contains(&update_type)
                || version.as_ref().is_some_and(|version| {
                    rule.versions
                        .iter()
                        .any(|requirement| requirement.matches(version))
                })
        })
    }

    /// The group an update belongs to, if any.
    #[must_use]
    pub fn group_of(
        &self,
        name: &str,
        dependency_type: DependencyType,
        update_type: UpdateType,
    ) -> Option<&Group> {
        self.groups.iter().find(|group| {
            (group.patterns.is_empty()
                || group
                    .patterns
                    .iter()
                    .any(|pattern| wildcard_match(pattern, name)))
                && !group
                    .exclude_patterns
                    .iter()
                    .any(|pattern| wildcard_match(pattern, name))
                && group
                    .dependency_type
                    .is_none_or(|wanted| wanted == dependency_type)
                && (group.update_types.is_empty() || group.update_types.contains(&update_type))
        })
    }
}

fn strings(table: &toml::Table, key: &str, context: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("[updates] {context}: {key} must be a list of strings"))
            })
            .collect(),
        Some(_) => Err(format!(
            "[updates] {context}: {key} must be a list of strings"
        )),
    }
}

fn check_keys(table: &toml::Table, context: &str, known: &[&str]) -> Result<(), String> {
    match table.keys().find(|key| !known.contains(&key.as_str())) {
        Some(key) => Err(format!("[updates] {context}: unknown key `{key}`")),
        None => Ok(()),
    }
}

fn update_types(table: &toml::Table, context: &str) -> Result<Vec<UpdateType>, String> {
    strings(table, "update-types", context)?
        .iter()
        .map(|text| {
            UpdateType::parse(text).ok_or_else(|| {
                format!("[updates] {context}: update-types are \"major\", \"minor\" or \"patch\", not `{text}`")
            })
        })
        .collect()
}

/// Parses the `[updates]` table of a `cargoscope.toml`.
///
/// # Errors
///
/// Returns a message for unknown keys, wrong types, update types, versions
/// or dependency types, so that a typo never silently opens pull requests.
pub fn parse(table: &toml::Table) -> Result<UpdatesConfig, String> {
    check_keys(
        table,
        "top",
        &[
            "ignore",
            "groups",
            "open-pull-requests-limit",
            "include-dev",
        ],
    )?;
    let mut config = UpdatesConfig::default();
    match table.get("open-pull-requests-limit") {
        None => {}
        Some(toml::Value::Integer(limit)) if *limit >= 0 => {
            config.open_pull_requests_limit = usize::try_from(*limit).ok();
        }
        Some(_) => {
            return Err("[updates] open-pull-requests-limit must be a number from 0".to_owned());
        }
    }
    match table.get("include-dev") {
        None => {}
        Some(toml::Value::Boolean(value)) => config.include_dev = *value,
        Some(_) => return Err("[updates] include-dev must be true or false".to_owned()),
    }
    let entries = |key: &str| -> Result<Vec<&toml::Table>, String> {
        match table.get(key) {
            None => Ok(Vec::new()),
            Some(toml::Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_table()
                        .ok_or_else(|| format!("[updates] {key} entries must be tables"))
                })
                .collect(),
            Some(_) => Err(format!("[updates] {key} must be an array of tables")),
        }
    };
    for entry in entries("ignore")? {
        check_keys(
            entry,
            "ignore",
            &["name", "versions", "update-types", "reason"],
        )?;
        let name = entry
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .ok_or("[updates] ignore entries need a `name`")?
            .to_owned();
        let context = format!("ignore `{name}`");
        let versions = strings(entry, "versions", &context)?
            .iter()
            .map(|text| {
                semver::VersionReq::parse(text)
                    .map_err(|error| format!("[updates] {context}: version `{text}`: {error}"))
            })
            .collect::<Result<_, _>>()?;
        config.ignore.push(IgnoreRule {
            update_types: update_types(entry, &context)?,
            versions,
            reason: entry
                .get("reason")
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
            name,
        });
    }
    for entry in entries("groups")? {
        check_keys(
            entry,
            "groups",
            &[
                "name",
                "patterns",
                "exclude-patterns",
                "dependency-type",
                "update-types",
            ],
        )?;
        let name = entry
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|name| {
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            })
            .ok_or("[updates] groups need a `name` made of letters, digits, `-` and `_`")?
            .to_owned();
        let context = format!("group `{name}`");
        let dependency_type = match entry.get("dependency-type").map(toml::Value::as_str) {
            None => None,
            Some(Some("production")) => Some(DependencyType::Production),
            Some(Some("development")) => Some(DependencyType::Development),
            Some(_) => {
                return Err(format!(
                    "[updates] {context}: dependency-type is \"production\" or \"development\""
                ));
            }
        };
        config.groups.push(Group {
            patterns: strings(entry, "patterns", &context)?,
            exclude_patterns: strings(entry, "exclude-patterns", &context)?,
            update_types: update_types(entry, &context)?,
            dependency_type,
            name,
        });
    }
    Ok(config)
}

/// Reads `[updates]` from the text of a `cargoscope.toml`; the defaults
/// without the table.
///
/// # Errors
///
/// Returns a message for invalid TOML or an invalid `[updates]` table.
pub fn from_toml(text: &str) -> Result<UpdatesConfig, String> {
    let value: toml::Table = toml::from_str(text).map_err(|error| error.to_string())?;
    match value.get("updates") {
        None => Ok(UpdatesConfig::default()),
        Some(toml::Value::Table(table)) => parse(table),
        Some(_) => Err("[updates] must be a table".to_owned()),
    }
}

/// Reads `[updates]` from `project_root/cargoscope.toml`; the defaults when
/// there is no such file or table.
///
/// # Errors
///
/// Returns a message naming the file for unreadable or invalid content.
pub fn load(project_root: &Path) -> Result<UpdatesConfig, String> {
    let path = project_root.join(crate::config::FILE_NAME);
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return Ok(UpdatesConfig::default());
    };
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(format!(
            "{} must be a regular file under 1 MiB",
            path.display()
        ));
    }
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    from_toml(&text).map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{DependencyType, UpdateType, parse, wildcard_match};

    fn config(text: &str) -> super::UpdatesConfig {
        let table: toml::Table = toml::from_str(text).expect("toml");
        parse(
            table
                .get("updates")
                .and_then(toml::Value::as_table)
                .expect("[updates]"),
        )
        .expect("valid")
    }

    #[test]
    fn classifies_updates_by_the_component_that_changes() {
        assert_eq!(
            UpdateType::between("1.2.3", "1.2.4"),
            Some(UpdateType::Patch)
        );
        assert_eq!(
            UpdateType::between("1.2.3", "1.3.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            UpdateType::between("0.8.1", "0.9.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            UpdateType::between("1.9.0", "2.0.0"),
            Some(UpdateType::Major)
        );
        assert_eq!(UpdateType::between("1.2.3", "1.2.3"), None);
    }

    #[test]
    fn matches_wildcards() {
        assert!(wildcard_match("serde*", "serde_json"));
        assert!(wildcard_match("aws-*-types", "aws-sdk-types"));
        assert!(wildcard_match("tokio", "tokio"));
        assert!(!wildcard_match("tokio", "tokio-util"));
        assert!(!wildcard_match("*-sys", "openssl"));
    }

    #[test]
    fn ignores_by_name_versions_and_update_types() {
        let config = config(
            "[updates]\nignore = [\n  { name = \"tokio\", update-types = [\"major\"] },\n  { name = \"aws-*\" },\n  { name = \"regex\", versions = [\">= 2\"] },\n]\n",
        );
        assert!(
            config
                .ignored("tokio", "2.0.0", UpdateType::Major)
                .is_some()
        );
        assert!(
            config
                .ignored("tokio", "1.40.0", UpdateType::Minor)
                .is_none()
        );
        assert!(
            config
                .ignored("aws-config", "1.1.0", UpdateType::Patch)
                .is_some()
        );
        assert!(
            config
                .ignored("regex", "2.0.0", UpdateType::Major)
                .is_some()
        );
        assert!(
            config
                .ignored("regex", "1.11.0", UpdateType::Minor)
                .is_none()
        );
    }

    #[test]
    fn groups_take_the_first_match() {
        let config = config(
            "[updates]\ngroups = [\n  { name = \"serde\", patterns = [\"serde*\"], exclude-patterns = [\"serde_yaml\"] },\n  { name = \"dev\", dependency-type = \"development\" },\n  { name = \"patches\", update-types = [\"patch\"] },\n]\n",
        );
        let group = |name, kind, update| {
            config
                .group_of(name, kind, update)
                .map(|group| group.name.as_str())
        };
        assert_eq!(
            group("serde_json", DependencyType::Production, UpdateType::Minor),
            Some("serde")
        );
        assert_eq!(
            group("serde_yaml", DependencyType::Production, UpdateType::Patch),
            Some("patches")
        );
        assert_eq!(
            group("tempfile", DependencyType::Development, UpdateType::Major),
            Some("dev")
        );
        assert_eq!(
            group("tokio", DependencyType::Production, UpdateType::Minor),
            None
        );
    }

    #[test]
    fn rejects_typos() {
        let error = |text: &str| {
            let table: toml::Table = toml::from_str(text).expect("toml");
            parse(
                table
                    .get("updates")
                    .and_then(toml::Value::as_table)
                    .expect("[updates]"),
            )
            .unwrap_err()
        };
        assert!(error("[updates]\nignores = []\n").contains("unknown key `ignores`"));
        assert!(
            error("[updates]\nignore = [{ name = \"x\", update-types = [\"huge\"] }]\n")
                .contains("update-types")
        );
        assert!(
            error("[updates]\ngroups = [{ name = \"a b\" }]\n").contains("groups need a `name`")
        );
        assert!(error("[updates]\nopen-pull-requests-limit = -1\n").contains("limit"));
    }
}
