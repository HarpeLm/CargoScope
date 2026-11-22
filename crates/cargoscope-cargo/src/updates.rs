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

/// Default anti-supply-chain cooldown window for `fix --updates` (7 days).
pub const DEFAULT_COOLDOWN_DAYS: u64 = 7;

/// How version constraints in `Cargo.toml` are updated (Dependabot's
/// `versioning-strategy`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VersioningStrategy {
    /// CargoScope default: `lockfile-only` unless `--breaking`, in which case
    /// requirements are raised when needed.
    #[default]
    Auto,
    /// Only update `Cargo.lock` within existing `Cargo.toml` requirements.
    LockfileOnly,
    /// Update `Cargo.lock`, raising `Cargo.toml` only when the requirement blocks the upgrade.
    IncreaseIfNecessary,
    /// Always raise the `Cargo.toml` requirement to the target version, even when compatible.
    Increase,
    /// Widen `Cargo.toml` bounds (e.g. `>=1.0, <3.0`) to keep old compatibility while allowing the new line.
    Widen,
}

impl VersioningStrategy {
    /// Parses a strategy name from CLI, `cargoscope.toml`, or `.github/dependabot.yml`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "auto" => Some(Self::Auto),
            "lockfile-only" => Some(Self::LockfileOnly),
            "increase-if-necessary" => Some(Self::IncreaseIfNecessary),
            "increase" => Some(Self::Increase),
            "widen" => Some(Self::Widen),
            _ => None,
        }
    }

    /// Machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::LockfileOnly => "lockfile-only",
            Self::IncreaseIfNecessary => "increase-if-necessary",
            Self::Increase => "increase",
            Self::Widen => "widen",
        }
    }
}

/// Anti-supply-chain cooldown rules before proposing newly published crate
/// versions in `fix --updates`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooldownConfig {
    /// Default minimum age in days before proposing an update (default: 7).
    pub default_days: u64,
    /// Minimum age for major updates (`semver-major-days`).
    pub semver_major_days: Option<u64>,
    /// Minimum age for minor updates (`semver-minor-days`).
    pub semver_minor_days: Option<u64>,
    /// Minimum age for patch updates (`semver-patch-days`).
    pub semver_patch_days: Option<u64>,
    /// If non-empty, only crates matching these wildcard patterns get cooldown.
    pub include: Vec<String>,
    /// Wildcard patterns exempt from cooldown (`days = 0` unless overridden).
    pub exclude: Vec<String>,
    /// Per-dependency cooldown overrides `(pattern, days)` (first match wins).
    pub overrides: Vec<(String, u64)>,
}

impl Default for CooldownConfig {
    fn default() -> Self {
        Self {
            default_days: DEFAULT_COOLDOWN_DAYS,
            semver_major_days: None,
            semver_minor_days: None,
            semver_patch_days: None,
            include: Vec::new(),
            exclude: Vec::new(),
            overrides: Vec::new(),
        }
    }
}

impl CooldownConfig {
    /// Effective cooldown in days for crate `name` and `update_type`.
    #[must_use]
    pub fn days_for(&self, name: &str, update_type: UpdateType) -> u64 {
        if let Some((_, days)) = self
            .overrides
            .iter()
            .find(|(pattern, _)| wildcard_match(pattern, name))
        {
            return *days;
        }
        if self.exclude.iter().any(|p| wildcard_match(p, name)) {
            return 0;
        }
        if !self.include.is_empty() && !self.include.iter().any(|p| wildcard_match(p, name)) {
            return 0;
        }
        match update_type {
            UpdateType::Major => self.semver_major_days.unwrap_or(self.default_days),
            UpdateType::Minor => self.semver_minor_days.unwrap_or(self.default_days),
            UpdateType::Patch => self.semver_patch_days.unwrap_or(self.default_days),
        }
    }
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
    /// Manifest requirement update strategy.
    pub versioning_strategy: VersioningStrategy,
    /// Release age cooldown rules (`default_days = 7`).
    pub cooldown: CooldownConfig,
    /// Default PR labels (also read from `.github/dependabot.yml`).
    pub labels: Vec<String>,
    /// Default PR reviewers (also read from `.github/dependabot.yml`).
    pub reviewers: Vec<String>,
    /// Default commit/PR title prefix (also read from `.github/dependabot.yml`).
    pub commit_prefix: Option<String>,
    /// Schedule interval from `.github/dependabot.yml`, if any.
    pub schedule_interval: Option<String>,
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self {
            ignore: Vec::new(),
            groups: Vec::new(),
            open_pull_requests_limit: None,
            include_dev: true,
            versioning_strategy: VersioningStrategy::Auto,
            cooldown: CooldownConfig::default(),
            labels: Vec::new(),
            reviewers: Vec::new(),
            commit_prefix: None,
            schedule_interval: None,
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

fn parse_days_value(value: &toml::Value, context: &str) -> Result<u64, String> {
    match value {
        toml::Value::Integer(days) if *days >= 0 => {
            u64::try_from(*days).map_err(|_| format!("[updates] {context}: days out of range"))
        }
        toml::Value::String(text) => {
            let trimmed = text.trim();
            let stripped = trimmed.strip_suffix('d').unwrap_or(trimmed).trim();
            stripped.parse::<u64>().map_err(|_| {
                format!("[updates] {context}: expected non-negative days (e.g. 7 or \"7d\"), not `{text}`")
            })
        }
        _ => Err(format!(
            "[updates] {context}: expected non-negative integer days (e.g. 7 or \"7d\")"
        )),
    }
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
            "versioning-strategy",
            "cooldown",
            "labels",
            "reviewers",
            "commit-prefix",
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
    match table.get("versioning-strategy") {
        None => {}
        Some(toml::Value::String(text)) => {
            config.versioning_strategy = VersioningStrategy::parse(text).ok_or_else(|| {
                format!(
                    "[updates] versioning-strategy must be auto, lockfile-only, increase-if-necessary, increase, or widen, not `{text}`"
                )
            })?;
        }
        Some(_) => return Err("[updates] versioning-strategy must be a string".to_owned()),
    }
    if let Some(cd) = table.get("cooldown") {
        match cd {
            toml::Value::Table(cd_table) => {
                check_keys(
                    cd_table,
                    "cooldown",
                    &[
                        "default",
                        "default-days",
                        "semver-major-days",
                        "semver-minor-days",
                        "semver-patch-days",
                        "include",
                        "exclude",
                        "overrides",
                    ],
                )?;
                if let Some(v) = cd_table
                    .get("default-days")
                    .or_else(|| cd_table.get("default"))
                {
                    config.cooldown.default_days = parse_days_value(v, "cooldown.default-days")?;
                }
                if let Some(v) = cd_table.get("semver-major-days") {
                    config.cooldown.semver_major_days =
                        Some(parse_days_value(v, "cooldown.semver-major-days")?);
                }
                if let Some(v) = cd_table.get("semver-minor-days") {
                    config.cooldown.semver_minor_days =
                        Some(parse_days_value(v, "cooldown.semver-minor-days")?);
                }
                if let Some(v) = cd_table.get("semver-patch-days") {
                    config.cooldown.semver_patch_days =
                        Some(parse_days_value(v, "cooldown.semver-patch-days")?);
                }
                config.cooldown.include = strings(cd_table, "include", "cooldown")?;
                config.cooldown.exclude = strings(cd_table, "exclude", "cooldown")?;
                if let Some(overrides) = cd_table.get("overrides") {
                    let overrides = overrides
                        .as_table()
                        .ok_or("[updates] cooldown.overrides must be a table of crate = days")?;
                    for (name, val) in overrides {
                        let days = parse_days_value(val, &format!("cooldown.overrides.{name}"))?;
                        config.cooldown.overrides.push((name.clone(), days));
                    }
                }
            }
            other => {
                config.cooldown.default_days = parse_days_value(other, "cooldown")?;
            }
        }
    }
    config.labels = strings(table, "labels", "top")?;
    config.reviewers = strings(table, "reviewers", "top")?;
    match table.get("commit-prefix") {
        None => {}
        Some(toml::Value::String(prefix)) => config.commit_prefix = Some(prefix.clone()),
        Some(_) => return Err("[updates] commit-prefix must be a string".to_owned()),
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

/// Reads `[updates]` from `project_root/cargoscope.toml`, falling back to
/// `.github/dependabot.yml` (`package-ecosystem: "cargo"`) when
/// `cargoscope.toml` is absent or defines no `[updates]` table.
///
/// # Errors
///
/// Returns a message naming the file for unreadable or invalid content.
pub fn load(project_root: &Path) -> Result<UpdatesConfig, String> {
    let path = project_root.join(crate::config::FILE_NAME);
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Err(format!(
                "{} must be a regular file under 1 MiB",
                path.display()
            ));
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let value: toml::Table =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        if let Some(updates) = value.get("updates") {
            let table = updates
                .as_table()
                .ok_or_else(|| format!("{}: [updates] must be a table", path.display()))?;
            return parse(table).map_err(|error| format!("{}: {error}", path.display()));
        }
    }
    Ok(crate::dependabot::load(project_root).unwrap_or_default())
}

/// Appends an ignore rule to `[updates] ignore` in `contents` (`cargoscope.toml`),
/// creating `[updates]` and `ignore` if absent while keeping existing formatting
/// and comments. Returns the updated contents and `false` if an identical rule
/// already exists.
///
/// # Errors
///
/// Returns a message when `contents` is not valid TOML, or when `[updates]` or
/// `[updates] ignore` has an incompatible type.
pub fn add_ignore_rule(
    contents: &str,
    name: &str,
    versions: Option<&[String]>,
    update_types: Option<&[UpdateType]>,
    reason: Option<&str>,
) -> Result<(String, bool), String> {
    let mut document: toml_edit::DocumentMut =
        contents.parse().map_err(|error| format!("{error}"))?;
    let updates_item = document
        .as_table_mut()
        .entry("updates")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let updates_table = updates_item
        .as_table_like_mut()
        .ok_or_else(|| "[updates] must be a table".to_owned())?;
    let ignore_item = updates_table
        .entry("ignore")
        .or_insert_with(|| toml_edit::value(toml_edit::Array::new()));
    let ignore_array = ignore_item
        .as_value_mut()
        .and_then(toml_edit::Value::as_array_mut)
        .ok_or_else(|| "[updates] ignore must be an array of tables".to_owned())?;

    let desired_versions: Vec<&str> = versions.unwrap_or(&[]).iter().map(String::as_str).collect();
    let desired_types: Vec<&str> = update_types
        .unwrap_or(&[])
        .iter()
        .map(|kind| kind.as_str())
        .collect();
    let already_exists = ignore_array.iter().any(|item| {
        let Some(table) = item.as_inline_table() else {
            return false;
        };
        let same_name = table.get("name").and_then(toml_edit::Value::as_str) == Some(name);
        let entry_list = |key: &str| -> Vec<&str> {
            table
                .get(key)
                .and_then(toml_edit::Value::as_array)
                .map(|arr| arr.iter().filter_map(toml_edit::Value::as_str).collect())
                .unwrap_or_default()
        };
        same_name
            && entry_list("versions") == desired_versions
            && entry_list("update-types") == desired_types
    });
    if already_exists {
        return Ok((contents.to_owned(), false));
    }

    let mut rule = toml_edit::InlineTable::new();
    rule.insert("name", toml_edit::Value::from(name));
    if !desired_versions.is_empty() {
        let mut arr = toml_edit::Array::new();
        for v in desired_versions {
            arr.push(v);
        }
        rule.insert("versions", toml_edit::Value::Array(arr));
    }
    if !desired_types.is_empty() {
        let mut arr = toml_edit::Array::new();
        for kind in desired_types {
            arr.push(kind);
        }
        rule.insert("update-types", toml_edit::Value::Array(arr));
    }
    if let Some(reason) = reason.filter(|r| !r.trim().is_empty()) {
        rule.insert("reason", toml_edit::Value::from(reason));
    }
    let mut val = toml_edit::Value::InlineTable(rule);
    val.decor_mut().set_prefix("\n  ");
    ignore_array.push_formatted(val);
    ignore_array.set_trailing("\n");
    ignore_array.set_trailing_comma(true);

    Ok((document.to_string(), true))
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

    #[test]
    fn adds_ignore_rule_and_stays_idempotent() {
        let original = "# project policy\n[advisories]\nignore = []\n";
        let versions = vec!["1.0.210".to_owned()];
        let (edited, added) = super::add_ignore_rule(
            original,
            "serde",
            Some(&versions),
            None,
            Some("ignored from pull request"),
        )
        .expect("valid edit");
        assert!(added);
        assert!(edited.contains("# project policy\n"), "{edited}");
        assert!(
            edited.contains(
                "{ name = \"serde\", versions = [\"1.0.210\"], reason = \"ignored from pull request\" }"
            ),
            "{edited}"
        );

        let (again, added_again) =
            super::add_ignore_rule(&edited, "serde", Some(&versions), None, None).expect("valid");
        assert!(!added_again);
        assert_eq!(again, edited);

        let types = vec![super::UpdateType::Major];
        let (with_major, added_major) =
            super::add_ignore_rule(&edited, "ureq", None, Some(&types), None).expect("valid");
        assert!(added_major);
        let table: toml::Table = toml::from_str(&with_major).expect("valid TOML");
        let parsed = super::parse(table["updates"].as_table().unwrap()).expect("valid [updates]");
        assert_eq!(parsed.ignore.len(), 2);
    }

    #[test]
    fn cooldown_defaults_to_7d_and_dependabot_fallback_works() {
        let cfg = super::UpdatesConfig::default();
        assert_eq!(cfg.cooldown.default_days, 7);
        assert_eq!(cfg.cooldown.days_for("serde", super::UpdateType::Minor), 7);

        let parsed = super::from_toml(
            r#"
[updates]
versioning-strategy = "widen"
labels = ["deps", "rust"]
reviewers = ["alice"]
commit-prefix = "chore(deps): "

[updates.cooldown]
default-days = 7
semver-major-days = 14
overrides = { serde = 1 }
exclude = ["anyhow"]
"#,
        )
        .expect("valid config");
        assert_eq!(parsed.versioning_strategy, super::VersioningStrategy::Widen);
        assert_eq!(
            parsed.cooldown.days_for("serde", super::UpdateType::Major),
            1
        );
        assert_eq!(
            parsed.cooldown.days_for("anyhow", super::UpdateType::Major),
            0
        );
        assert_eq!(
            parsed.cooldown.days_for("tokio", super::UpdateType::Major),
            14
        );
        assert_eq!(
            parsed.cooldown.days_for("tokio", super::UpdateType::Patch),
            7
        );

        let dir = std::env::temp_dir().join(format!("cargoscope-dep-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".github")).expect("mkdir");
        std::fs::write(
            dir.join(".github/dependabot.yml"),
            r#"
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    versioning-strategy: "lockfile-only"
    cooldown:
      default-days: 5
      include: ["tokio"]
    labels: ["dependencies"]
"#,
        )
        .expect("write dependabot.yml");
        let loaded = super::load(&dir).expect("load dependabot fallback");
        assert_eq!(
            loaded.versioning_strategy,
            super::VersioningStrategy::LockfileOnly
        );
        assert_eq!(loaded.cooldown.default_days, 5);
        assert_eq!(loaded.labels, vec!["dependencies"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
