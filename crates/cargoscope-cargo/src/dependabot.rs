//! Native `.github/dependabot.yml` loader (`package-ecosystem: "cargo"`).
//!
//! Translates Dependabot v2 settings (`schedule`, `groups`, `ignore`,
//! `open-pull-requests-limit`, `versioning-strategy`, `cooldown`, `labels`,
//! `reviewers`, `commit-message`, `allow`) into [`UpdatesConfig`] so Cargo
//! projects can migrate without rewriting configuration.

use std::path::Path;

use crate::updates::{
    CooldownConfig, DependencyType, Group, IgnoreRule, UpdateType, UpdatesConfig,
    VersioningStrategy,
};

#[derive(Debug, Clone)]
enum Yaml {
    Scalar(String),
    Seq(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Scalar(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_seq(&self) -> Option<&[Yaml]> {
        match self {
            Self::Seq(items) => Some(items),
            _ => None,
        }
    }

    fn as_map(&self) -> Option<&[(String, Yaml)]> {
        match self {
            Self::Map(entries) => Some(entries),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&Yaml> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    fn strings(&self) -> Vec<String> {
        match self {
            Self::Seq(items) => items
                .iter()
                .filter_map(Self::as_str)
                .map(str::to_owned)
                .collect(),
            Self::Scalar(s) => vec![s.clone()],
            Self::Map(_) => Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct Line<'a> {
    indent: usize,
    text: &'a str,
}

fn strip_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let bytes = line.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single
                && !in_double
                && (idx == 0 || bytes[idx - 1].is_ascii_whitespace()) =>
            {
                return &line[..idx];
            }
            _ => {}
        }
    }
    line
}

fn unquote(text: &str) -> String {
    let t = text.trim();
    if let Some(inner) = t.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        inner.replace("\\\"", "\"")
    } else if let Some(inner) = t.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        inner.replace("''", "'")
    } else {
        t.to_owned()
    }
}

fn parse_inline_scalar_or_seq(raw: &str) -> Yaml {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let items = split_top_level(inner)
            .into_iter()
            .filter(|part| !part.is_empty())
            .map(|part| Yaml::Scalar(unquote(part)))
            .collect();
        Yaml::Seq(items)
    } else {
        Yaml::Scalar(unquote(trimmed))
    }
}

fn split_top_level(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut start = 0;
    for (idx, b) in text.bytes().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b',' if !in_single && !in_double => {
                out.push(text[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn split_key_value(text: &str) -> Option<(&str, &str)> {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, b) in text.bytes().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b':' if !in_single && !in_double => {
                let after = &text[idx + 1..];
                if after.is_empty() || after.starts_with(char::is_whitespace) {
                    return Some((text[..idx].trim(), after.trim()));
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_yaml_lines(lines: &[Line<'_>], pos: &mut usize, min_indent: usize) -> Yaml {
    if *pos >= lines.len() {
        return Yaml::Map(Vec::new());
    }
    if lines[*pos].text.starts_with("- ") || lines[*pos].text == "-" {
        parse_seq(lines, pos, lines[*pos].indent)
    } else {
        parse_map(lines, pos, min_indent)
    }
}

fn parse_seq(lines: &[Line<'_>], pos: &mut usize, seq_indent: usize) -> Yaml {
    let mut items = Vec::new();
    while *pos < lines.len() {
        let line = &lines[*pos];
        if line.indent < seq_indent || (!line.text.starts_with("- ") && line.text != "-") {
            break;
        }
        if line.indent != seq_indent {
            break;
        }
        let rest = line.text.strip_prefix('-').unwrap_or("").trim();
        *pos += 1;
        if rest.is_empty() {
            if *pos < lines.len() && lines[*pos].indent > seq_indent {
                let child_indent = lines[*pos].indent;
                items.push(parse_yaml_lines(lines, pos, child_indent));
            } else {
                items.push(Yaml::Map(Vec::new()));
            }
        } else if let Some((k, v)) = split_key_value(rest) {
            // `- key: val` starts a map item at pseudo-indent `seq_indent + 2`.
            let key = unquote(k);
            let item_indent = seq_indent + 2;
            let first_val = if v.is_empty() {
                if *pos < lines.len() && lines[*pos].indent > item_indent {
                    let next_indent = lines[*pos].indent;
                    parse_yaml_lines(lines, pos, next_indent)
                } else if *pos < lines.len()
                    && lines[*pos].indent == item_indent
                    && (lines[*pos].text.starts_with("- ") || lines[*pos].text == "-")
                {
                    parse_seq(lines, pos, item_indent)
                } else {
                    Yaml::Map(Vec::new())
                }
            } else {
                parse_inline_scalar_or_seq(v)
            };
            let mut entries = vec![(key, first_val)];
            if *pos < lines.len() && lines[*pos].indent > seq_indent {
                let tail_indent = lines[*pos].indent;
                if let Yaml::Map(more) = parse_map(lines, pos, tail_indent) {
                    entries.extend(more);
                }
            }
            items.push(Yaml::Map(entries));
        } else {
            items.push(parse_inline_scalar_or_seq(rest));
        }
    }
    Yaml::Seq(items)
}

fn parse_map(lines: &[Line<'_>], pos: &mut usize, map_indent: usize) -> Yaml {
    let mut entries = Vec::new();
    while *pos < lines.len() {
        let line = &lines[*pos];
        if line.indent < map_indent || line.text.starts_with("- ") || line.text == "-" {
            break;
        }
        if line.indent > map_indent {
            *pos += 1;
            continue;
        }
        let Some((k, v)) = split_key_value(line.text) else {
            *pos += 1;
            continue;
        };
        let key = unquote(k);
        *pos += 1;
        let val = if v.is_empty() {
            if *pos < lines.len() && lines[*pos].indent > map_indent {
                let next_indent = lines[*pos].indent;
                parse_yaml_lines(lines, pos, next_indent)
            } else if *pos < lines.len()
                && lines[*pos].indent == map_indent
                && (lines[*pos].text.starts_with("- ") || lines[*pos].text == "-")
            {
                parse_seq(lines, pos, map_indent)
            } else {
                Yaml::Map(Vec::new())
            }
        } else {
            parse_inline_scalar_or_seq(v)
        };
        entries.push((key, val));
    }
    Yaml::Map(entries)
}

fn parse_yaml(text: &str) -> Yaml {
    let lines: Vec<Line<'_>> = text
        .lines()
        .filter_map(|raw| {
            let cleaned = strip_comment(raw).trim_end();
            let trimmed = cleaned.trim_start();
            if trimmed.is_empty() || trimmed == "---" {
                return None;
            }
            Some(Line {
                indent: cleaned.len() - trimmed.len(),
                text: trimmed,
            })
        })
        .collect();
    let mut pos = 0;
    let indent = lines.first().map_or(0, |l| l.indent);
    parse_yaml_lines(&lines, &mut pos, indent)
}

fn map_update_types(raw: &[String]) -> Vec<UpdateType> {
    let mut out = Vec::new();
    for item in raw {
        let mapped = match item.as_str() {
            "patch" | "version-update:semver-patch" => Some(UpdateType::Patch),
            "minor" | "version-update:semver-minor" => Some(UpdateType::Minor),
            "major" | "version-update:semver-major" => Some(UpdateType::Major),
            _ => None,
        };
        if let Some(kind) = mapped
            && !out.contains(&kind)
        {
            out.push(kind);
        }
    }
    out
}

/// Parses `.github/dependabot.yml` content and returns an [`UpdatesConfig`]
/// merged from every `package-ecosystem: "cargo"` entry, or `None` when no
/// Cargo ecosystem block exists.
#[must_use]
pub fn parse_dependabot_yml(text: &str) -> Option<UpdatesConfig> {
    let root = parse_yaml(text);
    let updates = root.get("updates")?.as_seq()?;
    let cargo_blocks: Vec<&Yaml> = updates
        .iter()
        .filter(|entry| {
            entry
                .get("package-ecosystem")
                .and_then(Yaml::as_str)
                .is_some_and(|eco| eco.eq_ignore_ascii_case("cargo"))
        })
        .collect();
    if cargo_blocks.is_empty() {
        return None;
    }

    let mut config = UpdatesConfig::default();
    for block in cargo_blocks {
        if let Some(limit) = block
            .get("open-pull-requests-limit")
            .and_then(Yaml::as_str)
            .and_then(|s| s.parse::<usize>().ok())
        {
            config.open_pull_requests_limit = Some(limit);
        }
        if let Some(strategy) = block
            .get("versioning-strategy")
            .and_then(Yaml::as_str)
            .and_then(VersioningStrategy::parse)
        {
            config.versioning_strategy = strategy;
        }
        if let Some(interval) = block
            .get("schedule")
            .and_then(|s| s.get("interval"))
            .and_then(Yaml::as_str)
        {
            config.schedule_interval = Some(interval.to_owned());
        }
        if let Some(labels) = block.get("labels") {
            for label in labels.strings() {
                if !config.labels.contains(&label) {
                    config.labels.push(label);
                }
            }
        }
        if let Some(reviewers) = block.get("reviewers") {
            for rev in reviewers.strings() {
                if !config.reviewers.contains(&rev) {
                    config.reviewers.push(rev);
                }
            }
        }
        if let Some(prefix) = block
            .get("commit-message")
            .and_then(|c| c.get("prefix"))
            .and_then(Yaml::as_str)
        {
            config.commit_prefix = Some(prefix.to_owned());
        }
        if let Some(allow) = block.get("allow").and_then(Yaml::as_seq) {
            let allows_dev = allow.iter().any(|entry| {
                matches!(
                    entry.get("dependency-type").and_then(Yaml::as_str),
                    None | Some("all" | "development" | "indirect")
                )
            });
            if !allow.is_empty() && !allows_dev {
                config.include_dev = false;
            }
        }
        if let Some(cd) = block.get("cooldown") {
            parse_dependabot_cooldown(cd, &mut config.cooldown);
        }
        if let Some(ignores) = block.get("ignore").and_then(Yaml::as_seq) {
            for rule in ignores {
                let Some(name) = rule
                    .get("dependency-name")
                    .and_then(Yaml::as_str)
                    .filter(|s| !s.is_empty())
                else {
                    continue;
                };
                let versions = rule
                    .get("versions")
                    .map(Yaml::strings)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|v| semver::VersionReq::parse(&v).ok())
                    .collect();
                let update_types = rule
                    .get("update-types")
                    .map(|u| map_update_types(&u.strings()))
                    .unwrap_or_default();
                config.ignore.push(IgnoreRule {
                    name: name.to_owned(),
                    versions,
                    update_types,
                    reason: Some("configured in .github/dependabot.yml".to_owned()),
                });
            }
        }
        if let Some(groups) = block.get("groups").and_then(Yaml::as_map) {
            for (name, body) in groups {
                let dependency_type = match body.get("dependency-type").and_then(Yaml::as_str) {
                    Some("production") => Some(DependencyType::Production),
                    Some("development") => Some(DependencyType::Development),
                    _ => None,
                };
                config.groups.push(Group {
                    name: name.clone(),
                    patterns: body.get("patterns").map(Yaml::strings).unwrap_or_default(),
                    exclude_patterns: body
                        .get("exclude-patterns")
                        .map(Yaml::strings)
                        .unwrap_or_default(),
                    dependency_type,
                    update_types: body
                        .get("update-types")
                        .map(|u| map_update_types(&u.strings()))
                        .unwrap_or_default(),
                });
            }
        }
    }
    Some(config)
}

fn parse_dependabot_cooldown(node: &Yaml, cooldown: &mut CooldownConfig) {
    if let Some(days) = node
        .get("default-days")
        .and_then(Yaml::as_str)
        .and_then(|s| s.parse::<u64>().ok())
    {
        cooldown.default_days = days;
    }
    for (key, dst) in [
        ("semver-major-days", &mut cooldown.semver_major_days),
        ("semver-minor-days", &mut cooldown.semver_minor_days),
        ("semver-patch-days", &mut cooldown.semver_patch_days),
    ] {
        if let Some(days) = node
            .get(key)
            .and_then(Yaml::as_str)
            .and_then(|s| s.parse::<u64>().ok())
        {
            *dst = Some(days);
        }
    }
    if let Some(inc) = node.get("include") {
        cooldown.include.extend(inc.strings());
    }
    if let Some(exc) = node.get("exclude") {
        cooldown.exclude.extend(exc.strings());
    }
}

/// Loads `.github/dependabot.yml` (or `.yaml`) from `project_root` if present
/// and defining at least one `cargo` ecosystem entry.
#[must_use]
pub fn load(project_root: &Path) -> Option<UpdatesConfig> {
    for rel in [".github/dependabot.yml", ".github/dependabot.yaml"] {
        let path = project_root.join(rel);
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > 1024 * 1024 {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Some(config) = parse_dependabot_yml(&text)
        {
            return Some(config);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse_dependabot_yml;
    use crate::updates::{DependencyType, UpdateType, VersioningStrategy};

    #[test]
    fn parses_cargo_ecosystem_from_dependabot_yml() {
        let yml = r#"
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    versioning-strategy: increase-if-necessary
    labels:
      - "dependencies"
      - "rust"
    reviewers: ["HarpeLm"]
    commit-message:
      prefix: "chore(deps): "
    cooldown:
      default-days: 5
      semver-major-days: 14
      exclude:
        - "serde*"
    ignore:
      - dependency-name: "tokio"
        update-types: ["version-update:semver-major"]
      - dependency-name: "regex"
        versions: [">= 2.0"]
    groups:
      serde:
        patterns: ["serde*"]
        dependency-type: "production"
        update-types: ["minor", "patch"]
"#;
        let cfg = parse_dependabot_yml(yml).expect("cargo config");
        assert_eq!(cfg.open_pull_requests_limit, Some(10));
        assert_eq!(
            cfg.versioning_strategy,
            VersioningStrategy::IncreaseIfNecessary
        );
        assert_eq!(cfg.schedule_interval.as_deref(), Some("daily"));
        assert_eq!(cfg.labels, vec!["dependencies", "rust"]);
        assert_eq!(cfg.reviewers, vec!["HarpeLm"]);
        assert_eq!(cfg.commit_prefix.as_deref(), Some("chore(deps): "));
        assert_eq!(cfg.cooldown.default_days, 5);
        assert_eq!(cfg.cooldown.semver_major_days, Some(14));
        assert_eq!(cfg.cooldown.days_for("serde_json", UpdateType::Major), 0);
        assert_eq!(cfg.cooldown.days_for("clap", UpdateType::Major), 14);
        assert_eq!(cfg.cooldown.days_for("clap", UpdateType::Minor), 5);
        assert!(cfg.ignored("tokio", "2.0.0", UpdateType::Major).is_some());
        assert!(cfg.ignored("regex", "2.1.0", UpdateType::Minor).is_some());
        assert_eq!(cfg.groups.len(), 1);
        assert_eq!(cfg.groups[0].name, "serde");
        assert_eq!(
            cfg.groups[0].dependency_type,
            Some(DependencyType::Production)
        );
        assert_eq!(
            cfg.groups[0].update_types,
            vec![UpdateType::Minor, UpdateType::Patch]
        );
    }
}
