//! Detection, planning, and in-place updates for GitHub Actions workflows
//! (`.github/workflows/*.yml`) and container base images (`Dockerfile*`), so Rust
//! repositories can replace Dependabot without leaving a separate config behind.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::updates::{UpdateType, UpdatesConfig};

/// One `uses: owner/repo@ref` entry found in a workflow or composite action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionUse {
    /// Path relative to the repository root (e.g. `.github/workflows/ci.yml`).
    pub file: String,
    /// 0-based line index inside `file`.
    pub line_index: usize,
    /// `owner/repo` portion used for GitHub API queries and ignore rules.
    pub owner_repo: String,
    /// Full action path before `@` (may include a subpath like `github/codeql-action/upload-sarif`).
    pub action_path: String,
    /// Raw ref after `@` (tag like `v4.1.0` or 40-char commit SHA).
    pub raw_ref: String,
    /// Optional version extracted from a trailing comment (`# v4.2.1` on SHA pins).
    pub comment_version: Option<String>,
    /// True when `raw_ref` is a 40-character hexadecimal git SHA.
    pub pinned_sha: bool,
}

/// One `FROM` base-image instruction discovered in a `Dockerfile` or `Containerfile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerFrom {
    /// Path relative to the repository root (e.g. `Dockerfile`).
    pub file: String,
    /// 0-based line index inside `file`.
    pub line_index: usize,
    /// Image reference without tag/digest (e.g. `rust`, `ghcr.io/owner/app`).
    pub image: String,
    /// Optional tag after `:` (e.g. `1.82-slim-bookworm`).
    pub raw_tag: Option<String>,
    /// Optional digest after `@` (e.g. `sha256:...`).
    pub raw_digest: Option<String>,
}

/// Candidate remote tag/release metadata supplied by the caller/cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRelease {
    pub tag: String,
    pub published_unix: Option<u64>,
    pub sha: Option<String>,
    pub digest: Option<String>,
}

/// Planned outcome for an action or Docker base image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcosystemPlan {
    Update {
        target_ref: String,
        display_to: String,
        update_type: UpdateType,
        sha: Option<String>,
        digest: Option<String>,
        cooldown_skipped: Option<String>,
    },
    Cooldown {
        to: String,
        age_days: u64,
        required_days: u64,
    },
    Ignored {
        to: String,
        reason: String,
    },
}

/// Parses a loose version tag (`v4`, `4.2`, `1.85-slim-bookworm`) into `(SemVer, variant_suffix)`.
#[must_use]
pub fn parse_tag_version(tag: &str) -> Option<(semver::Version, String)> {
    let trimmed = tag.trim().trim_start_matches('v');
    if trimmed.is_empty() || !trimmed.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let split_at = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(trimmed.len());
    let num_part = trimmed[..split_at].trim_end_matches('.');
    let suffix = &trimmed[split_at..];
    if num_part.is_empty() {
        return None;
    }
    let mut parts = num_part.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().map_or(Some(0), |p| p.parse::<u64>().ok())?;
    let patch = parts.next().map_or(Some(0), |p| p.parse::<u64>().ok())?;
    if parts.next().is_some() {
        return None;
    }
    Some((semver::Version::new(major, minor, patch), suffix.to_owned()))
}

fn is_hex_sha40(text: &str) -> bool {
    text.len() == 40 && text.chars().all(|c| c.is_ascii_hexdigit())
}

fn rel_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Discovers all `uses: owner/repo@ref` lines in `.github/workflows/*.{yml,yaml}`
/// and `.github/actions/*/*.{yml,yaml}`.
#[must_use]
pub fn find_action_uses(root: &Path) -> Vec<ActionUse> {
    let mut files = Vec::new();
    let workflows = root.join(".github").join("workflows");
    collect_yaml_files(&workflows, &mut files);
    let actions = root.join(".github").join("actions");
    if let Ok(entries) = fs::read_dir(actions) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                for name in ["action.yml", "action.yaml"] {
                    let f = p.join(name);
                    if f.is_file() {
                        files.push(f);
                    }
                }
            }
        }
    }
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        let label = rel_label(root, &file);
        out.extend(parse_action_uses_from_str(&label, &text));
    }
    out
}

fn collect_yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yml" || e == "yaml")
        {
            out.push(path);
        }
    }
}

/// Parses `uses: owner/repo@ref` references from workflow YAML text.
#[must_use]
pub fn parse_action_uses_from_str(file: &str, text: &str) -> Vec<ActionUse> {
    let mut out = Vec::new();
    for (line_index, raw_line) in text.lines().enumerate() {
        let trimmed = raw_line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        let after_dash = trimmed.strip_prefix('-').map_or(trimmed, str::trim_start);
        let Some(rest) = after_dash.strip_prefix("uses:") else {
            continue;
        };
        let rest = rest.trim_start();
        let (value_part, comment_part) = split_yaml_inline_comment(rest);
        let spec = value_part.trim().trim_matches('"').trim_matches('\'');
        if spec.is_empty()
            || spec.starts_with("./")
            || spec.starts_with("docker://")
            || spec.contains("${{")
        {
            continue;
        }
        let Some((action_path, raw_ref)) = spec.split_once('@') else {
            continue;
        };
        let mut segs = action_path.split('/');
        let (Some(owner), Some(repo)) = (segs.next(), segs.next()) else {
            continue;
        };
        if owner.is_empty() || repo.is_empty() {
            continue;
        }
        let owner_repo = format!("{owner}/{repo}");
        let raw_ref = raw_ref.trim().to_owned();
        if raw_ref.is_empty() {
            continue;
        }
        let pinned_sha = is_hex_sha40(&raw_ref);
        let comment_version = comment_part.and_then(|c| {
            c.split_whitespace()
                .find(|tok| parse_tag_version(tok).is_some())
                .map(str::to_owned)
        });
        out.push(ActionUse {
            file: file.to_owned(),
            line_index,
            owner_repo,
            action_path: action_path.to_owned(),
            raw_ref,
            comment_version,
            pinned_sha,
        });
    }
    out
}

fn split_yaml_inline_comment(text: &str) -> (&str, Option<&str>) {
    let bytes = text.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for (idx, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single
                && !in_double
                && (idx == 0 || bytes[idx - 1].is_ascii_whitespace()) =>
            {
                return (&text[..idx], Some(&text[idx + 1..]));
            }
            _ => {}
        }
    }
    (text, None)
}

/// Discovers `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, and `Containerfile`
/// base-image instructions under `root`.
#[must_use]
pub fn find_docker_froms(root: &Path) -> Vec<DockerFrom> {
    let mut files = Vec::new();
    collect_dockerfiles(root, 0, &mut files);
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        let label = rel_label(root, &file);
        out.extend(parse_docker_froms_from_str(&label, &text));
    }
    out
}

fn is_dockerfile_name(name: &str) -> bool {
    name == "Dockerfile"
        || name == "Containerfile"
        || name.starts_with("Dockerfile.")
        || name.ends_with(".Dockerfile")
}

fn collect_dockerfiles(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 4 || out.len() >= 128 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if path.is_dir() {
            if matches!(name, "target" | ".git" | "node_modules" | "vendor") {
                continue;
            }
            collect_dockerfiles(&path, depth + 1, out);
        } else if path.is_file() && is_dockerfile_name(name) {
            out.push(path);
        }
    }
}

/// Parses `FROM` instructions from Dockerfile contents, skipping `scratch`,
/// build args (`$...`), and earlier multi-stage alias names.
#[must_use]
pub fn parse_docker_froms_from_str(file: &str, text: &str) -> Vec<DockerFrom> {
    let mut out = Vec::new();
    let mut stages = BTreeSet::new();
    for (line_index, raw_line) in text.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut tokens = trimmed.split_whitespace();
        let Some(first) = tokens.next() else {
            continue;
        };
        if !first.eq_ignore_ascii_case("FROM") {
            continue;
        }
        let mut rest: Vec<&str> = tokens.collect();
        while rest.first().is_some_and(|t| t.starts_with("--")) {
            rest.remove(0);
        }
        let Some(&image_spec) = rest.first() else {
            continue;
        };
        if rest.len() >= 3 && rest[1].eq_ignore_ascii_case("AS") {
            stages.insert(rest[2].to_ascii_lowercase());
        }
        if image_spec.eq_ignore_ascii_case("scratch")
            || image_spec.contains('$')
            || stages.contains(&image_spec.to_ascii_lowercase())
        {
            continue;
        }
        let (without_digest, raw_digest) = match image_spec.split_once('@') {
            Some((img, dig)) => (img, Some(dig.to_owned())),
            None => (image_spec, None),
        };
        // Split `:tag` only after any `registry:port/` slash.
        let last_slash = without_digest.rfind('/');
        let colon_pos = without_digest.rfind(':');
        let (image, raw_tag) = match (colon_pos, last_slash) {
            (Some(c), Some(s)) if c > s => (
                without_digest[..c].to_owned(),
                Some(without_digest[c + 1..].to_owned()),
            ),
            (Some(c), None) => (
                without_digest[..c].to_owned(),
                Some(without_digest[c + 1..].to_owned()),
            ),
            _ => (without_digest.to_owned(), None),
        };
        out.push(DockerFrom {
            file: file.to_owned(),
            line_index,
            image,
            raw_tag,
            raw_digest,
        });
    }
    out
}

fn tag_precision_parts(tag: &str) -> usize {
    let trimmed = tag.trim().trim_start_matches('v');
    let split_at = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(trimmed.len());
    trimmed[..split_at].trim_end_matches('.').split('.').count()
}

fn update_type_between(from: &semver::Version, to: &semver::Version) -> Option<UpdateType> {
    if to <= from {
        return None;
    }
    if to.major != from.major {
        Some(UpdateType::Major)
    } else if to.minor != from.minor {
        Some(UpdateType::Minor)
    } else {
        Some(UpdateType::Patch)
    }
}

enum CooldownOutcome<'a> {
    Use {
        release: &'a CandidateRelease,
        version: semver::Version,
        skipped_note: Option<String>,
    },
    Held {
        to: String,
        age_days: u64,
        required_days: u64,
    },
}

fn cooldown_check<'a>(
    name: &str,
    from: &semver::Version,
    candidates: &[(&'a CandidateRelease, semver::Version)],
    config: &UpdatesConfig,
    now_unix: u64,
) -> Option<CooldownOutcome<'a>> {
    let newest = candidates.first()?;
    let mut blocked_info: Option<(String, u64, u64)> = None;
    let mut skipped_list = Vec::new();
    for (cand, ver) in candidates {
        let Some(ut) = update_type_between(from, ver) else {
            continue;
        };
        let required = config.cooldown.days_for(name, ut);
        if required > 0
            && let Some(pub_ts) = cand.published_unix
        {
            let age_days = now_unix.saturating_sub(pub_ts) / 86_400;
            if age_days < required {
                skipped_list.push(cand.tag.clone());
                if blocked_info.is_none() {
                    blocked_info = Some((cand.tag.clone(), age_days, required));
                }
                continue;
            }
        }
        let note = (!skipped_list.is_empty()).then(|| {
            format!(
                "{} inside cooldown (picked older eligible {})",
                skipped_list.join(", "),
                cand.tag
            )
        });
        return Some(CooldownOutcome::Use {
            release: cand,
            version: ver.clone(),
            skipped_note: note,
        });
    }
    let _ = newest;
    blocked_info.map(|(to, age_days, required_days)| CooldownOutcome::Held {
        to,
        age_days,
        required_days,
    })
}

/// Plans a GitHub Action update against remote releases/tags while enforcing
/// `breaking`, `ignore`, and 7-day default `cooldown`.
#[must_use]
pub fn plan_action_update(
    action: &ActionUse,
    releases: &[CandidateRelease],
    config: &UpdatesConfig,
    breaking: bool,
    now_unix: u64,
) -> Option<EcosystemPlan> {
    let current_str = if action.pinned_sha {
        action.comment_version.as_deref()?
    } else {
        action.raw_ref.as_str()
    };
    let (cur_ver, cur_suffix) = parse_tag_version(current_str)?;
    let cur_parts = tag_precision_parts(current_str);

    let mut parsed: Vec<(&CandidateRelease, semver::Version)> = releases
        .iter()
        .filter_map(|rel| {
            let (ver, suffix) = parse_tag_version(&rel.tag)?;
            if suffix != cur_suffix || ver <= cur_ver {
                return None;
            }
            let compat = ver.major == cur_ver.major;
            if !breaking && !compat {
                return None;
            }
            // Do not suggest replacing a floating major tag (`@v4`) with `@v4.2.1`
            // unless SHA-pinned; only suggest major upgrades when `--breaking`.
            if !action.pinned_sha && cur_parts == 1 && ver.major == cur_ver.major {
                return None;
            }
            if action.pinned_sha && rel.sha.is_none() {
                return None;
            }
            Some((rel, ver))
        })
        .collect();
    parsed.sort_by(|a, b| b.1.cmp(&a.1));

    let (chosen, chosen_ver, skipped_note) =
        match cooldown_check(&action.owner_repo, &cur_ver, &parsed, config, now_unix)? {
            CooldownOutcome::Use {
                release,
                version,
                skipped_note,
            } => (release, version, skipped_note),
            CooldownOutcome::Held {
                to,
                age_days,
                required_days,
            } => {
                return Some(EcosystemPlan::Cooldown {
                    to,
                    age_days,
                    required_days,
                });
            }
        };

    let ut = update_type_between(&cur_ver, &chosen_ver)?;
    if let Some(rule) = config.ignored(&action.owner_repo, &chosen_ver.to_string(), ut) {
        return Some(EcosystemPlan::Ignored {
            to: chosen.tag.clone(),
            reason: rule
                .reason
                .clone()
                .unwrap_or_else(|| format!("ignored (`{}`)", rule.name)),
        });
    }

    let target_ref = if action.pinned_sha {
        chosen.sha.clone()?
    } else if cur_parts == 1 {
        format!("v{}", chosen_ver.major)
    } else {
        chosen.tag.clone()
    };
    let display_to = if action.pinned_sha {
        let short = &target_ref[..target_ref.len().min(7)];
        format!("{} ({short})", chosen.tag)
    } else {
        target_ref.clone()
    };

    Some(EcosystemPlan::Update {
        target_ref,
        display_to,
        update_type: ut,
        sha: chosen.sha.clone(),
        digest: None,
        cooldown_skipped: skipped_note,
    })
}

/// Plans a Dockerfile base-image update preserving variant suffix (`-slim`, `-alpine`)
/// and enforcing `breaking`, `ignore`, and `cooldown`.
#[must_use]
pub fn plan_docker_update(
    from: &DockerFrom,
    releases: &[CandidateRelease],
    config: &UpdatesConfig,
    breaking: bool,
    now_unix: u64,
) -> Option<EcosystemPlan> {
    let current_tag = from.raw_tag.as_deref()?;
    let (cur_ver, cur_suffix) = parse_tag_version(current_tag)?;
    let cur_parts = tag_precision_parts(current_tag);

    let mut parsed: Vec<(&CandidateRelease, semver::Version)> = releases
        .iter()
        .filter_map(|rel| {
            let (ver, suffix) = parse_tag_version(&rel.tag)?;
            if suffix != cur_suffix || ver <= cur_ver {
                return None;
            }
            if tag_precision_parts(&rel.tag) < cur_parts.min(2) {
                return None;
            }
            let compat = if cur_ver.major == 0 {
                ver.major == 0 && ver.minor == cur_ver.minor
            } else {
                ver.major == cur_ver.major
            };
            if !breaking && !compat {
                return None;
            }
            Some((rel, ver))
        })
        .collect();
    parsed.sort_by(|a, b| b.1.cmp(&a.1));

    let (chosen, chosen_ver, skipped_note) =
        match cooldown_check(&from.image, &cur_ver, &parsed, config, now_unix)? {
            CooldownOutcome::Use {
                release,
                version,
                skipped_note,
            } => (release, version, skipped_note),
            CooldownOutcome::Held {
                to,
                age_days,
                required_days,
            } => {
                return Some(EcosystemPlan::Cooldown {
                    to,
                    age_days,
                    required_days,
                });
            }
        };

    let ut = update_type_between(&cur_ver, &chosen_ver)?;
    if let Some(rule) = config.ignored(&from.image, &chosen_ver.to_string(), ut) {
        return Some(EcosystemPlan::Ignored {
            to: chosen.tag.clone(),
            reason: rule
                .reason
                .clone()
                .unwrap_or_else(|| format!("ignored (`{}`)", rule.name)),
        });
    }

    Some(EcosystemPlan::Update {
        target_ref: chosen.tag.clone(),
        display_to: chosen.tag.clone(),
        update_type: ut,
        sha: None,
        digest: chosen.digest.clone(),
        cooldown_skipped: skipped_note,
    })
}

type ActionEdit<'a> = (&'a ActionUse, &'a str, Option<&'a str>);

/// Applies a set of `(ActionUse, target_ref, display_tag)` updates in-place
/// while keeping YAML formatting and comments intact.
///
/// # Errors
///
/// Returns an I/O error if a workflow file cannot be read or written.
pub fn apply_action_updates(root: &Path, edits: &[ActionEdit<'_>]) -> std::io::Result<usize> {
    let mut by_file: std::collections::BTreeMap<&str, Vec<ActionEdit<'_>>> =
        std::collections::BTreeMap::new();
    for &(action, target_ref, comment_tag) in edits {
        by_file
            .entry(action.file.as_str())
            .or_default()
            .push((action, target_ref, comment_tag));
    }
    let mut changed_files = 0usize;
    for (rel, list) in by_file {
        let path = root.join(rel);
        let original = fs::read_to_string(&path)?;
        let trailing_nl = original.ends_with('\n');
        let mut lines: Vec<String> = original.lines().map(str::to_owned).collect();
        let mut dirty = false;
        for (action, target_ref, comment_tag) in list {
            let Some(line) = lines.get_mut(action.line_index) else {
                continue;
            };
            let old_token = format!("{}@{}", action.action_path, action.raw_ref);
            let new_token = format!("{}@{target_ref}", action.action_path);
            if line.contains(&old_token) {
                let mut updated = line.replacen(&old_token, &new_token, 1);
                if action.pinned_sha
                    && let (Some(old_ver), Some(new_ver)) =
                        (action.comment_version.as_deref(), comment_tag)
                {
                    updated = updated.replacen(old_ver, new_ver, 1);
                }
                if updated != *line {
                    *line = updated;
                    dirty = true;
                }
            }
        }
        if dirty {
            let mut joined = lines.join("\n");
            if trailing_nl {
                joined.push('\n');
            }
            fs::write(&path, joined)?;
            changed_files += 1;
        }
    }
    Ok(changed_files)
}

/// Applies Dockerfile base-image updates (`image:old_tag` -> `image:new_tag`)
/// preserving flags (`--platform=...`), stages (`AS ...`), and comments.
///
/// # Errors
///
/// Returns an I/O error if a Dockerfile cannot be read or written.
pub fn apply_docker_updates(root: &Path, edits: &[(&DockerFrom, &str)]) -> std::io::Result<usize> {
    let mut by_file: std::collections::BTreeMap<&str, Vec<(&DockerFrom, &str)>> =
        std::collections::BTreeMap::new();
    for &(from, new_tag) in edits {
        by_file
            .entry(from.file.as_str())
            .or_default()
            .push((from, new_tag));
    }
    let mut changed_files = 0usize;
    for (rel, list) in by_file {
        let path = root.join(rel);
        let original = fs::read_to_string(&path)?;
        let trailing_nl = original.ends_with('\n');
        let mut lines: Vec<String> = original.lines().map(str::to_owned).collect();
        let mut dirty = false;
        for (from, new_tag) in list {
            let Some(line) = lines.get_mut(from.line_index) else {
                continue;
            };
            let Some(old_tag) = from.raw_tag.as_deref() else {
                continue;
            };
            let old_token = format!("{}:{old_tag}", from.image);
            let new_token = format!("{}:{new_tag}", from.image);
            if line.contains(&old_token) {
                let updated = line.replacen(&old_token, &new_token, 1);
                if updated != *line {
                    *line = updated;
                    dirty = true;
                }
            }
        }
        if dirty {
            let mut joined = lines.join("\n");
            if trailing_nl {
                joined.push('\n');
            }
            fs::write(&path, joined)?;
            changed_files += 1;
        }
    }
    Ok(changed_files)
}

#[cfg(test)]
mod tests {
    use super::{
        ActionUse, CandidateRelease, DockerFrom, EcosystemPlan, apply_action_updates,
        apply_docker_updates, parse_action_uses_from_str, parse_docker_froms_from_str,
        plan_action_update, plan_docker_update,
    };
    use crate::updates::{UpdateType, UpdatesConfig};

    #[test]
    fn parses_actions_and_dockerfiles_without_touching_local_or_stage_refs() {
        let wf = r#"
steps:
  - uses: actions/checkout@v4.1.0
  - uses: ./local-action
  - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.5
  - uses: github/codeql-action/upload-sarif@v3
"#;
        let uses = parse_action_uses_from_str(".github/workflows/ci.yml", wf);
        assert_eq!(uses.len(), 3);
        assert_eq!(uses[0].owner_repo, "actions/checkout");
        assert!(!uses[0].pinned_sha);
        assert!(uses[1].pinned_sha);
        assert_eq!(uses[1].comment_version.as_deref(), Some("v2.7.5"));
        assert_eq!(uses[2].owner_repo, "github/codeql-action");

        let df = r#"
FROM --platform=linux/amd64 rust:1.82-slim-bookworm AS builder
FROM builder AS second
FROM scratch
FROM ghcr.io/harpelm/cargoscope:0.11.0
"#;
        let froms = parse_docker_froms_from_str("Dockerfile", df);
        assert_eq!(froms.len(), 2);
        assert_eq!(froms[0].image, "rust");
        assert_eq!(froms[0].raw_tag.as_deref(), Some("1.82-slim-bookworm"));
        assert_eq!(froms[1].image, "ghcr.io/harpelm/cargoscope");
    }

    #[test]
    fn plans_and_applies_action_and_docker_updates_with_cooldown() {
        let now = 2_000_000_000u64;
        let cfg = UpdatesConfig::default();

        let action = ActionUse {
            file: ".github/workflows/ci.yml".to_owned(),
            line_index: 1,
            owner_repo: "actions/checkout".to_owned(),
            action_path: "actions/checkout".to_owned(),
            raw_ref: "v4.1.0".to_owned(),
            comment_version: None,
            pinned_sha: false,
        };
        let action_releases = vec![
            CandidateRelease {
                tag: "v4.2.2".to_owned(),
                published_unix: Some(now - 2 * 86_400),
                sha: None,
                digest: None,
            },
            CandidateRelease {
                tag: "v4.2.1".to_owned(),
                published_unix: Some(now - 20 * 86_400),
                sha: None,
                digest: None,
            },
            CandidateRelease {
                tag: "v5.0.0".to_owned(),
                published_unix: Some(now - 30 * 86_400),
                sha: None,
                digest: None,
            },
        ];
        // Compatible mode skips v5.0.0 (major) and skips v4.2.2 (2d < 7d cooldown), picking v4.2.1.
        assert_eq!(
            plan_action_update(&action, &action_releases, &cfg, false, now),
            Some(EcosystemPlan::Update {
                target_ref: "v4.2.1".to_owned(),
                display_to: "v4.2.1".to_owned(),
                update_type: UpdateType::Minor,
                sha: None,
                digest: None,
                cooldown_skipped: Some(
                    "v4.2.2 inside cooldown (picked older eligible v4.2.1)".to_owned()
                ),
            })
        );

        let from = DockerFrom {
            file: "Dockerfile".to_owned(),
            line_index: 0,
            image: "rust".to_owned(),
            raw_tag: Some("1.82-slim-bookworm".to_owned()),
            raw_digest: None,
        };
        let docker_releases = vec![
            CandidateRelease {
                tag: "1.90-alpine".to_owned(),
                published_unix: Some(now - 20 * 86_400),
                sha: None,
                digest: None,
            },
            CandidateRelease {
                tag: "1.85-slim-bookworm".to_owned(),
                published_unix: Some(now - 10 * 86_400),
                sha: None,
                digest: None,
            },
        ];
        assert_eq!(
            plan_docker_update(&from, &docker_releases, &cfg, false, now),
            Some(EcosystemPlan::Update {
                target_ref: "1.85-slim-bookworm".to_owned(),
                display_to: "1.85-slim-bookworm".to_owned(),
                update_type: UpdateType::Minor,
                sha: None,
                digest: None,
                cooldown_skipped: None,
            })
        );

        let dir = std::env::temp_dir().join(format!("cargoscope-eco-apply-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".github/workflows")).expect("mkdir");
        std::fs::write(
            dir.join(".github/workflows/ci.yml"),
            "steps:\n  - uses: actions/checkout@v4.1.0\n",
        )
        .expect("write yml");
        std::fs::write(
            dir.join("Dockerfile"),
            "FROM --platform=linux/amd64 rust:1.82-slim-bookworm AS builder\n",
        )
        .expect("write df");

        assert_eq!(
            apply_action_updates(&dir, &[(&action, "v4.2.1", None)]).expect("apply action"),
            1
        );
        assert_eq!(
            apply_docker_updates(&dir, &[(&from, "1.85-slim-bookworm")]).expect("apply docker"),
            1
        );
        assert!(
            std::fs::read_to_string(dir.join(".github/workflows/ci.yml"))
                .expect("read yml")
                .contains("uses: actions/checkout@v4.2.1")
        );
        assert!(
            std::fs::read_to_string(dir.join("Dockerfile"))
                .expect("read df")
                .contains("FROM --platform=linux/amd64 rust:1.85-slim-bookworm AS builder")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
