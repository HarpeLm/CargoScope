//! What an update pull request says beyond the versions: the release notes
//! taken from the crate's changelog, the minimum Rust version of the new
//! version against the project's, and what changes in `Cargo.lock`.

use std::collections::{BTreeMap, BTreeSet};

use cargoscope_core::Inventory;

/// Lines of release notes kept per crate; the rest is behind the links.
const MAX_NOTE_LINES: usize = 60;

/// The first version-like token of a heading (`v1.2.3`, `[0.4.45]`,
/// `1.2` read as `1.2.0`), if any.
fn heading_version(text: &str) -> Option<semver::Version> {
    let bytes = text.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start].is_ascii_digit()
            || (start > 0 && (bytes[start - 1].is_ascii_alphanumeric() && bytes[start - 1] != b'v'))
        {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'.' | b'-' | b'+'))
        {
            end += 1;
        }
        let token = text[start..end].trim_end_matches(['.', '-', '+']);
        let dots = token
            .split(['-', '+'])
            .next()
            .unwrap_or("")
            .matches('.')
            .count();
        let padded = match dots {
            1 => {
                let (core, rest) = token
                    .find(['-', '+'])
                    .map_or((token, ""), |at| token.split_at(at));
                format!("{core}.0{rest}")
            }
            2 => token.to_owned(),
            _ => {
                start = end;
                continue;
            }
        };
        if let Ok(version) = semver::Version::parse(&padded) {
            return Some(version);
        }
        start = end;
    }
    None
}

/// A heading of a Markdown changelog: its level (1 for `#`, setext `===`)
/// and its text.
fn heading(line: &str, next: Option<&str>) -> Option<(usize, String)> {
    let trimmed = line.trim_start();
    let hashes = trimmed.chars().take_while(|c| *c == '#').count();
    if (1..=6).contains(&hashes) && trimmed[hashes..].starts_with(' ') {
        return Some((hashes, trimmed[hashes..].trim().to_owned()));
    }
    let underline = next?.trim();
    if !trimmed.is_empty() && underline.len() >= 3 {
        if underline.chars().all(|c| c == '=') {
            return Some((1, trimmed.trim().to_owned()));
        }
        if underline.chars().all(|c| c == '-') {
            return Some((2, trimmed.trim().to_owned()));
        }
    }
    None
}

/// The sections of `changelog` for the versions after `from` up to `to`,
/// newest first as in the file, with version headings as `####`. `None` when
/// no section of that range is found.
pub fn release_notes(changelog: &str, from: &str, to: &str) -> Option<String> {
    let from = semver::Version::parse(from).ok()?;
    let to = semver::Version::parse(to).ok()?;
    let lines: Vec<&str> = changelog.lines().collect();
    // Each heading with a version opens a section that runs until the next
    // heading of the same or a higher level.
    let mut sections: Vec<(usize, usize, semver::Version, String)> = Vec::new();
    let mut open: Option<(usize, usize, semver::Version, String)> = None;
    let mut skip_next = false;
    for (index, line) in lines.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let Some((level, text)) = heading(line, lines.get(index + 1).copied()) else {
            continue;
        };
        let setext = !line.trim_start().starts_with('#');
        if let Some((_, open_level, _, _)) = &open
            && level <= *open_level
            && let Some((start, _, version, title)) = open.take()
        {
            sections.push((start, index, version, title));
        }
        if open.is_none()
            && let Some(version) = heading_version(&text)
        {
            let body_start = index + if setext { 2 } else { 1 };
            open = Some((body_start, level, version, text));
        }
        skip_next = setext;
    }
    if let Some((start, _, version, title)) = open {
        sections.push((start, lines.len(), version, title));
    }

    let mut out: Vec<String> = Vec::new();
    let mut kept = 0;
    let mut truncated = false;
    for (start, end, version, title) in sections {
        if version <= from || version > to {
            continue;
        }
        kept += 1;
        if out.len() >= MAX_NOTE_LINES {
            truncated = true;
            continue;
        }
        if !out.is_empty() {
            out.push(String::new());
        }
        out.push(format!("#### {title}"));
        for line in &lines[start..end] {
            if out.len() >= MAX_NOTE_LINES {
                truncated = true;
                break;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                out.push(format!("##### {}", trimmed.trim_start_matches('#').trim()));
            } else {
                out.push((*line).to_owned());
            }
        }
        while out.last().is_some_and(|line| line.trim().is_empty()) {
            out.pop();
        }
    }
    if kept == 0 {
        return None;
    }
    if truncated {
        out.push(String::new());
        out.push("*… cut here: the rest is in the release notes.*".to_owned());
    }
    Some(out.join("\n"))
}

/// Release notes made safe to copy into a pull request, as Dependabot does:
/// `@name` mentions go in code (no notification), GitHub links go through
/// `redirect.github.com` (no backlink in the other repository), and issue
/// references (`#12`, `owner/repo#12`) become plain links or code so that
/// they do not point at the project's own issues.
pub fn sanitize_notes(notes: &str, repository: Option<&str>) -> String {
    let repository = repository
        .map(|url| url.trim_end_matches('/').trim_end_matches(".git"))
        .and_then(|url| url.strip_prefix("https://github.com/"))
        .filter(|path| path.matches('/').count() == 1);
    let text = notes.replace("https://github.com/", "https://redirect.github.com/");
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_code = false;
    while index < chars.len() {
        let c = chars[index];
        if c == '`' {
            in_code = !in_code;
            out.push(c);
            index += 1;
            continue;
        }
        let boundary = index == 0 || {
            let before = chars[index - 1];
            before.is_whitespace() || matches!(before, '(' | '[' | ',' | ';' | ':')
        };
        if in_code || !boundary {
            out.push(c);
            index += 1;
            continue;
        }
        // A word that may be `@name` or `owner/repo#12`.
        let end = (index..chars.len())
            .find(|&at| {
                !(chars[at].is_ascii_alphanumeric()
                    || matches!(chars[at], '-' | '_' | '.' | '/' | '#' | '@' | '[' | ']'))
                    || (chars[at] == '.'
                        && chars.get(at + 1).is_none_or(|next| next.is_whitespace()))
            })
            .unwrap_or(chars.len());
        let word: String = chars[index..end].iter().collect();
        let mention = word.len() > 1
            && word.starts_with('@')
            && word[1..].starts_with(|c: char| c.is_ascii_alphanumeric());
        let number = word
            .strip_prefix('#')
            .filter(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()));
        let cross = word.contains('#')
            && word.contains('/')
            && !word.starts_with('#')
            && word
                .rsplit('#')
                .next()
                .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()));
        if mention || cross {
            out.push('`');
            out.push_str(&word);
            out.push('`');
            index = end;
        } else if let Some(number) = number {
            match repository {
                Some(path) => out.push_str(&format!(
                    "[#{number}](https://redirect.github.com/{path}/issues/{number})"
                )),
                None => out.push_str(&format!("`#{number}`")),
            }
            index = end;
        } else {
            out.push(c);
            index += 1;
        }
    }
    out
}

/// The lowest `rust-version` the project's manifests declare (a package's,
/// or `[workspace.package]`'s), if any.
pub fn project_rust_version<'a>(manifests: impl Iterator<Item = &'a str>) -> Option<String> {
    manifests
        .filter_map(|text| toml::from_str::<toml::Value>(text).ok())
        .filter_map(|value| {
            let direct = value
                .get("package")
                .and_then(|package| package.get("rust-version"))
                .and_then(toml::Value::as_str)
                .map(str::to_owned);
            direct.or_else(|| {
                value
                    .get("workspace")
                    .and_then(|workspace| workspace.get("package"))
                    .and_then(|package| package.get("rust-version"))
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
            })
        })
        .min_by_key(|version| rust_version_key(version))
}

/// `1.80` and `1.80.1` as comparable numbers.
pub fn rust_version_key(version: &str) -> (u64, u64, u64) {
    let mut parts = version
        .trim()
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

/// What changes in `Cargo.lock` between two inventories.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LockDiff {
    pub added: Vec<(String, String)>,
    pub removed: Vec<(String, String)>,
    /// Name, old version, new version: a crate with one version on each side.
    pub updated: Vec<(String, String, String)>,
    pub before: usize,
    pub after: usize,
}

impl LockDiff {
    pub fn between(before: &Inventory, after: &Inventory) -> Self {
        let set = |inventory: &Inventory| -> BTreeSet<(String, String)> {
            inventory
                .packages
                .iter()
                .filter(|package| !package.root)
                .map(|package| (package.name.clone(), package.version.clone()))
                .collect()
        };
        let (old, new) = (set(before), set(after));
        let mut added: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut removed: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, version) in new.difference(&old) {
            added.entry(name.clone()).or_default().push(version.clone());
        }
        for (name, version) in old.difference(&new) {
            removed
                .entry(name.clone())
                .or_default()
                .push(version.clone());
        }
        let mut diff = Self {
            before: old.len(),
            after: new.len(),
            ..Self::default()
        };
        for (name, versions) in &added {
            match (versions.as_slice(), removed.get(name).map(Vec::as_slice)) {
                ([to], Some([from])) => {
                    diff.updated.push((name.clone(), from.clone(), to.clone()));
                }
                _ => diff
                    .added
                    .extend(versions.iter().map(|v| (name.clone(), v.clone()))),
            }
        }
        for (name, versions) in &removed {
            let replaced = matches!(
                (versions.as_slice(), added.get(name).map(Vec::as_slice)),
                ([_], Some([_]))
            );
            if !replaced {
                diff.removed
                    .extend(versions.iter().map(|v| (name.clone(), v.clone())));
            }
        }
        diff
    }

    pub fn changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.updated.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{LockDiff, heading_version, project_rust_version, release_notes, sanitize_notes};
    use cargoscope_core::{Inventory, Package};

    #[test]
    fn reads_versions_in_headings() {
        let v = |text: &str| heading_version(text).map(|version| version.to_string());
        assert_eq!(v("[0.4.45] - 2026-06-04"), Some("0.4.45".to_owned()));
        assert_eq!(v("v1.2.3"), Some("1.2.3".to_owned()));
        assert_eq!(v("Version 2.0 (2024)"), Some("2.0.0".to_owned()));
        assert_eq!(v("1.0.0-rc.1"), Some("1.0.0-rc.1".to_owned()));
        assert_eq!(v("Unreleased"), None);
        assert_eq!(v("2024-03-01"), None);
    }

    const CHANGELOG: &str = "# Changelog\n\n## Unreleased\n- wip\n\n## [0.4.45] - 2026-06-04\n### Added\n- `abs_diff`\n\n## [0.4.44]\n- docs\n\n## 0.4.30\n- old\n";

    #[test]
    fn keeps_only_the_sections_of_the_update() {
        let notes = release_notes(CHANGELOG, "0.4.30", "0.4.45").expect("notes");
        assert_eq!(
            notes,
            "#### [0.4.45] - 2026-06-04\n##### Added\n- `abs_diff`\n\n#### [0.4.44]\n- docs"
        );
        assert!(release_notes(CHANGELOG, "0.4.45", "0.4.46").is_none());
        let setext = "1.1.0\n=====\n* fix\n\n1.0.0\n=====\n* first\n";
        assert_eq!(
            release_notes(setext, "1.0.0", "1.1.0").as_deref(),
            Some("#### 1.1.0\n* fix")
        );
    }

    #[test]
    fn cuts_long_notes() {
        let long: String = (0..100).map(|i| format!("- change {i}\n")).collect();
        let notes = release_notes(&format!("## 2.0.0\n{long}"), "1.0.0", "2.0.0").expect("notes");
        assert!(notes.lines().count() <= 62, "{notes}");
        assert!(notes.ends_with("the rest is in the release notes.*"));
    }

    #[test]
    fn finds_the_lowest_rust_version_of_the_project() {
        let manifests = [
            "[workspace.package]\nrust-version = \"1.80\"\n",
            "[package]\nname = \"a\"\nrust-version = \"1.75\"\n",
            "[package]\nname = \"b\"\n",
        ];
        assert_eq!(
            project_rust_version(manifests.into_iter()),
            Some("1.75".to_owned())
        );
        assert_eq!(project_rust_version(["[package]\n"].into_iter()), None);
    }

    fn inventory(packages: &[(&str, &str)]) -> Inventory {
        Inventory {
            packages: packages
                .iter()
                .map(|(name, version)| Package {
                    name: (*name).to_owned(),
                    version: (*version).to_owned(),
                    source: None,
                    root: false,
                    direct: false,
                    dependencies: Vec::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn diffs_two_lockfiles() {
        let before = inventory(&[
            ("a", "1.0.0"),
            ("b", "1.0.0"),
            ("c", "0.1.0"),
            ("d", "1.0.0"),
            ("d", "2.0.0"),
        ]);
        let after = inventory(&[
            ("a", "1.1.0"),
            ("b", "1.0.0"),
            ("e", "0.3.0"),
            ("d", "2.0.0"),
        ]);
        let diff = LockDiff::between(&before, &after);
        assert_eq!(
            diff.updated,
            vec![("a".into(), "1.0.0".into(), "1.1.0".into())]
        );
        assert_eq!(diff.added, vec![("e".into(), "0.3.0".into())]);
        assert_eq!(
            diff.removed,
            vec![("c".into(), "0.1.0".into()), ("d".into(), "1.0.0".into())]
        );
        assert_eq!((diff.before, diff.after, diff.changes()), (5, 4, 4));
    }

    #[test]
    fn notes_notify_no_one_and_link_nowhere_in_the_project() {
        let notes = "* fix by @SAY-5 in https://github.com/chronotope/chrono/pull/1787\n* see #12 and rust-lang/rust#99 (thanks @djc)\n* `@keep` and a@b.c email\n";
        assert_eq!(
            sanitize_notes(notes, Some("https://github.com/chronotope/chrono")),
            "* fix by `@SAY-5` in https://redirect.github.com/chronotope/chrono/pull/1787\n* see [#12](https://redirect.github.com/chronotope/chrono/issues/12) and `rust-lang/rust#99` (thanks `@djc`)\n* `@keep` and a@b.c email\n"
        );
        assert_eq!(sanitize_notes("fixes #3", None), "fixes `#3`");
    }
}
