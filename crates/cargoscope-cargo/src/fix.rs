//! Removal of unused dependencies from a `Cargo.toml` (`cargoscope fix`).
//!
//! Edits go through `toml_edit`, so the rest of the manifest keeps its
//! formatting, order and comments. A dependency is removed from its section
//! and from the same section of every `[target.'...']` table.

use toml_edit::{DocumentMut, Item};

/// What happened to one dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Removed from these tables (`dependencies`,
    /// `target.'cfg(unix)'.dependencies`, ...).
    Removed(Vec<String>),
    /// Left in place, with the reason.
    Skipped(String),
}

fn is_optional_dependency(document: &DocumentMut, key: &str, targets: &[String]) -> bool {
    let sections = [
        "dependencies",
        "dev-dependencies",
        "dev_dependencies",
        "build-dependencies",
        "build_dependencies",
    ];
    let check_table = |item: Option<&Item>| {
        item.and_then(Item::as_table_like)
            .and_then(|table| table.get(key))
            .and_then(Item::as_table_like)
            .and_then(|dep| dep.get("optional"))
            .and_then(Item::as_bool)
            == Some(true)
    };
    if sections
        .iter()
        .any(|section| check_table(document.get(section)))
    {
        return true;
    }
    let Some(target_table) = document.get("target").and_then(Item::as_table_like) else {
        return false;
    };
    targets.iter().any(|target| {
        let entry = target_table.get(target);
        sections
            .iter()
            .any(|section| check_table(entry.and_then(|item| item.get(section))))
    })
}

fn has_dep_reference(document: &DocumentMut, key: &str) -> bool {
    let Some(features) = document.get("features").and_then(Item::as_table_like) else {
        return false;
    };
    let dep_entry = format!("dep:{key}");
    features.iter().any(|(_, value)| {
        value.as_array().is_some_and(|array| {
            array
                .iter()
                .filter_map(|entry| entry.as_str())
                .any(|entry| entry == dep_entry)
        })
    })
}

fn has_blocking_feature_reference(document: &DocumentMut, key: &str, is_optional: bool) -> bool {
    let Some(features) = document.get("features").and_then(Item::as_table_like) else {
        return false;
    };
    let has_dep = has_dep_reference(document, key);
    if features.contains_key(key) && !has_dep {
        return true;
    }
    let dep_entry = format!("dep:{key}");
    let prefix = format!("{key}/");
    let weak_prefix = format!("{key}?/");
    features.iter().any(|(_, value)| {
        value.as_array().is_some_and(|array| {
            array
                .iter()
                .filter_map(|entry| entry.as_str())
                .any(|entry| {
                    (entry == key && !(features.contains_key(key) && has_dep))
                        || (is_optional
                            && !has_dep
                            && (entry.starts_with(&prefix) || entry.starts_with(&weak_prefix)))
                        || (!is_optional && entry == dep_entry)
                })
        })
    })
}

fn clean_feature_subfeatures(document: &mut DocumentMut, key: &str) -> bool {
    let Some(features) = document
        .get_mut("features")
        .and_then(Item::as_table_like_mut)
    else {
        return false;
    };
    let dep_entry = format!("dep:{key}");
    let prefix = format!("{key}/");
    let weak_prefix = format!("{key}?/");
    let mut cleaned = false;
    for (_, value) in features.iter_mut() {
        let Some(array) = value.as_array_mut() else {
            continue;
        };
        let before = array.len();
        array.retain(|item| {
            item.as_str().is_none_or(|entry| {
                entry != dep_entry
                    && !entry.starts_with(&prefix)
                    && !entry.starts_with(&weak_prefix)
            })
        });
        if array.len() != before {
            cleaned = true;
            if let Some(first) = array.get_mut(0)
                && first
                    .decor()
                    .prefix()
                    .and_then(|prefix| prefix.as_str())
                    .is_some_and(|prefix| prefix.starts_with(' '))
            {
                first.decor_mut().set_prefix("");
            }
        }
    }
    cleaned
}

/// Removes `key` from the table at `path` of `document`; returns whether it
/// was there.
fn remove_from(document: &mut DocumentMut, path: &[&str], key: &str) -> bool {
    let mut item: &mut Item = document.as_item_mut();
    for step in path {
        let Some(next) = item.get_mut(*step) else {
            return false;
        };
        item = next;
    }
    item.as_table_like_mut()
        .is_some_and(|table| table.remove(key).is_some())
}

/// Removes each `(section, key)` from a manifest.
///
/// `section` is `dependencies`, `dev-dependencies` or `build-dependencies`;
/// the underscore spelling and target-specific tables are handled too. An
/// implicit feature reference in `[features]` (without `dep:key`) is skipped;
/// `dep:key`, `key/feature` and `key?/feature` entries are cleaned from
/// `[features]`.
///
/// # Errors
///
/// Returns a message when the manifest is not valid TOML.
pub fn remove_dependencies(
    contents: &str,
    removals: &[(&str, &str)],
) -> Result<(String, Vec<Outcome>), String> {
    let mut document: DocumentMut = contents.parse().map_err(|error| format!("{error}"))?;
    let targets: Vec<String> = document
        .get("target")
        .and_then(Item::as_table_like)
        .map(|targets| targets.iter().map(|(name, _)| name.to_owned()).collect())
        .unwrap_or_default();

    let mut outcomes = Vec::new();
    for &(section, key) in removals {
        if section == "workspace.dependencies" {
            outcomes.push(
                if remove_from(&mut document, &["workspace", "dependencies"], key) {
                    Outcome::Removed(vec![section.to_owned()])
                } else {
                    Outcome::Skipped(format!("`{key}` was not found in [{section}]"))
                },
            );
            continue;
        }
        let is_optional = is_optional_dependency(&document, key, &targets);
        if has_blocking_feature_reference(&document, key, is_optional) {
            outcomes.push(Outcome::Skipped(format!("`{key}` is named in [features]")));
            continue;
        }
        let underscore = section.replace('-', "_");
        let spellings: Vec<&str> = if underscore == section {
            vec![section]
        } else {
            vec![section, underscore.as_str()]
        };
        let mut removed = Vec::new();
        for spelling in &spellings {
            if remove_from(&mut document, &[spelling], key) {
                removed.push((*spelling).to_owned());
            }
            for target in &targets {
                if remove_from(&mut document, &["target", target, spelling], key) {
                    removed.push(format!("target.'{target}'.{spelling}"));
                }
            }
        }
        if !removed.is_empty() && clean_feature_subfeatures(&mut document, key) {
            removed.push("features".to_owned());
        }
        outcomes.push(if removed.is_empty() {
            Outcome::Skipped(format!("`{key}` was not found in [{section}]"))
        } else {
            Outcome::Removed(removed)
        });
    }
    Ok((document.to_string(), outcomes))
}

/// Keys declared with `workspace = true` in the dependency tables of a
/// manifest (target-specific tables included).
#[must_use]
pub fn workspace_references(contents: &str) -> std::collections::BTreeSet<String> {
    let mut keys = std::collections::BTreeSet::new();
    let Ok(document) = contents.parse::<DocumentMut>() else {
        return keys;
    };
    let mut tables: Vec<&Item> = Vec::new();
    let sections = [
        "dependencies",
        "dev-dependencies",
        "dev_dependencies",
        "build-dependencies",
        "build_dependencies",
    ];
    for section in sections {
        if let Some(table) = document.get(section) {
            tables.push(table);
        }
    }
    if let Some(targets) = document.get("target").and_then(Item::as_table_like) {
        for (_, target) in targets.iter() {
            for section in sections {
                if let Some(table) = target.get(section) {
                    tables.push(table);
                }
            }
        }
    }
    for table in tables.into_iter().filter_map(Item::as_table_like) {
        for (key, value) in table.iter() {
            let inherited = value
                .as_table_like()
                .and_then(|entry| entry.get("workspace"))
                .and_then(Item::as_bool)
                == Some(true);
            if inherited {
                keys.insert(key.to_owned());
            }
        }
    }
    keys
}

/// Removes `keys` from `[workspace.dependencies]`; returns the new contents
/// and the keys that were there.
///
/// # Errors
///
/// Returns a message when the manifest is not valid TOML.
pub fn remove_workspace_dependencies(
    contents: &str,
    keys: &[&str],
) -> Result<(String, Vec<String>), String> {
    let mut document: DocumentMut = contents.parse().map_err(|error| format!("{error}"))?;
    let removed = keys
        .iter()
        .filter(|key| remove_from(&mut document, &["workspace", "dependencies"], key))
        .map(|key| (*key).to_owned())
        .collect();
    Ok((document.to_string(), removed))
}

fn table_mut<'a>(
    document: &'a mut DocumentMut,
    path: &[String],
) -> Option<&'a mut dyn toml_edit::TableLike> {
    // `Item::get_mut` would insert a missing key (an empty `workspace = {}`
    // in a member manifest makes Cargo read it as a workspace root);
    // `TableLike::get_mut` only looks.
    let mut item: &mut Item = document.as_item_mut();
    for step in path {
        item = item.as_table_like_mut()?.get_mut(step.as_str())?;
    }
    item.as_table_like_mut()
}

/// Sets the version requirement of every declaration of the crate `package`
/// (by key, or by `package = "..."` for a renamed dependency) to
/// `requirement`, in the dependency tables of a manifest, its
/// `[target.'...']` tables and its `[workspace.dependencies]`. Entries
/// inherited with `workspace = true` and path or git dependencies are left
/// alone. Returns the new contents and whether anything changed.
///
/// # Errors
///
/// Returns a message when the manifest is not valid TOML.
pub fn set_requirement(
    contents: &str,
    package: &str,
    requirement: &str,
) -> Result<(String, bool), String> {
    set_requirement_for_version(contents, package, None, requirement)
}

/// Like [`set_requirement`], but when `from_version` is given, only declarations
/// whose existing version requirement matches `from_version` are updated.
///
/// This prevents downgrading or touching another major version line of the same
/// crate elsewhere in a workspace (for example updating `time = "0.1"` without
/// touching another member's `time = "0.3"`).
///
/// # Errors
///
/// Returns a message when the manifest is not valid TOML.
pub fn set_requirement_for_version(
    contents: &str,
    package: &str,
    from_version: Option<&str>,
    requirement: &str,
) -> Result<(String, bool), String> {
    rewrite_requirement_for_version(contents, package, from_version, |old| {
        keep_pin(old, requirement)
    })
}

/// Like [`set_requirement_for_version`], widening existing bounded requirements
/// (`"1.0"` -> `">=1.0, <3.0.0"`, `">=1.0, <2.0"` -> `">=1.0, <3.0.0"`) when
/// `target` sits outside the existing SemVer line (Dependabot's
/// `versioning-strategy: widen`). Pinned requirements (`=1.2.3`) stay pinned.
///
/// # Errors
///
/// Returns a message when the manifest is not valid TOML.
pub fn widen_requirement_for_version(
    contents: &str,
    package: &str,
    from_version: Option<&str>,
    target: &semver::Version,
) -> Result<(String, bool), String> {
    let target_str = target.to_string();
    rewrite_requirement_for_version(contents, package, from_version, |old| {
        widen_range(old, target, &target_str)
    })
}

fn rewrite_requirement_for_version(
    contents: &str,
    package: &str,
    from_version: Option<&str>,
    mut make_req: impl FnMut(Option<&str>) -> String,
) -> Result<(String, bool), String> {
    let mut document: DocumentMut = contents.parse().map_err(|error| format!("{error}"))?;
    let from = from_version.and_then(|version| semver::Version::parse(version).ok());
    let sections = [
        "dependencies",
        "dev-dependencies",
        "dev_dependencies",
        "build-dependencies",
        "build_dependencies",
    ];
    let mut paths: Vec<Vec<String>> = sections.iter().map(|s| vec![(*s).to_owned()]).collect();
    paths.push(vec!["workspace".to_owned(), "dependencies".to_owned()]);
    let targets: Vec<String> = document
        .get("target")
        .and_then(Item::as_table_like)
        .map(|targets| targets.iter().map(|(name, _)| name.to_owned()).collect())
        .unwrap_or_default();
    for target in &targets {
        for section in sections {
            paths.push(vec![
                "target".to_owned(),
                target.clone(),
                section.to_owned(),
            ]);
        }
    }

    let mut changed = false;
    for path in paths {
        let Some(table) = table_mut(&mut document, &path) else {
            continue;
        };
        for (key, value) in table.iter_mut() {
            let renamed_to = value
                .as_table_like()
                .and_then(|entry| entry.get("package"))
                .and_then(Item::as_str)
                .map(str::to_owned);
            if renamed_to.as_deref().unwrap_or(key.get()) != package {
                continue;
            }
            if value.is_str() {
                if !matches_from(value.as_str(), from.as_ref()) {
                    continue;
                }
                let requirement = make_req(value.as_str());
                if value.as_str() != Some(requirement.as_str()) {
                    // `name = "1.2"`: keep the surrounding spaces and comment.
                    let decor = value.as_value().map(|v| v.decor().clone());
                    *value = toml_edit::value(requirement);
                    if let (Some(decor), Some(new)) = (decor, value.as_value_mut()) {
                        *new.decor_mut() = decor;
                    }
                    changed = true;
                }
            } else if let Some(entry) = value.as_table_like_mut() {
                if entry.get("workspace").is_some()
                    || entry.get("path").is_some()
                    || entry.get("git").is_some()
                {
                    continue;
                }
                let existing = entry
                    .get("version")
                    .and_then(Item::as_str)
                    .map(str::to_owned);
                if existing.is_none() || !matches_from(existing.as_deref(), from.as_ref()) {
                    continue;
                }
                let requirement = make_req(existing.as_deref());
                if existing.as_deref() != Some(requirement.as_str()) {
                    let decor = entry
                        .get("version")
                        .and_then(Item::as_value)
                        .map(|v| v.decor().clone());
                    if let Some(slot) = entry.get_mut("version") {
                        *slot = toml_edit::value(requirement);
                        if let (Some(decor), Some(new)) = (decor, slot.as_value_mut()) {
                            *new.decor_mut() = decor;
                        }
                        changed = true;
                    }
                }
            }
        }
    }
    Ok((document.to_string(), changed))
}

fn widen_range(old: Option<&str>, target: &semver::Version, target_str: &str) -> String {
    let Some(old_str) = old.map(str::trim).filter(|s| !s.is_empty()) else {
        return target_str.to_owned();
    };
    if old_str.starts_with('=') {
        return format!("={target_str}");
    }
    if semver::VersionReq::parse(old_str).is_ok_and(|req| req.matches(target)) {
        return old_str.to_owned();
    }
    let upper = if target.major > 0 {
        format!("<{}.0.0", target.major + 1)
    } else if target.minor > 0 {
        format!("<0.{}.0", target.minor + 1)
    } else {
        format!("<0.0.{}", target.patch + 1)
    };
    let lower = if let Some(rest) = old_str.strip_prefix(">=") {
        rest.split(',').next().unwrap_or(rest).trim()
    } else {
        old_str
            .trim_start_matches('^')
            .trim_start_matches('~')
            .trim()
    };
    if lower.starts_with(|c: char| c.is_ascii_digit()) {
        format!(">={lower}, {upper}")
    } else {
        target_str.to_owned()
    }
}

fn matches_from(old: Option<&str>, from: Option<&semver::Version>) -> bool {
    let (Some(old), Some(from)) = (old, from) else {
        return true;
    };
    semver::VersionReq::parse(old).map_or(true, |requirement| requirement.matches(from))
}

/// The requirement to write over `old`: a bare version (`1.2.3`) stays pinned
/// (`=1.2.3`) when `old` was, so an update never unpins a dependency.
fn keep_pin(old: Option<&str>, requirement: &str) -> String {
    let pinned = old.is_some_and(|old| old.trim_start().starts_with('='));
    if pinned && requirement.starts_with(|c: char| c.is_ascii_digit()) {
        format!("={requirement}")
    } else {
        requirement.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{Outcome, remove_dependencies};

    const MANIFEST: &str = r#"[package]
name = "demo" # the demo
version = "0.1.0"

[dependencies]
# Logging.
log = "0.4"
regex = "1"   # unused
serde = { version = "1", features = ["derive"] }
optional-thing = { version = "1", optional = true }

[dev_dependencies]
pretty_assertions = "1"

[target.'cfg(unix)'.dependencies]
regex = "1"
libc = "0.2"

[features]
extra = ["optional-thing"]
"#;

    #[test]
    fn removes_dependencies_and_keeps_everything_else() {
        let (edited, outcomes) = remove_dependencies(
            MANIFEST,
            &[
                ("dependencies", "regex"),
                ("dev-dependencies", "pretty_assertions"),
            ],
        )
        .expect("valid manifest");
        assert_eq!(
            outcomes,
            vec![
                Outcome::Removed(vec![
                    "dependencies".to_owned(),
                    "target.'cfg(unix)'.dependencies".to_owned()
                ]),
                Outcome::Removed(vec!["dev_dependencies".to_owned()]),
            ]
        );
        let expected = MANIFEST
            .replace("regex = \"1\"   # unused\n", "")
            .replace("pretty_assertions = \"1\"\n", "")
            .replace(
                "[target.'cfg(unix)'.dependencies]\nregex = \"1\"\n",
                "[target.'cfg(unix)'.dependencies]\n",
            );
        assert_eq!(edited, expected);
    }

    #[test]
    fn skips_feature_references_and_missing_entries() {
        let (edited, outcomes) = remove_dependencies(
            MANIFEST,
            &[
                ("dependencies", "optional-thing"),
                ("build-dependencies", "cc"),
            ],
        )
        .expect("valid manifest");
        assert_eq!(edited, MANIFEST);
        assert_eq!(
            outcomes,
            vec![
                Outcome::Skipped("`optional-thing` is named in [features]".to_owned()),
                Outcome::Skipped("`cc` was not found in [build-dependencies]".to_owned()),
            ]
        );
    }

    #[test]
    fn finds_and_removes_workspace_dependencies() {
        let member = "[dependencies]\nlog.workspace = true\nregex = { workspace = true, features = [\"std\"] }\nrand = \"0.8\"\n\n[target.'cfg(unix)'.dev-dependencies]\nlibc = { workspace = true }\n";
        assert_eq!(
            super::workspace_references(member)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["libc", "log", "regex"]
        );
        let root = "[workspace]\nmembers = [\"a\"]\n\n[workspace.dependencies]\nlog = \"0.4\" # logging\nregex = \"1\"\n";
        let (edited, removed) =
            super::remove_workspace_dependencies(root, &["regex", "absent"]).expect("valid");
        assert_eq!(removed, vec!["regex"]);
        assert_eq!(edited, root.replace("regex = \"1\"\n", ""));
    }

    #[test]
    fn sets_the_requirement_of_a_crate_everywhere_it_is_declared() {
        let manifest = "[dependencies]\nchrono = \"=0.4.19\" # pinned\nold = { package = \"chrono\", version = \"0.4\", default-features = false }\nserde = \"1\"\nshared.workspace = true\n\n[dev-dependencies.chrono]\nversion = \"0.4.19\"\n\n[target.'cfg(unix)'.dependencies]\nchrono = { version = \"0.4.19\", optional = true }\n\n[workspace.dependencies]\nchrono = \"0.4.19\"\n";
        let (edited, changed) =
            super::set_requirement(manifest, "chrono", "0.4.20").expect("valid");
        assert!(changed);
        assert_eq!(
            edited,
            "[dependencies]\nchrono = \"=0.4.20\" # pinned\nold = { package = \"chrono\", version = \"0.4.20\", default-features = false }\nserde = \"1\"\nshared.workspace = true\n\n[dev-dependencies.chrono]\nversion = \"0.4.20\"\n\n[target.'cfg(unix)'.dependencies]\nchrono = { version = \"0.4.20\", optional = true }\n\n[workspace.dependencies]\nchrono = \"0.4.20\"\n"
        );
        let (again, changed_again) =
            super::set_requirement(&edited, "chrono", "0.4.20").expect("valid");
        assert!(!changed_again);
        assert_eq!(again, edited);
        let (same, changed) = super::set_requirement(manifest, "regex", "1.9.0").expect("valid");
        assert!(!changed);
        assert_eq!(same, manifest);
    }

    #[test]
    fn set_requirement_keeps_a_pinned_dependency_pinned() {
        let manifest = "[dependencies]\nchrono = \"=0.4.19\"\nserde = { version = \"= 1.0.1\", features = [\"derive\"] }\nlog = \"0.4\"\n";
        let (chrono, changed) = super::set_requirement(manifest, "chrono", "0.4.45").unwrap();
        assert!(changed);
        assert!(chrono.contains("chrono = \"=0.4.45\""), "{chrono}");
        let (serde, _) = super::set_requirement(manifest, "serde", "1.0.2").unwrap();
        assert!(serde.contains("version = \"=1.0.2\""), "{serde}");
        let (log, _) = super::set_requirement(manifest, "log", "0.4.20").unwrap();
        assert!(log.contains("log = \"0.4.20\""), "{log}");
        // Already exact: nothing to change.
        let (_, unchanged) = super::set_requirement(manifest, "chrono", "=0.4.19").unwrap();
        assert!(!unchanged);
    }

    #[test]
    fn set_requirement_adds_no_table_to_a_member_manifest() {
        let member = "[package]\nname = \"member\"\nedition.workspace = true\n\n[dependencies]\nureq = \"2\"\n";
        let (edited, changed) = super::set_requirement(member, "ureq", "3.5.2").expect("valid");
        assert!(changed);
        assert_eq!(edited, member.replace("\"2\"", "\"3.5.2\""));
        assert!(!edited.contains("workspace = {}"), "{edited}");
    }

    #[test]
    fn handles_the_table_form_and_inline_tables() {
        let manifest = "[package]\nname = \"demo\"\n\n[dependencies.regex]\nversion = \"1\"\n\n[dependencies]\nlog = \"0.4\"\n";
        let (edited, outcomes) =
            remove_dependencies(manifest, &[("dependencies", "regex")]).expect("valid");
        assert_eq!(
            outcomes,
            vec![Outcome::Removed(vec!["dependencies".to_owned()])]
        );
        assert!(!edited.contains("regex"), "{edited}");
        assert!(edited.contains("log = \"0.4\""));

        let inline =
            "[package]\nname = \"demo\"\ndependencies = { regex = \"1\", log = \"0.4\" }\n";
        assert!(remove_dependencies(inline, &[("dependencies", "regex")]).is_ok());
        assert!(remove_dependencies("not = [valid", &[]).is_err());
    }

    #[test]
    fn removes_subfeature_and_dep_references_from_features() {
        let manifest = r#"[package]
name = "demo"

[dependencies]
foo = "1"
bar = { version = "1", optional = true }
baz = { version = "1", optional = true }
serde = "1"

[features]
std = ["foo/std", "serde?/std", "foo?/alloc"]
extra = ["dep:bar", "bar/extra"]
other = ["baz"]
"#;
        let (edited, outcomes) = remove_dependencies(
            manifest,
            &[
                ("dependencies", "foo"),
                ("dependencies", "bar"),
                ("dependencies", "baz"),
            ],
        )
        .expect("valid manifest");
        assert_eq!(
            outcomes,
            vec![
                Outcome::Removed(vec!["dependencies".to_owned(), "features".to_owned()]),
                Outcome::Removed(vec!["dependencies".to_owned(), "features".to_owned()]),
                Outcome::Skipped("`baz` is named in [features]".to_owned()),
            ]
        );
        assert!(!edited.contains("foo"), "{edited}");
        assert!(!edited.contains("bar"), "{edited}");
        assert!(edited.contains("std = [\"serde?/std\"]"), "{edited}");
        assert!(edited.contains("extra = []"), "{edited}");
        assert!(
            edited.contains("baz = { version = \"1\", optional = true }"),
            "{edited}"
        );
    }

    #[test]
    fn set_requirement_for_version_propagates_workspace_and_skips_other_major_lines() {
        let workspace_root = r#"[workspace]
members = ["a", "b"]

[workspace.dependencies]
time = "=0.1.45" # pinned workspace dep
old_time = { package = "time", version = "0.1" }
dotted.package = "time"
dotted.version = "=0.1.45"
local_time = { package = "time", path = "vendor/time", version = "0.1.45" }
git_time = { package = "time", git = "https://example.test/time", version = "0.1.45" }
"#;
        let (edited_root, changed_root) =
            super::set_requirement_for_version(workspace_root, "time", Some("0.1.45"), "0.2.23")
                .expect("valid root manifest");
        assert!(changed_root);
        assert!(
            edited_root.contains("time = \"=0.2.23\" # pinned workspace dep"),
            "{edited_root}"
        );
        assert!(
            edited_root.contains("old_time = { package = \"time\", version = \"0.2.23\" }"),
            "{edited_root}"
        );
        assert!(
            edited_root.contains("dotted.version = \"=0.2.23\""),
            "{edited_root}"
        );
        assert!(
            edited_root.contains(
                "local_time = { package = \"time\", path = \"vendor/time\", version = \"0.1.45\" }"
            ),
            "{edited_root}"
        );
        assert!(
            edited_root.contains("git_time = { package = \"time\", git = \"https://example.test/time\", version = \"0.1.45\" }"),
            "{edited_root}"
        );

        let inheriting_member = "[package]\nname = \"a\"\n\n[dependencies]\ntime = { workspace = true, features = [\"std\"] }\nold_time.workspace = true\n";
        let (edited_a, changed_a) =
            super::set_requirement_for_version(inheriting_member, "time", Some("0.1.45"), "0.2.23")
                .expect("valid member a");
        assert!(!changed_a);
        assert_eq!(edited_a, inheriting_member);

        let newer_major_member = "[package]\nname = \"b\"\n\n[dependencies]\ntime = \"0.3\"\n";
        let (edited_b, changed_b) = super::set_requirement_for_version(
            newer_major_member,
            "time",
            Some("0.1.45"),
            "0.2.23",
        )
        .expect("valid member b");
        assert!(!changed_b);
        assert_eq!(edited_b, newer_major_member);
    }

    #[test]
    fn widen_requirement_for_version_expands_restrictive_bounds() {
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.200\"\nanyhow = \"~1.0.80\"\n";
        let serde_target = semver::Version::parse("1.0.210").expect("semver");
        let (edited_serde, changed_serde) =
            super::widen_requirement_for_version(manifest, "serde", Some("1.0.200"), &serde_target)
                .expect("valid manifest");
        assert!(changed_serde);
        assert!(
            edited_serde.contains("serde = \"=1.0.210\""),
            "{edited_serde}"
        );

        let anyhow_target = semver::Version::parse("1.1.0").expect("semver");
        let (edited_anyhow, changed_anyhow) = super::widen_requirement_for_version(
            &edited_serde,
            "anyhow",
            Some("1.0.80"),
            &anyhow_target,
        )
        .expect("valid manifest");
        assert!(changed_anyhow);
        assert!(
            edited_anyhow.contains("anyhow = \">=1.0.80, <2.0.0\""),
            "{edited_anyhow}"
        );
    }
}
