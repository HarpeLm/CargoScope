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

/// The dependency names a `[features]` table refers to: `name`, `dep:name`,
/// `name/feature` and `name?/feature`.
fn feature_references(document: &DocumentMut) -> Vec<String> {
    let Some(features) = document.get("features").and_then(Item::as_table_like) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for (_, value) in features.iter() {
        let Some(array) = value.as_array() else {
            continue;
        };
        for entry in array.iter().filter_map(|entry| entry.as_str()) {
            let name = entry.strip_prefix("dep:").unwrap_or(entry);
            let name = name.split('/').next().unwrap_or(name);
            names.push(name.trim_end_matches('?').to_owned());
        }
    }
    names
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
/// the underscore spelling and target-specific tables are handled too. A
/// dependency named in `[features]` is skipped: removing it would break the
/// manifest.
///
/// # Errors
///
/// Returns a message when the manifest is not valid TOML.
pub fn remove_dependencies(
    contents: &str,
    removals: &[(&str, &str)],
) -> Result<(String, Vec<Outcome>), String> {
    let mut document: DocumentMut = contents.parse().map_err(|error| format!("{error}"))?;
    let referenced = feature_references(&document);
    let targets: Vec<String> = document
        .get("target")
        .and_then(Item::as_table_like)
        .map(|targets| targets.iter().map(|(name, _)| name.to_owned()).collect())
        .unwrap_or_default();

    let mut outcomes = Vec::new();
    for &(section, key) in removals {
        if referenced.iter().any(|name| name == key) {
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
    let mut item: &mut Item = document.as_item_mut();
    for step in path {
        item = item.get_mut(step.as_str())?;
    }
    item.as_table_like_mut()
}

/// The item at `path` in `document`, if every step exists.
fn item_at<'a>(document: &'a mut DocumentMut, path: &[String]) -> Option<&'a mut Item> {
    let mut item = document.as_item_mut();
    for step in path {
        item = item.get_mut(step.as_str())?;
    }
    Some(item)
}

/// Sets the version requirement of every declaration of the crate `package`
/// (by key, or by `package = "..."` for a renamed dependency) to
/// `requirement`, in the dependency tables of a manifest, its
/// `[target.'...']` tables and its `[workspace.dependencies]`. Entries
/// inherited with `workspace = true` and path or git dependencies without a
/// version are left alone. Returns the new contents and whether anything
/// changed.
///
/// # Errors
///
/// Returns a message when the manifest is not valid TOML.
pub fn set_requirement(
    contents: &str,
    package: &str,
    requirement: &str,
) -> Result<(String, bool), String> {
    let mut document: DocumentMut = contents.parse().map_err(|error| format!("{error}"))?;
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
        let Some(table) = item_at(&mut document, &path).and_then(Item::as_table_like_mut) else {
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
                if value.as_str() != Some(requirement) {
                    // `name = "1.2"`: keep the surrounding spaces and comment.
                    let decor = value.as_value().map(|v| v.decor().clone());
                    *value = toml_edit::value(requirement);
                    if let (Some(decor), Some(new)) = (decor, value.as_value_mut()) {
                        *new.decor_mut() = decor;
                    }
                    changed = true;
                }
            } else if let Some(entry) = value.as_table_like_mut()
                && entry.get("version").is_some()
                && entry.get("version").and_then(Item::as_str) != Some(requirement)
            {
                let decor = entry
                    .get("version")
                    .and_then(Item::as_value)
                    .map(|v| v.decor().clone());
                entry.insert("version", toml_edit::value(requirement));
                if let (Some(decor), Some(new)) =
                    (decor, entry.get_mut("version").and_then(Item::as_value_mut))
                {
                    *new.decor_mut() = decor;
                }
                changed = true;
            }
        }
    }
    Ok((document.to_string(), changed))
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
extra = ["dep:optional-thing"]
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
            "[dependencies]\nchrono = \"0.4.20\" # pinned\nold = { package = \"chrono\", version = \"0.4.20\", default-features = false }\nserde = \"1\"\nshared.workspace = true\n\n[dev-dependencies.chrono]\nversion = \"0.4.20\"\n\n[target.'cfg(unix)'.dependencies]\nchrono = { version = \"0.4.20\", optional = true }\n\n[workspace.dependencies]\nchrono = \"0.4.20\"\n"
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
}
