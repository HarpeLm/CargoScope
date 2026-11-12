//! Workspace member discovery, including glob patterns such as `crates/*`.
//!
//! Supports `*` and `?` inside path segments, which covers the patterns
//! Cargo projects use in practice. `**` and `[...]` classes are not expanded
//! and are ignored. Symbolic links are not followed.

use std::fs;
use std::path::Path;

const MAX_MEMBERS: usize = 4_096;

/// Matches one path segment against a pattern with `*` and `?`.
fn segment_matches(pattern: &[u8], name: &[u8]) -> bool {
    match (pattern.first(), name.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            segment_matches(&pattern[1..], name)
                || (!name.is_empty() && segment_matches(pattern, &name[1..]))
        }
        (Some(b'?'), Some(_)) => segment_matches(&pattern[1..], &name[1..]),
        (Some(expected), Some(actual)) if expected == actual => {
            segment_matches(&pattern[1..], &name[1..])
        }
        _ => false,
    }
}

fn is_supported(pattern: &str) -> bool {
    !pattern.contains("**") && !pattern.contains('[') && !pattern.contains("..")
}

/// Expands `pattern` (relative to `root`) into member directories that
/// contain a `Cargo.toml`, as relative paths with `/` separators, sorted.
fn expand(root: &Path, pattern: &str) -> Vec<String> {
    let segments: Vec<&str> = pattern
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    let mut found = Vec::new();
    walk(root, &segments, String::new(), &mut found);
    found.sort();
    found
}

fn walk(dir: &Path, segments: &[&str], prefix: String, found: &mut Vec<String>) {
    if found.len() >= MAX_MEMBERS {
        return;
    }
    let Some((segment, rest)) = segments.split_first() else {
        if is_regular_file(&dir.join("Cargo.toml")) {
            found.push(prefix);
        }
        return;
    };
    let join = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        }
    };
    if !segment.contains(['*', '?']) {
        let next = dir.join(segment);
        if is_directory(&next) {
            walk(&next, rest, join(segment), found);
        }
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| is_directory(&entry.path()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| !name.starts_with('.'))
        .filter(|name| segment_matches(segment.as_bytes(), name.as_bytes()))
        .collect();
    names.sort();
    for name in names {
        walk(&dir.join(&name), rest, join(&name), found);
    }
}

fn is_directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn normalize(path: &str) -> String {
    path.split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// Workspace members of the manifest at `root`: explicit paths and expanded
/// glob patterns, minus `exclude`, without duplicates, in a stable order.
///
/// Returns the members and warnings for patterns that are not supported.
pub fn members(root: &Path, manifest: &toml::Value) -> (Vec<String>, Vec<String>) {
    let workspace = manifest.get("workspace");
    let strings = |key: &str| -> Vec<String> {
        workspace
            .and_then(|workspace| workspace.get(key))
            .and_then(toml::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let excluded: Vec<String> = strings("exclude")
        .iter()
        .map(|path| normalize(path))
        .collect();
    let mut members = Vec::new();
    let mut warnings = Vec::new();

    for pattern in strings("members") {
        if !is_supported(&pattern) {
            warnings.push(format!(
                "workspace member pattern `{pattern}` is not supported and was skipped"
            ));
            continue;
        }
        let expanded = if pattern.contains(['*', '?']) {
            expand(root, &pattern)
        } else {
            vec![normalize(&pattern)]
        };
        for member in expanded {
            if !excluded.contains(&member) && !members.contains(&member) {
                members.push(member);
            }
        }
    }

    (members, warnings)
}

#[cfg(test)]
mod tests {
    use super::{members, segment_matches};
    use std::fs;

    #[test]
    fn matches_star_and_question_mark() {
        assert!(segment_matches(b"*", b"core"));
        assert!(segment_matches(b"cargo*", b"cargoscope"));
        assert!(segment_matches(b"*-cli", b"cargoscope-cli"));
        assert!(segment_matches(b"v?", b"v2"));
        assert!(!segment_matches(b"v?", b"v10"));
        assert!(!segment_matches(b"*-cli", b"cargoscope-core"));
    }

    #[test]
    fn expands_globs_applies_excludes_and_skips_unsupported_patterns() {
        let root = std::env::temp_dir().join(format!("cargoscope-ws-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for dir in [
            "crates/a",
            "crates/b",
            "crates/no-manifest",
            "tools/x",
            "crates/.hidden",
        ] {
            fs::create_dir_all(root.join(dir)).expect("create dir");
        }
        for dir in ["crates/a", "crates/b", "tools/x", "crates/.hidden"] {
            fs::write(
                root.join(dir).join("Cargo.toml"),
                "[package]\nname = \"x\"\n",
            )
            .expect("write");
        }
        let manifest: toml::Value = toml::from_str(
            r#"
            [workspace]
            members = ["crates/*", "tools/x", "./crates/a", "deep/**"]
            exclude = ["crates/b"]
            "#,
        )
        .expect("valid");

        let (found, warnings) = members(&root, &manifest);
        assert_eq!(found, vec!["crates/a", "tools/x"]);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("deep/**"));
        let _ = fs::remove_dir_all(&root);
    }
}
