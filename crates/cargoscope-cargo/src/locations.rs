//! Line numbers of packages in `Cargo.lock` and of dependencies in
//! `Cargo.toml`, used to point SARIF results at the right place.

/// 1-based line of the `name = "..."` line of each `[[package]]`, keyed by
/// `(name, version)`.
#[must_use]
pub fn lockfile_lines(contents: &str) -> Vec<((String, String), u32)> {
    let mut lines = Vec::new();
    let mut current: Option<(String, u32)> = None;
    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if line == "[[package]]" {
            current = None;
        } else if let Some(name) = quoted(line, "name") {
            current = Some((name, number));
        } else if let Some(version) = quoted(line, "version") {
            if let Some((name, name_line)) = current.take() {
                lines.push(((name, version), name_line));
            }
        }
    }
    lines
}

/// 1-based line where `key` is declared in a dependency `section`
/// (`dependencies`, `dev-dependencies` or `build-dependencies`), including
/// `[target.'...'.section]` tables and the `[section.key]` form.
#[must_use]
pub fn manifest_dependency_line(contents: &str, section: &str, key: &str) -> Option<u32> {
    let underscore = section.replace('-', "_");
    let mut in_section = false;
    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if line.starts_with('[') {
            let header = line.trim_start_matches('[').trim_end_matches(']').trim();
            let header = header.split('#').next().unwrap_or(header).trim();
            let header = header.trim_end_matches(']').trim();
            in_section = [section, underscore.as_str()]
                .iter()
                .any(|name| header == *name || header.ends_with(&format!(".{name}")));
            let table_form = [section, underscore.as_str()].iter().any(|name| {
                header == format!("{name}.{key}")
                    || header.ends_with(&format!(".{name}.{key}"))
                    || header == format!("{name}.\"{key}\"")
            });
            if table_form {
                return Some(number);
            }
            continue;
        }
        if !in_section {
            continue;
        }
        let name = line
            .split(['=', '.'])
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"');
        if name == key && line.contains('=') {
            return Some(number);
        }
    }
    None
}

fn quoted(line: &str, key: &str) -> Option<String> {
    let rest = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    Some(rest.strip_prefix('"')?.strip_suffix('"')?.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{lockfile_lines, manifest_dependency_line};

    #[test]
    fn finds_package_lines_in_lockfile() {
        let lock = "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"b\"\nversion = \"2.0.0\"\n";
        assert_eq!(
            lockfile_lines(lock),
            vec![
                (("a".to_owned(), "1.0.0".to_owned()), 4),
                (("b".to_owned(), "2.0.0".to_owned()), 8),
            ]
        );
    }

    #[test]
    fn finds_dependency_lines_in_every_form() {
        let manifest = r#"[package]
name = "demo"
log = "not a dependency"

[dependencies]
log = "0.4"
serde.workspace = true
"quoted-dep" = "1"

[dev-dependencies]
log = "0.4"

[target.'cfg(windows)'.dependencies]
winapi = "0.3"

[build-dependencies.cc]
version = "1"
"#;
        assert_eq!(
            manifest_dependency_line(manifest, "dependencies", "log"),
            Some(6)
        );
        assert_eq!(
            manifest_dependency_line(manifest, "dependencies", "serde"),
            Some(7)
        );
        assert_eq!(
            manifest_dependency_line(manifest, "dependencies", "quoted-dep"),
            Some(8)
        );
        assert_eq!(
            manifest_dependency_line(manifest, "dev-dependencies", "log"),
            Some(11)
        );
        assert_eq!(
            manifest_dependency_line(manifest, "dependencies", "winapi"),
            Some(14)
        );
        assert_eq!(
            manifest_dependency_line(manifest, "build-dependencies", "cc"),
            Some(16)
        );
        assert_eq!(
            manifest_dependency_line(manifest, "dependencies", "missing"),
            None
        );
    }
}
