//! Report rendering: text and JSON today, SARIF planned for v0.1.

use std::fmt::Write;
use std::path::Path;

use cargoscope_core::{Inventory, Package, VERSION};

/// Version of the JSON report format.
pub const JSON_FORMAT_VERSION: u32 = 1;

fn scope(package: &Package) -> &'static str {
    if package.root {
        "root"
    } else if package.direct {
        "direct"
    } else {
        "transitive"
    }
}

/// Renders a human-readable inventory report.
///
/// Each transitive package shows the shortest dependency chain that pulls it in.
#[must_use]
pub fn render_text(project_root: &Path, inventory: &Inventory) -> String {
    let mut out = String::new();
    // Writing to a String cannot fail.
    let _ = writeln!(out, "CargoScope {VERSION}");
    let _ = writeln!(out, "Target: {}", project_root.display());
    let _ = writeln!(out, "Resolved packages: {}", inventory.packages.len());

    for (index, package) in inventory.packages.iter().enumerate() {
        let _ = write!(
            out,
            "- {} {} [{}]",
            package.name,
            package.version,
            scope(package)
        );
        if let Some(source) = &package.source {
            let _ = write!(out, " ({source})");
        }
        out.push('\n');

        if package.root || package.direct {
            continue;
        }
        match inventory.path_to(index) {
            Some(path) => {
                let chain: Vec<&str> = path
                    .iter()
                    .map(|&step| inventory.packages[step].name.as_str())
                    .collect();
                let _ = writeln!(out, "    via {}", chain.join(" -> "));
            }
            None => out.push_str("    not reachable from any root package\n"),
        }
    }

    out
}

/// Renders a versioned JSON inventory report, terminated by a newline.
///
/// Each package carries its `scope` and `path`: the shortest chain of
/// `{name, version}` from a root package to it, or `null` when unreachable.
#[must_use]
pub fn render_json(project_root: &Path, inventory: &Inventory) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\"format_version\":{JSON_FORMAT_VERSION},\"tool_version\":\"{}\",\"target\":\"{}\",\"packages\":[",
        json_escape(VERSION),
        json_escape(&project_root.display().to_string())
    );

    for (index, package) in inventory.packages.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"name\":\"{}\",\"version\":\"{}\",\"scope\":\"{}\",\"direct\":{},\"source\":",
            json_escape(&package.name),
            json_escape(&package.version),
            scope(package),
            package.direct
        );
        match &package.source {
            Some(source) => {
                let _ = write!(out, "\"{}\"", json_escape(source));
            }
            None => out.push_str("null"),
        }
        out.push_str(",\"path\":");
        match inventory.path_to(index) {
            Some(path) => {
                out.push('[');
                for (position, &step) in path.iter().enumerate() {
                    if position > 0 {
                        out.push(',');
                    }
                    let step = &inventory.packages[step];
                    let _ = write!(
                        out,
                        "{{\"name\":\"{}\",\"version\":\"{}\"}}",
                        json_escape(&step.name),
                        json_escape(&step.version)
                    );
                }
                out.push(']');
            }
            None => out.push_str("null"),
        }
        out.push('}');
    }

    out.push_str("]}\n");
    out
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", u32::from(character));
            }
            character => escaped.push(character),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::{json_escape, render_json, render_text};
    use cargoscope_core::{Inventory, Package};
    use std::path::Path;

    fn package(
        name: &str,
        source: Option<&str>,
        root: bool,
        direct: bool,
        deps: Vec<usize>,
    ) -> Package {
        Package {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            source: source.map(str::to_owned),
            root,
            direct,
            dependencies: deps,
        }
    }

    // 0 app (root) -> 1 alpha (direct) -> 2 beta (transitive); 3 orphan
    fn sample() -> Inventory {
        Inventory {
            packages: vec![
                package("app", None, true, false, vec![1]),
                package(
                    "alpha",
                    Some("registry+https://example.test"),
                    false,
                    true,
                    vec![2],
                ),
                package("beta", None, false, false, vec![]),
                package("orphan", None, false, false, vec![]),
            ],
        }
    }

    #[test]
    fn text_report_lists_scope_source_and_path() {
        let text = render_text(Path::new("."), &sample());
        assert!(text.contains("Resolved packages: 4\n"));
        assert!(text.contains("- app 1.0.0 [root]\n"));
        assert!(text.contains("- alpha 1.0.0 [direct] (registry+https://example.test)\n"));
        assert!(text.contains("- beta 1.0.0 [transitive]\n    via app -> alpha -> beta\n"));
        assert!(
            text.contains("- orphan 1.0.0 [transitive]\n    not reachable from any root package\n")
        );
    }

    #[test]
    fn json_report_includes_scope_and_path() {
        let json = render_json(Path::new("."), &sample());
        assert!(json.starts_with("{\"format_version\":1,"));
        assert!(json.contains(
            "{\"name\":\"beta\",\"version\":\"1.0.0\",\"scope\":\"transitive\",\"direct\":false,\"source\":null,\"path\":[{\"name\":\"app\",\"version\":\"1.0.0\"},{\"name\":\"alpha\",\"version\":\"1.0.0\"},{\"name\":\"beta\",\"version\":\"1.0.0\"}]}"
        ));
        assert!(json.contains("\"name\":\"orphan\",\"version\":\"1.0.0\",\"scope\":\"transitive\",\"direct\":false,\"source\":null,\"path\":null}"));
        assert!(json.ends_with("]}\n"));
    }

    #[test]
    fn escapes_quotes_backslashes_and_control_characters() {
        assert_eq!(json_escape("a\"b\\c\n\u{1}"), "a\\\"b\\\\c\\n\\u0001");
    }
}
