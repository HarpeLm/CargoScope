//! Report rendering: text and JSON today, SARIF planned for v0.1.

use std::fmt::Write;
use std::path::Path;

use cargoscope_core::{Inventory, VERSION};

/// Version of the JSON report format.
pub const JSON_FORMAT_VERSION: u32 = 1;

/// Renders a human-readable inventory report.
#[must_use]
pub fn render_text(project_root: &Path, inventory: &Inventory) -> String {
    let mut out = String::new();
    // Writing to a String cannot fail.
    let _ = writeln!(out, "CargoScope {VERSION}");
    let _ = writeln!(out, "Target: {}", project_root.display());
    let _ = writeln!(out, "Resolved packages: {}", inventory.packages.len());

    for package in &inventory.packages {
        let scope = if package.direct {
            "direct"
        } else {
            "transitive"
        };
        let _ = write!(out, "- {} {} [{scope}]", package.name, package.version);
        if let Some(source) = &package.source {
            let _ = write!(out, " ({source})");
        }
        out.push('\n');
    }

    out
}

/// Renders a versioned JSON inventory report, terminated by a newline.
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
            "{{\"name\":\"{}\",\"version\":\"{}\",\"direct\":{},\"source\":",
            json_escape(&package.name),
            json_escape(&package.version),
            package.direct
        );
        match &package.source {
            Some(source) => {
                let _ = write!(out, "\"{}\"}}", json_escape(source));
            }
            None => out.push_str("null}"),
        }
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

    fn sample() -> Inventory {
        Inventory {
            packages: vec![
                Package {
                    name: "alpha".to_owned(),
                    version: "1.0.0".to_owned(),
                    source: Some("registry+https://example.test".to_owned()),
                    direct: true,
                },
                Package {
                    name: "beta".to_owned(),
                    version: "2.0.0".to_owned(),
                    source: None,
                    direct: false,
                },
            ],
        }
    }

    #[test]
    fn text_report_lists_scope_and_source() {
        let text = render_text(Path::new("."), &sample());
        assert!(text.contains("Resolved packages: 2\n"));
        assert!(text.contains("- alpha 1.0.0 [direct] (registry+https://example.test)\n"));
        assert!(text.contains("- beta 2.0.0 [transitive]\n"));
    }

    #[test]
    fn json_report_is_versioned_and_uses_null_for_missing_source() {
        let json = render_json(Path::new("."), &sample());
        assert!(json.starts_with("{\"format_version\":1,"));
        assert!(json.contains(
            "{\"name\":\"beta\",\"version\":\"2.0.0\",\"direct\":false,\"source\":null}"
        ));
        assert!(json.ends_with("]}\n"));
    }

    #[test]
    fn escapes_quotes_backslashes_and_control_characters() {
        assert_eq!(json_escape("a\"b\\c\n\u{1}"), "a\\\"b\\\\c\\n\\u0001");
    }
}
