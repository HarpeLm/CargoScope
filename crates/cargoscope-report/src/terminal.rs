//! The default text report for a terminal: a header with one counter per
//! check, vulnerable crates grouped (one line each, with the version that
//! fixes all their advisories), notices grouped by kind, and the commands to
//! run next. Colors only when asked (a terminal without `NO_COLOR`).
//!
//! `--verbose` keeps the full listing of every advisory instead.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

use cargoscope_core::{AdvisoryFinding, AdvisoryKind, Report, Severity, UnusedConfidence, VERSION};

/// ANSI styling, or none.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Paint {
    on: bool,
}

impl Paint {
    pub(crate) const fn new(on: bool) -> Self {
        Self { on }
    }

    fn style(self, code: &str, text: &str) -> String {
        if self.on {
            format!("\u{1b}[{code}m{text}\u{1b}[0m")
        } else {
            text.to_owned()
        }
    }

    pub(crate) fn red(self, text: &str) -> String {
        self.style("31", text)
    }

    pub(crate) fn yellow(self, text: &str) -> String {
        self.style("33", text)
    }

    pub(crate) fn green(self, text: &str) -> String {
        self.style("32", text)
    }

    pub(crate) fn blue(self, text: &str) -> String {
        self.style("34", text)
    }

    pub(crate) fn dim(self, text: &str) -> String {
        self.style("2", text)
    }

    pub(crate) fn bold(self, text: &str) -> String {
        self.style("1", text)
    }
}

fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("{count} {word}")
    } else {
        format!("{count} {word}s")
    }
}

fn active(report: &Report) -> impl Iterator<Item = &AdvisoryFinding> {
    report
        .advisories
        .iter()
        .filter(|finding| finding.ignored.is_none())
}

/// `CargoScope 0.7.0  path · 106 packages · data from 2026-11-15`, then one
/// colored counter per check that ran.
pub(crate) fn header(out: &mut String, project_root: &Path, report: &Report, paint: Paint) {
    let date = report
        .advisory_db_date
        .as_deref()
        .or(report.registry_date.as_deref())
        .map(|date| format!(" · data from {date}"))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "{}  {}",
        paint.bold(&format!("CargoScope {VERSION}")),
        paint.dim(&format!(
            "{} · {}{date}",
            project_root.display(),
            plural(report.inventory.packages.len(), "package")
        ))
    );

    let mut counters = Vec::new();
    if report.checks.advisories {
        let vulnerable = vulnerable_crates(report).len();
        counters.push(if vulnerable == 0 {
            paint.green("✔ no known vulnerability")
        } else {
            paint.red(&format!("✖ {}", plural(vulnerable, "vulnerable crate")))
        });
        let notices = active(report)
            .filter(|finding| matches!(finding.kind, AdvisoryKind::Informational(_)))
            .count();
        if notices > 0 {
            counters.push(paint.yellow(&format!("⚠ {}", plural(notices, "notice"))));
        }
    }
    if report.checks.unused {
        let likely = report
            .unused
            .iter()
            .filter(|finding| {
                finding.ignored.is_none() && finding.confidence == UnusedConfidence::Likely
            })
            .count();
        counters.push(if likely == 0 {
            paint.green("✔ no unused dependency")
        } else {
            paint.yellow(&format!("✖ {likely} likely unused"))
        });
    }
    if report.checks.versions {
        let outdated = report
            .package_info
            .iter()
            .zip(&report.inventory.packages)
            .filter(|(info, package)| info.outdated && package.direct)
            .count();
        if outdated > 0 {
            counters.push(paint.blue(&format!("↑ {outdated} outdated")));
        }
        let watch = crate::maintenance_rows(report).len();
        if watch > 0 {
            counters.push(paint.yellow(&format!("◆ {watch} to watch")));
        }
    }
    if let Some(violations) = &report.policy {
        let errors = violations
            .iter()
            .filter(|v| v.level == cargoscope_core::policy::ViolationLevel::Error)
            .count();
        counters.push(if errors == 0 {
            paint.green("✔ policy respected")
        } else {
            paint.red(&format!("✖ {}", plural(errors, "policy violation")))
        });
    }
    if !counters.is_empty() {
        let _ = writeln!(out, "\n  {}", counters.join("   "));
    }
}

/// Vulnerabilities not ignored, by package index.
fn vulnerable_crates(report: &Report) -> BTreeMap<usize, Vec<&AdvisoryFinding>> {
    let mut crates: BTreeMap<usize, Vec<&AdvisoryFinding>> = BTreeMap::new();
    for finding in active(report) {
        if matches!(finding.kind, AdvisoryKind::Vulnerability) {
            crates.entry(finding.package).or_default().push(finding);
        }
    }
    crates
}

/// The smallest version above `current` that one advisory's `patched`
/// ranges accept, if any.
fn smallest_fix(finding: &AdvisoryFinding, current: &semver::Version) -> Option<semver::Version> {
    let requirements: Vec<semver::VersionReq> = finding
        .patched
        .iter()
        .filter_map(|range| semver::VersionReq::parse(range).ok())
        .collect();
    requirements
        .iter()
        .flat_map(|requirement| &requirement.comparators)
        .map(|comparator| {
            semver::Version::new(
                comparator.major,
                comparator.minor.unwrap_or(0),
                comparator.patch.unwrap_or(0),
            )
        })
        .filter(|version| {
            version > current
                && requirements
                    .iter()
                    .any(|requirement| requirement.matches(version))
        })
        .min()
}

/// The version that fixes every advisory of a crate, if one does; and how
/// many advisories have no fix at all.
fn crate_fix(findings: &[&AdvisoryFinding], version: &str) -> (Option<semver::Version>, usize) {
    let Ok(current) = semver::Version::parse(version) else {
        return (None, 0);
    };
    let mut without_fix = 0;
    let mut needed: Option<semver::Version> = None;
    for finding in findings {
        match smallest_fix(finding, &current) {
            Some(fix) => needed = Some(needed.map_or(fix.clone(), |known| known.max(fix))),
            None => without_fix += 1,
        }
    }
    let fixes_all = needed.filter(|candidate| {
        findings.iter().all(|finding| {
            finding.patched.is_empty()
                || finding.patched.iter().any(|range| {
                    semver::VersionReq::parse(range)
                        .is_ok_and(|requirement| requirement.matches(candidate))
                })
        })
    });
    (fixes_all, without_fix)
}

/// `a › b › … › y › z`: the first package and the last two steps.
fn short_chain(report: &Report, index: usize) -> Option<String> {
    let path = report.inventory.path_to(index)?;
    let names: Vec<&str> = path
        .iter()
        .map(|&step| report.inventory.packages[step].name.as_str())
        .collect();
    Some(if names.len() > 4 {
        format!(
            "{} › … › {}",
            names[0],
            names[names.len() - 2..].join(" › ")
        )
    } else {
        names.join(" › ")
    })
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_owned()
    } else {
        format!("{}…", text.chars().take(width - 1).collect::<String>())
    }
}

/// Vulnerable crates, one entry each, worst first; then notices by kind.
pub(crate) fn advisories(out: &mut String, report: &Report, paint: Paint) {
    let crates = vulnerable_crates(report);
    if crates.is_empty() {
        let _ = writeln!(
            out,
            "\n{}  {}",
            paint.bold("Vulnerabilities"),
            paint.green("none known (this does not mean the dependencies are safe)")
        );
    } else {
        let _ = writeln!(out, "\n{}", paint.bold("Vulnerabilities"));
        let mut entries: Vec<(usize, Vec<&AdvisoryFinding>)> = crates.into_iter().collect();
        let worst = |findings: &Vec<&AdvisoryFinding>| {
            findings.iter().filter_map(|finding| finding.severity).max()
        };
        entries.sort_by(|left, right| {
            worst(&right.1)
                .cmp(&worst(&left.1))
                .then(right.1.len().cmp(&left.1.len()))
        });
        let name_width = entries
            .iter()
            .map(|(index, _)| {
                let package = &report.inventory.packages[*index];
                package.name.len() + package.version.len() + 1
            })
            .max()
            .unwrap_or(0);
        for (index, findings) in &entries {
            let package = &report.inventory.packages[*index];
            let issue = match findings.as_slice() {
                [only] => format!(
                    "{}: {}",
                    only.severity.map_or("unknown severity", Severity::as_str),
                    truncate(&only.title, 44)
                ),
                many => {
                    let severity = worst(&many.to_vec())
                        .map(|severity| format!(", up to {}", severity.as_str()))
                        .unwrap_or_default();
                    format!("{} advisories{severity}", many.len())
                }
            };
            let (fix, without_fix) = crate_fix(findings, &package.version);
            let fix = match (fix, without_fix) {
                (Some(version), 0) if findings.len() > 1 => {
                    paint.green(&format!("fix: {version} fixes all"))
                }
                (Some(version), 0) => paint.green(&format!("fix: {version}")),
                (_, count) if count == findings.len() => paint.yellow("no fixed version"),
                (_, count) => paint.yellow(&format!("{count} without a fix")),
            };
            let name = format!("{} {}", package.name, package.version);
            let _ = writeln!(
                out,
                "  {} {}{}  {}  {}",
                paint.red("✖"),
                paint.bold(&package.name),
                format!(" {}", package.version)
                    + &" ".repeat(name_width.saturating_sub(name.len())),
                paint.red(&issue),
                fix
            );
            if let Some(chain) = short_chain(report, *index) {
                let _ = writeln!(out, "      {}", paint.dim(&format!("via {chain}")));
            }
        }
    }

    let mut notices: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for finding in active(report) {
        if let AdvisoryKind::Informational(kind) = &finding.kind {
            let name = report.inventory.packages[finding.package].name.clone();
            let names = notices.entry(kind.as_str()).or_default();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    if !notices.is_empty() {
        let _ = writeln!(
            out,
            "\n{} {}",
            paint.bold("Notices"),
            paint.dim("(not vulnerabilities)")
        );
        let kind_width = notices.keys().map(|kind| kind.len()).max().unwrap_or(0);
        for (kind, mut names) in notices {
            names.sort();
            let shown: Vec<String> = names.iter().take(6).cloned().collect();
            let more = names.len().saturating_sub(shown.len());
            let more = if more > 0 {
                format!(" {}", paint.dim(&format!("+{more}")))
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "  {}{}  {}{more}",
                paint.yellow(kind),
                " ".repeat(kind_width - kind.len()),
                shown.join(", ")
            );
        }
    }
    let ignored = report
        .advisories
        .iter()
        .filter(|finding| finding.ignored.is_some())
        .count();
    if ignored > 0 {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "{} ignored by the configuration (see --verbose)",
                plural(ignored, "advisory")
            ))
        );
    }
}

/// The commands that act on what the report found.
pub(crate) fn next_steps(out: &mut String, report: &Report, verbose: bool, paint: Paint) {
    let mut steps: Vec<(String, String)> = Vec::new();
    if (report.checks.advisories && report.advisory_db_date.is_none())
        || ((report.checks.versions || report.checks.licenses) && report.registry_date.is_none())
    {
        steps.push((
            "cargoscope update".to_owned(),
            "download the advisory database and crates.io data".to_owned(),
        ));
    }
    let fixable = vulnerable_crates(report)
        .iter()
        .filter(|(index, findings)| {
            crate_fix(findings, &report.inventory.packages[**index].version)
                .0
                .is_some()
        })
        .count();
    if fixable > 0 {
        steps.push((
            "cargoscope fix --advisories".to_owned(),
            format!(
                "update {}, dry run first",
                plural(fixable, "vulnerable crate")
            ),
        ));
    }
    let likely = report
        .unused
        .iter()
        .filter(|finding| {
            finding.ignored.is_none() && finding.confidence == UnusedConfidence::Likely
        })
        .count();
    if likely > 0 {
        steps.push((
            "cargoscope fix".to_owned(),
            format!(
                "remove {}, dry run first",
                plural(likely, "likely-unused dependency")
            ),
        ));
    }
    let outdated = report
        .package_info
        .iter()
        .zip(&report.inventory.packages)
        .filter(|(info, package)| info.outdated && package.direct)
        .count();
    if outdated > 0 {
        steps.push((
            "cargoscope fix --updates".to_owned(),
            format!("update {}", plural(outdated, "outdated direct dependency")),
        ));
    }
    if !verbose && !report.advisories.is_empty() {
        steps.push((
            "cargoscope scan --verbose".to_owned(),
            "every advisory and package in full".to_owned(),
        ));
    }
    if steps.is_empty() {
        return;
    }
    let width = steps
        .iter()
        .map(|(command, _)| command.len())
        .max()
        .unwrap_or(0);
    let _ = writeln!(out, "\n{}", paint.bold("Next steps"));
    for (command, what) in steps {
        let _ = writeln!(
            out,
            "  {} {command}{}  {}",
            paint.blue("›"),
            " ".repeat(width - command.len()),
            paint.dim(&what)
        );
    }
}

/// Bold section titles (a line at column 0 after an empty line, up to its
/// first colon) and yellow warnings, in the rest of the text report.
pub(crate) fn style_sections(text: &str, paint: Paint) -> String {
    if !paint.on {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len() + 256);
    let mut previous_empty = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("warning:") {
            out.push_str(&paint.yellow("warning:"));
            out.push_str(rest);
        } else if previous_empty
            && line.starts_with(|c: char| c.is_ascii_uppercase())
            && !line.contains('\u{1b}')
        {
            match line.split_once(':') {
                Some((title, rest)) => {
                    out.push_str(&paint.bold(title));
                    out.push(':');
                    out.push_str(rest);
                }
                None => out.push_str(&paint.bold(line)),
            }
        } else {
            out.push_str(line);
        }
        out.push('\n');
        previous_empty = line.is_empty();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Paint, crate_fix, style_sections, truncate};
    use cargoscope_core::{AdvisoryFinding, AdvisoryKind};

    fn finding(patched: &[&str]) -> AdvisoryFinding {
        AdvisoryFinding {
            package: 0,
            id: "RUSTSEC-0".to_owned(),
            aliases: Vec::new(),
            title: "t".to_owned(),
            date: "2026-01-01".to_owned(),
            url: None,
            kind: AdvisoryKind::Vulnerability,
            severity: None,
            patched: patched.iter().map(|range| (*range).to_owned()).collect(),
            ignored: None,
        }
    }

    #[test]
    fn finds_the_version_that_fixes_every_advisory_of_a_crate() {
        let a = finding(&[">= 0.10.48"]);
        let b = finding(&[">= 0.10.78"]);
        let (fix, without) = crate_fix(&[&a, &b], "0.10.33");
        assert_eq!(fix.map(|v| v.to_string()).as_deref(), Some("0.10.78"));
        assert_eq!(without, 0);
        let none = finding(&[]);
        assert_eq!(crate_fix(&[&a, &none], "0.10.33").1, 1);
        // A fix on an old line does not fix the newer line's advisory.
        let old_line = finding(&["^1.1.4"]);
        let new_line = finding(&[">= 2.0.0"]);
        assert_eq!(crate_fix(&[&old_line, &new_line], "1.1.0").0, None);
    }

    #[test]
    fn styles_only_when_asked() {
        let text = "Header\n\nLicenses of 3 packages:\n- MIT: 3\n\nwarning: careful\n";
        assert_eq!(style_sections(text, Paint::new(false)), text);
        let styled = style_sections(text, Paint::new(true));
        assert!(styled.contains("\u{1b}[1mLicenses of 3 packages\u{1b}[0m:"));
        assert!(styled.contains("\u{1b}[33mwarning:\u{1b}[0m careful"));
        assert_eq!(truncate("abcdef", 4), "abc…");
    }
}
