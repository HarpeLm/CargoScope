//! The default terminal UI (**Telemetry HUD**) for `cargoscope scan`:
//! an instrument-panel header with one KPI per check, horizontal ruled
//! sections, severity/relevance badges (`⌖ affects-you` / `◌ unlikely`),
//! clickable OSC 8 links, proportional weight and license bars, and concise
//! next-step commands.
//!
//! Colors and OSC 8 links are emitted only when enabled (interactive terminal
//! without `NO_COLOR`, or `--color always`). `--verbose` keeps the full
//! exhaustive text listing.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

use cargoscope_core::{
    AdvisoryFinding, AdvisoryKind, AdvisoryRelevance, OutdatedKind, Report, Severity,
    UnusedConfidence, VERSION, policy::ViolationLevel,
};

use crate::TextOptions;

/// The width assumed when the terminal's is unknown (a pipe, a file, CI).
const DEFAULT_WIDTH: usize = 100;
/// The narrowest width the report lays itself out for.
const NARROWEST_WIDTH: usize = 60;
/// The widest the report gets, however wide the terminal.
const WIDEST_WIDTH: usize = 120;
/// Where advisory detail lines start.
const DETAIL_INDENT: usize = 10;

/// The plain six-character label of a severity, as the pills show it.
fn severity_label(severity: Option<Severity>) -> (usize, &'static str) {
    let label = match severity {
        Some(Severity::Critical) => "[CRIT]",
        Some(Severity::High) => "[HIGH]",
        Some(Severity::Medium) => "[MED ]",
        Some(Severity::Low) => "[LOW ]",
        Some(Severity::None) | None => "[UNKN]",
    };
    (6, label)
}

/// ANSI styling, or none.
#[derive(Debug, Clone, Copy)]
pub struct Paint {
    on: bool,
}

impl Paint {
    /// Creates a styling helper enabled only when `on` is `true`.
    #[must_use]
    pub const fn new(on: bool) -> Self {
        Self { on }
    }

    /// Returns whether ANSI styling is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.on
    }

    fn style(self, code: &str, text: &str) -> String {
        if self.on {
            format!("\u{1b}[{code}m{text}\u{1b}[0m")
        } else {
            text.to_owned()
        }
    }

    /// Styles `text` red when enabled.
    #[must_use]
    pub fn red(self, text: &str) -> String {
        self.style("31", text)
    }

    /// Styles `text` bold red when enabled.
    #[must_use]
    pub fn red_bold(self, text: &str) -> String {
        self.style("1;31", text)
    }

    /// Styles `text` yellow/amber when enabled.
    #[must_use]
    pub fn yellow(self, text: &str) -> String {
        self.style("33", text)
    }

    /// Styles `text` bold yellow when enabled.
    #[must_use]
    pub fn yellow_bold(self, text: &str) -> String {
        self.style("1;33", text)
    }

    /// Styles `text` green when enabled.
    #[must_use]
    pub fn green(self, text: &str) -> String {
        self.style("32", text)
    }

    /// Styles `text` bold green when enabled.
    #[must_use]
    pub fn green_bold(self, text: &str) -> String {
        self.style("1;32", text)
    }

    /// Styles `text` blue when enabled.
    #[must_use]
    pub fn blue(self, text: &str) -> String {
        self.style("34", text)
    }

    /// Brand Rust copper-orange (`#fb923c`, ANSI 256 color 209).
    #[must_use]
    pub fn rust(self, text: &str) -> String {
        self.style("38;5;209", text)
    }

    /// Brand Rust copper-orange bold.
    #[must_use]
    pub fn rust_bold(self, text: &str) -> String {
        self.style("1;38;5;209", text)
    }

    /// Brand Optical Scope cyan (`#38bdf8`, ANSI 256 color 39).
    #[must_use]
    pub fn scope(self, text: &str) -> String {
        self.style("38;5;39", text)
    }

    /// Brand Optical Scope cyan bold.
    #[must_use]
    pub fn scope_bold(self, text: &str) -> String {
        self.style("1;38;5;39", text)
    }

    /// Accent purple for `(dev)` / `(build)` tags.
    #[must_use]
    pub fn purple(self, text: &str) -> String {
        self.style("38;5;141", text)
    }

    /// Dims `text` when enabled.
    #[must_use]
    pub fn dim(self, text: &str) -> String {
        self.style("2", text)
    }

    /// Bolds `text` when enabled.
    #[must_use]
    pub fn bold(self, text: &str) -> String {
        self.style("1", text)
    }

    /// High-contrast severity pill (falls back to `[TAG]` when color is off).
    #[must_use]
    fn severity_pill(self, severity: Option<Severity>) -> (String, usize) {
        match severity {
            Some(Severity::Critical) => {
                if self.on {
                    (self.style("1;97;41", " CRIT "), 6)
                } else {
                    ("[CRIT]".to_owned(), 6)
                }
            }
            Some(Severity::High) => {
                if self.on {
                    (self.style("1;97;48;5;166", " HIGH "), 6)
                } else {
                    ("[HIGH]".to_owned(), 6)
                }
            }
            Some(Severity::Medium) => {
                if self.on {
                    (self.style("1;30;43", " MED  "), 6)
                } else {
                    ("[MED ]".to_owned(), 6)
                }
            }
            Some(Severity::Low) => {
                if self.on {
                    (self.style("1;37;100", " LOW  "), 6)
                } else {
                    ("[LOW ]".to_owned(), 6)
                }
            }
            Some(Severity::None) | None => {
                if self.on {
                    (self.style("1;37;100", " UNKN "), 6)
                } else {
                    ("[UNKN]".to_owned(), 6)
                }
            }
        }
    }

    /// Wraps `label` in an OSC 8 terminal hyperlink when styling is enabled.
    #[must_use]
    pub fn link(self, url: &str, label: &str) -> String {
        if self.on {
            format!("\u{1b}]8;;{url}\u{1b}\\{label}\u{1b}]8;;\u{1b}\\")
        } else {
            label.to_owned()
        }
    }
}

pub(crate) fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("{count} {word}")
    } else if let Some(stem) = word.strip_suffix('y') {
        format!("{count} {stem}ies")
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

fn format_duration(ms: u64) -> String {
    if ms >= 10_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms >= 1_000 {
        format!("{:.2}s", ms as f64 / 1000.0)
    } else {
        format!("{ms} ms")
    }
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_owned()
    } else if width <= 1 {
        "…".to_owned()
    } else {
        format!("{}…", text.chars().take(width - 1).collect::<String>())
    }
}

/// Visible width of `text`: its characters, without ANSI styles and OSC 8 links.
fn visible_len(text: &str) -> usize {
    let mut count = 0;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            skip_escape(&mut chars);
        } else {
            count += 1;
        }
    }
    count
}

/// Skips the rest of an escape sequence after its `ESC`, returning it.
fn skip_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut sequence = String::from('\u{1b}');
    match chars.next() {
        Some('[') => {
            sequence.push('[');
            for c in chars.by_ref() {
                sequence.push(c);
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        }
        Some(']') => {
            sequence.push(']');
            while let Some(c) = chars.next() {
                sequence.push(c);
                if c == '\u{7}' {
                    break;
                }
                if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                    sequence.push('\\');
                    chars.next();
                    break;
                }
            }
        }
        Some(other) => sequence.push(other),
        None => {}
    }
    sequence
}

/// Cuts a styled line to `width` visible characters, ending it with `…` and
/// closing any open style or link.
fn clip(line: &str, width: usize) -> String {
    if visible_len(line) <= width {
        return line.to_owned();
    }
    let mut out = String::new();
    let mut count = 0;
    let mut styled = false;
    let mut in_link = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            let sequence = skip_escape(&mut chars);
            if let Some(target) = sequence.strip_prefix("\u{1b}]8;;") {
                in_link = !(target.starts_with('\u{1b}') || target.starts_with('\u{7}'));
            } else if sequence.starts_with("\u{1b}[") {
                styled = sequence != "\u{1b}[0m";
            }
            out.push_str(&sequence);
            continue;
        }
        if count + 1 >= width {
            break;
        }
        out.push(c);
        count += 1;
    }
    out.push('…');
    if in_link {
        out.push_str("\u{1b}]8;;\u{1b}\\");
    }
    if styled {
        out.push_str("\u{1b}[0m");
    }
    out
}

/// Word-wraps plain `text` into lines of at most `width` characters.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(10);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split(' ').filter(|word| !word.is_empty()) {
        let needed = if line.is_empty() {
            word.chars().count()
        } else {
            line.chars().count() + 1 + word.chars().count()
        };
        if needed > width && !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Writes dimmed `text`, wrapped to `width` and indented by `indent`.
fn write_wrapped(out: &mut String, text: &str, indent: usize, width: usize, paint: Paint) {
    for line in wrap(text, width.saturating_sub(indent)) {
        let _ = writeln!(out, "{}{}", " ".repeat(indent), paint.dim(&line));
    }
}

/// The name shown for the project: its directory's name.
fn project_name(project_root: &Path) -> String {
    project_root
        .canonicalize()
        .ok()
        .as_deref()
        .unwrap_or(project_root)
        .file_name()
        .map_or_else(
            || project_root.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        )
}

/// Renders the complete default Telemetry HUD dashboard (`!options.verbose`).
pub(crate) fn render_hud(project_root: &Path, report: &Report, options: TextOptions) -> String {
    let paint = Paint::new(options.color);
    let mut out = String::new();
    let columns = options
        .width
        .unwrap_or(DEFAULT_WIDTH)
        .clamp(NARROWEST_WIDTH, WIDEST_WIDTH);
    let width = hud_header(
        &mut out,
        project_root,
        report,
        options.duration_ms,
        columns,
        paint,
    );

    let mut showed_any_section = false;
    if report.checks.advisories {
        showed_any_section |= hud_advisories(&mut out, report, width, paint);
    }
    if report.checks.policy {
        showed_any_section |= hud_policy(&mut out, report, width, paint);
    }
    if report.checks.versions {
        showed_any_section |= hud_yanked(&mut out, report, width, paint);
        showed_any_section |= hud_recent(&mut out, report, options.now, width, paint);
    }
    if report.checks.unused {
        showed_any_section |= hud_unused(&mut out, report, options.show_uncertain, width, paint);
    }
    if report.checks.versions {
        showed_any_section |= hud_outdated(&mut out, report, width, paint);
        showed_any_section |= hud_maintenance(&mut out, report, width, paint);
    }
    showed_any_section |= hud_unsafe(&mut out, report, width, paint);
    showed_any_section |= hud_audits(&mut out, report, width, paint);
    showed_any_section |= hud_weights(&mut out, report, width, paint);
    showed_any_section |= hud_duplicates(&mut out, report, width, paint);
    if report.checks.licenses {
        showed_any_section |= hud_licenses(&mut out, report, width, paint);
    }

    if !showed_any_section && report.checks.advisories {
        let _ = writeln!(
            out,
            "\n  {} {}",
            paint.green("✔"),
            paint.green(
                "All checks clear — no known vulnerabilities (this does not guarantee safety)"
            )
        );
    }

    for warning in &report.warnings {
        let mut lines = wrap(&format!("warning: {warning}"), width.saturating_sub(2)).into_iter();
        if let Some(first) = lines.next() {
            let rest = first.strip_prefix("warning:").unwrap_or(&first);
            let _ = writeln!(out, "\n  {}{rest}", paint.yellow("warning:"));
        }
        for line in lines {
            let _ = writeln!(out, "  {line}");
        }
    }

    let date_note = report
        .advisory_db_date
        .as_deref()
        .or(report.registry_date.as_deref())
        .map(|date| format!(" · data {date}"))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "\n  {}",
        paint.dim(&format!(
            "Resolved packages: {} (use --verbose to list them){date_note}",
            report.inventory.packages.len()
        ))
    );

    if options.next_steps {
        next_steps(&mut out, report, false, paint);
    }
    let mut fitted = String::with_capacity(out.len());
    for line in out.lines() {
        fitted.push_str(&clip(line, width));
        fitted.push('\n');
    }
    fitted
}

/// Renders the boxed Telemetry HUD header and returns its outer character width.
fn hud_header(
    out: &mut String,
    project_root: &Path,
    report: &Report,
    duration_ms: Option<u64>,
    columns: usize,
    paint: Paint,
) -> usize {
    // Build KPI cells as (plain_width, styled_text).
    let mut cells: Vec<(usize, String)> = Vec::new();
    if report.checks.advisories {
        let vuln = vulnerable_crates(report).len();
        if vuln == 0 {
            let plain = "✔ 0 vuln";
            cells.push((plain.chars().count(), paint.green(plain)));
        } else {
            let plain = format!("✖ {vuln} vuln");
            cells.push((plain.chars().count(), paint.red_bold(&plain)));
        }
        let notices = active(report)
            .filter(|finding| matches!(finding.kind, AdvisoryKind::Informational(_)))
            .count();
        if notices > 0 {
            let plain = format!("⚠ {}", plural(notices, "notice"));
            cells.push((plain.chars().count(), paint.yellow(&plain)));
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
        if likely == 0 {
            let plain = "✔ 0 unused";
            cells.push((plain.chars().count(), paint.green(plain)));
        } else {
            let plain = format!("✖ {likely} unused");
            cells.push((plain.chars().count(), paint.yellow_bold(&plain)));
        }
    }
    if report.checks.versions {
        let outdated = report
            .package_info
            .iter()
            .zip(&report.inventory.packages)
            .filter(|(info, package)| info.outdated && package.direct)
            .count();
        if outdated > 0 {
            let plain = format!("↑ {outdated} outdated");
            cells.push((plain.chars().count(), paint.scope_bold(&plain)));
        }
        let watch = crate::maintenance_rows(report).len();
        if watch > 0 {
            let plain = format!("◆ {watch} watch");
            cells.push((plain.chars().count(), paint.yellow(&plain)));
        }
    }
    let dupes = report.inventory.duplicates().len();
    if dupes > 0 {
        let plain = format!("⊞ {}", plural(dupes, "dupe"));
        cells.push((plain.chars().count(), paint.dim(&plain)));
    }
    {
        let plain = format!("{} pkgs", report.inventory.packages.len());
        cells.push((plain.chars().count(), paint.bold(&plain)));
    }
    if let Some(violations) = &report.policy {
        let errors = violations
            .iter()
            .filter(|v| v.level == ViolationLevel::Error)
            .count();
        if errors == 0 {
            let plain = "✔ policy";
            cells.push((plain.chars().count(), paint.green(plain)));
        } else {
            let plain = format!("✖ {errors} policy");
            cells.push((plain.chars().count(), paint.red_bold(&plain)));
        }
    }

    // Middle rows: "│  <cell>  │  <cell>  │", as many as the width needs.
    let sep_plain = "  │  ";
    let sep_styled = format!("  {}  ", paint.dim("│"));
    let sep_len = sep_plain.chars().count();

    // Right-hand telemetry tag on top border.
    let target_short = truncate(&project_name(project_root), 24);
    let mode = if report.unused_precise {
        "precise"
    } else {
        "offline"
    };
    let mut meta_parts = vec![target_short];
    if let Some(ms) = duration_ms {
        meta_parts.push(format_duration(ms));
    }
    meta_parts.push(mode.to_owned());
    let right_plain = meta_parts.join(" · ");

    let left_plain = format!("◎ CARGOSCOPE {VERSION}");
    // The box spans the report's width; KPI cells wrap onto more rows when needed.
    // Top bar: "╭─ " (3) + left + " " (1) + dashes (>=2) + " " (1) + right + " ─╮" (3)
    let top_fixed = 3 + left_plain.chars().count() + 1 + 2 + 1 + 3;
    let width = columns;
    let right_plain = truncate(&right_plain, width.saturating_sub(top_fixed).max(1));

    let dash_count = width
        .saturating_sub(3 + left_plain.chars().count() + 1 + 1 + right_plain.chars().count() + 3);
    let left_styled = format!(
        "{} {}{} {}",
        paint.scope("◎"),
        paint.rust_bold("CARGO"),
        paint.bold("SCOPE"),
        paint.dim(VERSION)
    );
    let _ = writeln!(
        out,
        "{} {left_styled} {} {} {}",
        paint.scope("╭─"),
        paint.scope(&"─".repeat(dash_count)),
        paint.dim(&right_plain),
        paint.scope("─╮")
    );

    let inner = width.saturating_sub(6);
    let mut rows: Vec<Vec<&(usize, String)>> = vec![Vec::new()];
    let mut row_len = 0;
    for cell in &cells {
        let row = rows.last_mut().expect("rows starts with one row");
        let needed = if row.is_empty() {
            cell.0
        } else {
            row_len + sep_len + cell.0
        };
        if needed > inner && !row.is_empty() {
            rows.push(vec![cell]);
            row_len = cell.0;
        } else {
            row.push(cell);
            row_len = needed;
        }
    }
    for row in rows {
        let row_plain_len =
            row.iter().map(|(w, _)| *w).sum::<usize>() + row.len().saturating_sub(1) * sep_len;
        let kpi_styled: String = row
            .iter()
            .map(|(_, s)| s.as_str())
            .collect::<Vec<_>>()
            .join(&sep_styled);
        let right_pad = width.saturating_sub(3 + row_plain_len + 1);
        let _ = writeln!(
            out,
            "{}  {kpi_styled}{}{}",
            paint.scope("│"),
            " ".repeat(right_pad),
            paint.scope("│")
        );
    }

    let _ = writeln!(
        out,
        "{}",
        paint.scope(&format!("╰{}╯", "─".repeat(width.saturating_sub(2))))
    );
    width
}

fn section_rule(out: &mut String, title: &str, subtitle: Option<&str>, width: usize, paint: Paint) {
    let sub_plain = subtitle.map(|s| format!(" ({s})")).unwrap_or_default();
    let prefix_len = 2 + title.chars().count() + sub_plain.chars().count() + 1;
    let dashes = width.saturating_sub(prefix_len).max(3);
    let sub_styled = subtitle
        .map(|s| format!(" {}", paint.dim(&format!("({s})"))))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "\n  {}{sub_styled} {}",
        paint.bold(title),
        paint.dim(&"─".repeat(dashes))
    );
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
pub fn crate_fix(findings: &[&AdvisoryFinding], version: &str) -> (Option<semver::Version>, usize) {
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

fn format_relevance(relevance: AdvisoryRelevance, paint: Paint) -> (String, usize) {
    match relevance {
        AdvisoryRelevance::AffectsYou => {
            let label = "⌖ affects-you";
            (paint.red(label), label.chars().count())
        }
        AdvisoryRelevance::Possibly => {
            let label = "◐ possibly";
            (paint.yellow(label), label.chars().count())
        }
        AdvisoryRelevance::Unlikely => {
            let label = "◌ unlikely";
            (paint.dim(label), label.chars().count())
        }
    }
}

fn advisory_id_link(finding: &AdvisoryFinding, paint: Paint) -> String {
    if finding.id.starts_with("RUSTSEC-") {
        let url = format!("https://rustsec.org/advisories/{}", finding.id);
        paint.scope(&paint.link(&url, &finding.id))
    } else if let Some(url) = &finding.url {
        paint.scope(&paint.link(url, &finding.id))
    } else {
        paint.scope(&finding.id)
    }
}

fn hud_advisories(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    let mut printed = false;
    let crates = vulnerable_crates(report);
    if !crates.is_empty() {
        printed = true;
        let mut entries: Vec<(usize, Vec<&AdvisoryFinding>)> = crates.into_iter().collect();
        let worst = |findings: &Vec<&AdvisoryFinding>| {
            findings.iter().filter_map(|finding| finding.severity).max()
        };
        let best_relevance = |findings: &Vec<&AdvisoryFinding>| {
            findings
                .iter()
                .map(|finding| finding.relevance)
                .min()
                .unwrap_or(AdvisoryRelevance::AffectsYou)
        };
        entries.sort_by(|left, right| {
            best_relevance(&left.1)
                .cmp(&best_relevance(&right.1))
                .then(worst(&right.1).cmp(&worst(&left.1)))
                .then(right.1.len().cmp(&left.1.len()))
        });
        let affects_count = entries
            .iter()
            .filter(|(_, f)| best_relevance(f) == AdvisoryRelevance::AffectsYou)
            .count();
        let sub = format!(
            "{} · {affects_count} in build scope",
            plural(entries.len(), "crate")
        );
        section_rule(out, "ADVISORIES", Some(&sub), width, paint);

        let name_width = entries
            .iter()
            .map(|(index, _)| {
                let package = &report.inventory.packages[*index];
                package.name.len() + package.version.len() + 1
            })
            .max()
            .unwrap_or(0);

        // Precompute fix text so columns align neatly.
        let rows: Vec<_> = entries
            .iter()
            .map(|(index, findings)| {
                let package = &report.inventory.packages[*index];
                let (fix, without_fix) = crate_fix(findings, &package.version);
                let (fix_plain, fix_styled) = match (fix, without_fix) {
                    (Some(version), 0) if findings.len() > 1 => {
                        let p = format!("→ {version} (fixes all)");
                        (p.clone(), paint.green(&p))
                    }
                    (Some(version), 0) => {
                        let p = format!("→ {version}");
                        (p.clone(), paint.green(&p))
                    }
                    (_, count) if count == findings.len() => {
                        let p = "no fix".to_owned();
                        (p.clone(), paint.yellow(&p))
                    }
                    (_, count) => {
                        let p = format!("{count} unfixed");
                        (p.clone(), paint.yellow(&p))
                    }
                };
                (*index, findings, fix_plain, fix_styled)
            })
            .collect();
        let fix_width = rows
            .iter()
            .map(|(_, _, p, _)| p.chars().count())
            .max()
            .unwrap_or(0);
        let id_width = rows
            .iter()
            .map(|(_, findings, _, _)| {
                findings[0].id.chars().count()
                    + if findings.len() > 1 {
                        format!(" +{}", findings.len() - 1).len()
                    } else {
                        0
                    }
            })
            .max()
            .unwrap_or(0);
        // The fix column moves to the detail line when the row would not fit.
        let fix_inline = 2 + 6 + 2 + name_width + 2 + fix_width + 2 + 13 + 2 + id_width <= width;

        for (index, findings, fix_plain, fix_styled) in rows {
            let package = &report.inventory.packages[index];
            let name_plain_len = package.name.len() + 1 + package.version.len();
            let name_pad = " ".repeat(name_width.saturating_sub(name_plain_len));
            let crate_relevance = best_relevance(findings);
            let (rel_styled, rel_len) = format_relevance(crate_relevance, paint);
            let rel_pad = " ".repeat(13_usize.saturating_sub(rel_len));
            let more = if findings.len() > 1 {
                format!(" +{}", findings.len() - 1)
            } else {
                String::new()
            };
            let fix_column = if fix_inline {
                format!(
                    "{fix_styled}{}  ",
                    " ".repeat(fix_width.saturating_sub(fix_plain.chars().count()))
                )
            } else {
                String::new()
            };

            if crate_relevance == AdvisoryRelevance::Unlikely {
                // One dimmed line: these crates are not built, so they stay quiet.
                let (_, pill_label) = severity_label(worst(findings));
                let reason = findings
                    .iter()
                    .find_map(|finding| finding.relevance_reason.as_deref())
                    .map(|reason| {
                        if reason.contains("is not built") {
                            "not built".to_owned()
                        } else {
                            reason.to_owned()
                        }
                    })
                    .unwrap_or_default();
                let fix_plain_column = if fix_inline {
                    format!(
                        "{fix_plain}{}  ",
                        " ".repeat(fix_width.saturating_sub(fix_plain.chars().count()))
                    )
                } else {
                    String::new()
                };
                let line = format!(
                    "  {pill_label}  {} {}{name_pad}  {fix_plain_column}◌ unlikely{rel_pad}  {}{more}",
                    package.name, package.version, findings[0].id
                );
                if reason.is_empty() {
                    let _ = writeln!(out, "{}", paint.dim(&line));
                } else if line.chars().count() + 2 + reason.chars().count() <= width {
                    let _ = writeln!(out, "{}", paint.dim(&format!("{line}  {reason}")));
                } else {
                    let _ = writeln!(out, "{}", paint.dim(&line));
                    write_wrapped(out, &reason, DETAIL_INDENT, width, paint);
                }
                continue;
            }

            let (pill, _) = paint.severity_pill(worst(findings));
            let id_summary = format!(
                "{}{}",
                advisory_id_link(findings[0], paint),
                paint.dim(&more)
            );
            let _ = writeln!(
                out,
                "  {pill}  {} {}{name_pad}  {fix_column}{rel_styled}{rel_pad}  {id_summary}",
                paint.bold(&package.name),
                paint.dim(&package.version),
            );
            let mut detail_parts = Vec::new();
            if !fix_inline {
                detail_parts.push(format!("fix {fix_plain}"));
            }
            if let Some(chain) = short_chain(report, index) {
                detail_parts.push(format!("via {chain}"));
            }
            if findings.len() == 1 {
                detail_parts.push(findings[0].title.clone());
            }
            if !detail_parts.is_empty() {
                write_wrapped(out, &detail_parts.join(" · "), DETAIL_INDENT, width, paint);
            }
            if crate_relevance != AdvisoryRelevance::AffectsYou
                && let Some(reason) = findings
                    .iter()
                    .find_map(|finding| finding.relevance_reason.as_deref())
            {
                write_wrapped(out, reason, DETAIL_INDENT, width, paint);
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
        printed = true;
        section_rule(out, "NOTICES", Some("not vulnerabilities"), width, paint);
        let kind_width = notices.keys().map(|kind| kind.len()).max().unwrap_or(0);
        for (kind, mut names) in notices {
            names.sort();
            // As many names as fit on the line, keeping room for "+N".
            let room = width.saturating_sub(2 + kind_width + 2 + 5);
            let mut shown: Vec<String> = Vec::new();
            let mut used = 0;
            for name in names.iter().take(6) {
                let needed = used + if shown.is_empty() { 0 } else { 2 } + name.chars().count();
                if needed > room && !shown.is_empty() {
                    break;
                }
                used = needed;
                shown.push(name.clone());
            }
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
                " ".repeat(kind_width.saturating_sub(kind.len())),
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
        printed = true;
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "{} ignored by configuration (see --verbose)",
                plural(ignored, "advisory")
            ))
        );
    }
    printed
}

fn hud_policy(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    let Some(violations) = &report.policy else {
        return false;
    };
    if violations.is_empty() {
        return false;
    }
    let errors = violations
        .iter()
        .filter(|v| v.level == ViolationLevel::Error)
        .count();
    let warnings = violations.len() - errors;
    let sub = match (errors, warnings) {
        (e, 0) => plural(e, "error"),
        (0, w) => plural(w, "warning"),
        (e, w) => format!("{}, {}", plural(e, "error"), plural(w, "warning")),
    };
    section_rule(out, "POLICY", Some(&sub), width, paint);
    for violation in violations.iter().take(10) {
        let icon = match violation.level {
            ViolationLevel::Error => paint.red("✖"),
            ViolationLevel::Warning => paint.yellow("⚠"),
        };
        let target = report
            .inventory
            .packages
            .get(violation.package)
            .map(|pkg| format!("{} {} ", paint.bold(&pkg.name), paint.dim(&pkg.version)))
            .unwrap_or_default();
        let first = format!("  {icon} {}  {target}", paint.dim(violation.rule.as_str()));
        // The message wraps under the line rather than being cut.
        let words: Vec<&str> = violation.message.split(' ').collect();
        let room = width.saturating_sub(visible_len(&first));
        let mut taken = 0;
        let mut used = 0;
        for word in &words {
            let needed = used + usize::from(taken > 0) + word.chars().count();
            if needed > room && taken > 0 {
                break;
            }
            used = needed;
            taken += 1;
        }
        let _ = writeln!(out, "{first}{}", words[..taken].join(" "));
        let rest = words[taken..].join(" ");
        for line in wrap(&rest, width.saturating_sub(6)) {
            let _ = writeln!(out, "      {line}");
        }
        if let Some(chain) = short_chain(report, violation.package) {
            let _ = writeln!(out, "      {}", paint.dim(&format!("via {chain}")));
        }
    }
    if violations.len() > 10 {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "+ {} more — use --verbose for all",
                violations.len() - 10
            ))
        );
    }
    true
}

fn hud_yanked(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    let registry_packages = crate::registry_packages(report);
    let yanked: Vec<usize> = registry_packages
        .iter()
        .filter(|(_, info)| info.yanked == Some(true))
        .map(|(index, _)| *index)
        .collect();
    if yanked.is_empty() {
        return false;
    }
    section_rule(
        out,
        "YANKED",
        Some(&plural(yanked.len(), "crate")),
        width,
        paint,
    );
    for &index in yanked.iter().take(5) {
        let package = &report.inventory.packages[index];
        let chain_note = short_chain(report, index)
            .map(|c| format!("  {}", paint.dim(&format!("← {c}"))))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {} {} {}{chain_note}",
            paint.red("✖"),
            paint.bold(&package.name),
            paint.dim(&package.version)
        );
    }
    if yanked.len() > 5 {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "+ {} more — use --verbose for all",
                yanked.len() - 5
            ))
        );
    }
    true
}

fn hud_recent(
    out: &mut String,
    report: &Report,
    now: Option<u64>,
    width: usize,
    paint: Paint,
) -> bool {
    let rows = crate::recent_releases(report, now);
    if rows.is_empty() {
        return false;
    }
    let sub = format!(
        "{} in the last {} h · review them before trusting",
        plural(rows.len(), "release"),
        cargoscope_core::RECENT_RELEASE_HOURS
    );
    section_rule(out, "RECENT RELEASES", Some(&sub), width, paint);
    for &(index, hours) in rows.iter().take(5) {
        let package = &report.inventory.packages[index];
        let chain_note = short_chain(report, index)
            .map(|c| format!("  {}", paint.dim(&format!("← {c}"))))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {} {} {}  {}{chain_note}",
            paint.yellow("◷"),
            paint.bold(&package.name),
            paint.dim(&package.version),
            paint.yellow(&crate::describe_age(hours))
        );
    }
    if rows.len() > 5 {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "+ {} more — use --verbose for all",
                rows.len() - 5
            ))
        );
    }
    true
}

fn hud_unused(
    out: &mut String,
    report: &Report,
    show_uncertain: bool,
    width: usize,
    paint: Paint,
) -> bool {
    let active_unused: Vec<&cargoscope_core::UnusedFinding> = report
        .unused
        .iter()
        .filter(|finding| finding.ignored.is_none())
        .collect();
    let shown: Vec<&cargoscope_core::UnusedFinding> = active_unused
        .iter()
        .copied()
        .filter(|finding| show_uncertain || finding.confidence == UnusedConfidence::Likely)
        .collect();
    let hidden = active_unused.len() - shown.len();
    let ignored = report.unused.len() - active_unused.len();
    if shown.is_empty() && ignored == 0 {
        if hidden > 0 {
            let _ = writeln!(
                out,
                "\n  {}",
                paint.dim(&format!(
                    "{} possibly-unused {} hidden (use --show-uncertain to list)",
                    hidden,
                    if hidden == 1 {
                        "dependency"
                    } else {
                        "dependencies"
                    }
                ))
            );
            return true;
        }
        return false;
    }
    let mode = if report.unused_precise {
        "compiler --precise"
    } else {
        "static analysis"
    };
    let sub = format!("{} · {mode}", plural(shown.len(), "candidate"));
    section_rule(out, "UNUSED DEPENDENCIES", Some(&sub), width, paint);

    let dep_width = shown
        .iter()
        .map(|finding| finding.dependency.len())
        .max()
        .unwrap_or(0);
    let man_width = shown
        .iter()
        .map(|finding| finding.manifest.len())
        .max()
        .unwrap_or(0);

    for finding in &shown {
        let icon = if finding.confidence == UnusedConfidence::Likely {
            paint.yellow("×")
        } else {
            paint.dim("?")
        };
        let conf = if finding.confidence == UnusedConfidence::Possibly {
            format!("  {}", paint.dim("possibly-unused"))
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "  {icon} {}{}  {}{}  {}{conf}",
            paint.bold(&finding.dependency),
            " ".repeat(dep_width.saturating_sub(finding.dependency.len())),
            finding.manifest,
            " ".repeat(man_width.saturating_sub(finding.manifest.len())),
            paint.dim(&format!("[{}]", finding.kind.section()))
        );
    }
    if hidden > 0 {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "+ {hidden} possibly-unused hidden (use --show-uncertain to list)"
            ))
        );
    }
    if ignored > 0 {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "{ignored} ignored via [package.metadata.cargoscope]"
            ))
        );
    }
    true
}

fn hud_outdated(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    let registry_packages = crate::registry_packages(report);
    let total_outdated = registry_packages
        .iter()
        .filter(|(_, info)| info.outdated)
        .count();
    let direct_outdated: Vec<(usize, &cargoscope_core::PackageInfo)> = registry_packages
        .iter()
        .filter(|(index, info)| info.outdated && report.inventory.packages[*index].direct)
        .copied()
        .collect();
    if direct_outdated.is_empty() {
        return false;
    }
    let sub = format!("{} direct · {total_outdated} total", direct_outdated.len());
    section_rule(out, "OUTDATED DIRECT", Some(&sub), width, paint);

    let shown = direct_outdated.len().min(8);
    let slice = &direct_outdated[..shown];
    let name_w = slice
        .iter()
        .map(|(index, _)| report.inventory.packages[*index].name.len())
        .max()
        .unwrap_or(0);
    let ver_w = slice
        .iter()
        .map(|(index, _)| report.inventory.packages[*index].version.len())
        .max()
        .unwrap_or(0);

    let rows: Vec<_> = slice
        .iter()
        .map(|&(index, info)| {
            let pkg = &report.inventory.packages[index];
            let latest = info.latest_version.as_deref().unwrap_or("?");
            let (target_plain, target_styled, kind_plain, kind_styled) = match info
                .outdated_kind(&pkg.version)
            {
                OutdatedKind::Compatible => {
                    let compat = info.compatible_upgrade(&pkg.version).unwrap_or(latest);
                    (
                        compat.to_owned(),
                        paint.green(compat),
                        "compatible",
                        paint.green("compatible"),
                    )
                }
                OutdatedKind::Breaking => (
                    latest.to_owned(),
                    paint.rust(latest),
                    "breaking",
                    paint.rust("breaking"),
                ),
                OutdatedKind::Both => {
                    let compat = info.compatible_upgrade(&pkg.version).unwrap_or(latest);
                    let p = format!("{compat} / {latest}");
                    let s = format!(
                        "{} {} {}",
                        paint.green(compat),
                        paint.dim("/"),
                        paint.rust(latest)
                    );
                    (p, s, "compat+break", paint.yellow("compat+break"))
                }
                OutdatedKind::None => (latest.to_owned(), paint.bold(latest), "", String::new()),
            };
            (
                pkg,
                info,
                target_plain,
                target_styled,
                kind_plain,
                kind_styled,
            )
        })
        .collect();
    let target_w = rows
        .iter()
        .map(|(_, _, p, _, _, _)| p.len())
        .max()
        .unwrap_or(0);
    let kind_w = rows
        .iter()
        .map(|(_, _, _, _, k, _)| k.len())
        .max()
        .unwrap_or(0);

    for (pkg, info, target_plain, target_styled, kind_plain, kind_styled) in rows {
        let published = info
            .latest_published
            .as_deref()
            .map(|date| format!("  {}", paint.dim(date)))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {}{}  {}{} {} {target_styled}{}  {kind_styled}{}{published}",
            paint.bold(&pkg.name),
            " ".repeat(name_w.saturating_sub(pkg.name.len())),
            paint.dim(&pkg.version),
            " ".repeat(ver_w.saturating_sub(pkg.version.len())),
            paint.dim("→"),
            " ".repeat(target_w.saturating_sub(target_plain.len())),
            " ".repeat(kind_w.saturating_sub(kind_plain.len())),
        );
    }
    if direct_outdated.len() > shown {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "+ {} more — use --verbose for all",
                direct_outdated.len() - shown
            ))
        );
    }
    true
}

fn hud_maintenance(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    let rows = crate::maintenance_rows(report);
    if rows.is_empty() {
        return false;
    }
    let total_direct = crate::registry_packages(report)
        .iter()
        .filter(|(index, _)| {
            let pkg = &report.inventory.packages[*index];
            pkg.direct && !pkg.root
        })
        .count();
    let sub = format!("{} of {total_direct} direct to watch", rows.len());
    section_rule(out, "MAINTENANCE", Some(&sub), width, paint);
    for (index, concerns) in rows.iter().take(6) {
        let pkg = &report.inventory.packages[*index];
        let info = &report.package_info[*index];
        let reasons: Vec<String> = concerns
            .iter()
            .map(|concern| crate::describe_concern(*concern, info))
            .collect();
        let _ = writeln!(
            out,
            "  {} {} {}  {}",
            paint.yellow("◆"),
            paint.bold(&pkg.name),
            paint.dim(&pkg.version),
            reasons.join(" · ")
        );
    }
    if rows.len() > 6 {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "+ {} more — use --verbose for all",
                rows.len() - 6
            ))
        );
    }
    true
}

fn mass_bar(value: usize, max_value: usize, is_top: bool, paint: Paint) -> String {
    const BAR_WIDTH: usize = 10;
    let filled = if max_value == 0 {
        0
    } else {
        ((value * BAR_WIDTH) + max_value / 2)
            .checked_div(max_value)
            .unwrap_or(0)
            .clamp(1, BAR_WIDTH)
    };
    let empty = BAR_WIDTH - filled;
    let fill_str = "━".repeat(filled);
    let empty_str = "─".repeat(empty);
    let colored_fill = if is_top {
        paint.rust(&fill_str)
    } else {
        paint.scope(&fill_str)
    };
    format!("{colored_fill}{}", paint.dim(&empty_str))
}

fn hud_unsafe(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    // Direct dependencies: the ones the project chose. Transitive ones,
    // generated bindings included, are listed with --verbose.
    let (all_rows, _) = crate::unsafe_rows(report);
    let rows: Vec<_> = all_rows
        .iter()
        .filter(|(index, _)| report.inventory.packages[*index].direct)
        .copied()
        .collect();
    if rows.is_empty() {
        return false;
    }
    let direct_counted = report
        .unsafe_code
        .iter()
        .zip(&report.inventory.packages)
        .filter(|(count, package)| count.is_some() && package.direct)
        .count();
    let sub = format!(
        "{} of {} direct dependencies · {} crates in all",
        rows.len(),
        direct_counted,
        all_rows.len()
    );
    section_rule(out, "UNSAFE CODE", Some(&sub), width, paint);
    let shown = rows.len().min(5);
    let slice = &rows[..shown];
    let most = slice.first().map_or(1, |(_, count)| count.total());
    let label_w = slice
        .iter()
        .map(|(index, _)| {
            let pkg = &report.inventory.packages[*index];
            pkg.name.len() + 1 + pkg.version.len()
        })
        .max()
        .unwrap_or(0);
    let total_w = slice
        .iter()
        .map(|(_, count)| count.total().to_string().len())
        .max()
        .unwrap_or(1);
    for (pos, (index, count)) in slice.iter().enumerate() {
        let pkg = &report.inventory.packages[*index];
        let bar = mass_bar(count.total(), most, pos == 0, paint);
        let _ = writeln!(
            out,
            "  {} {}{}  {bar}  {}  {}",
            paint.bold(&pkg.name),
            paint.dim(&pkg.version),
            " ".repeat(label_w.saturating_sub(pkg.name.len() + 1 + pkg.version.len())),
            paint.bold(&format!("{:>total_w$}", count.total())),
            paint.dim(&crate::describe_unsafe(count))
        );
    }
    if rows.len() > shown {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "+ {} more — use --verbose for all",
                rows.len() - shown
            ))
        );
    }
    true
}

fn hud_audits(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    let Some(coverage) = crate::audit_coverage(report) else {
        return false;
    };
    let sub = if coverage.organisations.is_empty() {
        "cargo-vet".to_owned()
    } else {
        format!("cargo-vet · {}", coverage.organisations.join(", "))
    };
    section_rule(out, "AUDITS", Some(&sub), width, paint);
    let _ = writeln!(
        out,
        "  {} {} of {} crates.io packages reviewed by an organisation  {}",
        paint.green("✔"),
        paint.bold(&coverage.audited.to_string()),
        coverage.counted,
        paint.dim(&format!("{} safe-to-deploy", coverage.deploy))
    );
    if !coverage.direct_unaudited.is_empty() {
        let names: Vec<&str> = coverage
            .direct_unaudited
            .iter()
            .map(|&index| report.inventory.packages[index].name.as_str())
            .collect();
        let prefix = "  ◇ no audit of the version in use: ";
        let room = width.saturating_sub(prefix.chars().count() + 6);
        let mut shown: Vec<&str> = Vec::new();
        let mut used = 0;
        for name in &names {
            let needed = used + usize::from(!shown.is_empty()) * 2 + name.chars().count();
            if needed > room && !shown.is_empty() {
                break;
            }
            used = needed;
            shown.push(name);
        }
        let more = names.len() - shown.len();
        let _ = writeln!(
            out,
            "  {} {}{}{}",
            paint.yellow("◇"),
            paint.dim("no audit of the version in use: "),
            shown.join(", "),
            if more > 0 {
                format!(" {}", paint.dim(&format!("+{more}")))
            } else {
                String::new()
            }
        );
    }
    true
}

fn hud_weights(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    let heavy = crate::sorted_heavy_weights(report);
    if heavy.is_empty() {
        return false;
    }
    section_rule(
        out,
        "HEAVIEST DIRECT",
        Some("exclusive / subtree"),
        width,
        paint,
    );
    let shown = heavy.len().min(5);
    let slice = &heavy[..shown];
    let max_exclusive = slice.iter().map(|&(_, exc, _)| exc).max().unwrap_or(1);
    let label_w = slice
        .iter()
        .map(|&(index, _, _)| {
            let pkg = &report.inventory.packages[index];
            pkg.name.len() + 1 + pkg.version.len() + crate::kind_note(report, &pkg.name).len()
        })
        .max()
        .unwrap_or(0);
    let exc_w = slice
        .iter()
        .map(|&(_, exc, _)| exc.to_string().len())
        .max()
        .unwrap_or(1);

    for (pos, &(index, exclusive, tree)) in slice.iter().enumerate() {
        let pkg = &report.inventory.packages[index];
        let note = crate::kind_note(report, &pkg.name);
        let plain_len = pkg.name.len() + 1 + pkg.version.len() + note.len();
        let note_styled = if note.is_empty() {
            String::new()
        } else {
            paint.purple(note)
        };
        let bar = mass_bar(
            exclusive,
            max_exclusive,
            pos == 0 || exclusive * 2 >= max_exclusive,
            paint,
        );
        let exc_text = format!("{exclusive:>exc_w$}");
        let _ = writeln!(
            out,
            "  {} {}{note_styled}{}  {bar}  {} {}",
            paint.bold(&pkg.name),
            paint.dim(&pkg.version),
            " ".repeat(label_w.saturating_sub(plain_len)),
            paint.bold(&exc_text),
            paint.dim(&format!("/ {tree} pkgs"))
        );
    }
    if heavy.len() > shown {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "+ {} more — use --verbose for all",
                heavy.len() - shown
            ))
        );
    }
    true
}

fn hud_duplicates(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    let inventory = &report.inventory;
    let duplicates = inventory.duplicates();
    if duplicates.is_empty() {
        return false;
    }
    let sub = format!(
        "{} compiled more than once",
        plural(duplicates.len(), "crate")
    );
    section_rule(out, "DUPLICATES", Some(&sub), width, paint);
    let shown = duplicates.len().min(5);
    let slice = &duplicates[..shown];
    let name_w = slice.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    let ver_w = slice
        .iter()
        .map(|(_, indices)| {
            indices
                .iter()
                .map(|&index| inventory.packages[index].version.len())
                .sum::<usize>()
                + indices.len().saturating_sub(1) * 2
        })
        .max()
        .unwrap_or(0);

    for (name, indices) in slice {
        let mut versions_styled = Vec::with_capacity(indices.len());
        let mut ver_plain_len = 0usize;
        for (pos, &index) in indices.iter().enumerate() {
            let v = inventory.packages[index].version.as_str();
            if pos > 0 {
                ver_plain_len += 2;
            }
            ver_plain_len += v.len();
            if pos + 1 < indices.len() {
                versions_styled.push(paint.yellow(v));
            } else {
                versions_styled.push(v.to_owned());
            }
        }
        let oldest = indices[0];
        let via = short_chain(report, oldest)
            .map(|c| {
                let note = inventory
                    .path_to(oldest)
                    .and_then(|path| path.get(1).copied())
                    .map_or("", |first| {
                        crate::kind_note(report, &inventory.packages[first].name)
                    });
                format!(
                    "{}  {}",
                    " ".repeat(ver_w.saturating_sub(ver_plain_len)),
                    paint.dim(&format!("← {c}{note}"))
                )
            })
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {}{}  {}{via}",
            paint.bold(name),
            " ".repeat(name_w.saturating_sub(name.len())),
            versions_styled.join(", ")
        );
    }
    if duplicates.len() > shown {
        let _ = writeln!(
            out,
            "  {}",
            paint.dim(&format!(
                "+ {} more — use --verbose for all",
                duplicates.len() - shown
            ))
        );
    }
    true
}

fn hud_licenses(out: &mut String, report: &Report, width: usize, paint: Paint) -> bool {
    let registry_packages = crate::registry_packages(report);
    if registry_packages.is_empty() {
        return false;
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut unknown = 0usize;
    for (_, info) in &registry_packages {
        match info.license.as_deref() {
            Some(expr) => *counts.entry(expr).or_insert(0) += 1,
            None => unknown += 1,
        }
    }
    let total = registry_packages.len();
    if counts.is_empty() && unknown == total {
        return false;
    }
    let mut sorted: Vec<(&str, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));

    let sub = format!(
        "{total} registry pkgs · {}",
        plural(sorted.len(), "expression")
    );
    section_rule(out, "LICENSES", Some(&sub), width, paint);

    // 24-cell segmented distribution bar: top 1 (green), top 2 (scope), top 3 (amber), rest (dim).
    const BAR_WIDTH: usize = 24;
    let c1 = sorted.first().map_or(0, |x| x.1);
    let c2 = sorted.get(1).map_or(0, |x| x.1);
    let c3 = sorted.get(2).map_or(0, |x| x.1);
    let mut w1 = (c1 * BAR_WIDTH) / total;
    let mut w2 = (c2 * BAR_WIDTH) / total;
    let mut w3 = (c3 * BAR_WIDTH) / total;
    if c1 > 0 && w1 == 0 {
        w1 = 1;
    }
    if c2 > 0 && w2 == 0 && w1 < BAR_WIDTH {
        w2 = 1;
    }
    if c3 > 0 && w3 == 0 && w1 + w2 < BAR_WIDTH {
        w3 = 1;
    }
    let used = (w1 + w2 + w3).min(BAR_WIDTH);
    let w_rest = BAR_WIDTH - used;
    let bar = format!(
        "{}{}{}{}",
        paint.green(&"━".repeat(w1.min(BAR_WIDTH))),
        paint.scope(&"━".repeat(w2.min(BAR_WIDTH.saturating_sub(w1)))),
        paint.yellow(&"━".repeat(w3.min(BAR_WIDTH.saturating_sub(w1 + w2)))),
        paint.dim(&"─".repeat(w_rest)),
    );

    let mut summary_parts: Vec<String> = sorted
        .iter()
        .take(3)
        .map(|(expr, count)| format!("{expr} ({count})"))
        .collect();
    if unknown > 0 {
        summary_parts.push(format!("{unknown} unknown"));
    }
    let summary = summary_parts.join(" · ");
    if 2 + BAR_WIDTH + 2 + summary.chars().count() <= width {
        let _ = writeln!(out, "  {bar}  {}", paint.dim(&summary));
    } else {
        let _ = writeln!(out, "  {bar}");
        write_wrapped(out, &summary, 2, width, paint);
    }
    true
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
    let _ = writeln!(out, "\n  {}", paint.bold("Next steps"));
    for (command, what) in steps {
        let _ = writeln!(
            out,
            "  {} {}{}  {}",
            paint.green("›"),
            paint.bold(&command),
            " ".repeat(width.saturating_sub(command.len())),
            paint.dim(&what)
        );
    }
}

/// Bold section titles (a line at column 0 after an empty line, up to its
/// first colon) and yellow warnings, in the verbose text report.
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
    use super::{
        Paint, clip, crate_fix, format_duration, mass_bar, plural, style_sections, truncate,
        visible_len, wrap,
    };
    use cargoscope_core::{AdvisoryFinding, AdvisoryKind, AdvisoryRelevance};

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
            affected_arch: Vec::new(),
            affected_os: Vec::new(),
            affected_functions: Vec::new(),
            relevance: AdvisoryRelevance::AffectsYou,
            relevance_reason: None,
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
        let old_line = finding(&["^1.1.4"]);
        let new_line = finding(&[">= 2.0.0"]);
        assert_eq!(crate_fix(&[&old_line, &new_line], "1.1.0").0, None);
    }

    #[test]
    fn plurals_of_words_ending_in_y() {
        assert_eq!(
            plural(2, "outdated direct dependency"),
            "2 outdated direct dependencies"
        );
        assert_eq!(plural(1, "dependency"), "1 dependency");
        assert_eq!(plural(3, "notice"), "3 notices");
    }

    #[test]
    fn styles_only_when_asked() {
        let text = "Header\n\nLicenses of 3 packages:\n- MIT: 3\n\nwarning: careful\n";
        assert_eq!(style_sections(text, Paint::new(false)), text);
        let styled = style_sections(text, Paint::new(true));
        assert!(styled.contains("\u{1b}[1mLicenses of 3 packages\u{1b}[0m:"));
        assert!(styled.contains("\u{1b}[33mwarning:\u{1b}[0m careful"));
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(
            Paint::new(false).link("https://example.test", "RUSTSEC-1"),
            "RUSTSEC-1"
        );
        assert!(
            Paint::new(true)
                .link("https://example.test", "RUSTSEC-1")
                .contains("\u{1b}]8;;https://example.test\u{1b}\\")
        );
        assert_eq!(mass_bar(5, 10, false, Paint::new(false)), "━━━━━─────");
        assert_eq!(format_duration(24), "24 ms");
        assert_eq!(format_duration(1250), "1.25s");
    }

    #[test]
    fn lines_fit_the_width_without_breaking_styles_or_links() {
        let paint = Paint::new(true);
        let line = format!(
            "{} {}",
            paint.red("vulnerable"),
            paint.link("https://example.test", "RUSTSEC-2026-0001")
        );
        assert_eq!(visible_len(&line), 28);
        assert_eq!(clip(&line, 40), line);
        let cut = clip(&line, 15);
        assert_eq!(visible_len(&cut), 15);
        assert!(cut.ends_with("…\u{1b}]8;;\u{1b}\\"), "{cut:?}");
        let plain = clip("a long plain line", 7);
        assert_eq!(plain, "a long…");
        assert_eq!(
            wrap("via a › b › c · A title that is long", 16),
            ["via a › b › c ·", "A title that is", "long"]
        );
    }
}
