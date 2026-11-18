//! `cargoscope init`: creates `cargoscope.toml` (translating `deny.toml` and
//! `.cargo/audit.toml` when present) and/or `.github/workflows/cargoscope.yml`.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargoscope_cargo::config::{
    AdvisoryIgnore, FILE_NAME as CONFIG_FILE, external_advisory_ignores, parse_advisory_ignores,
    parse_policy,
};
use cargoscope_core::policy::{LintLevel, Policy, UnknownLicense};

const WORKFLOW_REL_PATH: &str = ".github/workflows/cargoscope.yml";

/// Parsed options for `cargoscope init`.
#[derive(Debug, PartialEq, Eq)]
pub struct InitOptions {
    pub path: PathBuf,
    pub ci: bool,
    pub policy: bool,
    pub dry_run: bool,
    pub force: bool,
}

impl InitOptions {
    fn write_policy(&self) -> bool {
        self.policy || !self.ci
    }

    fn write_ci(&self) -> bool {
        self.ci
    }
}

/// Parses arguments for `cargoscope init`.
///
/// # Errors
///
/// Returns an error message on unknown flags or multiple paths.
pub fn parse_init_options(arguments: impl Iterator<Item = String>) -> Result<InitOptions, String> {
    let mut options = InitOptions {
        path: PathBuf::from("."),
        ci: false,
        policy: false,
        dry_run: false,
        force: false,
    };
    let mut path_given = false;
    for argument in arguments {
        match argument.as_str() {
            "--ci" => options.ci = true,
            "--policy" => options.policy = true,
            "--dry-run" => options.dry_run = true,
            "--force" => options.force = true,
            other if other.starts_with('-') => {
                return Err(format!("Unknown option for init: {other}"));
            }
            _ if path_given => return Err("Only one path may be provided.".to_owned()),
            _ => {
                options.path = PathBuf::from(argument);
                path_given = true;
            }
        }
    }
    Ok(options)
}

/// Minimal, permission-safe GitHub Actions workflow template for `cargoscope init --ci`.
#[must_use]
pub fn render_ci_workflow() -> &'static str {
    "\
name: CargoScope

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write   # optional: uploads SARIF to GitHub code scanning
  pull-requests: write     # optional: comments on pull requests with what changed

jobs:
  cargoscope:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HarpeLm/CargoScope@v0.7.5
        with:
          fail-on: high    # or none, to report without failing builds
"
}

fn starter_cargoscope_toml() -> &'static str {
    "\
# CargoScope configuration (see https://github.com/HarpeLm/CargoScope/blob/main/docs/policy.md)

# [graph]
# exclude-dev = true
# targets = [\"x86_64-unknown-linux-gnu\", \"aarch64-apple-darwin\"]

[licenses]
allow = [\"MIT\", \"Apache-2.0\", \"BSD-3-Clause\", \"Unicode-3.0\", \"ISC\", \"Zlib\"]
deny = []
unknown = \"deny\"

[sources]
allow-registries = [\"crates.io\"]
unknown-registry = \"deny\"
unknown-git = \"deny\"

[bans]
multiple-versions = \"allow\"
# skip-multiple-versions = [\"windows-sys\"]

# [advisories]
# ignore = [{ id = \"RUSTSEC-0000-0000\", reason = \"why it does not apply\" }]

# [updates]
# open-pull-requests-limit = 5
# include-dev = true
"
}

fn toml_str(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

fn toml_array(items: &[String]) -> String {
    let encoded: Vec<String> = items.iter().map(|item| toml_str(item)).collect();
    format!("[{}]", encoded.join(", "))
}

fn lint_level_str(level: LintLevel) -> &'static str {
    match level {
        LintLevel::Allow => "allow",
        LintLevel::Warn => "warn",
        LintLevel::Deny => "deny",
    }
}

fn push_inline_str(fields: &mut Vec<String>, key: &str, value: &str) {
    fields.push(format!("{key} = {}", toml_str(value)));
}

fn append_graph(out: &mut String, policy: &Policy) {
    let feature_list = policy
        .features
        .as_ref()
        .map(|features| features.list.as_slice())
        .unwrap_or(&[]);
    let all_features = policy
        .features
        .as_ref()
        .is_some_and(|features| features.all);
    let no_default = policy
        .features
        .as_ref()
        .is_some_and(|features| features.no_default);
    if policy.targets.is_empty()
        && feature_list.is_empty()
        && !all_features
        && !no_default
        && !policy.exclude_dev
    {
        return;
    }
    out.push_str("[graph]\n");
    if !policy.targets.is_empty() {
        let _ = writeln!(out, "targets = {}", toml_array(&policy.targets));
    }
    if !feature_list.is_empty() {
        let _ = writeln!(out, "features = {}", toml_array(feature_list));
    }
    if all_features {
        out.push_str("all-features = true\n");
    }
    if no_default {
        out.push_str("no-default-features = true\n");
    }
    if policy.exclude_dev {
        out.push_str("exclude-dev = true\n");
    }
    if policy.exclude_unpublished {
        out.push_str(
            "# Note: deny.toml had exclude-unpublished = true (cargoscope.toml checks all workspace members unless limited via targets/features).\n",
        );
    }
    out.push('\n');
}

fn append_licenses(out: &mut String, policy: &Policy) {
    if !policy.check_licenses {
        return;
    }
    out.push_str("[licenses]\n");
    let _ = writeln!(out, "allow = {}", toml_array(&policy.allow_licenses));
    if policy.allow_licenses.is_empty() && policy.empty_allow_denies_all {
        out.push_str(
            "# Note: empty `allow` rejects every license in cargo-deny; in cargoscope.toml an empty `allow` permits any license not in `deny`.\n",
        );
    }
    if !policy.deny_licenses.is_empty() {
        let _ = writeln!(out, "deny = {}", toml_array(&policy.deny_licenses));
    }
    let unknown = match policy.unknown_license {
        UnknownLicense::Deny => "deny",
        UnknownLicense::Allow => "allow",
    };
    let _ = writeln!(out, "unknown = {}", toml_str(unknown));
    if policy.licenses_include_workspace {
        out.push_str("include-workspace = true\n");
    }
    if policy.confidence_threshold != 800 {
        let ratio = format!("{:.3}", f64::from(policy.confidence_threshold) / 1000.0);
        let trimmed = ratio.trim_end_matches('0').trim_end_matches('.');
        let _ = writeln!(out, "confidence-threshold = {trimmed}");
    }
    if policy.unused_allowed_license != LintLevel::Allow {
        let _ = writeln!(
            out,
            "unused-allowed-license = {}",
            toml_str(lint_level_str(policy.unused_allowed_license))
        );
    }
    let exceptions: Vec<_> = policy
        .license_exceptions
        .iter()
        .filter(|entry| !entry.allow.is_empty())
        .collect();
    if !exceptions.is_empty() {
        out.push_str("exceptions = [\n");
        for entry in exceptions {
            let mut fields = Vec::new();
            push_inline_str(&mut fields, "name", &entry.name);
            if let Some(version) = &entry.version {
                push_inline_str(&mut fields, "version", version);
            }
            fields.push(format!("allow = {}", toml_array(&entry.allow)));
            push_inline_str(&mut fields, "reason", non_empty_reason(&entry.reason));
            let _ = writeln!(out, "  {{ {} }},", fields.join(", "));
        }
        out.push_str("]\n");
    }
    if !policy.license_clarifications.is_empty() {
        out.push_str("clarify = [\n");
        for entry in &policy.license_clarifications {
            let mut fields = Vec::new();
            push_inline_str(&mut fields, "name", &entry.name);
            if let Some(version) = &entry.version {
                push_inline_str(&mut fields, "version", version);
            }
            push_inline_str(&mut fields, "expression", &entry.expression);
            push_inline_str(&mut fields, "reason", non_empty_reason(&entry.reason));
            if !entry.license_files.is_empty() {
                let files: Vec<String> = entry
                    .license_files
                    .iter()
                    .map(|file| match file.hash {
                        Some(hash) => {
                            format!("{{ path = {}, hash = 0x{hash:08x} }}", toml_str(&file.path))
                        }
                        None => format!("{{ path = {} }}", toml_str(&file.path)),
                    })
                    .collect();
                fields.push(format!("license-files = [{}]", files.join(", ")));
            }
            let _ = writeln!(out, "  {{ {} }},", fields.join(", "));
        }
        out.push_str("]\n");
    }
    if policy.private_ignore
        || !policy.private_registries.is_empty()
        || !policy.private_ignore_sources.is_empty()
    {
        out.push_str("\n[licenses.private]\n");
        if policy.private_ignore {
            out.push_str("ignore = true\n");
        }
        if !policy.private_registries.is_empty() {
            let _ = writeln!(
                out,
                "registries = {}",
                toml_array(&policy.private_registries)
            );
        }
        if !policy.private_ignore_sources.is_empty() {
            let _ = writeln!(
                out,
                "ignore-sources = {}",
                toml_array(&policy.private_ignore_sources)
            );
        }
    }
    out.push('\n');
}

fn append_sources(out: &mut String, policy: &Policy) {
    let Some(registries) = &policy.allow_registries else {
        return;
    };
    out.push_str("[sources]\n");
    let _ = writeln!(out, "allow-registries = {}", toml_array(registries));
    if !policy.allow_git.is_empty() {
        let _ = writeln!(out, "allow-git = {}", toml_array(&policy.allow_git));
    }
    let _ = writeln!(
        out,
        "unknown-registry = {}",
        toml_str(lint_level_str(policy.registry_source_level))
    );
    let _ = writeln!(
        out,
        "unknown-git = {}",
        toml_str(lint_level_str(policy.git_source_level))
    );
    out.push('\n');
}

fn append_bans(out: &mut String, policy: &Policy) {
    let feature_bans: Vec<_> = policy
        .feature_bans
        .iter()
        .filter(|ban| !ban.allow.is_empty() || !ban.deny.is_empty() || ban.exact)
        .collect();
    let has_bans = !policy.bans.is_empty()
        || !feature_bans.is_empty()
        || policy.allow_build_scripts.is_some()
        || policy.build_include_workspace
        || policy.build_inspection.is_some()
        || policy.multiple_versions != LintLevel::Allow
        || !policy.skip_multiple_versions.is_empty()
        || !policy.deny_multiple_versions_of.is_empty()
        || !policy.skip_multiple_versions_trees.is_empty();
    if !has_bans {
        return;
    }
    out.push_str("[bans]\n");
    if policy.multiple_versions != LintLevel::Allow || !policy.skip_multiple_versions.is_empty() {
        let _ = writeln!(
            out,
            "multiple-versions = {}",
            toml_str(lint_level_str(policy.multiple_versions))
        );
    }
    if !policy.skip_multiple_versions.is_empty() {
        let _ = writeln!(
            out,
            "skip-multiple-versions = {}",
            toml_array(&policy.skip_multiple_versions)
        );
    }
    if !policy.deny_multiple_versions_of.is_empty() {
        let _ = writeln!(
            out,
            "# Note: deny.toml had deny-multiple-versions on: {}",
            policy.deny_multiple_versions_of.join(", ")
        );
    }
    if !policy.skip_multiple_versions_trees.is_empty() {
        let names: Vec<&str> = policy
            .skip_multiple_versions_trees
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        let _ = writeln!(
            out,
            "# Note: deny.toml had skip-tree on: {}",
            names.join(", ")
        );
    }
    if !policy.bans.is_empty() {
        out.push_str("deny = [\n");
        for ban in &policy.bans {
            let mut fields = Vec::new();
            push_inline_str(&mut fields, "name", &ban.name);
            if let Some(version) = &ban.version {
                push_inline_str(&mut fields, "version", version);
            }
            push_inline_str(&mut fields, "reason", non_empty_reason(&ban.reason));
            if !ban.wrappers.is_empty() {
                fields.push(format!("wrappers = {}", toml_array(&ban.wrappers)));
            }
            let _ = writeln!(out, "  {{ {} }},", fields.join(", "));
        }
        out.push_str("]\n");
    }
    if !feature_bans.is_empty() {
        out.push_str("features = [\n");
        for ban in feature_bans {
            let mut fields = Vec::new();
            push_inline_str(&mut fields, "name", &ban.name);
            if let Some(version) = &ban.version {
                push_inline_str(&mut fields, "version", version);
            }
            if !ban.allow.is_empty() {
                fields.push(format!("allow = {}", toml_array(&ban.allow)));
            }
            if !ban.deny.is_empty() {
                fields.push(format!("deny = {}", toml_array(&ban.deny)));
            }
            if ban.exact {
                fields.push("exact = true".to_owned());
            }
            push_inline_str(&mut fields, "reason", non_empty_reason(&ban.reason));
            let _ = writeln!(out, "  {{ {} }},", fields.join(", "));
        }
        out.push_str("]\n");
    }
    if policy.allow_build_scripts.is_some()
        || policy.build_include_workspace
        || policy.build_inspection.is_some()
    {
        out.push_str("\n[bans.build]\n");
        if let Some(allow) = &policy.allow_build_scripts {
            let items: Vec<String> = allow
                .iter()
                .map(|entry| match &entry.version {
                    Some(version) => format!(
                        "{{ name = {}, version = {} }}",
                        toml_str(&entry.name),
                        toml_str(version)
                    ),
                    None => toml_str(&entry.name),
                })
                .collect();
            let _ = writeln!(out, "allow-build-scripts = [{}]", items.join(", "));
        }
        if policy.build_include_workspace {
            out.push_str("include-workspace = true\n");
        }
        if let Some(inspection) = &policy.build_inspection {
            let _ = writeln!(
                out,
                "executables = {}",
                toml_str(lint_level_str(inspection.executables))
            );
            if inspection.interpreted != LintLevel::Allow {
                let _ = writeln!(
                    out,
                    "interpreted = {}",
                    toml_str(lint_level_str(inspection.interpreted))
                );
            }
            if !inspection.script_extensions.is_empty() {
                let _ = writeln!(
                    out,
                    "script-extensions = {}",
                    toml_array(&inspection.script_extensions)
                );
            }
            if inspection.enable_builtin_globs {
                out.push_str("enable-builtin-globs = true\n");
            }
            if inspection.include_dependencies {
                out.push_str("include-dependencies = true\n");
            }
            if inspection.include_archives {
                out.push_str("include-archives = true\n");
            }
            if !inspection.bypass.is_empty() {
                out.push_str("bypass = [\n");
                for entry in &inspection.bypass {
                    let mut fields = Vec::new();
                    push_inline_str(&mut fields, "name", &entry.name);
                    if let Some(version) = &entry.version {
                        push_inline_str(&mut fields, "version", version);
                    }
                    if let Some(sum) = &entry.build_script {
                        push_inline_str(&mut fields, "build-script", sum);
                    }
                    if !entry.required_features.is_empty() {
                        fields.push(format!(
                            "required-features = {}",
                            toml_array(&entry.required_features)
                        ));
                    }
                    if !entry.allow_globs.is_empty() {
                        fields.push(format!("allow-globs = {}", toml_array(&entry.allow_globs)));
                    }
                    if !entry.allow.is_empty() {
                        let files: Vec<String> = entry
                            .allow
                            .iter()
                            .map(|(path, sum)| match sum {
                                Some(sum) => format!(
                                    "{{ path = {}, checksum = {} }}",
                                    toml_str(path),
                                    toml_str(sum)
                                ),
                                None => format!("{{ path = {} }}", toml_str(path)),
                            })
                            .collect();
                        fields.push(format!("allow = [{}]", files.join(", ")));
                    }
                    let _ = writeln!(out, "  {{ {} }},", fields.join(", "));
                }
                out.push_str("]\n");
            }
        }
    }
    out.push('\n');
}

fn append_advisories(out: &mut String, ignores: &[AdvisoryIgnore]) {
    if ignores.is_empty() {
        return;
    }
    out.push_str("[advisories]\nignore = [\n");
    for ignore in ignores {
        let mut fields = Vec::new();
        push_inline_str(&mut fields, "id", &ignore.id);
        push_inline_str(&mut fields, "reason", non_empty_reason(&ignore.reason));
        if let Some(until) = &ignore.until {
            push_inline_str(&mut fields, "until", until);
        }
        let _ = writeln!(out, "  {{ {} }},", fields.join(", "));
    }
    out.push_str("]\n\n");
}

fn non_empty_reason(reason: &str) -> &str {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        "from existing policy"
    } else {
        trimmed
    }
}

/// Renders `cargoscope.toml` for `project_root`, translating `deny.toml` and
/// `.cargo/audit.toml` when present, or returns a starter template otherwise.
/// Also returns the translated `deny.toml` path (if any) and translation notes.
///
/// # Errors
///
/// Returns an error if an existing `deny.toml` cannot be read or if the
/// rendered configuration fails CargoScope validation.
pub fn render_cargoscope_toml(
    project_root: &Path,
) -> Result<(String, Option<PathBuf>, Vec<String>), String> {
    let translation = cargoscope_cargo::deny::load(project_root)?;
    let ignores = external_advisory_ignores(project_root)?;

    let (source_deny, policy, notes) = match translation {
        Some(translation) => (
            Some(translation.path),
            translation.policy,
            translation.notes,
        ),
        None => (None, None, Vec::new()),
    };

    if source_deny.is_none() && ignores.is_empty() {
        let text = starter_cargoscope_toml().to_owned();
        parse_policy(&text)?;
        parse_advisory_ignores(&text)?;
        return Ok((text, None, notes));
    }

    let mut out = String::from("# Generated by `cargoscope init`");
    if let Some(path) = &source_deny {
        let label = path.strip_prefix(project_root).unwrap_or(path);
        let _ = write!(out, " from {}", label.display());
    }
    if ignores
        .iter()
        .any(|ignore| ignore.source == ".cargo/audit.toml")
    {
        out.push_str(" (+ .cargo/audit.toml)");
    }
    out.push('\n');
    for note in &notes {
        let _ = writeln!(out, "# Note: {note}");
    }
    out.push('\n');

    if let Some(policy) = &policy {
        append_graph(&mut out, policy);
        append_licenses(&mut out, policy);
        append_sources(&mut out, policy);
        append_bans(&mut out, policy);
    }
    append_advisories(&mut out, &ignores);
    out.push_str("# [updates]\n# open-pull-requests-limit = 5\n# include-dev = true\n");

    parse_policy(&out)?;
    parse_advisory_ignores(&out)?;
    Ok((out, source_deny, notes))
}

/// Executes `cargoscope init`.
pub fn init_command(arguments: impl Iterator<Item = String>) -> ExitCode {
    let options = match parse_init_options(arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\nRun cargoscope init --help for usage.");
            return ExitCode::from(2);
        }
    };

    let root = options.path.as_path();
    if options.write_policy() && !root.join("Cargo.toml").is_file() {
        eprintln!(
            "CargoScope could not initialize: no Cargo.toml found at {}",
            root.display()
        );
        return ExitCode::from(2);
    }

    let policy_path = root.join(CONFIG_FILE);
    let workflow_path = root.join(WORKFLOW_REL_PATH);
    if !options.dry_run && !options.force {
        if options.write_policy() && policy_path.exists() {
            eprintln!(
                "CargoScope could not initialize: {} already exists (use --force to overwrite, or --dry-run to preview)",
                policy_path.display()
            );
            return ExitCode::from(2);
        }
        if options.write_ci() && workflow_path.exists() {
            eprintln!(
                "CargoScope could not initialize: {} already exists (use --force to overwrite, or --dry-run to preview)",
                workflow_path.display()
            );
            return ExitCode::from(2);
        }
    }

    let policy_rendered = if options.write_policy() {
        match render_cargoscope_toml(root) {
            Ok(rendered) => Some(rendered),
            Err(error) => {
                eprintln!("CargoScope could not initialize: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };

    if options.dry_run {
        if let Some((text, _, notes)) = &policy_rendered {
            println!("# {}\n{text}", policy_path.display());
            for note in notes {
                eprintln!("warning: {note}");
            }
        }
        if options.write_ci() {
            println!("# {}\n{}", workflow_path.display(), render_ci_workflow());
        }
        return ExitCode::SUCCESS;
    }

    if let Some((text, source_deny, notes)) = policy_rendered {
        if let Err(error) = fs::write(&policy_path, &text) {
            eprintln!(
                "CargoScope could not write {}: {error}",
                policy_path.display()
            );
            return ExitCode::from(2);
        }
        println!("Created {}", policy_path.display());
        if let Some(deny_path) = source_deny {
            println!("Translated from {}", deny_path.display());
        }
        for note in &notes {
            eprintln!("warning: {note}");
        }
    }

    if options.write_ci() {
        if let Some(parent) = workflow_path.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            eprintln!("CargoScope could not create {}: {error}", parent.display());
            return ExitCode::from(2);
        }
        if let Err(error) = fs::write(&workflow_path, render_ci_workflow()) {
            eprintln!(
                "CargoScope could not write {}: {error}",
                workflow_path.display()
            );
            return ExitCode::from(2);
        }
        println!("Created {}", workflow_path.display());
    } else {
        println!("Tip: run `cargoscope init --ci` to also create {WORKFLOW_REL_PATH}.");
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{parse_init_options, render_cargoscope_toml, render_ci_workflow};
    use cargoscope_cargo::config::{parse_advisory_ignores, parse_policy};
    use std::path::PathBuf;

    #[test]
    fn parses_init_options_and_checks_defaults() {
        let default = parse_init_options(std::iter::empty()).expect("valid");
        assert_eq!(default.path, PathBuf::from("."));
        assert!(default.write_policy());
        assert!(!default.write_ci());

        let ci_only =
            parse_init_options(["--ci", "app"].into_iter().map(str::to_owned)).expect("ci");
        assert_eq!(ci_only.path, PathBuf::from("app"));
        assert!(ci_only.write_ci());
        assert!(!ci_only.write_policy());

        let both = parse_init_options(
            ["--ci", "--policy", "--dry-run", "--force"]
                .into_iter()
                .map(str::to_owned),
        )
        .expect("both");
        assert!(both.write_ci() && both.write_policy() && both.dry_run && both.force);
        assert!(parse_init_options(["--unknown"].into_iter().map(str::to_owned)).is_err());
        assert!(parse_init_options(["a", "b"].into_iter().map(str::to_owned)).is_err());
    }

    #[test]
    fn renders_valid_starter_and_translated_cargoscope_toml() {
        let dir = std::env::temp_dir().join(format!("cargoscope-init-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".cargo")).expect("mkdir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo.toml");

        let (starter, deny_path, _) = render_cargoscope_toml(&dir).expect("starter");
        assert!(deny_path.is_none());
        assert!(
            parse_policy(&starter)
                .expect("starter policy parses")
                .is_some()
        );

        std::fs::write(
            dir.join("deny.toml"),
            r#"[graph]
targets = ["x86_64-unknown-linux-gnu"]
exclude-dev = true

[licenses]
allow = ["MIT", "Apache-2.0"]
deny = ["GPL-3.0-only"]
unused-allowed-license = "warn"
exceptions = [{ crate = "ring", allow = ["ISC"], reason = "checked" }]
clarify = [{ crate = "webpki", expression = "ISC", reason = "checked", license-files = [{ path = "LICENSE", hash = 305419896 }] }]

[licenses.private]
ignore = true

[sources]
unknown-git = "deny"
allow-git = ["https://github.com/myorg/"]

[bans]
multiple-versions = "warn"
skip = ["windows-sys"]
deny = [{ crate = "openssl", reason = "use rustls" }]

[bans.build]
allow-build-scripts = ["cc"]
executables = "deny"

[advisories]
ignore = [{ id = "RUSTSEC-2020-0071", reason = "only time" }]
"#,
        )
        .expect("deny.toml");
        std::fs::write(
            dir.join(".cargo/audit.toml"),
            "[advisories]\nignore = [\"RUSTSEC-2024-0001\"]\n",
        )
        .expect("audit.toml");

        let (translated, deny_path, _) = render_cargoscope_toml(&dir).expect("translated");
        assert_eq!(deny_path.as_deref(), Some(dir.join("deny.toml").as_path()));
        let policy = parse_policy(&translated)
            .expect("translated policy parses")
            .expect("non-empty policy");
        assert_eq!(policy.targets, vec!["x86_64-unknown-linux-gnu"]);
        assert!(policy.exclude_dev);
        assert!(policy.private_ignore);
        assert_eq!(policy.bans.len(), 1);
        assert_eq!(policy.allow_build_scripts.as_ref().map(Vec::len), Some(1));
        let ignores = parse_advisory_ignores(&translated).expect("ignores parse");
        assert_eq!(ignores.len(), 2);

        let ci = render_ci_workflow();
        assert!(ci.contains("HarpeLm/CargoScope@v0.7.5"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
