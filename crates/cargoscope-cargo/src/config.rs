//! `cargoscope.toml`, the project configuration file (see docs/policy.md).

use std::path::Path;

use cargoscope_core::policy::{
    Ban, BuildBypass, BuildInspection, BuildScriptAllow, FeatureBan, LicenseFileHash, LintLevel,
    Policy, UnknownLicense,
};

/// File name, looked up in the scanned directory.
pub const FILE_NAME: &str = "cargoscope.toml";

fn strings(table: &toml::Table, key: &str, context: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("[{context}] {key} must contain strings"))
            })
            .collect(),
        Some(_) => Err(format!("[{context}] {key} must be an array of strings")),
    }
}

fn check_keys(table: &toml::Table, context: &str, known: &[&str]) -> Result<(), String> {
    match table.keys().find(|key| !known.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "unknown key `{key}` in [{context}]; expected one of: {}",
            known.join(", ")
        )),
        None => Ok(()),
    }
}

/// Reads `[graph] targets`: target triples the policy is limited to.
/// `[graph]`: targets, the feature keys (`features`, `all-features`,
/// `no-default-features`; `None` when no feature key is set) and
/// `exclude-dev`.
type Graph = (Vec<String>, Option<cargoscope_core::policy::Features>, bool);

fn parse_graph(value: &toml::Table) -> Result<Graph, String> {
    let Some(graph) = value.get("graph") else {
        return Ok((Vec::new(), None, false));
    };
    let graph = graph
        .as_table()
        .ok_or_else(|| "[graph] must be a table".to_owned())?;
    check_keys(
        graph,
        "graph",
        &[
            "targets",
            "features",
            "all-features",
            "no-default-features",
            "exclude-dev",
        ],
    )?;
    let flag = |key: &str| match graph.get(key) {
        None => Ok(false),
        Some(toml::Value::Boolean(value)) => Ok(*value),
        Some(_) => Err(format!("[graph] {key} must be true or false")),
    };
    let list = strings(graph, "features", "graph")?;
    for feature in &list {
        let valid = !feature.is_empty()
            && !feature.starts_with('-')
            && feature
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '+' | '.'));
        if !valid {
            return Err(format!(
                "[graph] features: `{feature}` is not a feature name (use `member/feature` in a workspace)"
            ));
        }
    }
    let features = ["features", "all-features", "no-default-features"]
        .iter()
        .any(|key| graph.contains_key(*key))
        .then(|| -> Result<_, String> {
            Ok(cargoscope_core::policy::Features {
                list,
                all: flag("all-features")?,
                no_default: flag("no-default-features")?,
            })
        })
        .transpose()?;
    let targets = strings(graph, "targets", "graph")?;
    for target in &targets {
        let valid = !target.is_empty()
            && !target.starts_with('-')
            && target
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if !valid {
            return Err(format!(
                "[graph] targets: `{target}` is not a target triple such as x86_64-unknown-linux-gnu"
            ));
        }
    }
    let exclude_dev = flag("exclude-dev")?;
    Ok((targets, features, exclude_dev))
}

/// Parses the text of a `cargoscope.toml`. Returns `None` when it defines
/// no policy section.
///
/// # Errors
///
/// Returns a message for invalid TOML, unknown keys or wrong value types,
/// so that a typo never silently disables a rule.
pub fn parse_policy(text: &str) -> Result<Option<Policy>, String> {
    let value: toml::Table = toml::from_str(text).map_err(|error| error.to_string())?;
    check_keys(
        &value,
        "top level",
        &[
            "licenses",
            "sources",
            "bans",
            "advisories",
            "graph",
            "updates",
        ],
    )?;
    if let Some(updates) = value.get("updates") {
        let table = updates.as_table().ok_or("[updates] must be a table")?;
        crate::updates::parse(table)?;
    }
    let (targets, features, exclude_dev) = parse_graph(&value)?;
    if !["licenses", "sources", "bans"]
        .iter()
        .any(|key| value.contains_key(*key))
    {
        return Ok(None);
    }
    let table = |key: &str| -> Result<Option<&toml::Table>, String> {
        match value.get(key) {
            None => Ok(None),
            Some(toml::Value::Table(table)) => Ok(Some(table)),
            Some(_) => Err(format!("[{key}] must be a table")),
        }
    };
    let mut policy = Policy {
        targets,
        features,
        exclude_dev,
        ..Policy::default()
    };

    if let Some(licenses) = table("licenses")? {
        check_keys(
            licenses,
            "licenses",
            &[
                "allow",
                "deny",
                "unknown",
                "exceptions",
                "clarify",
                "include-workspace",
                "private",
                "confidence-threshold",
                "unused-allowed-license",
            ],
        )?;
        policy.check_licenses = true;
        policy.licenses_include_workspace = match licenses.get("include-workspace") {
            None => false,
            Some(toml::Value::Boolean(value)) => *value,
            Some(_) => return Err("[licenses] include-workspace must be true or false".to_owned()),
        };
        if let Some(threshold) = licenses.get("confidence-threshold") {
            policy.confidence_threshold = confidence_threshold(threshold)
                .ok_or("[licenses] confidence-threshold must be a number from 0.0 to 1.0")?;
        }
        policy.unused_allowed_license = parse_lint_level(
            licenses,
            "unused-allowed-license",
            "licenses",
            LintLevel::Allow,
        )?;
        match licenses.get("private") {
            None => {}
            Some(toml::Value::Table(private)) => {
                check_keys(
                    private,
                    "licenses.private",
                    &["ignore", "registries", "ignore-sources"],
                )?;
                policy.private_ignore = match private.get("ignore") {
                    None => false,
                    Some(toml::Value::Boolean(value)) => *value,
                    Some(_) => {
                        return Err("[licenses.private] ignore must be true or false".to_owned());
                    }
                };
                policy.private_registries = strings(private, "registries", "licenses.private")?;
                policy.private_ignore_sources =
                    strings(private, "ignore-sources", "licenses.private")?;
            }
            Some(_) => return Err("[licenses] private must be a table".to_owned()),
        }
        policy.allow_licenses = strings(licenses, "allow", "licenses")?;
        policy.deny_licenses = strings(licenses, "deny", "licenses")?;
        policy.unknown_license = match licenses.get("unknown").map(|value| value.as_str()) {
            None | Some(Some("deny")) => UnknownLicense::Deny,
            Some(Some("allow")) => UnknownLicense::Allow,
            _ => return Err("[licenses] unknown must be \"deny\" or \"allow\"".to_owned()),
        };
        for license in policy.allow_licenses.iter().chain(&policy.deny_licenses) {
            cargoscope_core::license::parse(license)
                .map_err(|error| format!("[licenses] `{license}`: {error}"))?;
        }
        for entry in crate_entries(
            licenses,
            "exceptions",
            &["name", "version", "allow", "reason"],
        )? {
            let allow = strings(entry.table, "allow", "licenses.exceptions")?;
            if allow.is_empty() {
                return Err(format!(
                    "[licenses] exception for `{}` needs a non-empty `allow` list",
                    entry.name
                ));
            }
            for license in &allow {
                cargoscope_core::license::parse(license).map_err(|error| {
                    format!(
                        "[licenses] exception for `{}`: `{license}`: {error}",
                        entry.name
                    )
                })?;
            }
            policy
                .license_exceptions
                .push(cargoscope_core::policy::LicenseException {
                    name: entry.name,
                    version: entry.version,
                    allow,
                    reason: entry.reason,
                });
        }
        for entry in crate_entries(
            licenses,
            "clarify",
            &["name", "version", "expression", "reason", "license-files"],
        )? {
            let expression = entry
                .table
                .get("expression")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "[licenses] clarify for `{}` needs an `expression`",
                        entry.name
                    )
                })?
                .to_owned();
            cargoscope_core::license::parse(&expression).map_err(|error| {
                format!(
                    "[licenses] clarify for `{}`: `{expression}`: {error}",
                    entry.name
                )
            })?;
            let license_files = parse_license_files(entry.table, &entry.name)?;
            policy
                .license_clarifications
                .push(cargoscope_core::policy::LicenseClarification {
                    name: entry.name,
                    version: entry.version,
                    expression,
                    reason: entry.reason,
                    license_files,
                });
        }
    }

    if let Some(sources) = table("sources")? {
        check_keys(
            sources,
            "sources",
            &[
                "allow-registries",
                "allow-git",
                "unknown-registry",
                "unknown-git",
            ],
        )?;
        let registries = strings(sources, "allow-registries", "sources")?;
        policy.allow_registries = Some(if sources.contains_key("allow-registries") {
            registries
        } else {
            vec!["crates.io".to_owned()]
        });
        policy.allow_git = strings(sources, "allow-git", "sources")?;
        policy.registry_source_level =
            parse_lint_level(sources, "unknown-registry", "sources", LintLevel::Deny)?;
        policy.git_source_level =
            parse_lint_level(sources, "unknown-git", "sources", LintLevel::Deny)?;
    }

    if let Some(bans) = table("bans")? {
        check_keys(
            bans,
            "bans",
            &[
                "deny",
                "features",
                "build",
                "multiple-versions",
                "skip-multiple-versions",
            ],
        )?;
        policy.multiple_versions =
            parse_lint_level(bans, "multiple-versions", "bans", LintLevel::Allow)?;
        policy.skip_multiple_versions = strings(bans, "skip-multiple-versions", "bans")?;
        let entries = match bans.get("deny") {
            None => Vec::new(),
            Some(toml::Value::Array(entries)) => entries.clone(),
            Some(_) => return Err("[bans] deny must be an array of tables".to_owned()),
        };
        for entry in entries {
            let entry = entry.as_table().ok_or(
                "[bans] deny entries must be tables such as { name = \"...\", reason = \"...\" }",
            )?;
            check_keys(
                entry,
                "bans.deny",
                &["name", "version", "reason", "wrappers"],
            )?;
            let field = |key: &str| {
                entry
                    .get(key)
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
            };
            let name = field("name").ok_or("[bans] deny entries need a `name`")?;
            let reason = field("reason")
                .filter(|reason| !reason.trim().is_empty())
                .ok_or_else(|| format!("[bans] `{name}` needs a non-empty `reason`"))?;
            let version = field("version");
            if let Some(requirement) = &version {
                semver::VersionReq::parse(requirement)
                    .map_err(|error| format!("[bans] `{name}` version `{requirement}`: {error}"))?;
            }
            let wrappers = strings(entry, "wrappers", "bans.deny")?;
            policy.bans.push(Ban {
                name,
                version,
                reason,
                wrappers,
            });
        }
        policy.feature_bans = parse_feature_bans(bans)?;
        (policy.allow_build_scripts, policy.build_include_workspace) = parse_build_config(bans)?;
        if let Some(build) = bans.get("build").and_then(toml::Value::as_table) {
            policy.build_inspection = Some(build_inspection(build)?);
        }
    }

    Ok(Some(policy))
}

fn parse_lint_level(
    section: &toml::Table,
    key: &str,
    context: &str,
    default: LintLevel,
) -> Result<LintLevel, String> {
    match section.get(key) {
        None => Ok(default),
        Some(value) => match value.as_str() {
            Some("allow") => Ok(LintLevel::Allow),
            Some("warn") => Ok(LintLevel::Warn),
            Some("deny") => Ok(LintLevel::Deny),
            _ => Err(format!(
                "[{context}] {key} must be \"deny\", \"warn\" or \"allow\""
            )),
        },
    }
}

fn parse_license_files(
    table: &toml::Table,
    crate_name: &str,
) -> Result<Vec<LicenseFileHash>, String> {
    let Some(entries) = table.get("license-files") else {
        return Ok(Vec::new());
    };
    let entries = entries.as_array().ok_or_else(|| {
        format!("[licenses] clarify for `{crate_name}`: license-files must be an array of tables")
    })?;
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry.as_table().ok_or_else(|| {
            format!(
                "[licenses] clarify for `{crate_name}`: license-files entries must be tables such as {{ path = \"LICENSE\", hash = 0x12345678 }}"
            )
        })?;
        check_keys(entry, "licenses.clarify.license-files", &["path", "hash"])?;
        let path = entry
            .get("path")
            .and_then(toml::Value::as_str)
            .filter(|path| !path.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "[licenses] clarify for `{crate_name}`: license-files entries need a `path`"
                )
            })?
            .to_owned();
        let hash = match entry.get("hash") {
            None => None,
            Some(toml::Value::Integer(value)) => {
                let value = u32::try_from(*value).map_err(|_| {
                    format!(
                        "[licenses] clarify for `{crate_name}`: hash for `{path}` must fit in a 32-bit unsigned integer"
                    )
                })?;
                Some(value)
            }
            Some(_) => {
                return Err(format!(
                    "[licenses] clarify for `{crate_name}`: hash for `{path}` must be a 32-bit integer"
                ));
            }
        };
        parsed.push(LicenseFileHash { path, hash });
    }
    Ok(parsed)
}

fn parse_build_config(bans: &toml::Table) -> Result<(Option<Vec<BuildScriptAllow>>, bool), String> {
    let Some(build) = bans.get("build") else {
        return Ok((None, false));
    };
    let build = build
        .as_table()
        .ok_or("[bans] build must be a table".to_owned())?;
    check_keys(
        build,
        "bans.build",
        &[
            "allow-build-scripts",
            "include-workspace",
            "executables",
            "interpreted",
            "script-extensions",
            "enable-builtin-globs",
            "include-dependencies",
            "include-archives",
            "bypass",
        ],
    )?;
    let include_workspace = match build.get("include-workspace") {
        None => false,
        Some(toml::Value::Boolean(value)) => *value,
        Some(_) => return Err("[bans.build] include-workspace must be true or false".to_owned()),
    };
    let Some(allow) = build.get("allow-build-scripts") else {
        return Ok((None, include_workspace));
    };
    let entries = allow
        .as_array()
        .ok_or("[bans.build] allow-build-scripts must be an array".to_owned())?;
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in entries {
        let (name, version) = if let Some(spec) = entry.as_str() {
            crate::deny::crate_spec(&toml::Value::String(spec.to_owned()))
                .ok_or_else(|| format!("[bans.build] invalid crate spec `{spec}`"))?
        } else if let Some(table) = entry.as_table() {
            check_keys(
                table,
                "bans.build.allow-build-scripts",
                &["name", "version"],
            )?;
            let name = table
                .get("name")
                .and_then(toml::Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .ok_or("[bans.build] allow-build-scripts table entries need a `name`")?
                .to_owned();
            let version = table
                .get("version")
                .and_then(toml::Value::as_str)
                .map(str::to_owned);
            (name, version)
        } else {
            return Err(
                "[bans.build] allow-build-scripts entries must be strings or `{ name, version }` tables"
                    .to_owned(),
            );
        };
        if let Some(req) = &version {
            semver::VersionReq::parse(req).map_err(|error| {
                format!("[bans.build] allow-build-scripts `{name}` version `{req}`: {error}")
            })?;
        }
        parsed.push(BuildScriptAllow { name, version });
    }
    Ok((Some(parsed), include_workspace))
}

/// Reads the inspection settings of a `[bans.build]` table (shared by
/// `cargoscope.toml` and `deny.toml`).
///
/// # Errors
///
/// Returns a message for a wrong type, an invalid level, extension, version
/// requirement or SHA-256 checksum.
pub fn build_inspection(build: &toml::Table) -> Result<BuildInspection, String> {
    let level = |key: &str, default: LintLevel| -> Result<LintLevel, String> {
        match build.get(key).map(toml::Value::as_str) {
            None => Ok(default),
            Some(Some("allow")) => Ok(LintLevel::Allow),
            Some(Some("warn")) => Ok(LintLevel::Warn),
            Some(Some("deny")) => Ok(LintLevel::Deny),
            _ => Err(format!(
                "[bans.build] {key} must be \"allow\", \"warn\" or \"deny\""
            )),
        }
    };
    let flag = |key: &str| -> Result<bool, String> {
        match build.get(key) {
            None => Ok(false),
            Some(toml::Value::Boolean(value)) => Ok(*value),
            Some(_) => Err(format!("[bans.build] {key} must be true or false")),
        }
    };
    let list = |table: &toml::Table, key: &str, context: &str| -> Result<Vec<String>, String> {
        match table.get(key) {
            None => Ok(Vec::new()),
            Some(toml::Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("[{context}] {key} must be a list of strings"))
                })
                .collect(),
            Some(_) => Err(format!("[{context}] {key} must be a list of strings")),
        }
    };
    let checksum = |value: &toml::Value, what: &str| -> Result<String, String> {
        value
            .as_str()
            .filter(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| {
                format!("[bans.build] {what} must be a SHA-256 checksum (64 hexadecimal digits)")
            })
    };
    let script_extensions = list(build, "script-extensions", "bans.build")?;
    if let Some(bad) = script_extensions.iter().find(|extension| {
        extension.is_empty() || !extension.chars().all(|c| c.is_ascii_alphanumeric())
    }) {
        return Err(format!(
            "[bans.build] script-extensions: `{bad}` is not a file extension (letters and digits, no dot)"
        ));
    }
    let mut bypass = Vec::new();
    match build.get("bypass") {
        None => {}
        Some(toml::Value::Array(entries)) => {
            for entry in entries {
                let table = entry
                    .as_table()
                    .ok_or("[bans.build] bypass entries must be tables")?;
                let (name, version) = crate::deny::crate_spec(entry)
                    .ok_or("[bans.build] bypass entries need a crate (`crate = \"name@version\"` or `name`)")?;
                if let Some(req) = &version {
                    semver::VersionReq::parse(req).map_err(|error| {
                        format!("[bans.build] bypass `{name}` version `{req}`: {error}")
                    })?;
                }
                let build_script = table
                    .get("build-script")
                    .map(|value| checksum(value, &format!("bypass `{name}` build-script")))
                    .transpose()?;
                let mut allow = Vec::new();
                for file in table
                    .get("allow")
                    .and_then(toml::Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let path = file
                        .get("path")
                        .and_then(toml::Value::as_str)
                        .ok_or_else(|| {
                            format!("[bans.build] bypass `{name}` allow entries need a `path`")
                        })?
                        .to_owned();
                    let sum = file
                        .get("checksum")
                        .map(|value| {
                            checksum(value, &format!("bypass `{name}` checksum of `{path}`"))
                        })
                        .transpose()?;
                    allow.push((path, sum));
                }
                allow.sort();
                bypass.push(BuildBypass {
                    name,
                    version,
                    build_script,
                    required_features: list(table, "required-features", "bans.build.bypass")?,
                    allow_globs: list(table, "allow-globs", "bans.build.bypass")?,
                    allow,
                });
            }
        }
        Some(_) => return Err("[bans.build] bypass must be an array of tables".to_owned()),
    }
    Ok(BuildInspection {
        executables: level("executables", LintLevel::Deny)?,
        interpreted: level("interpreted", LintLevel::Allow)?,
        script_extensions,
        enable_builtin_globs: flag("enable-builtin-globs")?,
        include_dependencies: flag("include-dependencies")?,
        include_archives: flag("include-archives")?,
        bypass,
    })
}

fn parse_feature_bans(bans: &toml::Table) -> Result<Vec<FeatureBan>, String> {
    let entries = match bans.get("features") {
        None => return Ok(Vec::new()),
        Some(toml::Value::Array(entries)) => entries,
        Some(_) => return Err("[bans] features must be an array of tables".to_owned()),
    };
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry.as_table().ok_or(
            "[bans] features entries must be tables such as { name = \"...\", deny = [\"...\"], reason = \"...\" }",
        )?;
        check_keys(
            entry,
            "bans.features",
            &["name", "version", "allow", "deny", "exact", "reason"],
        )?;
        let field = |key: &str| {
            entry
                .get(key)
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };
        let name = field("name").ok_or("[bans] features entries need a `name`")?;
        let reason = field("reason")
            .filter(|reason| !reason.trim().is_empty())
            .ok_or_else(|| format!("[bans] features for `{name}` needs a non-empty `reason`"))?;
        let version = field("version");
        if let Some(requirement) = &version {
            semver::VersionReq::parse(requirement).map_err(|error| {
                format!("[bans] features for `{name}` version `{requirement}`: {error}")
            })?;
        }
        let allow = strings(entry, "allow", "bans.features")?;
        let deny = strings(entry, "deny", "bans.features")?;
        let exact = match entry.get("exact") {
            None => false,
            Some(toml::Value::Boolean(value)) => *value,
            Some(_) => {
                return Err(format!(
                    "[bans] features for `{name}`: `exact` must be true or false"
                ));
            }
        };
        if allow.is_empty() && deny.is_empty() && !exact {
            return Err(format!(
                "[bans] features for `{name}` must set `deny`, `allow`, or `exact = true`"
            ));
        }
        parsed.push(FeatureBan {
            name,
            version,
            allow,
            deny,
            exact,
            reason,
        });
    }
    Ok(parsed)
}

/// One `{ name, version, reason, ... }` table of a crate list.
struct CrateEntry<'a> {
    name: String,
    version: Option<String>,
    reason: String,
    table: &'a toml::Table,
}

/// A `confidence-threshold` value (0.0 to 1.0), in thousandths.
#[must_use]
pub fn confidence_threshold(value: &toml::Value) -> Option<u16> {
    let number = value
        .as_float()
        .or_else(|| value.as_integer().map(|integer| integer as f64))?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (0.0..=1.0)
        .contains(&number)
        .then(|| (number * 1000.0).round() as u16)
}

/// Reads `[licenses] KEY = [{ name = "...", reason = "...", ... }]`: every
/// entry needs a `name` and a non-empty `reason`; `version`, when given, must
/// be a valid requirement.
fn crate_entries<'a>(
    section: &'a toml::Table,
    key: &str,
    known: &[&str],
) -> Result<Vec<CrateEntry<'a>>, String> {
    let entries = match section.get(key) {
        None => return Ok(Vec::new()),
        Some(toml::Value::Array(entries)) => entries,
        Some(_) => return Err(format!("[licenses] {key} must be an array of tables")),
    };
    entries
        .iter()
        .map(|entry| {
            let table = entry.as_table().ok_or_else(|| {
                format!("[licenses] {key} entries must be tables such as {{ name = \"...\", reason = \"...\" }}")
            })?;
            check_keys(table, &format!("licenses.{key}"), known)?;
            let field = |name: &str| table.get(name).and_then(toml::Value::as_str).map(str::to_owned);
            let name = field("name").ok_or_else(|| format!("[licenses] {key} entries need a `name`"))?;
            let reason = field("reason")
                .filter(|reason| !reason.trim().is_empty())
                .ok_or_else(|| format!("[licenses] {key} for `{name}` needs a non-empty `reason`"))?;
            let version = field("version");
            if let Some(requirement) = &version {
                semver::VersionReq::parse(requirement).map_err(|error| {
                    format!("[licenses] {key} for `{name}` version `{requirement}`: {error}")
                })?;
            }
            Ok(CrateEntry { name, version, reason, table })
        })
        .collect()
}

/// An advisory to ignore, from `[advisories] ignore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryIgnore {
    /// Advisory ID or alias (`RUSTSEC-...`, `CVE-...`, `GHSA-...`).
    pub id: String,
    /// Why it is ignored; required.
    pub reason: String,
    /// Last day (`YYYY-MM-DD`) the ignore applies, if limited.
    pub until: Option<String>,
    /// File the ignore comes from (`cargoscope.toml`, `deny.toml`,
    /// `.cargo/audit.toml`), for messages.
    pub source: &'static str,
}

fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
}

/// Parses `[advisories] ignore = [{ id, reason, until }]`.
///
/// # Errors
///
/// Returns a message for unknown keys, a missing `id` or `reason`, or an
/// `until` that is not a `YYYY-MM-DD` date.
pub fn parse_advisory_ignores(text: &str) -> Result<Vec<AdvisoryIgnore>, String> {
    let value: toml::Table = toml::from_str(text).map_err(|error| error.to_string())?;
    let Some(advisories) = value.get("advisories") else {
        return Ok(Vec::new());
    };
    let advisories = advisories
        .as_table()
        .ok_or("[advisories] must be a table")?;
    check_keys(advisories, "advisories", &["ignore"])?;
    let entries = match advisories.get("ignore") {
        None => return Ok(Vec::new()),
        Some(toml::Value::Array(entries)) => entries,
        Some(_) => return Err("[advisories] ignore must be an array of tables".to_owned()),
    };
    let mut ignores = Vec::new();
    for entry in entries {
        let entry = entry.as_table().ok_or(
            "[advisories] ignore entries must be tables such as { id = \"RUSTSEC-...\", reason = \"...\" }",
        )?;
        check_keys(entry, "advisories.ignore", &["id", "reason", "until"])?;
        let field = |key: &str| {
            entry
                .get(key)
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };
        let id = field("id").ok_or("[advisories] ignore entries need an `id`")?;
        let reason = field("reason")
            .filter(|reason| !reason.trim().is_empty())
            .ok_or_else(|| format!("[advisories] `{id}` needs a non-empty `reason`"))?;
        let until = field("until");
        if let Some(date) = &until
            && !is_date(date)
        {
            return Err(format!(
                "[advisories] `{id}` until must be a YYYY-MM-DD date, not `{date}`"
            ));
        }
        ignores.push(AdvisoryIgnore {
            id,
            reason,
            until,
            source: FILE_NAME,
        });
    }
    Ok(ignores)
}

fn read_config(project_root: &Path) -> Result<Option<String>, String> {
    let path = project_root.join(FILE_NAME);
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return Ok(None);
    };
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(format!(
            "{} must be a regular file under 1 MiB",
            path.display()
        ));
    }
    std::fs::read_to_string(&path)
        .map(Some)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Reads advisory ignores from cargo-deny's `deny.toml` and cargo-audit's
/// `.cargo/audit.toml` in `project_root`.
///
/// # Errors
///
/// Returns a message when `deny.toml` cannot be read or is invalid TOML.
pub fn external_advisory_ignores(project_root: &Path) -> Result<Vec<AdvisoryIgnore>, String> {
    let mut ignores = crate::deny::load(project_root)?
        .map(|translation| translation.ignores)
        .unwrap_or_default();
    for ignore in audit_toml_ignores(project_root) {
        if !ignores.iter().any(|known| known.id == ignore.id) {
            ignores.push(ignore);
        }
    }
    Ok(ignores)
}

/// Reads `[advisories] ignore` from `project_root/cargoscope.toml`, or,
/// without one, from cargo-deny's `deny.toml` and cargo-audit's
/// `.cargo/audit.toml`.
///
/// # Errors
///
/// Returns a message naming the file for unreadable or invalid content.
pub fn load_advisory_ignores(project_root: &Path) -> Result<Vec<AdvisoryIgnore>, String> {
    match read_config(project_root)? {
        None => external_advisory_ignores(project_root),
        Some(text) => parse_advisory_ignores(&text)
            .map_err(|error| format!("{}: {error}", project_root.join(FILE_NAME).display())),
    }
}

/// `[advisories] ignore = ["RUSTSEC-..."]` of cargo-audit's
/// `.cargo/audit.toml`, so that a project moving from cargo-audit keeps its
/// decisions. An unreadable file is skipped: cargo-audit is not required.
fn audit_toml_ignores(project_root: &Path) -> Vec<AdvisoryIgnore> {
    let path = project_root.join(".cargo").join("audit.toml");
    let readable = std::fs::symlink_metadata(&path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 1024 * 1024);
    if !readable {
        return Vec::new();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
        .and_then(|value| value.get("advisories")?.get("ignore")?.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(toml::Value::as_str)
        .map(|id| AdvisoryIgnore {
            id: id.to_owned(),
            reason: "from .cargo/audit.toml".to_owned(),
            until: None,
            source: ".cargo/audit.toml",
        })
        .collect()
}

/// Reads `cargoscope.toml` from `project_root`, or, without one, the rules
/// of cargo-deny's `deny.toml` (see [`crate::deny`]).
///
/// # Errors
///
/// Returns a message naming the file for unreadable or invalid content.
pub fn load_policy(project_root: &Path) -> Result<Option<Policy>, String> {
    let path = project_root.join(FILE_NAME);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Ok(crate::deny::load(project_root)?.and_then(|translation| translation.policy));
        }
    };
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(format!(
            "{} must be a regular file under 1 MiB",
            path.display()
        ));
    }
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    parse_policy(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Notes for the report when `deny.toml` stands in for a missing
/// `cargoscope.toml`: which file is used and what it could not translate.
#[must_use]
pub fn deny_notes(project_root: &Path) -> Vec<String> {
    if std::fs::symlink_metadata(project_root.join(FILE_NAME)).is_ok() {
        return Vec::new();
    }
    match crate::deny::load(project_root) {
        Ok(Some(translation)) => {
            let name = translation
                .path
                .strip_prefix(project_root)
                .unwrap_or(&translation.path)
                .display()
                .to_string();
            std::iter::once(format!(
                "no cargoscope.toml: the rules of {name} (cargo-deny) are used; write a cargoscope.toml to replace them"
            ))
            .chain(translation.notes)
            .collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_policy;
    use cargoscope_core::policy::{LintLevel, UnknownLicense};

    #[test]
    fn parses_every_section() {
        let policy = parse_policy(
            r#"
            [licenses]
            allow = ["MIT", "Apache-2.0"]
            unknown = "allow"
            [sources]
            allow-git = ["https://github.com/myorg/"]
            unknown-registry = "warn"
            [bans]
            deny = [{ name = "openssl", version = "<0.10", reason = "use rustls" }]
            multiple-versions = "deny"
            skip-multiple-versions = ["windows-sys"]
            [bans.build]
            allow-build-scripts = ["cc", "ring@^0.17"]
            include-workspace = true
            "#,
        )
        .expect("valid")
        .expect("has a policy");
        assert_eq!(policy.allow_licenses, vec!["MIT", "Apache-2.0"]);
        assert_eq!(policy.unknown_license, UnknownLicense::Allow);
        assert_eq!(policy.allow_registries, Some(vec!["crates.io".to_owned()]));
        assert_eq!(policy.registry_source_level, LintLevel::Warn);
        assert_eq!(policy.git_source_level, LintLevel::Deny);
        assert_eq!(policy.bans[0].version.as_deref(), Some("<0.10"));
        assert_eq!(policy.multiple_versions, LintLevel::Deny);
        assert_eq!(policy.skip_multiple_versions, vec!["windows-sys"]);
        assert!(policy.build_include_workspace);
        assert_eq!(policy.allow_build_scripts.as_ref().map(Vec::len), Some(2));
        let warn_mv = parse_policy("[bans]\nmultiple-versions = \"warn\"\n")
            .expect("valid")
            .expect("policy");
        assert_eq!(warn_mv.multiple_versions, LintLevel::Warn);
        assert!(
            parse_policy("[bans]\nmultiple-versions = \"other\"\n")
                .unwrap_err()
                .contains("must be \"deny\", \"warn\" or \"allow\"")
        );
    }

    #[test]
    fn parses_graph_targets_and_rejects_anything_else() {
        let policy = parse_policy(
            "[graph]\ntargets = [\"x86_64-unknown-linux-gnu\", \"aarch64-apple-darwin\"]\n[licenses]\nallow = [\"MIT\"]\n",
        )
        .expect("valid")
        .expect("has a policy");
        assert_eq!(
            policy.targets,
            vec!["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]
        );
        // [graph] alone sets no rule, hence no policy.
        assert!(
            parse_policy("[graph]\ntargets = [\"x86_64-unknown-linux-gnu\"]\n")
                .expect("valid")
                .is_none()
        );
        for bad in [
            "[graph]\ntargets = [\"--manifest-path\"]\n",
            "[graph]\ntargets = [\"\"]\n",
            "[graph]\ntargets = [\"linux gnu\"]\n",
        ] {
            let text = format!("{bad}[bans]\nmultiple-versions = \"deny\"\n");
            assert!(
                parse_policy(&text)
                    .unwrap_err()
                    .contains("not a target triple"),
                "{bad}"
            );
        }
        assert!(
            parse_policy("[graph]\ntarget = []\n[bans]\n")
                .unwrap_err()
                .contains("unknown key")
        );
    }

    #[test]
    fn parses_graph_features() {
        let policy = |text: &str| parse_policy(text).expect("valid").expect("policy");
        assert!(policy("[graph]\nexclude-dev = true\n[bans]\n").exclude_dev);
        let none = policy("[graph]\ntargets = [\"x86_64-unknown-linux-gnu\"]\n[bans]\n");
        assert_eq!(none.features, None);
        let some = policy(
            "[graph]\nfeatures = [\"app/extra\", \"tls\"]\nno-default-features = true\n[bans]\n",
        );
        let features = some.features.expect("features");
        assert_eq!(features.list, vec!["app/extra", "tls"]);
        assert!(features.no_default && !features.all);
        assert_eq!(
            features.cargo_args(),
            vec!["--no-default-features", "--features", "app/extra,tls"]
        );
        let all = policy("[graph]\nall-features = true\n[licenses]\n")
            .features
            .expect("features");
        assert_eq!(all.cargo_args(), vec!["--all-features"]);

        let error = |text: &str| parse_policy(text).expect_err("invalid");
        assert!(
            error("[graph]\nall-features = \"yes\"\n[bans]\n").contains("must be true or false")
        );
        assert!(error("[graph]\nfeatures = [\"a b\"]\n[bans]\n").contains("is not a feature name"));
    }

    #[test]
    fn parses_license_exceptions_and_clarifications() {
        let policy = parse_policy(
            r#"
            [licenses]
            allow = ["MIT"]
            exceptions = [{ name = "ring", version = "^0.17", allow = ["ISC", "OpenSSL"], reason = "reviewed" }]
            clarify = [{ name = "webpki", expression = "ISC", reason = "LICENSE file checked" }]
            "#,
        )
        .expect("valid")
        .expect("policy");
        assert_eq!(policy.license_exceptions[0].name, "ring");
        assert_eq!(
            policy.license_exceptions[0].version.as_deref(),
            Some("^0.17")
        );
        assert_eq!(policy.license_exceptions[0].allow, vec!["ISC", "OpenSSL"]);
        assert_eq!(policy.license_clarifications[0].expression, "ISC");

        let error = |text: &str| parse_policy(text).expect_err("invalid");
        assert!(
            error("[licenses]\nexceptions = [{ name = \"a\", allow = [\"MIT\"] }]\n")
                .contains("needs a non-empty `reason`")
        );
        assert!(
            error("[licenses]\nexceptions = [{ name = \"a\", allow = [], reason = \"r\" }]\n")
                .contains("non-empty `allow`")
        );
        assert!(
            error("[licenses]\nclarify = [{ name = \"a\", reason = \"r\" }]\n")
                .contains("needs an `expression`")
        );
        assert!(error("[licenses]\nclarify = [{ name = \"a\", expression = \"MIT AND\", reason = \"r\" }]\n").contains("clarify for `a`"));
        assert!(error("[licenses]\nclarify = [{ name = \"a\", expression = \"MIT\", reason = \"r\", hash = 1 }]\n").contains("unknown key `hash`"));
        assert!(error("[licenses]\nexceptions = [{ name = \"a\", version = \"one\", allow = [\"MIT\"], reason = \"r\" }]\n").contains("version `one`"));
    }

    #[test]
    fn parses_advisory_ignores_and_rejects_bad_entries() {
        let ignores = super::parse_advisory_ignores(
            r#"
            [advisories]
            ignore = [
              { id = "RUSTSEC-2020-0071", reason = "time is only used in a build tool" },
              { id = "CVE-2024-1234", reason = "not reachable", until = "2027-01-31" },
            ]
            "#,
        )
        .expect("valid");
        assert_eq!(ignores.len(), 2);
        assert_eq!(ignores[1].until.as_deref(), Some("2027-01-31"));
        assert!(
            super::parse_advisory_ignores("[advisories]\nignore = [{ id = \"X\" }]\n")
                .unwrap_err()
                .contains("non-empty `reason`")
        );
        assert!(
            super::parse_advisory_ignores(
                "[advisories]\nignore = [{ id = \"X\", reason = \"r\", until = \"soon\" }]\n"
            )
            .unwrap_err()
            .contains("YYYY-MM-DD")
        );
        assert!(
            super::parse_advisory_ignores("[advisories]\nignores = []\n")
                .unwrap_err()
                .contains("unknown key")
        );
        // A file with only [advisories] defines no policy.
        assert_eq!(parse_policy("[advisories]\nignore = []\n"), Ok(None));
    }

    #[test]
    fn rejects_typos_and_missing_reasons() {
        assert!(
            parse_policy("[licenses]\nalow = [\"MIT\"]\n")
                .unwrap_err()
                .contains("unknown key `alow`")
        );
        assert!(
            parse_policy("[lisences]\n")
                .unwrap_err()
                .contains("unknown key `lisences`")
        );
        assert!(
            parse_policy("[bans]\ndeny = [{ name = \"x\" }]\n")
                .unwrap_err()
                .contains("non-empty `reason`")
        );
        assert!(
            parse_policy(
                "[bans]\ndeny = [{ name = \"x\", reason = \"r\", version = \"not a req\" }]\n"
            )
            .is_err()
        );
        assert!(parse_policy("[licenses]\nallow = [\"MIT OR\"]\n").is_err());
        assert_eq!(parse_policy(""), Ok(None));
    }

    #[test]
    fn reads_the_ignores_of_cargo_audit_without_a_cargoscope_toml() {
        let dir =
            std::env::temp_dir().join(format!("cargoscope-audit-toml-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".cargo")).expect("dir");
        std::fs::write(
            dir.join(".cargo/audit.toml"),
            "[advisories]\nignore = [\"RUSTSEC-2024-0436\", \"RUSTSEC-2025-0141\"]\n",
        )
        .expect("audit.toml");
        std::fs::write(
            dir.join("deny.toml"),
            "[advisories]\nignore = [{ id = \"RUSTSEC-2025-0141\", reason = \"bincode is fine here\" }]\n",
        )
        .expect("deny.toml");
        let ignores = super::load_advisory_ignores(&dir).expect("valid");
        let found: Vec<(&str, &str)> = ignores
            .iter()
            .map(|ignore| (ignore.id.as_str(), ignore.reason.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("RUSTSEC-2025-0141", "bincode is fine here"),
                ("RUSTSEC-2024-0436", "from .cargo/audit.toml"),
            ]
        );
        // A cargoscope.toml is the only file read.
        std::fs::write(dir.join("cargoscope.toml"), "[advisories]\nignore = []\n").expect("write");
        assert!(
            super::load_advisory_ignores(&dir)
                .expect("valid")
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_feature_bans_and_rejects_invalid_entries() {
        let policy = parse_policy(
            r#"
            [bans]
            features = [
              { name = "derive_more", deny = ["error"], reason = "small errors" },
              { name = "getrandom", version = "^0.2", allow = ["std"], exact = true, reason = "exact std" },
            ]
            "#,
        )
        .expect("valid")
        .expect("policy");
        assert_eq!(policy.feature_bans.len(), 2);
        assert_eq!(policy.feature_bans[0].name, "derive_more");
        assert_eq!(policy.feature_bans[0].deny, vec!["error"]);
        assert!(!policy.feature_bans[0].exact);
        assert_eq!(policy.feature_bans[1].version.as_deref(), Some("^0.2"));
        assert_eq!(policy.feature_bans[1].allow, vec!["std"]);
        assert!(policy.feature_bans[1].exact);

        let error = |text: &str| parse_policy(text).expect_err("invalid");
        assert!(
            error("[bans]\nfeatures = [{ name = \"a\", deny = [\"x\"] }]\n")
                .contains("needs a non-empty `reason`")
        );
        assert!(
            error("[bans]\nfeatures = [{ name = \"a\", reason = \"r\" }]\n")
                .contains("must set `deny`, `allow`, or `exact = true`")
        );
        assert!(
            error("[bans]\nfeatures = [{ name = \"a\", exact = \"yes\", reason = \"r\" }]\n")
                .contains("must be true or false")
        );
        assert!(
            error(
                "[bans]\nfeatures = [{ name = \"a\", deny = [\"x\"], extra = 1, reason = \"r\" }]\n"
            )
            .contains("unknown key `extra`")
        );
    }
}
