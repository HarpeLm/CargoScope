//! Conservative static hints for unused or overly broad dependency features
//! (e.g. `tokio = { features = ["full"] }` or `serde = { features = ["derive"] }`).
//!
//! Hints are informational only and never fail CI or edit manifests automatically.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;

use cargoscope_core::{DependencyKind, FeatureHint, UnusedFinding};
use proc_macro2::{Delimiter, TokenStream, TokenTree};

use super::references::{collect_references, includes_generated_code};
use super::sources::collect_sources;
use super::{IgnoreList, ignore_list, ignore_list_at, visit_dependency_tables};

/// Usage signals extracted from a package's Rust sources for feature checking.
#[derive(Debug, Default, Clone)]
pub(crate) struct FeatureSignals {
    derive_traits: BTreeSet<String>,
    idents: BTreeSet<String>,
    lower_idents: BTreeSet<String>,
    scoped_paths: BTreeSet<(String, String)>,
    glob_uses: BTreeSet<String>,
    reexported_roots: BTreeSet<String>,
    pub(crate) incomplete: bool,
}

impl FeatureSignals {
    fn merge(&mut self, other: &Self) {
        self.incomplete |= other.incomplete;
        self.derive_traits
            .extend(other.derive_traits.iter().cloned());
        self.idents.extend(other.idents.iter().cloned());
        self.lower_idents.extend(other.lower_idents.iter().cloned());
        self.scoped_paths.extend(other.scoped_paths.iter().cloned());
        self.glob_uses.extend(other.glob_uses.iter().cloned());
        self.reexported_roots
            .extend(other.reexported_roots.iter().cloned());
    }

    fn has_scoped(&self, crate_ident: &str, segment: &str) -> bool {
        self.scoped_paths
            .contains(&(crate_ident.to_owned(), segment.to_owned()))
    }
}

#[derive(Debug, Default)]
pub(crate) struct PrecomputedSignals {
    pub(crate) code: FeatureSignals,
    pub(crate) build: FeatureSignals,
}

pub(crate) fn consume_feature_stream(
    tokens: Option<TokenStream>,
    generated_code: bool,
    signals: &mut FeatureSignals,
) {
    let Some(tokens) = tokens else {
        signals.incomplete = true;
        return;
    };
    if generated_code {
        signals.incomplete = true;
    }
    walk_stream(tokens, signals);
}

fn collect_signals_from_files(files: &[std::path::PathBuf], skipped: usize) -> FeatureSignals {
    let mut signals = FeatureSignals {
        incomplete: skipped > 0,
        ..FeatureSignals::default()
    };
    for file in files {
        let Ok(text) = fs::read_to_string(file) else {
            signals.incomplete = true;
            continue;
        };
        let Ok(tokens) = TokenStream::from_str(&text) else {
            signals.incomplete = true;
            continue;
        };
        let generated = includes_generated_code(tokens.clone());
        consume_feature_stream(Some(tokens), generated, &mut signals);
    }
    signals
}

fn walk_stream(stream: TokenStream, signals: &mut FeatureSignals) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Ident(ident) => {
                let raw = ident.to_string();
                let name = raw.strip_prefix("r#").unwrap_or(&raw).to_owned();
                signals.lower_idents.insert(name.to_ascii_lowercase());
                signals.idents.insert(name.clone());

                // Detect `crate::sub` and `use crate::{a, b::c}` / `use crate::*`.
                if let (Some(TokenTree::Punct(p1)), Some(TokenTree::Punct(p2))) =
                    (tokens.get(index + 1), tokens.get(index + 2))
                    && p1.as_char() == ':'
                    && p2.as_char() == ':'
                {
                    match tokens.get(index + 3) {
                        Some(TokenTree::Ident(sub)) => {
                            let sub_raw = sub.to_string();
                            let sub_name = sub_raw.strip_prefix("r#").unwrap_or(&sub_raw);
                            signals
                                .scoped_paths
                                .insert((name.clone(), sub_name.to_owned()));
                        }
                        Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => {
                            collect_use_group_segments(&name, group.stream(), signals);
                        }
                        Some(TokenTree::Punct(star)) if star.as_char() == '*' => {
                            signals.glob_uses.insert(name.clone());
                        }
                        _ => {}
                    }
                }

                // Detect `pub use <crate>` up to `;` (excluding `pub(crate) use` / `pub(super) use`).
                if name == "use"
                    && index >= 1
                    && matches!(&tokens[index - 1], TokenTree::Ident(prev) if prev == "pub")
                {
                    let mut roots = BTreeSet::new();
                    let tail: TokenStream = tokens[index..]
                        .iter()
                        .take_while(|t| !matches!(t, TokenTree::Punct(p) if p.as_char() == ';'))
                        .cloned()
                        .collect();
                    collect_references(tail, &mut roots);
                    signals.reexported_roots.extend(roots);
                }
            }
            TokenTree::Group(group) => {
                if group.delimiter() == Delimiter::Bracket
                    && index.checked_sub(1).is_some_and(|prev| {
                        matches!(&tokens[prev], TokenTree::Punct(p) if p.as_char() == '#' || p.as_char() == '!')
                    })
                {
                    collect_attribute_derives(group.stream(), signals);
                }
                walk_stream(group.stream(), signals);
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

fn collect_use_group_segments(root: &str, group: TokenStream, signals: &mut FeatureSignals) {
    let tokens: Vec<TokenTree> = group.into_iter().collect();
    let mut at_item_start = true;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Ident(ident) if at_item_start => {
                let raw = ident.to_string();
                let seg = raw.strip_prefix("r#").unwrap_or(&raw);
                if !matches!(seg, "self" | "super" | "crate") {
                    signals
                        .scoped_paths
                        .insert((root.to_owned(), seg.to_owned()));
                }
                at_item_start = false;
            }
            TokenTree::Punct(p) if p.as_char() == '*' && at_item_start => {
                signals.glob_uses.insert(root.to_owned());
                at_item_start = false;
            }
            TokenTree::Punct(p) if p.as_char() == ',' => {
                at_item_start = true;
            }
            TokenTree::Group(nested) if nested.delimiter() == Delimiter::Brace && index > 0 => {
                // Nested group already handled for sub-items; top-level `seg` captured above.
                at_item_start = false;
            }
            _ => {}
        }
    }
}

fn collect_attribute_derives(stream: TokenStream, signals: &mut FeatureSignals) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Ident(ident) if ident == "derive" => {
                if let Some(TokenTree::Group(args)) = tokens.get(index + 1)
                    && args.delimiter() == Delimiter::Parenthesis
                {
                    let inner: Vec<TokenTree> = args.stream().into_iter().collect();
                    for (pos, item) in inner.iter().enumerate() {
                        if let TokenTree::Ident(trait_ident) = item {
                            // Capture final segment of each derive path (`serde::Serialize` -> `Serialize`).
                            let followed_by_path = matches!(
                                (inner.get(pos + 1), inner.get(pos + 2)),
                                (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
                                    if a.as_char() == ':' && b.as_char() == ':'
                            );
                            if !followed_by_path {
                                let name = trait_ident.to_string();
                                signals
                                    .derive_traits
                                    .insert(name.strip_prefix("r#").unwrap_or(&name).to_owned());
                            }
                        }
                    }
                }
            }
            TokenTree::Group(group) => collect_attribute_derives(group.stream(), signals),
            _ => {}
        }
    }
}

struct AnalyzedPackage<'a> {
    name: &'a str,
    manifest_label: &'a str,
    manifest: &'a toml::Value,
    code: FeatureSignals,
    build: FeatureSignals,
    ignored: IgnoreList,
    forwarded: BTreeSet<String>,
    inherited_keys: BTreeSet<String>,
}

/// Finds enabled dependency features with no matching static source usage.
#[must_use]
pub fn find_unused_features(
    project_root: &Path,
    packages: &[(std::path::PathBuf, String, toml::Value)],
    workspace_dependencies: Option<&toml::Value>,
    unused_findings: &[UnusedFinding],
) -> Vec<FeatureHint> {
    find_unused_features_with_signals(
        project_root,
        packages,
        workspace_dependencies,
        unused_findings,
        None,
    )
}

/// Like [`find_unused_features`], reusing precomputed per-package feature signals
/// when available so workspace source files are only read and lexed once.
#[must_use]
pub(crate) fn find_unused_features_with_signals(
    project_root: &Path,
    packages: &[(std::path::PathBuf, String, toml::Value)],
    workspace_dependencies: Option<&toml::Value>,
    unused_findings: &[UnusedFinding],
    precomputed: Option<Vec<PrecomputedSignals>>,
) -> Vec<FeatureHint> {
    let unused_set: BTreeSet<(&str, DependencyKind, &str)> = unused_findings
        .iter()
        .map(|f| (f.manifest.as_str(), f.kind, f.dependency.as_str()))
        .collect();

    let signals_vec = precomputed.unwrap_or_else(|| {
        packages
            .iter()
            .map(|(dir, _, manifest)| {
                let sources = collect_sources(dir, manifest);
                PrecomputedSignals {
                    code: collect_signals_from_files(&sources.code, sources.skipped),
                    build: collect_signals_from_files(&sources.build, sources.skipped),
                }
            })
            .collect()
    });

    let mut analyzed = Vec::with_capacity(packages.len());
    for ((_, label, manifest), sig) in packages.iter().zip(signals_vec) {
        let name = manifest
            .get("package")
            .and_then(|pkg| pkg.get("name"))
            .and_then(toml::Value::as_str)
            .unwrap_or("unknown");
        let (ignored, _) = ignore_list(manifest);
        let forwarded = forwarded_keys(manifest);
        let mut inherited_keys = BTreeSet::new();
        super::workspace_inherited_keys(manifest, &mut inherited_keys);
        analyzed.push(AnalyzedPackage {
            name,
            manifest_label: label.as_str(),
            manifest,
            code: sig.code,
            build: sig.build,
            ignored,
            forwarded,
            inherited_keys,
        });
    }

    let mut hints = Vec::new();
    for pkg in &analyzed {
        visit_dependency_tables(pkg.manifest, |kind, _, entries| {
            for (key, spec) in entries {
                if pkg.ignored.contains_key(key)
                    || pkg.forwarded.contains(key)
                    || unused_set.contains(&(pkg.manifest_label, kind, key.as_str()))
                {
                    continue;
                }
                let inherited = spec
                    .get("workspace")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false);
                // Only inspect explicit local `features = [...]` here; workspace-level
                // features are checked across all inheriting members below.
                let Some(features) = explicit_features(spec) else {
                    continue;
                };
                if inherited && features.is_empty() {
                    continue;
                }
                let from_workspace = inherited
                    .then(|| workspace_dependencies.and_then(|ws| ws.get(key)))
                    .flatten();
                let real_package = spec
                    .get("package")
                    .or_else(|| from_workspace.and_then(|s| s.get("package")))
                    .and_then(toml::Value::as_str)
                    .unwrap_or(key);
                let signals = if kind == DependencyKind::Build {
                    &pkg.build
                } else {
                    &pkg.code
                };
                if signals.incomplete {
                    continue;
                }
                let ident = key.replace('-', "_");
                if signals.reexported_roots.contains(&ident) || signals.glob_uses.contains(&ident) {
                    continue;
                }
                if let Some((flagged, suggested, reason)) =
                    evaluate_features(real_package, &features, signals)
                {
                    hints.push(FeatureHint {
                        declared_by: pkg.name.to_owned(),
                        manifest: pkg.manifest_label.to_owned(),
                        dependency: key.clone(),
                        package: real_package.to_owned(),
                        kind,
                        features: flagged,
                        suggested,
                        reason,
                    });
                }
            }
        });
    }

    if let Some(ws_table) = workspace_dependencies.and_then(toml::Value::as_table) {
        collect_workspace_feature_hints(project_root, ws_table, &analyzed, &unused_set, &mut hints);
    }

    hints.sort_by(|a, b| {
        (&a.manifest, a.kind, &a.dependency).cmp(&(&b.manifest, b.kind, &b.dependency))
    });
    hints
}

fn collect_workspace_feature_hints(
    project_root: &Path,
    ws_table: &toml::map::Map<String, toml::Value>,
    analyzed: &[AnalyzedPackage<'_>],
    unused_set: &BTreeSet<(&str, DependencyKind, &str)>,
    hints: &mut Vec<FeatureHint>,
) {
    let mut ws_ignored = IgnoreList::new();
    if let Ok(contents) = fs::read_to_string(project_root.join("Cargo.toml"))
        && let Ok(root_manifest) = toml::from_str::<toml::Value>(&contents)
    {
        let (ignores, _) = ignore_list_at(&root_manifest, "workspace");
        ws_ignored.extend(ignores);
        if root_manifest.get("package").is_some() {
            let (pkg_ignores, _) = ignore_list_at(&root_manifest, "package");
            for (k, v) in pkg_ignores {
                ws_ignored.entry(k).or_insert(v);
            }
        }
    }

    // Group usage signals across all non-build / build inheriting members per key.
    let mut consumers: BTreeMap<&str, FeatureSignals> = BTreeMap::new();
    for pkg in analyzed {
        for key in &pkg.inherited_keys {
            if pkg.forwarded.contains(key) {
                consumers.entry(key.as_str()).or_default().incomplete = true;
                continue;
            }
            let entry = consumers.entry(key.as_str()).or_default();
            entry.merge(&pkg.code);
            entry.merge(&pkg.build);
        }
    }

    for (key, spec) in ws_table {
        if ws_ignored.contains_key(key)
            || unused_set.contains(&("Cargo.toml", DependencyKind::Workspace, key.as_str()))
        {
            continue;
        }
        let Some(features) = explicit_features(spec) else {
            continue;
        };
        let Some(signals) = consumers.get(key.as_str()) else {
            continue;
        };
        let ident = key.replace('-', "_");
        if signals.incomplete
            || signals.reexported_roots.contains(&ident)
            || signals.glob_uses.contains(&ident)
        {
            continue;
        }
        let real_package = spec
            .get("package")
            .and_then(toml::Value::as_str)
            .unwrap_or(key);
        if let Some((flagged, suggested, reason)) =
            evaluate_features(real_package, &features, signals)
        {
            hints.push(FeatureHint {
                declared_by: "workspace".to_owned(),
                manifest: "Cargo.toml".to_owned(),
                dependency: key.clone(),
                package: real_package.to_owned(),
                kind: DependencyKind::Workspace,
                features: flagged,
                suggested,
                reason,
            });
        }
    }
}

fn explicit_features(spec: &toml::Value) -> Option<Vec<String>> {
    let arr = spec.get("features")?.as_array()?;
    let list: Vec<String> = arr
        .iter()
        .filter_map(toml::Value::as_str)
        .map(str::to_owned)
        .collect();
    (!list.is_empty()).then_some(list)
}

fn forwarded_keys(manifest: &toml::Value) -> BTreeSet<String> {
    super::features_forwarded_to(manifest)
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// Evaluates curated high-signal crates/features against extracted source signals.
fn evaluate_features(
    package: &str,
    enabled: &[String],
    signals: &FeatureSignals,
) -> Option<(Vec<String>, Vec<String>, String)> {
    match package {
        "tokio" => evaluate_tokio_full(enabled, signals),
        "serde" => evaluate_derive_feature(
            enabled,
            signals,
            &["Serialize", "Deserialize"],
            "serde_derive",
            "no `#[derive(Serialize)]` or `#[derive(Deserialize)]` found in sources",
        ),
        "clap" => evaluate_derive_feature(
            enabled,
            signals,
            &[
                "Parser",
                "Args",
                "Subcommand",
                "ValueEnum",
                "FromArgMatches",
                "CommandFactory",
            ],
            "clap_derive",
            "no clap derive macro (`Parser`, `Args`, `Subcommand`, `ValueEnum`) found in sources",
        ),
        "syn" => evaluate_syn_full(enabled, signals),
        "reqwest" => evaluate_reqwest(enabled, signals),
        "sqlx" => evaluate_sqlx(enabled, signals),
        "uuid" => evaluate_uuid(enabled, signals),
        _ => None,
    }
}

fn evaluate_tokio_full(
    enabled: &[String],
    signals: &FeatureSignals,
) -> Option<(Vec<String>, Vec<String>, String)> {
    if !enabled.iter().any(|f| f == "full") {
        return None;
    }
    let has_io_ext = [
        "AsyncReadExt",
        "AsyncWriteExt",
        "AsyncBufReadExt",
        "AsyncSeekExt",
    ]
    .iter()
    .any(|ext| signals.idents.contains(*ext));
    let has_io = signals.has_scoped("tokio", "io") || has_io_ext;
    let has_fs = signals.has_scoped("tokio", "fs");
    let has_net = signals.has_scoped("tokio", "net");
    let has_process = signals.has_scoped("tokio", "process");
    let has_signal = signals.has_scoped("tokio", "signal");
    let has_time = signals.has_scoped("tokio", "time");
    let has_sync = signals.has_scoped("tokio", "sync");
    let has_macros = ["main", "test", "select", "pin", "join", "try_join"]
        .iter()
        .any(|m| signals.has_scoped("tokio", m));
    let has_rt = has_macros
        || ["runtime", "task", "spawn"]
            .iter()
            .any(|r| signals.has_scoped("tokio", r));

    let missing_heavy: Vec<&str> = [
        ("fs", has_fs),
        ("net", has_net),
        ("process", has_process),
        ("signal", has_signal),
        ("io-util", has_io),
        ("time", has_time),
    ]
    .into_iter()
    .filter_map(|(name, used)| (!used).then_some(name))
    .collect();

    if missing_heavy.len() < 4 {
        return None;
    }

    let mut suggested = Vec::new();
    if has_rt {
        suggested.push("rt-multi-thread".to_owned());
    }
    if has_macros {
        suggested.push("macros".to_owned());
    }
    if has_sync {
        suggested.push("sync".to_owned());
    }
    if has_time {
        suggested.push("time".to_owned());
    }
    if has_net {
        suggested.push("net".to_owned());
    }
    if has_fs {
        suggested.push("fs".to_owned());
    }
    if has_io {
        suggested.push("io-util".to_owned());
    }
    let reason = format!(
        "`features = [\"full\"]` enables all tokio subsystems, while static analysis saw no {}",
        missing_heavy.join(", ")
    );
    Some((vec!["full".to_owned()], suggested, reason))
}

fn evaluate_derive_feature(
    enabled: &[String],
    signals: &FeatureSignals,
    traits: &[&str],
    direct_macro_crate: &str,
    reason: &str,
) -> Option<(Vec<String>, Vec<String>, String)> {
    if !enabled.iter().any(|f| f == "derive") {
        return None;
    }
    let used = traits.iter().any(|t| signals.derive_traits.contains(*t))
        || signals.idents.contains(direct_macro_crate);
    if used {
        return None;
    }
    Some((vec!["derive".to_owned()], Vec::new(), reason.to_owned()))
}

fn evaluate_syn_full(
    enabled: &[String],
    signals: &FeatureSignals,
) -> Option<(Vec<String>, Vec<String>, String)> {
    if !enabled.iter().any(|f| f == "full") {
        return None;
    }
    const FULL_MODULES: [&str; 3] = ["visit", "visit_mut", "fold"];
    const FULL_ITEMS: [&str; 17] = [
        "Arm",
        "Block",
        "Expr",
        "File",
        "FnArg",
        "ForeignItem",
        "ImplItem",
        "Item",
        "ItemEnum",
        "ItemFn",
        "ItemImpl",
        "ItemStruct",
        "ItemTrait",
        "Local",
        "Pat",
        "Signature",
        "Stmt",
    ];
    let uses_full = FULL_MODULES.iter().any(|m| signals.has_scoped("syn", m))
        || FULL_ITEMS.iter().any(|t| signals.idents.contains(*t))
        || signals.idents.contains("parse_file");
    if uses_full {
        return None;
    }
    Some((
        vec!["full".to_owned()],
        vec!["derive".to_owned()],
        "`syn` enables `full`, while static analysis found no full-AST types (`Expr`, `Item`, `Stmt`, `visit`) in sources".to_owned(),
    ))
}

fn evaluate_reqwest(
    enabled: &[String],
    signals: &FeatureSignals,
) -> Option<(Vec<String>, Vec<String>, String)> {
    let mut unused = Vec::new();
    for feat in ["blocking", "multipart", "json"] {
        if enabled.iter().any(|f| f == feat) && !signals.lower_idents.contains(feat) {
            unused.push(feat.to_owned());
        }
    }
    (!unused.is_empty()).then(|| {
        let reason = format!(
            "`reqwest` enables {} with no matching API token found in sources",
            unused.join(", ")
        );
        (unused, Vec::new(), reason)
    })
}

fn evaluate_sqlx(
    enabled: &[String],
    signals: &FeatureSignals,
) -> Option<(Vec<String>, Vec<String>, String)> {
    let mut unused = Vec::new();
    if enabled.iter().any(|f| f == "mysql")
        && !signals.lower_idents.iter().any(|id| id.contains("mysql"))
    {
        unused.push("mysql".to_owned());
    }
    if enabled.iter().any(|f| f == "sqlite")
        && !signals.lower_idents.iter().any(|id| id.contains("sqlite"))
    {
        unused.push("sqlite".to_owned());
    }
    if enabled.iter().any(|f| f == "postgres")
        && !signals
            .lower_idents
            .iter()
            .any(|id| id.contains("postgres") || id.starts_with("pg"))
    {
        unused.push("postgres".to_owned());
    }
    (!unused.is_empty()).then(|| {
        let reason = format!(
            "`sqlx` enables unused database driver feature(s): {}",
            unused.join(", ")
        );
        (unused, Vec::new(), reason)
    })
}

fn evaluate_uuid(
    enabled: &[String],
    signals: &FeatureSignals,
) -> Option<(Vec<String>, Vec<String>, String)> {
    let mut unused = Vec::new();
    if enabled.iter().any(|f| f == "v4") && !signals.lower_idents.iter().any(|id| id.contains("v4"))
    {
        unused.push("v4".to_owned());
    }
    if enabled.iter().any(|f| f == "v7") && !signals.lower_idents.iter().any(|id| id.contains("v7"))
    {
        unused.push("v7".to_owned());
    }
    if enabled.iter().any(|f| f == "serde")
        && !signals.derive_traits.contains("Serialize")
        && !signals.derive_traits.contains("Deserialize")
    {
        unused.push("serde".to_owned());
    }
    (!unused.is_empty()).then(|| {
        let reason = format!("`uuid` enables unused feature(s): {}", unused.join(", "));
        (unused, Vec::new(), reason)
    })
}

#[cfg(test)]
mod tests {
    use super::find_unused_features;
    use cargoscope_core::DependencyKind;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cargoscope-feat-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).expect("src dir");
        dir
    }

    #[test]
    fn flags_unused_tokio_full_and_serde_derive_and_keeps_used_ones() {
        let dir = temp_dir("basic");
        let manifest_str = r#"
[package]
name = "app"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
clap = { version = "4", features = ["derive"] }
reqwest = { version = "0.12", features = ["blocking", "json"] }
"#;
        std::fs::write(dir.join("Cargo.toml"), manifest_str).expect("manifest");
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

#[tokio::main]
async fn run(req: reqwest::Client) {
    let _ = req.get("https://example.test").send().await;
    let _m = Mutex::new(1);
}

#[derive(clap::Parser)]
struct Cli {}

pub fn takes<T: DeserializeOwned>() {}
"#,
        )
        .expect("lib.rs");

        let manifest: toml::Value = toml::from_str(manifest_str).expect("toml");
        let packages = vec![(dir.clone(), "Cargo.toml".to_owned(), manifest)];
        let hints = find_unused_features(&dir, &packages, None, &[]);

        let tokio = hints
            .iter()
            .find(|h| h.dependency == "tokio")
            .expect("tokio hint");
        assert_eq!(tokio.features, vec!["full"]);
        assert!(tokio.suggested.contains(&"rt-multi-thread".to_owned()));
        assert!(tokio.suggested.contains(&"macros".to_owned()));
        assert!(tokio.suggested.contains(&"sync".to_owned()));

        let serde = hints
            .iter()
            .find(|h| h.dependency == "serde")
            .expect("serde hint");
        assert_eq!(serde.features, vec!["derive"]);
        assert!(serde.suggested.is_empty());

        let reqwest = hints
            .iter()
            .find(|h| h.dependency == "reqwest")
            .expect("reqwest hint");
        assert_eq!(reqwest.features, vec!["blocking", "json"]);

        // `clap` derives Parser, so no hint is emitted for it.
        assert!(!hints.iter().any(|h| h.dependency == "clap"), "{hints:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn skips_pub_reexports_glob_imports_and_aggregates_workspace_inheritance() {
        let dir = temp_dir("workspace");
        std::fs::create_dir_all(dir.join("a/src")).expect("a");
        std::fs::create_dir_all(dir.join("b/src")).expect("b");
        let root_str = r#"
[workspace]
members = ["a", "b"]

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
"#;
        let a_str = "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[dependencies]\ntokio.workspace = true\nserde.workspace = true\n";
        let b_str = "[package]\nname = \"b\"\nversion = \"0.1.0\"\n[dependencies]\ntokio.workspace = true\nserde.workspace = true\n";
        std::fs::write(dir.join("Cargo.toml"), root_str).expect("root");
        std::fs::write(dir.join("a/Cargo.toml"), a_str).expect("a");
        std::fs::write(dir.join("b/Cargo.toml"), b_str).expect("b");
        std::fs::write(
            dir.join("a/src/lib.rs"),
            "#[derive(serde::Serialize)]\npub struct S;\npub async fn f() { let _ = tokio::sync::Notify::new(); }\n",
        )
        .expect("a lib");
        std::fs::write(
            dir.join("b/src/lib.rs"),
            "pub use serde::Deserialize;\npub async fn g() { tokio::time::sleep(std::time::Duration::from_millis(1)).await; }\n",
        )
        .expect("b lib");

        let root_toml: toml::Value = toml::from_str(root_str).expect("root");
        let ws_deps = root_toml
            .get("workspace")
            .and_then(|w| w.get("dependencies"));
        let packages = vec![
            (
                dir.join("a"),
                "a/Cargo.toml".to_owned(),
                toml::from_str(a_str).expect("a"),
            ),
            (
                dir.join("b"),
                "b/Cargo.toml".to_owned(),
                toml::from_str(b_str).expect("b"),
            ),
        ];

        let hints = find_unused_features(&dir, &packages, ws_deps, &[]);
        // Member `a` derives Serialize, so workspace `serde` `derive` is used.
        assert!(!hints.iter().any(|h| h.dependency == "serde"), "{hints:?}");
        // Workspace `tokio` `full` only uses sync + time -> flagged once on workspace.
        let tokio = hints
            .iter()
            .find(|h| h.dependency == "tokio")
            .expect("tokio ws hint");
        assert_eq!(tokio.kind, DependencyKind::Workspace);
        assert!(tokio.suggested.contains(&"sync".to_owned()));
        assert!(tokio.suggested.contains(&"time".to_owned()));

        // Glob `use tokio::*;` suppresses tokio hint.
        std::fs::write(dir.join("a/src/lib.rs"), "use tokio::*;\n").expect("glob");
        let after_glob = find_unused_features(&dir, &packages, ws_deps, &[]);
        assert!(
            !after_glob.iter().any(|h| h.dependency == "tokio"),
            "{after_glob:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
