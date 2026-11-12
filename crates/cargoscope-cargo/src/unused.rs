//! Static detection of likely-unused dependencies (SPEC.md section 5.2).
//!
//! Each Rust source file is split into tokens with `proc-macro2`, so comments
//! and string literals are ignored while paths inside macro invocations and
//! attributes are still seen. A file that cannot be tokenized falls back to a
//! plain text search and lowers the confidence of every finding.
//!
//! Nothing is compiled or executed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use cargoscope_core::{DependencyKind, Inventory, UnusedConfidence, UnusedFinding};
use proc_macro2::{TokenStream, TokenTree};

const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_FILES: usize = 20_000;

/// Directories searched for sources, relative to a package manifest.
const SOURCE_DIRS: [&str; 4] = ["src", "tests", "benches", "examples"];

/// One dependency declared in a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredDependency {
    /// Manifest key, which is the crate name used in code (with `-` read as `_`).
    pub key: String,
    /// Real crate name (`package = "..."`), or the key.
    pub package: String,
    /// Manifest section.
    pub kind: DependencyKind,
    /// Declared with `optional = true`.
    pub optional: bool,
    /// Declared under `[target.'...'.*dependencies]`.
    pub target_specific: bool,
    /// Declared with `features` or `default-features`.
    pub sets_features: bool,
}

/// Reads every declared dependency of a manifest.
///
/// `workspace_dependencies` is the `[workspace.dependencies]` table of the
/// workspace root, used to resolve `dep = { workspace = true }` entries.
pub fn declared_dependencies(
    manifest: &toml::Value,
    workspace_dependencies: Option<&toml::Value>,
) -> Vec<DeclaredDependency> {
    let mut declared = Vec::new();
    let mut read_tables = |table: &toml::Value, target_specific: bool| {
        for kind in [
            DependencyKind::Normal,
            DependencyKind::Dev,
            DependencyKind::Build,
        ] {
            let mut names = vec![kind.section()];
            if kind != DependencyKind::Normal {
                // Cargo also accepts the underscore spelling.
                names.push(match kind {
                    DependencyKind::Dev => "dev_dependencies",
                    _ => "build_dependencies",
                });
            }
            for name in names {
                let Some(entries) = table.get(name).and_then(toml::Value::as_table) else {
                    continue;
                };
                for (key, specification) in entries {
                    let inherited = specification
                        .get("workspace")
                        .and_then(toml::Value::as_bool)
                        .unwrap_or(false);
                    let from_workspace = inherited
                        .then(|| workspace_dependencies.and_then(|deps| deps.get(key)))
                        .flatten();
                    let lookup = |field: &str| {
                        specification
                            .get(field)
                            .or_else(|| from_workspace.and_then(|spec| spec.get(field)))
                    };
                    declared.push(DeclaredDependency {
                        key: key.clone(),
                        package: lookup("package")
                            .and_then(toml::Value::as_str)
                            .unwrap_or(key)
                            .to_owned(),
                        kind,
                        optional: specification
                            .get("optional")
                            .and_then(toml::Value::as_bool)
                            .unwrap_or(false),
                        target_specific,
                        sets_features: lookup("features").is_some()
                            || lookup("default-features").is_some()
                            || lookup("default_features").is_some(),
                    });
                }
            }
        }
    };

    read_tables(manifest, false);
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            read_tables(target, true);
        }
    }
    declared.sort_by(|left, right| (left.kind, &left.key).cmp(&(right.kind, &right.key)));
    declared.dedup_by(|left, right| left.kind == right.kind && left.key == right.key);
    declared
}

/// Ignore entries from configuration: dependency key → reason.
pub type IgnoreList = BTreeMap<String, String>;

/// Reads `[package.metadata.cargoscope] ignore-unused = [{ name, reason }]`.
///
/// Entries without a non-empty `reason` are not applied and are returned as
/// warnings, so that every exception stays explained.
pub fn ignore_list(manifest: &toml::Value) -> (IgnoreList, Vec<String>) {
    let mut ignored = IgnoreList::new();
    let mut warnings = Vec::new();
    let entries = manifest
        .get("package")
        .and_then(|package| package.get("metadata"))
        .and_then(|metadata| metadata.get("cargoscope"))
        .and_then(|config| config.get("ignore-unused"))
        .and_then(toml::Value::as_array);
    for entry in entries.into_iter().flatten() {
        let name = entry.get("name").and_then(toml::Value::as_str);
        let reason = entry
            .get("reason")
            .and_then(toml::Value::as_str)
            .map(str::trim)
            .filter(|reason| !reason.is_empty());
        match (name, reason) {
            (Some(name), Some(reason)) => {
                ignored.insert(name.to_owned(), reason.to_owned());
            }
            (Some(name), None) => warnings.push(format!(
                "ignore-unused entry for `{name}` has no reason and is not applied"
            )),
            _ => warnings.push("ignore-unused entry without `name` is not applied".to_owned()),
        }
    }
    (ignored, warnings)
}

/// Where a package's code lives.
#[derive(Debug, Default)]
struct Sources {
    /// Files of the library, binaries, tests, benches and examples.
    code: Vec<PathBuf>,
    /// Build script files.
    build: Vec<PathBuf>,
    /// The package has a build script (which may generate included code).
    has_build_script: bool,
    /// The directory is a package downloaded from a registry (`Cargo.toml.orig`).
    published_copy: bool,
    /// At least one file was found in tests/, benches/ or examples/.
    has_test_files: bool,
    /// Files skipped because of size, depth or count limits.
    skipped: usize,
}

fn collect_sources(package_dir: &Path, manifest: &toml::Value) -> Sources {
    let mut sources = Sources {
        published_copy: is_regular_file(&package_dir.join("Cargo.toml.orig")),
        ..Sources::default()
    };
    for dir in SOURCE_DIRS {
        let before = sources.code.len();
        walk(
            &package_dir.join(dir),
            0,
            &mut sources.code,
            &mut sources.skipped,
        );
        sources.has_test_files |= dir != "src" && sources.code.len() > before;
    }
    // Targets with custom paths, such as `[[bin]] path = "tools/main.rs"`.
    for section in ["lib", "bin", "test", "bench", "example"] {
        let targets: Vec<&toml::Value> = match manifest.get(section) {
            Some(toml::Value::Array(items)) => items.iter().collect(),
            Some(table @ toml::Value::Table(_)) => vec![table],
            _ => Vec::new(),
        };
        for target in targets {
            if let Some(path) = target.get("path").and_then(toml::Value::as_str) {
                // Follow `mod name;` declarations, since such targets often
                // live outside src/ (`crates/core/main.rs`, `main.rs`).
                follow_modules(
                    &package_dir.join(path),
                    0,
                    &mut sources.code,
                    &mut sources.skipped,
                );
            }
        }
    }

    let build_setting = manifest
        .get("package")
        .and_then(|package| package.get("build"));
    let build_path = match build_setting {
        Some(toml::Value::String(path)) => Some(package_dir.join(path)),
        Some(toml::Value::Boolean(false)) => None,
        _ => Some(package_dir.join("build.rs")),
    };
    if let Some(path) = build_path.filter(|path| is_regular_file(path)) {
        sources.has_build_script = true;
        // Build scripts often reuse code from src/ with `#[path] mod` or
        // `include!("...")`.
        follow_modules(&path, 0, &mut sources.build, &mut sources.skipped);
        if let Some(dir) = path.parent().filter(|dir| *dir != package_dir) {
            walk(dir, 0, &mut sources.build, &mut sources.skipped);
        }
    }

    sources.code.sort();
    sources.code.dedup();
    sources.build.sort();
    sources.build.dedup();
    sources
}

fn is_regular_file(path: &Path) -> bool {
    // Symbolic links are never followed.
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn add_file(path: &Path, files: &mut Vec<PathBuf>, skipped: &mut usize) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if !metadata.is_file() || path.extension().is_none_or(|ext| ext != "rs") {
        return;
    }
    if metadata.len() > MAX_SOURCE_BYTES || files.len() >= MAX_FILES {
        *skipped += 1;
        return;
    }
    files.push(path.to_path_buf());
}

/// Adds `file` and, recursively, the files of the modules it declares with
/// `mod name;` (as `name.rs` or `name/mod.rs`, or a `#[path = "..."]`).
fn follow_modules(file: &Path, depth: usize, files: &mut Vec<PathBuf>, skipped: &mut usize) {
    if depth > MAX_DEPTH || files.iter().any(|known| known == file) {
        return;
    }
    let before = files.len();
    add_file(file, files, skipped);
    if files.len() == before {
        return;
    }
    let Ok(text) = fs::read_to_string(file) else {
        return;
    };
    let Ok(tokens) = TokenStream::from_str(&text) else {
        return;
    };
    let Some(dir) = file.parent() else {
        return;
    };
    // Children of `main.rs`, `lib.rs` and `mod.rs` live next to them; those
    // of `foo.rs` live in `foo/`.
    let stem = file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    let module_dir = if matches!(stem, "main" | "lib" | "mod") || depth == 0 {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    for included in included_files(tokens.clone())
        .into_iter()
        .filter(|path| !path.contains(".."))
    {
        follow_modules(&dir.join(included), depth + 1, files, skipped);
    }
    for (name, explicit_path) in declared_modules(tokens) {
        if explicit_path
            .as_deref()
            .is_some_and(|path| path.contains(".."))
        {
            continue;
        }
        let candidates = match explicit_path {
            Some(path) => vec![dir.join(path)],
            None => vec![
                module_dir.join(format!("{name}.rs")),
                module_dir.join(&name).join("mod.rs"),
            ],
        };
        if let Some(found) = candidates.into_iter().find(|path| is_regular_file(path)) {
            follow_modules(&found, depth + 1, files, skipped);
        }
    }
}

/// Paths given to `include!("...")` with a plain string literal.
fn included_files(tokens: TokenStream) -> Vec<String> {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    let mut files = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Group(group) => files.extend(included_files(group.stream())),
            TokenTree::Ident(ident) if ident == "include" => {
                if let (Some(TokenTree::Punct(bang)), Some(TokenTree::Group(arguments))) =
                    (tokens.get(index + 1), tokens.get(index + 2))
                {
                    let inner: Vec<TokenTree> = arguments.stream().into_iter().collect();
                    if let ([TokenTree::Literal(path)], '!') = (inner.as_slice(), bang.as_char()) {
                        let text = path.to_string();
                        if let Some(path) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"'))
                        {
                            files.push(path.to_owned());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    files
}

/// Top-level `mod name;` declarations, with their `#[path = "..."]` if any.
fn declared_modules(tokens: TokenStream) -> Vec<(String, Option<String>)> {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    let mut modules = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let TokenTree::Ident(keyword) = token else {
            continue;
        };
        if keyword != "mod" {
            continue;
        }
        let (Some(TokenTree::Ident(name)), Some(TokenTree::Punct(semicolon))) =
            (tokens.get(index + 1), tokens.get(index + 2))
        else {
            continue;
        };
        if semicolon.as_char() != ';' {
            continue;
        }
        let explicit_path = tokens[..index].iter().rev().find_map(|token| match token {
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                match inner.as_slice() {
                    [
                        TokenTree::Ident(attribute),
                        TokenTree::Punct(eq),
                        TokenTree::Literal(path),
                    ] if attribute == "path" && eq.as_char() == '=' => {
                        Some(path.to_string().trim_matches('"').to_owned())
                    }
                    _ => None,
                }
            }
            _ => None,
        });
        // Only an attribute directly before this `mod` counts.
        let directly_before = index >= 2
            && matches!(&tokens[index - 2], TokenTree::Punct(hash) if hash.as_char() == '#');
        modules.push((name.to_string(), explicit_path.filter(|_| directly_before)));
    }
    modules
}

fn walk(dir: &Path, depth: usize, files: &mut Vec<PathBuf>, skipped: &mut usize) {
    if depth > MAX_DEPTH {
        *skipped += 1;
        return;
    }
    if !fs::symlink_metadata(dir).is_ok_and(|metadata| metadata.is_dir()) {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            walk(&path, depth + 1, files, skipped);
        } else {
            add_file(&path, files, skipped);
        }
    }
}

/// Crate identifiers referenced by a set of files.
#[derive(Debug, Default)]
struct References {
    names: BTreeSet<String>,
    /// Text of doc comments (`///`, `//!`), where doctests use dev-dependencies.
    doc_text: Vec<String>,
    /// Some file includes code generated in `OUT_DIR` (`include!(...OUT_DIR...)`).
    includes_generated_code: bool,
    /// Files that could not be tokenized and were searched as plain text.
    text_fallback: Vec<PathBuf>,
    /// Raw contents of those files, searched as plain text.
    raw_text: Vec<String>,
}

impl References {
    fn in_docs(&self, ident: &str) -> bool {
        self.doc_text.iter().any(|text| text_mentions(text, ident))
    }

    fn contains(&self, ident: &str) -> bool {
        self.names.contains(ident) || self.raw_text.iter().any(|text| text_mentions(text, ident))
    }
}

fn scan_files(files: &[PathBuf]) -> References {
    let mut references = References::default();
    for file in files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        if let Ok(tokens) = TokenStream::from_str(&text) {
            references.includes_generated_code |= includes_generated_code(tokens.clone());
            collect_doc_text(tokens.clone(), &mut references.doc_text);
            collect_references(tokens, &mut references.names);
        } else {
            references.text_fallback.push(file.clone());
            references.raw_text.push(text);
        }
    }
    references
}

/// Records identifiers that appear as the first segment of a path
/// (`name::...`), after `extern crate`, or after `use`.
fn collect_references(tokens: TokenStream, names: &mut BTreeSet<String>) {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Group(group) => {
                let is_attribute = group.delimiter() == proc_macro2::Delimiter::Bracket
                    && index.checked_sub(1).is_some_and(|previous| {
                        matches!(&tokens[previous], TokenTree::Punct(p) if p.as_char() == '#' || p.as_char() == '!')
                    });
                if is_attribute {
                    collect_attribute_references(group.stream(), names);
                }
                collect_references(group.stream(), names);
            }
            TokenTree::Ident(ident) => {
                let name = ident.to_string();
                let name = name.strip_prefix("r#").unwrap_or(&name).to_owned();
                let followed_by_path = matches!(
                    (tokens.get(index + 1), tokens.get(index + 2)),
                    (Some(TokenTree::Punct(first)), Some(TokenTree::Punct(second)))
                        if first.as_char() == ':' && second.as_char() == ':'
                );
                let previous = |offset: usize| {
                    index
                        .checked_sub(offset)
                        .and_then(|position| tokens.get(position))
                        .map(ToString::to_string)
                };
                let after_use = previous(1).as_deref() == Some("use");
                let after_extern_crate = previous(1).as_deref() == Some("crate")
                    && previous(2).as_deref() == Some("extern");
                if followed_by_path || after_use || after_extern_crate {
                    names.insert(name);
                }
            }
            _ => {}
        }
    }
}

/// References specific to attributes: the attribute name itself (derive
/// helper attributes such as `#[serde(...)]` need their crate), and string
/// literals holding a path, as in `#[serde(with = "serde_regex")]`.
fn collect_attribute_references(tokens: TokenStream, names: &mut BTreeSet<String>) {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    if let Some(TokenTree::Ident(head)) = tokens.first() {
        if head == "doc" {
            return;
        }
        if matches!(tokens.get(1), Some(TokenTree::Group(_)) | None) {
            names.insert(head.to_string());
        }
    }
    collect_path_literals(&tokens, names);
}

fn collect_path_literals(tokens: &[TokenTree], names: &mut BTreeSet<String>) {
    for token in tokens {
        match token {
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                collect_path_literals(&inner, names);
            }
            TokenTree::Literal(literal) => {
                let text = literal.to_string();
                let Some(text) = text
                    .strip_prefix('"')
                    .and_then(|text| text.strip_suffix('"'))
                else {
                    continue;
                };
                let first = text.split("::").next().unwrap_or_default();
                let is_path = !first.is_empty()
                    && first.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !first.starts_with(|c: char| c.is_ascii_digit())
                    && text.split("::").all(|segment| {
                        segment
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    });
                if is_path {
                    names.insert(first.to_owned());
                }
            }
            _ => {}
        }
    }
}

/// Collects the text of `#[doc = "..."]` attributes, which is how doc
/// comments appear in a token stream.
fn collect_doc_text(tokens: TokenStream, out: &mut Vec<String>) {
    for token in tokens {
        if let TokenTree::Group(group) = token {
            let inner: Vec<TokenTree> = group.stream().into_iter().collect();
            if let [
                TokenTree::Ident(ident),
                TokenTree::Punct(eq),
                TokenTree::Literal(text),
            ] = inner.as_slice()
            {
                if ident == "doc" && eq.as_char() == '=' {
                    out.push(text.to_string());
                    continue;
                }
            }
            collect_doc_text(group.stream(), out);
        }
    }
}

/// Detects `include!(...)` invocations whose arguments mention `OUT_DIR`.
fn includes_generated_code(tokens: TokenStream) -> bool {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    tokens.iter().enumerate().any(|(index, token)| match token {
        TokenTree::Group(group) => includes_generated_code(group.stream()),
        TokenTree::Ident(ident) => {
            let name = ident.to_string();
            let Some((TokenTree::Punct(bang), Some(TokenTree::Group(arguments)))) = tokens
                .get(index + 1)
                .map(|bang| (bang, tokens.get(index + 2)))
            else {
                return false;
            };
            if bang.as_char() != '!' {
                return false;
            }
            match name.as_str() {
                // `include!(concat!(env!("OUT_DIR"), "/gen.rs"))`.
                "include" => arguments.to_string().contains("OUT_DIR"),
                // These embed data, not code.
                "include_str" | "include_bytes" => false,
                // `tonic::include_proto!`, `include_generated!`, ...
                other => other.starts_with("include_"),
            }
        }
        _ => false,
    })
}

/// Plain text search used only for files that cannot be tokenized.
fn text_mentions(text: &str, ident: &str) -> bool {
    text.match_indices(ident).any(|(position, _)| {
        let before = text[..position].chars().next_back();
        let after = &text[position + ident.len()..];
        before.is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
            && (after.starts_with("::") || after.starts_with(';') || after.starts_with(' '))
    })
}

/// A project package to analyze.
pub struct PackageToCheck<'a> {
    /// Package name.
    pub name: &'a str,
    /// Directory containing its `Cargo.toml`.
    pub dir: &'a Path,
    /// Manifest path relative to the scanned directory, for reports.
    pub manifest_label: &'a str,
    /// Parsed manifest.
    pub manifest: &'a toml::Value,
}

/// Finds declared dependencies with no usage in a package's sources.
///
/// `inventory` is used to recognise dependencies that are also pulled in
/// transitively, which may be declared only to select their features.
pub fn check_package(
    package: &PackageToCheck<'_>,
    workspace_dependencies: Option<&toml::Value>,
    inventory: &Inventory,
) -> (Vec<UnusedFinding>, Vec<String>) {
    let sources = collect_sources(package.dir, package.manifest);
    let code_refs = scan_files(&sources.code);
    let build_refs = scan_files(&sources.build);
    let (ignored, mut warnings) = ignore_list(package.manifest);
    if sources.skipped > 0 {
        warnings.push(format!(
            "{}: {} source file(s) skipped (size, depth or count limit); unused results may be wrong",
            package.manifest_label, sources.skipped
        ));
    }

    let transitive_names: BTreeSet<&str> = inventory
        .packages
        .iter()
        .filter(|candidate| !candidate.root)
        .flat_map(|candidate| candidate.dependencies.iter())
        .map(|&index| inventory.packages[index].name.as_str())
        .collect();

    let mut findings = Vec::new();
    for dependency in declared_dependencies(package.manifest, workspace_dependencies) {
        let ident = dependency.key.replace('-', "_");
        let (references, searched, searched_label) = match dependency.kind {
            DependencyKind::Build => (&build_refs, sources.build.len(), "build script"),
            _ => (
                &code_refs,
                sources.code.len(),
                "src/, tests/, benches/, examples/",
            ),
        };
        if references.contains(&ident)
            || (dependency.kind == DependencyKind::Dev && references.in_docs(&ident))
        {
            continue;
        }

        let mut evidence = vec![format!(
            "no `{ident}::`, `use {ident}` or `extern crate {ident}` in {searched} file(s) ({searched_label})"
        )];
        let mut exceptions = Vec::new();
        if dependency.package.ends_with("-sys") || dependency.package.ends_with("_sys") {
            exceptions
                .push("`-sys` crates are often linked only for their native library".to_owned());
        }
        if dependency.optional {
            exceptions
                .push("optional dependency: may only be used to forward a feature".to_owned());
        }
        if dependency.target_specific {
            exceptions.push("platform-specific dependency".to_owned());
        }
        if dependency.sets_features && transitive_names.contains(dependency.package.as_str()) {
            exceptions.push(
                "also a transitive dependency: may be declared only to select its features"
                    .to_owned(),
            );
        }
        if sources.has_build_script
            && dependency.kind != DependencyKind::Build
            && code_refs.includes_generated_code
        {
            exceptions.push(
                "the sources include code generated by the build script, which may use it"
                    .to_owned(),
            );
        }
        if !references.text_fallback.is_empty() {
            exceptions.push(format!(
                "{} file(s) could not be tokenized and were searched as plain text",
                references.text_fallback.len()
            ));
        }
        if dependency.kind == DependencyKind::Dev && sources.published_copy {
            exceptions.push(
                "published package copy (Cargo.toml.orig present): test files are often excluded from it"
                    .to_owned(),
            );
        } else if dependency.kind == DependencyKind::Dev && !sources.has_test_files {
            exceptions.push(
                "no tests/, benches/ or examples/ found: test files may be missing from this copy"
                    .to_owned(),
            );
        }
        if searched == 0 {
            exceptions.push(format!("no {searched_label} file found"));
        }

        let confidence = if exceptions.is_empty() {
            UnusedConfidence::Likely
        } else {
            UnusedConfidence::Possibly
        };
        evidence.extend(exceptions);
        findings.push(UnusedFinding {
            declared_by: package.name.to_owned(),
            manifest: package.manifest_label.to_owned(),
            dependency: dependency.key.clone(),
            package: dependency.package.clone(),
            kind: dependency.kind,
            confidence,
            evidence,
            ignored: ignored.get(&dependency.key).cloned(),
        });
    }

    findings.sort_by(|left, right| {
        (left.confidence, left.kind, &left.dependency).cmp(&(
            right.confidence,
            right.kind,
            &right.dependency,
        ))
    });
    (findings, warnings)
}

#[cfg(test)]
mod tests {
    use super::{collect_references, declared_dependencies, ignore_list, text_mentions};
    use cargoscope_core::DependencyKind;
    use proc_macro2::TokenStream;
    use std::collections::BTreeSet;
    use std::str::FromStr;

    fn references(source: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        collect_references(
            TokenStream::from_str(source).expect("tokenizes"),
            &mut names,
        );
        names
    }

    #[test]
    fn finds_paths_uses_extern_crates_macros_and_attributes() {
        let names = references(
            r#"
            use serde::Serialize;
            use anyhow;
            extern crate log;
            #[tokio::main]
            async fn main() {
                println!("{}", itoa::Buffer::new().format(1));
                let _ = r#async::run();
            }
            "#,
        );
        for expected in ["serde", "anyhow", "log", "tokio", "itoa", "async"] {
            assert!(names.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn derive_helper_attributes_and_path_strings_count_as_references() {
        let names = references(
            r#"
            #[derive(Deserialize)]
            #[serde(tag = "type", content = "data")]
            struct A {
                #[serde(with = "serde_regex", default)]
                r: Regex,
                #[serde(deserialize_with = "humantime_serde::deserialize")]
                d: Duration,
            }
            #[doc = "log"]
            #[inline]
            fn f() {}
            "#,
        );
        assert!(names.contains("serde"));
        assert!(names.contains("serde_regex"));
        assert!(names.contains("humantime_serde"));
        assert!(!names.contains("log"), "doc text is not a reference");
    }

    #[test]
    fn ignores_comments_and_strings() {
        let names = references(
            r#"
            // regex::Regex is not used
            /* rand::random */
            fn main() { let _ = "chrono::Utc"; }
            "#,
        );
        assert!(names.is_empty(), "{names:?}");
    }

    #[test]
    fn local_modules_count_as_references_but_never_hide_other_crates() {
        let names = references("mod util; fn f() { util::g(); }");
        assert!(names.contains("util"));
        assert!(!names.contains("serde"));
    }

    #[test]
    fn detects_included_generated_code() {
        let generated =
            TokenStream::from_str(r#"mod gen { include!(concat!(env!("OUT_DIR"), "/gen.rs")); }"#)
                .expect("tokenizes");
        assert!(super::includes_generated_code(generated));
        let plain =
            TokenStream::from_str(r#"const A: &str = include_str!("a.txt");"#).expect("tokenizes");
        assert!(!super::includes_generated_code(plain));
    }

    #[test]
    fn collects_doc_comment_text() {
        let tokens = TokenStream::from_str(
            "/// ```\n/// use async_stream::stream;\n/// ```\nfn f() {}\n//! inner docs mention tempfile::tempdir\n",
        )
        .expect("tokenizes");
        let mut docs = Vec::new();
        super::collect_doc_text(tokens, &mut docs);
        let joined = docs.join("\n");
        assert!(text_mentions(&joined, "async_stream"));
    }

    #[test]
    fn follows_module_declarations_from_a_custom_target_path() {
        let root = std::env::temp_dir().join(format!("cargoscope-mods-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("core/flags")).expect("dirs");
        std::fs::write(
            root.join("core/main.rs"),
            "mod flags;\n#[path = \"extra_impl.rs\"]\nmod extra;\nfn main() {}\n",
        )
        .expect("write");
        std::fs::write(root.join("core/flags/mod.rs"), "mod parse;\n").expect("write");
        std::fs::write(root.join("core/flags/parse.rs"), "use lexopt::Parser;\n").expect("write");
        std::fs::write(root.join("core/extra_impl.rs"), "").expect("write");
        let mut files = Vec::new();
        let mut skipped = 0;
        super::follow_modules(&root.join("core/main.rs"), 0, &mut files, &mut skipped);
        let names: Vec<String> = files
            .iter()
            .map(|file| {
                file.strip_prefix(&root)
                    .expect("inside")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "core/main.rs",
                "core/flags/mod.rs",
                "core/flags/parse.rs",
                "core/extra_impl.rs"
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn follows_path_modules_and_includes_from_a_build_script() {
        let root = std::env::temp_dir().join(format!("cargoscope-build-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src/cmd")).expect("dirs");
        std::fs::write(
            root.join("build.rs"),
            "#[path = \"src/cmd/cmd.rs\"]\nmod cmd;\ninclude!(\"src/cli.rs\");\ninclude!(\"../outside.rs\");\nfn main() {}\n",
        )
        .expect("write");
        std::fs::write(root.join("src/cmd/cmd.rs"), "").expect("write");
        std::fs::write(root.join("src/cli.rs"), "").expect("write");
        let mut files = Vec::new();
        let mut skipped = 0;
        super::follow_modules(&root.join("build.rs"), 0, &mut files, &mut skipped);
        let mut names: Vec<String> = files
            .iter()
            .map(|file| {
                file.strip_prefix(&root)
                    .expect("inside")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        names.sort();
        assert_eq!(names, vec!["build.rs", "src/cli.rs", "src/cmd/cmd.rs"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn text_fallback_requires_a_path_like_mention() {
        assert!(text_mentions("x = serde::de", "serde"));
        assert!(!text_mentions("my_serde::de", "serde"));
        assert!(!text_mentions("serde_json::x", "serde"));
    }

    #[test]
    fn reads_all_sections_renames_targets_and_workspace_inheritance() {
        let manifest: toml::Value = toml::from_str(
            r#"
            [package]
            name = "demo"
            [dependencies]
            json = { package = "serde_json", version = "1" }
            shared = { workspace = true }
            opt = { version = "1", optional = true }
            [dev-dependencies]
            tempfile = "3"
            [build-dependencies]
            cc = "1"
            [target.'cfg(windows)'.dependencies]
            winapi = "0.3"
            "#,
        )
        .expect("valid");
        let workspace: toml::Value = toml::from_str(
            r#"shared = { package = "real-shared", version = "1", features = ["x"] }"#,
        )
        .expect("valid");

        let declared = declared_dependencies(&manifest, Some(&workspace));
        let summary: Vec<(DependencyKind, &str, &str, bool, bool, bool)> = declared
            .iter()
            .map(|d| {
                (
                    d.kind,
                    d.key.as_str(),
                    d.package.as_str(),
                    d.optional,
                    d.target_specific,
                    d.sets_features,
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    DependencyKind::Normal,
                    "json",
                    "serde_json",
                    false,
                    false,
                    false
                ),
                (DependencyKind::Normal, "opt", "opt", true, false, false),
                (
                    DependencyKind::Normal,
                    "shared",
                    "real-shared",
                    false,
                    false,
                    true
                ),
                (
                    DependencyKind::Normal,
                    "winapi",
                    "winapi",
                    false,
                    true,
                    false
                ),
                (
                    DependencyKind::Dev,
                    "tempfile",
                    "tempfile",
                    false,
                    false,
                    false
                ),
                (DependencyKind::Build, "cc", "cc", false, false, false),
            ]
        );
    }

    #[test]
    fn ignore_entries_require_a_reason() {
        let manifest: toml::Value = toml::from_str(
            r#"
            [package]
            name = "demo"
            [package.metadata.cargoscope]
            ignore-unused = [
              { name = "once_cell", reason = "used by generated code" },
              { name = "log" },
            ]
            "#,
        )
        .expect("valid");
        let (ignored, warnings) = ignore_list(&manifest);
        assert_eq!(
            ignored.get("once_cell").map(String::as_str),
            Some("used by generated code")
        );
        assert!(!ignored.contains_key("log"));
        assert_eq!(warnings.len(), 1);
    }
}
