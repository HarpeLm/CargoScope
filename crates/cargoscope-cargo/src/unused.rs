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
    /// `path = "..."` of a local dependency, and whether it is relative to
    /// the workspace root (inherited with `workspace = true`) rather than to
    /// the package.
    pub path: Option<(String, bool)>,
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
                        path: specification
                            .get("path")
                            .and_then(toml::Value::as_str)
                            .map(|path| (path.to_owned(), false))
                            .or_else(|| {
                                from_workspace
                                    .and_then(|spec| spec.get("path"))
                                    .and_then(toml::Value::as_str)
                                    .map(|path| (path.to_owned(), true))
                            }),
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

/// The directory that `include!`, `#[path]` and target paths may reach: the
/// workspace root (the nearest ancestor whose `Cargo.toml` has a
/// `[workspace]` table), or the package itself outside a workspace.
fn source_bound(package_dir: &Path) -> PathBuf {
    let start = package_dir
        .canonicalize()
        .unwrap_or_else(|_| package_dir.to_path_buf());
    let mut current = Some(start.as_path());
    while let Some(dir) = current {
        let manifest = dir.join("Cargo.toml");
        let is_workspace = fs::symlink_metadata(&manifest)
            .is_ok_and(|m| m.is_file() && m.len() <= MAX_SOURCE_BYTES)
            && fs::read_to_string(&manifest)
                .ok()
                .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
                .is_some_and(|value| value.get("workspace").is_some());
        if is_workspace {
            return dir.to_path_buf();
        }
        current = dir.parent();
    }
    start
}

/// Whether `path` resolves to a location inside `bound` (no escape through
/// `..`, an absolute path or a symbolic link).
fn is_within(bound: &Path, path: &Path) -> bool {
    path.canonicalize()
        .is_ok_and(|resolved| resolved.starts_with(bound))
}

fn collect_sources(package_dir: &Path, manifest: &toml::Value) -> Sources {
    let bound = source_bound(package_dir);
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
                    &bound,
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
        follow_modules(&path, &bound, 0, &mut sources.build, &mut sources.skipped);
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
/// `mod name;` (as `name.rs` or `name/mod.rs`, or a `#[path = "..."]`) and
/// the files it includes with `include!`. Files outside `bound` are never
/// read, so `..` is followed only while it stays in the workspace.
fn follow_modules(
    file: &Path,
    bound: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
    skipped: &mut usize,
) {
    if depth > MAX_DEPTH || files.iter().any(|known| known == file) || !is_within(bound, file) {
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
    for included in included_files(tokens.clone()) {
        follow_modules(&dir.join(included), bound, depth + 1, files, skipped);
    }
    for (name, explicit_path) in declared_modules(tokens) {
        let candidates = match explicit_path {
            Some(path) => vec![dir.join(path)],
            None => vec![
                module_dir.join(format!("{name}.rs")),
                module_dir.join(&name).join("mod.rs"),
            ],
        };
        if let Some(found) = candidates.into_iter().find(|path| is_regular_file(path)) {
            follow_modules(&found, bound, depth + 1, files, skipped);
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

/// `mod name;` declarations, with their `#[path = "..."]` if any.
///
/// Top-level declarations are all returned. Inside blocks (a function
/// body, as in nushell's build script) only `#[path]` modules are, since the
/// file of an unannotated nested module cannot be located reliably.
fn declared_modules(tokens: TokenStream) -> Vec<(String, Option<String>)> {
    let mut modules = Vec::new();
    collect_modules(tokens, true, &mut modules);
    modules
}

fn path_attribute(token: &TokenTree) -> Option<String> {
    let TokenTree::Group(group) = token else {
        return None;
    };
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

fn collect_modules(
    tokens: TokenStream,
    top_level: bool,
    modules: &mut Vec<(String, Option<String>)>,
) {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Group(group) if group.delimiter() == proc_macro2::Delimiter::Brace => {
                collect_modules(group.stream(), false, modules);
            }
            TokenTree::Ident(keyword) if keyword == "mod" => {
                let (Some(TokenTree::Ident(name)), Some(TokenTree::Punct(semicolon))) =
                    (tokens.get(index + 1), tokens.get(index + 2))
                else {
                    continue;
                };
                if semicolon.as_char() != ';' {
                    continue;
                }
                // Look through the attributes right before this `mod`
                // (`#[path = "..."] #[expect(dead_code)] mod args;`), and
                // only those: a `#[path]` of an earlier item does not count.
                let mut explicit_path = None;
                let mut position = index;
                while position >= 2 {
                    let is_attribute = matches!(&tokens[position - 2], TokenTree::Punct(hash) if hash.as_char() == '#')
                        && matches!(&tokens[position - 1], TokenTree::Group(group) if group.delimiter() == proc_macro2::Delimiter::Bracket);
                    if !is_attribute {
                        break;
                    }
                    if let Some(path) = path_attribute(&tokens[position - 1]) {
                        explicit_path = Some(path);
                        break;
                    }
                    position -= 2;
                }
                if top_level || explicit_path.is_some() {
                    modules.push((name.to_string(), explicit_path));
                }
            }
            _ => {}
        }
    }
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
            collect_doc_text(tokens.clone(), &mut references.doc_text, file.parent());
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
    collect_references_in(tokens, false, names);
}

/// Whether the tokens before `index` end with `::` that continues a path
/// (`a::b`, `crate::b`, `<T as X>::b`, `$crate::b`), as opposed to a
/// leading `::` (`::phf::Map`), which starts an absolute path.
fn continues_path(tokens: &[TokenTree], index: usize) -> bool {
    let is_colon = |position: usize| matches!(tokens.get(position), Some(TokenTree::Punct(p)) if p.as_char() == ':');
    if index < 2 || !is_colon(index - 1) || !is_colon(index - 2) {
        return false;
    }
    match index
        .checked_sub(3)
        .and_then(|position| tokens.get(position))
    {
        // After a keyword, `::` starts an absolute path: `impl ::serde::Serialize`.
        Some(TokenTree::Ident(ident)) => !matches!(
            ident.to_string().as_str(),
            "as" | "const"
                | "dyn"
                | "else"
                | "for"
                | "if"
                | "impl"
                | "in"
                | "let"
                | "match"
                | "mut"
                | "pub"
                | "ref"
                | "return"
                | "static"
                | "type"
                | "unsafe"
                | "use"
                | "where"
                | "while"
                | "yield"
        ),
        Some(TokenTree::Punct(p)) => p.as_char() == '>',
        Some(TokenTree::Group(_)) | Some(TokenTree::Literal(_)) | None => false,
    }
}

/// `nested` is true inside a `use` group that follows `::`
/// (`use std::{io::Read, fmt}`), where names are not crate roots.
fn collect_references_in(tokens: TokenStream, nested: bool, names: &mut BTreeSet<String>) {
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
                let use_group = group.delimiter() == proc_macro2::Delimiter::Brace
                    && index >= 1
                    && matches!(&tokens[index - 1], TokenTree::Punct(p) if p.as_char() == ':');
                collect_references_in(group.stream(), use_group, names);
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
                // Only the first segment of a path names a crate:
                // `deno_runtime::deno_node::X` uses deno_runtime, not deno_node.
                let first_segment = !nested && !continues_path(&tokens, index);
                if (followed_by_path && first_segment) || after_use || after_extern_crate {
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
fn collect_doc_text(tokens: TokenStream, out: &mut Vec<String>, dir: Option<&Path>) {
    for token in tokens {
        if let TokenTree::Group(group) = token {
            let inner: Vec<TokenTree> = group.stream().into_iter().collect();
            // `#[doc = include_str!("../docs/guide.md")]`: read the file.
            if let (
                [
                    TokenTree::Ident(ident),
                    TokenTree::Punct(eq),
                    TokenTree::Ident(macro_name),
                    TokenTree::Punct(bang),
                    TokenTree::Group(arguments),
                ],
                Some(dir),
            ) = (inner.as_slice(), dir)
            {
                if ident == "doc"
                    && eq.as_char() == '='
                    && macro_name == "include_str"
                    && bang.as_char() == '!'
                {
                    let path = arguments.stream().to_string();
                    let path = path.trim().trim_matches('"');
                    let file = dir.join(path);
                    let readable = fs::symlink_metadata(&file).is_ok_and(|metadata| {
                        metadata.is_file() && metadata.len() <= MAX_SOURCE_BYTES
                    });
                    if readable {
                        if let Ok(text) = fs::read_to_string(&file) {
                            out.push(text);
                        }
                    }
                    continue;
                }
            }
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
            collect_doc_text(group.stream(), out, dir);
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
            && (after.starts_with("::")
                || after.starts_with(';')
                || after.starts_with(' ')
                || after.starts_with('`'))
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
    /// Workspace root, for paths of dependencies inherited from it.
    pub workspace_root: &'a Path,
}

/// The `[lib] name` of a dependency, when its manifest is available locally:
/// a path dependency, or a crate unpacked in `$CARGO_HOME/registry/src`.
fn library_name(
    dependency: &DeclaredDependency,
    package: &PackageToCheck<'_>,
    inventory: &Inventory,
) -> Option<String> {
    let lib_name = |manifest: &Path| -> Option<String> {
        let metadata = fs::symlink_metadata(manifest).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_SOURCE_BYTES {
            return None;
        }
        let value: toml::Value = toml::from_str(&fs::read_to_string(manifest).ok()?).ok()?;
        value
            .get("lib")
            .and_then(|lib| lib.get("name"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
    };
    if let Some((path, from_workspace)) = &dependency.path {
        let base = if *from_workspace {
            package.workspace_root
        } else {
            package.dir
        };
        return lib_name(&base.join(path).join("Cargo.toml"));
    }
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo"))
        })?;
    let registries = fs::read_dir(cargo_home.join("registry").join("src")).ok()?;
    let registries: Vec<PathBuf> = registries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    inventory
        .packages
        .iter()
        .filter(|candidate| candidate.name == dependency.package && candidate.source.is_some())
        .find_map(|candidate| {
            registries.iter().find_map(|registry| {
                lib_name(
                    &registry
                        .join(format!("{}-{}", candidate.name, candidate.version))
                        .join("Cargo.toml"),
                )
            })
        })
}

/// Dependencies that `[features]` forward features to (`"dep/feature"`,
/// `"dep?/feature"`).
fn features_forwarded_to(manifest: &toml::Value) -> BTreeSet<&str> {
    manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|features| features.values())
        .filter_map(toml::Value::as_array)
        .flatten()
        .filter_map(toml::Value::as_str)
        .filter_map(|entry| entry.split_once('/'))
        .map(|(dependency, _)| dependency.trim_end_matches('?'))
        .collect()
}

/// Names the library of `crate_name` plausibly uses when its `[lib] name`
/// is unknown: `atuin-vt100` → `vt100`, `tui-textarea-2` → `tui_textarea`.
fn library_name_guesses(crate_name: &str) -> Vec<String> {
    let segments: Vec<&str> = crate_name
        .split(['-', '_'])
        .filter(|s| !s.is_empty())
        .collect();
    let mut guesses = Vec::new();
    for start in 0..segments.len() {
        for end in start + 1..=segments.len() {
            if start == 0 && end == segments.len() {
                continue;
            }
            if start != 0 && end != segments.len() {
                continue;
            }
            let guess = segments[start..end].join("_");
            let too_generic = matches!(
                guess.as_str(),
                "core" | "std" | "alloc" | "crate" | "self" | "super" | "rs" | "rust"
            );
            if !too_generic
                && !guess.starts_with(|c: char| c.is_ascii_digit())
                && !guesses.contains(&guess)
            {
                guesses.push(guess);
            }
        }
    }
    guesses
}

/// Finds declared dependencies with no usage in a package's sources.
///
/// `inventory` is used to recognise dependencies that are also pulled in
/// transitively, which may be declared only to select their features.
/// Crate identifiers referenced inside the `macro_rules!` bodies of a
/// package. A macro expands in the crate that calls it, so these crates may
/// be needed by the packages that use the macro.
#[must_use]
pub fn macro_references(dir: &Path, manifest: &toml::Value) -> BTreeSet<String> {
    let sources = collect_sources(dir, manifest);
    let mut names = BTreeSet::new();
    for file in &sources.code {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        if let Ok(tokens) = TokenStream::from_str(&text) {
            collect_macro_bodies(tokens, &mut names);
        }
    }
    names
}

fn collect_macro_bodies(tokens: TokenStream, names: &mut BTreeSet<String>) {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Ident(ident) if ident == "macro_rules" => {
                if let Some(TokenTree::Group(body)) = tokens.get(index + 3) {
                    collect_references(body.stream(), names);
                }
            }
            TokenTree::Group(group) => collect_macro_bodies(group.stream(), names),
            _ => {}
        }
    }
}

/// Macro references of the workspace packages, keyed by crate identifier
/// (package name with `-` read as `_`).
#[derive(Debug, Default)]
pub struct WorkspaceMacros {
    /// Crates mentioned in `macro_rules!` bodies, by providing crate.
    pub macro_rules: BTreeMap<String, BTreeSet<String>>,
    /// Crates that workspace proc-macro crates generate paths to, by
    /// proc-macro crate: paths in `quote!` and crate names in strings, as in
    /// `manifest.get_path("bevy_extract")`.
    pub proc_macros: BTreeMap<String, BTreeSet<String>>,
}

/// Whether a manifest declares a proc-macro library.
#[must_use]
pub fn is_proc_macro(manifest: &toml::Value) -> bool {
    let lib = manifest.get("lib");
    ["proc-macro", "proc_macro"].iter().any(|key| {
        lib.and_then(|lib| lib.get(*key))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
    })
}

/// Crates a proc-macro crate may generate paths to.
#[must_use]
pub fn proc_macro_generated(dir: &Path, manifest: &toml::Value) -> BTreeSet<String> {
    let sources = collect_sources(dir, manifest);
    let mut names = BTreeSet::new();
    for file in &sources.code {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        if let Ok(tokens) = TokenStream::from_str(&text) {
            collect_quoted_references(tokens.clone(), &mut names);
            let tokens: Vec<TokenTree> = tokens.into_iter().collect();
            collect_identifier_strings(&tokens, &mut names);
        }
    }
    names
}

/// References inside `quote!`, `quote_spanned!` and `parse_quote!`, which
/// is the code a proc macro emits (not the code it runs).
fn collect_quoted_references(tokens: TokenStream, names: &mut BTreeSet<String>) {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Ident(ident)
                if matches!(
                    ident.to_string().as_str(),
                    "quote" | "quote_spanned" | "parse_quote"
                ) =>
            {
                if let (Some(TokenTree::Punct(bang)), Some(TokenTree::Group(body))) =
                    (tokens.get(index + 1), tokens.get(index + 2))
                {
                    if bang.as_char() == '!' {
                        collect_references(body.stream(), names);
                    }
                }
            }
            TokenTree::Group(group) => collect_quoted_references(group.stream(), names),
            _ => {}
        }
    }
}

/// String literals that are a plain crate-like identifier (`"bevy_extract"`).
fn collect_identifier_strings(tokens: &[TokenTree], names: &mut BTreeSet<String>) {
    for token in tokens {
        match token {
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                collect_identifier_strings(&inner, names);
            }
            TokenTree::Literal(literal) => {
                let text = literal.to_string();
                if let Some(text) = text
                    .strip_prefix('"')
                    .and_then(|text| text.strip_suffix('"'))
                {
                    let plain = !text.is_empty()
                        && text
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                        && !text.starts_with(|c: char| c.is_ascii_digit());
                    if plain {
                        names.insert(text.replace('-', "_"));
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn check_package(
    package: &PackageToCheck<'_>,
    workspace_dependencies: Option<&toml::Value>,
    inventory: &Inventory,
    workspace_macros: &WorkspaceMacros,
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
        let renamed = dependency.key != dependency.package;
        let ident = if renamed {
            dependency.key.replace('-', "_")
        } else {
            library_name(&dependency, package, inventory)
                .unwrap_or_else(|| dependency.key.replace('-', "_"))
        };
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
        let declared_idents: Vec<String> =
            declared_dependencies(package.manifest, workspace_dependencies)
                .iter()
                .map(|declared| declared.key.replace('-', "_"))
                .collect();
        if !renamed && ident == dependency.key.replace('-', "_") {
            if let Some(guess) = library_name_guesses(&dependency.package)
                .into_iter()
                // A guess that is itself a declared dependency (`tokio` for
                // `tokio-test`) is explained by that dependency.
                .filter(|guess| !declared_idents.contains(guess))
                .find(|guess| references.contains(guess))
            {
                exceptions.push(format!(
                    "`{guess}::` is used: the library name of `{}` may differ from its package name",
                    dependency.package
                ));
            }
        }
        if dependency.kind != DependencyKind::Dev
            && features_forwarded_to(package.manifest).contains(dependency.key.as_str())
        {
            exceptions.push(format!(
                "named in [features] (`{}/...`): may be declared only to forward a feature",
                dependency.key
            ));
        }
        if dependency.kind != DependencyKind::Dev && references.in_docs(&ident) {
            exceptions.push(
                "mentioned in documentation (a doc link needs the crate to resolve)".to_owned(),
            );
        }
        if let Some(provider) =
            workspace_macros
                .proc_macros
                .iter()
                .find_map(|(crate_ident, names)| {
                    (crate_ident != &ident && names.contains(&ident)).then_some(crate_ident)
                })
        {
            exceptions.push(format!(
                "workspace proc-macro crate `{provider}` generates paths to it, which derives and attributes expand in this crate"
            ));
        }
        if let Some(provider) =
            workspace_macros
                .macro_rules
                .iter()
                .find_map(|(crate_ident, names)| {
                    (declared_idents.contains(crate_ident) && names.contains(&ident))
                        .then_some(crate_ident)
                })
        {
            exceptions.push(format!(
                "may be used through a macro of workspace crate `{provider}`, which mentions it"
            ));
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
        if sources.skipped > 0 {
            exceptions.push(format!(
                "{} source file(s) were skipped (size, depth or count limit) and not searched",
                sources.skipped
            ));
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
    fn only_the_first_path_segment_names_a_crate() {
        let names = references(
            r#"
            use std::{io::Read, fmt};
            pub type R = deno_runtime::deno_node::NodeResolver;
            static M: ::phf::Map<u8, u8> = todo!();
            fn f() { let _ = <T as regex::Pattern>::bytes::Regex::new(); }
            fn g() { quote! { #server_fn_path::const_format::concatcp!() } }
            fn h() { $crate::log::info!(); serde_json::json!({}); }
            impl ::serde::Serialize for X {}
            fn k() -> impl ::futures::Future { todo!() }
            "#,
        );
        for expected in [
            "std",
            "deno_runtime",
            "phf",
            "regex",
            "server_fn_path",
            "serde_json",
            "serde",
            "futures",
        ] {
            assert!(names.contains(expected), "missing {expected}");
        }
        for unexpected in ["io", "deno_node", "bytes", "const_format", "log"] {
            assert!(
                !names.contains(unexpected),
                "{unexpected} is not a crate root"
            );
        }
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
        super::collect_doc_text(tokens, &mut docs, None);
        let joined = docs.join("\n");
        assert!(text_mentions(&joined, "async_stream"));
        assert!(text_mentions(
            "- [`mdbook_markdown`]: the renderer",
            "mdbook_markdown"
        ));
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
        let bound = root.canonicalize().expect("root");
        super::follow_modules(
            &root.join("core/main.rs"),
            &bound,
            0,
            &mut files,
            &mut skipped,
        );
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
        let bound = root.canonicalize().expect("root");
        super::follow_modules(&root.join("build.rs"), &bound, 0, &mut files, &mut skipped);
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
    fn guesses_library_names_from_package_names() {
        assert_eq!(
            super::library_name_guesses("atuin-vt100"),
            vec!["atuin", "vt100"]
        );
        assert_eq!(
            super::library_name_guesses("tui-textarea-2"),
            vec!["tui", "tui_textarea", "textarea_2"]
        );
        assert_eq!(super::library_name_guesses("tracing-core"), vec!["tracing"]);
        assert!(super::library_name_guesses("serde").is_empty());
    }

    #[test]
    fn reads_markdown_included_as_documentation() {
        let root = std::env::temp_dir().join(format!("cargoscope-docmd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src/handler")).expect("dirs");
        std::fs::create_dir_all(root.join("src/docs")).expect("dirs");
        std::fs::write(
            root.join("src/docs/errors.md"),
            "```rust\nfn f() -> Result<(), anyhow::Error> { Ok(()) }\n```\n",
        )
        .expect("write");
        let file = root.join("src/handler/mod.rs");
        std::fs::write(&file, "#![doc = include_str!(\"../docs/errors.md\")]\n").expect("write");
        let references = super::scan_files(&[file]);
        assert!(references.in_docs("anyhow"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn finds_dependencies_that_features_forward_to() {
        let manifest: toml::Value = toml::from_str(
            r#"
            [features]
            search = ["mdbook-html/search"]
            tls = ["reqwest?/rustls-tls", "dep:openssl", "local"]
            "#,
        )
        .expect("valid");
        let forwarded: Vec<&str> = super::features_forwarded_to(&manifest)
            .into_iter()
            .collect();
        assert_eq!(forwarded, vec!["mdbook-html", "reqwest"]);
    }

    #[test]
    fn skipped_large_files_lower_confidence() {
        let root = std::env::temp_dir().join(format!("cargoscope-big-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("dirs");
        std::fs::write(root.join("src/lib.rs"), "mod generated;\n").expect("write");
        let big = format!(
            "pub static M: ::phf::Map<u8, u8> = todo!();\n{}",
            "//\n".repeat(1_100_000)
        );
        std::fs::write(root.join("src/generated.rs"), big).expect("write");
        let manifest: toml::Value =
            toml::from_str("[package]\nname = \"big\"\n[dependencies]\nphf = \"0.11\"\n")
                .expect("valid");
        let (findings, warnings) = super::check_package(
            &super::PackageToCheck {
                name: "big",
                dir: &root,
                manifest_label: "Cargo.toml",
                manifest: &manifest,
                workspace_root: &root,
            },
            None,
            &cargoscope_core::Inventory {
                packages: Vec::new(),
            },
            &super::WorkspaceMacros::default(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].confidence,
            cargoscope_core::UnusedConfidence::Possibly
        );
        assert!(warnings.iter().any(|warning| warning.contains("skipped")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn finds_path_modules_declared_inside_functions() {
        let tokens = TokenStream::from_str(
            "mod top;\nfn build() {\n    #[path = \"src/theme.rs\"]\n    mod theme;\n    mod unknown;\n}\n#[inline]\nmod plain;\n#[path = \"src/args.rs\"]\n#[expect(dead_code)]\nmod args;\n#[path = \"x.rs\"]\nfn f() {}\nmod after_fn;\n",
        )
        .expect("tokenizes");
        assert_eq!(
            super::declared_modules(tokens),
            vec![
                ("top".to_owned(), None),
                ("theme".to_owned(), Some("src/theme.rs".to_owned())),
                ("plain".to_owned(), None),
                ("args".to_owned(), Some("src/args.rs".to_owned())),
                ("after_fn".to_owned(), None),
            ]
        );
    }

    #[test]
    fn proc_macro_generated_paths_come_from_quote_and_crate_name_strings() {
        let root = std::env::temp_dir().join(format!("cargoscope-pm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("dirs");
        std::fs::write(
            root.join("src/lib.rs"),
            r#"
            use syn::DeriveInput;
            fn path() -> syn::Path { manifest.get_path("bevy_extract") }
            fn emit() { quote! { impl ::bevy_ecs::Resource for X {} } }
            "#,
        )
        .expect("write");
        let manifest: toml::Value =
            toml::from_str("[package]\nname = \"m\"\n[lib]\nproc-macro = true\n").expect("valid");
        assert!(super::is_proc_macro(&manifest));
        let names = super::proc_macro_generated(&root, &manifest);
        assert!(names.contains("bevy_extract"));
        assert!(names.contains("bevy_ecs"));
        assert!(
            !names.contains("syn"),
            "the macro's own dependencies are not generated"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn follows_parent_paths_inside_the_workspace_only() {
        let base = std::env::temp_dir().join(format!("cargoscope-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("repo");
        std::fs::create_dir_all(root.join("tests/no-std")).expect("dirs");
        std::fs::create_dir_all(root.join("tests/include")).expect("dirs");
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"tests/no-std\"]\n",
        )
        .expect("write");
        std::fs::write(
            root.join("tests/no-std/Cargo.toml"),
            "[package]\nname = \"no-std\"\n",
        )
        .expect("write");
        std::fs::write(
            root.join("tests/no-std/lib.rs"),
            "include!(\"../include/basic.rs\");\ninclude!(\"../../../secret.rs\");\n#[path = \"/etc/hosts.rs\"]\nmod abs;\n",
        )
        .expect("write");
        std::fs::write(
            root.join("tests/include/basic.rs"),
            "use pin_project_lite::pin_project;\n",
        )
        .expect("write");
        std::fs::write(base.join("secret.rs"), "use leaked::Thing;\n").expect("write");

        let bound = super::source_bound(&root.join("tests/no-std"));
        assert_eq!(bound, root.canonicalize().expect("root"));
        let mut files = Vec::new();
        let mut skipped = 0;
        super::follow_modules(
            &root.join("tests/no-std/lib.rs"),
            &bound,
            0,
            &mut files,
            &mut skipped,
        );
        let names: Vec<String> = files
            .iter()
            .map(|file| {
                file.file_name()
                    .expect("name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(
            names,
            vec!["lib.rs", "basic.rs"],
            "secret.rs is outside the workspace"
        );
        let _ = std::fs::remove_dir_all(&base);
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
