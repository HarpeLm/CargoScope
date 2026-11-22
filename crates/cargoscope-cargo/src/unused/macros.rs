//! Crates the workspace's own macros expand to: exported `macro_rules!` bodies
//! and the paths proc-macro crates generate.

use super::*;

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

/// Whether the item starting at `index` has `#[macro_export]` among its
/// attributes (also inside `#[cfg_attr(..., macro_export)]`).
pub(super) fn has_macro_export(tokens: &[TokenTree], index: usize) -> bool {
    let mut end = index;
    while end >= 2 {
        let (TokenTree::Punct(hash), TokenTree::Group(attribute)) =
            (&tokens[end - 2], &tokens[end - 1])
        else {
            return false;
        };
        if hash.as_char() != '#' || attribute.delimiter() != proc_macro2::Delimiter::Bracket {
            return false;
        }
        let mentions = |stream: TokenStream| -> bool {
            fn walk(stream: TokenStream) -> bool {
                stream.into_iter().any(|tree| match tree {
                    TokenTree::Ident(ident) => ident == "macro_export",
                    TokenTree::Group(group) => walk(group.stream()),
                    _ => false,
                })
            }
            walk(stream)
        };
        if mentions(attribute.stream()) {
            return true;
        }
        end -= 2;
    }
    false
}

/// Crates named in the bodies of the exported `macro_rules!` of a token
/// stream: a macro without `#[macro_export]` cannot be called from another
/// crate, so what it names never needs to be a dependency of its callers.
pub(super) fn collect_macro_bodies(tokens: TokenStream, names: &mut BTreeSet<String>) {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Ident(ident) if ident == "macro_rules" => {
                if has_macro_export(&tokens, index)
                    && let Some(TokenTree::Group(body)) = tokens.get(index + 3)
                {
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
    /// Crates that external (registry/git) proc-macro crates in `Cargo.lock`
    /// emit in `quote!` / `quote_spanned!` / `parse_quote!`, by proc-macro
    /// crate identifier.
    pub external_proc_macros: BTreeMap<String, BTreeSet<String>>,
    /// Crates that external build-dependencies unpacked on disk emit paths to
    /// (by package name), used to avoid treating build-only helpers such as
    /// `syn`/`tempfile`/`regex` as runtime generated-code targets.
    pub build_dep_emitted: BTreeMap<String, BTreeSet<String>>,
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

/// Crates a proc-macro crate may generate paths to (`quote!` paths plus
/// identifier-like string literals, for workspace proc-macros).
#[must_use]
pub fn proc_macro_generated(dir: &Path, manifest: &toml::Value) -> BTreeSet<String> {
    collect_proc_macro_paths(dir, manifest, true)
}

/// Crates an external proc-macro crate emits in `quote!` / `quote_spanned!`
/// / `parse_quote!`.
#[must_use]
pub fn proc_macro_quoted(dir: &Path, manifest: &toml::Value) -> BTreeSet<String> {
    collect_proc_macro_paths(dir, manifest, false)
}

/// Crate identifiers that a build-dependency (`prost-build`, `cxx-build`, ...)
/// emits in generated Rust code (`quote!` paths and `"crate::..."` string
/// literals across its source files).
#[must_use]
pub fn build_dep_emitted(dir: &Path, manifest: &toml::Value) -> BTreeSet<String> {
    let sources = collect_sources(dir, manifest);
    let mut names = BTreeSet::new();
    for file in &sources.code {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        if let Ok(tokens) = TokenStream::from_str(&text) {
            collect_quoted_references(tokens.clone(), &mut names);
            let tokens: Vec<TokenTree> = tokens.into_iter().collect();
            super::references::collect_path_literals(&tokens, &mut names);
        } else {
            for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                if text.contains(&format!("{word}::")) && !word.is_empty() {
                    names.insert(word.to_owned());
                }
            }
        }
    }
    names
}

fn collect_proc_macro_paths(
    dir: &Path,
    manifest: &toml::Value,
    include_strings: bool,
) -> BTreeSet<String> {
    let sources = collect_sources(dir, manifest);
    let mut names = BTreeSet::new();
    for file in &sources.code {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        if let Ok(tokens) = TokenStream::from_str(&text) {
            collect_quoted_references(tokens.clone(), &mut names);
            if include_strings {
                let tokens: Vec<TokenTree> = tokens.into_iter().collect();
                collect_identifier_strings(&tokens, &mut names);
            }
        }
    }
    names
}

/// References inside `quote!`, `quote_spanned!` and `parse_quote!`, which
/// is the code a proc macro emits (not the code it runs).
pub(super) fn collect_quoted_references(tokens: TokenStream, names: &mut BTreeSet<String>) {
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
                    && bang.as_char() == '!'
                {
                    collect_references(body.stream(), names);
                }
            }
            TokenTree::Group(group) => collect_quoted_references(group.stream(), names),
            _ => {}
        }
    }
}

/// String literals that are a plain crate-like identifier (`"bevy_extract"`).
pub(super) fn collect_identifier_strings(tokens: &[TokenTree], names: &mut BTreeSet<String>) {
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
