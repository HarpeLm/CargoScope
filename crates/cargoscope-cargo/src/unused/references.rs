//! What the files of a package reference: paths, `use` and `extern crate`,
//! attributes and path strings, documentation, and code generated in
//! `OUT_DIR`.

use super::*;

/// Crate identifiers referenced by a set of files.
#[derive(Debug, Default)]
pub(super) struct References {
    pub(super) names: BTreeSet<String>,
    /// Text of doc comments (`///`, `//!`), where doctests use dev-dependencies.
    pub(super) doc_text: Vec<String>,
    /// Some file includes code generated in `OUT_DIR` (`include!(...OUT_DIR...)`).
    pub(super) includes_generated_code: bool,
    /// Files that could not be tokenized and were searched as plain text.
    pub(super) text_fallback: Vec<PathBuf>,
    /// Raw contents of those files, searched as plain text.
    pub(super) raw_text: Vec<String>,
}

impl References {
    pub(super) fn in_docs(&self, ident: &str) -> bool {
        self.doc_text.iter().any(|text| doc_mentions(text, ident))
    }

    pub(super) fn contains(&self, ident: &str) -> bool {
        self.names.contains(ident) || self.raw_text.iter().any(|text| text_mentions(text, ident))
    }
}

pub(super) fn scan_files(files: &[PathBuf]) -> References {
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
pub(super) fn collect_references(tokens: TokenStream, names: &mut BTreeSet<String>) {
    collect_references_in(tokens, false, names);
}

/// Whether the tokens before `index` end with `::` that continues a path
/// (`a::b`, `crate::b`, `<T as X>::b`, `$crate::b`), as opposed to a
/// leading `::` (`::phf::Map`), which starts an absolute path.
pub(super) fn continues_path(tokens: &[TokenTree], index: usize) -> bool {
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
        // `<T as X>::b` continues a path; `=> ::b` and `-> ::b` (a match arm,
        // a return type) start one.
        Some(TokenTree::Punct(p)) => {
            p.as_char() == '>'
                && !index.checked_sub(4).and_then(|position| tokens.get(position)).is_some_and(
                    |token| matches!(token, TokenTree::Punct(q) if q.as_char() == '=' || q.as_char() == '-'),
                )
        }
        Some(TokenTree::Group(_)) | Some(TokenTree::Literal(_)) | None => false,
    }
}

/// `nested` is true inside a `use` group that follows `::`
/// (`use std::{io::Read, fmt}`), where names are not crate roots.
pub(super) fn collect_references_in(
    tokens: TokenStream,
    nested: bool,
    names: &mut BTreeSet<String>,
) {
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
pub(super) fn collect_attribute_references(tokens: TokenStream, names: &mut BTreeSet<String>) {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    if let Some(TokenTree::Ident(head)) = tokens.first() {
        let head_name = head.to_string();
        if head_name == "doc" {
            return;
        }
        let builtin_attribute = matches!(
            head_name.as_str(),
            "cfg"
                | "cfg_attr"
                | "derive"
                | "test"
                | "bench"
                | "allow"
                | "warn"
                | "deny"
                | "forbid"
                | "expect"
                | "inline"
                | "cold"
                | "repr"
                | "must_use"
                | "non_exhaustive"
                | "track_caller"
                | "no_mangle"
                | "export_name"
                | "link"
                | "link_name"
                | "link_section"
                | "used"
                | "global_allocator"
                | "panic_handler"
                | "feature"
                | "macro_export"
                | "macro_use"
                | "path"
                | "ignore"
                | "should_panic"
                | "automatically_derived"
                | "no_std"
                | "no_main"
                | "recursion_limit"
                | "type_length_limit"
                | "windows_subsystem"
                | "crate_name"
                | "crate_type"
        );
        if !builtin_attribute && matches!(tokens.get(1), Some(TokenTree::Group(_)) | None) {
            names.insert(head_name);
        }
    }
    collect_path_literals(&tokens, names);
}

pub(super) fn collect_path_literals(tokens: &[TokenTree], names: &mut BTreeSet<String>) {
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
pub(super) fn collect_doc_text(tokens: TokenStream, out: &mut Vec<String>, dir: Option<&Path>) {
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
                && ident == "doc"
                && eq.as_char() == '='
                && macro_name == "include_str"
                && bang.as_char() == '!'
            {
                let path = arguments.stream().to_string();
                let path = path.trim().trim_matches('"');
                let file = dir.join(path);
                let readable = fs::symlink_metadata(&file)
                    .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= MAX_SOURCE_BYTES);
                if readable && let Ok(text) = fs::read_to_string(&file) {
                    out.push(text);
                }
                continue;
            }
            if let [
                TokenTree::Ident(ident),
                TokenTree::Punct(eq),
                TokenTree::Literal(text),
            ] = inner.as_slice()
                && ident == "doc"
                && eq.as_char() == '='
            {
                out.push(text.to_string());
                continue;
            }
            collect_doc_text(group.stream(), out, dir);
        }
    }
}

/// Detects `include!(...)` invocations whose arguments mention `OUT_DIR`.
pub(super) fn includes_generated_code(tokens: TokenStream) -> bool {
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
pub(super) fn text_mentions(text: &str, ident: &str) -> bool {
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

/// Whether documentation text refers to the crate `ident` the way code or a
/// doc link does: a path (`ident::Item`), `use ident` or `extern crate
/// ident`, or the bare name as code or a link (`` `ident` ``, `[ident]`).
/// Prose (`which` in a sentence) and file names (`Cargo.toml`) do not count.
pub(super) fn doc_mentions(text: &str, ident: &str) -> bool {
    text.match_indices(ident).any(|(position, _)| {
        let before = text[..position].chars().next_back();
        let after = &text[position + ident.len()..];
        let word_start =
            before.is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '_' | '.' | '/' | '-')));
        let word_end = after
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '_' | '.' | '-')));
        if !word_start {
            return false;
        }
        if after.starts_with("::") {
            return true;
        }
        if !word_end {
            return false;
        }
        let head = text[..position].trim_end();
        let code_or_link =
            matches!(before, Some('`' | '[')) && matches!(after.chars().next(), Some('`' | ']'));
        code_or_link
            || head.ends_with(" use")
            || head == "use"
            || head.ends_with("\nuse")
            || head.ends_with("extern crate")
    })
}
