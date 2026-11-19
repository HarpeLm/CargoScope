//! How much `unsafe` code each dependency contains, counted offline from the
//! sources Cargo already downloaded: `unsafe` blocks, functions, impls and
//! traits, read with a Rust lexer so comments and strings never count.

use std::fs;
use std::path::{Path, PathBuf};

use cargoscope_core::{Inventory, UnsafeCount};
use proc_macro2::{Delimiter, TokenStream, TokenTree};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FILES: usize = 5_000;
const MAX_DEPTH: usize = 16;

/// Version of the cached count format.
const CACHE_FORMAT: &str = "v1";

/// `unsafe` counts of every package of `inventory`, by package index: `None`
/// for workspace members and packages whose sources are not on disk.
///
/// Registry packages never change once published, so their counts are kept
/// in `cache_dir` (when given) and read back on later scans. Packages are
/// counted on several threads.
#[must_use]
pub fn count_unsafe(
    project_root: &Path,
    inventory: &Inventory,
    cache_dir: Option<&Path>,
) -> Vec<Option<UnsafeCount>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, PoisonError};

    let dirs = crate::crate_sources::resolve_package_dirs(project_root, inventory);
    let cache = cache_dir.map(|dir| dir.join("unsafe"));
    let jobs: Vec<(usize, PathBuf, Option<PathBuf>)> = inventory
        .packages
        .iter()
        .zip(dirs)
        .enumerate()
        .filter_map(|(index, (package, dir))| {
            let source = package.source.as_deref()?;
            let cached = (source.starts_with("registry+") || source.starts_with("sparse+"))
                .then(|| {
                    cache
                        .as_ref()
                        .map(|cache| cache.join(format!("{}-{}", package.name, package.version)))
                })
                .flatten()
                .filter(|_| is_safe(&package.name) && is_safe(&package.version));
            Some((index, dir?, cached))
        })
        .collect();

    let results = Mutex::new(vec![None; inventory.packages.len()]);
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism()
        .map_or(4, usize::from)
        .min(16);
    std::thread::scope(|scope| {
        for _ in 0..threads.min(jobs.len()) {
            scope.spawn(|| {
                while let Some((index, dir, cached)) =
                    jobs.get(next.fetch_add(1, Ordering::Relaxed))
                {
                    let count = cached.as_deref().and_then(read_cached).unwrap_or_else(|| {
                        let count = count_package(dir);
                        if let Some(cached) = cached {
                            write_cached(cached, &count);
                        }
                        count
                    });
                    results.lock().unwrap_or_else(PoisonError::into_inner)[*index] = Some(count);
                }
            });
        }
    });
    results.into_inner().unwrap_or_else(PoisonError::into_inner)
}

fn is_safe(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with('.')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
}

fn read_cached(path: &Path) -> Option<UnsafeCount> {
    let text = fs::read_to_string(path).ok()?;
    let mut fields = text.split_whitespace();
    if fields.next()? != CACHE_FORMAT {
        return None;
    }
    let mut number = || fields.next()?.parse::<usize>().ok();
    Some(UnsafeCount {
        blocks: number()?,
        functions: number()?,
        impls: number()?,
        traits: number()?,
        other: number()?,
        unreadable_files: number()?,
    })
}

fn write_cached(path: &Path, count: &UnsafeCount) {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::write(
        path,
        format!(
            "{CACHE_FORMAT} {} {} {} {} {} {}\n",
            count.blocks,
            count.functions,
            count.impls,
            count.traits,
            count.other,
            count.unreadable_files
        ),
    );
}

/// Counts the `unsafe` code of the package in `dir`: the `.rs` files under
/// `src/` and the build script, without following symbolic links.
#[must_use]
pub fn count_package(dir: &Path) -> UnsafeCount {
    let mut files = Vec::new();
    collect_rs_files(&dir.join("src"), 0, &mut files);
    let build = dir.join("build.rs");
    if fs::symlink_metadata(&build).is_ok_and(|meta| meta.is_file()) {
        files.push(build);
    }
    let mut count = UnsafeCount::default();
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        let Ok(tokens) = text.parse::<TokenStream>() else {
            count.unreadable_files += 1;
            continue;
        };
        count_tokens(tokens, &mut count);
    }
    count
}

fn collect_rs_files(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH || files.len() >= MAX_FILES {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(fs::DirEntry::path);
    for entry in entries {
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let path = entry.path();
        if meta.is_dir() {
            collect_rs_files(&path, depth + 1, files);
        } else if meta.is_file()
            && meta.len() <= MAX_FILE_BYTES
            && path.extension().is_some_and(|ext| ext == "rs")
            && files.len() < MAX_FILES
        {
            files.push(path);
        }
    }
}

fn count_tokens(tokens: TokenStream, count: &mut UnsafeCount) {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    for (at, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Group(group) => count_tokens(group.stream(), count),
            TokenTree::Ident(ident) if ident == "unsafe" => {
                // What follows `unsafe`, skipping `extern "C"` and the like.
                let mut next = at + 1;
                if matches!(tokens.get(next), Some(TokenTree::Ident(ident)) if ident == "extern") {
                    next += 1;
                    if matches!(tokens.get(next), Some(TokenTree::Literal(_))) {
                        next += 1;
                    }
                }
                match tokens.get(next) {
                    Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => {
                        if next == at + 1 {
                            count.blocks += 1;
                        } else {
                            // `unsafe extern "C" { … }`: foreign declarations.
                            count.functions += 1;
                        }
                    }
                    Some(TokenTree::Ident(ident)) if ident == "fn" => count.functions += 1,
                    Some(TokenTree::Ident(ident)) if ident == "impl" => count.impls += 1,
                    Some(TokenTree::Ident(ident)) if ident == "trait" || ident == "auto" => {
                        count.traits += 1;
                    }
                    // `unsafe` inside a macro or attribute (`#[unsafe(no_mangle)]`).
                    _ => count.other += 1,
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::count_tokens;
    use cargoscope_core::UnsafeCount;

    fn count(source: &str) -> UnsafeCount {
        let mut count = UnsafeCount::default();
        count_tokens(source.parse().expect("valid Rust tokens"), &mut count);
        count
    }

    #[test]
    fn counts_blocks_functions_impls_and_traits() {
        let found = count(
            r#"
            // unsafe in a comment does not count
            const TEXT: &str = "unsafe { not code }";
            unsafe fn raw() {}
            pub(crate) unsafe fn other() {}
            const unsafe fn constant() {}
            unsafe impl Send for Thing {}
            unsafe trait Marker {}
            unsafe extern "C" { fn puts(s: *const u8) -> i32; }
            fn safe() {
                let x = unsafe { raw() };
                let y = || unsafe { other() };
            }
            #[unsafe(no_mangle)]
            pub extern "C" fn exported() {}
            "#,
        );
        assert_eq!(found.blocks, 2);
        assert_eq!(found.functions, 4);
        assert_eq!(found.impls, 1);
        assert_eq!(found.traits, 1);
        assert_eq!(found.other, 1);
        assert_eq!(found.total(), 9);
    }

    #[test]
    fn safe_code_counts_nothing() {
        assert_eq!(count("fn main() { println!(\"safe\"); }").total(), 0);
    }
}
