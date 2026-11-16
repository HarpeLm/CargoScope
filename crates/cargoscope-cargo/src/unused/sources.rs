//! Which files a package's code is read from: the target directories, targets
//! with custom paths, `#[path]` modules and `include!`, symbolic links that stay
//! inside the workspace, and the build script; with size, depth and count limits.

use super::*;

pub(super) const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
pub(super) const MAX_DEPTH: usize = 32;
pub(super) const MAX_FILES: usize = 20_000;

/// Directories searched for sources, relative to a package manifest.
pub(super) const SOURCE_DIRS: [&str; 4] = ["src", "tests", "benches", "examples"];

/// Where a package's code lives.
#[derive(Debug, Default)]
pub(super) struct Sources {
    /// Files of the library, binaries, tests, benches and examples.
    pub(super) code: Vec<PathBuf>,
    /// Build script files.
    pub(super) build: Vec<PathBuf>,
    /// The package has a build script (which may generate included code).
    pub(super) has_build_script: bool,
    /// The directory is a package downloaded from a registry (`Cargo.toml.orig`).
    pub(super) published_copy: bool,
    /// At least one file was found in tests/, benches/ or examples/.
    pub(super) has_test_files: bool,
    /// The package is inside a git checkout (a `.git` entry in it or an
    /// ancestor), so its test files are not missing.
    pub(super) git_checkout: bool,
    /// Files skipped because of size, depth or count limits.
    pub(super) skipped: usize,
}

/// The directory that `include!`, `#[path]` and target paths may reach: the
/// workspace root (the nearest ancestor whose `Cargo.toml` has a
/// `[workspace]` table), or the package itself outside a workspace.
pub(super) fn source_bound(package_dir: &Path) -> PathBuf {
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

/// Whether `package_dir` or one of its ancestors holds a `.git` directory or
/// file (a worktree or submodule).
pub(super) fn in_git_checkout(package_dir: &Path) -> bool {
    let start = package_dir
        .canonicalize()
        .unwrap_or_else(|_| package_dir.to_path_buf());
    start
        .ancestors()
        .any(|dir| fs::symlink_metadata(dir.join(".git")).is_ok())
}

/// Whether `path` resolves to a location inside `bound` (no escape through
/// `..`, an absolute path or a symbolic link).
pub(super) fn is_within(bound: &Path, path: &Path) -> bool {
    path.canonicalize()
        .is_ok_and(|resolved| resolved.starts_with(bound))
}

pub(super) fn collect_sources(package_dir: &Path, manifest: &toml::Value) -> Sources {
    let bound = source_bound(package_dir);
    let mut sources = Sources {
        published_copy: is_regular_file(&package_dir.join("Cargo.toml.orig")),
        git_checkout: in_git_checkout(package_dir),
        ..Sources::default()
    };
    for dir in SOURCE_DIRS {
        let before = sources.code.len();
        walk(
            &package_dir.join(dir),
            &bound,
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
            walk(dir, &bound, 0, &mut sources.build, &mut sources.skipped);
        }
    }

    sources.code.sort();
    sources.code.dedup();
    sources.build.sort();
    sources.build.dedup();
    sources
}

pub(super) fn is_regular_file(path: &Path) -> bool {
    // Symbolic links are never followed.
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
}

/// The metadata of `path` as Cargo reads it: a symbolic link is followed
/// when it resolves to a file inside `bound` (the workspace), as with
/// `src/bin/cli.rs -> ../../shared/cli.rs`; links that leave the workspace
/// are never followed.
pub(super) fn source_metadata(path: &Path, bound: &Path) -> Option<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_symlink() {
        return Some(metadata);
    }
    if !is_within(bound, path) {
        return None;
    }
    fs::metadata(path).ok().filter(fs::Metadata::is_file)
}

pub(super) fn is_source_file(path: &Path, bound: &Path) -> bool {
    source_metadata(path, bound).is_some_and(|metadata| metadata.is_file())
}

pub(super) fn add_file(path: &Path, bound: &Path, files: &mut Vec<PathBuf>, skipped: &mut usize) {
    let Some(metadata) = source_metadata(path, bound) else {
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
pub(super) fn follow_modules(
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
    add_file(file, bound, files, skipped);
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
        if let Some(found) = candidates
            .into_iter()
            .find(|path| is_source_file(path, bound))
        {
            follow_modules(&found, bound, depth + 1, files, skipped);
        }
    }
}

/// Paths given to `include!("...")` with a plain string literal.
pub(super) fn included_files(tokens: TokenStream) -> Vec<String> {
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
pub(super) fn declared_modules(tokens: TokenStream) -> Vec<(String, Option<String>)> {
    let mut modules = Vec::new();
    collect_modules(tokens, true, &mut modules);
    modules
}

pub(super) fn path_attribute(token: &TokenTree) -> Option<String> {
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

pub(super) fn collect_modules(
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
                    let module_name = name.to_string();
                    let module_name = module_name
                        .strip_prefix("r#")
                        .unwrap_or(&module_name)
                        .to_owned();
                    modules.push((module_name, explicit_path));
                }
            }
            _ => {}
        }
    }
}

pub(super) fn walk(
    dir: &Path,
    bound: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
    skipped: &mut usize,
) {
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
            walk(&path, bound, depth + 1, files, skipped);
        } else {
            add_file(&path, bound, files, skipped);
        }
    }
}
