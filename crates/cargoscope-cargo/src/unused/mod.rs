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

mod macros;
mod references;
mod rules;
mod sources;

#[cfg(test)]
use self::macros::*;
pub use self::macros::{WorkspaceMacros, is_proc_macro, macro_references, proc_macro_generated};
use self::references::*;
use self::rules::*;
use self::sources::*;

/// Collects identifier tokens across all `.rs` source and build-script files
/// discovered for a package.
pub(crate) fn collect_package_idents(
    package_dir: &Path,
    manifest: &toml::Value,
    out: &mut BTreeSet<String>,
) {
    let sources = collect_sources(package_dir, manifest);
    scan_idents(&sources.code, out);
    scan_idents(&sources.build, out);
}

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
    /// Declared with features that can change the crate for its other
    /// users (anything but `derive`, which only adds macros); turning
    /// default features off never does, since features only add up.
    pub sets_features: bool,
    /// Declared with a feature meant for tests (`test-support`,
    /// `test-util`, `testing`, `mock`, `fixtures`...): a dev-dependency on a
    /// workspace crate may exist only to turn it on for the package's tests.
    pub test_features: bool,
    /// `path = "..."` of a local dependency, and whether it is relative to
    /// the workspace root (inherited with `workspace = true`) rather than to
    /// the package.
    pub path: Option<(String, bool)>,
}

/// Whether a declaration enables features that may matter to the other
/// crates using the dependency (feature unification): its own `features`
/// and those of the `[workspace.dependencies]` entry it inherits, except
/// `derive`, which only re-exports derive macros.
fn selects_features(specification: &toml::Value, from_workspace: Option<&toml::Value>) -> bool {
    [Some(specification), from_workspace]
        .into_iter()
        .flatten()
        .filter_map(|spec| spec.get("features").and_then(toml::Value::as_array))
        .flatten()
        .filter_map(toml::Value::as_str)
        .any(|feature| feature != "derive")
}

/// Whether a declaration enables a feature meant for tests, by its name.
fn enables_test_features(
    specification: &toml::Value,
    from_workspace: Option<&toml::Value>,
) -> bool {
    [Some(specification), from_workspace]
        .into_iter()
        .flatten()
        .filter_map(|spec| spec.get("features").and_then(toml::Value::as_array))
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(str::to_ascii_lowercase)
        .any(|feature| {
            feature.contains("test") || feature.contains("mock") || feature.contains("fixture")
        })
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
                        sets_features: selects_features(specification, from_workspace),
                        test_features: enables_test_features(specification, from_workspace),
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

/// The library name of a dependency, when its manifest is available locally
/// (a path dependency, or a crate unpacked in `$CARGO_HOME/registry/src`):
/// its `[lib] name`, or else its package name with `-` read as `_`.
/// `None` when the manifest is not available.
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
        let explicit = value
            .get("lib")
            .and_then(|lib| lib.get("name"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned);
        let package_name = value
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)?;
        Some(explicit.unwrap_or_else(|| package_name.replace('-', "_")))
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

/// Optional dependencies referenced only via `"dep:<key>"` in `[features]`
/// (never as a feature key, bare `"<key>"`, `"<key>/..."`, or `"<key>?/..."`).
fn dep_only_features(manifest: &toml::Value) -> BTreeSet<&str> {
    let Some(features) = manifest.get("features").and_then(toml::Value::as_table) else {
        return BTreeSet::new();
    };
    let mut has_dep = BTreeSet::new();
    let mut blocked = BTreeSet::new();
    for (feature_name, value) in features {
        blocked.insert(feature_name.as_str());
        let Some(array) = value.as_array() else {
            continue;
        };
        for entry in array.iter().filter_map(toml::Value::as_str) {
            if let Some(key) = entry.strip_prefix("dep:") {
                has_dep.insert(key);
            } else if let Some((dependency, _)) = entry.split_once('/') {
                blocked.insert(dependency.trim_end_matches('?'));
            } else {
                blocked.insert(entry);
            }
        }
    }
    has_dep.difference(&blocked).copied().collect()
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
                "core"
                    | "std"
                    | "alloc"
                    | "proc_macro"
                    | "crate"
                    | "self"
                    | "super"
                    | "rs"
                    | "rust"
                    | "impl"
                    | "assert"
                    | "derive"
                    | "macro"
                    | "macros"
                    | "test"
                    | "tests"
                    | "bench"
                    | "benches"
                    | "cfg"
                    | "ext"
                    | "util"
                    | "utils"
                    | "common"
                    | "types"
                    | "internal"
                    | "internals"
                    | "sys"
                    | "ffi"
                    | "build"
                    | "cli"
                    | "bin"
                    | "lib"
                    | "dev"
                    | "async"
                    | "sync"
                    | "error"
                    | "errors"
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

/// Walks dependencies of `package_name` in `inventory` at depth 2 or more.
/// When `only_external_sources` is true, only collects dependencies declared by
/// external packages (`!root`) because workspace packages' `Cargo.lock` entries
/// also include their `dev-dependencies`.
fn collect_dependencies_of<'a>(
    inventory: &'a Inventory,
    package_name: &str,
    only_external_sources: bool,
) -> BTreeSet<&'a str> {
    let roots: Vec<usize> = inventory
        .packages
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.source.is_none() && candidate.name == package_name)
        .map(|(index, _)| index)
        .collect();
    if roots.is_empty() {
        return inventory
            .packages
            .iter()
            .filter(|candidate| !candidate.root)
            .flat_map(|candidate| candidate.dependencies.iter())
            .map(|&index| inventory.packages[index].name.as_str())
            .collect();
    }
    let mut stack: Vec<usize> = roots
        .iter()
        .flat_map(|&root| inventory.packages[root].dependencies.iter().copied())
        .collect();
    let mut visited = BTreeSet::new();
    let mut collected = BTreeSet::new();
    while let Some(index) = stack.pop() {
        if !visited.insert(index) {
            continue;
        }
        let include = !only_external_sources || !inventory.packages[index].root;
        for &dep in &inventory.packages[index].dependencies {
            if include {
                collected.insert(inventory.packages[dep].name.as_str());
            }
            stack.push(dep);
        }
    }
    collected
}

/// External transitive dependencies of `package_name` (depth 2 or more,
/// collecting only from external packages so workspace dev-dependencies do not leak in).
fn transitive_dependencies_of<'a>(
    inventory: &'a Inventory,
    package_name: &str,
) -> BTreeSet<&'a str> {
    collect_dependencies_of(inventory, package_name, true)
}

/// All packages reachable at depth 2 or more from `package_name`, including
/// workspace proc-macro crates re-exported through sibling packages.
fn reachable_dependencies_of<'a>(
    inventory: &'a Inventory,
    package_name: &str,
) -> BTreeSet<&'a str> {
    collect_dependencies_of(inventory, package_name, false)
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

    let transitive_names = transitive_dependencies_of(inventory, package.name);
    let build_dependency_names: Vec<String> =
        declared_dependencies(package.manifest, workspace_dependencies)
            .into_iter()
            .filter(|declared| declared.kind == DependencyKind::Build)
            .map(|declared| declared.package)
            .collect();
    let build_dependency_names: Vec<&str> =
        build_dependency_names.iter().map(String::as_str).collect();
    let mut build_tree: BTreeSet<String> =
        build_dependency_tree(inventory, package.name, &build_dependency_names)
            .into_iter()
            .map(str::to_owned)
            .collect();
    let build_reads_files = sources.has_build_script && build_script_reads_files(&sources.build);
    // A code generator named `X-build` or `X-codegen` writes code for the
    // crate `X`, which it need not depend on (`tonic-prost-build` writes
    // `tonic_prost::...`).
    for generator in &build_dependency_names {
        for suffix in ["-build", "_build", "-codegen", "_codegen"] {
            if let Some(runtime) = generator.strip_suffix(suffix) {
                build_tree.insert(runtime.to_owned());
            }
        }
    }
    let reachable_idents: BTreeSet<String> = reachable_dependencies_of(inventory, package.name)
        .iter()
        .map(|name| name.replace('-', "_"))
        .collect();
    let declared = declared_dependencies(package.manifest, workspace_dependencies);
    let facts = PackageFacts {
        sources: &sources,
        code_refs: &code_refs,
        transitive_names: &transitive_names,
        build_tree: &build_tree,
        build_reads_files,
        reachable_idents: &reachable_idents,
        declared_idents: declared
            .iter()
            .map(|declared| declared.key.replace('-', "_"))
            .collect(),
        forwarded_features: features_forwarded_to(package.manifest),
        dep_only_features: dep_only_features(package.manifest),
        workspace_macros,
    };

    let mut findings = Vec::new();
    for dependency in &declared {
        let renamed = dependency.key != dependency.package;
        let known_library = if renamed {
            None
        } else {
            library_name(dependency, package, inventory)
        };
        let library_known = known_library.is_some();
        let ident = known_library.unwrap_or_else(|| dependency.key.replace('-', "_"));
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
        let candidate = DependencyFacts {
            dependency,
            ident: &ident,
            renamed,
            library_known,
            references,
            searched,
            searched_label,
        };
        let mut evidence = vec![format!(
            "no `{ident}::`, `use {ident}` or `extern crate {ident}` in {searched} file(s) ({searched_label})"
        )];
        let reasons = reasons_to_keep(&facts, &candidate);
        let confidence = if reasons.is_empty() {
            UnusedConfidence::Likely
        } else {
            UnusedConfidence::Possibly
        };
        evidence.extend(reasons.into_iter().map(|(_, reason)| reason));
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
            fn m(s: S) { match s { S::Url(u) => ::http_helpers::fetch(u), _ => {} } }
            fn n() -> ::retval::T { todo!() }
            "#,
        );
        for expected in [
            "http_helpers",
            "retval",
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
    fn follows_cfg_attr_paths_on_module_declarations() {
        let root = std::env::temp_dir().join(format!("cargoscope-cfg-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src/sys")).expect("dirs");
        std::fs::write(
            root.join("src/lib.rs"),
            r#"
#[cfg_attr(unix, path = "sys/unix.rs")]
#[cfg_attr(windows, path = "sys/windows.rs")]
pub mod sys;
"#,
        )
        .expect("write lib");
        std::fs::write(root.join("src/sys/unix.rs"), "").expect("write unix");
        std::fs::write(root.join("src/sys/windows.rs"), "").expect("write windows");
        let mut files = Vec::new();
        let mut skipped = 0;
        let bound = root.canonicalize().expect("root");
        super::follow_modules(
            &root.join("src/lib.rs"),
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
            vec!["src/lib.rs", "src/sys/unix.rs", "src/sys/windows.rs"]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn generated_code_explains_only_crates_the_build_script_can_name() {
        use cargoscope_core::{Inventory, Package};
        let package = |name: &str, root: bool, dependencies: Vec<usize>| Package {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            source: (!root)
                .then(|| "registry+https://github.com/rust-lang/crates.io-index".to_owned()),
            root,
            direct: !root,
            dependencies,
        };
        // app -> prost-build (build) -> prost; app -> serde, sha2.
        let inventory = Inventory {
            packages: vec![
                package("app", true, vec![1, 3, 4]),
                package("prost-build", false, vec![2]),
                package("prost", false, vec![]),
                package("serde", false, vec![]),
                package("sha2", false, vec![]),
            ],
        };
        let tree = super::build_dependency_tree(&inventory, "app", &["prost-build"]);
        assert!(tree.contains("prost") && tree.contains("prost-build"));
        assert!(!tree.contains("sha2") && !tree.contains("serde"));

        let dir = std::env::temp_dir().join(format!("cargoscope-gen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let build = dir.join("build.rs");
        std::fs::write(
            &build,
            "fn main() { write(\"let id = uuid::Uuid::new_v4();\"); }\n",
        )
        .expect("write");
        assert!(super::build_sources_name(
            std::slice::from_ref(&build),
            "uuid"
        ));
        assert!(!super::build_sources_name(
            std::slice::from_ref(&build),
            "sha2"
        ));
        assert!(!super::build_script_reads_files(std::slice::from_ref(
            &build
        )));
        // A build script that turns Markdown into tests may use any crate.
        let reader = dir.join("tests_from_docs.rs");
        std::fs::write(
            &reader,
            "fn main() { let md = std::fs::read_to_string(\"docs.md\"); }\n",
        )
        .expect("write");
        assert!(super::build_script_reads_files(&[build, reader]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn follows_symbolic_links_inside_the_workspace_only() {
        let root = std::env::temp_dir().join(format!("cargoscope-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("app/src/bin")).expect("dirs");
        std::fs::create_dir_all(root.join("shared")).expect("dirs");
        std::fs::write(root.join("shared/cli.rs"), "use clap::Parser;\n").expect("write");
        let outside =
            std::env::temp_dir().join(format!("cargoscope-outside-{}.rs", std::process::id()));
        std::fs::write(&outside, "use secret::X;\n").expect("write");
        std::os::unix::fs::symlink("../../../shared/cli.rs", root.join("app/src/bin/cli.rs"))
            .expect("link");
        std::os::unix::fs::symlink(&outside, root.join("app/src/bin/escape.rs")).expect("link");
        let bound = root.canonicalize().expect("root");
        let mut files = Vec::new();
        let mut skipped = 0;
        super::walk(&root.join("app/src"), &bound, 0, &mut files, &mut skipped);
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
            vec!["cli.rs"],
            "the link leaving the workspace is not followed"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
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
        assert!(super::library_name_guesses("assert-impl").is_empty());
        assert_eq!(super::library_name_guesses("tokio-test"), vec!["tokio"]);
        assert_eq!(super::library_name_guesses("strum-macros"), vec!["strum"]);
        assert!(super::library_name_guesses("serde").is_empty());
    }

    #[test]
    fn documentation_mentions_need_code_or_a_link() {
        use super::doc_mentions;
        assert!(doc_mentions("see [`toml::Value`] for details", "toml"));
        assert!(doc_mentions("parsed with `toml`.", "toml"));
        assert!(doc_mentions("parsed with [toml].", "toml"));
        assert!(doc_mentions("```\nuse which;\n```", "which"));
        assert!(!doc_mentions("Watch `Cargo.toml` and `Cargo.lock`", "toml"));
        assert!(!doc_mentions("which is the default", "which"));
        assert!(!doc_mentions("see src/http/mod.rs", "http"));
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
    fn known_library_names_git_checkouts_and_compile_tests() {
        let root = std::env::temp_dir().join(format!("cargoscope-rules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("app/src")).expect("dirs");
        std::fs::create_dir_all(root.join("assert-impl")).expect("dirs");
        // A path dependency whose library keeps its package name.
        std::fs::write(
            root.join("assert-impl/Cargo.toml"),
            "[package]\nname = \"assert-impl\"\nversion = \"0.1.0\"\n",
        )
        .expect("write");
        std::fs::write(
            root.join("app/src/lib.rs"),
            "use wasm_bindgen::prelude::*;\nmod imp { pub fn f() {} }\npub fn g() { imp::f(); }\n",
        )
        .expect("write");
        let manifest: toml::Value = toml::from_str(
            "[package]\nname = \"app\"\n[dependencies]\nassert-impl = { path = \"../assert-impl\" }\nwasm-bindgen = \"0.2\"\nwasm-bindgen-futures = \"0.4\"\n[dev-dependencies]\nbytes = \"1\"\n",
        )
        .expect("valid");
        let check = || {
            super::check_package(
                &super::PackageToCheck {
                    name: "app",
                    dir: &root.join("app"),
                    manifest_label: "app/Cargo.toml",
                    manifest: &manifest,
                    workspace_root: &root,
                },
                None,
                &cargoscope_core::Inventory {
                    packages: Vec::new(),
                },
                &super::WorkspaceMacros::default(),
            )
            .0
        };
        let confidence = |findings: &[cargoscope_core::UnusedFinding], name: &str| {
            findings
                .iter()
                .find(|finding| finding.dependency == name)
                .map(|finding| finding.confidence)
        };
        use cargoscope_core::UnusedConfidence::{Likely, Possibly};

        let findings = check();
        // `imp::` would look like a guess for `assert-impl`, but its library
        // name is known (`assert_impl`), so no guess is made.
        assert_eq!(confidence(&findings, "assert-impl"), Some(Likely));
        assert_eq!(
            confidence(&findings, "wasm-bindgen-futures"),
            Some(Possibly)
        );
        // No tests and no git checkout: the test files may be missing.
        assert_eq!(confidence(&findings, "bytes"), Some(Possibly));

        // In a git checkout, missing test files are really missing.
        std::fs::create_dir_all(root.join(".git")).expect("git dir");
        assert_eq!(confidence(&check(), "bytes"), Some(Likely));

        // A package that runs trybuild compiles test files with its dev-dependencies.
        std::fs::write(
            root.join("app/src/lib.rs"),
            "#[test] fn ui() { trybuild::TestCases::new(); }\n",
        )
        .expect("write");
        assert_eq!(confidence(&check(), "bytes"), Some(Possibly));
        // ... unless its compile tests are in tests/, which are read.
        std::fs::create_dir_all(root.join("app/tests")).expect("tests dir");
        std::fs::write(root.join("app/tests/ui.rs"), "fn main() {}\n").expect("write");
        assert_eq!(confidence(&check(), "bytes"), Some(Likely));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn finds_path_modules_declared_inside_functions() {
        let tokens = TokenStream::from_str(
            "mod top;\nmod r#enum;\nfn build() {\n    #[path = \"src/theme.rs\"]\n    mod theme;\n    mod unknown;\n}\n#[inline]\nmod plain;\n#[path = \"src/args.rs\"]\n#[expect(dead_code)]\nmod args;\n#[path = \"x.rs\"]\nfn f() {}\nmod after_fn;\n",
        )
        .expect("tokenizes");
        assert_eq!(
            super::declared_modules(tokens),
            vec![
                ("top".to_owned(), None),
                ("enum".to_owned(), None),
                ("theme".to_owned(), Some("src/theme.rs".to_owned())),
                ("plain".to_owned(), None),
                ("args".to_owned(), Some("src/args.rs".to_owned())),
                ("after_fn".to_owned(), None),
            ]
        );
    }

    #[test]
    fn only_exported_macros_count_for_their_callers() {
        use std::str::FromStr;
        let names = |code: &str| {
            let mut names = std::collections::BTreeSet::new();
            super::collect_macro_bodies(
                proc_macro2::TokenStream::from_str(code).expect("tokens"),
                &mut names,
            );
            names
        };
        // A macro without #[macro_export] cannot be called from another crate.
        assert!(names("macro_rules! inner { () => { serde_json::json!({}) }; }").is_empty());
        assert!(names("#[macro_export]\n#[doc(hidden)]\nmacro_rules! out { () => { serde_json::json!({}) }; }").contains("serde_json"));
        assert!(names("#[cfg_attr(feature = \"x\", macro_export)]\nmacro_rules! out { () => { itoa::Buffer::new() }; }").contains("itoa"));
        assert!(
            names("mod m { #[macro_export] macro_rules! nested { () => { log::info!(\"\") }; } }")
                .contains("log")
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
    fn follows_path_modules_of_source_files_into_other_crates_of_the_workspace() {
        // neomacs's xtask reuses `../../neovm-core/build_support/*.rs`, which
        // use crates no file of xtask itself names.
        let base = std::env::temp_dir().join(format!("cargoscope-xpath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("repo");
        for dir in ["crates/xtask/src", "crates/core/build_support"] {
            std::fs::create_dir_all(root.join(dir)).expect("dirs");
        }
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/xtask\", \"crates/core\"]\n",
        )
        .expect("write");
        let manifest = "[package]\nname = \"xtask\"\n";
        std::fs::write(root.join("crates/xtask/Cargo.toml"), manifest).expect("write");
        std::fs::write(
            root.join("crates/xtask/src/main.rs"),
            "#[path = \"../../core/build_support/generated.rs\"]\nmod generated;\n#[path = \"../../../../outside.rs\"]\nmod outside;\nfn main() {}\n",
        )
        .expect("write");
        std::fs::write(
            root.join("crates/core/build_support/generated.rs"),
            "mod helper;\npub fn run() { flate2::Compression::default(); }\n",
        )
        .expect("write");
        std::fs::create_dir_all(root.join("crates/core/build_support/generated")).expect("dirs");
        std::fs::write(
            root.join("crates/core/build_support/generated/helper.rs"),
            "use proc_macro2::TokenStream;\n",
        )
        .expect("write");
        std::fs::write(base.join("outside.rs"), "use leaked::Thing;\n").expect("write");

        let manifest: toml::Value = toml::from_str(manifest).expect("toml");
        let sources = super::collect_sources(&root.join("crates/xtask"), &manifest);
        let names: Vec<String> = sources
            .code
            .iter()
            .map(|file| {
                file.file_name()
                    .expect("name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(names.contains(&"generated.rs".to_owned()), "{names:?}");
        assert!(names.contains(&"helper.rs".to_owned()), "{names:?}");
        assert!(
            !names.contains(&"outside.rs".to_owned()),
            "outside the workspace: {names:?}"
        );
        let refs = super::scan_files(&sources.code);
        assert!(refs.contains("flate2") && refs.contains("proc_macro2"));
        let _ = std::fs::remove_dir_all(&base);
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

    #[test]
    fn per_package_transitive_deps_proc_macros_and_builtin_attributes() {
        // 1. Built-in attributes should not record `test`, `derive`, or `cfg`,
        // while nested attribute paths (`serde(with = "serde_regex")`) are still kept.
        let names = references(
            r#"
            #[cfg(test)]
            #[derive(Debug)]
            #[cfg_attr(test, serde(with = "serde_regex"))]
            struct Demo;

            #[test]
            fn it_works() {}
            "#,
        );
        for builtin in ["test", "derive", "cfg", "cfg_attr"] {
            assert!(!names.contains(builtin), "built-in recorded: {builtin}");
        }
        assert!(names.contains("serde_regex"));

        // 2. Empty `features = []` does not count as setting features.
        let empty_features: toml::Value = toml::from_str(
            "[package]\nname = \"app\"\n[dependencies]\ngetrandom = { version = \"0.2\", features = [] }\n",
        )
        .expect("valid");
        let declared = declared_dependencies(&empty_features, None);
        assert_eq!(declared.len(), 1);
        assert!(!declared[0].sets_features);
        // `derive` only adds macros and turning default features off never
        // reaches other crates; `wasm_js`, also inherited, does.
        let features: toml::Value = toml::from_str(
            "[package]\nname = \"app\"\n[dependencies]\nserde = { version = \"1\", features = [\"derive\"] }\nscopeguard = { version = \"1\", default-features = false }\ngetrandom = { workspace = true }\n",
        )
        .expect("valid");
        let workspace: toml::Value =
            toml::from_str("getrandom = { version = \"0.4\", features = [\"wasm_js\"] }\n")
                .expect("valid");
        let declared = declared_dependencies(&features, Some(&workspace));
        let selects = |key: &str| {
            declared
                .iter()
                .find(|dependency| dependency.key == key)
                .expect("declared")
                .sets_features
        };
        assert!(!selects("serde"));
        assert!(!selects("scopeguard"));
        assert!(selects("getrandom"));

        // Features meant for tests, by name; `plugin` or `os` are not.
        let test_support: toml::Value = toml::from_str(
            "[package]\nname = \"app\"\n[dev-dependencies]\nengine = { path = \"../engine\", default-features = false, features = [\"test-support\"] }\nmocked = { path = \"../mocked\", features = [\"Mock\"] }\nplugin = { path = \"../plugin\", features = [\"plugin\", \"os\"] }\n",
        )
        .expect("valid");
        let declared = declared_dependencies(&test_support, None);
        let for_tests = |key: &str| {
            declared
                .iter()
                .find(|dependency| dependency.key == key)
                .expect("declared")
                .test_features
        };
        assert!(for_tests("engine"));
        assert!(for_tests("mocked"));
        assert!(!for_tests("plugin"));

        // 3. Per-package transitive dependencies and scoped workspace proc-macros.
        // Package `app` transitively reaches `reexport_macro` via `app_helper`,
        // `via_depended_sibling_ext` via `depended_sibling` -> `depended_sibling_ext`,
        // while `sibling_only_transitive` is only reachable from unrelated `sibling`,
        // and `ws_member_dev` is directly attached to workspace (`root = true`) package
        // `depended_sibling` (so it could be a dev-dependency of `depended_sibling`).
        let inventory = cargoscope_core::Inventory {
            packages: vec![
                cargoscope_core::Package {
                    name: "app".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: false,
                    dependencies: vec![2, 3, 4, 9], // app_helper, direct_macro, unrelated_dep, depended_sibling
                },
                cargoscope_core::Package {
                    name: "sibling".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: false,
                    dependencies: vec![5], // sibling_helper
                },
                cargoscope_core::Package {
                    name: "app_helper".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: Some("registry".to_owned()),
                    root: false,
                    direct: true,
                    dependencies: vec![6], // reexport_macro
                },
                cargoscope_core::Package {
                    name: "direct_macro".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: true,
                    dependencies: vec![],
                },
                cargoscope_core::Package {
                    name: "unrelated_dep".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: Some("registry".to_owned()),
                    root: false,
                    direct: true,
                    dependencies: vec![],
                },
                cargoscope_core::Package {
                    name: "sibling_helper".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: Some("registry".to_owned()),
                    root: false,
                    direct: true,
                    dependencies: vec![7], // sibling_only_transitive
                },
                cargoscope_core::Package {
                    name: "reexport_macro".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: false,
                    dependencies: vec![],
                },
                cargoscope_core::Package {
                    name: "sibling_only_transitive".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: Some("registry".to_owned()),
                    root: false,
                    direct: false,
                    dependencies: vec![],
                },
                cargoscope_core::Package {
                    name: "ws_member_dev".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: Some("registry".to_owned()),
                    root: false,
                    direct: false,
                    dependencies: vec![],
                },
                cargoscope_core::Package {
                    name: "depended_sibling".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: None,
                    root: true,
                    direct: true,
                    dependencies: vec![8, 10], // ws_member_dev, depended_sibling_ext
                },
                cargoscope_core::Package {
                    name: "depended_sibling_ext".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: Some("registry".to_owned()),
                    root: false,
                    direct: false,
                    dependencies: vec![11], // via_depended_sibling_ext
                },
                cargoscope_core::Package {
                    name: "via_depended_sibling_ext".to_owned(),
                    version: "0.1.0".to_owned(),
                    source: Some("registry".to_owned()),
                    root: false,
                    direct: false,
                    dependencies: vec![],
                },
            ],
        };
        let app_transitive = super::transitive_dependencies_of(&inventory, "app");
        assert!(app_transitive.contains("reexport_macro"));
        assert!(app_transitive.contains("via_depended_sibling_ext"));
        assert!(!app_transitive.contains("ws_member_dev"));
        assert!(!app_transitive.contains("sibling_only_transitive"));
        let app_reachable = super::reachable_dependencies_of(&inventory, "app");
        assert!(app_reachable.contains("reexport_macro"));
        assert!(app_reachable.contains("ws_member_dev"));
        assert!(app_reachable.contains("via_depended_sibling_ext"));

        let root = std::env::temp_dir().join(format!("cargoscope-scoped-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("app/src")).expect("dirs");
        std::fs::create_dir_all(root.join(".git")).expect("git");
        std::fs::write(
            root.join("app/src/lib.rs"),
            "#[derive(direct_macro::Gen, strum_macros::EnumIter)]\npub struct X;\n",
        )
        .expect("write");

        let manifest: toml::Value = toml::from_str(
            r#"
            [package]
            name = "app"
            [dependencies]
            direct_macro = "0.1"
            sibling_only_transitive = { version = "0.1", features = ["a"] }
            ws_member_dev = { version = "0.1", features = ["a"] }
            unreferenced_pm_dep = "0.1"
            used_pm_dep = "0.1"
            reexported_pm_dep = "0.1"
            unused_pm_crate = "0.1"
            strum = "0.27"
            strum_macros = "0.28"
            "#,
        )
        .expect("valid");

        let mut workspace_macros = super::WorkspaceMacros::default();
        workspace_macros.proc_macros.insert(
            "unrelated_pm_crate".to_owned(),
            ["unreferenced_pm_dep".to_owned()].into_iter().collect(),
        );
        workspace_macros.proc_macros.insert(
            "unused_pm_crate".to_owned(),
            ["unreferenced_pm_dep".to_owned()].into_iter().collect(),
        );
        workspace_macros.proc_macros.insert(
            "direct_macro".to_owned(),
            ["used_pm_dep".to_owned()].into_iter().collect(),
        );
        workspace_macros.proc_macros.insert(
            "reexport_macro".to_owned(),
            ["reexported_pm_dep".to_owned()].into_iter().collect(),
        );

        let (findings, _) = super::check_package(
            &super::PackageToCheck {
                name: "app",
                dir: &root.join("app"),
                manifest_label: "app/Cargo.toml",
                manifest: &manifest,
                workspace_root: &root,
            },
            None,
            &inventory,
            &workspace_macros,
        );
        let confidence = |name: &str| {
            findings
                .iter()
                .find(|finding| finding.dependency == name)
                .map(|finding| finding.confidence)
        };
        use cargoscope_core::UnusedConfidence::{Likely, Possibly};
        assert_eq!(confidence("sibling_only_transitive"), Some(Likely));
        assert_eq!(confidence("ws_member_dev"), Some(Likely));
        assert_eq!(confidence("unreferenced_pm_dep"), Some(Likely));
        assert_eq!(confidence("unused_pm_crate"), Some(Likely));
        assert_eq!(confidence("used_pm_dep"), Some(Possibly));
        assert_eq!(confidence("reexported_pm_dep"), Some(Possibly));
        assert_eq!(confidence("strum"), Some(Possibly));

        // Without `strum_macros` referenced, `strum` is `Likely`.
        std::fs::write(root.join("app/src/lib.rs"), "pub struct X;\n").expect("write");
        let (without_strum_macros, _) = super::check_package(
            &super::PackageToCheck {
                name: "app",
                dir: &root.join("app"),
                manifest_label: "app/Cargo.toml",
                manifest: &manifest,
                workspace_root: &root,
            },
            None,
            &inventory,
            &workspace_macros,
        );
        assert_eq!(
            without_strum_macros
                .iter()
                .find(|finding| finding.dependency == "strum")
                .map(|finding| finding.confidence),
            Some(Likely)
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
