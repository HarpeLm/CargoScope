//! The facts about a package and an unreferenced dependency, the rules that
//! find a reason to keep it (each a pure function in `RULES`), and the one
//! place that turns those reasons into likely or possibly unused.

use super::*;

/// Names of the packages a build script can generate code for: its
/// build-dependencies and everything they pull in (`prost-build` brings
/// `prost`, `tonic-build` brings `prost-build`...).
pub(super) fn build_dependency_tree<'a>(
    inventory: &'a Inventory,
    package_name: &str,
    build_dependencies: &[&str],
) -> BTreeSet<&'a str> {
    let mut names = BTreeSet::new();
    let Some(package) = inventory
        .packages
        .iter()
        .find(|package| package.root && package.name == package_name)
    else {
        return names;
    };
    let mut stack: Vec<usize> = package
        .dependencies
        .iter()
        .copied()
        .filter(|&index| build_dependencies.contains(&inventory.packages[index].name.as_str()))
        .collect();
    // A lockfile edge Cargo leaves ambiguous (two `x 1.0.0`, one local, one
    // from a registry) may be missing: look such names up directly.
    for name in build_dependencies {
        if !stack
            .iter()
            .any(|&index| inventory.packages[index].name == *name)
        {
            stack.extend(
                inventory
                    .packages
                    .iter()
                    .enumerate()
                    .filter(|(_, candidate)| candidate.name == *name)
                    .map(|(index, _)| index),
            );
        }
    }
    let mut seen: BTreeSet<usize> = stack.iter().copied().collect();
    while let Some(index) = stack.pop() {
        names.insert(inventory.packages[index].name.as_str());
        for &next in &inventory.packages[index].dependencies {
            if seen.insert(next) {
                stack.push(next);
            }
        }
    }
    names
}

/// Whether the build script reads other files (Markdown, templates, test
/// directories...): the code it generates from them may then use any crate.
pub(super) fn build_script_reads_files(build_files: &[PathBuf]) -> bool {
    const READS: [&str; 8] = [
        "read_to_string",
        "File::open",
        "fs::read",
        "read_dir",
        "WalkDir",
        "walkdir::",
        "glob(",
        "glob::",
    ];
    build_files.iter().any(|file| {
        fs::read_to_string(file).is_ok_and(|text| READS.iter().any(|call| text.contains(call)))
    })
}

/// Whether the build script's sources name `ident` as a path (`ident::`),
/// in code or in the text of the code it writes (`"uuid::Uuid::new_v4()"`).
pub(super) fn build_sources_name(build_files: &[PathBuf], ident: &str) -> bool {
    let needle = format!("{ident}::");
    build_files.iter().any(|file| {
        fs::read_to_string(file).is_ok_and(|text| {
            text.match_indices(&needle).any(|(position, _)| {
                text[..position]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
            })
        })
    })
}

/// What is known about the package being checked, shared by every rule.
pub(super) struct PackageFacts<'a> {
    pub(super) sources: &'a Sources,
    /// References in the library, binaries, tests, benches and examples.
    pub(super) code_refs: &'a References,
    /// Packages the package reaches through other packages.
    pub(super) transitive_names: &'a BTreeSet<&'a str>,
    /// Crates its build script can generate code for (see
    /// [`build_dependency_tree`]).
    pub(super) build_tree: &'a BTreeSet<String>,
    /// The build script reads other files, so generated code may use anything.
    pub(super) build_reads_files: bool,
    /// Identifiers of the packages reachable at depth 2 or more.
    pub(super) reachable_idents: &'a BTreeSet<String>,
    /// Identifiers of every declared dependency.
    pub(super) declared_idents: Vec<String>,
    /// Dependencies named in `[features]` as `name/feature`.
    pub(super) forwarded_features: BTreeSet<&'a str>,
    pub(super) workspace_macros: &'a WorkspaceMacros,
}

/// What is known about one dependency no file references.
pub(super) struct DependencyFacts<'a> {
    pub(super) dependency: &'a DeclaredDependency,
    /// Library name searched for (`-` read as `_`).
    pub(super) ident: &'a str,
    pub(super) renamed: bool,
    /// The library name was read from the dependency's own manifest.
    pub(super) library_known: bool,
    /// References of the files that could use it (build script or code).
    pub(super) references: &'a References,
    pub(super) searched: usize,
    pub(super) searched_label: &'a str,
}

/// A reason a dependency nothing references may still be needed, which
/// makes it `possibly-unused`: one pure function per rule, returning the
/// reason shown in the report.
pub(super) type Rule = fn(&PackageFacts<'_>, &DependencyFacts<'_>) -> Option<String>;

/// Every rule, by name, in the order its reason is reported.
pub(super) const RULES: &[(&str, Rule)] = &[
    ("sys-crate", rule_sys_crate),
    ("optional", rule_optional),
    ("platform-specific", rule_platform_specific),
    ("selects-features", rule_selects_features),
    ("library-name-guess", rule_library_name_guess),
    ("forwarded-feature", rule_forwarded_feature),
    ("documentation", rule_documentation),
    ("workspace-proc-macro", rule_workspace_proc_macro),
    ("workspace-macro-rules", rule_workspace_macro_rules),
    ("compile-tests", rule_compile_tests),
    ("wasm-bindgen-futures", rule_wasm_bindgen_futures),
    ("strum-macros", rule_strum_macros),
    ("generated-code", rule_generated_code),
    ("text-fallback", rule_text_fallback),
    ("test-files-missing", rule_test_files_missing),
    ("skipped-files", rule_skipped_files),
    ("nothing-searched", rule_nothing_searched),
];

/// The reasons, by rule name, to keep a dependency nothing references.
/// None means `likely-unused`.
pub(super) fn reasons_to_keep(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Vec<(&'static str, String)> {
    RULES
        .iter()
        .filter_map(|(name, rule)| rule(package, candidate).map(|reason| (*name, reason)))
        .collect()
}

pub(super) fn rule_sys_crate(
    _: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    let package = &candidate.dependency.package;
    (package.ends_with("-sys") || package.ends_with("_sys"))
        .then(|| "`-sys` crates are often linked only for their native library".to_owned())
}

pub(super) fn rule_optional(
    _: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    candidate
        .dependency
        .optional
        .then(|| "optional dependency: may only be used to forward a feature".to_owned())
}

pub(super) fn rule_platform_specific(
    _: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    candidate
        .dependency
        .target_specific
        .then(|| "platform-specific dependency".to_owned())
}

pub(super) fn rule_selects_features(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    let dependency = candidate.dependency;
    (dependency.sets_features
        && package
            .transitive_names
            .contains(dependency.package.as_str()))
    .then(|| "also a transitive dependency: may be declared only to select its features".to_owned())
}

/// Guesses only when the library name could not be read.
pub(super) fn rule_library_name_guess(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    let dependency = candidate.dependency;
    if candidate.renamed
        || candidate.library_known
        || candidate.ident != dependency.key.replace('-', "_")
    {
        return None;
    }
    let guess = library_name_guesses(&dependency.package)
        .into_iter()
        // A guess that is itself a declared dependency (`tokio` for
        // `tokio-test`) is explained by that dependency.
        .filter(|guess| !package.declared_idents.contains(guess))
        .find(|guess| candidate.references.contains(guess))?;
    Some(format!(
        "`{guess}::` is used: the library name of `{}` may differ from its package name",
        dependency.package
    ))
}

pub(super) fn rule_forwarded_feature(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    let dependency = candidate.dependency;
    (dependency.kind != DependencyKind::Dev
        && package.forwarded_features.contains(dependency.key.as_str()))
    .then(|| {
        format!(
            "named in [features] (`{}/...`): may be declared only to forward a feature",
            dependency.key
        )
    })
}

pub(super) fn rule_documentation(
    _: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    (candidate.dependency.kind != DependencyKind::Dev
        && candidate.references.in_docs(candidate.ident))
    .then(|| "mentioned in documentation (a doc link needs the crate to resolve)".to_owned())
}

pub(super) fn rule_workspace_proc_macro(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    let provider =
        package
            .workspace_macros
            .proc_macros
            .iter()
            .find_map(|(crate_ident, names)| {
                let proc_macro_reachable = if package.declared_idents.contains(crate_ident) {
                    candidate.references.contains(crate_ident)
                } else {
                    package.reachable_idents.contains(crate_ident)
                };
                (crate_ident != candidate.ident
                    && proc_macro_reachable
                    && names.contains(candidate.ident))
                .then_some(crate_ident)
            })?;
    Some(format!(
        "workspace proc-macro crate `{provider}` generates paths to it, which derives and attributes expand in this crate"
    ))
}

pub(super) fn rule_workspace_macro_rules(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    let provider =
        package
            .workspace_macros
            .macro_rules
            .iter()
            .find_map(|(crate_ident, names)| {
                // A macro can only be called through its crate: a path, `use`
                // or `extern crate` of the provider.
                (package.declared_idents.contains(crate_ident)
                    && candidate.references.contains(crate_ident)
                    && names.contains(candidate.ident))
                .then_some(crate_ident)
            })?;
    Some(format!(
        "may be used through a macro of workspace crate `{provider}`, which mentions it"
    ))
}

/// Compile tests in tests/ are read like any test; without tests/, the
/// files trybuild compiles live elsewhere and are not read.
pub(super) fn rule_compile_tests(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    (candidate.dependency.kind == DependencyKind::Dev
        && !package.sources.has_test_files
        && (package.code_refs.contains("trybuild") || package.code_refs.contains("ui_test")))
    .then(|| {
        "the package runs compile tests (trybuild) on files outside it, built against its dev-dependencies"
            .to_owned()
    })
}

pub(super) fn rule_wasm_bindgen_futures(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    (candidate.ident == "wasm_bindgen_futures" && package.code_refs.contains("wasm_bindgen")).then(
        || "`#[wasm_bindgen]` on an async function expands to wasm-bindgen-futures".to_owned(),
    )
}

pub(super) fn rule_strum_macros(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    (candidate.ident == "strum" && package.code_refs.contains("strum_macros"))
        .then(|| "`strum_macros` derives expand to traits in `strum`".to_owned())
}

/// Generated code can only use a crate the build script names, or one a
/// code generator among its build-dependencies brings along; a build script
/// that reads other files may generate anything.
pub(super) fn rule_generated_code(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    let dependency = candidate.dependency;
    (package.sources.has_build_script
        && dependency.kind != DependencyKind::Build
        && package.code_refs.includes_generated_code
        && (package.build_reads_files
            || package.build_tree.contains(&dependency.package)
            || build_sources_name(&package.sources.build, candidate.ident)))
    .then(|| "the sources include code generated by the build script, which may use it".to_owned())
}

pub(super) fn rule_text_fallback(
    _: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    let fallback = candidate.references.text_fallback.len();
    (fallback > 0).then(|| {
        format!("{fallback} file(s) could not be tokenized and were searched as plain text")
    })
}

pub(super) fn rule_test_files_missing(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    if candidate.dependency.kind != DependencyKind::Dev {
        return None;
    }
    let sources = package.sources;
    if sources.published_copy {
        Some(
            "published package copy (Cargo.toml.orig present): test files are often excluded from it"
                .to_owned(),
        )
    } else if !sources.has_test_files && !sources.git_checkout {
        Some(
            "no tests/, benches/ or examples/ found: test files may be missing from this copy"
                .to_owned(),
        )
    } else {
        None
    }
}

pub(super) fn rule_skipped_files(
    package: &PackageFacts<'_>,
    _: &DependencyFacts<'_>,
) -> Option<String> {
    let skipped = package.sources.skipped;
    (skipped > 0).then(|| {
        format!(
            "{skipped} source file(s) were skipped (size, depth or count limit) and not searched"
        )
    })
}

pub(super) fn rule_nothing_searched(
    _: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    (candidate.searched == 0).then(|| format!("no {} file found", candidate.searched_label))
}
