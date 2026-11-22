//! The facts about a package and an unreferenced dependency, the rules that
//! find a reason to keep it (each a pure function in `RULES`), and the one
//! place that turns those reasons into likely or possibly unused.
//!
//! To add a rule: write `fn rule_x(&PackageFacts, &DependencyFacts) ->
//! Option<String>`, add it to `RULES` with a name, test it here, and check that
//! the benchmark sets (tests/corpus) do not lose precision.

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
    /// Optional dependencies referenced only with `dep:<key>` in `[features]`.
    pub(super) dep_only_features: BTreeSet<&'a str>,
    pub(super) workspace_macros: &'a WorkspaceMacros,
    /// Target crate identifiers emitted in `quote!` by external proc-macros
    /// reachable through referenced direct dependencies.
    pub(super) external_macro_targets:
        &'a std::collections::BTreeMap<String, Vec<(String, String)>>,
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
    ("external-proc-macro", rule_external_proc_macro),
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
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    if !candidate.dependency.optional {
        return None;
    }
    if package
        .dep_only_features
        .contains(candidate.dependency.key.as_str())
        && !package
            .transitive_names
            .contains(candidate.dependency.package.as_str())
        && !candidate
            .dependency
            .package
            .starts_with("rustc-std-workspace-")
    {
        return None;
    }
    Some("optional dependency: may only be used to forward a feature".to_owned())
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
    if !dependency.sets_features {
        return None;
    }
    if package
        .transitive_names
        .contains(dependency.package.as_str())
    {
        return Some(
            "also a transitive dependency: may be declared only to select its features".to_owned(),
        );
    }
    // A dev-dependency on a workspace crate the package also reaches through
    // another dependency, turning on a feature meant for tests
    // (`features = ["test-support"]`): it changes that crate for the
    // package's tests, as Cargo unifies features. Other features (`plugin`,
    // `os`) are not enough: such dev-dependencies are usually leftovers.
    (dependency.kind == DependencyKind::Dev
        && dependency.test_features
        && dependency.path.is_some()
        && package
            .reachable_idents
            .contains(&dependency.package.replace('-', "_")))
    .then(|| {
        "a workspace crate also reached through another dependency: may be declared only to enable its test features for this package's tests".to_owned()
    })
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

pub(super) fn rule_external_proc_macro(
    package: &PackageFacts<'_>,
    candidate: &DependencyFacts<'_>,
) -> Option<String> {
    if candidate.dependency.kind == DependencyKind::Build {
        return None;
    }
    let providers = package.external_macro_targets.get(candidate.ident)?;
    let (provider_ident, pm_ident) = providers
        .iter()
        .find(|(provider_ident, _)| provider_ident != candidate.ident)?;
    Some(format!(
        "proc-macro crate `{pm_ident}` (used via `{provider_ident}`) generates paths to `{}` in `quote!`",
        candidate.ident
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cargoscope_core::DependencyKind;

    use super::{DependencyFacts, PackageFacts, RULES, reasons_to_keep};
    use crate::unused::references::References;
    use crate::unused::sources::Sources;
    use crate::unused::{DeclaredDependency, WorkspaceMacros};

    fn dependency(key: &str) -> DeclaredDependency {
        DeclaredDependency {
            key: key.to_owned(),
            package: key.to_owned(),
            kind: DependencyKind::Normal,
            optional: false,
            target_specific: false,
            sets_features: false,
            test_features: false,
            path: None,
        }
    }

    /// The rules that keep `dependency` when the package reaches the
    /// `reachable` crates (identifiers) through other dependencies.
    fn kept_with_reachable(
        dependency: &DeclaredDependency,
        reachable: &BTreeSet<String>,
    ) -> Vec<&'static str> {
        // A git checkout: missing test files are not a reason to keep it.
        let sources = Sources {
            git_checkout: true,
            ..Sources::default()
        };
        let code = References::default();
        let transitive = BTreeSet::new();
        let build_tree = BTreeSet::new();
        let macros = WorkspaceMacros::default();
        let package = PackageFacts {
            sources: &sources,
            code_refs: &code,
            transitive_names: &transitive,
            build_tree: &build_tree,
            build_reads_files: false,
            reachable_idents: reachable,
            declared_idents: vec![dependency.key.replace('-', "_")],
            forwarded_features: BTreeSet::new(),
            dep_only_features: BTreeSet::new(),
            workspace_macros: &macros,
            external_macro_targets: &std::collections::BTreeMap::new(),
        };
        let ident = dependency.key.replace('-', "_");
        let candidate = DependencyFacts {
            dependency,
            ident: &ident,
            renamed: false,
            library_known: true,
            references: &code,
            searched: 1,
            searched_label: "src/",
        };
        reasons_to_keep(&package, &candidate)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    /// Runs the rules on `dependency` with the given package context, and
    /// returns the names of the rules that keep it.
    fn kept_by(
        dependency: &DeclaredDependency,
        sources: &Sources,
        code: &References,
        transitive: &BTreeSet<&str>,
        build_tree: &BTreeSet<String>,
    ) -> Vec<&'static str> {
        let macros = WorkspaceMacros::default();
        let reachable = BTreeSet::new();
        let package = PackageFacts {
            sources,
            code_refs: code,
            transitive_names: transitive,
            build_tree,
            build_reads_files: false,
            reachable_idents: &reachable,
            declared_idents: vec![dependency.key.replace('-', "_")],
            forwarded_features: BTreeSet::new(),
            dep_only_features: BTreeSet::new(),
            workspace_macros: &macros,
            external_macro_targets: &std::collections::BTreeMap::new(),
        };
        let ident = dependency.key.replace('-', "_");
        let candidate = DependencyFacts {
            dependency,
            ident: &ident,
            renamed: false,
            library_known: true,
            references: code,
            searched: sources.code.len(),
            searched_label: "src/",
        };
        reasons_to_keep(&package, &candidate)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    fn with_code() -> Sources {
        Sources {
            code: vec!["src/lib.rs".into()],
            has_test_files: true,
            git_checkout: true,
            ..Sources::default()
        }
    }

    #[test]
    fn rule_names_are_unique() {
        let names: BTreeSet<&str> = RULES.iter().map(|(name, _)| *name).collect();
        assert_eq!(names.len(), RULES.len());
    }

    #[test]
    fn a_plain_unreferenced_dependency_has_no_reason_to_be_kept() {
        let none = BTreeSet::new();
        let kept = kept_by(
            &dependency("log"),
            &with_code(),
            &References::default(),
            &none,
            &BTreeSet::new(),
        );
        assert!(kept.is_empty(), "{kept:?}");
    }

    #[test]
    fn each_declaration_rule_fires_on_its_own_case_only() {
        let none = BTreeSet::new();
        let tree = BTreeSet::new();
        let code = References::default();
        let sources = with_code();
        let check =
            |dependency: DeclaredDependency, transitive: &BTreeSet<&str>, expected: &[&str]| {
                assert_eq!(
                    kept_by(&dependency, &sources, &code, transitive, &tree),
                    expected,
                    "{}",
                    dependency.key
                );
            };
        check(dependency("openssl-sys"), &none, &["sys-crate"]);
        check(
            DeclaredDependency {
                optional: true,
                ..dependency("chrono")
            },
            &none,
            &["optional"],
        );
        check(
            DeclaredDependency {
                target_specific: true,
                ..dependency("winapi")
            },
            &none,
            &["platform-specific"],
        );
        // Selecting features matters only for a crate others also use.
        let getrandom = DeclaredDependency {
            sets_features: true,
            ..dependency("getrandom")
        };
        check(getrandom.clone(), &none, &[]);
        check(
            getrandom,
            &BTreeSet::from(["getrandom"]),
            &["selects-features"],
        );
        // A workspace crate reached through another dependency: a
        // dev-dependency enabling its `test-support` feature is needed even
        // if no file names it (neomacs-layout-engine -> neovm-eval).
        let local = DeclaredDependency {
            kind: DependencyKind::Dev,
            sets_features: true,
            test_features: true,
            path: Some(("../neovm-eval".to_owned(), false)),
            ..dependency("neovm-eval")
        };
        let reachable = BTreeSet::from(["neovm_eval".to_owned()]);
        assert_eq!(
            kept_with_reachable(&local, &reachable),
            vec!["selects-features"]
        );
        assert!(kept_with_reachable(&local, &BTreeSet::new()).is_empty());
        let no_features = DeclaredDependency {
            sets_features: false,
            test_features: false,
            ..local.clone()
        };
        assert!(kept_with_reachable(&no_features, &reachable).is_empty());
        // Other features of a workspace crate (nushell's `plugin`, `os`) do
        // not count: those dev-dependencies were leftovers.
        let other_feature = DeclaredDependency {
            test_features: false,
            ..local.clone()
        };
        assert!(kept_with_reachable(&other_feature, &reachable).is_empty());
        let normal = DeclaredDependency {
            kind: DependencyKind::Normal,
            ..local.clone()
        };
        assert!(kept_with_reachable(&normal, &reachable).is_empty());
        let external = DeclaredDependency {
            path: None,
            ..local
        };
        assert!(
            kept_with_reachable(&external, &reachable).is_empty(),
            "an external crate counts only when it is a transitive dependency"
        );
        // Missing test files only matter for dev-dependencies of a copy.
        let dev = DeclaredDependency {
            kind: DependencyKind::Dev,
            ..dependency("tempfile")
        };
        assert_eq!(
            kept_by(
                &dev,
                &Sources {
                    code: vec!["src/lib.rs".into()],
                    ..Sources::default()
                },
                &code,
                &none,
                &tree
            ),
            ["test-files-missing"]
        );
        check(dev, &none, &[]);
    }

    #[test]
    fn generated_code_keeps_only_crates_the_build_script_can_produce_code_for() {
        let none = BTreeSet::new();
        let sources = Sources {
            has_build_script: true,
            ..with_code()
        };
        let code = References {
            includes_generated_code: true,
            ..References::default()
        };
        let tree = BTreeSet::from(["prost".to_owned()]);
        assert_eq!(
            kept_by(&dependency("prost"), &sources, &code, &none, &tree),
            ["generated-code"]
        );
        assert!(kept_by(&dependency("sha2"), &sources, &code, &none, &tree).is_empty());
    }

    #[test]
    fn incomplete_searches_keep_every_dependency() {
        let none = BTreeSet::new();
        let tree = BTreeSet::new();
        let skipped = Sources {
            skipped: 2,
            ..with_code()
        };
        assert_eq!(
            kept_by(
                &dependency("log"),
                &skipped,
                &References::default(),
                &none,
                &tree
            ),
            ["skipped-files"]
        );
        let empty = Sources {
            code: Vec::new(),
            has_test_files: true,
            git_checkout: true,
            ..Sources::default()
        };
        assert_eq!(
            kept_by(
                &dependency("log"),
                &empty,
                &References::default(),
                &none,
                &tree
            ),
            ["nothing-searched"]
        );
    }

    #[test]
    fn dep_only_optional_feature_is_not_kept_unless_transitive() {
        let sources = with_code();
        let code = References::default();
        let build_tree = BTreeSet::new();
        let macros = WorkspaceMacros::default();
        let reachable = BTreeSet::new();
        let dep = DeclaredDependency {
            optional: true,
            ..dependency("chrono")
        };
        let empty = BTreeSet::new();
        let transitive = BTreeSet::from(["chrono"]);
        let mut package = PackageFacts {
            sources: &sources,
            code_refs: &code,
            transitive_names: &empty,
            build_tree: &build_tree,
            build_reads_files: false,
            reachable_idents: &reachable,
            declared_idents: vec!["chrono".to_owned()],
            forwarded_features: BTreeSet::new(),
            dep_only_features: BTreeSet::from(["chrono"]),
            workspace_macros: &macros,
            external_macro_targets: &std::collections::BTreeMap::new(),
        };
        let candidate = DependencyFacts {
            dependency: &dep,
            ident: "chrono",
            renamed: false,
            library_known: true,
            references: &code,
            searched: sources.code.len(),
            searched_label: "src/",
        };
        assert!(reasons_to_keep(&package, &candidate).is_empty());

        package.transitive_names = &transitive;
        assert_eq!(
            reasons_to_keep(&package, &candidate)
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            vec!["optional"]
        );
    }
}
