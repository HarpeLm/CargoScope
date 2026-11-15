# CargoScope and cargo-shear (2026-11-15)

cargo-shear 1.14.1 (default mode, `shear/unused_dependency` findings) compared with CargoScope at commit `292df60`, on two sets.

## 1. Library crates, judged by rustc

73 popular library repositories, judged by the compiler: see [compiler-benchmark.md](compiler-benchmark.md#re-run-with-cargo-shear-2026-11-15).

| | Precision | Certain unused found (of 15) |
|---|---|---|
| CargoScope (`likely-unused`) | 100% (10 of 10) | 10 |
| cargo-shear | 83.3% (15 of 18) | 14 |

On libraries, **cargo-shear finds more** and still errs rarely.

## 2. Applications: the labelled corpus

The 70 repositories of [corpus.toml](corpus.toml), mostly applications and large workspaces. The labels cover only the dependencies CargoScope reported at some point, so most of cargo-shear's findings are not labelled.

| | Findings | Labelled correct | Labelled wrong | Not labelled |
|---|---|---|---|---|
| CargoScope (`likely-unused`) | 183 | 181 | 2 (both `known`) | 0 |
| cargo-shear | 550 | 189 | 12 | 349 |

**The 349 unlabelled findings are all cases CargoScope treats as uncertain** (`possibly-unused`, 327) or as used (22). By CargoScope's reason: a dependency that is also transitive and may only select features, or is optional (108); possibly used through a macro of a workspace crate (58); a package without test files (47); a package whose build script generates code (43); `-sys` crates (22); platform-specific dependencies (20); a library name that may differ (18); doc links (10).

**A sample of 37 of them, read by hand** (3 or 4 per reason, chosen at random):

- **13 are needed**: removing them breaks or changes the build. A transitive dependency declared to enable a feature (`getrandom` with `js` or `wasm_js` for WebAssembly, `openssl-sys` with `vendored`); `-sys` crates declared with `bundled` (`pq-sys`, `mysqlclient-sys` in diesel's examples); `tonic-prost`, used by the code tonic-build generates; `quickcheck`, which the `#[quickcheck]` attribute of `quickcheck_macros` expands to; `serde` used by serde_core's doctests; `heck` used by intra-doc links.
- **8 are really unused**: dev-dependencies of packages without tests (`tokio` in pingora-openssl, `bevy_core_pipeline` in bevy_ui), libraries whose name never appears (`human-sort` in lsd, `tokio-test` in leptos), dependencies only named by local variables (`bytes` in zellij-server).
- **16 could not be decided quickly** (uses through workspace macros, platform-specific code, generated test files).

So between about a third (13 of 37) and three quarters (29 of 37, if every undecided one is needed) of these 349 are needed, which puts **cargo-shear's precision on applications between about 48% and 75%**, against 98.9% for CargoScope's default output on the same corpus (not a blind number, see the limits); and **cargo-shear finds real unused dependencies that CargoScope only lists as `possibly-unused`** (with `--show-uncertain`).

## What this says

- **Neither tool dominates.** cargo-shear finds more unused dependencies; CargoScope's default output is a list you can act on with very few mistakes. The difference comes from CargoScope's cautious rules: on libraries they mostly cost recall, on applications they mostly prevent wrong removals.
- **CargoScope's misses are concentrated in a few rules** (macros of workspace crates, library names, packages without tests, feature selection). Making these rules sharper is the clearest way to close the recall gap without losing precision.
- **Since Rust 1.100, Cargo warns about unused normal and build dependencies by itself**, from the compiler (not dev-dependencies, and `cargo fix` removes nothing). Static tools keep their value for dev-dependencies, for CI without a build, and for removal, but the bar is now the compiler.

## After sharpening CargoScope's rules (commit `112740c`)

The rules behind CargoScope's misses were made narrower, each on a fact the scanner can check:

- **Library names**: when the dependency's manifest is available (a path dependency, or a crate unpacked in `$CARGO_HOME`), its library name is known even without a `[lib] name`, so no guess is made from the package name (`assert-impl`, `human-sort`).
- **Packages without test files**: missing test files are only suspected in published copies; inside a git checkout, a dev-dependency used by no test file is reported (`snapbox`, `tokio-test`, `insta`).
- **Workspace macros**: a macro of a workspace crate can only explain a dependency if the package uses that crate.
- Two new cautious rules found while labelling: a package without `tests/` that runs trybuild compiles test files from elsewhere against its dev-dependencies (deno's `compile_test_runner`), and `#[wasm_bindgen]` on an async function expands to `wasm-bindgen-futures`.

| | Before | After `112740c` | After `b1b49a6` + follow-up |
|---|---|---|---:|
| Libraries (rustc judge): correct of reported, certain unused found | 10 of 10, 10 of 15 | **12 of 12, 12 of 15** | *(not re-run)* |
| Applications (labelled corpus): correct of reported | 181 of 183 (98.9%) | **221 of 223** (99.1%) | **233 of 235** (99.1%) |

The sharper rules in `112740c` brought 37 new application findings, all checked by reading the code: 35 really unused, and 2 wrong, which led to the two new rules above.

### Second pass on the application corpus (commit `b1b49a6` and follow-up)

A second set of refinements tightened three checks to package scope and fixed two edge cases found during corpus validation:

- **Built-in attributes & generic library affixes**: Rust built-in attributes (`#[doc]`, `#[cfg]`, `#[allow]`, etc.) no longer count as external crate references, and generic affixes (`impl`, `assert`, `macros`, `test`, ...) are filtered from fallback library-name guesses (`b1b49a6`).
- **Per-package reachability**: both transitive feature-selection (`sets_features`, now also ignoring empty `features = []`) and sibling workspace proc-macro reachability are scoped to packages reachable from the checked package rather than the entire workspace (`b1b49a6`, with traversal through reachable workspace members onto their external dependencies fixed afterwards so workspace `dev-dependencies` still do not leak in).
- **Corpus validation additions**: raw module identifiers (`mod r#enum;`) resolve to `enum.rs` (preventing a false positive on `indexmap` in deno's `libs/ops`), and `strum` is recognized as required when `strum_macros` is used because derives such as `EnumIter` expand to `::strum::IntoEnumIterator` (protecting atuin's `atuin-common` and correcting `examples/function_memory_game`'s `strum` label in `yewstack/yew`).

On the 70-repository corpus (`cargo run --release -p cargoscope-corpus --offline`), this surfaced **13 newly detected genuinely unused dependencies** with **0 new false positives** (**233 of 235** correct, **99.1%**: 20/20 development, 11/11 held-out, 134/134 held-out-2, 68/70 held-out-3). Both wrong findings that remain are the known, accepted ones of egui. cargo-shear still finds more on libraries (14 of 15 in the `rustc` run above, which has not been re-run since `112740c`), with errors CargoScope does not make.

## Limits

- The corpus labels were built from CargoScope's findings, and CargoScope's rules were tuned on part of this corpus: its numbers here are not blind. The library set is blind for cargo-shear, not for CargoScope (see the compiler benchmark).
- The application sample is small (37 of 349): the precision range above is an estimate, not a measure.
