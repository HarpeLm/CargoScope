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

## Limits

- The corpus labels were built from CargoScope's findings, and CargoScope's rules were tuned on part of this corpus: its numbers here are not blind. The library set is blind for cargo-shear, not for CargoScope (see the compiler benchmark).
- The application sample is small (37 of 349): the precision range above is an estimate, not a measure.
