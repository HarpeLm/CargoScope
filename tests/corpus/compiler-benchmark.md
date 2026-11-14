# Compiler Benchmark: the Compiler as Judge (2026-11-14)

A blind test of unused-dependency detection where the judge is rustc, not a person.

## Protocol

- **Repositories:** the GitHub repositories of the most downloaded crates on crates.io, in download order, skipping those already used in any earlier test and a few giant monorepos: 98 repositories, listed with their commits in [compiler-judge/repositories.txt](compiler-judge/repositories.txt). None was seen before.
- **Tools, frozen before the judge ran:** CargoScope at commit `d0abe03`, cargo-machete 0.9.2 (default mode).
- **Judge:** each repository was compiled in the official `rust:1` Docker image (rustc 1.99.1, Linux) **without network**, with `cargo check --workspace --all-targets --all-features` and rustc's `unused_crate_dependencies` lint. An independent script ([compiler-judge/judge.py](compiler-judge/judge.py), which uses no CargoScope code) marks a declared dependency **used** when a compiled target that receives it uses it, and **unused** when every such target reports it unused.
- **Kept for the measure:** the 73 repositories that compiled with all features. 16 compiled only with default features: there, code behind features is not compiled and the lint over-reports, so they were dropped. 9 did not compile in the container (nightly-only tests, a pinned toolchain or a newer rustc required). For 17 kept repositories whose benchmarks need nightly, benchmarks were skipped and their dev-dependencies are not judged.
- 700 dependencies were judged.

### What the judge can and cannot prove

- **"Used" is proof.** If rustc sees a target use the dependency, a tool that reports it unused is wrong.
- **"Unused" is not complete proof.** The lint sees only Linux and the enabled features, and does not compile doctests. A dependency used only on Windows or only in doctests looks unused to it. So the recall below is computed on the **16 dependencies rustc reports unused and whose name appears nowhere in the package's Rust files**: these are unused beyond reasonable doubt.

## Results

| | Reported and judged | Correct | Wrong | Precision | Recall (of the 16 certain) |
|---|---|---|---|---|---|
| **CargoScope** (`likely-unused`, default output) | 12 | 11 | 1 | **91.7%** | **62.5%** (10) |
| CargoScope with `--show-uncertain` | 24 | 18 | 6 | 75.0% | 93.8% (15) |
| **cargo-machete** (default) | 10 | 8 | 2 | **80.0%** | **31.2%** (5) |

## What this shows

- **On these foundational library crates, both tools rarely err, and CargoScope finds twice as many really unused dependencies** (10 against 5) with slightly better precision (1 error against 2).
- **The gap is much smaller than in the application-heavy corpus**, where cargo-machete had about 100 times more false positives (see [cargo-machete.md](cargo-machete.md)). Those false positives come mostly from patterns that libraries rarely have: renamed libraries, crates only used in attributes, `-sys` crates, generated code, large workspaces with macros. **The "100 times" figure must not be presented as general**: it depends on the kind of project.
- **The numbers are small.** 12 and 10 judged findings, so one error moves precision by about 8 points. These well-kept crates have few unused dependencies.
- **CargoScope's error is a real defect, found blind:** `include!("../include/basic.rs")` in pin-project-lite's `tests/no-std` uses the dependency, but CargoScope never follows paths containing `..`, a safety rule that is too strict when the path stays inside the repository. cargo-machete makes the same error. Not fixed during this test; **fixed afterwards in commit 034b72a**: `include!` and `#[path]` with `..` are now followed while they stay inside the workspace (absolute paths, symbolic links and paths that leave the workspace are still never read). pin-project-lite's finding disappears, and the labelled corpus gives the same results as before. The table above keeps the frozen, pre-fix numbers.
- `--show-uncertain` finds almost all certain unused dependencies (15 of 16) at the cost of more wrong ones (6 of 24): `possibly-unused` is a useful list to review, not a list to act on blindly.

## Reproduce

See [compiler-judge/README.md](compiler-judge/README.md). Compilation runs inside the container only; the host only fetches sources.
