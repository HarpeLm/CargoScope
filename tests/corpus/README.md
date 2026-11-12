# Unused-Dependency Corpus

[`corpus.toml`](corpus.toml) pins 40 open-source Rust repositories to a commit and labels, by reading their code, the dependencies CargoScope reports as `likely-unused`:

- `unused`: the dependency is really unused by the package's code.
- `used`: CargoScope reported it wrongly at some point. These labels guard against regressions.

Replay it with:

```sh
cargo run -p cargoscope-corpus -- target/corpus
```

The tool fetches each repository with `git`, creates a `Cargo.lock` with `cargo generate-lockfile` when the repository has none (this only resolves versions; no build script or project code runs), scans it, and compares the findings with the labels. It fails on any wrong or unlabelled finding, or below 97% precision.

## Results (2026-11-12)

| Set | Repositories | `likely-unused` reported | Correct | Precision |
|---|---|---|---|---|
| Development | 30 | 11 | 11 | 100% |
| Held-out, first run | 10 | 11 | 10 | **90.9%** |
| Held-out, after the fix below | 10 | 9 | 9 | 100% |

**How to read these numbers:**

- The development set was used to design the rules. Its first run reported 60 `likely-unused` dependencies, most of them wrong. Each wrong one led to a rule: following `mod` declarations from targets outside `src/`, build scripts that include files, derive helper attributes, paths in attribute strings, macros of sibling crates, library names that differ from package names, generated code, documentation links, and feature forwarding. Its 100% therefore says little about unseen projects.
- The held-out set was labelled before any change. Its only wrong finding (`phf` in typos, used in a skipped 2 MiB generated file) revealed a bug: skipped files did not lower confidence. After the fix, the held-out set is no longer independent. **90.9% on unseen code is the honest figure**, below the 97% target of SPEC.md; a new held-out set is needed before claiming the target.
- Recall is lower by design: on the development set, 9 of 20 dependencies labelled `unused` are only reported as `possibly-unused`, for example `tokio-test` next to tokio, or `heck` in a package with a skipped file.
- Labels come from reading code, not from the compiler. Repositories without a committed `Cargo.lock` get one generated at run time, so their results can drift slightly over time.
