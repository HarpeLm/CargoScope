# Blind Benchmark (2026-11-12)

A fresh test with no correction allowed: 15 repositories never seen before, tool versions frozen before running anything, and unused-dependency labels set without knowing which tool reported them.

## Protocol

- **Tools, frozen before the run:** CargoScope at commit `4e0aeac` (0.1.0-alpha.3 plus later fixes), cargo-machete 0.9.2 (default mode), cargo-audit 0.23.0, cargo-deny 0.20.2.
- **Repositories (pinned commits):** BurntSushi/xsv `f4304660231d`, dalance/procs `7ffb8c4f2ecb`, chmln/sd `44febdf86343`, tealdeer-rs/tealdeer `993a8e0232ef`, cantino/mcfly `6eed8ebd879c`, skim-rs/skim `6faa57cbf570`, nushell/reedline `14be1e0f597b`, ratatui/ratatui `41c26a74b3bc`, crossterm-rs/crossterm `de052f5c30c4`, sharkdp/vivid `efc43e83f31f`, mitsuhiko/similar `bf4c758b3f17`, rust-cli/env_logger `3c6b8239c9ad`, tokio-rs/mini-redis `3d93b42bc363`, seanmonstar/warp `ff34d7213ed5`, hyperium/h2 `1fa08adf2236`. None is in the labelled corpus.
- **Scope:** the workspace members reported by `cargo metadata --no-deps`, for every tool.
- **Unused-dependency labels:** the findings of both tools were merged, shuffled and labelled by reading the code with the tool hidden, then unblinded.
- **Same inputs:** both advisory databases from the same day (RustSec, 2026-11-12); the same license allow list for CargoScope's `cargoscope.toml` and cargo-deny's `deny.toml`.
- Nothing was compiled. No rule of CargoScope was changed after the run.

## Results

### Unused dependencies

| | CargoScope (`likely-unused`) | cargo-machete |
|---|---|---|
| Reported | 5 | 1 |
| Correct | 5 | 0 |
| Wrong | 0 | 1 (`streaming-stats`, imported as `extern crate stats`) |
| Truly unused found, of the 5 known | 5 | 0 |

**Read this with care: 6 findings in total is far too few to prove a ratio.** These well-maintained, medium-sized projects have few unused dependencies. The result agrees with the larger, non-blind comparison in [cargo-machete.md](cargo-machete.md), but on its own it proves only that CargoScope made no mistake on these 15 repositories. The labels come from reading code; the compiler was not used as a judge (no sandbox was available).

### Security advisories (versus cargo-audit)

| | CargoScope | cargo-audit |
|---|---|---|
| Advisory findings | 52 | 52 |
| Identical findings | 52 | 52 |
| Yanked versions in use | 4 | 4 |

Identical. A first run differed by 7 advisories only because cargo-audit's local database was 6 days older; with both databases from the same day, every finding matched.

### Licenses (versus cargo-deny, same allow list)

| | CargoScope | cargo-deny |
|---|---|---|
| Packages with a license outside the allow list | 8 | 4 |
| Found by both | 4 | 4 |

The 4 extra ones (`CDLA-Permissive-2.0`, `LGPL-3.0`, `WTFPL`) really are outside the allow list. They are pulled in only by non-default features: cargo-deny checks the default-feature graph, CargoScope the whole `Cargo.lock`. Both choices are defensible; CargoScope is stricter, and cannot yet be told to follow the default-feature graph.

### Speed (one run per repository, warm caches)

| | Median | Slowest | 15 repositories |
|---|---|---|---|
| CargoScope `scan` (all checks) | 0.06 s | 0.24 s | 1.1 s |
| cargo-machete | 0.04 s | 0.13 s | 0.7 s |
| cargo-audit | 0.11 s | 0.23 s | 2.0 s |
| cargo-deny (advisories + licenses) | 1.09 s | 4.33 s | 25.1 s |

CargoScope's `scan` is offline; its download step (`cargoscope update`) is not timed.

## Where competitors are better, or we have nothing yet

Feature list from the tools' documented behaviour, not re-checked against their latest documentation.

| Capability | Who has it | CargoScope |
|---|---|---|
| Ignore one advisory, with a reason | cargo-audit (`audit.toml`), cargo-deny | **No** (only `--baseline` and `--fail-on`) |
| Audit compiled binaries | cargo-audit (`cargo audit bin`) | No |
| Suggest or apply advisory fixes | cargo-audit (`fix`, experimental), Dependabot, Renovate | No |
| Automatic update pull requests, continuous monitoring | Dependabot, Renovate | No, by design |
| License clarifications and per-crate exceptions | cargo-deny | No |
| Ban duplicate versions, or features | cargo-deny | No |
| Check only the graph of chosen features and targets | cargo-deny, cargo-tree | No: always the whole `Cargo.lock` |
| Remove unused dependencies automatically | cargo-machete (`--fix`) | No (`fix` is on the roadmap) |
| Compiler-accurate unused detection, proven at scale | cargo-udeps | `--precise` exists, not measured at scale |
| Compatible versus latest update | cargo-outdated | Latest only |
| Inverted tree, duplicates, feature edges | cargo-tree (`-i`, `-d`, `-e features`) | Shortest path only |
| Other ecosystems | OSV-Scanner, Dependabot, Renovate, Snyk, Trivy | Rust only, by design |
| Stable release on crates.io, Homebrew, npm, PyPI | all of them | Pre-release on GitHub only |
| Users, maintainers, track record | all of them | None yet |

## Where CargoScope is ahead on this test

- **Unused dependencies:** no wrong finding, and all 5 really unused ones found, where cargo-machete found none of them and reported one used crate.
- **One run instead of four tools:** advisories identical to cargo-audit, licenses at least as strict as cargo-deny, yanked versions, unused dependencies and dependency paths in a single report, in about the time cargo-audit takes alone.
