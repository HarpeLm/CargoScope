# `--precise` Benchmark at Scale (2026-11-19)

Measuring CargoScope's opt-in compiler-based mode (`cargoscope scan --precise`) across **76 pinned open-source Rust repositories** (56 foundational libraries + 20 active applications/CLIs) on both **Rust `1.99.1`** (`rustc`'s `unused_crate_dependencies` lint) and **Rust `1.100.0`** (Cargo's native `cargo::unused_dependencies` lint), to validate the `SPEC.md` section 12 criterion (**97% precision goal for `--precise`**).

## Protocol

- **Repositories (76 total, all pinned to existing corpus commits):**
  - **56 libraries:** every repository marked `all-features` (without `no-benches`) in [compiler-judge/repositories.txt](compiler-judge/repositories.txt).
  - **20 applications / CLIs:** 20 pinned repositories from [blind-judge-3/repositories.txt](blind-judge-3/repositories.txt) (`sayanarijit/xplr`, `anordal/shellharden`, `topgrade-rs/topgrade`, `agentclientprotocol/agent-client-protocol`, `szabodanika/microbin`, `squidowl/halloy`, `tokio-rs/console`, `timothymiller/cloudflare-ddns`, `medialab/xan`, `orhun/binsider`, `jhspetersson/fselect`, `Keats/tera`, `oxipng/oxipng`, `crossterm-rs/crossterm`, `tobi/disktree`, `linebender/resvg`, `jmacdonald/amp`, `lycheeverse/lychee`, `YS-L/csvlens`, `redlib-org/redlib`).
- **Two-phase design (to preserve a blind held-out measure):**
  - **Set 1 (40 repos: 30 libraries + 10 apps):** run first on CargoScope `0.9.0-dev` (matching `v0.8.0`'s `precise.rs`) to measure pre-fix behavior and audit every finding.
  - **Set 2 (36 unseen repos: 26 libraries + 10 apps):** run **blind** after fixing the defect uncovered on Set 1, without looking at Set 2 before freezing the fix.
- **Host & toolchains:** macOS (`aarch64-apple-darwin`), `rustc 1.99.1` and `rustc 1.100.0`.
- **Commands (for each repository, with `target/cargoscope-precise` cleared before each `--precise` run):**
  ```sh
  cargoscope scan . --checks inventory,unused --format json
  RUSTUP_TOOLCHAIN=1.99.1 cargoscope scan . --checks inventory,unused --precise --format json
  RUSTUP_TOOLCHAIN=1.100.0 cargoscope scan . --checks inventory,unused --precise --format json
  ```
- **Compilation rate:** **72 of 76 repositories (`94.7%`)** compiled cleanly with `cargo check --workspace --all-targets --all-features` on both `1.99.1` and `1.100.0` (`8,158` resolved `Cargo.lock` packages). The 4 that failed compilation on macOS (`szabodanika/microbin`, `tokio-rs/console`, `orhun/binsider`, `oxipng/oxipng`) exited with status `2` as expected and are excluded from `--precise` precision counts.
- **Ground truth:** every `likely-unused` finding was verified directly against the package's `Cargo.toml`, Rust source files, doctests, README includes, and feature flags.

## Results

### 1. Set 1 (40 repos, 37 compiling) — Pre-fix discovery and post-fix re-check

| Mode | Compiled | `likely-unused` | Confirmed code-unused | Strictly removable | False positives | Precision (code-unused / strict) | Median time | Total time |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| Static (default, offline) | 40 / 40 | 17 *(11 on the 37)* | 11 *(on the 37)* | 10 *(on the 37)* | 0 *(on the 37)* | **100.0% / 90.9%** | 27 ms | 2.5 s |
| **`--precise` (`1.99.1`, pre-fix)** | 37 / 40 | 24 | 13 | 12 | **11** | 54.2% / 50.0% | 2,936 ms | 298.0 s |
| **`--precise` (`1.99.1`, post-fix)** | 37 / 40 | 13 | **13** | **12** | **0** *(1 pin)* | **100.0% / 92.3%** | 2,880 ms | 296.6 s |
| **`--precise` (`1.100.0`)** | 37 / 40 | 4 | **4** | **4** | **0** | **100.0% / 100.0%** | 2,980 ms | 322.2 s |

#### Defect uncovered on Set 1 (and fixed before Set 2)

Pre-fix, `precise::refine` emitted **every** dependency reported by `rustc` as `likely-unused` even when CargoScope's static analysis **had already found an explicit reference** in the crate's source or doctests. All **11 of 11 (`100%`)** of those compiler-only disagreements on Set 1 were false positives:

- **6 doctest-only dev-dependencies** (`cargo check` does not compile doctests or `#[cfg(doctest)]`): `serde_stacker` (`serde-rs/json`), `doc-comment` (`BurntSushi/aho-corasick`), `sha2` (`RustCrypto/traits` `digest`), `serde_json` (`rayon-rs/either`), `annotate-snippets` and `anyhow` (`winnow-rs/winnow`).
- **4 mutually-exclusive `#[cfg(not(feature = ...))]` dependencies** masked by `--all-features`: `foldhash` (`serde-rs/json`), `critical-section` normal + dev (`matklad/once_cell`), `libm` (`rust-num/num-traits`).
- **1 nightly/cfg-gated test crate:** `pin-project-lite` (`taiki-e/pin-project-lite` `tests/no-core`).

**Fix (`crates/cargoscope-cargo/src/precise.rs`):** when the compiler reports a dependency unused under `--all-targets --all-features` *despite* static analysis finding a reference, `precise::refine` now classifies it as **`possibly-unused`** instead of `likely-unused` (still visible with `--show-uncertain`, never auto-removed by `cargoscope fix --precise`). Static findings (`likely-unused` or `possibly-unused`) confirmed by the compiler still become `likely-unused`, and static false positives proved used by the compiler are still eliminated.

### 2. Blind Held-Out Set 2 (36 unseen repos, 35 compiling) — Post-fix validation

Run blind on 36 repositories never inspected during the fix:

| Mode | Compiled | `likely-unused` | Confirmed code-unused | Strictly removable | False positives | Precision | `possibly-unused` | Median time | Total time |
|---|---:|---:|---:|---:|---:|---|---:|---:|---:|
| Static (default, offline) | 36 / 36 | 14 | 14 | 14 | 0 | **100.0%** | 5 | 20 ms | 1.3 s |
| **`--precise` (`1.99.1`, blind)** | 35 / 36 | **16** | **16** | **16** | **0** | **100.0%** | 27 | 3,732 ms | 287.3 s |
| **`--precise` (`1.100.0`, blind)** | 35 / 36 | **10** | **10** | **10** | **0** | **100.0%** | 2 | 3,819 ms | 289.8 s |

Every single one of the **16** `likely-unused` findings on Rust `1.99.1` (and **10** on Rust `1.100.0`) was verified genuinely unused:
- `nix-rust/nix`: `assert-impl` (dev)
- `rustls/webpki-roots`: `webpki` in `webpki-ccadb` *(promoted from static `possibly-unused`)*, `percent-encoding` (dev) in `webpki-root-certs`, `percent-encoding` (dev) in `webpki-roots`
- `rust-cli/anstyle`: `snapbox` (dev) in `anstyle-progress`
- `bytecodealliance/wasi-rs`: `alloc` in `wasip1` *(promoted from static `possibly-unused`)*, `cfg-if` in `witx-bindgen`
- `strawlab/iana-time-zone`: `getrandom` (dev)
- `dtolnay/async-trait`: `tracing-attributes` (dev)
- `Peternator7/strum`: `strum_macros` in `strum_nostd_tests`
- `yaahc/displaydoc`: `libc` (dev)
- `lycheeverse/lychee`: `headers`, `http-serde`, `tracing-subscriber` (dev) in `lychee-bin`; `http`, `regex` in `examples/collect_links`

In addition, the post-fix rule safely kept **27** compiler-only disagreements on Set 2 (doctests in `tower`, `memoffset`, `sync_wrapper`, `displaydoc`, `anstream`, `nix`, `webpki-roots`, and mutually-exclusive features in `crossterm`) in `possibly-unused`, preventing 27 false positives.

### 3. Combined Summary (All 72 Compiling Repositories, 8,158 Packages)

| Mode | Compiled | `likely-unused` | Confirmed code-unused | Strictly removable | Precision (code-unused / strict) | Median time | Total time |
|---|---:|---:|---:|---:|---|---:|---:|
| Static (default, on the 72) | 72 / 72 | 25 | 25 | 24 | **100.0% / 96.0%** | **22 ms** | **3.6 s** |
| **`--precise` (`1.99.1`, post-fix)** | 72 / 76 | **29** | **29** | **28** | **100.0% / 96.6%** *(100% blind)* | 3,638 ms | 583.9 s |
| **`--precise` (`1.100.0`, post-fix)** | 72 / 76 | **14** | **14** | **14** | **100.0% / 100.0%** | 3,416 ms | 612.1 s |

- **SPEC.md 97% criterion:** validated on the 35-repo blind held-out set at **`100.0%` (`16/16` on `1.99.1`, `10/10` on `1.100.0`)** and **`100.0%` code-unused (`29/29`) / `96.6%` strictly removable (`28/29`)** across all 72 compiling repos. The single borderline item across all 72 repos is `rust-i18n-support = "=4.2.1"` in `topgrade-rs/topgrade`, which is genuinely unimported in code (`rustc` itself reports it unused) and explicitly commented `# Temporary transitive dependency pins` in `Cargo.toml`.
- **Recall gain over static (`1.99.1`):** `--precise` promoted **+4** genuinely unused dependencies that static analysis conservatively kept in `possibly-unused` (`url` in `squidowl/halloy`'s `ipc`, `digest` in `RustCrypto/traits`'s `elliptic-curve`, `webpki` in `rustls/webpki-roots`'s `webpki-ccadb`, and `alloc` in `bytecodealliance/wasi-rs`'s `wasip1`), bringing `likely-unused` findings from `25` to `29` (`+16%`) without introducing false positives.
- **Cost:** `--precise` is roughly **165× slower** than default static scanning (median `3.6 s` vs `22 ms`, total `9.7 min` vs `3.6 s` across 72 repos), requires compiling target code (executing `build.rs` and proc macros), and fails when `--all-targets --all-features` does not build on the host platform (`4/76` repos here).

## Important Behavioral Difference: Rust `1.99.1` vs Rust `1.100.0`

Starting with **Rust `1.100.0`**, Cargo replaces rustc's JSON `unused_crate_dependencies` diagnostic with its own `cargo::unused_dependencies` lint (`--json=...,unused-externs-silent`). Measuring both side by side across 72 repositories revealed two significant limitations of Cargo `1.100.0`'s built-in lint:

1. **No `dev-dependencies`:** Cargo's lint does not check `[dev-dependencies]`; CargoScope keeps its static result for them (`12` of the `14` findings on `1.100.0`).
2. **Transitive dependencies are silently skipped:** Cargo `1.100.0` intentionally suppresses `cargo::unused_dependencies` whenever a declared dependency also appears transitively anywhere in the package's dependency graph (assuming it may exist to pin a version or unify features). On real workspaces where crates share dependencies across members (`squidowl/halloy`, `lycheeverse/lychee`, `rustls/webpki-roots`, `Peternator7/strum`), this silenced **15 of 17** genuinely unused normal dependencies (`100%` precision, but much lower recall than `1.99.1` or static mode).

**Practical takeaway:**
- Use **default static mode** for fast (`~22 ms`), offline, zero-execution CI checks and high recall across all dependency kinds (including dev-dependencies and transitive duplicates).
- Use **`--precise`** on trusted code when you want compiler verification of static candidates — and note that Rust `1.99.x` provides full normal + dev + build compiler coverage, while Rust `1.100+` uses Cargo's narrower lint for normal/build dependencies plus CargoScope's static fallback for dev-dependencies.
