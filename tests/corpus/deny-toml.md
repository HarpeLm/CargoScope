# Reading deny.toml: CargoScope against cargo-deny (2026-11-15)

28 repositories of the first two corpora (`corpus.toml` and `compiler-judge`, excluding one pre-0.14 config rejected by cargo-deny 0.20.2) have their own cargo-deny configuration (`deny.toml`, `.deny.toml`). Including `blind-judge` brings the total to 36 repositories, 34 of which are accepted by cargo-deny 0.20.2. For each, `cargo deny check licenses bans sources` (cargo-deny 0.20.2) and `cargoscope scan --checks inventory,licenses,policy` (no `cargoscope.toml`, so CargoScope reads the same `deny.toml`) were run on the same commit, and their errors compared by rule and crate.

| | Crates reported by both | By cargo-deny only | By CargoScope only |
|---|---|---|---|
| First translation (28 repos, commit `22495c9`) | 3 | 9 | 104 |
| After the `834f525` fixes (28 repos) | 3 | 9 | 6 |
| After P4 fixes (same 28 repos) | 3 | 9 | 0 |
| **After Option A fixes (`[bans] build`, hashes, `"warn"`, same 28 repos)** | **12** | **0** | **0** |
| Expanded corpora with `blind-judge` after P4 (34 valid repos) | 10 | 22 | 0 |
| Expanded corpora with `blind-judge` after Option A (34 valid repos) | 31 | 1 | 2 |
| **Expanded corpora with `blind-judge` after graph fixes (34 valid repos)** | **32** | **0** | **0** |

**28 of the original 28 repositories (100%) give the same error set**, and the last two graph discrepancies across the **34 valid repositories** (`tower-rs/tower-http` and `taiki-e/portable-atomic`) are now resolved (both verified directly against `cargo-deny 0.20.2`).

The fixes the comparison led to:

- cargo-deny checks the graph of the **default features**; the first translation checked the whole `Cargo.lock`.
- `{ name = "x", deny-multiple-versions = true }` denies the duplicates of x, not x itself (bevy); it was read as a ban.
- `wrappers` of a ban, `skip-tree`, `exclude-unpublished` and cargo-deny's default `multiple-versions-include-dev = false` (duplicates pulled in only by dev-dependencies do not count) were added.
- A license with `+` ("or later", as `MPL-2.0+` in cargo's `im-rc`) was refused when its version is allowed. This also fixes `cargoscope.toml`.

Root-cause fixes implemented on `main` (`0.6.0-dev`) and verified in the re-run above (eliminating all 6 crates previously reported only by CargoScope):

- `[licenses] include-dev` in `deny.toml` now defaults to `false`, leaving dev-only dependencies out of license checks unless `include-dev = true` (such as `limbo-harness-support` in `rustls-webpki`, a `[dev-dependencies]` crate pulling non-allowed transitive licenses).
- When `Cargo.toml` defines a root `[package]`, reading `deny.toml` now roots `cargo tree` at that root package instead of adding `--workspace` (matching cargo-deny/`krates` for non-virtual root manifests such as `bevy`, `cargo`, `rustls-webpki`, and `ring`, keeping internal workspace test members out of the checked graph).
- `multiple-versions` ignores `semver-trick` self-dependencies (cases where all direct parents of a duplicate have the same crate name).
- `[bans] features` (`allow`, `deny`, `exact`) is now supported and translated from `deny.toml`.

- `[bans] build` (`allow-build-scripts` and `include-workspace`), `[licenses.clarify]` `license-files` 32-bit `xxHash32` verification, and `"warn"` lint levels (`[bans] multiple-versions = "warn"`, `[sources] unknown-registry` / `unknown-git = "warn"`) were added: all **21 `[bans] build` errors** across `taiki-e/pin-project` (7), `taiki-e/pin-project-lite` (9), and `taiki-e/portable-atomic` (5) now match `cargo-deny`.

- **1 license error** in `tower-rs/tower-http` (`zstd-sys`, `BSD-3-Clause AND BSD-2-Clause`), fixed on `0.6.0-dev`: `active_packages` now runs `cargo tree --prefix depth` without `--exclude` and prunes `exclude-unpublished` workspace members afterward, preserving workspace feature unification from `examples/*` onto `tower-http` (`full` -> `zstd-sys`) before excluding example-only dependencies (`cargo deny` 1 error == CargoScope 1 error).
- **2 build-script errors** (`proc-macro2`, `quote`) in `taiki-e/portable-atomic`, fixed on `0.6.0-dev`: `serde_core` declares `serde_derive` under `[target."cfg(any())".dependencies]`, which `cargo tree --target all` retains. CargoScope now reads `cargo metadata` `resolve.nodes` `dep_kinds` when `targets` is empty and prunes edges whose matching `dep_kinds` are all unsatisfiable (`cfg(any())` / `cfg(not(all()))`), matching `cargo-deny`'s 10 errors (`5` `[bans.build]` + `5` `[sources]`).

(Two older `deny.toml` files in `briansmith/untrusted` and `polyfill-rs/is_terminal_polyfill` use pre-0.14 `[advisories]` syntax rejected by cargo-deny 0.20.2 and were excluded from the comparison.)

Every remaining unsupported setting is listed in the report's warnings (for example `confidence-threshold`, `private`, `[bans.build] executables`/`interpreted`/`bypass`, `unused-allowed-license`).
