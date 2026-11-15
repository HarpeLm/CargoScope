# Reading deny.toml: CargoScope against cargo-deny (2026-11-15)

28 repositories of the first two corpora (`corpus.toml` and `compiler-judge`, excluding one pre-0.14 config rejected by cargo-deny 0.20.2) have their own cargo-deny configuration (`deny.toml`, `.deny.toml`). Including `blind-judge` brings the total to 36 repositories, 34 of which are accepted by cargo-deny 0.20.2. For each, `cargo deny check licenses bans sources` (cargo-deny 0.20.2) and `cargoscope scan --checks inventory,licenses,policy` (no `cargoscope.toml`, so CargoScope reads the same `deny.toml`) were run on the same commit, and their errors compared by rule and crate.

| | Crates reported by both | By cargo-deny only | By CargoScope only |
|---|---|---|---|
| First translation (28 repos, commit `22495c9`) | 3 | 9 | 104 |
| After the `834f525` fixes (28 repos) | 3 | 9 | 6 |
| **After P4 fixes on `0.6.0-dev` (same 28 repos)** | **3** | **9** | **0** |
| **Expanded corpora with `blind-judge` (34 valid repos, `0.6.0-dev`)** | **10** | **22** | **0** |

**27 of the original 28 repositories give exactly the same result** (up from 22/28 at `834f525`), and **30 of the 34 valid repositories** across all three corpora match identically with **0 crates reported by CargoScope only**.

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

What still differs on the 34 valid repositories (`22` crates reported by `cargo-deny` only, `0` by CargoScope only):

- **21 `[bans] build` errors** across 3 `taiki-e` repositories (`pin-project`: 7, `pin-project-lite`: 9, `portable-atomic`: 5): CargoScope does not enforce allowed build scripts yet and says so in a note. (On all 10 disallowed `[sources]` crates across those 3 repositories, both tools agree.)
- **1 license error** in `tower-rs/tower-http` (`zstd-sys`, `BSD-3-Clause AND BSD-2-Clause`): `tower-http` sets `exclude-unpublished = true` and `default = []`, while unpublished `examples/*` depend on `tower-http` with `features = ["full"]`. `cargo-deny` runs `cargo metadata` over the whole workspace before stripping `examples/*` in `krates`, keeping `zstd-sys` enabled by feature unification; CargoScope passes `--exclude` to `cargo tree`, so `tower-http` stays at `default = []` without `zstd-sys`.

(Two older `deny.toml` files in `briansmith/untrusted` and `polyfill-rs/is_terminal_polyfill` use pre-0.14 `[advisories]` syntax rejected by cargo-deny 0.20.2 and were excluded from the comparison.)

Every remaining unsupported setting is listed in the report's warnings (for example `confidence-threshold`, `private`, `[bans] build`, `unused-allowed-license`).
