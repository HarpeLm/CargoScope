# Reading deny.toml: CargoScope against cargo-deny (2026-11-15)

28 repositories of the corpora have their own cargo-deny configuration (`deny.toml`, `.deny.toml`). For each, `cargo deny check licenses bans sources` (cargo-deny 0.20.2) and `cargoscope scan --checks inventory,licenses,policy` (no `cargoscope.toml`, so CargoScope reads the same `deny.toml`) were run on the same commit, and their errors compared by rule and crate.

| | Crates reported by both | By cargo-deny only | By CargoScope only |
|---|---|---|---|
| First translation (commit `22495c9`) | 3 | 9 | 104 |
| After the fixes below (commit `834f525`) | 3 | 9 | 6 |

**22 of the 28 repositories give exactly the same result** (no error from either tool).

The fixes the comparison led to:

- cargo-deny checks the graph of the **default features**; the first translation checked the whole `Cargo.lock`.
- `{ name = "x", deny-multiple-versions = true }` denies the duplicates of x, not x itself (bevy); it was read as a ban.
- `wrappers` of a ban, `skip-tree`, `exclude-unpublished` and cargo-deny's default `multiple-versions-include-dev = false` (duplicates pulled in only by dev-dependencies do not count) were added.
- A license with `+` ("or later", as `MPL-2.0+` in cargo's `im-rc`) was refused when its version is allowed. This also fixes `cargoscope.toml`.

What remains:

- **9 crates found by cargo-deny only**, all in pin-project-lite: its `[bans] build` rule (allowed build scripts). CargoScope has no such rule and says so in a note.
- **6 crates found by CargoScope only**, all reached only through internal workspace members or test harnesses (`compile_fail_utils` in bevy, `resolver-tests` in cargo, `limbo-harness-support` in rustls-webpki, ring's wasm test dependencies) or an Android-only path (`jni-sys` in wgpu). cargo-deny leaves them out for a reason not found yet; CargoScope is stricter there.

Every setting CargoScope cannot translate is listed in the report's warnings (for example `confidence-threshold`, `private`, `[bans] build`, `features`, `unused-allowed-license`).
