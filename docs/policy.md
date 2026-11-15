# Dependency Policy and Ignored Advisories (`cargoscope.toml`)

Put a `cargoscope.toml` next to the root `Cargo.toml` to enforce rules on every resolved package that is not part of the project itself. Without the file, no policy is checked.

```toml
[graph]
# Optional: limit every rule below to the packages a build uses.
# Without [graph], the whole lockfile (every platform, every feature) is checked.
targets = ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]   # default: every platform
features = ["tls"]              # features to enable ("member/feature" in a workspace)
all-features = false
no-default-features = false
exclude-dev = true              # leave out what only dev-dependencies pull in

[licenses]
# Allowed licenses. An SPDX expression passes when some choice of its
# alternatives uses only allowed licenses: "MIT OR GPL-3.0" passes with MIT.
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]
# Denied licenses, checked even when `allow` is empty.
deny = ["GPL-3.0-only"]
# Packages whose license is unknown: "deny" (default) or "allow".
unknown = "deny"
# Licenses allowed for one crate only (optional version requirement), even
# when `deny` lists them. A reason is required.
exceptions = [
  { name = "ring", version = "^0.17", allow = ["ISC", "OpenSSL"], reason = "reviewed by legal" },
]
# The license of a crate whose metadata is wrong or missing: the expression
# replaces the crate's own in the report and in the rules. Optional
# `license-files` verify 32-bit xxHash checksums against unpacked crate sources.
clarify = [
  { name = "webpki", expression = "ISC", reason = "LICENSE file checked on 2026-11-15", license-files = [{ path = "LICENSE", hash = 0x12345678 }] },
]

[sources]
# Allowed registries: "crates.io" or a registry index URL.
# When [sources] is present and this key is not, only crates.io is allowed.
allow-registries = ["crates.io"]
# Allowed git repository URL prefixes.
allow-git = ["https://github.com/myorg/"]
# Optional levels for unlisted sources: "deny" (default), "warn", or "allow".
unknown-registry = "deny"
unknown-git = "deny"

[bans]
# Banned crates, with an optional version requirement and a required reason.
deny = [
  { name = "openssl", reason = "use rustls" },
  { name = "time", version = "<0.2.23", reason = "RUSTSEC-2020-0071" },
]
# Feature constraints for a crate (`allow`, `deny`, `exact`, optional `version` and `reason`).
features = [
  { name = "getrandom", version = "^0.2", allow = ["std", "js"], exact = true, reason = "wasm needs js" },
  { name = "derive_more", deny = ["error"], reason = "keep errors minimal" },
]
# "deny" fails the scan, "warn" reports warnings with exit code 0
# (default "allow": duplicates are only listed in the report).
multiple-versions = "deny"
# Crates accepted in several versions anyway.
skip-multiple-versions = ["windows-sys"]

[bans.build]
# Optional allowlist of crates permitted to run a custom `build.rs` script.
allow-build-scripts = ["cc", "ring@^0.17"]
# Whether workspace members with build scripts are checked too (default: false).
include-workspace = false
```

## Limiting the policy to a build: targets, features, dev-dependencies

`Cargo.lock` lists the dependencies of every platform and every feature, so by default a Windows-only crate, or a crate behind a feature you never enable, with an unwanted license fails the policy. With a `[graph]` table, the license, source, ban and `multiple-versions` rules only apply to the packages that build uses (a duplicate counts only when two of its versions are used):

- `targets`: the platforms (target triples) to consider; without it, every platform.
- `features`, `all-features`, `no-default-features`: the features of the project, as with `cargo build`; without them, the default features. `features = []` alone selects the default features on every platform.
- `exclude-dev`: leaves out the packages that only the project's dev-dependencies pull in (test and benchmark tools).

How it works:

- The packages come from `cargo tree --workspace --locked` with those targets, features and edges, which runs Cargo's own feature resolver. (`cargo metadata` is not used: its graph ignores the feature flags.) The sources of the dependencies must be on disk: run `cargo fetch` first (this is also what cargo-deny needs). Nothing is compiled or run.
- If Cargo cannot answer (sources missing, unknown target or feature, outdated lockfile), the scan stops with exit code 2 and Cargo's reason, rather than silently checking too much or too little.
- Targets are plain triples such as `x86_64-pc-windows-msvc`; anything else is an error.
- Advisories, unused dependencies, the package list and the "crates in several versions" listing still cover the whole lockfile. `[graph]` alone sets no rule.
- On the 15 repositories of the [first blind benchmark](../tests/corpus/blind-benchmark.md), `[graph] exclude-dev = true` gives exactly the 4 license findings cargo-deny gives, against 8 for the whole lockfile.

## Using an existing deny.toml

A project that already uses cargo-deny needs no `cargoscope.toml`: when there is none, CargoScope reads the rules of `deny.toml` (or `.deny.toml`, `.cargo/deny.toml`) and says so in a warning. As soon as a `cargoscope.toml` exists, it is the only file read.

| deny.toml | CargoScope |
|---|---|
| `[graph] targets` (strings or `{ triple }`), `features`, `all-features`, `no-default-features`, `exclude-dev`, `exclude-unpublished` (default: default features, as cargo-deny) | the same `[graph]` keys |
| `[licenses] allow`, `exceptions`, `clarify`, `include-dev` | the same (`include-dev` defaults to `false`, leaving dev-only dependencies out of license checks unless `true`), including `license-files` 32-bit xxHash checksums, with `crate = "name"`, `"name@version"` or `name`/`version`; a missing reason becomes "from deny.toml" |
| `[bans] deny` (with `wrappers`; `deny-multiple-versions` on a crate), `features`, `build` (`allow-build-scripts`, `include-workspace`), `multiple-versions` (`"deny"` / `"warn"`), `skip`, `skip-tree`, `multiple-versions-include-dev` | bans with wrappers, feature rules (`allow`, `deny`, `exact`), build-script allowlists, duplicate rules per crate (ignoring `semver-trick` self-dependencies), `skip-multiple-versions`, skipped trees; duplicates of dev-dependencies left out unless `multiple-versions-include-dev = true` |
| `[sources] unknown-registry`/`unknown-git` (`"deny"` / `"warn"` / `"allow"`), `allow-registry`, `allow-git`, `allow-org` | `allow-registries`, `allow-git` with per-source `"deny"` / `"warn"` / `"allow"` levels (an organisation becomes its URL prefix) |
| `[advisories] ignore` (IDs or `{ id, reason }`) | `[advisories] ignore` |

When reading `deny.toml` on a manifest with a root `[package]`, CargoScope also follows cargo-deny's default of rooting the dependency graph at that root package instead of adding `--workspace` (unless exclusions are configured). What has no equivalent is listed in the report's warnings, never dropped in silence: for example `confidence-threshold`, `private`, `[bans.build]` executable/interpreter/bypass rules, and advisory settings such as `unmaintained`. The reading is tolerant: an unknown key is a note, not an error, unlike in `cargoscope.toml`.

On the original 28-repository comparison against cargo-deny 0.20.2, CargoScope now matches **28 of 28 repositories** (12 crates reported by both, 0 by cargo-deny only, 0 by CargoScope only), and **32 of 34 valid repositories** across the expanded corpora (31 crates reported by both, 1 by cargo-deny only in `tower-http`, 2 by CargoScope only in `portable-atomic` from workspace feature unification): see [tests/corpus/deny-toml.md](../tests/corpus/deny-toml.md).

## Ignoring an advisory

```toml
[advisories]
ignore = [
  # Matched by advisory ID or by alias (CVE, GHSA).
  { id = "RUSTSEC-2020-0071", reason = "time is only used by a build tool" },
  # Optional last day; afterwards the advisory counts again.
  { id = "CVE-2024-1234", reason = "fix planned for the next release", until = "2027-01-31" },
]
```

- An ignored advisory **stays in the report**, with its reason, but never fails the scan or `compare`.
- In SARIF it is a suppressed result (`suppressions`, kind `external`, with the reason as justification), so code scanning shows it as dismissed.
- The JSON report carries the reason in `ignored_reason`.
- After its `until` date, an ignore stops applying, with a warning.
- An ignore that matches no advisory of the project produces a warning, so that stale entries get removed.
- A reason is required; an entry without one is an error.

A file with only `[advisories]` defines no policy.

## Behaviour of the policy

- Violations are listed in the report with their level (`error` or `warning`) and the dependency path that pulls the package in, in text, JSON (`policy`) and SARIF (`cargoscope/policy-license`, `-source`, `-ban`, `-multiple-versions`).
- **`error` violations fail the scan** (exit code 1) unless `--fail-on none`; **`warning` violations** (from `"warn"` levels) are reported cleanly in text, JSON and SARIF with exit code 0.
- License rules need crates.io data: run `cargoscope update` first. Without it they are skipped, with a warning.
- Licenses are compared without case. `WITH` exceptions never make a license unacceptable. The legacy form `MIT/Apache-2.0` is read as `MIT OR Apache-2.0`.
- The file is strict: an unknown key, a wrong type, an invalid license expression or version requirement, or a ban without a reason is an error (exit code 2), so that a typo never silently disables a rule.
- `--checks` without `policy` skips the policy.
- A license `exceptions` entry adds its licenses to `allow` (when `allow` is not empty) and removes them from `deny`, for the matching crate only. A `clarify` entry replaces the crate's license everywhere in the report (the licenses list, JSON, SARIF) and is checked even without crates.io data; a violation on it says "clarified in cargoscope.toml". Entries that match no package of the lockfile give a warning, so they do not linger after a crate is gone.

## Compared with cargo-deny

This covers the license, source, build-script and ban checks projects use (including `license-files` xxHash32 verification, `[bans.build] allow-build-scripts`, and `"warn"` lint levels), limited to the build you care about with `[graph]` (targets, features, dev-dependencies). cargo-deny has a few extra checks: binary/script/bypass scanning inside crates, `confidence-threshold` text matching from local license files without `clarify`, and advisory checks like `unmaintained` or `unsound`. Use it when you need those; CargoScope reads your `deny.toml` meanwhile.
