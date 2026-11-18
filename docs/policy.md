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
# Also check the project's own packages (workspace members, path dependencies),
# as cargo-deny does (default: false).
include-workspace = true
# Minimum score for a license text recognised in a LICENSE or COPYING file,
# used when a package has no usable `license` field (default: 0.8).
confidence-threshold = 0.8
# Allowed licenses that no checked package uses: "allow" (default), "warn" or "deny".
unused-allowed-license = "warn"

[licenses.private]
# Skip the licenses of unpublished packages (publish = false, or published
# only to the registries below) and of packages from the ignored sources.
ignore = true
registries = ["my-company"]
ignore-sources = ["https://registry.example.com/index"]

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
# Files inside the crates that run code at build time (see below).
executables = "deny"            # "allow" turns the inspection off
interpreted = "warn"            # #! scripts (default: "allow")
script-extensions = ["sh"]      # extra extensions that are errors
enable-builtin-globs = false    # also deny *.py, *.sh, *.bat, *.js...
include-dependencies = false    # also inspect what build-time crates depend on
include-archives = false        # count static archives (.a) as executables
bypass = [
  { crate = "ring", allow-globs = ["crypto/**"], allow = [{ path = "pregenerated/x.o", checksum = "<sha-256>" }] },
  { crate = "openssl-src", build-script = "<sha-256 of build.rs>", required-features = ["vendored"] },
]
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
- Advisories, unused dependencies, the package list and the "crates in several versions" listing still cover the whole lockfile, while `[graph]` also scopes **advisory relevance ranking** (marking unbuilt crates or mismatched platforms as `unlikely`), even if no license, ban or source rule is set. `[graph]` alone defines no policy violations.
- On the 15 repositories of the [first blind benchmark](../tests/corpus/blind-benchmark.md), `[graph] exclude-dev = true` gives exactly the 4 license findings cargo-deny gives, against 8 for the whole lockfile.

## Executables and scripts inside crates

A build script or a proc-macro runs on your machine (and in CI) at build time: a prebuilt binary or a script shipped next to it can run too. With a `[bans.build]` table, CargoScope inspects, as cargo-deny 0.20 does, every file of the crates that have a build script or a proc-macro (and, with `include-dependencies`, of what they depend on):

- a native executable (ELF, PE, Mach-O; static archives with `include-archives`), recognised by its first bytes whatever its name, is an error;
- a script recognised by its `#!` line follows `interpreted` (allowed by default);
- a file whose extension is in `script-extensions` (and cargo-deny's built-in list with `enable-builtin-globs`) is an error;
- `bypass` allows files of one crate by exact path (with an optional SHA-256 that must still match) or by `allow-globs`, or skips a whole crate whose build script still has the given SHA-256, unless one of its `required-features` is enabled. Entries that match nothing are reported, so they do not linger.

Workspace members are inspected only with `include-workspace`, git dependencies never (as in cargo-deny), and a crate whose build script is not in `allow-build-scripts` is reported for that alone. The sources must be on disk (`cargo fetch`). `executables = "allow"` turns the inspection off.

## Where licenses come from

For each package the license rules check, in this order (as cargo-deny 0.20 does):

1. a `clarify` entry that applies (and whose `license-files` hashes match);
2. the `license` field: from the crates.io data downloaded by `cargoscope update`, or from the package's own `Cargo.toml` for the project's packages (with `license.workspace = true` read from `[workspace.package]`), git dependencies and other registries;
3. when there is no `license` field, or it cannot be read: the texts of the package's `LICENSE*` and `COPYING*` files, and of its `license-file`, matched against the SPDX license list with the same license store and settings as cargo-deny. Every license found with a score of at least `confidence-threshold` is required: two files with MIT and Zlib give `MIT AND Zlib`. A violation on such a license says where it was found, for example `(detected in LICENSE-MIT)`; files whose text matches nothing well enough are named in a warning.

Steps 2 and 3 read the package sources on disk: run `cargo fetch` first. A package whose sources are missing keeps its crates.io data, with a warning.

## Using an existing deny.toml

A project that already uses cargo-deny needs no `cargoscope.toml`: when there is none, CargoScope reads the rules of `deny.toml` (or `.deny.toml`, `.cargo/deny.toml`) and says so in a warning. As soon as a `cargoscope.toml` exists, it is the only file read.

| deny.toml | CargoScope |
|---|---|
| `[graph] targets` (strings or `{ triple }`), `features`, `all-features`, `no-default-features`, `exclude-dev`, `exclude-unpublished` (default: default features, as cargo-deny) | the same `[graph]` keys |
| `[licenses] allow`, `exceptions`, `clarify`, `include-dev`, `confidence-threshold`, `unused-allowed-license`, `private` (`ignore`, `registries`, `ignore-sources`) | the same (`include-dev` defaults to `false`, leaving dev-only dependencies out of license checks unless `true`), including `license-files` 32-bit xxHash checksums, with `crate = "name"`, `"name@version"` or `name`/`version`; a missing reason becomes "from deny.toml". As in cargo-deny, the project's own packages are checked too (`include-workspace = true`), `unused-allowed-license` defaults to `"warn"`, and an empty `allow` list rejects every license |
| `[bans] deny` (with `wrappers`; `deny-multiple-versions` on a crate), `features`, `build` (`allow-build-scripts`, `include-workspace`, `executables`, `interpreted`, `script-extensions`, `enable-builtin-globs`, `include-dependencies`, `include-archives`, `bypass`), `multiple-versions` (`"deny"` / `"warn"`), `skip`, `skip-tree`, `multiple-versions-include-dev` | bans with wrappers, feature rules (`allow`, `deny`, `exact`), build-script allowlists, duplicate rules per crate (ignoring `semver-trick` self-dependencies), `skip-multiple-versions`, skipped trees; duplicates of dev-dependencies left out unless `multiple-versions-include-dev = true` |
| `[sources] unknown-registry`/`unknown-git` (`"deny"` / `"warn"` / `"allow"`), `allow-registry`, `allow-git`, `allow-org` | `allow-registries`, `allow-git` with per-source `"deny"` / `"warn"` / `"allow"` levels (an organisation becomes its URL prefix) |
| `[advisories] ignore` (IDs or `{ id, reason }`) | `[advisories] ignore` |

When reading `deny.toml` on a manifest with a root `[package]`, CargoScope also follows cargo-deny's default of rooting the dependency graph at that root package instead of adding `--workspace` (unless exclusions are configured). What has no equivalent is listed in the report's warnings, never dropped in silence: for example advisory settings such as `unmaintained`. The reading is tolerant: an unknown key is a note, not an error, unlike in `cargoscope.toml`.

On the original 28-repository comparison against cargo-deny 0.20.2, CargoScope now matches **28 of 28 repositories** (12 crates reported by both, 0 by cargo-deny only, 0 by CargoScope only), and **32 of 34 valid repositories** across the expanded corpora (31 crates reported by both, 1 by cargo-deny only in `tower-http`, 2 by CargoScope only in `portable-atomic` from workspace feature unification): see [tests/corpus/deny-toml.md](../tests/corpus/deny-toml.md).

## Ignoring an advisory

```toml
[advisories]
# Do not fail --fail-on when an advisory is ranked `unlikely`
# (dev-only, unbuilt by [graph], mismatched target, or uncalled affected function).
ignore-unlikely = true
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
- License rules need crates.io data: run `cargoscope update` first. Without it they are skipped for crates.io packages, with a warning; the project's own packages and licenses read from disk are still checked.
- Licenses are compared without case. `WITH` exceptions never make a license unacceptable. The legacy form `MIT/Apache-2.0` is read as `MIT OR Apache-2.0`.
- The file is strict: an unknown key, a wrong type, an invalid license expression or version requirement, or a ban without a reason is an error (exit code 2), so that a typo never silently disables a rule.
- `--checks` without `policy` skips the policy.
- A license `exceptions` entry adds its licenses to `allow` (when `allow` is not empty) and removes them from `deny`, for the matching crate only. A `clarify` entry replaces the crate's license everywhere in the report (the licenses list, JSON, SARIF) and is checked even without crates.io data; a violation on it says "clarified in cargoscope.toml". Entries that match no package of the lockfile give a warning, so they do not linger after a crate is gone.

## Compared with cargo-deny

This covers the license, source, build-script and ban checks projects use (including `license-files` xxHash32 verification, `[bans.build] allow-build-scripts`, and `"warn"` lint levels), limited to the build you care about with `[graph]` (targets, features, dev-dependencies). The license check now does what cargo-deny's does: license texts recognised from `LICENSE`/`COPYING` files with `confidence-threshold`, the project's own packages, `[licenses.private]` and `unused-allowed-license`. Executables and scripts inside build-time crates are inspected as well. cargo-deny still has advisory settings such as `unmaintained` or `unsound` levels. Use it when you need those; CargoScope reads your `deny.toml` meanwhile.
