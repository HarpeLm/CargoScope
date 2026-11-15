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
# replaces the crate's own in the report and in the rules.
clarify = [
  { name = "webpki", expression = "ISC", reason = "LICENSE file checked on 2026-11-15" },
]

[sources]
# Allowed registries: "crates.io" or a registry index URL.
# When [sources] is present and this key is not, only crates.io is allowed.
allow-registries = ["crates.io"]
# Allowed git repository URL prefixes.
allow-git = ["https://github.com/myorg/"]

[bans]
# Banned crates, with an optional version requirement and a required reason.
deny = [
  { name = "openssl", reason = "use rustls" },
  { name = "time", version = "<0.2.23", reason = "RUSTSEC-2020-0071" },
]
# "deny" makes every crate resolved in several versions a violation
# (default "allow": they are only listed in the report).
multiple-versions = "deny"
# Crates accepted in several versions anyway.
skip-multiple-versions = ["windows-sys"]
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
| `[graph] targets` (strings or `{ triple }`), `features`, `all-features`, `no-default-features`, `exclude-dev` | the same `[graph]` keys |
| `[licenses] allow`, `exceptions`, `clarify` | the same, with `crate = "name"`, `"name@version"` or `name`/`version`; a missing reason becomes "from deny.toml" |
| `[bans] deny`, `multiple-versions = "deny"`, `skip` | `[bans] deny`, `multiple-versions = "deny"`, `skip-multiple-versions` |
| `[sources] unknown-registry`/`unknown-git = "deny"`, `allow-registry`, `allow-git`, `allow-org` | `allow-registries`, `allow-git` (an organisation becomes its URL prefix) |
| `[advisories] ignore` (IDs or `{ id, reason }`) | `[advisories] ignore` |

What has no equivalent is listed in the report's warnings, never dropped in silence: for example `confidence-threshold`, the hashes of `license-files` (a clarification is not tied to the license files), `wrappers` (the ban then applies everywhere), `skip-tree`, feature bans, `"warn"` levels (a duplicate or a source at `"warn"` is shown but does not fail), and advisory settings such as `unmaintained`. The reading is tolerant: an unknown key is a note, not an error, unlike in `cargoscope.toml`.

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

- Violations are listed in the report with the dependency path that pulls the package in, in text, JSON (`policy`) and SARIF (`cargoscope/policy-license`, `-source`, `-ban`, level `error`).
- **Violations fail the scan** (exit code 1) unless `--fail-on none`.
- License rules need crates.io data: run `cargoscope update` first. Without it they are skipped, with a warning.
- Licenses are compared without case. `WITH` exceptions never make a license unacceptable. The legacy form `MIT/Apache-2.0` is read as `MIT OR Apache-2.0`.
- The file is strict: an unknown key, a wrong type, an invalid license expression or version requirement, or a ban without a reason is an error (exit code 2), so that a typo never silently disables a rule.
- `--checks` without `policy` skips the policy.
- A license `exceptions` entry adds its licenses to `allow` (when `allow` is not empty) and removes them from `deny`, for the matching crate only. A `clarify` entry replaces the crate's license everywhere in the report (the licenses list, JSON, SARIF) and is checked even without crates.io data; a violation on it says "clarified in cargoscope.toml". Entries that match no package of the lockfile give a warning, so they do not linger after a crate is gone.

## Compared with cargo-deny

This covers the license, source and ban checks most projects use, limited to the build you care about with `[graph]` (targets, features, dev-dependencies). cargo-deny has more: license clarifications pinned to the hash of the license files, duplicate rules per version or with wrappers, feature bans, and advisory configuration. Use it when you need those; CargoScope reads your `deny.toml` meanwhile.
