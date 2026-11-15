# Dependency Policy and Ignored Advisories (`cargoscope.toml`)

Put a `cargoscope.toml` next to the root `Cargo.toml` to enforce rules on every resolved package that is not part of the project itself. Without the file, no policy is checked.

```toml
[graph]
# Optional: limit every rule below to the packages these targets build.
# Without it, the whole lockfile (every platform) is checked.
targets = ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]

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

## Limiting the policy to some targets

`Cargo.lock` lists the dependencies of every platform, so by default a Windows-only crate with an unwanted license fails a Linux-only project. `[graph] targets` limits the license, source, ban and `multiple-versions` rules to the packages that at least one of the listed target triples builds (a duplicate counts only when two of its versions are built by the targets).

- The packages come from `cargo metadata --locked --filter-platform <target>`, which evaluates the `cfg(...)` of every dependency. The sources of the dependencies must be on disk: run `cargo fetch` first (this is also what cargo-deny needs). Nothing is compiled or run.
- If Cargo cannot answer (sources missing, unknown target, outdated lockfile), the scan stops with exit code 2 and Cargo's reason, rather than silently checking too much or too little.
- Targets are plain triples such as `x86_64-pc-windows-msvc`; anything else is an error.
- Advisories, unused dependencies, the package list and the "crates in several versions" listing still cover the whole lockfile. `[graph]` alone sets no rule.

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

This covers the license, source and ban checks most projects use, limited to the platforms you build for with `[graph] targets`. cargo-deny has more: license clarifications pinned to the hash of the license files, duplicate rules per version or with wrappers, feature bans, the feature graph, and advisory configuration. Use it when you need those.
