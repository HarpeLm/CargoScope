# Dependency Policy (`cargoscope.toml`)

Put a `cargoscope.toml` next to the root `Cargo.toml` to enforce rules on every resolved package that is not part of the project itself. Without the file, no policy is checked.

```toml
[licenses]
# Allowed licenses. An SPDX expression passes when some choice of its
# alternatives uses only allowed licenses: "MIT OR GPL-3.0" passes with MIT.
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]
# Denied licenses, checked even when `allow` is empty.
deny = ["GPL-3.0-only"]
# Packages whose license is unknown: "deny" (default) or "allow".
unknown = "deny"

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
```

## Behaviour

- Violations are listed in the report with the dependency path that pulls the package in, in text, JSON (`policy`) and SARIF (`cargoscope/policy-license`, `-source`, `-ban`, level `error`).
- **Violations fail the scan** (exit code 1) unless `--fail-on none`.
- License rules need crates.io data: run `cargoscope update` first. Without it they are skipped, with a warning.
- Licenses are compared without case. `WITH` exceptions never make a license unacceptable. The legacy form `MIT/Apache-2.0` is read as `MIT OR Apache-2.0`.
- The file is strict: an unknown key, a wrong type, an invalid license expression or version requirement, or a ban without a reason is an error (exit code 2), so that a typo never silently disables a rule.
- `--checks` without `policy` skips the policy.

## Compared with cargo-deny

This covers the license, source and ban checks most projects use. cargo-deny has more: license clarifications, per-crate exceptions, duplicate-version rules, feature bans, and advisory configuration. Use it when you need those.
