# Fixtures

Small Cargo projects used by integration tests. They are never built: CargoScope only reads their files.

| Fixture | Covers |
|---|---|
| `simple` | One package, direct and transitive dependencies |
| `workspace` | Explicit workspace members contributing direct dependencies |
| `renamed` | `package = "..."` renames and dev/build dependencies |
| `workspace-glob` | `members = ["crates/*"]` with an `exclude`d member |
| `workspace-macro` | A dependency used only through a `macro_rules!` of a sibling crate; library names that differ from package names (`[lib] name`, `tiny-bip39` used as `bip39`) |
| `multi-version` | Two versions of one crate: one direct, one pulled in transitively |
| `unused` | Every unused-detection case: comments, strings, macros, renames, `-sys`, optional, transitive with features, build script, ignore list |
| `policy` | A `cargoscope.toml` policy broken once by each rule (license, unknown license, git source, ban) |
| `no-lockfile` | Missing `Cargo.lock` (execution error, exit code 2) |

`advisory-cache` is a fake RustSec and crates.io cache used through `CARGOSCOPE_CACHE_DIR`. Its `CARGOSCOPE-TEST-*` advisories are invented for tests and do not describe real vulnerabilities.

Its `crates-io` folder holds invented version lists and licenses for `serde_json`, `serde` and `itoa` (the `itoa` version in use is marked yanked).
