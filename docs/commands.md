# Command Reference

Detailed usage for every CargoScope command and report section. See [docs/policy.md](policy.md) for `cargoscope.toml` and `deny.toml` policy rules, [docs/github-action.md](github-action.md) for the GitHub Action, [docs/github-app.md](github-app.md) for the 1-click hosted GitHub App (`cargoscope-bot[bot]`), and [docs/compatibility.md](compatibility.md) for `1.x` stability guarantees.

## Contents

- [`cargoscope update`](#cargoscope-update)
- [`cargoscope scan`](#cargoscope-scan)
- [`--precise` (compiler-accurate unused mode)](#--precise-compiler-accurate-unused-mode)
- [`cargoscope compare` and baselines](#cargoscope-compare-and-baselines)
- [`cargoscope aggregate`](#cargoscope-aggregate)
- [`cargoscope why`](#cargoscope-why)
- [`cargoscope audit-bin`](#cargoscope-audit-bin)
- [`cargoscope init`](#cargoscope-init)
- [`cargoscope fix`](#cargoscope-fix)
- [Report Sections & Ignores](#report-sections--ignores)

---

## `cargoscope update`

Downloads the [RustSec](https://rustsec.org/) advisory database archive and crates.io metadata for packages in `Cargo.lock` into the local cache (`CARGOSCOPE_CACHE_DIR` overrides the default cache location):

```sh
cargoscope update .            # full update (advisories, versions, licenses, maintenance indicators)
cargoscope update --fast .     # skip 1 req/s maintenance requests (alias: --no-maintenance)
```

- **Maintenance indicators** fetch crates.io owners (1 request per second, per crates.io crawler policy) and GitHub repository archived status (uses `GITHUB_TOKEN` or `GH_TOKEN` when set; unauthenticated limit is 60 req/hour and unknown statuses are retried on the next update). Maintenance data is cached for 7 days per crate.
- Use `cargoscope scan . --update [--fast]` to refresh data and scan in one command.

### Proxy support

`cargoscope update` honors `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` (uppercase or lowercase) with `http://[user:password@]host:port`. `NO_PROXY` matches exact hosts or suffixes (`*`, `crates.io`, `.example.com`); `localhost` always connects directly. Only `http://` proxies are supported, and an invalid proxy configuration fails explicitly rather than silently bypassing the proxy.

---

## `cargoscope scan`

Reads `Cargo.lock`, manifests, `cargoscope.toml` / `deny.toml`, and `.rs` files directly without executing project code:

```sh
cargoscope scan .                                              # default Telemetry HUD (offline)
cargoscope scan . --checks inventory,unused                    # structural + unused checks only (zero downloads needed)
cargoscope scan . --checks inventory,unsafe                    # count unsafe usage in dependencies on disk only
cargoscope scan . --update --fast                              # refresh data then scan
cargoscope scan . --format json --output report.json           # versioned JSON (docs/schema/report-v1.json)
cargoscope scan . --format sarif --output results.sarif        # SARIF 2.1.0 for GitHub Code Scanning
cargoscope scan . --format cyclonedx --output bom.cdx.json     # CycloneDX 1.5 SBOM + VEX not_affected
cargoscope scan . --format html --output report.html           # self-contained offline HTML report
cargoscope scan . --fail-on high                               # exit 1 only on high/critical vulnerabilities
cargoscope scan . --fail-on high --ignore-unlikely             # also skip unlikely advisories
cargoscope scan . --rustsec-only                               # RustSec advisories only, as cargo-audit reports
cargoscope scan . --fail-on none                               # always exit 0 unless execution error
cargoscope scan . --show-uncertain                             # include possibly-unused dependencies
cargoscope scan . --verbose                                    # full listing of all packages & advisories
cargoscope scan . --color auto|always|never                    # override terminal styling (also honors NO_COLOR)
```

**Exit codes:** `0` = OK, `1` = finding reached `--fail-on` or policy error, `2` = execution, usage, or configuration error.

### Advisory sources

`cargoscope update` downloads the [RustSec advisory database](https://github.com/rustsec/advisory-db) and the crates.io export of [OSV](https://osv.dev). From OSV, CargoScope keeps only what RustSec does not have: GitHub security advisories (`GHSA-…`) and malicious crates (`MAL-…`, always reported as critical). An OSV entry whose ID or alias (a CVE, say) is an alias of a RustSec advisory is the same issue and is left out, so nothing is reported twice. RustSec stays the source of the affected functions, operating systems and architectures that rank relevance; OSV advisories carry none, so they are ranked by dependency kind and build scope only.

`--rustsec-only` reports RustSec advisories alone, which is what `cargo-audit` reports. If OSV cannot be downloaded, `update` prints a warning and scans use RustSec alone.

### Unsafe code

A scan counts the uses of `unsafe` in every dependency whose sources are on disk (run `cargo fetch` first): `unsafe` blocks, `unsafe fn` items and `unsafe extern` blocks, `unsafe impl`, `unsafe trait`, and other uses such as `#[unsafe(no_mangle)]`. A Rust lexer reads the files under `src/` and the build script, so comments and strings never count, and nothing is compiled. The terminal report ranks the direct dependencies; `--verbose` lists every crate, generated bindings such as `windows` included. Published versions never change, so their counts are cached and later scans read them back.

### Published audits

`cargoscope update` downloads the audits listed in the [cargo-vet registry](https://github.com/mozilla/cargo-vet/blob/main/registry.toml): Mozilla, Google, the Bytecode Alliance, Zcash and others publish which crate versions they reviewed, as `safe-to-deploy` (fit to ship) or `safe-to-run` (fit for tests and development). A version counts as audited when an organisation reviewed it in full, or reviewed the changes from a version it had audited before (`delta` audits). The report shows how many crates.io packages are audited and which direct dependencies have no audit of the version in use; `--verbose` names the criteria and reviewers of each direct dependency. Publisher-based `trusted` entries are not used, since crates.io does not record who published a version, so a crate its owner is trusted for may still show as not audited.

### Freshness

A scan warns when the advisory data is more than 7 days old: advisories published after the download are missing until `cargoscope update` runs again. With crates.io data, the report also lists resolved versions published less than 72 hours before the scan (`RECENT RELEASES`). Compromised releases are usually caught and yanked within days, so a brand-new version deserves a look before you rely on it.

### Advisory relevance (`affects-you`, `possibly`, `unlikely`)

Each advisory is ranked against what the project actually builds (using `cargo tree --offline --locked --all-features --target all`, or `[graph]` in `cargoscope.toml` when configured):

- **`affects-you`**: reachable in normal/build dependencies on matching targets/platforms and (when `[affected.functions]` are specified) called in source identifiers.
- **`possibly`**: partial mismatch or unverified build graph (for example before `cargo fetch`).
- **`unlikely`**: only reachable via `[dev-dependencies]`, gated out by `[graph]` targets/features, mismatched `[affected]` OS/arch, or all `[affected.functions]` absent from project source identifiers.

### Feature hints

Under `--checks unused` (included by default), CargoScope flags conservative, high-impact dependency feature bloat such as `tokio = { features = ["full"] }`, `syn = { features = ["full"] }`, `serde = { features = ["derive"] }`, `clap = { features = ["derive"] }`, `reqwest`, `sqlx`, or `uuid` features when no matching API, module, or derive trait appears in parsed sources (skipping public re-exports, glob imports, forwarded `[features]`, and incomplete scans). Hints are strictly informational and never fail CI or edit `Cargo.toml`.

In CycloneDX exports, ignored and `unlikely` advisories carry VEX `analysis.state = "not_affected"`. Pass `--ignore-unlikely` (or set `[advisories] ignore-unlikely = true` in `cargoscope.toml`) to exclude `unlikely` findings from `--fail-on` failure thresholds.

---

## `--precise` (compiler-accurate unused mode)

```sh
cargoscope scan . --precise
```

> **Trust boundary:** `--precise` runs `cargo check --workspace --all-targets --all-features` inside `target/cargoscope-precise`, which **compiles the project and runs `build.rs` scripts and procedural macros**. Only run `--precise` on repositories you trust.

- On **Rust `< 1.100`**: reads `rustc`'s JSON `unused_crate_dependencies` lint across normal, dev, and build targets.
- On **Rust `>= 1.100`**: reads Cargo's native `cargo::unused_dependencies` lint for normal and build dependencies; `[dev-dependencies]` (which Cargo's lint skips) keep their static CargoScope result. Note that Cargo `1.100`'s lint also skips normal dependencies that appear transitively elsewhere in the dependency graph.
- When the compiler flags a crate despite CargoScope finding a static reference in sources or doctests (such as doctest-only dev-dependencies or `#[cfg(not(feature = "std"))]` code masked by `--all-features`), CargoScope keeps the finding as `possibly-unused` rather than `likely-unused`.
- Measured across 76 repositories (72 compiling, 8,158 packages): `100.0%` precision (`16/16`) on the 35-repo blind held-out set — see [tests/corpus/precise-benchmark.md](../tests/corpus/precise-benchmark.md).

---

## `cargoscope compare` and baselines

```sh
cargoscope scan . --format json --output baseline.json   # once, on main
cargoscope scan . --baseline baseline.json                # fail only on advisories absent from baseline
cargoscope compare baseline.json current.json             # diff advisories, yanked, unused, duplicates, versions
cargoscope compare baseline.json current.json --format json
cargoscope compare baseline.json current.json --format markdown --ignore-unlikely
```

`compare` exits with `1` when new advisories reach `--fail-on` (supporting `--ignore-unlikely` and `--color`).

---

## `cargoscope aggregate`

Merge multiple JSON scan reports across repositories or services into a single portfolio view:

```sh
cargoscope aggregate api.json worker.json cli.json
cargoscope aggregate reports/*.json --format html --output org-report.html
cargoscope aggregate reports/*.json --format json --output org-report.json
```

Combines shared advisories (with relevance), policy violations, licenses, outdated direct dependencies, and unused dependencies.

---

## `cargoscope why`

Explains why a crate exists in `Cargo.lock`:

```sh
cargoscope why quick-xml
cargoscope why quick-xml@0.39.2 --all-paths
cargoscope why quick-xml --format json
```

```text
quick-xml 0.39.2 [transitive]
  weight: 1 exclusive of 2 packages in its subtree
  advisories (2): HIGH RUSTSEC-2026-0194, HIGH RUSTSEC-2026-0195
  fix: 0.41.0, which wayland-scanner 0.31.10 does not accept yet: a new wayland-scanner release has to allow it first
  dependents (1): wayland-scanner 0.31.10
  used by members: data, halloy, ipc
  paths from root (54, through 2 direct dependencies, shortest of each):
    data 0.1.0 -> display-info 0.5.10 -> smithay-client-toolkit 0.20.0 -> wayland-scanner 0.31.10 -> quick-xml 0.39.2  +16 more
    data 0.1.0 -> iced 0.15.0-dev -> iced_winit 0.15.0-dev -> winit 0.30.8 -> smithay-client-toolkit 0.19.2 -> wayland-scanner 0.31.10 -> quick-xml 0.39.2  +36 more  also from halloy
  --all-paths lists every path
```

- **advisories** and **fix** come from the data of the last `cargoscope update` (offline). The fix is the smallest version that fixes every vulnerability: `cargo update` when it is within the SemVer range already required, a new requirement in `Cargo.toml` for a direct dependency, or, for a transitive crate, the crates that have to accept it first.
- **yanked** shows when the version was withdrawn from crates.io.
- **paths from root** counts every chain once, from the workspace member closest to the crate, and shows the shortest chain through each direct dependency with how many others go through it. `--all-paths` lists the chains themselves (up to 500).
- **weight** is how many packages would leave `Cargo.lock` without the crate.
- JSON gives all of it: `advisories`, `fix`, `yanked`, `members`, `path_count`, `routes` and the first `paths`.

---

## `cargoscope audit-bin`

Audits a compiled Rust binary on disk without executing it:

```sh
cargoscope update
cargoscope audit-bin target/release/my-app
cargoscope audit-bin target/release/my-app --format sarif --output bin.sarif
```

- Exact when the binary was built with [`cargo auditable build`](https://github.com/rust-secure-code/cargo-auditable) (reads the embedded zlib dependency tree).
- Falls back to crate paths retained in panic/unwind strings when `cargo-auditable` metadata is absent (less complete, clearly labeled in the report).
- Supports `--format text|json|sarif|cyclonedx|html`, `--output FILE`, `--fail-on`, `--color`, `--verbose`.

---

## `cargoscope init`

Bootstraps configuration and CI in one command:

```sh
cargoscope init            # generates starter cargoscope.toml (or migrates deny.toml + .cargo/audit.toml)
cargoscope init --ci       # also generates .github/workflows/cargoscope.yml
cargoscope init --dry-run  # preview generated files without writing
cargoscope init --force    # overwrite existing files
```

---

## `cargoscope fix`

### Removing unused dependencies

```sh
cargoscope fix .                       # dry run (likely-unused only)
cargoscope fix . --apply               # edit Cargo.toml manifests with toml_edit
cargoscope fix . --only rand,log       # restrict to specific dependencies
cargoscope fix . --include-uncertain   # also include possibly-unused findings
cargoscope fix . --precise --apply     # confirm with compiler before removing
cargoscope fix . --apply --verify      # run `cargo check --workspace --all-targets` and roll back on failure
cargo check                            # update Cargo.lock after applying
```

Removes unused entries from `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, and `[target.'...']` tables while preserving formatting and unrelated comments; automatically strips `dep:<crate>`, `<crate>/feature`, and `<crate>?/feature` from `[features]`; and removes orphaned entries from `[workspace.dependencies]` once no member uses them anymore. Never invokes `cargo` unless `--precise` or `--verify` is passed.

### Updating vulnerable packages (`--advisories`)

```sh
cargoscope fix --advisories .
cargoscope fix --advisories . --apply
cargoscope fix --advisories . --format markdown   # or json
cargoscope fix --advisories . --only chrono
```

Tries the smallest version that fixes **all** active advisories of each crate without introducing another advisory in the RustSec database:

1. First runs `cargo update -p <name>@<version> --precise <fixed> --dry-run` (lockfile-only resolution; never compiles code).
2. If a manifest requirement blocks the fix, retries with `set_requirement_for_version` updating matching declarations across `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, `[target.'...']`, member manifests, implicit local path crates, and `[workspace.dependencies]` (preserving pins such as `=0.4.19 -> =0.4.20`, `workspace = true` inheritance in members, comments, and formatting, while leaving unrelated major version lines elsewhere in the workspace and `path`/`git` entries untouched).
3. Refuses edits when another dependency in the graph still keeps the vulnerable version in `Cargo.lock`, and prints Cargo's explanation. When earlier updates already pulled a crate past its target, skips or settles it back to the smallest fixed version.
4. When the fix is a breaking version that the crates pulling the package in do not accept (`xcb 1.7.0 requires quick-xml ^0.30.0`), updates those crates within the range already required (`cargo update -p xcb@1.7.0 --dry-run`) and keeps that plan if the package lands on a fixed version: on halloy, xcb 1.7.1 and wayland-scanner 0.31.11 take quick-xml 0.41.0.
5. Otherwise says which crates hold the fix back and whether a newer release of them is out (`a newer release may allow it: rusqlite 0.43.0 (a breaking update)`), instead of Cargo's raw resolution error. When nothing can be updated, the summary says so instead of suggesting `--apply`.

### Updating direct dependencies (`--updates`)

```sh
cargoscope update .
cargoscope fix --updates .                     # dry run: compatible upgrades (7-day cooldown by default)
cargoscope fix --updates . --cooldown-for serde=1 --apply
cargoscope fix --updates --breaking . --apply  # also upgrade across major/0.x lines in manifests
```

Moves direct crates.io dependencies to their newest SemVer-compatible version in `Cargo.lock` (or updates `git+...` commits and alternative-registry dependencies via `cargo update -p`), or across major versions with `--breaking` / `--versioning-strategy` when Cargo resolves cleanly (nothing is compiled).

- **7-day cooldown by default**: skips crates.io releases younger than `--cooldown DAYS` (default `7`, or configured via `[updates.cooldown]` in `cargoscope.toml` or `.github/dependabot.yml`). When a crate is held back, an older eligible non-yanked release is used if available, or you can override specific dependencies with `--cooldown-for CRATE=DAYS` (for example `--cooldown-for tokio=1`) or `[updates.cooldown.overrides]`. Does not apply to `fix --advisories`.
- **`--versioning-strategy STRATEGY`**: `auto` (default: lockfile when possible, raise bounds if pinned or `--breaking`), `lockfile-only` (refuse updates requiring manifest edits), `increase-if-necessary`, `increase` (always raise manifest bounds and allow breaking), or `widen` (widen restrictive ranges like `~1.2.0` / `=1.2.3` into `>=1.2.0, <X` or bump bounds cleanly).
- **Zero-line `.github/dependabot.yml` fallback**: if `cargoscope.toml` has no `[updates]` table, CargoScope automatically reads `.github/dependabot.yml` (`package-ecosystem: "cargo"`).

---

## Report Sections & Ignores

- **Crates in several versions (`duplicates`)**: resolved duplicates compiled separately, showing the shortest chain pulling each older version in (and failing CI when `[bans] multiple-versions = "deny"` is enabled).
- **Heaviest direct dependencies (`direct_weights`)**: counts packages that would leave `Cargo.lock` if the direct dependency were removed (`exclusive`), versus total packages in its subtree (`tree`). Normal dependencies sort before `(dev)` / `(build)`-only dependencies.
- **Maintenance indicators**: flags direct crates.io dependencies with an archived repository, no release in 2+ years (`stale`), or a single individual crates.io owner (`rust-lang-owner` counts as a team). Never fails scans.

### Ignoring advisories or unused dependencies

In `cargoscope.toml`:

```toml
[advisories]
ignore-unlikely = true
ignore = [
  { id = "RUSTSEC-2020-0071", reason = "only used by a build tool", until = "2027-01-31" },
]
```

In a package's `Cargo.toml`:

```toml
[package.metadata.cargoscope]
ignore-unused = [
  { name = "once_cell", reason = "used by code generated in build.rs" },
]
```

Both require a `reason`; ignored entries remain visible in reports with their reason and never fail CI.
