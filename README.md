# CargoScope

**Understand every dependency in your Rust project: why it's there, what it risks, and what to do.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)

---

![cargoscope scan on a small project: two RustSec advisories with their dependency chain and fix, one unused dependency, licenses and outdated versions](docs/images/scan.gif)

CargoScope is an open-source CLI, written in Rust, for Rust/Cargo projects. One command produces one report: inventory, security advisories, available versions, licenses, likely-unused dependencies, and the dependency chain behind each finding. No more running cargo-audit, cargo-deny, cargo-machete and cargo-tree separately and reconciling their output.

## Principles

- **Local, no account**: the first scan needs no account and no online service.
- **Your code never leaves your machine**: nothing is uploaded.
- **No silent writes**: CargoScope never modifies your files, except `cargoscope fix --apply`, which you run on purpose.
- **Evidence first**: every finding shows its evidence, its source and the date of its data.
- **No code execution**: CargoScope reads files directly and never runs `cargo`, build scripts or project code by default.

## Status

**Version 0.5.1.** Unreleased on `main` (`0.6.0-dev`): added `[bans] features` (`allow`, `deny`, `exact`), `[bans.build]` (`allow-build-scripts`, `include-workspace`), `[licenses.clarify]` `license-files` `xxHash32` verification, `"warn"` lint levels, and aligned `deny.toml` parity with cargo-deny 0.20.2 (28 of 28 on the original corpus; 32 of 34 expanded). New in 0.5.1: without a `cargoscope.toml`, CargoScope reads cargo-deny's `deny.toml` (same result as cargo-deny on 22 of 28 projects in the recorded run), bans accept `wrappers`, and "or later" licenses such as `MPL-2.0+` pass when their version is allowed. New in 0.5.0: `cargoscope fix --advisories` updates vulnerable packages to the smallest fixed version Cargo accepts (editing `Cargo.lock`, and `Cargo.toml` when a direct requirement blocks the fix), the GitHub Action can open or update security update pull requests (`open-pr: true`), `cargoscope audit-bin` audits compiled binaries, `[graph]` limits `cargoscope.toml` policies to the build you care about (targets, features, `exclude-dev`, computed with `cargo tree`), `[licenses] exceptions` and `clarify` handle per-crate licenses, security pull requests can be one per package and close themselves when obsolete, `--precise` supports Cargo 1.100's `unused_dependencies` lint, and `cargoscope update` honours `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`. Since 0.4: `cargoscope fix` removes unused dependencies (dry run first), the heaviest direct dependencies, a `multiple-versions` policy rule, and sharper unused-dependency rules. Since 0.3.0, crates in several versions; since 0.2.0, pull request comments in the GitHub Action. `cargoscope update` downloads the RustSec advisory database and the crates.io data of a project; `cargoscope scan` then reports, offline, matching advisories, likely-unused dependencies with the evidence behind each one, licenses, yanked and outdated versions, a `cargoscope.toml` policy, and the dependency chain behind every finding, as text, JSON or SARIF. It is young: please report anything wrong in the [feedback issue](https://github.com/HarpeLm/CargoScope/issues/1).

**New here?** [Try CargoScope in two minutes](docs/try-it.md), then tell us how it went.

## Install

```sh
# Prebuilt binary, macOS and Linux
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/HarpeLm/CargoScope/releases/latest/download/cargoscope-installer.sh | sh

# Prebuilt binary, Windows (PowerShell)
irm https://github.com/HarpeLm/CargoScope/releases/latest/download/cargoscope-installer.ps1 | iex

# Homebrew
brew install HarpeLm/tap/cargoscope

# From crates.io
cargo install cargoscope

# Without installing, through npm
npx cargoscope scan .
```

From a clone of this repository: `cargo install --path crates/cargoscope-cli`.

## GitHub Action

On the GitHub Marketplace the action is listed as [**Dep Scout**](https://github.com/marketplace/actions/dep-scout) (the name CargoScope belongs to another GitHub account); it runs CargoScope.

```yaml
permissions:
  contents: read
  security-events: write   # to upload SARIF to code scanning
  pull-requests: write     # to comment on pull requests

jobs:
  cargoscope:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HarpeLm/CargoScope@v0.5.1
        with:
          fail-on: high        # or none, to report without failing
```

The action downloads the prebuilt binary (no compilation), caches advisory data for a day, prints the report in the log, and uploads SARIF results to the Security tab. Inputs: `version`, `path`, `fail-on`, `checks`, `sarif`, `upload-sarif`, `comment`, `new-only`.

On a pull request, the action also scans the base branch and comments with only what the pull request changes: new and resolved advisories, new yanked versions, new likely-unused dependencies, and added, removed or changed packages. A later run updates the same comment. Advisories already on the base branch do not fail the pull request (`new-only: false` to fail on all of them). Pull requests from forks get a read-only token: the comparison then goes to the job summary instead of a comment. The comment needs CargoScope 0.2.0 or later.

## Quick Start

```sh
# Download the RustSec database and this project's crates.io data (the only command that uses the network)
cargoscope update .

# Scan the current project, offline
cargoscope scan .
```

### Example Output

```
CargoScope 0.1.0
Target: .

Advisories: 1 (RustSec database downloaded 2026-11-12)
- RUSTSEC-2020-0071 [medium] time 0.1.45: Potential segfault in the time crate
    via my-app -> chrono -> time
    fix: upgrade to >= 0.2.23
    https://github.com/time-rs/time/issues/293

Resolved packages: 22
- cargoscope-cargo 0.1.0 [root]
- indexmap 2.14.2 [transitive] (registry+https://github.com/rust-lang/crates.io-index)
    via cargoscope-cargo -> toml -> toml_edit -> indexmap
- toml 0.8.23 [direct] (registry+https://github.com/rust-lang/crates.io-index)
...
```

Every transitive package shows the shortest dependency chain that pulls it in. The JSON report carries the same chain in a `path` field.

### Behind a Proxy

`cargoscope update` follows the usual environment variables: `HTTPS_PROXY` for the `https://` downloads (RustSec, crates.io), then `ALL_PROXY`, in upper or lower case, with `http://[user:password@]host:port` as value. `NO_PROXY` lists the hosts that go direct (`*`, `crates.io`, `.example.com`; a domain covers its subdomains), and localhost always does. Only `http://` proxies are supported; an unusable proxy setting is an error that names the variable, not a silent direct connection.

## More Usage

```sh
cargoscope scan . --format json --output report.json         # versioned JSON report
cargoscope scan . --format sarif --output results.sarif       # SARIF 2.1.0 for GitHub code scanning
cargoscope scan . --format cyclonedx --output bom.cdx.json    # CycloneDX 1.5 SBOM (components, licenses, advisories)
cargoscope why serde_json                                     # all reverse chains & pruning weight for a crate
cargoscope scan . --fail-on high                    # fail only on high or critical vulnerabilities
cargoscope scan . --fail-on none                    # never fail CI on findings
cargoscope scan . --checks inventory,unused          # run only some checks (no download needed)
cargoscope scan . --show-uncertain                  # also list possibly-unused dependencies
cargoscope scan . --verbose                         # also list every resolved package
```

By default, any security vulnerability fails the scan (exit code 1); vulnerabilities without a CVSS score count at every threshold, and informational advisories never fail. Set `CARGOSCOPE_CACHE_DIR` to choose where downloaded data is stored. Use `--fail-on none` to add CargoScope to CI alongside your existing tools without blocking builds. Exit codes: `0` OK, `1` threshold reached, `2` execution error.

The JSON report follows a published schema with a compatibility policy: see [docs/json-report.md](docs/json-report.md). SARIF results cover advisories (pointing at the package in `Cargo.lock`), yanked versions in use, and likely-unused dependencies (pointing at their line in `Cargo.toml`).

## Roadmap

| Version | Focus |
|---|---|
| **v0.1** | Unified Rust report: inventory, RustSec advisories, crates.io versions, licenses, unused candidates, dependency paths, text/JSON/SARIF, all distribution channels, GitHub Action |
| **v0.2** | Measured precision: compiler-oracle benchmark, opt-in `--precise` mode |
| **v0.3** | Report comparison, baselines, license and source policies |
| **v0.4** | Maintenance indicators, justified recommendations, exportable graph |
| **v0.5** | Locally generated HTML report |
| **v0.6** | Controlled fixes: `fix --dry-run` and `fix --apply` for unused dependencies arrived early, in 0.4; other fixes to come |
| **v0.7** | Multi-project aggregation of local reports |
| **1.0** | Stable CLI, JSON schema and compatibility policy |

CargoScope supports **Rust/Cargo only**. Other ecosystems are not planned until the Rust experience is clearly better than combining existing tools. See [SPEC.md](SPEC.md) for the full specification.

## Architecture

```
cargoscope/
├── crates/
│   ├── cargoscope-cli/        # commands, options, exit codes
│   ├── cargoscope-core/       # data model, orchestration, configuration
│   ├── cargoscope-cargo/      # Cargo parsing, resolution, unused analysis
│   ├── cargoscope-advisory/   # RustSec database and cache (skeleton)
│   └── cargoscope-report/     # text, JSON, SARIF and CycloneDX SBOM
└── tests/                     # fixtures and integration tests
```

Pipeline: **discover → parse → analyze → report**.

## Contributing

Contributions are welcome, especially false-positive reports for unused-dependency detection. See [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
cargo test --workspace
cargo clippy -- -W clippy::pedantic
cargo run -p cargoscope -- scan .
```

Unused-dependency detection is measured on a labelled corpus of 70 real repositories (about 91–94% precision on unseen code, above the 90% criterion of v0.1; on the same packages, cargo-machete's default mode has about 41% precision, see [the comparison](tests/corpus/cargo-machete.md), a [blind benchmark](tests/corpus/blind-benchmark.md) against cargo-machete, cargo-audit and cargo-deny, and a [benchmark judged by rustc](tests/corpus/compiler-benchmark.md) on 73 popular crates: 91.7% precision and twice cargo-machete's recall there; [against cargo-shear](tests/corpus/cargo-shear.md), CargoScope errs less but cargo-shear finds more, especially on libraries; and a [second blind test judged by rustc on 56 new repositories](tests/corpus/blind-judge/README.md), with no mistake in CargoScope's default output): see [tests/corpus](tests/corpus/README.md) for the method and the honest numbers.

## Crates in Several Versions

The report lists crates resolved in more than one version (for example `syn` 1 and 2), which Cargo compiles once per version. Every version but the newest shows the chain that pulls it in: that is the dependency to update to remove the duplicate. The JSON report has them in `duplicates`, and `compare` and the pull request comment list new ones.

With `multiple-versions = "deny"` under `[bans]` in `cargoscope.toml`, a duplicate fails the scan, as in cargo-deny; `skip-multiple-versions` lists crates accepted anyway (see [docs/policy.md](docs/policy.md)).

The list comes from `Cargo.lock`, which covers every platform and also optional dependencies that may never be enabled: on [uv](https://github.com/astral-sh/uv), it finds the 35 crates that `cargo tree --duplicates --target all --all-features` reports, plus one only present in the lockfile.

## Heaviest Direct Dependencies

```
Heaviest direct dependencies: packages that would leave the tree without each one
- ureq 2.12.1: 54 of the 72 packages it pulls in
- tar 0.4.46: 7 of the 11 packages it pulls in
- jsonschema 0.61.2 (dev): 57 of the 79 packages it pulls in
```

Dependencies declared only under `[dev-dependencies]` or `[build-dependencies]` are labelled `(dev)` or `(build)` and listed after the others, since they do not ship with the project; the same label marks a duplicate pulled in through them. For each direct dependency, the report counts the packages that would leave the dependency tree if no member depended on it directly (itself included), and the size of its own tree: the first number is what removing or replacing it saves. The ten heaviest are shown (all with `--verbose`), and the JSON report has every direct dependency in `direct_weights`. Like the rest of the report, it comes from `Cargo.lock`.

## Comparing Reports and Baselines

```sh
cargoscope scan . --format json --output baseline.json        # once, on main
cargoscope scan . --baseline baseline.json                     # later: only new advisories fail
cargoscope compare baseline.json current.json                  # what changed between two reports
```

`compare` lists new and resolved advisories, new yanked versions, new and resolved likely-unused dependencies, new and resolved crates in several versions, and version changes, as text, JSON (`--format json`) or Markdown for a pull request comment (`--format markdown`). It exits with 1 when new advisories reach `--fail-on`.

## Updating Vulnerable Packages

```sh
cargoscope fix --advisories .            # dry run: what can be updated, and what blocks the rest
cargoscope fix --advisories . --apply    # updates Cargo.lock, and Cargo.toml when a requirement blocks the fix
```

```
chrono 0.4.19 (RUSTSEC-2020-0159)
  - update to 0.4.20
time 0.1.45 (RUSTSEC-2020-0071)
  = cannot update: error: failed to select a version for the requirement `time = "^0.1.43"` / required by package `chrono v0.4.19`
```

For each vulnerability with a fix, CargoScope tries the smallest fixed version first with `cargo update --precise ... --dry-run`, so Cargo, which knows every version requirement, decides whether `Cargo.lock` can move without changing a manifest.

When the vulnerable package is a direct dependency and its own requirement is what blocks the fix (`chrono = "=0.4.19"`, or `time = "0.1"` while the fix is in 0.2.23), CargoScope retries with the requirement raised to the fixed version, in every manifest that declares it (`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, `[target.'...']` tables and `[workspace.dependencies]`; inline and table forms, comments and formatting kept). The report then says which manifests change:

```
chrono 0.4.19 (RUSTSEC-2020-0159)
  - update to 0.4.20 (in Cargo.toml)
```

The edit is refused when another dependency would still keep the vulnerable version in `Cargo.lock`. Entries inherited with `workspace = true` and path or git dependencies are left alone. When nothing works, Cargo's explanation shows which dependency to upgrade or which requirement to relax.

Nothing is written without `--apply`: the dry run only tries the manifest edits and restores them. With `--apply`, `Cargo.lock` gets the exact smallest fixed version and the manifests the requirement `"<version>"`. This runs `cargo update`, which may read the registry index; it compiles and runs nothing.

### Security update pull requests

The GitHub Action can open the pull request itself, on a schedule:

```yaml
on:
  schedule:
    - cron: "0 6 * * *"   # every day
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write
  actions: write          # only for ci-workflow
  security-events: write

jobs:
  security-updates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HarpeLm/CargoScope@v0.5.1
        with:
          fail-on: none
          open-pr: true
          pr-per-package: false  # optional: one PR per vulnerable package
          ci-workflow: ci.yml   # optional: starts your CI on the pull request
```

It runs `cargoscope fix --advisories --apply`; when `Cargo.lock` or a `Cargo.toml` changes, it commits both, pushes the branch `cargoscope/security-updates` and opens a pull request listing the fixed advisories, the versions before and after, and what stays vulnerable with Cargo's reason. A later run updates the same pull request. With `pr-per-package: true`, it opens one pull request per vulnerable package (on branch `cargoscope/security-updates/<package>`) and closes security pull requests that no longer apply. Two GitHub rules apply:

- With the default token, the repository must allow GitHub Actions to create pull requests (Settings, Actions, General, Workflow permissions). A personal access token or a GitHub App token passed as `token` does not need it.
- A pull request opened with the default token starts no workflow. `ci-workflow` works around it: a `workflow_dispatch` started by the default token does run, and its checks show on the pull request commit (your CI needs a `workflow_dispatch` trigger). A personal access token or a GitHub App token starts the usual pull request workflows.

## Auditing a Compiled Binary

```sh
cargoscope update                      # once, for the advisory database
cargoscope audit-bin target/release/my-app
```

Reports the advisories of the crates compiled into a Rust binary, with the chain that pulls each one in. It is exact for binaries built with [`cargo auditable build`](https://github.com/rust-secure-code/cargo-auditable), which embeds the dependency tree; on a test project it gives the same findings as `cargo audit bin`. Without that data, it falls back to the crate paths that panic messages keep in the binary: that list is incomplete, has no tree, and the report says so. The file is only read, never run. Options: `--format text|json`, `--fail-on`.

## Ignoring an Advisory

```toml
# cargoscope.toml
[advisories]
ignore = [{ id = "RUSTSEC-2020-0071", reason = "only used by a build tool", until = "2027-01-31" }]
```

Ignored advisories stay visible with their reason, but never fail the scan; in SARIF they are suppressed. See [docs/policy.md](docs/policy.md).

## Dependency Policy

Already using cargo-deny? Without a `cargoscope.toml`, CargoScope reads your `deny.toml` and lists what it cannot translate. A `cargoscope.toml` next to `Cargo.toml` enforces allowed licenses (with per-crate exceptions and clarifications), allowed sources, banned crates and features (`[bans] features`), and, optionally, a single version per crate, in the spirit of cargo-deny. With `[graph]` (`targets`, `features`, `all-features`, `no-default-features`, `exclude-dev`), the rules only apply to the packages that build uses. Violations fail the scan. See [docs/policy.md](docs/policy.md).

## Compiler-Accurate Mode

```sh
cargoscope scan . --precise
```

Confirms unused dependencies with the compiler (`cargo check --all-targets --all-features`, in `target/cargoscope-precise`): rustc's `unused_crate_dependencies` lint, or, from Rust 1.100, Cargo's own `unused_dependencies` lint. Cargo's lint does not check dev-dependencies, which then keep their static result. **It compiles the project, so build scripts and proc macros run**: use it on code you trust. It is never enabled by default, and covers only the current platform.

## Removing Unused Dependencies

```sh
cargoscope fix .            # dry run: shows what would be removed, writes nothing
cargoscope fix . --apply    # removes them from the Cargo.toml files
cargo check                 # updates Cargo.lock and confirms the build
```

```
crates/app/Cargo.toml
  - remove `rand` from [dependencies]
  - remove `pretty_assertions` from [dev-dependencies]
Cargo.toml
  - remove `rand` from [workspace.dependencies]: no member uses it anymore
```

Only likely-unused dependencies are removed: possibly-unused and ignored ones are never touched. A dependency is removed from its section and from the same section of `[target.'...']` tables, and kept when `[features]` names it. An entry of `[workspace.dependencies]` that no member uses anymore after the removal goes too. `--only rand,log` limits the removal to those dependencies. The manifests are edited with `toml_edit`, so formatting, order and the other comments stay as they were (a comment on the removed line goes with it). `fix` never runs `cargo`: run `cargo check` yourself afterwards. Add `--precise` to confirm the candidates with rustc first.

## Ignoring an Unused-Dependency Finding

```toml
[package.metadata.cargoscope]
ignore-unused = [
  { name = "once_cell", reason = "used by code generated in build.rs" },
]
```

A reason is required. Ignored dependencies stay visible in the report with their reason. Unused dependencies never fail the scan.

## License

Licensed under the [MIT License](LICENSE).
