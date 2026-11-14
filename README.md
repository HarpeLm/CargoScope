# Dep Scout

**Understand every dependency in your Rust project: why it's there, what it risks, and what to do.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)

---

Dep Scout is an open-source CLI, written in Rust, for Rust/Cargo projects. One command produces one report: inventory, security advisories, available versions, licenses, likely-unused dependencies, and the dependency chain behind each finding. No more running cargo-audit, cargo-deny, cargo-machete and cargo-tree separately and reconciling their output.

## Principles

- **Local, no account**: the first scan needs no account and no online service.
- **Your code never leaves your machine**: nothing is uploaded.
- **No silent writes**: Dep Scout never modifies your files.
- **Evidence first**: every finding shows its evidence, its source and the date of its data.
- **No code execution**: Dep Scout reads files directly and never runs `cargo`, build scripts or project code by default.

## Status

**Version 0.1.0, the first stable release.** `depscout update` downloads the RustSec advisory database and the crates.io data of a project; `depscout scan` then reports, offline, matching advisories, likely-unused dependencies with the evidence behind each one, licenses, yanked and outdated versions, a `depscout.toml` policy, and the dependency chain behind every finding, as text, JSON or SARIF. It is young: please report anything wrong in the [feedback issue](https://github.com/HarpeLm/DepScout/issues/1).

**New here?** [Try Dep Scout in two minutes](docs/try-it.md), then tell us how it went.

## Install

```sh
# Prebuilt binary, macOS and Linux
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/HarpeLm/DepScout/releases/latest/download/depscout-installer.sh | sh

# Prebuilt binary, Windows (PowerShell)
irm https://github.com/HarpeLm/DepScout/releases/latest/download/depscout-installer.ps1 | iex

# Homebrew
brew install HarpeLm/tap/depscout

# From crates.io
cargo install depscout

# Without installing, through npm
npx depscout scan .
```

From a clone of this repository: `cargo install --path crates/depscout-cli`.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # to upload SARIF to code scanning

jobs:
  depscout:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HarpeLm/DepScout@v0.1.1
        with:
          fail-on: high        # or none, to report without failing
```

The action downloads the prebuilt binary (no compilation), caches advisory data for a day, prints the report in the log, and uploads SARIF results to the Security tab. Inputs: `version`, `path`, `fail-on`, `checks`, `sarif`, `upload-sarif`.

## Quick Start

```sh
# Download the RustSec database and this project's crates.io data (the only command that uses the network)
depscout update .

# Scan the current project, offline
depscout scan .
```

### Example Output

```
Dep Scout 0.1.0
Target: .

Advisories: 1 (RustSec database downloaded 2026-11-12)
- RUSTSEC-2020-0071 [medium] time 0.1.45: Potential segfault in the time crate
    via my-app -> chrono -> time
    fix: upgrade to >= 0.2.23
    https://github.com/time-rs/time/issues/293

Resolved packages: 22
- depscout-cargo 0.1.0 [root]
- indexmap 2.14.2 [transitive] (registry+https://github.com/rust-lang/crates.io-index)
    via depscout-cargo -> toml -> toml_edit -> indexmap
- toml 0.8.23 [direct] (registry+https://github.com/rust-lang/crates.io-index)
...
```

Every transitive package shows the shortest dependency chain that pulls it in. The JSON report carries the same chain in a `path` field.

## More Usage

```sh
depscout scan . --format json --output report.json   # versioned JSON report
depscout scan . --format sarif --output results.sarif # SARIF 2.1.0 for GitHub code scanning
depscout scan . --fail-on high                    # fail only on high or critical vulnerabilities
depscout scan . --fail-on none                    # never fail CI on findings
depscout scan . --checks inventory,unused          # run only some checks (no download needed)
depscout scan . --show-uncertain                  # also list possibly-unused dependencies
depscout scan . --verbose                         # also list every resolved package
```

By default, any security vulnerability fails the scan (exit code 1); vulnerabilities without a CVSS score count at every threshold, and informational advisories never fail. Set `DEPSCOUT_CACHE_DIR` to choose where downloaded data is stored. Use `--fail-on none` to add Dep Scout to CI alongside your existing tools without blocking builds. Exit codes: `0` OK, `1` threshold reached, `2` execution error.

The JSON report follows a published schema with a compatibility policy: see [docs/json-report.md](docs/json-report.md). SARIF results cover advisories (pointing at the package in `Cargo.lock`), yanked versions in use, and likely-unused dependencies (pointing at their line in `Cargo.toml`).

## Roadmap

| Version | Focus |
|---|---|
| **v0.1** | Unified Rust report: inventory, RustSec advisories, crates.io versions, licenses, unused candidates, dependency paths, text/JSON/SARIF, all distribution channels, GitHub Action |
| **v0.2** | Measured precision: compiler-oracle benchmark, opt-in `--precise` mode |
| **v0.3** | Report comparison, baselines, license and source policies |
| **v0.4** | Maintenance indicators, justified recommendations, exportable graph |
| **v0.5** | Locally generated HTML report |
| **v0.6** | Controlled fixes (`fix --dry-run`, explicit `fix --apply`) |
| **v0.7** | Multi-project aggregation of local reports |
| **1.0** | Stable CLI, JSON schema and compatibility policy |

Dep Scout supports **Rust/Cargo only**. Other ecosystems are not planned until the Rust experience is clearly better than combining existing tools. See [SPEC.md](SPEC.md) for the full specification.

## Architecture

```
depscout/
├── crates/
│   ├── depscout-cli/        # commands, options, exit codes
│   ├── depscout-core/       # data model, orchestration, configuration
│   ├── depscout-cargo/      # Cargo parsing, resolution, unused analysis
│   ├── depscout-advisory/   # RustSec database and cache (skeleton)
│   └── depscout-report/     # text, JSON and SARIF
└── tests/                     # fixtures and integration tests
```

Pipeline: **discover → parse → analyze → report**.

## Contributing

Contributions are welcome, especially false-positive reports for unused-dependency detection. See [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
cargo test --workspace
cargo clippy -- -W clippy::pedantic
cargo run -p depscout -- scan .
```

Unused-dependency detection is measured on a labelled corpus of 70 real repositories (about 91–94% precision on unseen code, above the 90% criterion of v0.1; on the same packages, cargo-machete's default mode has about 41% precision, see [the comparison](tests/corpus/cargo-machete.md), a [blind benchmark](tests/corpus/blind-benchmark.md) against cargo-machete, cargo-audit and cargo-deny, and a [benchmark judged by rustc](tests/corpus/compiler-benchmark.md) on 73 popular crates: 91.7% precision and twice cargo-machete's recall there): see [tests/corpus](tests/corpus/README.md) for the method and the honest numbers.

## Comparing Reports and Baselines

```sh
depscout scan . --format json --output baseline.json        # once, on main
depscout scan . --baseline baseline.json                     # later: only new advisories fail
depscout compare baseline.json current.json                  # what changed between two reports
```

`compare` lists new and resolved advisories, new yanked versions, new and resolved likely-unused dependencies, and version changes. It exits with 1 when new advisories reach `--fail-on`.

## Ignoring an Advisory

```toml
# depscout.toml
[advisories]
ignore = [{ id = "RUSTSEC-2020-0071", reason = "only used by a build tool", until = "2027-01-31" }]
```

Ignored advisories stay visible with their reason, but never fail the scan; in SARIF they are suppressed. See [docs/policy.md](docs/policy.md).

## Dependency Policy

A `depscout.toml` next to `Cargo.toml` enforces allowed licenses, allowed sources and banned crates, in the spirit of cargo-deny. Violations fail the scan. See [docs/policy.md](docs/policy.md).

## Compiler-Accurate Mode

```sh
depscout scan . --precise
```

Confirms unused dependencies with rustc's `unused_crate_dependencies` lint (`cargo check --all-targets --all-features`, in `target/depscout-precise`). **It compiles the project, so build scripts and proc macros run**: use it on code you trust. It is never enabled by default, and covers only the current platform.

## Ignoring an Unused-Dependency Finding

```toml
[package.metadata.depscout]
ignore-unused = [
  { name = "once_cell", reason = "used by code generated in build.rs" },
]
```

A reason is required. Ignored dependencies stay visible in the report with their reason. Unused dependencies never fail the scan.

## License

Licensed under the [MIT License](LICENSE).
