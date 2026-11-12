# CargoScope

**Understand every dependency in your Rust project: why it's there, what it risks, and what to do.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

---

CargoScope is an open-source CLI, written in Rust, for Rust/Cargo projects. One command produces one report: inventory, security advisories, available versions, licenses, likely-unused dependencies, and the dependency chain behind each finding. No more running cargo-audit, cargo-deny, cargo-machete and cargo-tree separately and reconciling their output.

## Principles

- **Local, no account**: the first scan needs no account and no online service.
- **Your code never leaves your machine**: nothing is uploaded.
- **No silent writes**: CargoScope never modifies your files.
- **Evidence first**: every finding shows its evidence, its source and the date of its data.
- **No code execution**: CargoScope reads files directly and never runs `cargo`, build scripts or project code by default.

## Status

**Early development, not yet ready for production use.** Today, `cargoscope update` downloads the RustSec advisory database and the crates.io data of the project, and `cargoscope scan` reports matching advisories, licenses, outdated and yanked versions, and inventories the packages resolved in `Cargo.lock`, with the dependency chain behind every advisory and transitive package. It also lists likely-unused dependencies found by static analysis, with the evidence behind each one. Exit codes and `--fail-on` work as described below. The rest of the v0.1 scope below is in progress.

## Quick Start

```sh
# Install from source (prebuilt binaries, crates.io, Homebrew, npm and PyPI come with v0.1)
cargo install --path crates/cargoscope-cli

# Download the RustSec database and this project's crates.io data (the only command that uses the network)
cargoscope update .

# Scan the current project, offline
cargoscope scan .

# JSON output
cargoscope scan . --format json
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

## More Usage (some options still planned)

```sh
cargoscope scan . --format sarif --output results.sarif
cargoscope scan . --fail-on none                    # never fail CI on findings
cargoscope scan . --show-uncertain                  # also list possibly-unused dependencies
```

By default, any security vulnerability fails the scan (exit code 1); vulnerabilities without a CVSS score count at every threshold, and informational advisories never fail. Set `CARGOSCOPE_CACHE_DIR` to choose where downloaded data is stored. Use `--fail-on none` to add CargoScope to CI alongside your existing tools without blocking builds. Exit codes: `0` OK, `1` threshold reached, `2` execution error.

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

CargoScope supports **Rust/Cargo only**. Other ecosystems are not planned until the Rust experience is clearly better than combining existing tools. See [SPEC.md](SPEC.md) for the full specification.

## Architecture

```
cargoscope/
├── crates/
│   ├── cargoscope-cli/        # commands, options, exit codes
│   ├── cargoscope-core/       # data model, orchestration, configuration
│   ├── cargoscope-cargo/      # Cargo parsing, resolution, unused analysis
│   ├── cargoscope-advisory/   # RustSec database and cache (skeleton)
│   └── cargoscope-report/     # text and JSON (SARIF planned)
└── tests/                     # fixtures and integration tests
```

Pipeline: **discover → parse → analyze → report**.

## Contributing

Contributions are welcome, especially false-positive reports for unused-dependency detection. See [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
cargo test --workspace
cargo clippy -- -W clippy::pedantic
cargo run -p cargoscope-cli -- scan .
```

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
