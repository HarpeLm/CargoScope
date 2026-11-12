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

**Early development, not yet ready for production use.** Today, `cargoscope scan` inventories the packages resolved in `Cargo.lock` (direct and transitive) across explicit workspace members. The rest of the v0.1 scope below is in progress.

## Quick Start

```sh
# Install from source (prebuilt binaries, crates.io, Homebrew, npm and PyPI come with v0.1)
cargo install --path crates/cargoscope-cli

# Scan the current project
cargoscope scan .

# JSON output
cargoscope scan . --format json
```

### Example Output

```
CargoScope 0.1.0
Target: .
Resolved packages: 12
- serde 1.0.229 [direct] (registry+https://github.com/rust-lang/crates.io-index)
- serde_json 1.0.140 [transitive] (registry+https://github.com/rust-lang/crates.io-index)
- toml 0.8.23 [direct] (registry+https://github.com/rust-lang/crates.io-index)
...
```

## Planned v0.1 Usage

```sh
cargoscope update                                   # download RustSec + crates.io data (only network access)
cargoscope scan .                                   # full report, read-only, offline
cargoscope scan . --format sarif --output results.sarif
cargoscope scan . --fail-on none                    # never fail CI on findings
cargoscope scan . --show-uncertain                  # include possibly-unused candidates
```

By default, any security advisory fails the scan (exit code 1). Use `--fail-on none` to add CargoScope to CI alongside your existing tools without blocking builds. Exit codes: `0` OK, `1` threshold reached, `2` execution error.

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
│   ├── cargoscope-cargo/      # Cargo parsing, resolution, unused analysis (planned)
│   ├── cargoscope-advisory/   # RustSec database and cache (planned)
│   └── cargoscope-report/     # text, JSON, SARIF (planned)
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

## License

Licensed under the [MIT License](LICENSE).
