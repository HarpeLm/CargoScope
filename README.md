# CargoScope

**The Dependency Intelligence Engine** — discover, evaluate, and improve your project's dependencies.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

---

CargoScope is an open-source tool written in Rust that helps developers understand their dependency tree: what's installed, what's risky, what's unmaintained, and what action to take. It produces clear, actionable reports that complement your existing tools (Dependabot, Renovate, Snyk, etc.) without replacing them.

## Why CargoScope?

Most dependency tools answer one question at a time — vulnerabilities *or* licenses *or* updates. CargoScope aims to bring **inventory, known advisories, maintenance signals, unused dependency candidates, and transitive relationships** into a single, explainable report.

- **Local-first** — no account required, no code uploaded, no silent file changes
- **CI-ready** — JSON and SARIF output with configurable exit codes
- **Multi-ecosystem** (roadmap) — starting with Cargo, then Python, Node.js, and Go
- **Complementary** — works alongside your current security and update tools

## Quick Start

```sh
# Install from source
cargo install --path crates/cargoscope-cli

# Scan the current project
cargoscope scan .

# JSON output for CI or archival
cargoscope scan . --format json
```

## Usage

```sh
# Scan a specific project directory
cargoscope scan /path/to/project

# Text output (default) — human-readable summary
cargoscope scan .

# JSON output — structured for CI pipelines and tooling
cargoscope scan . --format json

# Show version
cargoscope --version
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

## Architecture

CargoScope is organized as a Cargo workspace with a clear separation between the CLI frontend and the analysis core:

```
cargoscope/
├── Cargo.toml                 # Workspace root
├── crates/
│   ├── cargoscope-cli/        # CLI entry point, commands, output formatting
│   └── cargoscope-core/       # Domain types, lockfile/manifest parsing, analysis
└── tests/                     # Integration tests and fixtures (planned)
```

The analysis pipeline follows: **discover → parse → normalize → analyze → report**.

As the project grows, the workspace will expand to include dedicated crates for reporting (`cargoscope-report`), advisory lookup (`cargoscope-advisory`), and ecosystem adapters (`cargoscope-python`, `cargoscope-npm`, etc.).

## Roadmap

| Phase | Focus | Status |
|---|---|---|
| **v0.1** | Cargo dependency inventory — direct and transitive | Current |
| **v0.2** | Known advisory lookup (OSV), dependency graph edges | Next |
| **v0.3** | CI integration — SARIF, GitHub Actions, exit codes | Planned |
| **v0.4** | Unused dependency candidates, maintenance signals | Planned |
| **v0.5** | Python ecosystem adapter | Planned |
| **v1.0** | Stable CLI, versioned JSON schema, multi-project aggregation | Planned |

See [SPEC.md](SPEC.md) for the full product specification and strategic positioning.

## Status

**Early development** — v0.1.0. The first feature inventories packages resolved in a Rust project's `Cargo.lock`. Not yet ready for production use.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```sh
# Run tests
cargo test --workspace

# Run with clippy
cargo clippy -- -W clippy::pedantic

# Run a local scan
cargo run -p cargoscope-cli -- scan .
```

### Good First Issues

Look for issues labeled `good first issue` or `help wanted`. If you'd like to add support for a new language ecosystem, see the adapter guide in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the [MIT License](LICENSE).
