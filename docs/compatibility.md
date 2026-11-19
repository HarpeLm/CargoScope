# Compatibility and Stability Policy

This document defines what CargoScope guarantees to keep stable across releases, what may evolve freely, and how the minimum supported Rust version (MSRV) is managed.

## Versioning

CargoScope follows [Semantic Versioning 2.0.0](https://semver.org/):

- **Pre-`1.0` (`0.x.y`)**: minor releases (`0.8.0`, `0.9.0`, ...) may introduce new commands, flags, report fields, or refine heuristics; breaking changes to documented machine-readable formats are avoided whenever possible and called out in [CHANGELOG.md](../CHANGELOG.md).
- **`1.x.y` (from `1.0.0` onward)**:
  - **Patch releases (`1.x.Z`)**: bug fixes, security fixes, documentation updates, and false-positive/false-negative refinements that do not break the compatibility guarantees below.
  - **Minor releases (`1.Y.0`)**: backwards-compatible additions (new subcommands, new optional CLI flags, new additive JSON fields, new optional `cargoscope.toml` keys, new checks).
  - **Major releases (`2.0.0`)**: breaking changes to any guaranteed interface below.

## Stability Contract (1.x Guarantees)

### Guaranteed stable across `1.x`

| Surface | Guarantee |
|---|---|
| **Exit codes** | `0` = success (no failing advisories or policy violations); `1` = findings reached `--fail-on` or a policy error occurred; `2` = execution, usage, or configuration error. |
| **CLI subcommands & documented flags** | Existing subcommands (`scan`, `update`, `compare`, `why`, `fix`, `audit-bin`, `aggregate`, `init`) and their documented long flags, values, and default semantics remain supported throughout `1.x`. Deprecated flags emit a warning and stay functional until `2.0`. |
| **JSON report (`format_version: 1`)** | Conforms to [docs/schema/report-v1.json](schema/report-v1.json) and [docs/json-report.md](json-report.md). Within `format_version: 1`, existing keys are never removed or given an incompatible type; new fields are additive only. Breaking changes require bumping `format_version` to `2`. |
| **Compare / Aggregate / Fix JSON outputs** | Existing top-level keys and field types stay backwards-compatible; new fields are additive only. |
| **SARIF & CycloneDX outputs** | Valid **SARIF 2.1.0** (`--format sarif`) and **CycloneDX 1.5** (`--format cyclonedx`, including VEX `not_affected` annotations). Existing rule IDs and structural layout remain compatible with GitHub Code Scanning and SBOM consumers. |
| **Configuration (`cargoscope.toml`)** | Existing sections (`[advisories]`, `[graph]`, `[licenses]`, `[sources]`, `[bans]`, `[updates]`, and `[package.metadata.cargoscope]`) and their keys keep their meaning. New keys are optional with backwards-compatible defaults. |
| **`deny.toml` & `.cargo/audit.toml` compatibility** | Supported keys remain supported; unsupported keys continue to emit clear warnings rather than silently passing. |
| **Offline & no-code-execution default** | `cargoscope scan` stays offline and never executes target project code unless the user explicitly opts in (`--update`, `--precise`). |
| **GitHub Action (`action.yml`)** | Existing inputs and outputs remain backwards-compatible within a major tag (`@v1`). |

### Explicitly *not* part of the stability contract

The following surfaces may change in minor or patch releases without being considered breaking changes:

- **Terminal text layout (`--format text`)**: wording, spacing, grouping, ANSI colors, summary truncation, and `Next steps` hints are designed for humans, not parsers. Scripts and CI jobs should consume `--format json`, `--format sarif`, or `--format cyclonedx`.
- **HTML report styling (`--format html`)**: visual layout, CSS, and interactive markup may evolve while staying self-contained and offline.
- **Markdown PR bodies (`--format markdown`)**: prose formatting and section order may evolve to improve readability, while keeping the machine-readable HTML marker comments (`<!-- cargoscope-security-pr -->`, `<!-- cargoscope-update-pr -->`) intact.
- **Diagnostic wording**: exact error messages and warning prose printed to `stderr`.
- **Unused-dependency heuristics**: static analysis rules and confidence classifications (`likely-unused` vs `possibly-unused`) may improve in any release to reduce false positives or improve recall.
- **Internal library crates (`cargoscope-core`, `cargoscope-cargo`, `cargoscope-advisory`, `cargoscope-report`)**: published on crates.io to build the `cargoscope` binary; their Rust API is internal and not covered by the `1.x` CLI stability contract unless explicitly promoted in a future release.

## Minimum Supported Rust Version (MSRV)

- **Current MSRV**: **Rust `1.90`** (Edition 2024), declared via `rust-version = "1.90"` in the workspace [Cargo.toml](../Cargo.toml) and verified in CI on every commit.
- **Policy in `1.x`**:
  - MSRV is **never** raised in a patch release (`1.x.Z`), except when required to remediate a security vulnerability in a dependency with no compatible workaround.
  - MSRV may be raised in a minor release (`1.Y.0`) only when needed by CargoScope or its direct dependencies, and will stay at least **6 months behind** the current stable Rust release whenever practical.
  - Any MSRV bump is explicitly noted in [CHANGELOG.md](../CHANGELOG.md).
- **Prebuilt binaries**: users installing via GitHub Releases, Homebrew, npm, PyPI (`pip`/`uvx`), Docker (`ghcr.io/harpelm/cargoscope`), or the GitHub Action do not need a Rust toolchain at all (except when running `--precise` or `fix --advisories` / `fix --updates`, which invoke the local `cargo`).

## Platform Support

Prebuilt binaries are produced and tested in CI for:

- **Linux**: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (and musl / container images)
- **macOS**: `aarch64-apple-darwin`, `x86_64-apple-darwin`
- **Windows**: `x86_64-pc-windows-msvc`

CI runs the full test suite on Linux, macOS, and Windows on every push and pull request.
