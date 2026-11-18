# Changelog

All notable changes to CargoScope are documented in this file.

## Unreleased

- Advisory relevance ranking (#25): evaluates whether each advisory affects shipped code (`affects-you`, `possibly`, `unlikely`) using `[graph]` target filtering (even without a policy rule table), `[dev-dependencies]` reachability, `[affected]` OS/architecture constraints, and uncalled `[affected.functions]`. Surfaces relevance across JSON, terminal, text, HTML, SARIF (`properties.relevance` + message note), CycloneDX 1.5 VEX (`analysis.state = "not_affected"` with `code_not_reachable` / `code_not_present`), and `cargoscope compare`; adds `--ignore-unlikely` (on `scan` and `compare`) and `[advisories] ignore-unlikely = true` in `cargoscope.toml`.

## 0.7.6 (2026-11-18)

- `cargoscope init` (`--ci`, `--policy`, `--dry-run`, `--force`) to create a starter `cargoscope.toml`, translate an existing `deny.toml` and `.cargo/audit.toml` into `cargoscope.toml`, and generate `.github/workflows/cargoscope.yml`.
- Non-blocking SARIF upload in `action.yml` (`continue-on-error: true` when `security-events: write` or Code Scanning is unavailable) and minimal 5-line CI snippet in `README.md`.
- `cargoscope update --fast` / `--no-maintenance` to skip the `1 req/s` crates.io maintenance requests on the first update.
- `cargoscope scan --update` (`--fast` / `--no-maintenance`) to download advisory and crates.io data and scan in one command.

## 0.7.5 (2026-11-17)

- Unused-dependency detection follows `#[path]` modules and `include!` into the rest of the workspace (such as an `xtask` reusing another workspace crate's files).
- Keeps as `possibly-unused` a dev-dependency that turns on a test feature (for example `test-support`) of a workspace crate the package also reaches.

## 0.7.4 (2026-11-17)

- `cargoscope fix --advisories --apply` skips a package an earlier update already moved past its target instead of stopping the run (#20).
- Brings packages Cargo moved along the way back to their smallest fixed version (`rustls-webpki` `0.103.16` rather than `0.103.17`, #21), even when another major version of the crate remains in `Cargo.lock`.

## 0.7.3 (2026-11-17)

- `cargoscope fix --advisories` and security pull requests move a vulnerable crate only to a version that fixes all of its advisories and is affected by none in the RustSec database.

## 0.7.2 (2026-11-17)

- Richer update pull requests with a leading "Needs attention" list, publication date, advisories fixed or introduced, license changes, minimum Rust version checked against the project's `rust-version`, maintenance concerns, `Cargo.lock` changes, release notes from crate changelogs or GitHub releases (mentions and issue references neutralised), and skip rules.
- `cargoscope fix --updates` and `--advisories` move pinned requirements (`=x.y.z`) and keep them pinned.

## 0.7.1 (2026-11-16)

- Shorter, colored terminal report (`cargoscope scan`): vulnerable crates grouped one per line with the version that fixes all advisories, informational notices grouped by kind, long lists trimmed with a count of remaining entries, and suggested next commands (`--verbose` prints the full report).
- `--color auto|always|never` and `NO_COLOR` support for `scan`; `--verbose` for `audit-bin`.
- GitHub Action listed as **CargoScope-Bot** on the GitHub Marketplace.

## 0.7.0 (2026-11-16)

- Dependabot-style version update pull requests via `cargoscope fix --updates [--breaking]`, `[updates]` configuration (`ignore`, `groups`, `open-pull-requests-limit`, `include-dev`), and Action inputs (`updates`, `updates-grouped`, `labels`, `reviewers`, `commit-prefix`, `auto-merge`), with source diff (`diff.rs`) and release-note links.
- Maintenance indicators for direct crates.io dependencies: archived GitHub repository, no release in 2 years, and single crates.io owner (`rust-lang-owner` treated as shared).
- Full `cargo-deny`-level license checking: license texts detected from `LICENSE*`/`COPYING*` files with `confidence-threshold`, the project's own packages, `[licenses.private]`, `unused-allowed-license`, and empty `allow` lists.
- `[bans.build]` inspection of executables and scripts in build-time crates, including `bypass` rules.
- `.cargo/audit.toml` ignores read automatically when there is no `cargoscope.toml`; pre-release advisory patched ranges read according to RustSec rules.
- Modularised unused-dependency engine (facts, named rules, decision) and fixes from the third blind benchmark on 80 never-seen repositories (symbolic-link sources inside the workspace, `=> ::` / `-> ::` paths, stricter doc mentions).

## 0.6.0 (2026-11-15)

- Standalone offline HTML report (`--format html`).
- SemVer `compatible` vs `breaking` classification for outdated dependencies (`OutdatedKind`, `latest_compatible`).
- CycloneDX 1.5 SBOM export (`--format cyclonedx`).
- `cargoscope why <crate>` reverse dependency chains, direct dependents, and pruning weights.
- `[bans] features` (`allow`, `deny`, `exact`), `[bans.build]` (`allow-build-scripts`, `include-workspace`), `[licenses.clarify]` `license-files` 32-bit `xxHash32` verification, `"warn"` lint levels, and graph fixes (`exclude-unpublished` feature unification, `cfg(any())` filtering under `--target all`) reaching 34 of 34 parity with `cargo-deny` 0.20.2.

## 0.5.1 (2026-11-15)

- Automatic fallback to `deny.toml` when no `cargoscope.toml` is present, `[bans]` `wrappers`, and `+` ("or later") SPDX license expressions such as `MPL-2.0+`.
- Corpus-validated unused-dependency rules (`mod r#enum;`, `strum_macros` companion crate, per-package transitive reachability).

## 0.5.0 (2026-11-15)

- `cargoscope fix --advisories` to update vulnerable packages to the smallest fixed version Cargo accepts (in `Cargo.lock`, and `Cargo.toml` / `[workspace.dependencies]` when pinned).
- Security update pull requests in the GitHub Action (`open-pr: true`, `pr-per-package`, closing obsolete PRs, `ci-workflow`).
- `cargoscope audit-bin` for compiled Rust binaries (`cargo-auditable` metadata and panic-path fallback).
- `[graph]` scoping (`targets`, `features`, `all-features`, `no-default-features`, `exclude-dev`), `[licenses] exceptions` and `clarify`, `--precise` support for Cargo 1.100's `unused_dependencies` lint, and `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY` support in `cargoscope update`.

## 0.4.1 (2026-11-15)

- Per-subcommand `--help` pages and CLI module split.

## 0.4.0 (2026-11-15)

- `cargoscope fix` (dry run, `--apply`, `--only`, `[workspace.dependencies]` cleanup) to remove likely-unused dependencies.
- Heaviest direct dependencies with `(dev)` / `(build)` labels, `[bans] multiple-versions` rule, and sharper unused-dependency rules.

## 0.3.0 (2026-11-15)

- Crates resolved in several versions in text/JSON reports, `compare`, and pull request comments; baselines and license/source policies.

## 0.2.0 (2026-11-15)

- Pull request comparison comments in the GitHub Action (`cargoscope compare --format markdown`) and `--precise` compiler-accurate mode.

## 0.1.1 (2026-11-14)

- Marketplace listing metadata for the GitHub Action.

## 0.1.0 (2026-11-14)

- Initial release: unified offline `scan` (inventory, RustSec advisories, crates.io versions/licenses, static unused-dependency analysis, dependency chains), `update`, `compare`, text/JSON/SARIF outputs, and prebuilt binaries, crates.io, Homebrew, npm, and GitHub Action distribution.
