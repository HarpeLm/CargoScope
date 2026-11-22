# Changelog

All notable changes to CargoScope are documented in this file.

## 0.12.0 (2026-11-22)

- **Native `.github/dependabot.yml` support**: when `cargoscope.toml` is absent or omits `[updates]`, CargoScope reads `.github/dependabot.yml` (`package-ecosystem: "cargo"`, `groups`, `ignore`, `open-pull-requests-limit`, `versioning-strategy`, `cooldown`, `labels`, `reviewers`, `commit-message.prefix`, `schedule`, `allow`) with zero migration boilerplate.
- **7-day default anti-supply-chain cooldown + per-dependency overrides**: `cargoscope fix --updates` skips crates.io releases younger than 7 days by default (picking the newest eligible non-yanked version outside the cooldown window, without ever blocking `fix --advisories`) and supports per-crate overrides via `--cooldown DAYS`, `--cooldown-for CRATE=DAYS`, or `[updates.cooldown.overrides]` in `cargoscope.toml`.
- **Full `versioning-strategy` support (`--versioning-strategy`)**: supports `auto`, `lockfile-only`, `increase-if-necessary`, `increase`, and `widen` (expanding restrictive bounds such as `~1.0.80` cleanest possible) across CLI, `cargoscope.toml`, and `.github/dependabot.yml`.
- **Git & alternative registry updates + Action auto-rebase**: `cargoscope fix --updates` tracks `git+...` commits and alternative/private `registry+...` dependencies via `cargo update -p`, while `action.yml` automatically rebases `CONFLICTING`/`DIRTY` CargoScope PRs and inherits `dependabot.yml` labels/reviewers/commit prefixes.
- **Audit of overly broad dependency features (#27)**: flags broad feature selections such as `tokio = ["full"]` or unused `serde = ["derive"]` in `FEATURE HINTS` (terminal, JSON `feature_hints` with schema in `docs/schema/report-v1.json`, HTML reports) and tightens static `unused` recall (`cargoscope fix --include-uncertain`).
- **3.16× faster `--checks unused` and ~1.8× faster full monorepo scans**: fused workspace source reading & `proc_macro2` lexing into a single parallel pass (`std::thread::scope`), cached external library-name lookups, parallelized external package inspection and `project_ident_tokens`, and ran `unused`, `unsafe`, and `advisories` + `policy` concurrently (`871 ms` for `--checks unused` and `3.83 s` full scan on `jdx/mise` with 1,184 crates).

## 0.11.0 (2026-11-22)

- Skip `yanked` versions and versions carrying another active advisory in `cargoscope fix --advisories` and in `cargoscope scan` terminal/HTML fix recommendations, consulting the local crates.io cache and advisory database with mathematical lower-bound fallback when the cache is absent or stale.
- Reduce static `unused` false positives from external (`Cargo.lock`) proc-macro crates by inspecting `quote!`/`quote_spanned!`/`parse_quote!` crate emissions when a direct provider dependency is referenced in source code (e.g., keeping proc-macro-emitted runtime/benchmark crates as `possibly-unused` while leaving genuinely unused `serde` as `likely-unused`).
- `cargoscope fix --apply --verify`: runs `cargo check --workspace --all-targets` after applying manifest edits and automatically rolls back all modified `Cargo.toml` files if compilation fails.
- Strict `--checks` gating for `unsafe`: `--checks` now includes `unsafe`, and `count_unsafe` plus the `UNSAFE CODE` HUD / HTML / text panels only run and render when `unsafe` is requested (or by default with all checks enabled).
- Orphan `[workspace.dependencies]` detection and cleanup: `cargoscope scan` directly flags `[workspace.dependencies]` entries inherited by no workspace member (supporting `[workspace.metadata.cargoscope] ignore-unused`), and `cargoscope fix` removes them (including with `--only`), updating `docs/schema/report-v1.json`.

## 0.10.0 (2026-11-22)

- `cargoscope fix --advisories`: when a fix is a breaking version that the crates pulling the package in do not accept, updates those crates within their range (`cargo update -p xcb`) if that moves the package to a fixed version. On halloy this fixes both quick-xml versions (xcb 1.7.0 → 1.7.1, wayland-scanner 0.31.10 → 0.31.11), where every update used to be refused. Packages that stay blocked get a plain reason (`xcb 1.7.0 requires quick-xml ^0.30.0, and the fix is 0.41.0`) with any newer release of the crates holding them back, instead of Cargo's error (`no matching package named crypto-bigint found` when elliptic-curve asks for 0.5); with nothing to update, the summary no longer suggests `--apply`. The scan, the HTML report and `why` mark such fixes `(via parent)` and count them for `fix --advisories`.
- Terminal report: a fix outside the SemVer range of a transitive crate is shown as `→ 0.41.0 (blocked)`, with the crates that have to accept it first (`waits on a new xcb release`), instead of a fix that `cargo update` cannot apply. Next steps count only the fixes `fix --advisories` can apply, and point to `cargoscope why` for the blocked ones. The HTML report and `why` use the same rule, and name every crate that holds the fix back.
- `cargoscope why`: shows the crate's advisories, the version that fixes them and what blocks it (the crate that has to accept a breaking fix first), and whether the version was yanked. Chains through another workspace member are no longer repeated for each member: paths are counted once and grouped by direct dependency, the shortest of each shown with how many others go through it, so the real total is shown instead of the 25-path cap (halloy: `why quick-xml` drops from 31 path lines to 3). `--all-paths` lists every chain; JSON gains `advisories`, `fix`, `yanked`, `members`, `path_count` and `routes`.
- HTML report: a What to do block opens the report with the fixes, most urgent first (the version that fixes each vulnerable crate, yanked versions, unused dependencies, recent releases to review, outdated dependencies), each with its command and a Copy button. Crate names link to crates.io and new versions to their source diff on diff.rs. Every table sorts by clicking a column title, and quick filters show vulnerabilities only, hide unlikely advisories, or keep direct dependencies only. A dependency map draws every package as a dot sized by how many packages depend on it, laid out offline by the page itself: zoom, pan, find a crate, and click one to see what it depends on and what depends on it.
- `scan --output FILE` prints one line on stderr once the report is written: its format, path, package count and vulnerable crates.
- HTML report redesign: a quieter layout with one copper accent, in dark and light mode; the header names the project directory (not `.`) with a status chip; summary metrics sit in one strip with colored dots; tabs, headings and column titles use sentence case; vulnerabilities are listed before notices; long tables scroll inside their panel with a fixed header; audited direct dependencies come first.
- HTML report: a Supply Chain section (and tab) lists recent releases with the chain that pulls them in, published cargo-vet audits of each direct dependency, and the `unsafe` code of every crate with sources on disk. `render_html` takes the scan time to list recent releases.
- Published audits: `cargoscope update` downloads the audits that organisations publish with cargo-vet (Mozilla, Google, the Bytecode Alliance, Zcash and the others of the cargo-vet registry, about 2 MB) and works out which exact versions they reviewed, following `delta` audits from fully audited versions. Scans show how many packages an organisation reviewed (`AUDITS`), which direct dependencies have no audit of the version in use, and `--verbose` gives the criteria and reviewers of each direct dependency; JSON packages gain an `audits` array. Publisher-based `trusted` entries are not used, since crates.io does not say who published a version.
- Unsafe code: a scan counts the `unsafe` blocks, functions, impls and traits of every dependency whose sources Cargo downloaded, with a Rust lexer (comments and strings never count), offline and without compiling. The terminal report ranks direct dependencies (`UNSAFE CODE`), `--verbose` lists every crate, and JSON packages gain an `unsafe` object. Counts of published versions are cached, so only the first scan of a version pays for it (nyaterm, 1,366 packages: +4 s the first time, nothing after).
- Recent releases: resolved versions published less than 72 hours before the scan are listed (`RECENT RELEASES` in the terminal report, `Recent releases` with `--verbose`), since compromised releases are usually caught within days. The crates.io cache now keeps each version's full publication time, and JSON packages gain a `published` field.
- A scan warns when the advisory data is more than 7 days old, since advisories published after the download are missing.
- Advisories from OSV: `cargoscope update` also downloads the crates.io export of OSV (3.8 MB) and keeps the GitHub security advisories (`GHSA-…`) and malicious crates (`MAL-…`, reported as critical) that RustSec does not have; entries naming a RustSec advisory's ID or alias are left out, so nothing is reported twice. On `russh 0.55.0`, a scan finds 15 GitHub advisories RustSec lacks. `--rustsec-only` reports RustSec alone, as `cargo-audit` does.
- `cargoscope update` downloads sparse index entries 16 at a time: a first `update --fast` on an 841-crate project drops from 49 s to 7 s, with identical cached data. crates.io API calls keep their one-per-second pace.
- `cargoscope update` shows a live `Maintenance data: 34/89 direct dependencies...` counter on a terminal while it fetches maintenance data (nothing in pipes or CI logs).
- Terminal report: the weight and license bars use line glyphs (`━━━━──────`), so consecutive rows no longer merge and the bars read without color.

## 0.9.1 (2026-11-19)

- PyPI wheels: fixed the `pypi.yml` build matrix (retired `macos-14` runners replaced by `macos-15-intel` and `macos-15`, Linux `aarch64` built natively on `ubuntu-22.04-arm` instead of cross-compiling `ring`), so `pip install cargoscope` and `uvx cargoscope` ship 6 wheels (Linux x86_64/aarch64/musl, macOS x86_64/arm64, Windows x64) plus an sdist. No change to the CLI.

## 0.9.0 (2026-11-19)

- Governance & stability contracts: added [SECURITY.md](SECURITY.md) (vulnerability reporting, offline/no-code-execution threat model, `unsafe_code = "forbid"`, and parser limits) and [docs/compatibility.md](docs/compatibility.md) (`1.x` CLI/exit-code/JSON/SARIF/CycloneDX stability guarantees and Rust `1.90`+ MSRV policy).
- `cargoscope fix --advisories` and `--updates` workspace propagation: updates `[workspace.dependencies]` (including renamed and dotted-key entries) and implicit local path members without touching `workspace = true` declarations, filters manifest edits by the vulnerable version so unrelated major version lines elsewhere in a workspace are never downgraded, and passes unambiguous `name@version` package specs to `cargo update` for multi-version lockfiles.
- `--precise` at scale (`tests/corpus/precise-benchmark.md`): measured across 76 repositories (72 compiling, 8,158 packages) on both Rust `1.99.1` and `1.100.0`; fixed `precise::refine` so compiler-only findings where static analysis saw a source/doctest reference (doctest-only dev-dependencies and mutually-exclusive `#[cfg(not(feature = ...))]` branches masked by `--all-features`) stay `possibly-unused` instead of `likely-unused`, reaching `100.0%` precision (`16/16`) on the 35-repo blind held-out set.
- PyPI Trusted Publisher workflow (`.github/workflows/pypi.yml`): enabled version-tag trigger and `publish` job targeting the `pypi` GitHub Actions environment.
- Terminal Telemetry HUD UI: redesigned default `cargoscope scan` terminal output with a boxed `◎ CARGOSCOPE` KPI cockpit header (Rust copper + Optical Scope cyan palette, elapsed scan duration, offline/precise badge), ruled sections, severity pills (`CRIT`/`HIGH`/`MED`/`LOW`), optical relevance indicators (`⌖ affects-you` / `◐ possibly` / `◌ unlikely`), clickable OSC 8 links on advisory IDs, proportional weight bars for heaviest direct dependencies, and a segmented license distribution bar (`--verbose` and `NO_COLOR` preserved cleanly).
- Terminal HUD fits the terminal: the report follows `COLUMNS` or the terminal's width (60 to 120 columns, 100 when unknown), KPI cells wrap onto more rows, long advisory details and policy messages wrap instead of running past the edge, the fix column moves under the advisory on narrow terminals, other lines are cut with `…`, the header names the project directory instead of `.`, and advisories ranked `unlikely` take one dimmed line.
- README overhaul: adaptive GitHub dark/light hero (`banner.svg` / `banner-light.svg`), refreshed Telemetry HUD `scan.gif`, KPI benchmark table, embedded `pipeline.svg`, HTML/PR preview cards, and extracted [docs/commands.md](docs/commands.md) and [docs/github-action.md](docs/github-action.md).

## 0.8.0 (2026-11-18)

- Update PR comment commands (#23): `/cargoscope rebase`, `/cargoscope recreate`, and `/cargoscope ignore this version | major version | minor version | dependency` (also `@cargoscope ...`) via `cargoscope fix --updates --comment-command ... --pr-body ...` and `action.yml` on `issue_comment` events.
- `cargoscope aggregate REPORT.json... [--format text|json|html]` merges JSON reports from multiple projects into a single view of shared advisories (ranked by relevance), licenses, outdated direct dependencies, and unused dependencies (#24).
- Unused dependencies & `cargoscope fix`: cleans `dep:<crate>`, `<crate>/feature`, and `<crate>?/feature` entries from `[features]` when deleting unused dependencies, lets `cargoscope fix` act on `possibly-unused` findings with `--include-uncertain` or explicit `--only`, stops keeping non-transitive `optional = true` crates wired only via `dep:` as uncertain, and follows `#[cfg_attr(..., path = "...")]` on module declarations.
- `cargoscope audit-bin` now supports `--format sarif`, `--format cyclonedx`, `--format html`, `--output FILE`, and `--color`.
- Colored terminal output (`--color auto|always|never`) across `why`, `fix` (`unused`, `--advisories`, `--updates`), `compare`, and `audit-bin` (#22).
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
