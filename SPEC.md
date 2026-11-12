# CargoScope — Product Specification

> **Version 2.0**
> Open-source dependency intelligence engine, written in Rust.

## 1. Executive Summary

CargoScope is an open-source engine that helps developers **discover, evaluate, and improve** their project dependencies. It aims to unify inventory, known vulnerabilities, maintenance signals, versions, likely-unused dependencies, and transitive relationships into understandable, CI-integrable reports.

**Positioning:** "Understand every dependency in your Rust project: why it's there, what it risks, and what to do." CargoScope starts with Rust/Cargo only; other ecosystems are a long-term possibility, considered only once the Rust experience is clearly better than combining existing tools (see 5.1).

CargoScope is designed to complement Dependabot, Renovate, Snyk, and OSV-Scanner. It does not ask teams to replace an already-installed tool: they can start by running a local analysis, then add a report to CI, and progressively adopt comparison and recommendation features. Becoming a primary tool is a possibility to earn through result quality, not a promise.

Guiding principles (all four are binding): local operation without a mandatory account for the first scan; no source code transmission by default; no silent file modification; recommendations justified by evidence; result quality before number of ecosystems. Adoption, downloads, and contributions are never guaranteed.

## 2. Target Users and Problems

**Primary user for v0.1: open-source Rust maintainers.** Their repositories are public test material, and they already use tools such as cargo-deny or cargo-machete. Their problem: get a reproducible, explainable dependency check that works locally and in CI, without adding noise.

Secondary, served by the same features:

- **Rust developers and small teams**: quickly understand what's installed and what deserves action.

Later (not targeted by v0.1):

- **Platform, DevOps, and security teams**: aggregate risks across multiple Rust repositories and prioritize fixes.
- **Multi-repo organizations**: spot the same risky component across several projects.
- **Ecosystem contributors**: add an adapter for another ecosystem, once the Rust experience is proven.

## 3. Positioning Strategy and Adoption

### Don't Start with a Migration

CargoScope must be tryable alongside existing tools and without file changes. Its adoption progression has three stages:

1. **Local complement**: `cargoscope scan .` produces a standalone diagnostic, without modifying the repository.
2. **CI presence**: the project publishes JSON or SARIF and applies team-chosen thresholds; existing checks continue to work.
3. **Continuous intelligence**: scan comparison, prioritization, repository fleet health, and guided recommendations.

### Competitive Landscape

**Long-term goal: replacement.** CargoScope aims to eventually cover what Rust teams get today from cargo-audit, cargo-deny and cargo-machete, so that one tool is enough. Adoption still starts as a complement (see above): replacement is earned feature by feature, only when CargoScope's result for that check is measurably at least as good as the specialized tool.

Tool features overlap and evolve. Verify current documentation before any public comparison.

| Project | General Role or Strength | CargoScope Angle to Validate |
|---|---|---|
| cargo-audit | RustSec advisory checks on Cargo.lock | Same advisories, explained with transitive path and fix options |
| cargo-deny | Policies on licenses, sources, bans and advisories | Cover its checks progressively, in one report with evidence |
| cargo-machete | Fast detection of likely-unused dependencies | Lower false positives through layered evidence and confidence levels |
| cargo-udeps | Compiler-based unused dependency detection | Static by default, compiler-accurate as opt-in `--precise` mode |
| cargo-tree | Dependency tree display | "Why is it here" explanations attached to each finding |
| OSV-Scanner | Multi-ecosystem vulnerability scanning from OSV data | Rust-specific depth instead of breadth |
| Dependabot | Alerts and update PRs, notably in GitHub | Local, exportable diagnostic that runs anywhere |
| Renovate | Update automation and dependency dashboard | Understand and prioritize; don't reimplement update automation |

Any public comparison states source, date, tool versions and method. Download counts are not unique users.

## 4. Product Differentiators

These are differentiation axes to validate, not established advantages.

### 4.1 Unified report (primary differentiator)

**One command, one report** for a Rust project: inventory, advisories, likely-unused dependencies and transitive paths, instead of running cargo-audit, cargo-deny, cargo-machete and cargo-tree separately and reconciling their outputs. This is the message used everywhere (README, demo, announcements).

Each finding in the report shows its evidence, provenance, freshness and limitations, and explains **why the package is there** (dependency chain, resolved version) and **how to fix it** (fixed version available, direct dependency to change). A recommendation may also combine maintenance activity and estimated migration cost when verifiable data exists.

### 4.2 Separate health indicators, no global score

The report shows separate indicators (security, maintenance, unused dependencies, version coherence) and their trends between scans. **No aggregated health score before 1.0.** If one is considered later, it must be transparent, configurable, dated, decomposable and evaluated first. No indicator is presented as a guarantee of security.

### 4.3 Dependency graph

Answers: which component introduces this package, which components depend on it, which paths are affected, which version is resolved. Text and JSON output first; interactive visualization only after the data model is validated.

### 4.4 Safe fixes (later, not in v0.1)

A preview command shows changes without writing. Any application must be explicitly requested, display affected files, keep a diff and validate modified files. Manifests and lockfiles are never modified silently.

### 4.5 Multi-project view (later, not in v0.1)

Aggregate exported JSON reports locally or in CI to spot components shared by several repositories. No mandatory central service.

## 5. Features and Scope

### MVP (v0.1)

- **Discovery**: `Cargo.toml`, `Cargo.lock` and explicit workspace members.
- **Inventory**: direct and transitive dependencies with declared and resolved versions, from `Cargo.lock`.
- **Advisories**: RustSec advisory database, downloaded as a whole and cached locally so scans work offline after an update. Each finding shows the advisory ID, source and database date.
- **Available versions**: latest non-yanked version on crates.io for each package (stable unless only pre-releases exist), its publication date, and whether the version in use is yanked, from the local cache.
- **Licenses**: license expression of every resolved crates.io package, as published (legacy forms such as `MIT/Apache-2.0` are shown as is), with a summary by license. Reporting only, no policy enforcement yet.
- **Likely-unused dependencies**: static analysis presented as candidates with confidence levels (see 5.2).
- **"Why is it here"**: every finding (advisory, unused candidate) shows its dependency chain and resolved version, plus the fixed version when one exists.
- **Output**: text, versioned JSON and SARIF; documented, stable CI exit codes.
- **Safety**: local analysis only, no code upload, no execution of repository scripts or builds.

### Next Steps

- Other ecosystems (Python, Node.js, Go) are deferred: see 5.1.
- GitHub Action, GitLab CI example, baselines and scan comparison.
- License and source policies, banned crates (toward covering cargo-deny).
- Opt-in compiler-accurate `--precise` mode for unused dependencies.
- Available version checking and maintenance indicators with provenance.
- Exportable graph, then locally-generated shareable HTML report.
- Proposed fixes in preview mode, then explicit and limited application.
- Multi-project aggregation from local reports.

### 5.1 Rust-first focus

CargoScope supports **only Rust/Cargo** until the Cargo experience is clearly better than running several tools separately. No other adapter is started before that point.

The first niche to win: **one report on a Rust project** combining inventory, advisories, unused-dependency candidates and transitive paths.

The key feature inside the unified report is **"why is this package here, and how do I fix it"**: for each finding, show the dependency chain that pulls it in (`my-app → reqwest → hyper → h2`), the resolved version, whether a fixed version exists, and which direct dependency would have to change. This is the most concrete and most demonstrable differentiator.

There is no interview phase: priorities are adjusted from feedback after publication.

### 5.2 Unused dependency detection without noise

The goal is precision over recall: missing a candidate is acceptable, a wrong one costs trust. Machine learning or reinforcement learning is not used. There is no labelled data or reward signal at the start, results would not be explainable, and the same input could give different outputs. A deterministic, evidence-based system is used instead.

**Layered evidence, from cheap to precise:**

1. **Token scan** (default) of every `.rs` file in `src/`, `tests/`, `benches/`, `examples/` and custom target paths, using the `proc-macro2` lexer. Comments and string literals are ignored, while paths inside macro invocations and attributes are seen. A dependency counts as used when its key (with `-` read as `_`) appears as `name::`, after `use`, or after `extern crate`. Build dependencies are searched only in the build script. Dev-dependencies are also searched in doc comments, where doctests use them.
2. **Text fallback**: a file that cannot be tokenized is searched as plain text, and every finding of that package is lowered to `possibly-unused`.
3. **Optional compiler-based check** (opt-in `--precise`, v0.2), since it runs a build. It is never run by default because build scripts execute code.

**Known false-positive sources, handled explicitly** (each lowers a finding to `possibly-unused` and is shown as evidence):

- `-sys` crates, often linked only for their native library.
- Optional dependencies, which may only forward a feature.
- Platform-specific dependencies (`[target.'cfg(...)'.dependencies]`).
- Dependencies declared with `features` or `default-features` that are also transitive: they may exist only to select features.
- Sources that `include!` code generated in `OUT_DIR` by a build script.
- Dev-dependencies when no `tests/`, `benches/` or `examples/` file exists, or when the directory is a published package copy (`Cargo.toml.orig` present), since test files are often excluded from published packages.
- Renames (`package = "..."`) and workspace inheritance (`workspace = true`) are resolved.

A local module with the same name as a dependency counts as a use: this can hide an unused dependency, which is accepted (precision over recall).

**Confidence levels, each with its evidence** (no arbitrary percentage):

- `likely-unused`: no reference found by any layer, no known exception applies.
- `possibly-unused`: no direct reference, but a pattern (macro, feature, `cfg`, `-sys`) could explain usage.
- Not reported: any reference found.

By default only `likely-unused` appears; `--show-uncertain` shows the rest.

**User control:** an ignore list in `[package.metadata.cargoscope]`, `ignore-unused = [{ name = "dep", reason = "..." }]`. The reason is required; an entry without one is not applied and produces a warning. Ignored dependencies are reported back as "ignored, reason: …", so exceptions stay visible. A standalone `cargoscope.toml` may come later.

**Corpus** (2026-11-12, see `tests/corpus/README.md`): 55 pinned repositories: 30 used to design the rules, then two held-out sets labelled before any change. Precision of `likely-unused` was **90.9%** (10 of 11) on the first held-out set and **93.6%** (103 of 110) on the second, larger one: below the 97% target. Both causes found in the second set were then fixed (paths generated by workspace proc macros, `#[path]` modules inside functions), so a third held-out set is needed before claiming the target. Paths generated by proc macros from outside the workspace remain invisible to static analysis. `cargo run -p cargoscope-corpus` replays the corpus and fails on any wrong or unlabelled finding, or below 97%.

**Measurement:** v0.1 ships with a hand-labelled corpus of 20–30 varied Rust crates. From v0.2, labels are produced at scale by a compiler oracle run offline in a network-less sandbox: the rustc `unused_crate_dependencies` lint aggregated over targets and features, dependency-removal experiments with `cargo check --all-targets --all-features`, and manifest-only removal commits mined from Git history as human-confirmed cases. Part of the corpus is held out for evaluation. The compiler is only a judge during development; the shipped default analysis stays static. Precision is measured on each release, and a regression blocks the release. User-reported false positives become new fixtures.

## 6. Rust Architecture

```text
cargoscope/
├── Cargo.toml
├── crates/
│   ├── cargoscope-cli/        # commands, options, exit codes
│   ├── cargoscope-core/       # data model, orchestration, configuration
│   ├── cargoscope-cargo/      # Cargo.toml / Cargo.lock parsing, resolution, unused analysis
│   ├── cargoscope-advisory/   # RustSec and crates.io data: explicit download, cache, provenance
│   └── cargoscope-report/     # text, JSON, SARIF, later HTML
└── tests/                     # fixture repositories and integration tests
```

Pipeline: `discover → parse → analyze → report`.

- **Cargo-specific data model.** Types such as `Package`, `Dependency`, `Finding`, `Evidence` and `DependencyPath` describe Cargo concepts directly. No cross-ecosystem abstraction is introduced until a second ecosystem is actually started.
- **Files are read directly** (`toml`, `cargo-lock` crates). CargoScope never invokes `cargo` or `rustc` by default: it works offline, without a Rust toolchain, and executes no project code. `cargo metadata` and builds are reserved for the opt-in `--precise` mode.
- Lockfiles are read first; declared and resolved versions are kept distinct.
- Network access (advisory database updates only) is documented, cached and can be disabled.

## 7. Data Sources and Security

### Sources

- **RustSec advisory database**: the reference Rust advisory source. Downloaded as a whole and stored locally; advisory IDs and original links are kept in every finding.
- **crates.io sparse index** (v0.1): available versions, yanked status and publication dates for resolved packages, cached locally.
- **Licenses** (v0.1): read first from the local Cargo registry sources (`$CARGO_HOME/registry/src`, no network); otherwise from the crates.io API, at most one request per second as its crawler policy asks, with a User-Agent naming the tool and its repository. A license is cached forever, since it never changes for a published version.
- Other sources (OSV.dev, GitHub advisories) are added only if they bring distinct coverage.

### Network policy

- **`cargoscope scan` never accesses the network.** It uses only local cached data.
- **`cargoscope update [PATH]`** explicitly downloads the RustSec database and refreshes crates.io data for the project at `PATH` (default `.`). Nothing is downloaded automatically. Missing crates.io data is a warning in the report, not an error.
- Every report shows the date of the advisory database and of the crates.io data used. A missing or old cache produces a visible warning, never a silent pass.
- Caches and mirrors can be configured for isolated environments.

"No advisory found" does not mean "safe".

### Hardening against untrusted repositories

Manifests, lockfiles and sources are treated as untrusted input:

- maximum file size and directory depth;
- symbolic links pointing outside the repository are not followed;
- malformed files produce readable errors, never panics;
- no project code, build script or `cargo` command is executed by default.

## 8. CLI UX

### v0.1 commands

```sh
# Download the RustSec database and refresh crates.io data (only network access)
cargoscope update

# Full report in the terminal, read-only, no network
cargoscope scan .

# JSON report for archiving or comparison
cargoscope scan . --format json --output cargoscope-report.json

# SARIF for GitHub code scanning
cargoscope scan . --format sarif --output results.sarif

# Choose checks and failure threshold
# (checks: inventory, advisories, unused, licenses, versions; skipped ones show "not checked")
cargoscope scan . --checks inventory,advisories,unused,licenses,versions --fail-on high

# Show uncertain unused candidates too
cargoscope scan . --show-uncertain
```

### Failure behaviour and exit codes

By default, **any security advisory fails the scan**, as cargo-audit does. `--fail-on <none|low|medium|high|critical>` changes the threshold; `--fail-on none` never fails on findings. Vulnerabilities without a CVSS score count at every threshold except `none`, since their severity is unknown. Informational advisories (`unmaintained`, `unsound`) are reported but never fail the scan. Unused-dependency and license findings never fail the scan unless explicitly requested.

| Code | Meaning |
|---|---|
| 0 | Scan completed, no finding at or above the threshold |
| 1 | Scan completed, at least one finding at or above the threshold |
| 2 | Execution error (unreadable file, missing advisory cache, invalid option) |

Exit codes are a stable contract from v0.1.

### Output formats

- **Text** (default): advisories, unused dependencies, licenses, yanked and outdated versions, then the inventory.
- **JSON**: described by the public schema `docs/schema/report-v1.json` and checked against it in tests. `format_version` changes only when a field is removed, renamed or changes meaning; fields may be added within a version.
- **SARIF 2.1.0**: one result per advisory (located at the package in `Cargo.lock`, with GitHub `security-severity`), per yanked version in use, and per likely-unused dependency (located at its line in `Cargo.toml`; possibly-unused ones only with `--show-uncertain`; ignored ones never). Validated against the official SARIF schema.
- `--output FILE` writes any format to a file instead of standard output.

### Later

```sh
cargoscope compare baseline.json current.json
cargoscope fix --dry-run
cargoscope fix --apply
```

`--help` is useful on every command, and a verbose mode shows the evidence behind each finding. Advisory IDs in examples come from real data, never invented.

## 9. Distribution and Release

The engine stays 100% Rust. Every distribution channel ships the same native binary; no business logic is written in another language.

### Release pipeline

```text
Git tag (v0.1.0)
      │
      ▼
GitHub Actions (cargo-dist + maturin)
      ├──▶ GitHub Releases (Linux/macOS/Windows binaries + SHA256)
      ├──▶ crates.io        (cargo install cargoscope)
      ├──▶ Homebrew tap     (brew install cargoscope)
      ├──▶ npm              (npx cargoscope)     ──► runs the native binary
      └──▶ PyPI             (pip/uvx cargoscope) ──► runs the native binary
```

- **cargo-dist**: generates the release workflow from `Cargo.toml` configuration. Prebuilt binaries for Linux (`x86_64`, `aarch64`, static `musl`), macOS (Intel and Apple Silicon) and Windows (`x86_64`, `aarch64`), with SHA256 checksums and build provenance where available.
- **Homebrew**: formula updated automatically in a `homebrew-tap` repository.
- **Shell / PowerShell installers**: one-line installers for CI pipelines that avoid compiling with `cargo install`.
- **npm**: a thin launcher package (handled by cargo-dist) that runs the prebuilt binary for the user's platform; no functional JavaScript.
- **PyPI**: `maturin` packages the Rust CLI binary into a wheel, so `pip install cargoscope` or `uvx cargoscope scan .` works without a Rust toolchain.

**All channels ship from v0.1**: GitHub Releases with installers, crates.io, Homebrew tap, npm and PyPI. npm and PyPI are distribution pipes only, so non-Rust users (for example a Python CI image) can run the tool without a Rust toolchain; they do not mean those ecosystems are analyzed. Check package-name availability on every registry before any announcement.

### Official GitHub Action (`cargoscope-action`)

Shipped with v0.1. A dedicated repository with a composite `action.yml` that:

1. Downloads the prebuilt binary for the requested version from GitHub Releases instead of compiling.
2. Runs `cargoscope update` and caches the RustSec and crates.io data between runs with `actions/cache`.
3. Runs `cargoscope scan . --format sarif` and can upload results to the GitHub Security tab via `github/codeql-action/upload-sarif`.

The action uses minimal permissions and pinned versions.

## 10. Roadmap

No dates: each version ships when its exit criteria are met. There is no interview phase; product direction comes from feedback after publication (issues, discussions, usage reports).

| Version | Work | Exit criteria |
|---|---|---|
| v0.1 — Unified Rust report | Cargo inventory, RustSec advisories, crates.io versions, licenses, static unused analysis, dependency paths, text/JSON/SARIF, exit codes, `update`, all distribution channels, GitHub Action | Every MVP item works on the fixture corpus; JSON schema documented; hand-labelled corpus of 20–30 crates passes; installs from every channel verified |
| v0.2 — Measured precision | Compiler oracle (`unused_crate_dependencies` lint, dependency-removal experiments, Git history) in a network-less sandbox on 100+ crates; public benchmark; opt-in `--precise` mode; GitLab CI example | Benchmark published with corpus, versions, commands and limits; precision regression blocks releases |
| v0.3 — Comparison and policies | `compare` between reports, baselines, license and source policies, banned crates | Covers the main cargo-deny checks with tests against its behaviour |
| v0.4 — Intelligence | Maintenance indicators with provenance, justified recommendations, exportable graph | Each recommendation links to evidence |
| v0.5 — Shareable report | Locally generated HTML report, optional badge | No upload required, data redacted by default |
| v0.6 — Controlled fixes | `fix --dry-run`, diff, explicit `fix --apply`, file validation | No change without explicit confirmation; tested on fixtures |
| v0.7 — Multi-project | Local aggregation of JSON reports, filters by repository and component | Several repositories analyzed without a central service |
| 1.0 — Stabilization | Compatibility, MSRV, versioning policy, security policy, documentation | Compatibility contracts and maintenance capacity established |

## 11. Risks and Responses

| Risk | Response |
|---|---|
| No interview phase: building something nobody needs | Publish early, track issues and feedback, adjust priorities between versions |
| Broad v0.1 delays the first release | Ship alpha pre-releases (`v0.1.0-alpha.N`) as items land; the v0.1 tag waits for all exit criteria |
| Failing on any advisory by default slows CI adoption | Document `--fail-on none` prominently in the README and Action examples |
| False positives on unused dependencies | Layered evidence, confidence levels, ignore list with reasons, compiler-oracle measurement |
| Misleading indicators | Separate indicators only, no global score before 1.0 |
| Inaccurate competitive comparisons | Verify current features, publish method and date |
| Risky fix recommendations | Preview, diff, explicit application and validation (later versions) |
| Incomplete or outdated advisory data | Provenance, database date in every report, warning on old cache |
| Untrusted repositories | No code execution by default, file limits, no symlink escape |

## 12. Success Criteria

Quality criteria only; no adoption targets.

- **Unused-dependency precision > 97%** on `likely-unused` findings, measured against the compiler oracle on the held-out corpus, before the feature is called stable.
- Parsing rate and format compatibility measured on the published corpus.
- Analysis time and offline behavior measured and documented.
- Every finding links to evidence and states its data date.
- Every report reproducible: same inputs and same cached data give the same output.
