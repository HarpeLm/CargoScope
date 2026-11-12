# CargoScope — Product Specification

> **Version 2.0**
> Open-source dependency intelligence engine, written in Rust.

## 1. Executive Summary

CargoScope is an open-source engine that helps developers **discover, evaluate, and improve** their project dependencies. It aims to unify inventory, known vulnerabilities, maintenance signals, versions, likely-unused dependencies, and transitive relationships into understandable, CI-integrable reports.

**Positioning:** "Understand every dependency in your Rust project: why it's there, what it risks, and what to do." CargoScope starts with Rust/Cargo only; other ecosystems are a long-term possibility, considered only once the Rust experience is clearly better than combining existing tools (see 5.1).

CargoScope is designed to complement Dependabot, Renovate, Snyk, and OSV-Scanner. It does not ask teams to replace an already-installed tool: they can start by running a local analysis, then add a report to CI, and progressively adopt comparison and recommendation features. Becoming a primary tool is a possibility to earn through result quality, not a promise.

Guiding principles (all four are binding): local operation without a mandatory account for the first scan; no source code transmission by default; no silent file modification; recommendations justified by evidence; result quality before number of ecosystems. Adoption, downloads, and contributions are never guaranteed.

## 2. Target Users and Problems

- **Developers and small teams**: quickly understand what's installed and what deserves action.
- **Open-source maintainers**: get reproducible checks that work locally and in CI.
- **Platform, DevOps, and security teams**: aggregate risks across multiple repositories and prioritize fixes.
- **Multi-repo organizations**: spot the same risky component across several projects.
- **Ecosystem contributors**: add or improve an adapter without rewriting the engine.

## 3. Positioning Strategy and Adoption

### Don't Start with a Migration

CargoScope must be tryable alongside existing tools and without file changes. Its adoption progression has three stages:

1. **Local complement**: `cargoscope scan .` produces a standalone diagnostic, without modifying the repository.
2. **CI presence**: the project publishes JSON or SARIF and applies team-chosen thresholds; existing checks continue to work.
3. **Continuous intelligence**: scan comparison, prioritization, repository fleet health, and guided recommendations.

### Competitive Landscape

| Project | General Role or Strength | CargoScope Angle to Validate |
|---|---|---|
| OSV-Scanner | Vulnerability analysis from OSV data and ecosystem formats | Broader report on inventory, maintenance, and decisions, reusing relevant advisories |
| cargo-deny | Cargo policies on licenses, sources, and advisories | Cross-ecosystem report and integration with specialized tools |
| cargo-machete | Detection of likely-unused Cargo dependencies | Progressively extend this analysis to other languages, with documented limits |
| depcheck | Detection of unused npm dependencies | Combine this check with inventory and other diagnostics |
| pip-audit | Python vulnerability audit | Cross-cutting report and common CI integrations |
| Renovate | Update automation, with dashboard and maintenance features | Help understand and prioritize fleet state; don't reimplement its automations without established advantage |
| Dependabot | Alerts and updates, notably in GitHub | Local/exportable diagnostic and multi-platform view as complement |
| Snyk | Developer security platform and risk management | Local and open-source option centered on an explainable report |
| Trivy | Security scanner covering multiple artifact types and configurations | Dedicated path for application dependency intelligence |

## 4. Product Differentiators

### 4.1 Dependency Intelligence

Move from isolated alerts to decision explanations. A recommendation can combine: security advisories, last known publication date, measurable maintenance activity, transitive dependency, fix availability, and estimated migration cost when verifiable data exists.

Each finding must show its evidence, provenance, freshness, and limitations.

### 4.2 Dependency Health Report

A health report can synthesize security, maintenance, dependency quality, and version coherence. A global score is a later option: it must be transparent, configurable, dated, comparable over time, and decomposable. A score never guarantees project security.

### 4.3 Dependency Graph

Represent transitive paths to answer: which component introduces this package, which components depend on it, which paths are affected, and which version is resolved?

### 4.4 Safe Fixes

A proposal command can preview changes without writing. Any application must be explicitly requested, display affected files, preserve a diff, and validate modified formats.

### 4.5 Multi-Project View

A local or CI mode can aggregate exported reports to spot components common to multiple repositories. Start without a mandatory central service.

## 5. Features and Scope

### MVP

- Manifest and lockfile discovery for announced supported formats.
- Direct and transitive inventory when a lockfile provides resolved data.
- Known advisory lookup via a documented source, with source and date.
- Text and versioned JSON report, documented CI exit codes.
- Initial analysis of likely-unused Cargo dependencies, with results presented as candidates.
- Local analysis, without code upload or automatic execution of repository scripts.

### Next Steps

- Other ecosystems (Python, Node.js, Go) are deferred: see 5.1.
- SARIF, GitHub Actions, GitLab CI, baselines, and scan comparison.
- Available version checking and maintenance indicators with provenance.
- Exportable graph, justified recommendations, then locally-generated shareable HTML report.
- Health score only after method definition, documentation, and evaluation.
- Proposed fixes in preview mode, then explicit and limited application.
- Multi-project aggregation from local reports.

### 5.1 Rust-first focus

CargoScope supports **only Rust/Cargo** until the Cargo experience is clearly better than running several tools separately. No other adapter is started before that point.

The first niche to win: **one report on a Rust project** combining inventory, advisories, unused-dependency candidates and transitive paths.

The flagship feature is **"why is this package here, and how do I fix it"**: for each finding, show the dependency chain that pulls it in (`my-app → reqwest → hyper → h2`), the resolved version, whether a fixed version exists, and which direct dependency would have to change. This is the most concrete and most demonstrable differentiator.

Stage 0 interviews (8–12 Rust maintainers) happen **before** substantial code beyond the core. They confirm which problems matter and which output formats people actually use.

### 5.2 Unused dependency detection without noise

The goal is precision over recall: missing a candidate is acceptable, a wrong one costs trust. Machine learning or reinforcement learning is not used. There is no labelled data or reward signal at the start, results would not be explainable, and the same input could give different outputs. A deterministic, evidence-based system is used instead.

**Layered evidence, from cheap to precise:**

1. **Textual scan** of `.rs` files for `use crate_name`, `crate_name::` and `extern crate` (normalizing `-` to `_` and honouring `package = "..."` renames).
2. **Syntactic scan** with a Rust parser (`syn`) to ignore comments and strings and to detect paths inside macros where possible.
3. **Optional compiler-based check** (opt-in, as `cargo-udeps` does), since it runs a build. It is never run by default because build scripts execute code.

**Known false-positive sources, handled explicitly:**

- Crates used only through macros (`serde` derive, `tokio::main`, `thiserror`).
- Usage in `build.rs` (`[build-dependencies]`), tests, benches and examples (`[dev-dependencies]`).
- Optional dependencies enabled by features, and `cfg(target_os = ...)` / platform-specific usage.
- Crates linked for side effects (allocators, `*-sys` crates, `links` keys).
- Re-exports, workspace-inherited dependencies and crate renames.

**Confidence levels, each with its evidence** (no arbitrary percentage):

- `likely-unused`: no reference found by any layer, no known exception applies.
- `possibly-unused`: no direct reference, but a pattern (macro, feature, `cfg`, `-sys`) could explain usage.
- Not reported: any reference found.

By default only `likely-unused` appears; `--show-uncertain` shows the rest.

**User control:** an ignore list in `cargoscope.toml` (or `[package.metadata.cargoscope]`) with a required reason, reported back as "ignored, reason: …", so exceptions stay visible.

**Measurement:** a published fixture corpus of real Rust crates with manually verified labels. Precision is measured on each release, and a regression blocks the release. User-reported false positives become new fixtures.

## 6. Rust Architecture

```text
cargoscope/
├── Cargo.toml
├── crates/
│   ├── cargoscope-cli/        # commands, options, exit codes
│   ├── cargoscope-core/       # canonical model, orchestration, configuration
│   ├── cargoscope-report/     # text, JSON, SARIF, later HTML
│   ├── cargoscope-advisory/   # clients, cache, advisory provenance
│   ├── cargoscope-cargo/      # Cargo.toml, Cargo.lock and resolution
│   ├── cargoscope-python/     # targeted Python formats
│   ├── cargoscope-npm/        # package.json and targeted lockfiles
│   └── cargoscope-go/         # later go.mod and go.sum
└── tests/                     # fixture repositories and integration tests
```

Pipeline: `discover → parse → normalize → analyze → report`.

## 7. Data Sources and Security

- **OSV.dev**: source to evaluate for advisories and compatible formats.
- **Ecosystem databases**: add only if they provide distinct coverage and if their use is documented.
- **Registries**: consult version metadata for obsolescence, with cache and rate limit compliance.
- **Local data**: allow caches and mirrors for isolated environments.

"No advisory found" does not mean "safe". Each finding indicates source and date.

## 8. CLI UX

```sh
cargoscope scan .
cargoscope scan . --format json --output cargoscope-report.json
cargoscope scan . --checks inventory,advisories --fail-on high
cargoscope scan . --format sarif --output results.sarif
cargoscope fix --dry-run
cargoscope fix --apply
cargoscope compare baseline.json current.json
```

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

npm and PyPI publishing comes once the corresponding ecosystems are supported. Check package-name availability on every registry before any announcement.

### Official GitHub Action (`cargoscope-action`)

A dedicated repository with a composite `action.yml` that:

1. Downloads the prebuilt binary for the requested version from GitHub Releases instead of compiling.
2. Caches the local OSV.dev advisory data between runs with `actions/cache`.
3. Runs `cargoscope scan . --format sarif` and can upload results to the GitHub Security tab via `github/codeql-action/upload-sarif`.

The action uses minimal permissions and pinned versions.

## 10. Roadmap

| Stage | Work | Exit Criterion |
|---|---|---|
| 0 — Validation | Maintainer interviews, priority problems | Recurring need identified |
| 1 — Rust Foundation | Workspace, CLI scan, model, Cargo inventory | Reproducible lockfile analysis and documented JSON |
| 2 — Minimal Security | Advisory source, cache, provenance, CI thresholds | Traceable results and tested network errors |
| 3 — Adoption without Migration | GitHub Action, GitLab example, simple install | User can try locally then add CI job |
| 4 — Precision and Comparison | Repository corpus, human validation, benchmark | Published results and limits |
| 5 — Second Ecosystem | Python recommended next; Node.js if demand justifies | Explicit coverage limits and fixtures |
| 6 — Intelligence | Measurable maintenance, justified recommendations, graph | Each recommendation has evidence |
| 7 — Shareable Report | Locally-generated HTML, optional badge | No upload required |
| 8 — Controlled Fixes | `fix --dry-run`, diff, explicit application | No change without explicit confirmation |
| 9 — Multi-Projects | Local JSON aggregation, repo and component filters | Multiple repos analyzed without central service |
| 10 — 1.0 Stabilization | Compatibility, MSRV, versioning policy, security, docs | Compatibility contracts established |

## 11. Risks and Responses

| Risk | Response |
|---|---|
| Multi-language scope too broad | Start with Cargo; expand only with tested adapter and maintenance capacity |
| False positives on unused/maintenance | Present candidates and evidence; calibrate on corpus |
| Misleading score | Start with distinct metrics; document weights and limits before aggregation |
| Inaccurate competitive comparisons | Verify current features and publish method and date |
| Risky update recommendation | Preview, diff, explicit application and validation |
| Incomplete or outdated advisories | Provenance, dates, refreshable cache, coverage warning |

## 12. Success Criteria

Before claiming stable coverage, measure on a published corpus: parsing rate, announced format compatibility, manually confirmed precision, false positives, analysis time, offline behavior, and advisory freshness. For each recommendation, verify that the explanation links to evidence. Growth objectives remain targets, never guarantees of adoption or superiority.
