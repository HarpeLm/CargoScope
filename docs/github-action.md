# GitHub Action (**CargoScope-Bot**)

CargoScope ships a composite GitHub Action (`action.yml` at the repository root), listed on the GitHub Marketplace as [**CargoScope-Bot**](https://github.com/marketplace/actions/cargoscope-bot).

It downloads the prebuilt binary (no Rust compilation required), caches RustSec and crates.io data across runs, and supports CI scanning, SARIF uploads, PR diff comments, automated security update PRs, and Dependabot-style dependency update PRs.

## Minimal CI Step

Drop this into any existing CI job with zero extra permissions:

```yaml
      - uses: HarpeLm/CargoScope@v0.11.0
        with:
          fail-on: high
          upload-sarif: false
```

Or generate a starter workflow automatically with `cargoscope init --ci`.

## Full PR Comment & SARIF Workflow

```yaml
permissions:
  contents: read
  security-events: write   # optional: upload SARIF to GitHub Code Scanning
  pull-requests: write     # optional: comment what the PR changes

jobs:
  cargoscope:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HarpeLm/CargoScope@v0.11.0
        with:
          fail-on: high    # or none, to report without failing
```

On pull requests, the Action scans the base branch too and posts/updates one comment listing new and resolved advisories, yanked crates, newly unused dependencies, and added/removed/changed packages. Advisories already present on the base branch do not fail the PR (`new-only: false` fails on all advisories). On pull requests from forks (read-only token), the comparison goes to the GitHub Job Summary instead of a PR comment.

**Inputs:** `version`, `path`, `fail-on`, `checks`, `sarif`, `upload-sarif`, `comment`, `new-only`, plus the PR automation inputs below.

---

## Automated Security Update PRs

Runs `cargoscope fix --advisories --apply` on a schedule and opens (or updates) a pull request whenever `Cargo.lock` or a `Cargo.toml` changes:

```yaml
on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write
  actions: write          # only needed when using ci-workflow
  security-events: write

jobs:
  security-updates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HarpeLm/CargoScope@v0.11.0
        with:
          fail-on: none
          open-pr: true
          pr-per-package: false  # true: one PR per vulnerable crate + closes resolved PRs
          ci-workflow: ci.yml    # optional: triggers workflow_dispatch on PR commits
```

Each PR lists the fixed advisories (with versions before/after and modified manifests) as well as any remaining blocked advisories with Cargo's exact reason.

---

## Dependabot-Style Version Update PRs

Opens one PR per direct dependency (or group) on a schedule — titled e.g. `Bump serde from 1.0.219 to 1.0.228` — and shows what Cargo refused and why:

```yaml
on:
  schedule:
    - cron: "0 6 * * 1"   # every Monday
  issue_comment:
    types: [created]      # enables /cargoscope rebase | recreate | ignore commands
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write
  actions: write          # optional, for ci-workflow

jobs:
  dependency-updates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HarpeLm/CargoScope@v0.11.0
        with:
          fail-on: none
          upload-sarif: false
          updates: compatible      # compatible or breaking
          updates-grouped: false   # true: combine updates into one PR
          ci-workflow: ci.yml      # optional: trigger CI on PR commit
          labels: dependencies     # optional (created automatically if missing)
          reviewers: my-org/rust   # optional GitHub users or teams
          commit-prefix: "chore(deps): "
          auto-merge: patch        # none | patch | minor (requires branch protection checks!)
```

> **Warning on `auto-merge`:** GitHub's auto-merge waits only for status checks marked **required** by a branch protection rule. Without required checks configured on your default branch, GitHub merges the PR immediately before CI runs.

### `[updates]` configuration in `cargoscope.toml`

Matches `dependabot.yml` semantics:

```toml
[updates]
open-pull-requests-limit = 5   # groups first, then individual crates
include-dev = true             # also propose dev-dependency updates (default)
ignore = [
  { name = "tokio", update-types = ["major"], reason = "migrating later" },
  { name = "aws-*" },
  { name = "regex", versions = [">= 2"] },
]
groups = [
  { name = "serde", patterns = ["serde*"] },
  { name = "patches", update-types = ["patch"], dependency-type = "production" },
]
```

Each PR body includes:
- A leading **Needs attention** section when a major version, higher MSRV (compared against the project's `rust-version`), license change, or new advisory is detected.
- Publication date, maintenance concerns, `Cargo.lock` diff, [diff.rs](https://diff.rs) comparison links, and changelog / GitHub Release notes (with `@mentions` and `#issue` references neutralized).
- Support for interactive PR comments (`issue_comment` trigger):
  - `/cargoscope rebase` / `/cargoscope recreate` (also `@cargoscope ...`)
  - `/cargoscope ignore this version`
  - `/cargoscope ignore this major version`
  - `/cargoscope ignore this minor version`
  - `/cargoscope ignore this dependency`

### Two GitHub permissions rules to know

1. **Allow GitHub Actions to open PRs:** under *Settings → Actions → General → Workflow permissions*, enable *"Allow GitHub Actions to create and approve pull requests"* (not needed if passing a PAT or GitHub App token via `token:`).
2. **CI workflows on bot PRs:** PRs created with the default `GITHUB_TOKEN` do not trigger `pull_request` workflows on their own. Pass `ci-workflow: ci.yml` (with `workflow_dispatch:` enabled in `ci.yml`) or provide a PAT / GitHub App token via `token:`.
