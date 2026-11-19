<div align="center">

<img src="docs/images/logo.svg" alt="" width="88">

<h1>CargoScope</h1>

<p>One offline report for the dependencies of a Rust project.</p>

[![Crates.io](https://img.shields.io/crates/v/cargoscope.svg)](https://crates.io/crates/cargoscope)
[![PyPI](https://img.shields.io/pypi/v/cargoscope.svg)](https://pypi.org/project/cargoscope/)
[![CI](https://github.com/HarpeLm/CargoScope/actions/workflows/ci.yml/badge.svg)](https://github.com/HarpeLm/CargoScope/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Install](#install) · [Usage](#usage) · [GitHub Action](#github-action) · [Documentation](#documentation)

<br>

<img src="docs/images/scan.gif" alt="cargoscope scan in a terminal" width="820">

</div>

<br>

<div align="center">

<h2>What it checks</h2>

</div>

| Check | What you get | Instead of |
|---|---|---|
| **Advisories** | RustSec, plus GitHub advisories and malicious crates from OSV, ranked by whether your build is exposed: `affects-you`, `possibly`, `unlikely` | `cargo-audit` |
| **Unused dependencies** | Static analysis, or checked by the compiler with `--precise` | `cargo-machete`, `cargo-shear` |
| **Policy** | Licenses, bans and sources, read from `cargoscope.toml` or your `deny.toml` | `cargo-deny` |
| **Versions** | Compatible and breaking updates, yanked crates, duplicates, maintenance | `cargo-outdated` |
| **Fixes** | Dry-run edits to `Cargo.toml` and `Cargo.lock`, or pull requests from the Action | Dependabot |

<p align="center">
Nothing runs from your dependencies, and nothing touches the network unless you run <code>cargoscope update</code>.
</p>

<div align="center">

<h2>Install</h2>

</div>

```sh
cargo install cargoscope
```

<details>
<summary>Other ways to install</summary>

```sh
# macOS and Linux, prebuilt binary
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/HarpeLm/CargoScope/releases/latest/download/cargoscope-installer.sh | sh

# Homebrew
brew install HarpeLm/tap/cargoscope

# npm
npx cargoscope scan . --update

# PyPI
pip install cargoscope
```

```powershell
# Windows, prebuilt binary
irm https://github.com/HarpeLm/CargoScope/releases/latest/download/cargoscope-installer.ps1 | iex
```

```sh
# Docker (use the :full tag for fix and --precise)
docker run --rm -v "$PWD:/src" -v cargoscope-cache:/cache ghcr.io/harpelm/cargoscope update .
docker run --rm -v "$PWD:/src" -v cargoscope-cache:/cache ghcr.io/harpelm/cargoscope scan .
```

```yaml
# GitLab CI
cargoscope:
  image:
    name: ghcr.io/harpelm/cargoscope:0.9.1
    entrypoint: [""]
  script:
    - cargoscope update .
    - cargoscope scan . --format sarif --output cargoscope.sarif --fail-on high
```

</details>

<div align="center">

<h2>Usage</h2>

</div>

```sh
cargoscope update             # download RustSec, OSV and crates.io data once
cargoscope scan               # the report, offline

cargoscope fix                # remove unused dependencies (dry run, --apply to write)
cargoscope fix --advisories   # update vulnerable crates
cargoscope fix --updates      # update outdated dependencies

cargoscope why serde          # why a crate is in the tree
cargoscope init --ci          # create cargoscope.toml and a CI workflow
```

<p align="center">
Reports also come as <code>--format json</code>, <code>sarif</code>, <code>html</code> or <code>cyclonedx</code>.<br>
<a href="docs/try-it.md">Two-minute walkthrough</a> · <a href="docs/commands.md">All commands</a>
</p>

<div align="center">

<h2>GitHub Action</h2>

</div>

```yaml
- uses: HarpeLm/CargoScope@v0.9.1
  with:
    fail-on: high
```

<p align="center">
Scans every pull request, and can open security and update pull requests on a schedule.<br>
<a href="docs/github-action.md">Action documentation</a>
</p>

<div align="center">

<h2>Benchmarks</h2>

</div>

| Median offline scan | Advisories vs `cargo-audit` | Policy vs `cargo-deny` | Unused precision |
|:---:|:---:|:---:|:---:|
| 22 ms | 1,376 / 1,376 (`--rustsec-only`) | 44 / 44 | 100% with `--precise` |

<p align="center">
<a href="tests/corpus/README.md">Methodology and raw results</a>
</p>

<div align="center">

<h2>Documentation</h2>

[Commands](docs/commands.md) · [GitHub Action](docs/github-action.md) · [Policy](docs/policy.md) · [JSON report](docs/json-report.md) · [Compatibility](docs/compatibility.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

<br>

Contributions and false-positive reports are welcome: [CONTRIBUTING.md](CONTRIBUTING.md) · [feedback issue](https://github.com/HarpeLm/CargoScope/issues/1)

MIT License

</div>
