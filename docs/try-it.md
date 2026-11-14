# Try Dep Scout in Two Minutes

Dep Scout reads your `Cargo.lock` and `Cargo.toml` files and tells you, in one report, which dependencies have known advisories, which look unused, which are yanked or outdated, and why each one is in your project. It never modifies your files and never runs your code.

This is the first stable version (`0.1.0`), and it is young: your feedback decides what comes next. See the end of this page.

## 1. Install (about 10 seconds)

macOS and Linux:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/HarpeLm/DepScout/releases/latest/download/depscout-installer.sh | sh
```

Windows (PowerShell):

```powershell
irm https://github.com/HarpeLm/DepScout/releases/latest/download/depscout-installer.ps1 | iex
```

Or with a Rust toolchain: `cargo install depscout`, or with Homebrew: `brew install HarpeLm/tap/depscout`.

## 2. Download the advisory data (the only step that uses the network)

From the root of a Rust project (where `Cargo.lock` is):

```sh
depscout update .
```

This downloads the RustSec advisory database and the crates.io data (versions, licenses) for your dependencies, into a local cache.

## 3. Scan (offline, read-only)

```sh
depscout scan .
```

The first line is a summary. Below it:

- **Advisories**: known RustSec advisories, with the chain that pulls the crate in and the version that fixes it.
- **Likely-unused dependencies**: declared dependencies with no use found in your code, with the evidence. These are candidates to check, not orders to delete.
- **Licenses**, **yanked versions in use**, **outdated direct dependencies**.

By default, a security vulnerability makes the command exit with code 1, as cargo-audit does. Add `--fail-on none` to only report.

## 4. Optional: go further

```sh
depscout scan . --show-uncertain     # also list dependencies that are only possibly unused, with the reason
depscout scan . --verbose            # list every resolved package with its dependency chain
depscout scan . --format json        # machine-readable report
depscout scan . --format sarif --output results.sarif   # for GitHub code scanning
depscout scan . --precise            # confirm unused dependencies with rustc (compiles your project)
```

`--precise` runs `cargo check`, so your build scripts and proc macros run: use it only on code you trust.

## 5. Tell us what happened

Open a [feedback issue](https://github.com/HarpeLm/DepScout/issues/new?template=feedback.yml). The most useful things to report:

- **A wrong finding**: a dependency reported as unused that is used, or an advisory that does not apply. Please include the `Cargo.toml` line and where the crate is used.
- **Anything confusing** in the report, an error message you did not understand, or an installation problem.
- **What you would need** to use it in CI, or to replace another tool.

Nothing is sent anywhere by Dep Scout: it has no telemetry.
