# Security Policy

## Supported Versions

Security fixes are released for the latest minor version on the `main` branch.

| Version | Supported |
|---|---|
| `0.9.x` (latest release) | Yes |
| `< 0.9.0` | No — please upgrade to the latest release |

Once `1.0.0` is released, the latest `1.x` minor series will receive security fixes according to [docs/compatibility.md](docs/compatibility.md).

## Reporting a Vulnerability

**Please do not report security vulnerabilities in public GitHub issues or pull requests.**

Report vulnerabilities privately through GitHub Security Advisories:

- <https://github.com/HarpeLm/CargoScope/security/advisories/new>

Include, if possible:

- The CargoScope version (`cargoscope --version`) and OS/architecture.
- A minimal reproduction (manifest/lockfile snippet, command line, or fixture).
- The expected impact (for example: arbitrary file read, code execution during default scan, missed vulnerability on a valid advisory, or output injection in HTML/Markdown).

You can expect an initial acknowledgement within **7 days**, and coordinated disclosure once a fix is released.

## Security Model and Trust Boundaries

CargoScope is designed to inspect untrusted Rust repositories safely by default.

### What CargoScope guarantees by default

1. **No arbitrary code execution on `scan` or `audit-bin`.**
   - `cargoscope scan` reads `Cargo.toml`, `Cargo.lock`, `cargoscope.toml` / `deny.toml`, and `.rs` files directly. It never compiles the target project, never executes `build.rs`, and never expands procedural macros.
   - `cargoscope audit-bin` only reads the binary file on disk; it never executes it.
   - `cargoscope fix` (without `--precise`) edits TOML manifests directly. `cargoscope fix --advisories` and `cargoscope fix --updates` invoke `cargo update` for lockfile resolution only (no compilation, no build scripts).
2. **Offline by default.**
   - `cargoscope scan`, `compare`, `why`, `aggregate`, `audit-bin`, and `init` make no network requests unless the user explicitly runs `cargoscope update` or passes `--update` to `scan`.
   - Network commands respect `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, and `NO_PROXY`, and download only from GitHub (RustSec advisory archive, optional release notes/archived status) and crates.io (sparse index, crate metadata, and `.crate` archives for update notes).
3. **Memory safety (`unsafe_code = "forbid"`).**
   - All workspace crates forbid `unsafe` code at the compiler level (`[workspace.lints.rust] unsafe_code = "forbid"` in `Cargo.toml`).
4. **Hardened filesystem and parser limits.**
   - Source traversal does not follow symlinks outside the workspace/repository boundary (`is_within` + `symlink_metadata`).
   - Hard caps prevent resource exhaustion on hostile repositories or archives:
     - Source files: `2 MiB` per file, `32` directory depth, `20,000` files per package (`crates/cargoscope-cargo/src/unused/sources.rs`).
     - Workspace members: `4,096` (`crates/cargoscope-cargo/src/workspace.rs`).
     - License files: `1 MiB` (`crates/cargoscope-cargo/src/licenses.rs`).
     - Embedded `cargo-auditable` zlib payload: `16 MiB` decompressed (`crates/cargoscope-cargo/src/binary.rs`).
     - Advisory database archive: `64 MiB` archive, `256 KiB` per advisory file (`crates/cargoscope-advisory/src/lib.rs`).
     - crates.io responses and crate tarballs: `16 MiB` sparse index, `4 MiB` API response, `64 MiB` `.crate` archive, `1 MiB` per extracted file (`crates/cargoscope-advisory/src/crates_io.rs`, `crate_files.rs`).
5. **Output sanitization.**
   - HTML reports (`--format html`) escape HTML entities and block non-`http(s)` links (`crates/cargoscope-report/src/html.rs`).
   - Generated pull request release notes neutralize `@mentions`, `#issue` references, and cross-repository links to avoid unwanted notifications or Markdown injection (`crates/cargoscope-cli/src/update_notes.rs`).

### Opt-in modes with different trust boundaries

- **`--precise` (`cargoscope scan --precise`, `cargoscope fix --precise`):** explicitly runs `cargo check --workspace --all-targets --all-features`, which **compiles the project and runs its `build.rs` scripts and procedural macros**. Only use `--precise` on repositories you trust or inside an isolated sandbox/container.
- **`[graph]` policy filtering / `deny.toml`:** invokes `cargo tree` / `cargo metadata` (which resolves metadata without compiling project code, though Cargo reads `.cargo/config.toml` in the target tree).
- **GitHub Action `auto-merge`:** enables GitHub auto-merge on generated update PRs. As documented in [README.md](README.md), always configure required CI status checks via branch protection before enabling `auto-merge`.

### Out of scope

- Missing or delayed advisories in upstream [RustSec `advisory-db`](https://github.com/RustSec/advisory-db) (please report those directly to RustSec).
- Static unused-dependency heuristics on untrusted or macro-heavy code (false positives/negatives are normal bug reports, not security vulnerabilities).
- Code execution when the user explicitly opts into `--precise`.
