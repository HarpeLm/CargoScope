# Compiler Judge

Scripts of the compiler benchmark (see [../compiler-benchmark.md](../compiler-benchmark.md)). They compile repositories in a Docker container **without network** with rustc's `unused_crate_dependencies` lint, and judge each declared dependency independently of CargoScope's code.

1. Clone the repositories of `repositories.txt` at their commits into `ORACLE/repos/<owner>_<name>`, and run `cargo fetch` in each with `CARGO_HOME=ORACLE/cargo-home` (downloads only, no code runs).
2. `sh run-judge.sh ORACLE`, then `sh retry.sh ORACLE` for repositories whose benchmarks need nightly.
3. Run CargoScope, cargo-machete and cargo-shear, writing `ORACLE/tools/cs-<repo>.json` (`cargoscope scan --checks inventory,unused --format json`), `ORACLE/tools/machete-<repo>.txt` and `ORACLE/tools/shear-<repo>.json` (`cargo shear --frozen --format json`).
4. Copy `judge.py` and `evaluate.py` into `ORACLE` and run `python3 ORACLE/evaluate.py`.

Build scripts and proc macros of the repositories run inside the container only. Use the `rust:1.99.1` image (with `RUSTUP_TOOLCHAIN` set to its toolchain, so `rust-toolchain.toml` files do not ask for a download): from Rust 1.100, Cargo reports unused dependencies itself and rustc's JSON messages no longer carry them.
