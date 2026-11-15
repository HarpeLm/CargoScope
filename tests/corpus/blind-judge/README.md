# Blind Judge

The second blind benchmark of unused-dependency detection: 80 repositories never used in an earlier test ([repositories.txt](repositories.txt)), judged by the compiler on GitHub Actions ([../../../.github/workflows/blind-benchmark.yml](../../../.github/workflows/blind-benchmark.yml)).

- The tools are built once at the start of the run and frozen: CargoScope at the commit of the run, cargo-machete 0.9.2, cargo-shear 1.14.1 (default modes).
- Each repository runs on its own disposable runner ([judge-one.sh](judge-one.sh)): the tools first, then `cargo check --workspace --all-targets --all-features` with Rust 1.99.1 and rustc's `unused_crate_dependencies` lint, judged by [../compiler-judge/judge.py](../compiler-judge/judge.py), which uses no CargoScope code. Repositories that compile only without benches have their dev-dependencies left unjudged; those that do not compile are dropped.
- The last job scores the tools with [../compiler-judge/evaluate.py](../compiler-judge/evaluate.py) and uploads the `evaluation` artifact.

Unlike the first compiler benchmark, the runners have network access: they are disposable machines, so no container is needed to keep build scripts away from a personal computer.

Run it from the Actions tab (`Blind benchmark`, "Run workflow").
