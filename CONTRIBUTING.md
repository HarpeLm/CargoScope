# Contributing to CargoScope

Thank you for your interest in contributing! CargoScope welcomes contributions of all kinds: bug reports, documentation improvements, new features, and fixtures.

## Getting Started

1. **Fork and clone** the repository.
2. Make sure you have Rust 1.85+ installed.
3. Run the test suite to confirm everything works:

```sh
cargo test
cargo clippy -- -W clippy::pedantic
```

## Development Guidelines

### Code Style

- Follow standard Rust conventions and `rustfmt` defaults.
- `unsafe_code` is forbidden across the workspace.
- Aim for clear, well-documented public APIs with `# Errors` sections on fallible functions.

### Testing

- Add unit tests alongside the code they exercise.
- Integration tests with fixture projects go in `tests/`.
- Every new parser or adapter should include fixture files covering normal cases and edge cases.

### Commit Messages

Use clear, descriptive commit messages:

```
Detect crates used only through derive macros

Treat `#[derive(Serialize)]` and similar attributes as usage
evidence for the providing crate. Tested with fixtures covering
renamed crates and workspace-inherited dependencies.
```

## Issue Labels

- `good first issue` — small, well-scoped tasks for newcomers
- `help wanted` — tasks where community help is especially welcome
- `false-positive` — a dependency wrongly reported as unused (please attach a minimal reproduction)
- `bug` — confirmed bugs
- `documentation` — improvements to docs, examples, or guides
- `performance` — analysis speed or resource usage

## Reporting a False Positive

CargoScope only supports Rust/Cargo. The most valuable contribution is a false-positive report for unused-dependency detection:

1. Open an issue with the `false-positive` label.
2. Include the `Cargo.toml` excerpt and the code that uses the crate (or a link to a public repository and commit).
3. Once confirmed, the case becomes a fixture in `tests/` so it never regresses.

## Security

If you discover a security vulnerability, please report it responsibly. Do **not** open a public issue. Instead, email the maintainers directly (contact details in the repository).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
