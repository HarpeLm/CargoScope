# Contributing to CargoScope

Thank you for your interest in contributing! CargoScope welcomes contributions of all kinds: bug reports, documentation improvements, new features, and ecosystem adapters.

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
Add Python lockfile parser for requirements.txt

Parse pinned versions from requirements.txt files, marking
each as a direct dependency. Tested with fixtures covering
comments, extras, and environment markers.
```

## Issue Labels

- `good first issue` — small, well-scoped tasks for newcomers
- `help wanted` — tasks where community help is especially welcome
- `language-adapter` — work on ecosystem-specific parsers
- `bug` — confirmed bugs
- `documentation` — improvements to docs, examples, or guides
- `performance` — analysis speed or resource usage

## Adding an Ecosystem Adapter

If you'd like to add support for a new language ecosystem:

1. Create a new crate under `crates/cargoscope-<ecosystem>/`.
2. Implement parsing for the ecosystem's manifest and lockfile formats.
3. Normalize results into the shared `Package` / `Dependency` model.
4. Add fixture files and tests covering supported format versions.
5. Document which files, format versions, and checks are supported.

You don't need to understand the entire engine — adapters are independently testable.

## Security

If you discover a security vulnerability, please report it responsibly. Do **not** open a public issue. Instead, email the maintainers directly (contact details in the repository).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
