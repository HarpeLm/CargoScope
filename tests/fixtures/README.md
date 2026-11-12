# Fixtures

Small Cargo projects used by integration tests. They are never built: CargoScope only reads their files.

| Fixture | Covers |
|---|---|
| `simple` | One package, direct and transitive dependencies |
| `workspace` | Explicit workspace members contributing direct dependencies |
| `renamed` | `package = "..."` renames and dev/build dependencies |
| `multi-version` | Two versions of one crate: one direct, one pulled in transitively |
| `no-lockfile` | Missing `Cargo.lock` (execution error, exit code 2) |
