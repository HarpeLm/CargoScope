# JSON Report

`cargoscope scan --format json` prints a single JSON object. Its structure is described by the JSON Schema [`schema/report-v1.json`](schema/report-v1.json), and every test run checks the output of the fixtures against it.

## Compatibility policy

- `format_version` is `1`. It changes only when a field is removed, renamed, or changes type or meaning.
- New fields may be added within the same `format_version`; the schema file is updated with them. Consumers must ignore fields they do not know.
- Enum values (`scope`, `kind`, `severity`, `confidence`, `section`) may gain new values within the same version; consumers should treat unknown values as "other".

## Main fields

| Field | Content |
|---|---|
| `advisory_database`, `registry` | Data source and the date it was downloaded by `cargoscope update` (`null` if never) |
| `advisories` | Known advisories affecting resolved packages, with severity, fix and dependency `path` |
| `packages` | Every resolved package: scope, source, dependency `path`, license, latest version, yanked status |
| `unused` | Every dependency with no usage found, `likely-unused` or `possibly-unused`, with evidence; ignored ones carry `ignored_reason` |
| `warnings` | Non-fatal problems that may make results incomplete |

A `path` is the shortest chain of `{name, version}` from a root package (the project or a workspace member) to the package. "No advisory found" does not mean the dependencies are safe.
