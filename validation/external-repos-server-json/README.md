# Server JSON Extension Wave

This package tracks focused external validation for semantically confirmed MCP Registry `server.json` artifacts.

Purpose:

- keep the canonical `validation/external-repos/*` package unchanged as the public beta precision baseline
- measure whether `SEC319` and `SEC320` produce useful external `Stable` hits on real `server.json` surfaces
- keep registry-metadata evidence separate from client config and tool-json evidence
- make repo admission deterministic and checked in

Workflow:

1. Maintain `repo-shortlist.toml` with exact pinned refs and semantic-confirmed `admission_paths`.
2. Run:
   - `cargo run -p lintai-cli --bin lintai-external-validation -- rerun --package=server-json-extension`
   - `cargo run -p lintai-cli --bin lintai-external-validation -- render-report --package=server-json-extension`
3. Review staged artifacts under `target/external-validation/server-json-extension/`.
4. Copy the reviewed ledger into `validation/external-repos-server-json/ledger.toml`.
5. Copy the rendered markdown into `docs/EXTERNAL_VALIDATION_SERVER_JSON_REPORT.md`.

Admission rules:

- repo must contain a semantically confirmed `server.json`
- basename must be exactly `server.json`
- semantic confirmation requires a top-level object with string `name`, string `version`, and at least one of:
  - `remotes` array
  - `packages` array
- fixture-like and docs/schema/spec/contracts-only paths are excluded from admission
- overlap with canonical and tool-json packages is allowed because this package is surface-scoped
