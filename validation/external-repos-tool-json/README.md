# Tool JSON Extension Wave

This package tracks the broader tool-json extension wave for committed operational `ToolDescriptorJson` usefulness.

Purpose:

- keep the canonical `validation/external-repos/*` package unchanged as the public beta precision baseline
- measure whether `SEC314`-`SEC318` produce useful non-fixture external hits on real tool-descriptor JSON
- make repo admission deterministic and checked in
- preserve extension wave history via an archived wave 1 baseline

Workflow:

1. Maintain `repo-shortlist.toml` with exact pinned refs and semantic-confirmed `admission_paths`.
2. Run:
   - `cargo run -p lintai-cli --bin lintai-external-validation -- rerun --package=tool-json-extension`
   - `cargo run -p lintai-cli --bin lintai-external-validation -- render-report --package=tool-json-extension`
3. Review staged artifacts under `target/external-validation/tool-json-extension/`.
4. Copy the reviewed ledger into `validation/external-repos-tool-json/ledger.toml`.
5. Copy the rendered markdown into `docs/EXTERNAL_VALIDATION_TOOL_JSON_REPORT.md`.

Admission rules:

- repo must not already be in the canonical `24`-repo cohort
- repo must have at least one committed `*tools*.json` file that classifies as `ArtifactKind::ToolDescriptorJson`
- fixture-like paths are excluded
- docs/spec/schema/contracts-only path segments are excluded when they appear as literal path segments
- semantic confirmation requires a tool descriptor with string `name` and one of:
  - `inputSchema`
  - `input_schema`
  - `parameters`
  - `function.parameters`
