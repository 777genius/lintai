# GitHub Actions Extension Wave

This package tracks focused external validation for semantically confirmed GitHub Actions workflow YAML.

Purpose:

- keep the canonical `validation/external-repos/*` package unchanged as the public beta precision baseline
- measure whether `SEC324` and `SEC325` produce useful external `Stable` and `Preview` hits on real workflow surfaces
- keep workflow evidence separate from tool-json and `server.json` evidence
- make repo admission deterministic and checked in

Workflow:

1. Maintain `repo-shortlist.toml` with exact pinned refs and semantic-confirmed `admission_paths`.
2. Run:
   - `cargo run -p lintai-cli --bin lintai-external-validation -- rerun --package=github-actions-extension`
   - `cargo run -p lintai-cli --bin lintai-external-validation -- render-report --package=github-actions-extension`
3. Review staged artifacts under `target/external-validation/github-actions-extension/`.
4. Copy the reviewed ledger into `validation/external-repos-github-actions/ledger.toml`.
5. Copy the rendered markdown into `docs/EXTERNAL_VALIDATION_GITHUB_ACTIONS_REPORT.md`.

Admission rules:

- repo must contain at least one semantically confirmed GitHub Actions workflow YAML file
- admitted paths live under `.github/workflows/`
- semantic confirmation requires a top-level mapping with `jobs` and at least one of `on`, `permissions`, `uses`, or `run`
- overlap with canonical, tool-json, and server-json packages is allowed because this package is surface-scoped
