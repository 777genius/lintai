# External Repo Validation

This directory is the checked-in evidence package for `lintai` external validation.

Files:

- `repo-shortlist.toml`: canonical selected cohort
- `ledger.toml`: machine-readable latest wave results
- `archive/wave2-ledger.toml`: machine-readable wave 2 baseline

Conventions:

- `category` means primary validation focus, not exclusive repo taxonomy
- `subtype` is `stress` or `control`
- `ownership` is `official` or `community`
- all repos are pinned by commit SHA
- wave 3 counts come from rerunning the real `lintai` binary against the pinned cohort
- canonical reruns use an explicit preset matrix: `recommended`, `base`, `mcp`, `claude`, `skills`, `preview`, `supply-chain`
- explicit preset reruns use builtin presets only and do not inherit repo-local `lintai.toml` preset activation
- findings are separated into `Stable` and `Preview` using current shipped rule tiers
- canonical ledgers preserve repo-level totals, ownership, per-lane summaries, and structured adjudications for `recommended stable` hits
- recoverable parse issues are tracked in `diagnostics`; only fatal parsing stays in `runtime_errors`

Internal rerun flow:

- `cargo build -q -p lintai-cli --bin lintai --bin lintai-external-validation`
- `cargo run -p lintai-cli --bin lintai-external-validation -- rerun --lintai-bin="$(pwd)/target/debug/lintai"`
- review `target/external-validation/wave3/candidate-ledger.toml`
- `cargo run -p lintai-cli --bin lintai-external-validation -- render-report`

The public-facing summary of this package is in [../../docs/EXTERNAL_VALIDATION_REPORT.md](../../docs/EXTERNAL_VALIDATION_REPORT.md).
