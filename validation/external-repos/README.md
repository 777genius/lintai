# External Repo Validation

This directory is the checked-in evidence package for `lintai` external validation.

Files:

- `repo-shortlist.toml`: canonical selected cohort
- `ledger.toml`: machine-readable latest wave results
- `archive/wave1-ledger.toml`: machine-readable wave 1 baseline

Conventions:

- `category` means primary validation focus, not exclusive repo taxonomy
- `subtype` is `stress` or `control`
- all repos are pinned by commit SHA
- wave 2 counts come from rerunning the real `lintai` binary against the pinned cohort
- findings are separated into `Stable` and `Preview` using current shipped rule tiers
- recoverable parse issues are tracked in `diagnostics`; only fatal parsing stays in `runtime_errors`

Internal rerun flow:

- `cargo run -p lintai-cli --bin lintai-external-validation -- rerun`
- review `target/external-validation/wave2/candidate-ledger.toml`
- `cargo run -p lintai-cli --bin lintai-external-validation -- render-report`

The public-facing summary of this package is in [../../docs/EXTERNAL_VALIDATION_REPORT.md](../../docs/EXTERNAL_VALIDATION_REPORT.md).
