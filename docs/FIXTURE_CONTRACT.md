# Fixture Contract

This document is the canonical contract for checked-in corpus cases and sample repos.
It reflects the current state after Iteration 3.

## Layout

Every corpus case is a directory:

- `corpus/<bucket>/<case-id>/case.toml`
- `corpus/<bucket>/<case-id>/repo/...`

Every sample repo follows the same contract:

- `sample-repos/<repo-name>/case.toml`
- `sample-repos/<repo-name>/repo/...`
- `sample-repos/<repo-name>/README.md`

The content root inside every case is `repo/`.

## Manifest

Every case directory contains a `case.toml` manifest.

```toml
id = "skill-clean-basic"
kind = "benign" # benign | malicious | edge | compat
entry_path = "repo"

expected_output = ["text", "json", "sarif"]
expected_runtime_errors = 0
expected_runtime_error_kinds = [] # read | invalid_utf8 | parse | provider_timeout
expected_diagnostics = 0
expected_scanned_files = 1
expected_skipped_files = 0

[[expected_findings]]
rule_code = "SEC201"
stable_key = "optional canonical stable key string"
tier = "stable" # stable | preview | deprecated
min_evidence_count = 2

expected_absent_rules = ["SEC900", "SEC901"]

[snapshot]
kind = "none" # none | json | sarif | explain-config
name = ""
```

## Rules

- `entry_path` is always relative to the directory containing `case.toml`.
- In this repository, `entry_path` is currently always `repo`.
- `expected_findings` may be empty.
- `expected_runtime_error_kinds` is optional and defaults to `[]`.
- `expected_scanned_files` and `expected_skipped_files` are optional and only asserted when present.
- `expected_absent_rules` must always be present.
- Compatibility cases use `kind = "compat"` and `snapshot.kind != "none"`.
- Sample repos use the same manifest shape as corpus cases.
- Only TOML is allowed for fixture manifests.

## Edge Cases

- Checked-in edge cases are reserved for text fixtures that are stable in git.
- CRLF, invalid UTF-8, and symlink escape behavior are generated at test runtime, not stored as checked-in corpus fixtures.
