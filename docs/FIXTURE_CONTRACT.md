# Fixture Contract

This document is the canonical Iteration 1 contract for corpus cases and sample repos.

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
expected_diagnostics = 0

[[expected_findings]]
rule_code = "SEC201"
stable_key = "optional canonical stable key string"
tier = "stable" # stable | preview | deprecated
min_evidence_count = 1

expected_absent_rules = ["SEC900", "SEC901"]

[snapshot]
kind = "none" # none | json | sarif | explain-config
name = ""
```

## Rules

- `entry_path` is always relative to the directory containing `case.toml`.
- In this repository, `entry_path` is currently always `repo`.
- `expected_findings` may be empty.
- `expected_absent_rules` must always be present.
- Compatibility cases use `kind = "compat"` and `snapshot.kind != "none"`.
- Sample repos use the same manifest shape as corpus cases.
- Only TOML is allowed for fixture manifests.
