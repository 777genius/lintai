# lintai v0.1 Delivery Roadmap

## Goal

- Ship a publishable external `v0.1` core.
- Freeze feature breadth during the delivery cycle.
- Finish corpus, sample repos, and release barrier work before any `v0.2` themes.

## Current State

- Core contracts are implemented and the workspace test suite is green.
- `lintai-api` is already the only stable contract crate.
- Iterations 1-6 are already landed:
  - Iteration 1: release scaffolding and fixture contract
  - Iteration 2: benign corpus and working workspace harness
  - Iteration 3: malicious coverage for all current ai-security rules plus repo-safe edge regression
  - Iteration 4: compatibility snapshots for `json`, `sarif`, `explain-config`, and `stable_key`
  - Iteration 5: real sample repos and end-to-end sample-repo coverage
  - Iteration 6: release barrier workflows and cross-platform smoke
- `ARCH_GAPS.md` still leaves final `v0.1` blockers:
  - docs-command certification has not yet been observed green on a candidate commit
  - final release-candidate validation has not been run yet
- Iteration 7 is intentionally split:
  - Phase A: docs hardening, docs-command gate, release checklist
  - Phase B: observe one green dry release and only then clear `ARCH_GAPS.md`

## Locked Constraints

- No new artifact kinds.
- No new public crates.
- No ecosystem, runtime host, or plugin loading work.
- No broad platform expansion beyond the locked `v0.1` surface.

## Iterations

1. Iteration 1: Release scaffolding and fixture contract. Done.
2. Iteration 2: Benign corpus and internal harness expansion. Done.
3. Iteration 3: Malicious and edge corpus. Done.
4. Iteration 4: Compatibility snapshots. Done.
5. Iteration 5: Sample repos. Done.
6. Iteration 6: GitHub Actions release barrier. Done.
7. Iteration 7: Docs hardening, docs-command gate, and first dry release. Phase A can land before final certification evidence exists.

## Definition Of Done

- All `Required For v0.1` gaps are closed.
- Sample repos are green.
- Corpus suites are green.
- Snapshot suites are green.
- Cross-platform smoke is green.

## Sequencing Rules

- No sample repo CI before sample repos exist.
- No snapshot suite before the fixture contract exists.
- No release candidate before all release gates are wired.
