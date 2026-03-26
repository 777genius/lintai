# lintai v0.1 Delivery Roadmap

## Goal

- Ship a publishable external `v0.1` core.
- Freeze feature breadth during the delivery cycle.
- Finish corpus, sample repos, and release barrier work before any `v0.2` themes.

## Current State

- Core contracts are implemented and the workspace test suite is green.
- `lintai-api` is already the only stable contract crate.
- `ARCH_GAPS.md` currently leaves two real `v0.1` blockers:
  - rule corpus and fixtures are too small
  - release automation and sample repos are incomplete

## Locked Constraints

- No new artifact kinds.
- No new public crates.
- No ecosystem, runtime host, or plugin loading work.
- No broad platform expansion beyond the locked `v0.1` surface.

## Iterations

1. Iteration 1: Release scaffolding and fixture contract
2. Iteration 2: Benign corpus and internal harness expansion
3. Iteration 3: Malicious and edge corpus
4. Iteration 4: Compatibility snapshots
5. Iteration 5: Sample repos
6. Iteration 6: GitHub Actions release barrier
7. Iteration 7: Docs hardening and first dry release

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
