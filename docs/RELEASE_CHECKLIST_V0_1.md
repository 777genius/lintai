# lintai v0.1 Release Checklist

This file is the repo-owned checklist for the first `v0.1` dry release and the eventual release candidate.

## Candidate

- Commit SHA: `<pending>`
- Candidate date: `<pending>`
- Outcome: `pending`

## Required GitHub Checks

These checks must be green on the candidate commit:

- `Barrier Gate`
- `Smoke Gate`
- `Docs Gate`

Branch protection is configured in GitHub, not in this repository. The release candidate is not valid unless the checks above are configured as required there.

## Required Repo Truth Checks

- `ARCH_GAPS.md` has no remaining `Required For v0.1` items.
- Root README commands are covered by the docs-command integration test.
- Sample repo README commands are covered by the docs-command integration test.
- `PUBLIC_COMPATIBILITY_POLICY.md` promises still match the implemented code.

## Dry Release Record

### Phase A: implementation

- [x] Root README rewritten around truthful executable commands.
- [x] Sample repo READMEs include expected exit behavior.
- [x] `crates/lintai-cli/tests/docs_commands.rs` added and green locally.
- [x] `.github/workflows/docs-command.yml` added.
- [x] Workflow docs updated.

### Phase B: certification

- [ ] Candidate commit SHA recorded above.
- [ ] `Barrier Gate` green on the candidate.
- [ ] `Smoke Gate` green on the candidate.
- [ ] `Docs Gate` green on the candidate.
- [ ] `ARCH_GAPS.md` cleared only after the gates above are green.

## Final Decision

- Pass: `<pending>`
- Blocking issues: `<pending>`
