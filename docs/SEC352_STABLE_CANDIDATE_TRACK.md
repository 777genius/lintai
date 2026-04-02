# SEC352 Stable-Candidate Track

> Promotion packet for `SEC352 / MD-UNSCOPED-BASH`.
> Goal: keep the rule in `Preview` until the remaining graduation work is explicit, reviewable, and small.

## Why This Rule Is Different

`SEC352` is no longer just an "interesting preview markdown rule".

- It is structural, not prose-led.
- It produces exact evidence on parsed AI-native frontmatter.
- It held up well in the latest external validation work on normal community skills, not only offensive-security corpora.

Current promotion readiness:

- product usefulness: `9/10`
- precision confidence: `9/10`
- stable-readiness today: `8/10`

## Signal Basis

The rule triggers when AI-native markdown frontmatter grants bare `Bash` in `allowed-tools` or `allowed_tools` instead of a scoped form such as `Bash(git:*)`.

Why this is a strong basis:

- the observation is deterministic
- the span can be pointed at exactly
- the rule does not depend on phrase lists or domain wording
- remediation is obvious and reviewable

Primary implementation references:

- rule spec: [`crates/lintai-ai-security/src/registry/markdown.rs`](https://github.com/777genius/lintai/blob/main/crates/lintai-ai-security/src/registry/markdown.rs)
- detector coverage: [`crates/lintai-ai-security/src/tests.rs`](https://github.com/777genius/lintai/blob/main/crates/lintai-ai-security/src/tests.rs)

## Evidence Package

### Corpus coverage

Malicious / should-fire corpus:

- [`corpus/malicious/skill-unscoped-bash-allowed-tools/case.toml`](https://github.com/777genius/lintai/blob/main/corpus/malicious/skill-unscoped-bash-allowed-tools/case.toml)

Benign / should-stay-clean corpus:

- [`corpus/benign/skill-scoped-bash-allowed-tools-safe/case.toml`](https://github.com/777genius/lintai/blob/main/corpus/benign/skill-scoped-bash-allowed-tools-safe/case.toml)
- [`corpus/benign/skill-unscoped-bash-fixture-safe/case.toml`](https://github.com/777genius/lintai/blob/main/corpus/benign/skill-unscoped-bash-fixture-safe/case.toml)

### Regression coverage

Current targeted tests cover:

- scalar frontmatter form
- YAML list frontmatter form
- scoped `Bash(...)` negative case
- fixture/testdata suppression

Reference block:

- [`crates/lintai-ai-security/src/tests.rs`](https://github.com/777genius/lintai/blob/main/crates/lintai-ai-security/src/tests.rs)

### Field validation

Latest broad field readout:

- `1545` files scanned across official, community, and stratified cohorts
- `SEC352`: `20` findings
- manual review: `20 TP`, `0 expected-but-benign`, `0 FP`

Primary narrative reference:

- [`EXTERNAL_VALIDATION_FIELD_UPDATE_2026-03-30.md`](EXTERNAL_VALIDATION_FIELD_UPDATE_2026-03-30.md)

## Graduation Checklist

- [x] Structural, deterministic signal basis
- [x] Exact evidence span available in findings
- [x] Malicious corpus case linked
- [x] Benign corpus cases linked
- [x] Regression tests for positive and negative forms
- [x] External usefulness demonstrated outside the canonical official cohort
- [x] No current false-positive cluster in the latest stratified pass
- [ ] Convert the current broad field pass into a reproducible promotion artifact, not only a manual field-update narrative
- [ ] Complete final stable graduation metadata at the native rule-spec level
- [ ] Confirm final stable messaging for severity and remediation wording

## Current Decision

Keep `SEC352` in `Preview` for now, but treat it as the leading stable-candidate in the skills-markdown lane.

This is the intended meaning of the current lifecycle posture:

- not "the rule is weak"
- not "the signal is unproven"
- but "the remaining work is promotion discipline, not detector credibility"

## Next Promotion Actions

1. Produce one reproducible checked-in precision artifact specifically for the promotion decision.
2. Freeze the final `Stable` rationale, deterministic signal basis, and corpus links in the rule metadata.
3. Re-evaluate whether `Warn` plus `message_only` remains the right stable posture, or whether remediation text should tighten before graduation.
