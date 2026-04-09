# lintai — `v0.1` to `1.0` Roadmap

> Canonical post-`v0.1` roadmap.
> `docs/ROADMAP_V0_1.md` remains the closed delivery record for the original `v0.1` scope; this document tracks what comes next.

## Summary

`lintai` is past the original `v0.1` delivery bar:

- release gates are green
- `ARCH_GAPS.md` has no remaining `Required For v0.1` gaps
- the first external validation wave on `24` public repos showed:
  - `0` stable findings
  - `1` preview finding
  - `2` parser/runtime rough edges

That means the next roadmap is **precision-first public-release hardening**, not broad feature sprawl.

## Phase 1 — Precision Hardening Sprint

### Goal

Remove the only concrete noise signal from the first external wave and reduce parser/runtime roughness so the initial public release feels deliberate rather than fragile.

### Work

- Narrow `SEC105` so repo-local relative references like `../../mcp.json` do not trigger by default when they resolve to an in-repo target artifact.
- Preserve the current unsafe path-traversal detection intent for obvious parent-escape instructions.
- Improve markdown/frontmatter parsing tolerance or downgrade malformed-frontmatter cases into clearer, less alarming runtime output.
- Improve runtime error messaging so public scans look like controlled unsupported-input behavior instead of parser collapse.
- Add checked-in regressions for:
  - project-local relative config references that should stay clean
  - malformed external-style frontmatter cases that should not degrade the overall UX

### Acceptance Criteria

- `SEC105` no longer fires on the confirmed Datadog-style repo-local case.
- Existing malicious path-traversal corpus still passes.
- The two known runtime parser cases from the first external wave are either eliminated or turned into clearly non-alarming diagnostics.

## Phase 2 — External Validation Wave 2

### Goal

Re-run external validation after Phase 1 and turn the current one-off wave into a repeatable release-quality signal.

### Work

- Keep the current checked-in `24`-repo cohort as the comparison baseline.
- Re-run the full wave and update:
  - `validation/external-repos/ledger.toml`
  - `docs/EXTERNAL_VALIDATION_REPORT.md`
- Add a `Delta From Previous Wave` section to the report.
- Compare:
  - stable findings count
  - preview findings count
  - runtime parser errors
  - repo verdict changes
- If coverage is still weak in a specific area, add up to `6` repos only to fill that gap.

### Decision Policy

- If `Stable` remains clean and preview noise drops: proceed to the initial public release.
- If `Stable` produces clear false positives: stop and fix precision before release.
- If parser/runtime roughness is still visible: do one more hardening pass before release.
- If the wave is still mostly silent but clean: that is acceptable for the initial public release because the product is precision-first.

## Phase 3 — Initial Public Release

### Goal

Ship `lintai` publicly with honest positioning: narrow, precision-first, offline-first, strong `0.x` release, not inflated “AI security platform” messaging.

### Work

- Freeze the current `v0.1` product contract and present the release as the initial public release.
- Freeze distribution posture for the release itself: ship through GitHub Release assets only and avoid implying that Homebrew, npm, or `cargo install` are part of the current release contract.
- Tighten public docs around:
  - who it is for
  - what surfaces it supports
  - what `Stable` means
  - what `Preview` means
  - what it explicitly does not do
- Add a short public evaluation guide:
  - run on real repos
  - separate `Stable` from `Preview`
  - expect conservative behavior
- Add a public release note that cites the external validation wave directly.
- Make external validation part of the release story, not an internal-only artifact.

### Compatibility Constraints

- Do not widen the public API surface for this release.
- Keep `lintai-api` as the only stable publishable contract crate.
- Keep the current CLI contract, JSON schema, SARIF, stable key, and fix surface unchanged unless a narrow bug fix forces an adjustment.
- Treat additional installer channels as post-`v0.1` follow-up work, not release blockers or implied commitments.

## Phase 4 — Structural Rule Expansion After The Initial Public Release

### Goal

Grow detection power without breaking the precision-first reputation established in the initial public release.

### Rule Strategy

Only add rules that have at least one of:

- clear structural signal
- deterministic evidence
- high-confidence external-repo relevance
- easy-to-explain remediation

Prioritized next areas:

- more MCP structural auth/config misuse patterns
- plugin hook execution/network patterns
- conservative skills/instructions expansion where signals stay deterministic enough for `Preview`
- workspace policy mismatches with stronger evidence
- parser-aware instruction misuse that can stay in `Preview` until validated
- keep GitHub Actions shipped as sidecar evidence, but do not use it as the main post-`v0.1` expansion track until AI-native usefulness is stronger

### Governance

- every new rule enters through the existing spec/lifecycle/catalog flow
- heuristic rules stay in `Preview`
- no `Stable` promotion without corpus linkage and external validation evidence
- every expansion batch is followed by a focused external validation refresh

## Phase 5 — `1.0` Gate and `v0.2+`

### `1.0` Gate

Do not call the product `1.0` until all are true:

- at least two external validation waves completed
- no recurring `Stable` false-positive cluster
- parser/runtime rough edges are rare and clearly messaged
- `v0.1` users have exercised the tool outside the author’s own repos
- positioning is stable and honest
- release and compatibility policy have survived at least one public cycle without churn

### `v0.2+` Themes

Only after the initial public release loop is stable:

- widen structural rule coverage
- consider broader ecosystem surfaces
- revisit adapter split and deferred architecture items in `ARCH_GAPS.md`
- consider broader fix coverage once rule/fix safety evidence supports it
- evaluate whether extra distribution channels are worth the maintenance surface after at least one public `v0.1` cycle proves the binary-release flow is sufficient

## Operating Rules

Throughout this roadmap:

- all existing corpus, compat, docs, sample-repo, and perf tests stay green
- external validation contract tests stay green
- every external-wave bug gets a checked-in regression
- release messaging must stay grounded in checked-in docs and checked-in evidence

Immediate default priority: **Phase 1 first, not new broad rule expansion**.
