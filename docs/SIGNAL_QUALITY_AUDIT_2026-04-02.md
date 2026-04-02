# Signal Quality Audit — 2026-04-02

This audit records the first repo-wide signal-quality sweep that prioritized real-world rule behavior over generic docs cleanup. The goal was to answer a narrow question for the highest-signal families: is the rule detector precise, is the product posture correct, and do the checked-in docs/tests actually defend that behavior.

## Scope

Primary review set:

- `SEC324`
- `SEC417`
- `SEC347`
- `SEC352`
- `SEC348`
- `SEC349`
- `SEC462`
- `SEC423` to `SEC427`

Related featured structural rules corrected during the same pass:

- `SEC329`
- `SEC340`

## Decision Summary

| Rule Family | Status | Why |
| --- | --- | --- |
| `SEC324` | `flagship practical` | Strong structural supply-chain control with clear remediation and low ambiguity. |
| `SEC417` | `flagship practical` | High-signal package provenance rule for mutable `pip install git+https://...` examples. |
| `SEC347` | `flagship practical` | Narrow MCP-doc launcher rule with good safety suppressions and clear guidance posture. |
| `SEC352` | `flagship practical` | Strongest least-privilege markdown signal in current field validation. |
| `SEC348` | `context-sensitive but valid` | Detector is precise, but many real docs trade reproducibility for convenience. |
| `SEC349` | `context-sensitive but valid` | High-value Docker host-escape detector, but examples can be intentionally instructional. |
| `SEC462` | `context-sensitive but valid` | Strong detector for TLS bypass guidance; context can still be training or lab material. |
| `SEC423` to `SEC427` | `governance/least-privilege` | These are real shared-authority smells, but they are not headline exploit-style security findings. |

## Family Decisions

### `SEC324` — GitHub Action pinning

- Detector shape: high precision. The rule is limited to third-party `uses:` references that are not pinned to a full commit SHA, while official `actions/*` references remain out of scope.
- Product posture: correct as a security rule.
- Severity and confidence: still appropriate as `Warn` plus `High`.
- Docs and tests: corrected. The checked-in rule page now documents the real trigger shape instead of a placeholder.
- Sweep result: keep this in the core practical set.

### `SEC417` — Unpinned `pip install git+https://...`

- Detector shape: high precision. Mutable git-backed installs trigger; immutable commit-pinned refs stay clean.
- Product posture: correct as a practical supply-chain rule.
- Severity and confidence: still appropriate as `Warn` plus `High`.
- Docs and tests: already aligned well enough; no posture change was needed.
- Sweep result: keep this in the core practical set.

### `SEC347` — Mutable MCP launcher in markdown docs

- Detector shape: high precision. The rule already gates on MCP context and suppresses safety phrasing instead of blindly matching `npx`.
- Product posture: correct in `preview`, with guidance wording rather than blame.
- Severity and confidence: still appropriate as `Warn` plus `High`.
- Docs and tests: acceptable and already narrow enough.
- Sweep result: keep as a flagship preview rule.

### `SEC352` — Bare `Bash` in frontmatter

- Detector shape: high precision. Parsed frontmatter is used instead of string splitting, and scoped `Bash(...)` forms stay clean.
- Product posture: correct as the main least-privilege flagship.
- Severity and confidence: still appropriate as `Warn` plus `High`.
- Docs and tests: already aligned and backed by field data.
- Sweep result: keep as the lead least-privilege rule.

### `SEC348` — Mutable Docker image

- Detector shape: high precision for `docker run` examples using registry-style mutable images.
- Product posture: correct only as a context-sensitive preview rule. This is reproducibility and hardening guidance more than proof of an unsafe runtime.
- Severity and confidence: `Warn` plus `High` still fits, but wording must stay careful.
- Docs and tests: acceptable.
- Sweep result: keep the rule, keep the preview posture, and avoid overselling it as a universal badness signal.

### `SEC349` — Docker host escape

- Detector shape: high precision. It targets `--privileged`, host namespaces, and Docker socket mounts in parsed Docker examples.
- Product posture: valid security signal, but still context-sensitive because infra and security labs may intentionally teach these patterns.
- Severity and confidence: `Warn` plus `High` still fits.
- Docs and tests: corrected during this sweep. The checked-in rule page now documents the real host-escape patterns instead of a placeholder.
- Sweep result: keep the detector, but preserve careful preview framing.

### `SEC462` — TLS bypass in network commands

- Detector shape: high precision. The rule only triggers when the same parsed region combines a network-capable command with explicit TLS-bypass flags or env overrides.
- Product posture: context-sensitive preview rule.
- Severity and confidence: still appropriate as `Warn` plus `High`.
- Docs and tests: acceptable.
- Sweep result: keep the rule and keep the wording grounded in copy-pastable bypass guidance rather than implying universal exploitability.

### `SEC423` to `SEC427` — Bare frontmatter tool grants

- Detector shape: high precision. Exact frontmatter tokens are used and fixture-like paths stay out of scope.
- Original issue: mispositioned. These findings were productively too loud when they lived in the main `preview + skills` lane as ordinary security findings.
- Product posture after this sweep: corrected to `governance/least-privilege`.
- Category after this sweep: `Hardening`, not general `Security`.
- Preset membership after this sweep: opt-in `governance`, not default `preview + skills`.
- Docs and tests after this sweep: corrected. The family now has exact positive and negative preset guards, and the corpus repos include `governance` so corpus tests reflect the shipped preset model instead of stale config.
- Sweep result: keep the detectors, but keep them in the quieter governance lane.

## Related Corrections Completed

These items were not the primary focus of the first-wave matrix, but they were important supporting fixes:

- `SEC329` rule docs were replaced with real mutable-launcher documentation.
- `SEC340` rule docs were replaced with real Claude-hook command-scope documentation.
- `docs/presets/advisory.md` was realigned with the site catalog wording for the active advisory snapshot model.
- `SEC756` wording was updated to talk about the active offline advisory snapshot rather than implying that only bundled data matters.

## Verification Model

This sweep intentionally used exact tests instead of hopeful pattern matches.

### Exact tests that matter for this slice

- `cargo test -p lintai-ai-security malicious_corpus_cases_trigger_expected_findings`
- `cargo test -p lintai-ai-security benign_corpus_cases_scan_cleanly`
- `cargo test -p lintai-ai-security requires_governance_preset`
- `cargo test -p lintai-cli catalog_render_matches_checked_in_markdown`
- `cargo test -p lintai-cli site_catalog_matches_checked_in_snapshot`
- `cargo test -p lintai-cli catalog_paths_have_matching_checked_in_pages`

### Process correction

During the sweep, generic `cargo test ... pattern` calls were checked against real test inventories first. `cargo test --test docs_contract -- --list`, `cargo test --test public_entrypoints -- --list`, and `cargo test --test docs_commands -- --list` were used to confirm exact test names before relying on them for verification. This avoids treating `0 tests` as a clean signal.

## Current Product Positioning

Treat these as the current top practical rules:

- `SEC324`
- `SEC417`
- `SEC347`
- `SEC352`

Treat these as useful but context-sensitive preview rules:

- `SEC348`
- `SEC349`
- `SEC462`

Treat these as governance or least-privilege review rules, not headline security findings:

- `SEC423`
- `SEC424`
- `SEC425`
- `SEC426`
- `SEC427`

## Release Matrix

Use this release matrix when deciding what to emphasize publicly.

### Core Product Signal

- `SEC324`
- `SEC417`
- `SEC347`
- `SEC352`

These rules are the best public evidence for the current product thesis: high-signal checks for AI-native configuration, instruction, and workflow artifacts with relatively low noise.

### Context-Sensitive Preview

- `SEC102`
- `SEC313`
- `SEC335`
- `SEC348`
- `SEC349`
- `SEC351`
- `SEC462`

These rules should stay shipped, but they should not be presented as the first proof of product quality. The right framing is "useful preview hardening signal that can still be domain-dependent" rather than "strong universal security hit."

### Governance / Least-Privilege Review

- `SEC423`
- `SEC424`
- `SEC425`
- `SEC426`
- `SEC427`

These rules are real shared-authority smells, but they belong in quieter policy review, not in the headline security lane.

## Next Sweep Targets

The next sensible signal-quality pass should focus on:

1. `SEC462` precision and wording against security-lab style docs.
2. The broader least-privilege family around `SEC352`, including whether `SEC404` earns enough field signal to stay prominent.
3. Additional placeholder rule pages for other rules that already have confirmed field hits but still ship weak checked-in docs.
