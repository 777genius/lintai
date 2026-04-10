# lintai — Positioning and Scope

> Canonical product-positioning note for `v0.1`.
> This document explains who `lintai` is for, what it is meant to catch, and what it does not promise yet.

## One Sentence

`lintai` is an offline-first, precision-first linter for repository-local AI agent artifacts and policy contracts: skills, MCP configs, hooks, permissions, Cursor rules, and adjacent plugin surfaces.

## Who It Is For

`lintai` is a strong fit for:

- teams that keep agent instructions, MCP configs, or plugin surfaces in git and want deterministic CI checks
- teams that want a quiet practical default plus explicit deeper-review sidecar lanes
- security-conscious repositories that prefer offline scanning over cloud upload
- maintainers who want structured findings, SARIF, stable rule ids, and explicit remediation support
- early users willing to use a narrow but disciplined ruleset instead of a broad speculative scanner

## Who It Is Not For

`lintai v0.1` is intentionally not aimed at:

- users who want broad registry crawling, package reputation, or cloud-managed threat intelligence
- teams expecting full IDE/LSP workflows, interactive triage UI, or hosted policy management
- users who need every AI platform and agent ecosystem covered from day one
- users who prefer aggressive heuristic detection even when it increases false positives materially

## What It Tries to Catch

The current shipped lanes are optimized for high-signal repository-local review such as:

- quiet default `recommended` checks for committed config and shared-policy signals that are easy to explain and review often
- deeper-review `preview` checks for useful but more contextual findings
- explicit `threat-review`, `compat`, `governance`, and `supply-chain` sidecar lanes for malicious-behavior review, contract quality, workflow policy, and supporting hardening controls
- hidden or override-style instructions in agent-facing text surfaces
- hook scripts that download-and-execute, exfiltrate secrets, disable TLS verification, or embed static auth
- MCP and plugin JSON configurations that shell out unsafely, use insecure endpoints, disable trust checks, pass through sensitive credentials, or launch remote tooling through mutable execution paths

The generated current rule inventory is documented in [SECURITY_RULES.md](SECURITY_RULES.md).

## What It Does Not Try to Do in `v0.1`

`lintai` does not currently try to be:

- a general-purpose malware sandbox
- a package registry or supply-chain reputation service
- an LLM-as-judge system for ambiguous intent classification
- a broad “scan everything AI-related on the internet” platform
- a full plugin ecosystem with third-party rule packs as part of the initial public contract
- a product where every useful finding is framed as a headline security issue

## Precision and Noise Policy

`lintai` prefers narrow, explainable, deterministic findings over maximal coverage.

That means:

- structural rules are the primary source of `Stable` findings
- heuristic rules stay in `Preview` until they have enough corpus and precision evidence
- “noisy but maybe useful” detection is not promoted into the stable contract just to increase apparent coverage
- some `Stable` findings outside the core AI-native thesis, such as unpinned third-party GitHub Actions, are intentionally positioned as supporting supply-chain hardening controls rather than claims of critical repository compromise
- compatibility and workflow-policy checks can still be valuable, but should stay in explicit sidecar lanes instead of inflating the main default security story

For the canonical rule-quality policy, see [RULE_QUALITY_POLICY.md](RULE_QUALITY_POLICY.md).

## Release Posture

The honest release posture for the current state is:

- initial public release now: `v0.1.0`
- practical `0.x` tool for real repository trials now
- distributed through GitHub Releases with prebuilt binaries only in this phase
- not yet positioned as a broad `1.0` security platform for the whole AI ecosystem

The current confidence base is the completed wave 2 external validation report in [EXTERNAL_VALIDATION_REPORT.md](EXTERNAL_VALIDATION_REPORT.md).

## Evaluation Guidance

The right way to evaluate `lintai` today is:

1. run it on repositories that already contain agent instructions, MCP configs, or Cursor Plugin surfaces
2. evaluate `recommended` first, then add `preview` and sidecar lanes deliberately
3. treat `diagnostics` separately from findings and from fatal runtime errors
4. record false positives, false negatives, and ambiguous cases explicitly
5. use MCP, plugin, hooks, and skills evidence as the primary signal for product usefulness; treat sidecar surfaces such as GitHub Actions and config compatibility as supporting evidence only

This is intentionally a precision-first rollout, not a “ship 100 rules first and validate later” strategy.
