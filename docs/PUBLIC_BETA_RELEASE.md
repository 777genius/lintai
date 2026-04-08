# lintai Public Beta Release

> Canonical release contract for the first public beta.
> This document turns the Phase 3 roadmap into a concrete release posture for `lintai`.

## Release Identity

- Release name: `lintai v0.1.0-beta.1`
- Release posture: public beta
- Audience: security-minded early adopters and CI trials
- Distribution channel: GitHub Releases with prebuilt binaries only

`lintai` is **not** positioned as `1.0` in this release.

## Product Contract

The public beta keeps the existing `v0.1` product contract unchanged:

- supported surfaces are exactly the current `v0.1` scope
- `Stable` findings are the release-quality baseline
- `Preview` findings are useful but non-baseline signals
- CLI commands, JSON schema, SARIF output, `stable_key`, and current `fix` surface do not expand in this phase

The canonical source of truth for `v0.1` scope remains [V0_1_RELEASE_CHARTER.md](V0_1_RELEASE_CHARTER.md).

## Packaging and Compatibility

- The CLI is distributed through GitHub binary artifacts only in this beta.
- GitHub Release assets may include convenience installer scripts such as `lintai-installer.sh` and `lintai-installer.ps1`; they remain part of the same release-asset channel, not a parallel package-manager channel.
- GitHub Release assets also carry release-verification artifacts for this beta: `SHA256SUMS`, a CycloneDX SBOM bundle, and a provenance attestation bundle for the published files.
- The canonical in-repo verification flow is [../scripts/release/verify-release-assets.sh](../scripts/release/verify-release-assets.sh), which checks `SHA256SUMS` and can verify the provenance bundle with `gh attestation verify`.
- The release promise for this phase is intentionally limited to those GitHub Release assets; users should not assume a parallel installer channel exists unless it is explicitly announced in a later release note.
- This phase does **not** promise Homebrew, npm, or `cargo install` support for the CLI.
- `lintai-api` remains the only stable publishable crate.
- All other crates remain internal-only implementation detail.

The compatibility contract remains anchored in [../PUBLIC_COMPATIBILITY_POLICY.md](../PUBLIC_COMPATIBILITY_POLICY.md).

## Evaluation and Trust Posture

Users evaluating the beta should:

1. run it on real repositories with supported surfaces
2. separate `Stable` from `Preview` findings
3. treat `diagnostics` separately from findings
4. expect conservative, precision-first behavior

The checked-in evidence for this release posture is [EXTERNAL_VALIDATION_REPORT.md](EXTERNAL_VALIDATION_REPORT.md).

## Beta Release Note

The canonical checked-in release note for this beta is [releases/v0.1.0-beta.1.md](releases/v0.1.0-beta.1.md).

## Shipping Checklist

The canonical workflow and asset checklist for this beta lives in [PUBLIC_BETA_SHIPPING_CHECKLIST.md](PUBLIC_BETA_SHIPPING_CHECKLIST.md).
