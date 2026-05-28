# lintai Public Release

> Canonical release contract for `lintai v0.1.0`.
> This document turns the public `v0.1` scope into a concrete release posture for `lintai`.

## Release Identity

- Release name: `lintai v0.1.0`
- Release posture: initial public release
- Audience: security-minded teams and early users running real repository trials
- Distribution channels: GitHub Releases with prebuilt binaries and the `lintai-cli` npm wrapper

`lintai` is **not** positioned as `1.0` in this release.

## Product Contract

The initial public release keeps the existing `v0.1` product contract unchanged:

- supported surfaces are exactly the current `v0.1` scope
- `Stable` findings are the release-quality baseline
- `Preview` findings are useful but non-baseline signals
- CLI commands, JSON schema, SARIF output, `stable_key`, and current `fix` surface do not expand in this phase

The canonical source of truth for `v0.1` scope remains [V0_1_RELEASE_CHARTER.md](V0_1_RELEASE_CHARTER.md).

## Packaging and Compatibility

- The CLI native binaries ship through GitHub binary artifacts.
- GitHub Release assets include convenience installer scripts such as `lintai-installer.sh` and `lintai-installer.ps1`; they remain part of the same release-asset channel, not a parallel package-manager channel.
- The macOS/Linux quick install path is `curl -fsSL https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh | sh`; it is a shortcut to the published GitHub Release installer asset, not a separate distribution channel.
- The `lintai-cli` npm package is a thin convenience wrapper. It downloads the matching GitHub Release asset, verifies `SHA256SUMS`, caches the native binary, and forwards arguments to `lintai`.
- The npm quick install path is `npx lintai-cli scan .`; it resolves back to the same release assets rather than a separate native binary distribution.
- GitHub Release assets also carry release-verification artifacts for this release: `SHA256SUMS`, a CycloneDX SBOM bundle, and a provenance attestation bundle for the published files.
- The canonical in-repo verification flow is [`scripts/release/verify-release-assets.sh`](https://github.com/777genius/lintai/blob/main/scripts/release/verify-release-assets.sh), which checks `SHA256SUMS` and can verify the provenance bundle with `gh attestation verify`.
- The release promise for this phase is limited to those GitHub Release assets and the `lintai-cli` wrapper over them; users should not assume any other installer channel exists unless it is explicitly announced in a later release note.
- This phase does **not** promise Homebrew or `cargo install` support for the CLI.
- `lintai-api` remains the only stable publishable crate.
- All other crates remain internal-only implementation detail.

The compatibility contract remains anchored in [../PUBLIC_COMPATIBILITY_POLICY.md](../PUBLIC_COMPATIBILITY_POLICY.md).

## Evaluation and Trust Posture

Users evaluating this release should:

1. run it on real repositories with supported surfaces
2. separate `Stable` from `Preview` findings
3. treat `diagnostics` separately from findings
4. expect conservative, precision-first behavior

The checked-in evidence for this release posture is [EXTERNAL_VALIDATION_REPORT.md](EXTERNAL_VALIDATION_REPORT.md).

## Release Note

The canonical checked-in release note for this release is [releases/v0.1.0.md](releases/v0.1.0.md).

## Shipping Checklist

The canonical workflow and asset checklist for this release lives in [PUBLIC_RELEASE_SHIPPING_CHECKLIST.md](PUBLIC_RELEASE_SHIPPING_CHECKLIST.md).
