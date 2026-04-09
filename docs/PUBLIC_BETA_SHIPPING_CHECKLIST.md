# lintai Public Beta Shipping Checklist

> Canonical shipping checklist for `v0.1.0-beta.1`.
> This document covers the tag, workflow, and asset truth for the first public beta release.

## Release Identity

- Release tag: `v0.1.0-beta.1`
- Release channel: GitHub Releases with prebuilt binaries
- Workflow: [`public-beta-release.yml`](https://github.com/777genius/lintai/blob/main/.github/workflows/public-beta-release.yml)
- Release note: [releases/v0.1.0-beta.1.md](releases/v0.1.0-beta.1.md)

## Preconditions

- `Barrier Gate` is green on the candidate commit
- `Smoke Gate` is green on the candidate commit
- `Docs Gate` is green on the candidate commit
- [PUBLIC_BETA_RELEASE.md](PUBLIC_BETA_RELEASE.md) matches the intended public beta posture
- [EXTERNAL_VALIDATION_REPORT.md](EXTERNAL_VALIDATION_REPORT.md) reflects the completed wave 2 evidence

## Expected Release Assets

The shipping workflow must publish exactly these asset classes:

- `lintai-v0.1.0-beta.1-x86_64-unknown-linux-gnu.tar.gz`
- `lintai-v0.1.0-beta.1-x86_64-unknown-linux-musl.tar.gz`
- `lintai-v0.1.0-beta.1-aarch64-apple-darwin.tar.gz`
- `lintai-v0.1.0-beta.1-x86_64-pc-windows-msvc.zip`
- `lintai-v0.1.0-beta.1-sbom.tar.gz`
- `lintai-v0.1.0-beta.1-provenance.intoto.jsonl`
- `lintai-installer.sh`
- `lintai-installer.ps1`
- `SHA256SUMS`

## Shipping Steps

1. Ensure the candidate commit already passed the required gates.
2. Create or push the `v0.1.0-beta.1` tag.
3. Let `public-beta-release.yml` build and upload the release assets.
4. Verify the GitHub Release is marked as prerelease.
5. Verify the uploaded body matches [releases/v0.1.0-beta.1.md](releases/v0.1.0-beta.1.md).
6. Verify the release assets, installer scripts, `SHA256SUMS`, SBOM bundle, and provenance bundle are present.
7. Verify the installer scripts still fetch only tagged GitHub Release assets and perform checksum validation before install.
8. Verify the workflow runs [`scripts/release/verify-release-assets.sh`](https://github.com/777genius/lintai/blob/main/scripts/release/verify-release-assets.sh) against the generated `SHA256SUMS` and provenance bundle before publish.
9. Verify the workflow published GitHub artifact attestations for the shipped release assets.
10. Verify no parallel package-manager or registry publication step was introduced for this beta workflow.

## Verification Commands

For a downloaded release directory:

```bash
./scripts/release/verify-release-assets.sh \
  --release-dir dist \
  --repo 777genius/lintai \
  --bundle dist/lintai-v0.1.0-beta.1-provenance.intoto.jsonl
```

This checks shipped file hashes from `SHA256SUMS` and then verifies the GitHub provenance bundle against each shipped asset.

Equivalent manual provenance verification uses `gh attestation verify` with the checked-in provenance bundle and a trusted root file.

## Post-Shipping Truth Check

The public-facing release posture is valid only if:

- the GitHub Release uses the checked-in release note
- the published assets match the expected target list above
- the installer scripts are shipped as convenience assets inside that same GitHub Release
- the release includes a checked-in supply-chain evidence bundle: CycloneDX SBOM plus provenance attestation bundle
- no docs imply Homebrew, npm, or `cargo install` support for the CLI in this beta
- no workflow or release note implies an alternative installation channel beyond downloading the published GitHub Release assets
