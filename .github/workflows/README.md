# GitHub Workflows

Active release barrier workflows start in Iteration 6. The docs contract gate is added in Iteration 7. Canonical fixture enforcement is now required across the main release/docs pipelines.

The release barrier is split into:

- `release-barrier.yml` for the Linux blocking suites
- `cross-platform-smoke.yml` for native smoke and Linux musl build smoke
- `docs-command.yml` for the executable docs contract
- `public-release.yml` for tagged public release asset builds and GitHub Release publishing

Required aggregate checks for `v0.1` release certification:

- `Barrier Gate`
- `Smoke Gate`
- `Docs Gate`
- checked-in fixture canonicalization gate via `normalize-case-manifests --check`

Public release shipping is tag-driven:

- tag shape: `v*`
- checked-in release note path: `docs/releases/<tag>.md`
- checked-in verification helper: `scripts/release/verify-release-assets.sh`
- tagged public release also refreshes the GitHub Pages landing/download metadata after publish
- published assets:
  - `x86_64-unknown-linux-gnu`
  - `x86_64-unknown-linux-musl`
  - `aarch64-apple-darwin`
  - `x86_64-pc-windows-msvc`
  - `lintai-<tag>-sbom.tar.gz`
  - `lintai-<tag>-provenance.intoto.jsonl`
  - `SHA256SUMS`
