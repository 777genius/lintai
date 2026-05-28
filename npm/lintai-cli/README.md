# lintai-cli

`lintai-cli` is the npm wrapper package for the `lintai` native CLI.

It is intended to download the matching GitHub Release binary for the current platform, verify it against `SHA256SUMS`, and then run `lintai`.

This package is checked into the repository, but it is not currently published to the public npm registry.

It also expects matching GitHub Release assets for the selected tag, so it is not a working public install path until those release assets are published.

## Intended Published Usage

```bash
npx lintai-cli scan .
```

```bash
npm i -g lintai-cli
lintai scan .
```

## Environment overrides

- `LINTAI_NPM_BASE_URL` - override the release asset base URL
- `LINTAI_NPM_CACHE_DIR` - override the local cache directory
- `LINTAI_NPM_RELEASE_TAG` - override the release tag, for example `v0.1.0`
- `LINTAI_NPM_SKIP_DOWNLOAD=1` - skip `postinstall` download
