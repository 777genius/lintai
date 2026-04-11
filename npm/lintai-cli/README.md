# lintai-cli

`lintai-cli` is the npm wrapper for the `lintai` native CLI.

It downloads the matching GitHub Release binary for the current platform, verifies it against `SHA256SUMS`, and then runs `lintai`.

## Usage

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
