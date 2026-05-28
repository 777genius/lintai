# lintai-cli

`lintai-cli` is the npm wrapper package for the `lintai` native CLI.

It downloads the matching GitHub Release binary for the current platform, verifies it against `SHA256SUMS`, caches it locally, and then runs `lintai`.

The package does not ship native binaries inside the npm tarball. GitHub Release assets remain the canonical binary source.

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
- `LINTAI_NPM_RELEASE_TAG` - override the release tag, for example `v0.1.1`
- `LINTAI_NPM_SKIP_DOWNLOAD=1` - skip `postinstall` download
