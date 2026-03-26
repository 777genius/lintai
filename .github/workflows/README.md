# GitHub Workflows

Active release barrier workflows start in Iteration 6. The docs contract gate is added in Iteration 7.

The release barrier is split into:

- `release-barrier.yml` for the Linux blocking suites
- `cross-platform-smoke.yml` for native smoke and Linux musl build smoke
- `docs-command.yml` for the executable docs contract

Required aggregate checks for `v0.1` release certification:

- `Barrier Gate`
- `Smoke Gate`
- `Docs Gate`
