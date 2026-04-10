# External Validation Server JSON Report

> Wave 2 extension report for semantically confirmed MCP Registry `server.json` surfaces.
> Source of truth lives in [validation/external-repos-server-json/repo-shortlist.toml](../validation/external-repos-server-json/repo-shortlist.toml), current results in [validation/external-repos-server-json/ledger.toml](../validation/external-repos-server-json/ledger.toml), and archived wave 1 baseline in [validation/external-repos-server-json/archive/wave1-ledger.toml](../validation/external-repos-server-json/archive/wave1-ledger.toml).

## Cohort Composition

- `18` repos evaluated
- `12` remote-enabled repos
- `6` control repos

## Admission Results

- `containers/kubernetes-mcp-server` via `server.json`. Cached canonical-cohort repo with a valid root server.json used as a clean control for package-only transport examples.
- `vapagentmedia/vap-showcase` via `server.json`. Cached real-world MCP app repo with a root server.json and remote registry metadata under remotes[].
- `cloudflare/mcp-server-cloudflare` via `server.json`. Registry-linked MCP server repo with remote entries using streamable-http and sse.
- `googleworkspace/developer-tools` via `server.json`. Official Google Workspace developer tools repo with a root server.json and remote MCP registry metadata.
- `IO-Aerospace-software-engineering/mcp-server` via `server.json`. Public MCP server with a root server.json exposing remote-enabled registry metadata.
- `MidOSresearch/midos` via `server.json`. Committed root server.json with both packages and remote registry metadata for an MCP-enabled workspace.
- `mldotink/mcp` via `server.json`. Root server.json with remote MCP registration metadata under remotes[].
- `netdata/netdata` via `server.json`. Large production repo with a root server.json using remote URLs and variable definitions in remotes[].
- `tldraw/tldraw` via `apps/mcp-app/server.json`. Nested application server.json with streamable-http and sse remotes under an operational app path.
- `arielbk/anki-mcp` via `server.json`. Packages-only server.json used as a clean control for valid registry metadata without remote risk.
- `hashicorp/terraform-mcp-server` via `server.json`. Packages-only server.json in a high-signal production repo, suitable as a control for package transport metadata.
- `VictoriaMetrics-Community/mcp-victoriametrics` via `server.json`. Packages-only root server.json in a public production-focused MCP server repo, used as a clean control.
- `github/github-mcp-server` via `server.json`. Official GitHub MCP server with root server.json remote metadata and header configuration under remotes[].
- `onkernel/kernel-mcp-server` via `server.json`. Operational MCP server repo with a valid root server.json and remote-enabled registry metadata.
- `peek-travel/mcp-intro` via `server.json`. Public tutorial repo with a committed root server.json using remotes[] under an operational path.
- `blockscout/mcp-server` via `server.json`. Production MCP server repo with a root server.json and semantically confirmed remote registry configuration.
- `domdomegg/airtable-mcp-server` via `server.json`. Packages-only server.json admitted as a clean control for valid registry metadata without remote risk.
- `formulahendry/mcp-server-code-runner` via `server.json`. Committed server.json with package transport metadata only, suitable as a control for server-registry validation.

## Overall Counts

- `194` stable findings
- `1` preview findings
- `3` runtime parser errors
- `0` diagnostics

## Delta From Previous Wave

- stable findings: `0` -> `194`
- preview findings: `0` -> `1`
- runtime parser errors: `2` -> `3`
- diagnostics: `0` -> `0`
- admitted repo set changes:
- added `blockscout/mcp-server`
- added `domdomegg/airtable-mcp-server`
- added `formulahendry/mcp-server-code-runner`
- added `github/github-mcp-server`
- added `onkernel/kernel-mcp-server`
- added `peek-travel/mcp-intro`

## Stable Hits

- no external `Stable` hits were observed from the current `server.json` stable rule batch

## Preview Hits

- no preview hits were observed in the server-json extension wave

## Runtime / Diagnostic Notes

- `MidOSresearch/midos`: `2` runtime parser errors, `0` diagnostics (non-admission-path issue)
- `formulahendry/mcp-server-code-runner`: `1` runtime parser errors, `0` diagnostics (non-admission-path issue)

## Recommended Next Step

Keep the `server.json` surface and continue discovery; do not weaken the current transport, secret, or compatibility checks just because this wave stays clean but sparse.
