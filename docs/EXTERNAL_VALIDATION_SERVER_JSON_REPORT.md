# External Validation Server JSON Report

> Focused extension report for semantically confirmed MCP Registry `server.json` surfaces.
> Source of truth lives in [validation/external-repos-server-json/repo-shortlist.toml](../validation/external-repos-server-json/repo-shortlist.toml) and [validation/external-repos-server-json/ledger.toml](../validation/external-repos-server-json/ledger.toml).

## Cohort Composition

- `12` repos evaluated
- `8` remote-enabled repos
- `4` control repos

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

## Overall Counts

- `0` stable findings
- `0` preview findings
- `2` runtime parser errors
- `0` diagnostics

## Stable Hits

- no external `Stable` hits were observed from `SEC319`-`SEC320`

## Preview Hits

- no preview hits were observed in the server-json extension wave

## Runtime / Diagnostic Notes

- `MidOSresearch/midos`: `2` runtime parser errors, `0` diagnostics (non-admission-path issue)

## Recommended Next Step

Keep the `server.json` surface and continue discovery; do not weaken `SEC319` or `SEC320` if this first wave stays clean but sparse.
