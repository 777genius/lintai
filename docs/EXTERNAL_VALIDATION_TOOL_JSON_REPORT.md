# External Validation Tool JSON Extension Report

> Wave 3 extension report for `ToolDescriptorJson` usefulness proof after tightening operational-only admission.
> Source of truth lives in [validation/external-repos-tool-json/repo-shortlist.toml](../validation/external-repos-tool-json/repo-shortlist.toml), current results in [validation/external-repos-tool-json/ledger.toml](../validation/external-repos-tool-json/ledger.toml), and archived wave 2 baseline in [validation/external-repos-tool-json/archive/wave2-ledger.toml](../validation/external-repos-tool-json/archive/wave2-ledger.toml).

## Cohort Composition

The extension cohort contains `8` public repositories focused on committed non-fixture tool-descriptor JSON.

- `8` `tool_json` repos total
- `7` `stress` repos
- `1` `control` repos

Broader discovery was attempted, but the target of `18` admitted repos was not reached under the stricter operational-only gate.

## Admission Results

Admitted repos and their semantic-confirmed non-fixture `ToolDescriptorJson` paths:

- `docker/hub-mcp` via `tools.json`. Seed-wave repo with committed top-level tool registration JSON used by a public MCP server.
- `OriShmila/alpha-vantage-mcp-server` via `alpha_vantage_mcp_server/tools.json`. Committed MCP server tool catalog under source control with explicit tool descriptors and inputSchema fields.
- `gitkraken/MCP-Docs` via `tools.json`. Public MCP server repo with checked-in tool descriptor JSON at repo root.
- `hanweg/mcp-tool-builder` via `tools/tools.json`. Committed non-fixture tool collection JSON using name and parameters fields.
- `TencentCloudBase/CloudBase-MCP` via `scripts/tools.json`. Committed generated tool catalog for a production MCP server, suitable as a clean-control descriptor source.
- `vapagentmedia/vap-showcase` via `mcp/tools.json`. Committed application-local MCP tool catalog with clear descriptor semantics and no excluded path segments.
- `masacento/mcp-go-example` via `tools.json`. Committed JSON-RPC tools/list response envelope whose nested result.tools payload contains valid MCP tool descriptors.
- `marklechner/kali-mcp-server` via `tools.json`. Committed top-level Kali MCP tool catalog with explicit tool descriptors and no excluded path segments.

## Overall Counts

- `8` repos evaluated
- `8` admitted tool-descriptor paths
- `0` stable findings
- `0` preview findings
- `1` runtime parser errors
- `1` diagnostics

## Delta From Previous Wave

- stable findings: `0` -> `0`
- preview findings: `0` -> `0`
- runtime parser errors: `1` -> `1`
- diagnostics: `1` -> `1`
- admitted repo set changes:
- removed `PRQELT/Autonomix`

- scarcity note: discovery exhausted before reaching the target cohort size of `18`; current admitted count is `8`

## Stable Hits

- no non-fixture external `Stable` hits were observed from `SEC314`-`SEC318`

## Preview Hits

- no preview hits were observed in the extension wave

## Runtime / Diagnostic Notes

- label legend: `admission-path issue` means the problem occurred on an admitted `ToolDescriptorJson` path; `non-admission-path issue` means the problem occurred on sibling material outside the admitted path set

- `OriShmila/alpha-vantage-mcp-server`: `1` runtime parser errors, `0` diagnostics (non-admission-path issue)
- `TencentCloudBase/CloudBase-MCP`: `0` runtime parser errors, `1` diagnostics (non-admission-path issue)

## Fixture Suppression Check

- all admitted repos passed the non-fixture path gate
- no admitted repo would have been excluded for `tests/fixtures/testdata/examples/samples`
- no admitted repo used tokenized path segments reserved for `docs/schema/spec/contracts`-only material
- no fake `Stable` usefulness signal was introduced from fixture or documentation-only paths

## Recommended Next Step

Extension evidence is not strong enough yet to justify promoting repos into the main canonical cohort; continue broader discovery or add more structural rules.
