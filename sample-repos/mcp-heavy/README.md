# mcp-heavy

This sample repo demonstrates an MCP-focused workspace with one safe entry and three unsafe patterns.

Included surfaces:

- `docs/SKILL.md`
- `mcp.json`

Expected findings:

- `SEC301` shell-wrapper MCP command
- `SEC302` plain HTTP MCP endpoint

Expected result:

- findings are expected from the quiet default profile
- findings are non-blocking under the current sample config
- every documented command exits `0`
- `fix .` should preview manual remediation suggestions but not plan or apply file changes
- `fix .` should show a candidate HTTPS rewrite for the plain-HTTP finding

Run these commands from `sample-repos/mcp-heavy/repo`:

```bash
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=json
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=sarif
```
