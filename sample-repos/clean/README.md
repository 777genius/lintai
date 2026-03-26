# clean

This sample repo demonstrates a small mixed-surface workspace that should scan cleanly.

Included surfaces:

- `docs/SKILL.md`
- `mcp.json`
- `.cursor-plugin/plugin.json`
- `.cursor-plugin/hooks.json`
- `.cursor-plugin/commands/setup.md`
- `.cursor-plugin/agents/reviewer.md`

Expected result:

- zero findings
- zero diagnostics
- zero runtime errors
- no blocking findings
- every documented command exits `0`

Run these commands from `sample-repos/clean/repo`:

```bash
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=json
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=sarif
```
