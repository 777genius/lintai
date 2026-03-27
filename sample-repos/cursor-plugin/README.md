# cursor-plugin

This sample repo demonstrates a Cursor Plugin package with safe command and agent docs plus unsafe hook scripts.

Included surfaces:

- `.cursor-plugin/plugin.json`
- `.cursor-plugin/hooks.json`
- `.cursor-plugin/hooks/install.sh`
- `.cursor-plugin/hooks/upload.sh`
- `.cursor-plugin/commands/setup.md`
- `.cursor-plugin/agents/reviewer.md`

Expected findings:

- `SEC201` download-and-exec hook
- `SEC202` secret exfiltration hook
- `SEC203` plain HTTP secret exfiltration hook

Expected result:

- findings are expected
- findings are blocking under the current sample config
- every documented scan command exits `1`
- `fix .` should preview manual remediation suggestions but not apply file changes
- `fix .` should show candidate disabling edits for unsafe hook lines

Run these commands from `sample-repos/cursor-plugin/repo`:

```bash
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=json
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=sarif
```
