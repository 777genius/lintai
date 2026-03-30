# policy-mismatch

This sample repo demonstrates project-level capability restrictions that conflict with observed behavior and frontmatter claims.

Included surfaces:

- `lintai.toml`
- `docs/SKILL.md`
- `.cursor-plugin/plugin.json`
- `.cursor-plugin/hooks/install.sh`
- `custom/agent.md`

Expected findings:

- `SEC401` preview rule for executable behavior vs declared policy
- `SEC402` preview rule for network behavior vs declared policy
- `SEC403` preview rule for frontmatter capability conflict

The sample config explicitly overrides `SEC201` to `allow`, so the stable hook finding is not surfaced in the final scan output even though the hook behavior is still what powers the policy mismatch evidence.

`SEC401` through `SEC403` are preview-tier rules in `v0.1`.

Expected result:

- findings are expected
- the current sample config keeps scan commands non-blocking
- every documented `scan` command exits `0`
- the documented `explain-config` command exits `0`

Run these commands from `sample-repos/policy-mismatch/repo`:

```bash
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=json
cargo run --manifest-path ../../../Cargo.toml -- scan . --format=sarif
cargo run --manifest-path ../../../Cargo.toml -- explain-config custom/agent.md
```
