# fixable-comments

This sample repo demonstrates the first safe-first `lintai fix` workflow.

Included surfaces:

- `docs/SKILL.md`

The sample repo explicitly enables the `preview` preset so the HTML-comment rules are active.

Expected result before fixing:

- findings for `SEC101` and `SEC103`
- zero diagnostics
- zero runtime errors
- non-blocking findings under the current sample config
- `scan` exits `0`
- `fix` preview exits `0`

Run these commands from `sample-repos/fixable-comments/repo`:

```bash
cargo run --manifest-path ../../../Cargo.toml -- scan .
cargo run --manifest-path ../../../Cargo.toml -- fix .
```

To apply the fixes, run the same command in a disposable copy of this repo:

```bash
cargo run --manifest-path ../../../Cargo.toml -- fix . --apply
cargo run --manifest-path ../../../Cargo.toml -- scan .
```

Expected result after `fix . --apply`:

- the hidden HTML comment spans are removed
- a follow-up `scan .` returns zero findings
- `fix . --apply` exits `0`
