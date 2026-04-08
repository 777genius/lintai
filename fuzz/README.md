# Parser Fuzzing

This directory keeps the checked-in `cargo-fuzz` harnesses for parser hardening.

Current target:

- `parse_documents` - exercises JSON, YAML, and markdown/frontmatter parsing on arbitrary bytes

Local usage:

```bash
cargo install --locked cargo-fuzz --version 0.13.1
cargo fuzz run parse_documents
```

Useful shorter smoke run:

```bash
cargo fuzz run parse_documents -- -max_total_time=30
```

The fuzz target treats panics and invariant violations as bugs. It is intentionally scoped to parser entrypoints so parser hardening can evolve without coupling to higher-level rule execution.
