---
title: guidance
layout: doc
lintaiPage: preset
presetId: guidance
---

## What This Preset Enables

The `guidance` preset enables advice-oriented rules that are useful, but intentionally not part of the core security baseline.

Typical examples include:

- Copilot instruction layout and `applyTo` contract checks
- Claude transcript consistency when a document explicitly prefers `uv` over bare `pip install`
- Cursor rule frontmatter hygiene and maintainability checks
- plugin-agent frontmatter boundary checks
- least-privilege advice such as wildcard tool grants in shared AI-native markdown

## When To Use It

Use it when you want product guidance such as Copilot instruction layout checks, Claude package-manager consistency checks, Cursor rule contract checks, or plugin-frontmatter boundary checks without turning those checks into headline security findings.

## Tradeoffs

These checks are intentionally advisory and should not be confused with the main trust-surface security contract.
