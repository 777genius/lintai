---
title: preview
layout: doc
lintaiPage: preset
presetId: preview
---

## What This Preset Enables

The `preview` preset enables deeper-review rules that expand coverage beyond the `recommended`
default.

This lane can include two different shapes of shipped preview rule:

- strong deeper-review rules that still align with the main product thesis, but are not part of the quiet `recommended` default
- context-sensitive preview rules that are still useful, but need more domain-specific validation before they should be read as universal signals

## When To Use It

Use it when you want wider discovery and are willing to review more contextual findings alongside the quiet default.

## Tradeoffs

This preset can surface more noise than `recommended`; dedicated sidecar lanes like `compat`, `guidance`, `governance`, and `advisory` still stay explicit. It is still the main deeper-review lane, not a catch-all guidance bucket.
