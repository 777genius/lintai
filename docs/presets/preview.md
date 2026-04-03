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

- core preview rules that still look like part of the main product thesis
- context-sensitive preview rules that are still useful, but need more domain-specific validation before they should be read as universal signals

## When To Use It

Use it when you want wider discovery and are willing to review more contextual findings alongside the quiet default.

## Tradeoffs

This preset can surface more noise than `recommended`; dedicated sidecar lanes like `compat`, `guidance`, `governance`, and `advisory` still stay explicit. It is still the main deeper-review lane, not a catch-all guidance bucket.
