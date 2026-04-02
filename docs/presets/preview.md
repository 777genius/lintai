---
title: preview
layout: doc
lintaiPage: preset
presetId: preview
---

## What This Preset Enables

The `preview` preset enables core preview rules that are still gathering precision evidence inside the main artifact-security lane.

This lane can include two different shapes of shipped preview rule:

- core preview rules that already look like part of the main product thesis
- context-sensitive preview rules that are still useful, but need more domain-specific validation before they should be read as universal signals

## When To Use It

Use it when you want wider discovery for the core product thesis and are willing to review lower-stability signals.

## Tradeoffs

This preset can surface more noise than `base`; dedicated sidecar lanes like `compat`, `guidance`, `governance`, and `supply-chain` still stay explicit. It is still the main preview lane, not a catch-all guidance bucket.
