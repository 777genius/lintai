---
title: preview
layout: doc
lintaiPage: preset
presetId: preview
---

## What This Preset Enables

The `preview` preset enables core preview rules that are still gathering precision evidence inside the main artifact-security lane.

## When To Use It

Use it when you want wider discovery for the core product thesis and are willing to review lower-stability signals.

## Tradeoffs

This preset can surface more noise than `base`; dedicated sidecar lanes like `compat`, `guidance`, and `supply-chain` still stay explicit.
