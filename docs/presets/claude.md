---
title: claude
layout: doc
lintaiPage: preset
presetId: claude
---

## What This Preset Enables

The `claude` preset scopes coverage to shared Claude settings and hook-policy surfaces.

That includes both:

- Claude-specific security checks
- Claude-specific compatibility and contract-quality checks that may also appear in the `compat` lane

## When To Use It

Use it when checked-in `.claude/settings.json` policy and hook configuration are part of your repository review surface.

## Tradeoffs

This preset is precise for Claude-specific config review, but it does not broaden markdown-only instruction checks by itself. Some findings in this preset are intentionally quality or compatibility signals rather than headline security findings.
