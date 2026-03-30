---
title: compat
layout: doc
lintaiPage: preset
presetId: compat
---

## What This Preset Enables

The `compat` preset enables workspace policy mismatch rules as a separate policy/audit lane.

## When To Use It

Use it when project policy and repo-local artifacts need to stay aligned.

## Tradeoffs

These checks depend on meaningful policy declarations; weak policy makes the preset less useful, and this lane is intentionally not part of the default security headline.
