---
title: compat
layout: doc
lintaiPage: preset
presetId: compat
---

## What This Preset Enables

The `compat` preset enables compatibility and contract checks as a separate audit lane.

That includes:

- workspace policy mismatch rules
- shared config contract checks where the file is valid enough to parse, but still likely to misbehave or mislead reviewers
- tool-specific compatibility checks such as Claude settings quality rules that are useful, but not headline security findings

## When To Use It

Use it when project policy and repo-local artifacts need to stay aligned, or when you want shared config correctness checks without mixing them into the main security preview lane.

## Tradeoffs

These checks depend on meaningful policy declarations; weak policy makes the preset less useful, and this lane is intentionally not part of the default security headline.
