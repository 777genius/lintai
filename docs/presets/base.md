---
title: base
layout: doc
lintaiPage: preset
presetId: base
---

## What This Preset Enables

The `base` preset enables the core shipped stable rule set for repo-local agent artifacts.

## When To Use It

Use this as the default baseline when you want high-signal agent-artifact checks without preview or sidecar lanes.

## Tradeoffs

You get conservative coverage and minimal surprise, but preview, policy, guidance, and supply-chain sidecar checks stay out unless you opt in separately.
