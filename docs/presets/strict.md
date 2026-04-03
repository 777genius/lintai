---
title: strict
layout: doc
lintaiPage: preset
presetId: strict
---

## What This Preset Enables

The `strict` preset is an overlay, not a membership bucket. It layers stricter severity posture on top of
already-active rules, and by default that means the `recommended` default set.

## When To Use It

Use it when you want already-active security rules to escalate more aggressively without silently enabling new rules.

## Tradeoffs

This changes severity posture, so apply it deliberately and communicate the rollout expectation.
