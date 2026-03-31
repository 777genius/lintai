---
title: governance
layout: doc
lintaiPage: preset
presetId: governance
---

## What This Preset Enables

The `governance` preset enables opt-in review rules for shared mutation authority and similar workflow-policy decisions that are structurally detectable, but should not be framed as headline security findings by default.

## When To Use It

Use it when you want `lintai` to review repo-wide defaults such as shared Git mutation authority, especially in teams that care about least privilege and workflow design in checked-in agent instructions.

## Tradeoffs

These checks are intentionally quieter than the core preview lane. They are precise, but some findings can still be legitimate workflow choices that need explicit review rather than automatic escalation.
