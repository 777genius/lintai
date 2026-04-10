---
title: governance
layout: doc
lintaiPage: preset
presetId: governance
---

## What This Preset Enables

The `governance` preset enables opt-in review rules for shared authority decisions that are structurally detectable, but should not be framed as headline security findings by default.

This includes both:

- shared mutation authority such as Git publication or repository-changing commands
- broad default read, write, edit, search, discovery, and fetch grants in checked-in AI-native frontmatter
- shared workflow permissions such as `curl`, `wget`, `git clone`, `git add`, or similar command grants in committed AI settings and frontmatter

## When To Use It

Use it when you want `lintai` to review repo-wide defaults such as shared Git mutation authority, shared workflow command grants, or broad bare tool grants in committed AI settings and `allowed-tools`, especially in teams that care about least privilege and workflow design in checked-in agent instructions.

## Tradeoffs

These checks are intentionally separate from both `recommended` and `preview`. They are precise, but some findings can still be legitimate workflow choices that need explicit review rather than automatic escalation.
