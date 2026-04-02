---
title: advisory
layout: doc
lintaiPage: preset
presetId: advisory
description: "Bundled dependency vulnerability checks that match installed lockfile versions against offline advisories."
---

## What This Preset Enables

The `advisory` preset enables offline dependency vulnerability checks driven by committed lockfiles and the bundled advisory snapshot.

## How To Enable It

Add the preset in the repository root `lintai.toml`:

```toml
[presets]
enable = ["advisory"]
```

Run `lintai scan .` from that repository root so the local config is discovered during the scan.

## When To Use It

Use it when you want concrete installed-version findings for npm dependencies without introducing live network dependency lookups into the scan path.

## Tradeoffs

This lane is intentionally opt-in and currently preview-scoped. It is narrower than a full vulnerability platform, but the findings are deterministic and tied to exact installed versions rather than manifest guesses.

## Snapshot Workflow

`lintai` ships with a bundled offline advisory snapshot. You can inspect or normalize snapshot files with:

```bash
lintai advisory-db export-bundled
lintai advisory-db update --input advisories.json --output advisories.normalized.json
```
