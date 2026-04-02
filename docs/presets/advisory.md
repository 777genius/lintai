---
title: advisory
layout: doc
lintaiPage: preset
presetId: advisory
description: "Offline dependency vulnerability checks that match installed lockfile versions against the active advisory snapshot."
---

## What This Preset Enables

The `advisory` preset enables offline dependency vulnerability checks driven by committed lockfiles and the active advisory snapshot, using the bundled dataset by default.

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

To run the advisory lane against a custom normalized snapshot, set `LINTAI_ADVISORY_SNAPSHOT` when invoking `lintai scan`:

```bash
LINTAI_ADVISORY_SNAPSHOT=/path/to/advisories.normalized.json lintai scan .
```

If the snapshot is unreadable or violates the advisory schema contract, `lintai scan` reports a runtime error and exits with code `2` instead of silently falling back to the bundled data.

The same fail-closed behavior applies when a committed lockfile records an advisory-tracked package with an invalid installed version string: `lintai scan` reports a runtime error instead of treating the advisory lane as clean.
