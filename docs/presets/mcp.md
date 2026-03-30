---
title: mcp
layout: doc
lintaiPage: preset
presetId: mcp
---

## What This Preset Enables

The `mcp` preset scopes coverage to JSON, tool descriptor, and server registry surfaces.

## When To Use It

Use it when MCP configs and tool/server descriptors are your main attack surface.

## Tradeoffs

This preset is precise for config-heavy repos, but it does not cover markdown-only instruction risks.
