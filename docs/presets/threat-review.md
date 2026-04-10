---
title: threat-review
layout: doc
lintaiPage: preset
presetId: threat-review
---

## What This Preset Enables

The `threat-review` preset enables explicit opt-in rules for malicious, credential-bearing, or
spyware-like behavior that is useful to detect, but too aggressive to present as part of the quiet
default or the softer `preview` lane.

This includes patterns such as:

- committed hooks or command configs that exfiltrate secrets, dump environments, or execute remote payloads
- committed MCP, plugin-hook, or Claude hook commands that attempt persistence, privilege escalation, or device capture
- instruction surfaces that carry overtly dangerous hidden directives, inline execution payloads, or committed secret-bearing examples

## When To Use It

Use it when you want an explicit malicious-behavior review pass on top of the normal product
experience, especially for red-team-style audits, suspicious repos, or security triage where
spyware-like and post-exploitation patterns should be surfaced intentionally.

## Tradeoffs

These rules are strong and useful, but they are intentionally more forceful than the main `preview`
lane. Keeping them explicit helps `lintai` stay honest with the community about what belongs in the
quiet default, what belongs in broader review, and what belongs in a dedicated threat-review pass.
