# lintai Documentation

<div class="lintai-page-intro">
  <p class="lintai-kicker">Rule Guide</p>
  <h1>Browse rules and presets with less guesswork.</h1>
  <p class="lintai-lead">
    Start with the quiet `recommended` default, then opt into `preview` or explicit sidecar
    lanes like `compat`, `governance`, and `supply-chain` only when you want broader review.
  </p>
  <div class="lintai-feature-list">
    <div class="lintai-feature-item">
      <strong><a href="/rules/">Rule Reference</a></strong>
      <span>Browse every shipped rule with a short name, summary, severity, and scope.</span>
    </div>
    <div class="lintai-feature-item">
      <strong><a href="/presets/">Preset Reference</a></strong>
      <span>See which rules each preset enables and how overlay presets change behavior.</span>
    </div>
  </div>
</div>

## Start Here

- Open [recommended preset](/presets/recommended) if you want the main default most teams should start with.
- Open [Rule Reference](/rules/) to browse checks by provider and rule code.
- Open [Preset Reference](/presets/) to understand activation defaults, overlays, and sidecar lanes.

## Featured Rules

If you only look at a few rules first, start with these:

- [SEC340](/rules/lintai-ai-security/sec340) for mutable package launchers in committed Claude hook settings.
- [SEC329](/rules/lintai-ai-security/sec329) for mutable package launchers in committed `mcp.json`.
- [SEC352](/rules/lintai-ai-security/sec352) for unscoped `Bash` grants in AI-native frontmatter. This remains the strongest skills-markdown preview rule from recent external validation.
- [SEC324](/rules/lintai-ai-security/sec324) for unpinned third-party GitHub Actions in committed CI. Treat this as a strong sidecar supply-chain control, not as the main quiet-default story.

## What You Will Find

- Short, readable rule names for faster scanning in the catalog and sidebar.
- Clear rule pages with summary, severity, lifecycle, and preset membership.
- Preset pages that show the rules they enable and what they are meant for.

## Project References

Most readers can stop at the rule and preset reference. If you need release or project-level detail,
the main supporting docs are:

- [SECURITY_RULES.md](SECURITY_RULES.md)
- [POSITIONING_AND_SCOPE.md](POSITIONING_AND_SCOPE.md)
- [EXTERNAL_VALIDATION_PLAN.md](EXTERNAL_VALIDATION_PLAN.md)
- [EXTERNAL_VALIDATION_FIELD_UPDATE_2026-03-30.md](EXTERNAL_VALIDATION_FIELD_UPDATE_2026-03-30.md)
- [SIGNAL_QUALITY_AUDIT_2026-04-02.md](SIGNAL_QUALITY_AUDIT_2026-04-02.md)
- [SEC352_STABLE_CANDIDATE_TRACK.md](SEC352_STABLE_CANDIDATE_TRACK.md)
- [EXTERNAL_VALIDATION_REPORT.md](EXTERNAL_VALIDATION_REPORT.md)
- [EXTERNAL_VALIDATION_TOOL_JSON_REPORT.md](EXTERNAL_VALIDATION_TOOL_JSON_REPORT.md)
- [EXTERNAL_VALIDATION_SERVER_JSON_REPORT.md](EXTERNAL_VALIDATION_SERVER_JSON_REPORT.md)
- [EXTERNAL_VALIDATION_GITHUB_ACTIONS_REPORT.md](EXTERNAL_VALIDATION_GITHUB_ACTIONS_REPORT.md)
- [EXTERNAL_VALIDATION_AI_NATIVE_DISCOVERY_REPORT.md](EXTERNAL_VALIDATION_AI_NATIVE_DISCOVERY_REPORT.md)
- [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md)
- [PUBLIC_RELEASE_SHIPPING_CHECKLIST.md](PUBLIC_RELEASE_SHIPPING_CHECKLIST.md)
- [V0_1_TO_1_0_ROADMAP.md](V0_1_TO_1_0_ROADMAP.md)

Current public release distribution is limited to GitHub Release assets only.
