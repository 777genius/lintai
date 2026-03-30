# lintai Documentation

<div class="lintai-page-intro">
  <p class="lintai-kicker">Rule Guide</p>
  <h1>Browse rules and presets with less guesswork.</h1>
  <p class="lintai-lead">
    This docs site helps you quickly understand what each lintai rule checks, where it applies,
    and which presets enable it.
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

- Open [Rule Reference](/rules/) to browse checks by provider and rule code.
- Open [Preset Reference](/presets/) to understand activation defaults and overlays.

## Featured Rules

If you only look at a few rules first, start with these:

- [SEC352](/rules/lintai-ai-security/sec352) for unscoped `Bash` grants in AI-native frontmatter. This is currently the highest-signal skills markdown rule from the latest external validation pass.
- [SEC347](/rules/lintai-ai-security/sec347) for mutable MCP launchers in markdown setup docs.
- [SEC340](/rules/lintai-ai-security/sec340) for mutable package launchers in committed Claude hook settings.
- [SEC329](/rules/lintai-ai-security/sec329) for mutable package launchers in committed `mcp.json`.

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
- [SEC352_STABLE_CANDIDATE_TRACK.md](SEC352_STABLE_CANDIDATE_TRACK.md)
- [EXTERNAL_VALIDATION_REPORT.md](EXTERNAL_VALIDATION_REPORT.md)
- [EXTERNAL_VALIDATION_TOOL_JSON_REPORT.md](EXTERNAL_VALIDATION_TOOL_JSON_REPORT.md)
- [EXTERNAL_VALIDATION_SERVER_JSON_REPORT.md](EXTERNAL_VALIDATION_SERVER_JSON_REPORT.md)
- [EXTERNAL_VALIDATION_GITHUB_ACTIONS_REPORT.md](EXTERNAL_VALIDATION_GITHUB_ACTIONS_REPORT.md)
- [EXTERNAL_VALIDATION_AI_NATIVE_DISCOVERY_REPORT.md](EXTERNAL_VALIDATION_AI_NATIVE_DISCOVERY_REPORT.md)
- [PUBLIC_BETA_RELEASE.md](PUBLIC_BETA_RELEASE.md)
- [PUBLIC_BETA_SHIPPING_CHECKLIST.md](PUBLIC_BETA_SHIPPING_CHECKLIST.md)
- [BETA_TO_1_0_ROADMAP.md](BETA_TO_1_0_ROADMAP.md)

Current beta distribution is limited to GitHub Release assets only.
