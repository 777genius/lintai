<div class="lintai-page-intro">
  <p class="lintai-kicker">Catalog-Driven Reference</p>
  <h1>Rule Reference</h1>
  <p class="lintai-lead">
    This is the primary browsing surface for shipped <code>lintai</code> rules. The goal is fast
    scanning first, then deep rule context once you open a page.
  </p>
  <div class="lintai-feature-list">
    <div class="lintai-feature-item">
      <strong>Generated machine truth</strong>
      <span>Metadata is exported directly from the Rust catalog.</span>
    </div>
    <div class="lintai-feature-item">
      <strong>Human-authored prose</strong>
      <span>Examples, caveats, and remediation live in checked-in Markdown.</span>
    </div>
    <div class="lintai-feature-item">
      <strong>Stable identity model</strong>
      <span>Canonical identity is provider-qualified, not <code>SECxxx</code>-qualified.</span>
    </div>
  </div>
</div>

## Start With These

These are the current highest-signal community-facing rules based on the latest external validation work:

- [SEC352](/rules/lintai-ai-security/sec352): unscoped `Bash` grants in AI-native frontmatter
- [SEC347](/rules/lintai-ai-security/sec347): markdown MCP setup through mutable package runners
- [SEC340](/rules/lintai-ai-security/sec340): Claude hook commands using mutable package launchers
- [SEC329](/rules/lintai-ai-security/sec329): committed `mcp.json` using mutable package launchers

<RuleDirectory />
