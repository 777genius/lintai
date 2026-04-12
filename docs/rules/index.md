<div class="lintai-page-intro">
  <p class="lintai-kicker">Catalog-Driven Reference</p>
  <h1>Rule Reference</h1>
  <p class="lintai-lead">
    This is the primary browsing surface for shipped <code>lintai</code> rules. The goal is fast
    scanning first, then deep rule context once you open a page.
  </p>
  <div class="lintai-feature-list">
    <div class="lintai-feature-item">
      <strong>Lane-first browsing</strong>
      <span>The directory is grouped by public lane first so the product model is visible immediately.</span>
    </div>
    <div class="lintai-feature-item">
      <strong>Human-authored prose</strong>
      <span>Examples, caveats, and remediation live in checked-in Markdown.</span>
    </div>
    <div class="lintai-feature-item">
      <strong>Provider stays secondary</strong>
      <span>Provider identity is still visible, but no longer drives the main browsing experience.</span>
    </div>
  </div>
</div>

## Start With These

These are the current highest-signal community-facing rules based on the latest external validation work. `SEC340` and `SEC329` are the clearest quiet-default story; `SEC324` and `SEC352` remain strong sidecar controls:

- [SEC340](/rules/lintai-ai-security/sec340): Claude hook commands using mutable package launchers
- [SEC329](/rules/lintai-ai-security/sec329): committed `mcp.json` using mutable package launchers
- [SEC352](/rules/lintai-ai-security/sec352): unscoped `Bash` grants in AI-native frontmatter as a governance least-privilege control
- [SEC324](/rules/lintai-ai-security/sec324): unpinned third-party GitHub Actions

## Reading The Catalog

- `recommended` means quiet practical default coverage
- `preview` means broader contextual review outside the default
- `threat-review` means explicit malicious, secret-bearing, or spyware-like review
- `supply-chain` means reproducibility, provenance, and dependency hardening review
- `compat` means config, schema, and policy contract review
- `governance` means shared authority and workflow policy review
- `guidance` means advice-oriented guidance and maintainability review
- `advisory` means installed-package advisory review

- `security` is a strong exploit, secret, or unsafe-execution signal
- `hardening` is a least-privilege, provenance, or hygiene signal
- `quality` is a contract or config correctness signal
- `audit` is a heuristic or triage-oriented signal

<RuleDirectory />
