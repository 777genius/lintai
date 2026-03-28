# External Validation GitHub Actions Report

> Wave 1 extension report for semantically confirmed GitHub Actions workflow surfaces.
> Source of truth lives in [validation/external-repos-github-actions/repo-shortlist.toml](../validation/external-repos-github-actions/repo-shortlist.toml) and [validation/external-repos-github-actions/ledger.toml](../validation/external-repos-github-actions/ledger.toml).

## Cohort Composition

- `18` repos evaluated
- `12` stress repos
- `6` control repos

## Admission Results

- `IO-Aerospace-software-engineering/mcp-server` via `.github/workflows/ci.yml`, `.github/workflows/release.yml`. Workflow set contains third-party action references in operational CI and release paths.
- `TencentCloudBase/CloudBase-MCP` via `.github/workflows/ai-dev.yaml`, `.github/workflows/build-zips.yml`, `.github/workflows/compat-check.yml`, `.github/workflows/crawl-docs.yml`, `.github/workflows/nightly-build.yaml`, `.github/workflows/npm-publish.yaml`, `.github/workflows/publish-clawhub-registry.yml`, `.github/workflows/push-allinone-skill.yml`, `.github/workflows/push-skills-repo.yaml`, `.github/workflows/stale.yml`, `.github/workflows/static.yml`, `.github/workflows/sync-branch.yml`, `.github/workflows/sync-claude-skills-mirror.yml`, `.github/workflows/sync-derived-branches.yml`, `.github/workflows/sync-to-cnb.yml`. Large operational workflow set with multiple third-party uses candidates across release and automation jobs.
- `VictoriaMetrics-Community/mcp-victoriametrics` via `.github/workflows/lint.yaml`, `.github/workflows/release.yml`. Small but operational workflow set with release automation and third-party action candidates.
- `blazickjp/arxiv-mcp-server` via `.github/workflows/lint.yml`, `.github/workflows/publish.yml`, `.github/workflows/tests.yml`. Operational publish and CI workflows with candidate third-party action pins.
- `cloudflare/mcp-server-cloudflare` via `.github/workflows/branches.yml`, `.github/workflows/main.yml`, `.github/workflows/release.yml`. Production workflow set with release automation and third-party action usage.
- `containers/kubernetes-mcp-server` via `.github/workflows/build.yaml`, `.github/workflows/helm.yaml`, `.github/workflows/labeler.yaml`, `.github/workflows/mcpchecker-report.yaml`, `.github/workflows/mcpchecker.yaml`, `.github/workflows/release-helm.yaml`, `.github/workflows/release-image.yml`, `.github/workflows/release-mcp-registry.yaml`, `.github/workflows/release-mcpb.yaml`, `.github/workflows/release.yaml`. Workflow-heavy repo with numerous operational release and validation jobs.
- `docker/hub-mcp` via `.github/workflows/lint.yml`, `.github/workflows/release.yml`, `.github/workflows/scorecard.yml`, `.github/workflows/tools-list.yml`. Operational workflow set with release automation and third-party action candidates.
- `googleworkspace/developer-tools` via `.github/workflows/release.yml`, `.github/workflows/test.yml`, `.github/workflows/update.yml`. Operational workflow set with release, test, and update automation suitable for GitHub Actions checks.
- `hashicorp/terraform-mcp-server` via `.github/workflows/build.yml`, `.github/workflows/changelog.yml`, `.github/workflows/e2e_test.yml`, `.github/workflows/publish-registry.yml`, `.github/workflows/release-checks.yml`, `.github/workflows/security-scan.yml`, `.github/workflows/unit_test.yml`. High-signal operational workflow set with several third-party action references.
- `modelcontextprotocol/registry` via `.github/workflows/cancel-pulumi-lock.yml`, `.github/workflows/ci.yml`, `.github/workflows/claude.yml`, `.github/workflows/deploy-production.yml`, `.github/workflows/deploy-staging.yml`, `.github/workflows/release.yml`, `.github/workflows/sync-db.yml`, `.github/workflows/sync-schema.yml`. Official registry repo with operational workflow set and multiple third-party action candidates.
- `netdata/netdata` via `.github/workflows/add-to-project.yml`, `.github/workflows/build.yml`, `.github/workflows/check-markdown.yml`, `.github/workflows/checks.yml`, `.github/workflows/cloud_regression.yml`, `.github/workflows/codeql.yml`, `.github/workflows/coverity.yml`, `.github/workflows/docker.yml`, `.github/workflows/generate-integrations.yml`, `.github/workflows/go-tests.yml`, `.github/workflows/kickstart-upload.yml`, `.github/workflows/labeler.yml`, `.github/workflows/monitor-releases.yml`, `.github/workflows/packagecloud.yml`, `.github/workflows/packaging.yml`, `.github/workflows/platform-eol-check.yml`, `.github/workflows/release.yml`, `.github/workflows/repoconfig-packages.yml`, `.github/workflows/review.yml`, `.github/workflows/tests.yml`, `.github/workflows/trigger-learn-update.yml`, `.github/workflows/update-mcp-registry.yml`. Large operational workflow set with many third-party action references and release automation.
- `tldraw/tldraw` via `.github/workflows/add-framer-rewrites.yml`, `.github/workflows/bump-versions.yml`, `.github/workflows/checks.yml`, `.github/workflows/claude.yml`, `.github/workflows/close-stale-issues.yml`, `.github/workflows/dependabot-dedupe.yml`, `.github/workflows/deploy-analytics.yml`, `.github/workflows/deploy-bemo.yml`, `.github/workflows/deploy-dotcom.yml`, `.github/workflows/get-changelog.yml`, `.github/workflows/i18n-download-strings.yml`, `.github/workflows/i18n-upload-strings.yml`, `.github/workflows/issue-triage.yml`, `.github/workflows/playwright-dotcom.yml`, `.github/workflows/playwright-examples.yml`, `.github/workflows/playwright-perf.yml`, `.github/workflows/playwright-update-snapshots.yml`, `.github/workflows/prune-preview-deploys.yml`, `.github/workflows/publish-branch.yml`, `.github/workflows/publish-canary.yml`, `.github/workflows/publish-editor-extensions.yml`, `.github/workflows/publish-manual.yml`, `.github/workflows/publish-new.yml`, `.github/workflows/publish-patch.yml`, `.github/workflows/publish-templates.yml`, `.github/workflows/staging-cleanup-daily.yml`, `.github/workflows/staging-e2e.yml`, `.github/workflows/trigger-dotcom-hotfix.yml`, `.github/workflows/trigger-production-build.yml`, `.github/workflows/trigger-sdk-hotfix.yml`, `.github/workflows/update-release-notes.yml`. Workflow-heavy production repo with many operational third-party action candidates.
- `MidOSresearch/midos` via `.github/workflows/midos-ci.yml`, `web/.github/workflows/deploy.yml`. Repo with semantically confirmed workflows but no intended SEC324 or SEC325 trigger in the current narrow classifier.
- `cursor/plugins` via `.github/workflows/validate-plugins.yml`. Single validation workflow used as a clean control for workflow parsing without an intended SEC324 or SEC325 trigger.
- `gitkraken/MCP-Docs` via `.github/workflows/merge-mate.yml`. Small operational workflow set used as a control for semantically confirmed workflow parsing.
- `mrexodia/ida-pro-mcp` via `.github/workflows/idalib-tests.yml`. Single operational workflow used as a control for GitHub Actions detection and parsing.
- `olostep/olostep-cursor-plugin` via `.github/workflows/integrity.yml`. Small operational workflow set used as a clean control for current GitHub Actions rules.
- `vapagentmedia/vap-showcase` via `.github/workflows/ci-example.yml`. Small workflow surface used as a control with semantically valid GitHub Actions YAML.

## Overall Counts

- `187` stable findings
- `0` preview findings
- `2` runtime parser errors
- `2` diagnostics

Interpretation note: the stable signal in this wave is dominated by `SEC324`. That rule is intentionally positioned as a supply-chain hardening control for mutable third-party action refs, not as a blanket claim that the affected repositories are critically compromised.

## Stable Hits

Most stable hits in this wave are `SEC324` supply-chain hardening findings on third-party actions pinned to tags or versions instead of immutable full SHAs.

- `IO-Aerospace-software-engineering/mcp-server`: `1` stable finding(s) via `SEC324`
- `TencentCloudBase/CloudBase-MCP`: `1` stable finding(s) via `SEC324`
- `VictoriaMetrics-Community/mcp-victoriametrics`: `1` stable finding(s) via `SEC324`
- `blazickjp/arxiv-mcp-server`: `1` stable finding(s) via `SEC324`
- `cloudflare/mcp-server-cloudflare`: `1` stable finding(s) via `SEC324`
- `containers/kubernetes-mcp-server`: `1` stable finding(s) via `SEC324`
- `docker/hub-mcp`: `1` stable finding(s) via `SEC324`
- `googleworkspace/developer-tools`: `1` stable finding(s) via `SEC324`
- `hashicorp/terraform-mcp-server`: `1` stable finding(s) via `SEC324`
- `modelcontextprotocol/registry`: `1` stable finding(s) via `SEC324`
- `netdata/netdata`: `1` stable finding(s) via `SEC324`
- `tldraw/tldraw`: `1` stable finding(s) via `SEC324`
- `gitkraken/MCP-Docs`: `1` stable finding(s) via `SEC324`
- `mrexodia/ida-pro-mcp`: `1` stable finding(s) via `SEC324`

## Preview Hits

- no preview hits were observed from `SEC325`

## Runtime / Diagnostic Notes

- `TencentCloudBase/CloudBase-MCP`: `0` runtime parser errors, `1` diagnostics (non-admission-path issue)
- `MidOSresearch/midos`: `2` runtime parser errors, `0` diagnostics (non-admission-path issue)
- `cursor/plugins`: `0` runtime parser errors, `1` diagnostics (non-admission-path issue)

## Recommended Next Step

Keep this package as supporting sidecar evidence only. The next expansion batches should return to MCP, Cursor Plugin, and skill surfaces rather than extending GitHub Actions further right now.
