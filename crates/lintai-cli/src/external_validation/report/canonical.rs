use std::path::Path;

use crate::external_validation::*;

pub(crate) fn render_report_from_ledgers(
    workspace_root: &Path,
    baseline: &ExternalValidationLedger,
    current: &ExternalValidationLedger,
) -> String {
    let baseline_counts = aggregate_counts(baseline);
    let current_counts = aggregate_counts(current);
    let verdict_changes = repo_verdict_changes(baseline, current);
    let fp_clusters = top_clusters(current, ClusterKind::FalsePositive);
    let fn_clusters = top_clusters(current, ClusterKind::FalseNegative);
    let preview_signal_repos = preview_signal_repos(current);
    let expanded_surface_counts = expanded_surface_counts(current);
    let tool_rule_hits = rule_count(current, &["SEC314", "SEC315", "SEC316", "SEC317", "SEC318"]);
    let mcp_rule_hits = rule_count(
        current,
        &[
            "SEC301", "SEC302", "SEC303", "SEC304", "SEC305", "SEC306", "SEC307", "SEC308",
            "SEC309", "SEC310", "SEC329", "SEC330", "SEC331", "SEC337", "SEC338", "SEC339",
            "SEC346",
        ],
    );
    let env_file_hits = rule_count(current, &["SEC336"]);
    let docker_rule_hits = rule_count(current, &["SEC337", "SEC338", "SEC339", "SEC346"]);
    let sec313_hits = rule_count(current, &["SEC313"]);
    let sec335_hits = rule_count(current, &["SEC335"]);
    let sec347_hits = rule_count(current, &["SEC347"]);
    let sec348_hits = rule_count(current, &["SEC348"]);
    let sec349_hits = rule_count(current, &["SEC349"]);
    let sec350_hits = rule_count(current, &["SEC350"]);
    let sec351_hits = rule_count(current, &["SEC351"]);
    let sec347_subtypes = sec347_subtype_counts(workspace_root, current);
    let sec348_repos = repos_with_rule_hits(current, &["SEC348"], false);
    let sec349_repos = repos_with_rule_hits(current, &["SEC349"], false);
    let sec350_repos = repos_with_rule_hits(current, &["SEC350"], false);
    let sec351_repos = repos_with_rule_hits(current, &["SEC351"], false);

    let datadog_status = phase_target_status(
        baseline,
        current,
        "datadog-labs/cursor-plugin",
        PhaseTargetKind::DatadogSec105,
    );
    let cursor_plugins_status = phase_target_status(
        baseline,
        current,
        "cursor/plugins",
        PhaseTargetKind::InvalidYamlRecovery,
    );
    let emmraan_status = phase_target_status(
        baseline,
        current,
        "Emmraan/agent-skills",
        PhaseTargetKind::InvalidYamlRecovery,
    );

    let mut output = String::new();
    output.push_str("# External Validation Report\n\n");
    output.push_str("> Second checked-in external validation summary for `lintai` after Phase 1 precision hardening.\n");
    output.push_str("> Cohort source of truth lives in [validation/external-repos/repo-shortlist.toml](../validation/external-repos/repo-shortlist.toml), current results in [validation/external-repos/ledger.toml](../validation/external-repos/ledger.toml), and wave 1 baseline in [validation/external-repos/archive/wave1-ledger.toml](../validation/external-repos/archive/wave1-ledger.toml).\n\n");
    output.push_str("## Cohort Composition\n\n");
    output.push_str(&format!(
        "The current cohort still contains `{}` public repositories:\n\n",
        current.evaluations.len()
    ));
    let category_counts = category_counts(current);
    output.push_str(&format!(
        "- `{}` `mcp`-focused repos\n",
        category_counts.get("mcp").copied().unwrap_or(0)
    ));
    output.push_str(&format!(
        "- `{}` `cursor_plugin`-focused repos\n",
        category_counts.get("cursor_plugin").copied().unwrap_or(0)
    ));
    output.push_str(&format!(
        "- `{}` `skills`-focused repos\n\n",
        category_counts.get("skills").copied().unwrap_or(0)
    ));

    output.push_str("## Overall Counts\n\n");
    output.push_str("Current checked-in wave 2 results:\n\n");
    output.push_str(&format!(
        "- `{}` repos evaluated\n",
        current.evaluations.len()
    ));
    output.push_str(&format!(
        "- `{}` total findings\n",
        current_counts.stable_findings + current_counts.preview_findings
    ));
    output.push_str(&format!(
        "- `{}` stable findings\n",
        current_counts.stable_findings
    ));
    output.push_str(&format!(
        "- `{}` preview findings\n",
        current_counts.preview_findings
    ));
    output.push_str(&format!(
        "- `{}` runtime parser errors\n",
        current_counts.runtime_errors
    ));
    output.push_str(&format!(
        "- `{}` diagnostics\n\n",
        current_counts.diagnostics
    ));

    output.push_str("## Hybrid Scope Expansion Results\n\n");
    output.push_str("Current wave inventory for the newly expanded JSON lanes:\n\n");
    output.push_str(&format!(
        "- repos with root `mcp.json`: `{}`\n",
        expanded_surface_counts.top_level_mcp
    ));
    output.push_str(&format!(
        "- repos with `.mcp.json`: `{}`\n",
        expanded_surface_counts.dot_mcp
    ));
    output.push_str(&format!(
        "- repos with `.cursor/mcp.json`: `{}`\n",
        expanded_surface_counts.cursor_mcp
    ));
    output.push_str(&format!(
        "- repos with `.vscode/mcp.json`: `{}`\n",
        expanded_surface_counts.vscode_mcp
    ));
    output.push_str(&format!(
        "- repos with `.roo/mcp.json`: `{}`\n",
        expanded_surface_counts.roo_mcp
    ));
    output.push_str(&format!(
        "- repos with `.kiro/settings/mcp.json`: `{}`\n",
        expanded_surface_counts.kiro_mcp
    ));
    output.push_str(&format!(
        "- repos with `gemini-extension.json`: `{}`\n",
        expanded_surface_counts.gemini_extension
    ));
    output.push_str(&format!(
        "- repos with `gemini.settings.json`: `{}`\n",
        expanded_surface_counts.gemini_settings
    ));
    output.push_str(&format!(
        "- repos with `.gemini/settings.json`: `{}`\n",
        expanded_surface_counts.dot_gemini_settings
    ));
    output.push_str(&format!(
        "- repos with `vscode.settings.json`: `{}`\n",
        expanded_surface_counts.vscode_settings
    ));
    output.push_str(&format!(
        "- repos with `.claude/mcp/*.json`: `{}`\n",
        expanded_surface_counts.claude_mcp
    ));
    output.push_str(&format!(
        "- repos with Docker-based MCP launch configs: `{}`\n",
        expanded_surface_counts.docker_mcp_launch
    ));
    output.push_str(&format!(
        "- MCP findings from expanded client-config coverage (`SEC301`-`SEC331`, `SEC337`-`SEC339`, `SEC346`): `{}`\n",
        mcp_rule_hits
    ));
    output.push_str(&format!("- findings from `SEC336`: `{}`\n", env_file_hits));
    output.push_str(&format!(
        "- findings from `SEC337`-`SEC339`, `SEC346`: `{}`\n",
        docker_rule_hits
    ));
    output.push_str("- AI-native markdown preview findings:\n");
    output.push_str(&format!(
        "  - `SEC313` fenced pipe-to-shell examples: `{}`\n",
        sec313_hits
    ));
    output.push_str(&format!(
        "  - `SEC335` metadata-service access examples: `{}`\n",
        sec335_hits
    ));
    output.push_str(&format!(
        "  - `SEC347` mutable MCP setup launcher examples: `{}`\n",
        sec347_hits
    ));
    output.push_str(&format!(
        "    - CLI-form repo hits: `{}`\n",
        sec347_subtypes.cli_form_repos
    ));
    output.push_str(&format!(
        "    - config-snippet-form repo hits: `{}`\n",
        sec347_subtypes.config_snippet_repos
    ));
    output.push_str(&format!(
        "  - `SEC348` mutable Docker registry-image examples: `{}`\n",
        sec348_hits
    ));
    output.push_str(&format!(
        "  - `SEC349` Docker host-escape or privileged runtime examples: `{}`\n",
        sec349_hits
    ));
    output.push_str(&format!(
        "  - `SEC350` untrusted-input instruction-promotion examples: `{}`\n",
        sec350_hits
    ));
    output.push_str(&format!(
        "  - `SEC351` approval-bypass instruction examples: `{}`\n",
        sec351_hits
    ));
    if sec347_hits > 0 {
        output.push_str(&format!(
            "  - current `SEC347` usefulness is being driven mainly by {}\n",
            sec347_primary_driver_label(sec347_subtypes)
        ));
    }
    output.push_str(&format!(
        "- repos with `tool_descriptor_json`: `{}`\n",
        expanded_surface_counts.tool_descriptor_json
    ));
    output.push_str(&format!(
        "- findings from `SEC314`-`SEC318`: `{}`\n",
        tool_rule_hits
    ));
    output.push_str(&format!(
        "- repos where new MCP client-config variants existed only under fixture-like paths: `{}`\n",
        expanded_surface_counts.fixture_only_client_variants
    ));
    output.push_str(&format!(
        "- repos where Docker-based MCP launch existed only under fixture-like client-config variants: `{}`\n",
        expanded_surface_counts.fixture_only_docker_client_variants
    ));
    if env_file_hits == 0 && mcp_rule_hits == 0 {
        output.push_str(
            "- expanded MCP client-config coverage produced no external MCP hits on the canonical cohort yet\n",
        );
    }
    if docker_rule_hits == 0 {
        output.push_str(
            "- no external hits were produced yet from Docker-based MCP launch hardening on the canonical cohort\n",
        );
    }
    if tool_rule_hits == 0 {
        output.push_str(
            "- no non-fixture external `Stable` hits were produced yet on committed tool-descriptor JSON\n",
        );
    }
    if sec348_repos.is_empty() {
        output.push_str(
            "- `SEC348` produced no repo-level preview hits yet on the canonical cohort\n",
        );
    } else {
        output.push_str("- `SEC348` repo-level preview hits on the canonical cohort:\n");
        for (repo, count, rule_codes) in sec348_repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` preview finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    if sec349_repos.is_empty() {
        output.push_str(
            "- `SEC349` produced no repo-level preview hits yet on the canonical cohort\n",
        );
    } else {
        output.push_str("- `SEC349` repo-level preview hits on the canonical cohort:\n");
        for (repo, count, rule_codes) in sec349_repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` preview finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    if sec350_repos.is_empty() {
        output.push_str(
            "- `SEC350` produced no repo-level preview hits yet on the canonical cohort\n",
        );
    } else {
        output.push_str("- `SEC350` repo-level preview hits on the canonical cohort:\n");
        for (repo, count, rule_codes) in sec350_repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` preview finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    if sec351_repos.is_empty() {
        output.push_str(
            "- `SEC351` produced no repo-level preview hits yet on the canonical cohort\n",
        );
    } else {
        output.push_str("- `SEC351` repo-level preview hits on the canonical cohort:\n");
        for (repo, count, rule_codes) in sec351_repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` preview finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    output.push_str(
        "- fixture/testdata/example suppression stayed active for the newly added MCP client-config variants and did not create a fake usefulness signal from fixture-like paths\n\n",
    );

    output.push_str("## Delta From Previous Wave\n\n");
    output.push_str(&format!(
        "- stable findings: `{}` -> `{}`\n",
        baseline_counts.stable_findings, current_counts.stable_findings
    ));
    output.push_str(&format!(
        "- preview findings: `{}` -> `{}`\n",
        baseline_counts.preview_findings, current_counts.preview_findings
    ));
    output.push_str(&format!(
        "- runtime parser errors: `{}` -> `{}`\n",
        baseline_counts.runtime_errors, current_counts.runtime_errors
    ));
    output.push_str(&format!(
        "- diagnostics: `{}` -> `{}`\n",
        baseline_counts.diagnostics, current_counts.diagnostics
    ));
    if verdict_changes.is_empty() {
        output.push_str("- repo verdict changes: none\n\n");
    } else {
        output.push_str("- repo verdict changes:\n");
        for change in &verdict_changes {
            output.push_str(&format!(
                "  - `{}`: `{}` -> `{}`\n",
                change.repo, change.from, change.to
            ));
        }
        output.push('\n');
    }

    output.push_str("## Stable Precision Summary\n\n");
    if current_counts.stable_findings == 0 {
        output.push_str("The current `Stable` layer remains clean across wave 2:\n\n");
        output.push_str("- no `Stable` findings were emitted\n");
        output.push_str("- no `Stable` false-positive cluster was observed\n");
        output
            .push_str("- no new `Stable` release-blocking noise signal surfaced in this wave\n\n");
    } else {
        output.push_str("Wave 2 surfaced `Stable` findings and requires another precision pass before beta.\n\n");
    }

    output.push_str("## Preview Usefulness Summary\n\n");
    output.push_str(&format!(
        "Wave 2 produced `{}` preview finding(s).\n\n",
        current_counts.preview_findings
    ));
    output.push_str(&format!(
        "- `datadog-labs/cursor-plugin`: `{}`\n",
        target_status_label(datadog_status)
    ));
    for (repo, count, rule_codes) in preview_signal_repos {
        output.push_str(&format!(
            "- `{repo}`: `{count}` preview finding(s) via {}\n",
            format_rule_codes(&rule_codes)
        ));
    }
    output.push('\n');

    output.push_str("## Runtime / Diagnostic Notes\n\n");
    output.push_str(&format!(
        "- `cursor/plugins`: `{}`\n",
        target_status_label(cursor_plugins_status)
    ));
    output.push_str(&format!(
        "- `Emmraan/agent-skills`: `{}`\n\n",
        target_status_label(emmraan_status)
    ));

    output.push_str("## Top FP Clusters\n\n");
    render_clusters(&mut output, &fp_clusters, "false-positive");
    output.push('\n');

    output.push_str("## Top FN Clusters\n\n");
    render_clusters(&mut output, &fn_clusters, "false-negative");
    output.push('\n');

    output.push_str("## Recommended Next Step\n\n");
    let next_step = if current_counts.stable_findings == 0
        && datadog_status != PhaseTargetStatus::Regressed
        && cursor_plugins_status != PhaseTargetStatus::Regressed
        && emmraan_status != PhaseTargetStatus::Regressed
    {
        "public beta"
    } else {
        "precision hardening"
    };
    output.push_str(&format!("`{next_step}`\n\n"));
    output.push_str("Rationale:\n\n");
    output.push_str("- this report is grounded in the current checked-in wave 2 ledger and archived wave 1 baseline\n");
    output.push_str("- the known Phase 1 follow-up repos are called out explicitly above\n");
    if next_step == "public beta" {
        output.push_str("- the current results do not show a new `Stable` precision regression\n");
    } else {
        output.push_str(
            "- one or more wave 2 signals still require another precision pass before beta\n",
        );
    }

    output
}
