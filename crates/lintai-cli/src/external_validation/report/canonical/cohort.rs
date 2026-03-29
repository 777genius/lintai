use crate::external_validation::*;

pub(super) fn append_header_and_cohort(output: &mut String, current: &ExternalValidationLedger) {
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
}

pub(super) fn append_overall_counts(
    output: &mut String,
    current: &ExternalValidationLedger,
    current_counts: &AggregateCounts,
) {
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
}

pub(super) fn append_delta_and_precision_summary(
    output: &mut String,
    baseline_counts: &AggregateCounts,
    current_counts: &AggregateCounts,
    verdict_changes: &[RepoVerdictChange],
) {
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
        for change in verdict_changes {
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
}

pub(super) fn append_preview_runtime_and_recommendation(
    output: &mut String,
    current_counts: &AggregateCounts,
    datadog_status: PhaseTargetStatus,
    cursor_plugins_status: PhaseTargetStatus,
    emmraan_status: PhaseTargetStatus,
    preview_signal_repos: Vec<(String, usize, Vec<String>)>,
    fp_clusters: &[(String, usize)],
    fn_clusters: &[(String, usize)],
) {
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
    render_clusters(output, fp_clusters, "false-positive");
    output.push('\n');

    output.push_str("## Top FN Clusters\n\n");
    render_clusters(output, fn_clusters, "false-negative");
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
}
