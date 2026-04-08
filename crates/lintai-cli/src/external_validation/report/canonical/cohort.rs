use super::{OwnershipCounts, RecommendedPrecisionReview, ReviewedRecommendedHit};
use crate::external_validation::*;

pub(super) struct PreviewRecommendationArgs<'a> {
    pub(super) datadog_status: PhaseTargetStatus,
    pub(super) cursor_plugins_status: PhaseTargetStatus,
    pub(super) emmraan_status: PhaseTargetStatus,
    pub(super) preview_signal_repos: Vec<(String, usize, Vec<String>)>,
    pub(super) fp_clusters: &'a [(String, usize)],
    pub(super) fn_clusters: &'a [(String, usize)],
    pub(super) precision_review: &'a RecommendedPrecisionReview,
    pub(super) preview_findings: usize,
    pub(super) cohort_size: usize,
    pub(super) ownership_counts: OwnershipCounts,
}

pub(super) fn append_header_and_cohort(output: &mut String, current: &ExternalValidationLedger) {
    output.push_str("# External Validation Report\n\n");
    output.push_str("> Third checked-in external validation summary for `lintai` after broader-mix precision evidence hardening.\n");
    output.push_str("> Cohort source of truth lives in [validation/external-repos/repo-shortlist.toml](../validation/external-repos/repo-shortlist.toml), current results in [validation/external-repos/ledger.toml](../validation/external-repos/ledger.toml), and wave 2 baseline in [validation/external-repos/archive/wave2-ledger.toml](../validation/external-repos/archive/wave2-ledger.toml).\n\n");
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
    output.push_str("Current checked-in wave 3 results:\n\n");
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

pub(super) fn append_lane_counts(
    output: &mut String,
    recommended_counts: LaneAggregateCounts,
    supply_chain_counts: LaneAggregateCounts,
    remaining_lane_counts: &[(String, LaneAggregateCounts)],
    ownership_counts: OwnershipCounts,
    recommended_hits_by_ownership: OwnershipCounts,
    zero_hit_coverage_by_ownership: OwnershipCounts,
) {
    output.push_str("## Recommended Counts By Tier\n\n");
    output.push_str(&format!(
        "- stable findings: `{}`\n",
        recommended_counts.stable_findings
    ));
    output.push_str(&format!(
        "- preview findings: `{}`\n\n",
        recommended_counts.preview_findings
    ));

    output.push_str("## Supply-Chain Counts By Tier\n\n");
    output.push_str(&format!(
        "- stable findings: `{}`\n",
        supply_chain_counts.stable_findings
    ));
    output.push_str(&format!(
        "- preview findings: `{}`\n\n",
        supply_chain_counts.preview_findings
    ));

    output.push_str("## Cohort Ownership Split\n\n");
    output.push_str(&format!(
        "- total official repos: `{}`\n",
        ownership_counts.official
    ));
    output.push_str(&format!(
        "- total community repos: `{}`\n\n",
        ownership_counts.community
    ));

    output.push_str("## Recommended Stable By Ownership\n\n");
    output.push_str(&format!(
        "- official `recommended stable` hit count: `{}`\n",
        recommended_hits_by_ownership.official
    ));
    output.push_str(&format!(
        "- community `recommended stable` hit count: `{}`\n\n",
        recommended_hits_by_ownership.community
    ));

    output.push_str("## Zero-Hit Coverage By Ownership\n\n");
    output.push_str(&format!(
        "- official repos with `0` `recommended stable` hits: `{}`\n",
        zero_hit_coverage_by_ownership.official
    ));
    output.push_str(&format!(
        "- community repos with `0` `recommended stable` hits: `{}`\n\n",
        zero_hit_coverage_by_ownership.community
    ));

    output.push_str("## Remaining Non-Default Lane Totals\n\n");
    if remaining_lane_counts.is_empty() {
        output.push_str("- no remaining explicit preset lanes were recorded\n\n");
        return;
    }

    for (lane_id, counts) in remaining_lane_counts {
        output.push_str(&format!(
            "- `{lane_id}`: `{}` stable, `{}` preview\n",
            counts.stable_findings, counts.preview_findings
        ));
    }
    output.push('\n');
}

pub(super) fn append_delta_and_precision_summary(
    output: &mut String,
    baseline_counts: &AggregateCounts,
    current_counts: &AggregateCounts,
    verdict_changes: &[RepoVerdictChange],
    precision_review: &RecommendedPrecisionReview,
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

    if !precision_review.stale_adjudications.is_empty() || !precision_review.invalid_adjudications.is_empty()
    {
        output.push_str("Validation warnings:\n\n");
        if !precision_review.stale_adjudications.is_empty() {
            output.push_str("- stale adjudications are present and should fail contract validation\n");
        }
        if !precision_review.invalid_adjudications.is_empty() {
            output.push_str("- invalid adjudications are present and should fail contract validation\n");
        }
        output.push('\n');
    }
}

pub(super) fn append_recommended_hit_review(
    output: &mut String,
    recommended_counts: LaneAggregateCounts,
    precision_review: &RecommendedPrecisionReview,
) {
    output.push_str("## Adjudication Coverage For Recommended Stable\n\n");
    output.push_str(&format!(
        "- recommended stable findings: `{}`\n",
        recommended_counts.stable_findings
    ));
    output.push_str(&format!(
        "- adjudicated hits: `{}`\n",
        precision_review.reviewed.len()
    ));
    output.push_str(&format!(
        "- unadjudicated hits: `{}`\n",
        precision_review.unadjudicated.len()
    ));
    output.push_str(&format!(
        "- adjudicated false positives: `{}`\n\n",
        precision_review.false_positive_hits.len()
    ));

    output.push_str("## Reviewed Recommended Stable Hits\n\n");
    if precision_review.reviewed.is_empty() {
        output.push_str("- no recommended stable hits were adjudicated in this wave\n");
    } else {
        for reviewed_hit in &precision_review.reviewed {
            append_reviewed_hit(output, reviewed_hit);
        }
    }
    if !precision_review.unadjudicated.is_empty() {
        output.push_str("- unadjudicated hits:\n");
        for (repo, hit) in &precision_review.unadjudicated {
            output.push_str(&format!(
                "  - `{repo}`: `{}` at `{}`\n",
                hit.rule_code, hit.normalized_path
            ));
        }
    }
    output.push('\n');
}

pub(super) fn append_preview_runtime_and_recommendation(
    output: &mut String,
    args: PreviewRecommendationArgs<'_>,
) {
    let PreviewRecommendationArgs {
        datadog_status,
        cursor_plugins_status,
        emmraan_status,
        preview_signal_repos,
        fp_clusters,
        fn_clusters,
        precision_review,
        preview_findings,
        cohort_size,
        ownership_counts,
    } = args;
    output.push_str("## Preview Usefulness Summary\n\n");
    output.push_str(&format!(
        "Wave 2 produced `{}` preview finding(s).\n\n",
        preview_findings
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
    let next_step = recommended_next_step(precision_review, cohort_size, ownership_counts);
    output.push_str(&format!("`{next_step}`\n\n"));
    output.push_str("Rationale:\n\n");
    output.push_str("- this report is grounded in the current checked-in wave 3 ledger and archived wave 2 baseline\n");
    output.push_str("- recommended stable precision is now evaluated from explicit preset-lane evidence and structured adjudications\n");
    output.push_str("- ownership split is now a checked-in part of the evidence model instead of an informal reading of repo owners\n");
    if next_step == "credible prod evidence for default precision" {
        output.push_str("- cohort size reached the `48`-repo bar and official coverage reached the `12`-repo target\n");
        output.push_str("- every currently observed `recommended` stable hit has an adjudication and none of them is marked `false_positive`\n");
    } else if next_step == "expand cohort" {
        output.push_str("- adjudication is complete for the current `recommended` stable layer, but the evidence bar still needs broader cohort coverage\n");
    } else {
        output.push_str(
            "- one or more `recommended` stable hits still requires adjudication or rule hardening before default precision can be treated as credible\n",
        );
    }
}

fn recommended_next_step(
    precision_review: &RecommendedPrecisionReview,
    cohort_size: usize,
    ownership_counts: OwnershipCounts,
) -> &'static str {
    if !precision_review.unadjudicated.is_empty() || !precision_review.false_positive_hits.is_empty()
    {
        return "precision hardening";
    }
    if cohort_size < 48 || ownership_counts.official < 12 || ownership_counts.community == 0 {
        return "expand cohort";
    }
    "credible prod evidence for default precision"
}

fn append_reviewed_hit(output: &mut String, reviewed_hit: &ReviewedRecommendedHit) {
    output.push_str(&format!(
        "- `{}`: `{}` at `{}` - `{}` - {}\n",
        reviewed_hit.repo,
        reviewed_hit.rule_code,
        reviewed_hit.normalized_path,
        adjudication_verdict_label(&reviewed_hit.verdict),
        reviewed_hit.summary
    ));
    output.push_str(&format!("  reason: {}\n", reviewed_hit.reason));
    if let Some(problem) = &reviewed_hit.problem {
        output.push_str(&format!("  problem: {}\n", problem));
    }
}

fn adjudication_verdict_label(verdict: &AdjudicationVerdict) -> &'static str {
    match verdict {
        AdjudicationVerdict::ConfirmedIssue => "confirmed_issue",
        AdjudicationVerdict::FalsePositive => "false_positive",
        AdjudicationVerdict::AcceptedHardeningHit => "accepted_hardening_hit",
    }
}
