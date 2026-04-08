use std::path::Path;

use crate::external_validation::*;

#[path = "canonical/cohort.rs"]
mod cohort;
#[path = "canonical/rules.rs"]
mod rules;
#[path = "canonical/surfaces.rs"]
mod surfaces;

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
    cohort::append_header_and_cohort(&mut output, current);
    cohort::append_overall_counts(&mut output, current, &current_counts);
    surfaces::append_hybrid_scope_expansion(&mut output, workspace_root, current);
    cohort::append_delta_and_precision_summary(
        &mut output,
        &baseline_counts,
        &current_counts,
        &verdict_changes,
    );
    cohort::append_preview_runtime_and_recommendation(
        &mut output,
        cohort::PreviewRecommendationArgs {
            current_counts: &current_counts,
            datadog_status,
            cursor_plugins_status,
            emmraan_status,
            preview_signal_repos,
            fp_clusters: &fp_clusters,
            fn_clusters: &fn_clusters,
        },
    );
    output
}
