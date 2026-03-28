use lintai_api::{Finding, RuleMetadata, ScanContext};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_github_workflow_unpinned_third_party_action(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    github_workflow_findings(
        ctx,
        meta,
        signals
            .github_workflow()
            .map(|signals| &signals.unpinned_third_party_action_spans),
        "GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA",
    )
}

pub(crate) fn check_github_workflow_untrusted_run_interpolation(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    github_workflow_findings(
        ctx,
        meta,
        signals
            .github_workflow()
            .map(|signals| &signals.direct_untrusted_run_interpolation_spans),
        "GitHub Actions workflow interpolates untrusted expression data directly inside a run command",
    )
}

fn github_workflow_findings(
    ctx: &ScanContext,
    meta: RuleMetadata,
    spans: Option<&Vec<lintai_api::Span>>,
    message: &'static str,
) -> Vec<Finding> {
    if ctx.artifact.kind != lintai_api::ArtifactKind::GitHubWorkflow {
        return Vec::new();
    }

    spans
        .into_iter()
        .flatten()
        .map(|span| finding_for_region(&meta, ctx, span, message))
        .collect()
}
