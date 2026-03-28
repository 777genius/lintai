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

pub(crate) fn check_github_workflow_pull_request_target_head_checkout(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    github_workflow_findings(
        ctx,
        meta,
        signals
            .github_workflow()
            .map(|signals| &signals.pull_request_target_head_checkout_spans),
        "GitHub Actions workflow triggered by pull_request_target checks out untrusted pull request head content",
    )
}

pub(crate) fn check_github_workflow_write_all_permissions(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    github_workflow_findings(
        ctx,
        meta,
        signals
            .github_workflow()
            .map(|signals| &signals.write_all_permission_spans),
        "GitHub Actions workflow grants GITHUB_TOKEN write-all permissions",
    )
}

pub(crate) fn check_github_workflow_write_capable_third_party_action(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    github_workflow_findings(
        ctx,
        meta,
        signals
            .github_workflow()
            .map(|signals| &signals.write_capable_third_party_action_spans),
        "GitHub Actions workflow combines explicit write-capable token permissions with a third-party action",
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
