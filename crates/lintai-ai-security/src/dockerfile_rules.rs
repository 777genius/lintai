use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_dockerfile_run_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .dockerfile()
            .and_then(|signals| signals.download_exec_span.clone()),
        "Dockerfile RUN instruction downloads remote code and executes it",
    )
}

pub(crate) fn check_dockerfile_final_stage_root_user(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .dockerfile()
            .and_then(|signals| signals.final_stage_root_user_span.clone()),
        "Dockerfile final stage explicitly runs as root",
    )
}

pub(crate) fn check_dockerfile_mutable_image(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .dockerfile()
            .and_then(|signals| signals.mutable_image_span.clone()),
        "Dockerfile FROM uses a mutable registry image without a digest pin",
    )
}

pub(crate) fn check_dockerfile_latest_image(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .dockerfile()
            .and_then(|signals| signals.latest_image_span.clone()),
        "Dockerfile FROM uses a latest or implicit-latest image tag",
    )
}

fn finding_from_span(
    ctx: &ScanContext,
    meta: RuleMetadata,
    span: Option<Span>,
    message: &'static str,
) -> Vec<Finding> {
    span.into_iter()
        .map(|span| finding_for_region(&meta, ctx, &span, message))
        .collect()
}
