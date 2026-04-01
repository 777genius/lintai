use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_docker_compose_privileged_runtime(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .docker_compose()
            .and_then(|signals| signals.privileged_runtime_span.clone()),
        "Docker Compose service enables privileged container runtime or host namespace access",
    )
}

pub(crate) fn check_docker_compose_mutable_image(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .docker_compose()
            .and_then(|signals| signals.mutable_image_span.clone()),
        "Docker Compose service image uses a mutable registry reference without a digest pin",
    )
}

pub(crate) fn check_docker_compose_latest_image(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .docker_compose()
            .and_then(|signals| signals.latest_image_span.clone()),
        "Docker Compose service image uses a latest or implicit-latest tag",
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
