use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_devcontainer_initialize_command(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .devcontainer()
            .and_then(|signals| signals.initialize_command_span.clone()),
        "Committed devcontainer config defines `initializeCommand`, which runs on the local host before the container starts",
    )
}

pub(crate) fn check_devcontainer_sensitive_bind_mount(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .devcontainer()
            .and_then(|signals| signals.sensitive_mount_span.clone()),
        "Committed devcontainer config bind-mounts sensitive local host material such as SSH keys, cloud credentials, kubeconfig, or docker.sock",
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
