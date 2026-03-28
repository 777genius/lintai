use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_server_json_insecure_remote_url(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    server_json_finding_from_span(
        ctx,
        meta,
        signals
            .server_json()
            .and_then(|signals| signals.insecure_remote_url_span.clone()),
        "server.json remotes entry uses an insecure or non-public remote URL",
    )
}

pub(crate) fn check_server_json_unresolved_remote_variable(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    server_json_finding_from_span(
        ctx,
        meta,
        signals
            .server_json()
            .and_then(|signals| signals.unresolved_remote_variable_span.clone()),
        "server.json remotes URL references an undefined template variable",
    )
}

pub(crate) fn check_server_json_literal_auth_header(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    server_json_finding_from_span(
        ctx,
        meta,
        signals
            .server_json()
            .and_then(|signals| signals.literal_auth_header_span.clone()),
        "server.json remotes header commits literal authentication material",
    )
}

pub(crate) fn check_server_json_unresolved_header_variable(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    server_json_finding_from_span(
        ctx,
        meta,
        signals
            .server_json()
            .and_then(|signals| signals.unresolved_header_variable_span.clone()),
        "server.json remotes header value references an undefined template variable",
    )
}

pub(crate) fn check_server_json_auth_header_policy_mismatch(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    server_json_finding_from_span(
        ctx,
        meta,
        signals
            .server_json()
            .and_then(|signals| signals.auth_header_policy_mismatch_span.clone()),
        "server.json auth header carries material without an explicit secret flag",
    )
}

fn server_json_finding_from_span(
    ctx: &ScanContext,
    meta: RuleMetadata,
    span: Option<Span>,
    message: &'static str,
) -> Vec<Finding> {
    if ctx.artifact.kind != lintai_api::ArtifactKind::ServerRegistryConfig {
        return Vec::new();
    }

    span.into_iter()
        .map(|span| finding_for_region(&meta, ctx, &span, message))
        .collect()
}
