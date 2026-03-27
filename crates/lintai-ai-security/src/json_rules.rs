use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_mcp_shell_wrapper(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.shell_wrapper_span.clone()),
        "MCP configuration shells out through sh -c or bash -c",
    )
}

pub(crate) fn check_plain_http_config(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.plain_http_endpoint_span.clone()),
        "configuration contains an insecure http:// endpoint",
    )
}

pub(crate) fn check_mcp_credential_env_passthrough(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.credential_env_passthrough_span.clone()),
        "MCP configuration passes through credential environment variables",
    )
}

pub(crate) fn check_json_hidden_instruction(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.hidden_instruction_span.clone()),
        "configuration description contains override-style hidden instructions",
    )
}

pub(crate) fn check_json_sensitive_env_reference(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.sensitive_env_reference_span.clone()),
        "configuration forwards a sensitive environment variable reference",
    )
}

pub(crate) fn check_json_suspicious_remote_endpoint(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.suspicious_remote_endpoint_span.clone()),
        "configuration points at a suspicious remote endpoint",
    )
}

pub(crate) fn check_trust_verification_disabled_config(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.trust_verification_disabled_span.clone()),
        "configuration disables TLS or certificate verification",
    )
}

pub(crate) fn check_static_auth_exposure_config(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.static_auth_exposure_span.clone()),
        "configuration embeds static authentication material in a connection or auth value",
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
