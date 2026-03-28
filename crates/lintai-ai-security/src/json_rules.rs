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

pub(crate) fn check_mcp_mutable_launcher(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.mutable_mcp_launcher_span.clone()),
        "MCP configuration uses a mutable package launcher in committed config",
    )
}

pub(crate) fn check_mcp_inline_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.inline_download_exec_command_span.clone()),
        "MCP configuration command downloads remote content and pipes it directly into a shell",
    )
}

pub(crate) fn check_mcp_network_tls_bypass_command(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.network_tls_bypass_command_span.clone()),
        "MCP configuration command disables TLS verification in a network-capable execution path",
    )
}

pub(crate) fn check_mcp_broad_env_file(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.broad_env_file_span.clone()),
        "repo-local MCP client config loads a broad dotenv-style envFile value",
    )
}

pub(crate) fn check_mcp_unpinned_docker_image(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.mutable_docker_image_span.clone()),
        "MCP configuration launches Docker with an image reference that is not digest-pinned",
    )
}

pub(crate) fn check_mcp_sensitive_docker_mount(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.sensitive_docker_mount_span.clone()),
        "MCP configuration launches Docker with a bind mount of sensitive host material",
    )
}

pub(crate) fn check_mcp_dangerous_docker_flag(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.dangerous_docker_flag_span.clone()),
        "MCP configuration launches Docker with a host-escape or privileged runtime flag",
    )
}

pub(crate) fn check_plugin_hook_mutable_launcher(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.mutable_plugin_hook_launcher_span.clone()),
        "plugin hook command uses a mutable package launcher in committed hooks.json",
    )
}

pub(crate) fn check_plugin_hook_inline_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.inline_download_exec_plugin_hook_span.clone()),
        "plugin hook command downloads remote content and pipes it directly into a shell",
    )
}

pub(crate) fn check_plugin_hook_network_tls_bypass(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.network_tls_bypass_plugin_hook_span.clone()),
        "plugin hook command disables TLS verification in a network-capable execution path",
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

pub(crate) fn check_json_literal_secret(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.literal_secret_span.clone()),
        "configuration commits literal secret material in env, auth, or header values",
    )
}

pub(crate) fn check_json_dangerous_endpoint_host(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.dangerous_endpoint_host_span.clone()),
        "configuration endpoint targets a metadata or private-network host literal",
    )
}

pub(crate) fn check_json_unsafe_plugin_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.unsafe_plugin_path_span.clone()),
        "cursor plugin manifest contains an unsafe absolute or parent-traversing path",
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
