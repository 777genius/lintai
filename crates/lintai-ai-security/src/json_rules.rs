use lintai_api::{ArtifactKind, Finding, RuleMetadata, ScanContext};

use crate::helpers::{finding_for_region, json_semantics};
use crate::json_locator::JsonLocationMap;
use crate::matchers::{
    first_json_credential_env_passthrough, first_json_plain_http_endpoint, first_json_shell_wrapper,
    first_json_static_auth_exposure, first_json_trust_verification_disabled,
};

pub(crate) fn check_mcp_shell_wrapper(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::McpConfig {
        return Vec::new();
    }

    let Some(value) = json_semantics(ctx).map(|json| &json.value) else {
        return Vec::new();
    };
    let Some(matched) = first_json_shell_wrapper(value) else {
        return Vec::new();
    };
    let locator = JsonLocationMap::parse(&ctx.content);
    let span = matched.resolve_span(locator.as_ref(), ctx.content.len());

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "MCP configuration shells out through sh -c or bash -c",
    )]
}

pub(crate) fn check_plain_http_config(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if !matches!(
        ctx.artifact.kind,
        ArtifactKind::McpConfig
            | ArtifactKind::CursorPluginManifest
            | ArtifactKind::CursorPluginHooks
    ) {
        return Vec::new();
    }

    let Some(value) = json_semantics(ctx).map(|json| &json.value) else {
        return Vec::new();
    };
    let Some(matched) = first_json_plain_http_endpoint(value) else {
        return Vec::new();
    };
    let locator = JsonLocationMap::parse(&ctx.content);
    let span = matched.resolve_span(locator.as_ref(), ctx.content.len());

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "configuration contains an insecure http:// endpoint",
    )]
}

pub(crate) fn check_mcp_credential_env_passthrough(
    ctx: &ScanContext,
    meta: &RuleMetadata,
) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::McpConfig {
        return Vec::new();
    }

    let Some(value) = json_semantics(ctx).map(|json| &json.value) else {
        return Vec::new();
    };
    let Some(matched) = first_json_credential_env_passthrough(value) else {
        return Vec::new();
    };
    let locator = JsonLocationMap::parse(&ctx.content);
    let span = matched.resolve_span(locator.as_ref(), ctx.content.len());

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "MCP configuration passes through credential environment variables",
    )]
}

pub(crate) fn check_trust_verification_disabled_config(
    ctx: &ScanContext,
    meta: &RuleMetadata,
) -> Vec<Finding> {
    if !matches!(
        ctx.artifact.kind,
        ArtifactKind::McpConfig
            | ArtifactKind::CursorPluginManifest
            | ArtifactKind::CursorPluginHooks
    ) {
        return Vec::new();
    }

    let Some(value) = json_semantics(ctx).map(|json| &json.value) else {
        return Vec::new();
    };
    let Some(matched) = first_json_trust_verification_disabled(value) else {
        return Vec::new();
    };
    let locator = JsonLocationMap::parse(&ctx.content);
    let span = matched.resolve_span(locator.as_ref(), ctx.content.len());

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "configuration disables TLS or certificate verification",
    )]
}

pub(crate) fn check_static_auth_exposure_config(
    ctx: &ScanContext,
    meta: &RuleMetadata,
) -> Vec<Finding> {
    if !matches!(
        ctx.artifact.kind,
        ArtifactKind::McpConfig
            | ArtifactKind::CursorPluginManifest
            | ArtifactKind::CursorPluginHooks
    ) {
        return Vec::new();
    }

    let Some(value) = json_semantics(ctx).map(|json| &json.value) else {
        return Vec::new();
    };
    let Some(matched) = first_json_static_auth_exposure(value) else {
        return Vec::new();
    };
    let locator = JsonLocationMap::parse(&ctx.content);
    let span = matched.resolve_span(locator.as_ref(), ctx.content.len());

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "configuration embeds static authentication material in a connection or auth value",
    )]
}
