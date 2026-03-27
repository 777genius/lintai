use lintai_api::{ArtifactKind, Finding, RuleMetadata, ScanContext};

use crate::helpers::finding_for_region;
use crate::matchers::{
    first_hook_download_exec_span, first_hook_plain_http_secret_exfil_span,
    first_hook_secret_exfil_span, first_hook_static_auth_exposure_span, first_hook_tls_bypass_span,
};

pub(crate) fn check_hook_download_exec(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let Some(span) = first_hook_download_exec_span(&ctx.content) else {
        return Vec::new();
    };

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "hook script downloads remote code and executes it",
    )]
}

pub(crate) fn check_hook_secret_exfil(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let Some(span) = first_hook_secret_exfil_span(&ctx.content) else {
        return Vec::new();
    };

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "hook script appears to send secrets over the network",
    )]
}

pub(crate) fn check_hook_plain_http_exfil(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let Some(span) = first_hook_plain_http_secret_exfil_span(&ctx.content) else {
        return Vec::new();
    };

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "hook script sends secret material to an insecure http:// endpoint",
    )]
}

pub(crate) fn check_hook_tls_bypass(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let Some(span) = first_hook_tls_bypass_span(&ctx.content) else {
        return Vec::new();
    };

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "hook script disables TLS or certificate verification for a network call",
    )]
}

pub(crate) fn check_hook_static_auth_exposure(
    ctx: &ScanContext,
    meta: &RuleMetadata,
) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::CursorHookScript {
        return Vec::new();
    }

    let Some(span) = first_hook_static_auth_exposure_span(&ctx.content) else {
        return Vec::new();
    };

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "hook script embeds static authentication material in a network call",
    )]
}
