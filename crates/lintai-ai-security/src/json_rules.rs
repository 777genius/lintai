use lintai_api::{ArtifactKind, Finding, RuleMetadata, ScanContext, Span};
use serde_json::Value;

use crate::helpers::{finding_for_region, json_semantics};

pub(crate) fn check_mcp_shell_wrapper(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::McpConfig {
        return Vec::new();
    }

    let Some(value) = json_semantics(ctx).map(|json| &json.value) else {
        return Vec::new();
    };
    if !contains_shell_wrapper(value) {
        return Vec::new();
    }

    vec![finding_for_region(
        meta,
        ctx,
        &Span::new(0, ctx.content.len()),
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
    if !contains_plain_http(value) {
        return Vec::new();
    }

    vec![finding_for_region(
        meta,
        ctx,
        &Span::new(0, ctx.content.len()),
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
    if !contains_credential_env_passthrough(value) {
        return Vec::new();
    }

    vec![finding_for_region(
        meta,
        ctx,
        &Span::new(0, ctx.content.len()),
        "MCP configuration passes through credential environment variables",
    )]
}

fn contains_shell_wrapper(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            let command = map
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = map
                .get("args")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .unwrap_or_default();

            if (command == "sh" || command == "bash") && args.contains(&"-c") {
                return true;
            }

            map.values().any(contains_shell_wrapper)
        }
        Value::Array(items) => items.iter().any(contains_shell_wrapper),
        _ => false,
    }
}

fn contains_plain_http(value: &Value) -> bool {
    match value {
        Value::String(text) => text.starts_with("http://"),
        Value::Array(items) => items.iter().any(contains_plain_http),
        Value::Object(map) => map.values().any(contains_plain_http),
        _ => false,
    }
}

fn contains_credential_env_passthrough(value: &Value) -> bool {
    const SECRET_ENV_KEYS: &[&str] = &[
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "AUTHORIZATION",
    ];

    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let lowered_key = key.to_lowercase();
                if (lowered_key == "env" || lowered_key == "environment")
                    && nested.as_object().is_some_and(|env_map| {
                        env_map.keys().any(|env_key| {
                            SECRET_ENV_KEYS
                                .iter()
                                .any(|secret| env_key.eq_ignore_ascii_case(secret))
                        })
                    })
                {
                    return true;
                }
            }

            map.values().any(contains_credential_env_passthrough)
        }
        Value::Array(items) => items.iter().any(contains_credential_env_passthrough),
        _ => false,
    }
}
