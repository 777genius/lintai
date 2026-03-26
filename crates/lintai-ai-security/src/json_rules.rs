use lintai_api::{ArtifactKind, Finding, RuleMetadata, ScanContext, Span};
use serde_json::Value;

use crate::helpers::{finding_for_region, json_semantics};
use crate::json_locator::{JsonLocationMap, JsonPathSegment};

pub(crate) fn check_mcp_shell_wrapper(ctx: &ScanContext, meta: &RuleMetadata) -> Vec<Finding> {
    if ctx.artifact.kind != ArtifactKind::McpConfig {
        return Vec::new();
    }

    let Some(value) = json_semantics(ctx).map(|json| &json.value) else {
        return Vec::new();
    };
    let Some(path) = find_shell_wrapper_path(value, &mut Vec::new()) else {
        return Vec::new();
    };
    let locator = JsonLocationMap::parse(&ctx.content);
    let span = locator
        .as_ref()
        .and_then(|map| map.value_span(&path))
        .cloned()
        .unwrap_or_else(|| Span::new(0, ctx.content.len()));

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
    let Some(path) = find_plain_http_path(value, &mut Vec::new()) else {
        return Vec::new();
    };
    let locator = JsonLocationMap::parse(&ctx.content);
    let span = locator
        .as_ref()
        .and_then(|map| map.value_span(&path))
        .cloned()
        .unwrap_or_else(|| Span::new(0, ctx.content.len()));

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
    let Some(path) = find_credential_env_passthrough_key_path(value, &mut Vec::new()) else {
        return Vec::new();
    };
    let locator = JsonLocationMap::parse(&ctx.content);
    let span = locator
        .as_ref()
        .and_then(|map| map.key_span(&path))
        .cloned()
        .unwrap_or_else(|| Span::new(0, ctx.content.len()));

    vec![finding_for_region(
        meta,
        ctx,
        &span,
        "MCP configuration passes through credential environment variables",
    )]
}

fn find_shell_wrapper_path(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
) -> Option<Vec<JsonPathSegment>> {
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
                let mut command_path = path.clone();
                command_path.push(JsonPathSegment::Key("command".to_owned()));
                return Some(command_path);
            }

            for (key, nested) in map {
                path.push(JsonPathSegment::Key(key.clone()));
                if let Some(found) = find_shell_wrapper_path(nested, path) {
                    path.pop();
                    return Some(found);
                }
                path.pop();
            }

            None
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                path.push(JsonPathSegment::Index(index));
                if let Some(found) = find_shell_wrapper_path(nested, path) {
                    path.pop();
                    return Some(found);
                }
                path.pop();
            }
            None
        }
        _ => None,
    }
}

fn find_plain_http_path(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
) -> Option<Vec<JsonPathSegment>> {
    match value {
        Value::String(text) => text.starts_with("http://").then(|| path.clone()),
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                path.push(JsonPathSegment::Index(index));
                if let Some(found) = find_plain_http_path(nested, path) {
                    path.pop();
                    return Some(found);
                }
                path.pop();
            }
            None
        }
        Value::Object(map) => {
            for (key, nested) in map {
                path.push(JsonPathSegment::Key(key.clone()));
                if let Some(found) = find_plain_http_path(nested, path) {
                    path.pop();
                    return Some(found);
                }
                path.pop();
            }
            None
        }
        _ => None,
    }
}

fn find_credential_env_passthrough_key_path(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
) -> Option<Vec<JsonPathSegment>> {
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
                if lowered_key == "env" || lowered_key == "environment" {
                    if let Some(env_map) = nested.as_object() {
                        for env_key in env_map.keys() {
                            if SECRET_ENV_KEYS
                                .iter()
                                .any(|secret| env_key.eq_ignore_ascii_case(secret))
                            {
                                let mut key_path = path.clone();
                                key_path.push(JsonPathSegment::Key(key.clone()));
                                key_path.push(JsonPathSegment::Key(env_key.clone()));
                                return Some(key_path);
                            }
                        }
                    }
                }

                path.push(JsonPathSegment::Key(key.clone()));
                if let Some(found) = find_credential_env_passthrough_key_path(nested, path) {
                    path.pop();
                    return Some(found);
                }
                path.pop();
            }
            None
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                path.push(JsonPathSegment::Index(index));
                if let Some(found) = find_credential_env_passthrough_key_path(nested, path) {
                    path.pop();
                    return Some(found);
                }
                path.pop();
            }
            None
        }
        _ => None,
    }
}
