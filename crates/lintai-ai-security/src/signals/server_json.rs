use lintai_api::{ArtifactKind, ScanContext};
use serde_json::Value;

use crate::helpers::json_semantics;
use crate::json_locator::{JsonLocationMap, JsonPathSegment};

use super::shared::*;
use super::{ServerJsonSignals, SignalWorkBudget};

impl ServerJsonSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::ServerRegistryConfig {
            return None;
        }

        let value = &json_semantics(ctx)?.value;
        let locator = JsonLocationMap::parse(&ctx.content);
        if locator.is_some() {
            metrics.json_locator_builds += 1;
        }
        let fallback_len = ctx.content.len();
        let mut signals = Self {
            locator,
            ..Self::default()
        };
        let Some(remotes) = value
            .as_object()
            .and_then(|root| root.get("remotes"))
            .and_then(Value::as_array)
        else {
            return Some(signals);
        };

        for (index, remote) in remotes.iter().enumerate() {
            metrics.json_values_visited += 1;
            let Some(remote_object) = remote.as_object() else {
                continue;
            };
            let remote_type = remote_object.get("type").and_then(Value::as_str);
            if !matches!(remote_type, Some("streamable-http" | "sse")) {
                continue;
            }
            let Some(url) = remote_object.get("url").and_then(Value::as_str) else {
                continue;
            };
            let remote_path = vec![
                JsonPathSegment::Key("remotes".to_owned()),
                JsonPathSegment::Index(index),
            ];
            if signals.insecure_remote_url_span.is_none() {
                let relative = find_non_loopback_http_relative_span(url)
                    .or_else(|| find_dangerous_endpoint_host_relative_span(url));
                if let Some(relative) = relative {
                    signals.insecure_remote_url_span = Some(resolve_child_relative_value_span(
                        &remote_path,
                        "url",
                        "url",
                        relative,
                        signals.locator.as_ref(),
                        fallback_len,
                    ));
                }
            }

            if signals.unresolved_remote_variable_span.is_none()
                && let Some(relative) =
                    find_unresolved_remote_variable_relative_span(url, remote_object)
            {
                signals.unresolved_remote_variable_span = Some(resolve_child_relative_value_span(
                    &remote_path,
                    "url",
                    "url",
                    relative,
                    signals.locator.as_ref(),
                    fallback_len,
                ));
            }

            let Some(headers) = remote_object.get("headers").and_then(Value::as_array) else {
                continue;
            };
            for (header_index, header) in headers.iter().enumerate() {
                metrics.json_values_visited += 1;
                let Some(header_object) = header.as_object() else {
                    continue;
                };
                let Some(name) = header_object.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if !is_server_auth_header_name(name) {
                    continue;
                }
                let header_path = vec![
                    JsonPathSegment::Key("remotes".to_owned()),
                    JsonPathSegment::Index(index),
                    JsonPathSegment::Key("headers".to_owned()),
                    JsonPathSegment::Index(header_index),
                ];
                if signals.literal_auth_header_span.is_none()
                    && let Some(relative) =
                        find_literal_auth_header_relative_span(name, header_object)
                {
                    signals.literal_auth_header_span = Some(resolve_relative_value_span(
                        &with_child_key(&header_path, "value"),
                        relative,
                        signals.locator.as_ref(),
                        fallback_len,
                    ));
                }
                if signals.unresolved_header_variable_span.is_none()
                    && let Some(relative) =
                        find_unresolved_header_variable_relative_span(header_object)
                {
                    signals.unresolved_header_variable_span = Some(resolve_relative_value_span(
                        &with_child_key(&header_path, "value"),
                        relative,
                        signals.locator.as_ref(),
                        fallback_len,
                    ));
                }
                if signals.auth_header_policy_mismatch_span.is_none()
                    && auth_header_policy_mismatch(header_object)
                {
                    let key = if header_object.contains_key("isSecret") {
                        "isSecret"
                    } else if header_object.contains_key("is_secret") {
                        "is_secret"
                    } else {
                        "name"
                    };
                    signals.auth_header_policy_mismatch_span =
                        Some(resolve_child_value_or_key_span(
                            &header_path,
                            key,
                            signals.locator.as_ref(),
                            fallback_len,
                        ));
                }
            }
        }

        Some(signals)
    }
}
