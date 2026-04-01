use lintai_api::ArtifactKind;
use serde_json::Value;

use crate::json_locator::{JsonLocationMap, JsonPathSegment};
use crate::signals::{JsonSignals, SignalWorkBudget};

use super::spans::{
    resolve_child_value_span, resolve_value_span, with_child_index, with_child_key,
};

mod claude_settings;
mod mcp_command;
mod object_rules;
mod string_rules;

pub(crate) use claude_settings::visit_claude_settings_value;

pub(crate) fn visit_json_value(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    artifact_kind: ArtifactKind,
    signals: &mut JsonSignals,
    metrics: &mut SignalWorkBudget,
) {
    metrics.json_values_visited += 1;

    if let Value::Object(map) = value {
        let command_shape = object_rules::analyze_json_object(
            map,
            path,
            locator,
            fallback_len,
            artifact_kind,
            signals,
        );

        if artifact_kind == ArtifactKind::McpConfig {
            mcp_command::apply_mcp_config_command_rules(
                path,
                locator,
                fallback_len,
                command_shape.command,
                command_shape.args,
                signals,
            );
        }

        if artifact_kind == ArtifactKind::CursorPluginHooks {
            mcp_command::apply_plugin_hook_command_rules(
                path,
                locator,
                fallback_len,
                command_shape.command,
                signals,
            );
        }

        if signals.shell_wrapper_span.is_none()
            && command_shape.shell_has_dash_c
            && let Some(command_key) = command_shape.shell_command_key
        {
            signals.shell_wrapper_span = Some(resolve_child_value_span(
                path,
                command_key,
                locator,
                fallback_len,
            ));
        } else if signals.shell_wrapper_span.is_none()
            && command_shape.shell_has_dash_c
            && let Some(args) = command_shape.args
            && args
                .first()
                .and_then(Value::as_str)
                .is_some_and(|arg0| arg0 == "sh" || arg0 == "bash")
        {
            let arg_path = with_child_index(&with_child_key(path, "args"), 0);
            signals.shell_wrapper_span = Some(resolve_value_span(&arg_path, locator, fallback_len));
        }
    }

    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                path.push(JsonPathSegment::Key(key.clone()));
                visit_json_value(
                    nested,
                    path,
                    locator,
                    fallback_len,
                    artifact_kind,
                    signals,
                    metrics,
                );
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                path.push(JsonPathSegment::Index(index));
                visit_json_value(
                    nested,
                    path,
                    locator,
                    fallback_len,
                    artifact_kind,
                    signals,
                    metrics,
                );
                path.pop();
            }
        }
        Value::String(text) => {
            string_rules::apply_string_rules(text, path, locator, fallback_len, signals);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
