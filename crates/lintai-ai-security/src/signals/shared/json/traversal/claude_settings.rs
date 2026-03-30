use serde_json::Value;

use crate::json_locator::{JsonLocationMap, JsonPathSegment};
use crate::signals::{ClaudeSettingsSignals, SignalWorkBudget};

use super::super::super::common::{
    find_command_tls_bypass_relative_span, find_mutable_launcher_relative_span,
    has_inline_download_pipe_exec, looks_like_network_capable_command,
};
use super::super::spans::{
    path_contains_key, resolve_child_relative_value_span, resolve_child_value_span,
};

fn find_home_directory_hook_command_relative_span(command: &str) -> Option<lintai_api::Span> {
    const PREFIXES: [&str; 3] = ["$HOME/", "/Users/", "/home/"];
    PREFIXES
        .iter()
        .find_map(|prefix| command.strip_prefix(prefix).map(|_| *prefix))
        .map(|prefix| lintai_api::Span::new(0, prefix.len()))
}

pub(crate) fn visit_claude_settings_value(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    signals: &mut ClaudeSettingsSignals,
    metrics: &mut SignalWorkBudget,
) {
    metrics.json_values_visited += 1;

    if let Value::Object(map) = value
        && path_contains_key(path, "hooks")
        && map.get("type").and_then(Value::as_str) == Some("command")
        && let Some(command) = map.get("command").and_then(Value::as_str)
    {
        if signals.home_directory_hook_command_span.is_none()
            && let Some(relative) = find_home_directory_hook_command_relative_span(command)
        {
            signals.home_directory_hook_command_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.mutable_launcher_span.is_none()
            && let Some(relative) = find_mutable_launcher_relative_span(command)
        {
            signals.mutable_launcher_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }

        let lowered = command.to_ascii_lowercase();
        if signals.inline_download_exec_span.is_none() && has_inline_download_pipe_exec(&lowered) {
            signals.inline_download_exec_span = Some(resolve_child_value_span(
                path,
                "command",
                locator,
                fallback_len,
            ));
        }

        let has_network_context = looks_like_network_capable_command(&lowered);
        if signals.network_tls_bypass_span.is_none()
            && has_network_context
            && let Some(relative) = find_command_tls_bypass_relative_span(command)
        {
            signals.network_tls_bypass_span = Some(resolve_child_relative_value_span(
                path,
                "command",
                "command",
                relative,
                locator,
                fallback_len,
            ));
        }
    }

    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                path.push(JsonPathSegment::Key(key.clone()));
                visit_claude_settings_value(nested, path, locator, fallback_len, signals, metrics);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                path.push(JsonPathSegment::Index(index));
                visit_claude_settings_value(nested, path, locator, fallback_len, signals, metrics);
                path.pop();
            }
        }
        _ => {}
    }
}
