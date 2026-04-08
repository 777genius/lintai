use lintai_api::Span;
use serde_json::Value;

use crate::json_locator::{JsonLocationMap, JsonPathSegment};

use super::super::common::{HTML_COMMENT_DIRECTIVE_MARKERS, find_ascii_case_insensitive};
use super::schema::{
    find_open_object_schema_lock_span_path, find_required_coverage_mismatch_span_path,
    resolve_openai_relative_schema_span, resolve_relative_schema_span,
};
use super::spans::{resolve_child_value_or_key_span, resolve_child_value_span};
use crate::signals::{SignalWorkBudget, ToolJsonSignals};

pub(crate) fn visit_tool_json_value(
    value: &Value,
    normalized_path: &str,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    signals: &mut ToolJsonSignals,
    metrics: &mut SignalWorkBudget,
) {
    let collections = collect_tool_descriptor_collections(value, metrics);
    if collections.is_empty() || signals.fixture_like_path {
        return;
    }

    for collection in collections {
        let mut seen_mcp_names = std::collections::BTreeSet::new();
        for path in collection {
            let Some(object) = json_object_at_path(value, &path) else {
                continue;
            };

            if is_mcp_style_tool_descriptor_object(object) {
                if signals.mcp_missing_machine_field_span.is_none()
                    && let Some(span) =
                        find_mcp_missing_machine_field_span(&path, object, locator, fallback_len)
                {
                    signals.mcp_missing_machine_field_span = Some(span);
                }

                if signals.duplicate_mcp_tool_name_span.is_none()
                    && let Some(name) = object.get("name").and_then(Value::as_str)
                    && !seen_mcp_names.insert(name.to_owned())
                {
                    signals.duplicate_mcp_tool_name_span = Some(resolve_child_value_span(
                        &path,
                        "name",
                        locator,
                        fallback_len,
                    ));
                }
            }

            if let Some(function_object) = openai_function_object(object) {
                let strict_enabled = object.get("strict").and_then(Value::as_bool) == Some(true)
                    || function_object.get("strict").and_then(Value::as_bool) == Some(true);
                if strict_enabled {
                    let parameters_key = "parameters";
                    if let Some(parameters) = function_object.get(parameters_key) {
                        if signals.openai_strict_additional_properties_span.is_none()
                            && let Some(relative_path) =
                                find_open_object_schema_lock_span_path(parameters, metrics)
                        {
                            signals.openai_strict_additional_properties_span =
                                Some(resolve_openai_relative_schema_span(
                                    &path,
                                    parameters_key,
                                    &relative_path,
                                    locator,
                                    fallback_len,
                                ));
                        }

                        if signals.openai_strict_required_span.is_none()
                            && let Some(relative_path) =
                                find_required_coverage_mismatch_span_path(parameters, metrics)
                        {
                            signals.openai_strict_required_span =
                                Some(resolve_openai_relative_schema_span(
                                    &path,
                                    parameters_key,
                                    &relative_path,
                                    locator,
                                    fallback_len,
                                ));
                        }
                    }
                }
            }

            if signals.anthropic_strict_locked_input_schema_span.is_none()
                && object.get("name").and_then(Value::as_str).is_some()
                && object.get("strict").and_then(Value::as_bool) == Some(true)
                && let Some(input_schema) = object.get("input_schema")
                && let Some(relative_path) =
                    find_open_object_schema_lock_span_path(input_schema, metrics)
            {
                signals.anthropic_strict_locked_input_schema_span =
                    Some(resolve_relative_schema_span(
                        &path,
                        "input_schema",
                        &relative_path,
                        locator,
                        fallback_len,
                    ));
            }
        }
    }

    let _ = normalized_path;
}

pub(crate) fn collect_tool_descriptor_collections(
    value: &Value,
    metrics: &mut SignalWorkBudget,
) -> Vec<Vec<Vec<JsonPathSegment>>> {
    metrics.json_values_visited += 1;
    let mut collections = Vec::new();

    match value {
        Value::Array(items) => {
            let paths = items
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    item.as_object()
                        .filter(|object| looks_like_tool_descriptor_object(object))
                        .map(|_| vec![JsonPathSegment::Index(index)])
                })
                .collect::<Vec<_>>();
            if !paths.is_empty() {
                collections.push(paths);
            }
        }
        Value::Object(map) => {
            if looks_like_tool_descriptor_object(map) {
                collections.push(vec![Vec::new()]);
            }

            for key in ["tools", "functions"] {
                let Some(items) = map.get(key).and_then(Value::as_array) else {
                    continue;
                };
                let paths = items
                    .iter()
                    .enumerate()
                    .filter_map(|(index, item)| {
                        item.as_object()
                            .filter(|object| looks_like_tool_descriptor_object(object))
                            .map(|_| {
                                vec![
                                    JsonPathSegment::Key(key.to_owned()),
                                    JsonPathSegment::Index(index),
                                ]
                            })
                    })
                    .collect::<Vec<_>>();
                if !paths.is_empty() {
                    collections.push(paths);
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }

    collections
}

pub(crate) fn json_object_at_path<'a>(
    value: &'a Value,
    path: &[JsonPathSegment],
) -> Option<&'a serde_json::Map<String, Value>> {
    let mut current = value;
    for segment in path {
        match segment {
            JsonPathSegment::Key(key) => {
                current = current.as_object()?.get(key)?;
            }
            JsonPathSegment::Index(index) => {
                current = current.as_array()?.get(*index)?;
            }
        }
    }
    current.as_object()
}

pub(crate) fn looks_like_tool_descriptor_object(object: &serde_json::Map<String, Value>) -> bool {
    if object.contains_key("tools") || object.contains_key("functions") {
        return false;
    }

    object.contains_key("inputSchema")
        || object.contains_key("input_schema")
        || object.contains_key("parameters")
        || object.contains_key("function")
        || object.contains_key("name")
}

pub(crate) fn is_mcp_style_tool_descriptor_object(object: &serde_json::Map<String, Value>) -> bool {
    if object.contains_key("inputSchema") {
        return true;
    }

    object.get("name").and_then(Value::as_str).is_some()
        && !object.contains_key("function")
        && !object.contains_key("input_schema")
        && !object.contains_key("parameters")
        && !object.contains_key("tools")
        && !object.contains_key("functions")
}

pub(crate) fn find_mcp_missing_machine_field_span(
    path: &[JsonPathSegment],
    object: &serde_json::Map<String, Value>,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Option<Span> {
    let has_name = object.get("name").and_then(Value::as_str).is_some();
    let has_input_schema = object.contains_key("inputSchema");

    if has_input_schema && !has_name {
        return Some(resolve_child_value_or_key_span(
            path,
            "inputSchema",
            locator,
            fallback_len,
        ));
    }

    if !has_input_schema
        && has_name
        && (object.get("description").and_then(Value::as_str).is_some()
            || object.get("title").and_then(Value::as_str).is_some()
            || object
                .get("annotations")
                .and_then(Value::as_object)
                .is_some())
    {
        return Some(resolve_child_value_span(
            path,
            "name",
            locator,
            fallback_len,
        ));
    }

    None
}

pub(crate) fn openai_function_object(
    object: &serde_json::Map<String, Value>,
) -> Option<&serde_json::Map<String, Value>> {
    (object.get("type").and_then(Value::as_str) == Some("function"))
        .then(|| object.get("function").and_then(Value::as_object))
        .flatten()
}

pub(crate) fn is_plugin_manifest_path_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("logo")
        || key.eq_ignore_ascii_case("skills")
        || key.eq_ignore_ascii_case("mcpServers")
        || key.eq_ignore_ascii_case("mcpservers")
        || key.eq_ignore_ascii_case("commands")
        || key.eq_ignore_ascii_case("agents")
        || key.eq_ignore_ascii_case("hooks")
}

pub(crate) fn is_unsafe_plugin_manifest_path(value: &str) -> bool {
    let normalized = value.trim();
    normalized.starts_with('/')
        || normalized.starts_with("~/")
        || normalized.starts_with("~\\")
        || normalized.contains("../")
        || normalized.contains("..\\")
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|byte| *byte == b':')
}

pub(crate) fn is_broad_dotenv_env_file(value: &str) -> bool {
    super::auth_env::is_broad_dotenv_env_file(value)
}

pub(crate) fn is_descriptive_json_key(key: &str) -> bool {
    super::auth_env::is_descriptive_json_key(key)
}

pub(crate) fn find_hidden_instruction_relative_span(text: &str) -> Option<Span> {
    HTML_COMMENT_DIRECTIVE_MARKERS.iter().find_map(|needle| {
        find_ascii_case_insensitive(text, needle)
            .map(|start| Span::new(start, start + needle.len()))
    })
}
