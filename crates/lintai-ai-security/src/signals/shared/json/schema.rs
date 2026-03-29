use lintai_api::Span;
use serde_json::Value;

use crate::json_locator::{JsonLocationMap, JsonPathSegment};

use super::spans::resolve_value_or_key_span;
use crate::signals::SignalWorkBudget;

pub(crate) fn find_open_object_schema_lock_span_path(
    value: &Value,
    metrics: &mut SignalWorkBudget,
) -> Option<Vec<JsonPathSegment>> {
    let mut path = Vec::new();
    find_open_object_schema_lock_span_path_inner(value, &mut path, metrics)
}

pub(crate) fn find_open_object_schema_lock_span_path_inner(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    metrics: &mut SignalWorkBudget,
) -> Option<Vec<JsonPathSegment>> {
    metrics.json_values_visited += 1;
    let object = value.as_object()?;
    let has_properties = object
        .get("properties")
        .and_then(Value::as_object)
        .is_some();
    if has_properties {
        match object.get("additionalProperties") {
            Some(Value::Bool(false)) => {}
            Some(_) => {
                let mut offending = path.clone();
                offending.push(JsonPathSegment::Key("additionalProperties".to_owned()));
                return Some(offending);
            }
            None => {
                let mut offending = path.clone();
                offending.push(JsonPathSegment::Key("properties".to_owned()));
                return Some(offending);
            }
        }
    }

    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        for (key, nested) in properties {
            path.push(JsonPathSegment::Key("properties".to_owned()));
            path.push(JsonPathSegment::Key(key.clone()));
            if let Some(offending) =
                find_open_object_schema_lock_span_path_inner(nested, path, metrics)
            {
                return Some(offending);
            }
            path.pop();
            path.pop();
        }
    }

    if let Some(items) = object.get("items") {
        path.push(JsonPathSegment::Key("items".to_owned()));
        if let Some(offending) = find_open_object_schema_lock_span_path_inner(items, path, metrics)
        {
            return Some(offending);
        }
        path.pop();
    }

    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(variants) = object.get(key).and_then(Value::as_array) {
            for (index, nested) in variants.iter().enumerate() {
                path.push(JsonPathSegment::Key(key.to_owned()));
                path.push(JsonPathSegment::Index(index));
                if let Some(offending) =
                    find_open_object_schema_lock_span_path_inner(nested, path, metrics)
                {
                    return Some(offending);
                }
                path.pop();
                path.pop();
            }
        }
    }

    None
}

pub(crate) fn find_required_coverage_mismatch_span_path(
    value: &Value,
    metrics: &mut SignalWorkBudget,
) -> Option<Vec<JsonPathSegment>> {
    let mut path = Vec::new();
    find_required_coverage_mismatch_span_path_inner(value, &mut path, metrics)
}

pub(crate) fn find_required_coverage_mismatch_span_path_inner(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    metrics: &mut SignalWorkBudget,
) -> Option<Vec<JsonPathSegment>> {
    metrics.json_values_visited += 1;
    let object = value.as_object()?;
    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        let property_keys = properties
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let required_keys = object
            .get("required")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default();
        if property_keys != required_keys {
            let mut offending = path.clone();
            offending.push(JsonPathSegment::Key(
                if object.get("required").is_some() {
                    "required"
                } else {
                    "properties"
                }
                .to_owned(),
            ));
            return Some(offending);
        }

        for (key, nested) in properties {
            path.push(JsonPathSegment::Key("properties".to_owned()));
            path.push(JsonPathSegment::Key(key.clone()));
            if let Some(offending) =
                find_required_coverage_mismatch_span_path_inner(nested, path, metrics)
            {
                return Some(offending);
            }
            path.pop();
            path.pop();
        }
    }

    if let Some(items) = object.get("items") {
        path.push(JsonPathSegment::Key("items".to_owned()));
        if let Some(offending) =
            find_required_coverage_mismatch_span_path_inner(items, path, metrics)
        {
            return Some(offending);
        }
        path.pop();
    }

    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(variants) = object.get(key).and_then(Value::as_array) {
            for (index, nested) in variants.iter().enumerate() {
                path.push(JsonPathSegment::Key(key.to_owned()));
                path.push(JsonPathSegment::Index(index));
                if let Some(offending) =
                    find_required_coverage_mismatch_span_path_inner(nested, path, metrics)
                {
                    return Some(offending);
                }
                path.pop();
                path.pop();
            }
        }
    }

    None
}

pub(crate) fn resolve_relative_schema_span(
    path: &[JsonPathSegment],
    schema_key: &str,
    relative_path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    let mut full_path = path.to_vec();
    full_path.push(JsonPathSegment::Key(schema_key.to_owned()));
    full_path.extend_from_slice(relative_path);
    resolve_value_or_key_span(&full_path, locator, fallback_len)
}

pub(crate) fn resolve_openai_relative_schema_span(
    path: &[JsonPathSegment],
    schema_key: &str,
    relative_path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
) -> Span {
    let mut full_path = path.to_vec();
    full_path.push(JsonPathSegment::Key("function".to_owned()));
    full_path.push(JsonPathSegment::Key(schema_key.to_owned()));
    full_path.extend_from_slice(relative_path);
    resolve_value_or_key_span(&full_path, locator, fallback_len)
}
