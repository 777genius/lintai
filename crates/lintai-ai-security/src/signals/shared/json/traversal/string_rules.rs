use crate::helpers::find_url_userinfo_span;
use crate::json_locator::{JsonLocationMap, JsonPathSegment};
use crate::signals::JsonSignals;

use super::super::server_headers::{
    find_dangerous_endpoint_host_relative_span, find_suspicious_remote_endpoint_relative_span,
    is_endpointish_json_key,
};
use super::super::spans::{resolve_relative_value_span, resolve_value_span};
use super::super::tool_descriptor::{
    find_hidden_instruction_relative_span, is_descriptive_json_key,
};

pub(super) fn apply_string_rules(
    text: &str,
    path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    signals: &mut JsonSignals,
) {
    if signals.plain_http_endpoint_span.is_none() && text.starts_with("http://") {
        signals.plain_http_endpoint_span = Some(resolve_value_span(path, locator, fallback_len));
    }

    if signals.static_auth_exposure_span.is_none()
        && let Some(relative) = find_url_userinfo_span(text)
    {
        signals.static_auth_exposure_span = Some(resolve_relative_value_span(
            path,
            relative,
            locator,
            fallback_len,
        ));
    }

    let Some(JsonPathSegment::Key(key)) = path.last() else {
        return;
    };

    if signals.hidden_instruction_span.is_none()
        && is_descriptive_json_key(key)
        && let Some(relative) = find_hidden_instruction_relative_span(text)
    {
        signals.hidden_instruction_span = Some(resolve_relative_value_span(
            path,
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.suspicious_remote_endpoint_span.is_none()
        && is_endpointish_json_key(key)
        && let Some(relative) = find_suspicious_remote_endpoint_relative_span(text)
    {
        signals.suspicious_remote_endpoint_span = Some(resolve_relative_value_span(
            path,
            relative,
            locator,
            fallback_len,
        ));
    }

    if signals.dangerous_endpoint_host_span.is_none()
        && is_endpointish_json_key(key)
        && let Some(relative) = find_dangerous_endpoint_host_relative_span(text)
    {
        signals.dangerous_endpoint_host_span = Some(resolve_relative_value_span(
            path,
            relative,
            locator,
            fallback_len,
        ));
    }
}
