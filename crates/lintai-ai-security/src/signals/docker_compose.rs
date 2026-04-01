use lintai_api::{ArtifactKind, ScanContext, Span};
use serde_json::{Map, Value};

use crate::helpers::yaml_semantics;

use super::shared::common::{
    docker_image_uses_latest_or_implicit_tag, looks_like_registry_image_reference,
};
use super::shared::github_workflow::normalize_yaml_scalar;
use super::shared::markdown::is_digest_pinned_docker_image;
use super::{DockerComposeSignals, SignalWorkBudget};

impl DockerComposeSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::DockerCompose {
            return None;
        }

        let value = &yaml_semantics(ctx)?.value;
        let Some(root) = value.as_object() else {
            return None;
        };
        let services = root.get("services")?.as_object()?;
        let has_privileged_runtime = services_have_privileged_runtime(services);
        let has_mutable_images = services_have_mutable_images(services);
        let has_latest_images = services_have_latest_images(services);
        if !has_privileged_runtime && !has_mutable_images && !has_latest_images {
            return Some(Self::default());
        }

        let mut signals = Self::default();
        let mut state = ComposeScanState::default();
        let mut offset = 0usize;
        for segment in ctx.content.split_inclusive('\n') {
            let line = segment.strip_suffix('\n').unwrap_or(segment);
            metrics.markdown_regions_visited += 1;
            collect_compose_line(&mut signals, &mut state, line, offset);
            if signals.privileged_runtime_span.is_some() {
                break;
            }
            offset += segment.len();
        }
        if signals.privileged_runtime_span.is_none() && offset < ctx.content.len() {
            collect_compose_line(&mut signals, &mut state, &ctx.content[offset..], offset);
        }
        Some(signals)
    }
}

#[derive(Default)]
struct ComposeScanState {
    services_indent: Option<usize>,
    current_service_indent: Option<usize>,
    cap_add_indent: Option<usize>,
}

fn services_have_privileged_runtime(services: &Map<String, Value>) -> bool {
    services
        .values()
        .filter_map(Value::as_object)
        .any(service_has_privileged_runtime)
}

fn services_have_mutable_images(services: &Map<String, Value>) -> bool {
    services
        .values()
        .filter_map(Value::as_object)
        .any(service_has_mutable_image)
}

fn services_have_latest_images(services: &Map<String, Value>) -> bool {
    services
        .values()
        .filter_map(Value::as_object)
        .any(service_has_latest_image)
}

fn service_has_privileged_runtime(service: &Map<String, Value>) -> bool {
    service
        .get("privileged")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || service_key_is_host(service, "network_mode")
        || service_key_is_host(service, "pid")
        || service_key_is_host(service, "ipc")
        || service
            .get("cap_add")
            .is_some_and(value_has_dangerous_cap_add)
}

fn service_has_mutable_image(service: &Map<String, Value>) -> bool {
    service
        .get("image")
        .and_then(Value::as_str)
        .is_some_and(|value| {
            let normalized = normalize_yaml_scalar(value);
            looks_like_registry_image_reference(normalized)
                && !is_digest_pinned_docker_image(normalized)
        })
}

fn service_has_latest_image(service: &Map<String, Value>) -> bool {
    service
        .get("image")
        .and_then(Value::as_str)
        .is_some_and(|value| docker_image_uses_latest_or_implicit_tag(normalize_yaml_scalar(value)))
}

fn service_key_is_host(service: &Map<String, Value>, key: &str) -> bool {
    service
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| normalize_yaml_scalar(value).eq_ignore_ascii_case("host"))
}

fn value_has_dangerous_cap_add(value: &Value) -> bool {
    match value {
        Value::String(text) => scalar_is_dangerous_cap_add(text),
        Value::Array(items) => items.iter().any(value_has_dangerous_cap_add),
        _ => false,
    }
}

fn scalar_is_dangerous_cap_add(value: &str) -> bool {
    matches!(
        normalize_yaml_scalar(value).to_ascii_uppercase().as_str(),
        "ALL" | "SYS_ADMIN"
    )
}

fn collect_compose_line(
    signals: &mut DockerComposeSignals,
    state: &mut ComposeScanState,
    line: &str,
    offset: usize,
) {
    if signals.privileged_runtime_span.is_some() {
        return;
    }

    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }

    let indent = line.len() - trimmed.len();

    if trimmed == "services:" {
        state.services_indent = Some(indent);
        state.current_service_indent = None;
        state.cap_add_indent = None;
        return;
    }

    let Some(services_indent) = state.services_indent else {
        return;
    };

    if indent <= services_indent && !trimmed.starts_with('-') {
        state.services_indent = None;
        state.current_service_indent = None;
        state.cap_add_indent = None;
        return;
    }

    if let Some(service_indent) = state.current_service_indent
        && indent <= service_indent
        && !trimmed.starts_with('-')
    {
        state.current_service_indent = None;
        state.cap_add_indent = None;
    }

    if state.current_service_indent.is_none()
        && indent > services_indent
        && trimmed.ends_with(':')
        && !trimmed.starts_with('-')
    {
        state.current_service_indent = Some(indent);
        state.cap_add_indent = None;
        return;
    }

    let Some(service_indent) = state.current_service_indent else {
        return;
    };
    if indent <= service_indent {
        return;
    }

    if let Some(cap_add_indent) = state.cap_add_indent {
        if indent > cap_add_indent && trimmed.starts_with('-') {
            let value = normalize_yaml_scalar(trimmed.trim_start_matches('-').trim());
            if scalar_is_dangerous_cap_add(value) {
                signals.privileged_runtime_span = Some(Span::new(offset, offset + line.len()));
            }
            return;
        }
        if indent <= cap_add_indent {
            state.cap_add_indent = None;
        }
    }

    let Some((key, value, value_start)) = parse_yaml_key_value(trimmed) else {
        return;
    };
    match key {
        "privileged" if normalize_yaml_scalar(value).eq_ignore_ascii_case("true") => {
            signals.privileged_runtime_span = Some(Span::new(
                offset + (line.len() - trimmed.len()) + value_start,
                offset + line.len(),
            ));
        }
        "image" => {
            let normalized = normalize_yaml_scalar(value);
            if looks_like_registry_image_reference(normalized)
                && !is_digest_pinned_docker_image(normalized)
            {
                signals.mutable_image_span = Some(Span::new(
                    offset + (line.len() - trimmed.len()) + value_start,
                    offset + line.len(),
                ));
            }
            if signals.latest_image_span.is_none()
                && docker_image_uses_latest_or_implicit_tag(normalized)
            {
                signals.latest_image_span = Some(Span::new(
                    offset + (line.len() - trimmed.len()) + value_start,
                    offset + line.len(),
                ));
            }
        }
        "network_mode" | "pid" | "ipc"
            if normalize_yaml_scalar(value).eq_ignore_ascii_case("host") =>
        {
            signals.privileged_runtime_span = Some(Span::new(
                offset + (line.len() - trimmed.len()) + value_start,
                offset + line.len(),
            ));
        }
        "cap_add" => {
            if value.is_empty() {
                state.cap_add_indent = Some(indent);
                return;
            }
            if inline_cap_add_contains_dangerous(value) {
                signals.privileged_runtime_span = Some(Span::new(
                    offset + (line.len() - trimmed.len()) + value_start,
                    offset + line.len(),
                ));
            }
        }
        _ => {}
    }
}

fn parse_yaml_key_value(line: &str) -> Option<(&str, &str, usize)> {
    let colon = line.find(':')?;
    let key = line[..colon].trim();
    if key.is_empty() {
        return None;
    }
    let value = line[colon + 1..].trim_start();
    let value_start = line.len() - value.len();
    Some((key, value, value_start))
}

fn inline_cap_add_contains_dangerous(value: &str) -> bool {
    let normalized = normalize_yaml_scalar(value);
    let inner = normalized
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(normalized);
    inner.split(',').any(scalar_is_dangerous_cap_add)
}
