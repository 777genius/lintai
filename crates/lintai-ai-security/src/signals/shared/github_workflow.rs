use lintai_api::Span;
use serde_json::Value;

use super::super::GithubWorkflowSignals;
pub(crate) fn is_semantic_github_workflow(root: &serde_json::Map<String, Value>) -> bool {
    if root.get("jobs").and_then(Value::as_object).is_none() {
        return false;
    }

    root.contains_key("on")
        || root.contains_key("permissions")
        || root.values().any(value_contains_github_workflow_steps)
}

pub(crate) fn workflow_has_event(value: Option<&Value>, event_name: &str) -> bool {
    let Some(value) = value else {
        return false;
    };
    match value {
        Value::String(name) => name.eq_ignore_ascii_case(event_name),
        Value::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(event_name))
        }),
        Value::Object(map) => map.keys().any(|name| name.eq_ignore_ascii_case(event_name)),
        _ => false,
    }
}

pub(crate) fn workflow_has_explicit_write_permissions(
    root: &serde_json::Map<String, Value>,
) -> bool {
    root.get("permissions")
        .is_some_and(permission_value_has_write_capability)
        || root
            .get("jobs")
            .and_then(Value::as_object)
            .is_some_and(|jobs| {
                jobs.values().any(|job| {
                    job.as_object()
                        .and_then(|job| job.get("permissions"))
                        .is_some_and(permission_value_has_write_capability)
                })
            })
}

pub(crate) fn permission_value_has_write_capability(value: &Value) -> bool {
    match value {
        Value::String(permission) => permission.eq_ignore_ascii_case("write-all"),
        Value::Object(map) => map.values().any(|value| {
            value
                .as_str()
                .is_some_and(|permission| permission.eq_ignore_ascii_case("write"))
        }),
        _ => false,
    }
}

pub(crate) fn value_contains_github_workflow_steps(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(value_contains_github_workflow_steps),
        Value::Object(object) => {
            object.contains_key("uses")
                || object.contains_key("run")
                || object.values().any(value_contains_github_workflow_steps)
        }
        _ => false,
    }
}

pub(crate) fn collect_github_workflow_line(
    signals: &mut GithubWorkflowSignals,
    line: &str,
    offset: usize,
    has_pull_request_target: bool,
    has_explicit_write_permissions: bool,
    saw_checkout_step: &mut bool,
    current_checkout_indent: &mut Option<usize>,
) {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return;
    }
    let line_indent = line.len() - trimmed.len();

    if current_checkout_indent
        .is_some_and(|indent| line_indent <= indent && !trimmed.starts_with('-'))
    {
        *current_checkout_indent = None;
    }

    if let Some((start, end)) = find_github_workflow_key_value_span(line, "uses") {
        let value = &line[start..end];
        let normalized = normalize_yaml_scalar(value);
        if is_checkout_action_reference(normalized) {
            *saw_checkout_step = true;
            *current_checkout_indent = Some(line_indent);
        } else {
            *current_checkout_indent = None;
        }

        if find_third_party_unpinned_action_relative_span(value).is_some() {
            signals
                .unpinned_third_party_action_spans
                .push(Span::new(offset + start, offset + end));
        }
        if has_explicit_write_permissions && is_third_party_action_reference(normalized) {
            signals
                .write_capable_third_party_action_spans
                .push(Span::new(offset + start, offset + end));
        }
    }

    if let Some((start, end)) = find_github_workflow_key_value_span(line, "run") {
        let value = &line[start..end];
        if let Some(relative) = find_direct_untrusted_run_interpolation_relative_span(value) {
            signals
                .direct_untrusted_run_interpolation_spans
                .push(Span::new(
                    offset + start + relative.start_byte,
                    offset + start + relative.end_byte,
                ));
        }
    }

    if let Some((start, end)) = find_github_workflow_key_value_span(line, "permissions") {
        let value = normalize_yaml_scalar(&line[start..end]);
        if value.eq_ignore_ascii_case("write-all") {
            signals
                .write_all_permission_spans
                .push(Span::new(offset + start, offset + end));
        }
    }

    if let Some((start, end)) = find_github_workflow_key_value_span(line, "ref") {
        let value = &line[start..end];
        if has_pull_request_target
            && *saw_checkout_step
            && current_checkout_indent.is_some_and(|indent| line_indent > indent)
            && find_untrusted_pull_request_ref_relative_span(value).is_some()
        {
            signals
                .pull_request_target_head_checkout_spans
                .push(Span::new(offset + start, offset + end));
        }
    }
}

pub(crate) fn find_github_workflow_key_value_span(line: &str, key: &str) -> Option<(usize, usize)> {
    let trimmed_start = line.len() - line.trim_start().len();
    let mut trimmed = &line[trimmed_start..];
    if let Some(rest) = trimmed.strip_prefix("- ") {
        trimmed = rest.trim_start();
    }
    let prefix = format!("{key}:");
    if !trimmed.starts_with(&prefix) {
        return None;
    }
    let value = trimmed[prefix.len()..].trim_start();
    if value.is_empty() {
        return None;
    }
    let value_start = line.len() - value.len();
    Some((value_start, line.len()))
}

pub(crate) fn normalize_yaml_scalar(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

pub(crate) fn parse_github_action_reference(value: &str) -> Option<(&str, &str, &str)> {
    let normalized = normalize_yaml_scalar(value);
    if normalized.starts_with("./") || normalized.starts_with("docker://") {
        return None;
    }
    let (action, reference) = normalized.split_once('@')?;
    let mut segments = action.split('/');
    let owner = segments.next()?;
    let repo = segments.next()?;
    if owner.is_empty() || repo.is_empty() || segments.next().is_some() {
        return None;
    }
    Some((owner, repo, reference))
}

pub(crate) fn is_third_party_action_reference(value: &str) -> bool {
    parse_github_action_reference(value)
        .is_some_and(|(owner, _, _)| !owner.eq_ignore_ascii_case("actions"))
}

pub(crate) fn is_checkout_action_reference(value: &str) -> bool {
    parse_github_action_reference(value).is_some_and(|(owner, repo, _)| {
        owner.eq_ignore_ascii_case("actions") && repo.eq_ignore_ascii_case("checkout")
    })
}

pub(crate) fn find_third_party_unpinned_action_relative_span(value: &str) -> Option<Span> {
    let normalized = normalize_yaml_scalar(value);
    let Some((owner, _, reference)) = parse_github_action_reference(normalized) else {
        return None;
    };
    if owner.eq_ignore_ascii_case("actions") {
        return None;
    }
    let is_full_sha = reference.len() == 40 && reference.chars().all(|ch| ch.is_ascii_hexdigit());
    (!is_full_sha).then_some(Span::new(0, normalized.len()))
}

pub(crate) fn find_untrusted_pull_request_ref_relative_span(value: &str) -> Option<Span> {
    let normalized = normalize_yaml_scalar(value);
    matches!(
        normalized,
        "${{ github.event.pull_request.head.sha }}"
            | "${{ github.event.pull_request.head.ref }}"
            | "${{ github.head_ref }}"
    )
    .then_some(Span::new(0, normalized.len()))
}

pub(crate) fn find_direct_untrusted_run_interpolation_relative_span(value: &str) -> Option<Span> {
    let normalized = normalize_yaml_scalar(value);
    let start = normalized.find("${{")?;
    let end = normalized[start..].find("}}").map(|rel| start + rel + 2)?;
    let expression = &normalized[start..end];
    let lowered = expression.to_ascii_lowercase();
    if !(lowered.contains("inputs.") || lowered.contains("github.event.")) {
        return None;
    }

    let trimmed = normalized.trim_start();
    let first_token = trimmed.split_whitespace().next().unwrap_or_default();
    let looks_like_env_assignment = first_token.contains('=')
        && first_token.split('=').next().is_some_and(|name| {
            let mut chars = name.chars();
            let Some(first) = chars.next() else {
                return false;
            };
            (first.is_ascii_alphabetic() || first == '_')
                && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        });
    if looks_like_env_assignment {
        return None;
    }

    Some(Span::new(start, end))
}
