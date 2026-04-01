use lintai_api::{ArtifactKind, ScanContext};
use serde_json::Value;

use crate::helpers::json_semantics;
use crate::json_locator::JsonLocationMap;

use super::shared::json::*;
use super::shared::markdown::{is_sensitive_docker_mount_spec, is_sensitive_docker_volume_spec};
use super::{DevcontainerSignals, SignalWorkBudget};

impl DevcontainerSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::DevcontainerConfig {
            return None;
        }

        let value = &json_semantics(ctx)?.value;
        let locator = JsonLocationMap::parse(&ctx.content);
        if locator.is_some() {
            metrics.json_locator_builds += 1;
        }
        let fallback_len = ctx.content.len();
        let mut signals = Self::default();
        let Some(root) = value.as_object() else {
            return Some(signals);
        };

        if let Some(command) = root.get("initializeCommand") {
            metrics.json_values_visited += 1;
            if has_nonempty_devcontainer_command(command) {
                signals.initialize_command_span = Some(resolve_value_span(
                    &with_child_key(&[], "initializeCommand"),
                    locator.as_ref(),
                    fallback_len,
                ));
            }
        }

        if let Some(workspace_mount) = root.get("workspaceMount").and_then(Value::as_str) {
            metrics.json_values_visited += 1;
            if is_sensitive_docker_mount_spec(workspace_mount) {
                signals.sensitive_mount_span = Some(resolve_value_span(
                    &with_child_key(&[], "workspaceMount"),
                    locator.as_ref(),
                    fallback_len,
                ));
            }
        }

        if signals.sensitive_mount_span.is_none() {
            collect_mounts_signal(
                root.get("mounts"),
                locator.as_ref(),
                fallback_len,
                metrics,
                &mut signals,
            );
        }

        if signals.sensitive_mount_span.is_none() {
            collect_run_args_signal(
                root.get("runArgs"),
                locator.as_ref(),
                fallback_len,
                metrics,
                &mut signals,
            );
        }

        Some(signals)
    }
}

fn has_nonempty_devcontainer_command(value: &Value) -> bool {
    match value {
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        _ => false,
    }
}

fn collect_mounts_signal(
    mounts: Option<&Value>,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    metrics: &mut SignalWorkBudget,
    signals: &mut DevcontainerSignals,
) {
    let Some(mounts) = mounts else {
        return;
    };

    match mounts {
        Value::String(spec) if is_sensitive_docker_mount_spec(spec) => {
            metrics.json_values_visited += 1;
            signals.sensitive_mount_span = Some(resolve_value_span(
                &with_child_key(&[], "mounts"),
                locator,
                fallback_len,
            ));
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                metrics.json_values_visited += 1;
                let Some(spec) = item.as_str() else {
                    continue;
                };
                if is_sensitive_docker_mount_spec(spec) {
                    signals.sensitive_mount_span = Some(resolve_value_span(
                        &with_child_index(&with_child_key(&[], "mounts"), index),
                        locator,
                        fallback_len,
                    ));
                    break;
                }
            }
        }
        _ => {}
    }
}

fn collect_run_args_signal(
    run_args: Option<&Value>,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    metrics: &mut SignalWorkBudget,
    signals: &mut DevcontainerSignals,
) {
    let Some(run_args) = run_args.and_then(Value::as_array) else {
        return;
    };

    let args_path = with_child_key(&[], "runArgs");
    let mut index = 0usize;
    while index < run_args.len() {
        metrics.json_values_visited += 1;
        let Some(text) = run_args[index].as_str() else {
            index += 1;
            continue;
        };

        let matched_index = if matches!(text, "-v" | "--volume") {
            run_args
                .get(index + 1)
                .and_then(Value::as_str)
                .filter(|spec| is_sensitive_docker_volume_spec(spec))
                .map(|_| index + 1)
        } else if text.starts_with("--volume=")
            && is_sensitive_docker_volume_spec(
                text.split_once('=')
                    .map(|(_, value)| value)
                    .unwrap_or_default(),
            )
        {
            Some(index)
        } else if text.starts_with("-v")
            && text.len() > 2
            && is_sensitive_docker_volume_spec(&text[2..])
        {
            Some(index)
        } else if text == "--mount" {
            run_args
                .get(index + 1)
                .and_then(Value::as_str)
                .filter(|spec| is_sensitive_docker_mount_spec(spec))
                .map(|_| index + 1)
        } else if text.starts_with("--mount=")
            && is_sensitive_docker_mount_spec(
                text.split_once('=')
                    .map(|(_, value)| value)
                    .unwrap_or_default(),
            )
        {
            Some(index)
        } else {
            None
        };

        if let Some(arg_index) = matched_index {
            signals.sensitive_mount_span = Some(resolve_value_span(
                &with_child_index(&args_path, arg_index),
                locator,
                fallback_len,
            ));
            break;
        }

        index += 1;
    }
}
