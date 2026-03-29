use lintai_api::{
    ArtifactKind, CapabilityProfile, ExecCapability, NetworkCapability, WorkspaceArtifact,
};

pub(crate) fn exec_forbidden(profile: &CapabilityProfile) -> bool {
    matches!(profile.exec, Some(ExecCapability::None))
}

pub(crate) fn network_forbidden(profile: &CapabilityProfile) -> bool {
    matches!(profile.network, Some(NetworkCapability::None))
}

pub(crate) fn artifact_observes_exec(ctx: &WorkspaceArtifact) -> bool {
    match ctx.artifact.kind {
        ArtifactKind::CursorHookScript => true,
        ArtifactKind::McpConfig => workspace_json_semantics(ctx)
            .map(|json| contains_shell_wrapper(&json.value))
            .unwrap_or(false),
        _ => false,
    }
}

pub(crate) fn artifact_observes_network(ctx: &WorkspaceArtifact) -> bool {
    match ctx.artifact.kind {
        ArtifactKind::CursorHookScript => {
            let lowered = ctx.content.to_lowercase();
            lowered.contains("curl ")
                || lowered.contains("wget ")
                || lowered.contains("http://")
                || lowered.contains("https://")
        }
        ArtifactKind::McpConfig
        | ArtifactKind::CursorPluginManifest
        | ArtifactKind::CursorPluginHooks => workspace_json_semantics(ctx)
            .map(|json| contains_network_reference(&json.value))
            .unwrap_or(false),
        _ => false,
    }
}

pub(crate) fn capabilities_conflict(
    project: &CapabilityProfile,
    skill: &CapabilityProfile,
) -> bool {
    if exec_forbidden(project) && !matches!(skill.exec, None | Some(ExecCapability::None)) {
        return true;
    }
    if network_forbidden(project) && !matches!(skill.network, None | Some(NetworkCapability::None))
    {
        return true;
    }
    false
}

pub(crate) fn contains_shell_wrapper(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            let command = map
                .get("command")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let args = map
                .get("args")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            ((command == "sh" || command == "bash") && args.contains(&"-c"))
                || map.values().any(contains_shell_wrapper)
        }
        serde_json::Value::Array(items) => items.iter().any(contains_shell_wrapper),
        _ => false,
    }
}

pub(crate) fn contains_network_reference(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => {
            text.starts_with("http://") || text.starts_with("https://")
        }
        serde_json::Value::Array(items) => items.iter().any(contains_network_reference),
        serde_json::Value::Object(map) => map.values().any(contains_network_reference),
        _ => false,
    }
}

pub(crate) fn workspace_json_semantics(
    ctx: &WorkspaceArtifact,
) -> Option<&lintai_api::JsonSemantics> {
    match ctx.semantics.as_ref() {
        Some(lintai_api::DocumentSemantics::Json(value)) => Some(value),
        _ => None,
    }
}
