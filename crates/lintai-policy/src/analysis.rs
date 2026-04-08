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

#[cfg(test)]
mod tests {
    use super::*;
    use lintai_api::{
        Artifact, ArtifactKind, CapabilityProfile, DocumentSemantics, ExecCapability,
        FrontmatterFormat, FrontmatterSemantics, JsonSemantics, MarkdownSemantics,
        NetworkCapability, ParsedDocument, SourceFormat, WorkspaceArtifact,
    };
    use serde_json::json;

    fn artifact(
        kind: ArtifactKind,
        semantics: Option<DocumentSemantics>,
        content: &str,
    ) -> WorkspaceArtifact {
        WorkspaceArtifact::new(
            Artifact::new("repo/file.txt", kind, SourceFormat::Markdown),
            content,
            ParsedDocument::new(Vec::new(), None),
            semantics,
        )
    }

    #[test]
    fn exec_forbidden_checks_none_only() {
        let mut none = CapabilityProfile::default();
        let mut shell = CapabilityProfile::default();

        none.exec = Some(ExecCapability::None);
        shell.exec = Some(ExecCapability::Shell);
        let not_set = CapabilityProfile::default();

        assert!(exec_forbidden(&none));
        assert!(!exec_forbidden(&shell));
        assert!(!exec_forbidden(&not_set));
    }

    #[test]
    fn network_forbidden_checks_none_only() {
        let mut none = CapabilityProfile::default();
        let mut outbound = CapabilityProfile::default();

        none.network = Some(NetworkCapability::None);
        outbound.network = Some(NetworkCapability::OutboundAny);

        assert!(network_forbidden(&none));
        assert!(!network_forbidden(&outbound));
    }

    #[test]
    fn artifact_observes_exec_reports_hook_script_always_true() {
        let artifact = artifact(ArtifactKind::CursorHookScript, None, "noop");

        assert!(artifact_observes_exec(&artifact));
    }

    #[test]
    fn artifact_observes_exec_detects_shell_wrapper_in_mcp_config() {
        let artifact = artifact(
            ArtifactKind::McpConfig,
            Some(DocumentSemantics::Json(JsonSemantics::new(json!(
                {"command":"sh","args":["-c","echo hi"]}
            )))),
            "",
        );

        assert!(artifact_observes_exec(&artifact));
    }

    #[test]
    fn artifact_observes_exec_rejects_non_shell_command() {
        let artifact = artifact(
            ArtifactKind::McpConfig,
            Some(DocumentSemantics::Json(JsonSemantics::new(json!(
                {"command":"python","args":["-c","print(1)"]}
            )))),
            "",
        );

        assert!(!artifact_observes_exec(&artifact));
    }

    #[test]
    fn artifact_observes_exec_ignores_non_mcp_artifacts() {
        let artifact = artifact(
            ArtifactKind::PackageManifest,
            Some(DocumentSemantics::Json(JsonSemantics::new(json!(
                {"command":"sh","args":["-c","echo"]}
            )))),
            "",
        );

        assert!(!artifact_observes_exec(&artifact));
    }

    #[test]
    fn artifact_observes_network_detects_shell_content() {
        let artifact = artifact(
            ArtifactKind::CursorHookScript,
            None,
            "curl https://example.com",
        );

        assert!(artifact_observes_network(&artifact));
    }

    #[test]
    fn artifact_observes_network_detects_nested_json_reference() {
        let artifact = artifact(
            ArtifactKind::CursorPluginManifest,
            Some(DocumentSemantics::Json(JsonSemantics::new(json!(
                {"tool":{"url":"https://example.com","nested":{"url":"http://local"}}}
            )))),
            "",
        );

        assert!(artifact_observes_network(&artifact));
    }

    #[test]
    fn artifact_observes_network_does_not_flag_non_network_artifacts() {
        let artifact = artifact(ArtifactKind::DevcontainerConfig, None, "copy ./src .");
        assert!(!artifact_observes_network(&artifact));
    }

    #[test]
    fn capabilities_conflict_detects_exec_disallowed_when_skill_requests_exec() {
        let mut project = CapabilityProfile::default();
        let mut skill = CapabilityProfile::default();
        project.exec = Some(ExecCapability::None);
        skill.exec = Some(ExecCapability::Subprocess);

        assert!(capabilities_conflict(&project, &skill));
    }

    #[test]
    fn capabilities_conflict_detects_network_disallowed_when_skill_requests_access() {
        let mut project = CapabilityProfile::default();
        let mut skill = CapabilityProfile::default();
        project.network = Some(NetworkCapability::None);
        skill.network = Some(NetworkCapability::OutboundAny);

        assert!(capabilities_conflict(&project, &skill));
    }

    #[test]
    fn capabilities_conflict_ignores_if_skill_does_not_exceed_project_limits() {
        let mut project = CapabilityProfile::default();
        let mut skill = CapabilityProfile::default();
        project.exec = Some(ExecCapability::None);
        project.network = Some(NetworkCapability::None);
        skill.exec = Some(ExecCapability::None);
        skill.network = Some(NetworkCapability::None);

        assert!(!capabilities_conflict(&project, &skill));
    }

    #[test]
    fn contains_shell_wrapper_checks_direct_and_nested_structures() {
        assert!(contains_shell_wrapper(
            &json!({"command":"bash","args":["-c","echo"]})
        ));
        assert!(!contains_shell_wrapper(
            &json!({"command":"python","args":["-c","print('ok')"]})
        ));
        assert!(contains_shell_wrapper(
            &json!({"outer":{"command":"sh","args":["-c","echo"]}})
        ));
        assert!(contains_shell_wrapper(
            &json!(["pre",{"command":"bash","args":["-c","echo"]}])
        ));
    }

    #[test]
    fn contains_network_reference_checks_recursive_json_values() {
        assert!(contains_network_reference(&json!("https://example.com")));
        assert!(!contains_network_reference(&json!("ftp://example.com")));
        assert!(contains_network_reference(
            &json!({"tool":[{"url":"https://example.com"}]})
        ));
        assert!(!contains_network_reference(&json!(123)));
    }

    #[test]
    fn workspace_json_semantics_extracts_json_only() {
        let json_artifact = artifact(
            ArtifactKind::CursorPluginManifest,
            Some(DocumentSemantics::Json(JsonSemantics::new(json!({"a":1})))),
            "",
        );
        let mdf = artifact(
            ArtifactKind::CursorPluginManifest,
            Some(DocumentSemantics::Markdown(MarkdownSemantics::new(Some(
                FrontmatterSemantics::new(FrontmatterFormat::Yaml, json!({"capabilities":{}})),
            )))),
            "",
        );
        assert!(workspace_json_semantics(&json_artifact).is_some());
        assert!(workspace_json_semantics(&mdf).is_none());
    }
}
