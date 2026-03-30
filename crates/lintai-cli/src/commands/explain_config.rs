use std::path::Path;
use std::process::ExitCode;

use lintai_api::ArtifactKind;
use lintai_engine::{ResolvedFileConfig, explain_file_config, load_workspace_config};

use crate::args::parse_explain_config_args;
use crate::path::validate_path_within_project;

pub(crate) fn run(
    current_dir: &Path,
    args: impl Iterator<Item = String>,
) -> Result<ExitCode, String> {
    let target = parse_explain_config_args(args)?;
    let workspace = load_workspace_config(current_dir)
        .map_err(|error| format!("config resolution failed: {error}"))?;
    validate_path_within_project(&target, workspace.engine_config.project_root.as_deref())
        .map_err(|error| format!("target validation failed: {error}"))?;
    let resolved = explain_file_config(&workspace, &target);
    print!(
        "{}",
        format_explain_config(workspace.source_path.as_deref(), &resolved)
    );
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn format_explain_config(
    config_source: Option<&Path>,
    resolved: &ResolvedFileConfig,
) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "config_source={}\n",
        config_source.map_or("<none>".to_owned(), |p| p.display().to_string())
    ));
    output.push_str(&format!("normalized_path={}\n", resolved.normalized_path));
    output.push_str(&format!("included={}\n", resolved.included));
    output.push_str(&format!("detected_kind={:?}\n", resolved.detected_kind));
    output.push_str(&format!("detected_format={:?}\n", resolved.detected_format));
    output.push_str(&format!("enabled_presets={:?}\n", resolved.enabled_presets));
    output.push_str(&format!(
        "relevant_surface_presets={:?}\n",
        relevant_surface_presets(resolved.detected_kind)
    ));
    output.push_str(&format!(
        "active_rule_count={}\n",
        resolved.active_rule_codes.len()
    ));
    output.push_str(&format!("output={:?}\n", resolved.output_format));
    output.push_str(&format!("ci_fail_on={:?}\n", resolved.ci_policy.fail_on));
    output.push_str(&format!(
        "ci_min_confidence={:?}\n",
        resolved.ci_policy.min_confidence
    ));
    output.push_str(&format!(
        "capability_conflict_mode={:?}\n",
        resolved.capability_conflict_mode
    ));
    output.push_str(&format!(
        "project_capabilities={:?}\n",
        resolved.project_capabilities
    ));
    output.push_str(&format!(
        "applied_overrides={:?}\n",
        resolved.applied_overrides
    ));
    output.push_str(&format!(
        "preset_category_overrides={:?}\n",
        resolved.preset_category_overrides
    ));
    output.push_str(&format!(
        "preset_rule_overrides={:?}\n",
        resolved.preset_rule_overrides
    ));
    output.push_str(&format!(
        "category_overrides={:?}\n",
        resolved.category_overrides
    ));
    output.push_str(&format!("rule_overrides={:?}\n", resolved.rule_overrides));
    output
}

fn relevant_surface_presets(detected_kind: Option<ArtifactKind>) -> Vec<&'static str> {
    match detected_kind {
        Some(
            ArtifactKind::Skill
            | ArtifactKind::Instructions
            | ArtifactKind::CursorRules
            | ArtifactKind::CursorPluginCommand
            | ArtifactKind::CursorPluginAgent,
        ) => vec!["skills"],
        Some(
            ArtifactKind::McpConfig
            | ArtifactKind::ServerRegistryConfig
            | ArtifactKind::ToolDescriptorJson
            | ArtifactKind::CursorPluginManifest
            | ArtifactKind::CursorPluginHooks,
        ) => vec!["mcp"],
        Some(ArtifactKind::ClaudeSettings) => vec!["claude"],
        Some(ArtifactKind::GitHubWorkflow | ArtifactKind::CursorHookScript) | None => Vec::new(),
        Some(_) => Vec::new(),
    }
}
