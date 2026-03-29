mod ai_native;
mod common;
mod github_actions;
mod server_json;
mod tool_json;

use super::*;

pub(crate) use ai_native::{admitted_ai_native_paths, is_ai_native_docker_config_path};
pub(crate) use common::{inventory_surfaces, is_tool_json_excluded_path};
pub(crate) use github_actions::admitted_github_workflow_paths;
pub(crate) use server_json::admitted_server_json_paths;
pub(crate) use tool_json::admitted_tool_descriptor_paths;

#[cfg(test)]
pub(crate) use ai_native::{
    contains_semantic_claude_command_settings, contains_semantic_docker_mcp_launch,
    contains_semantic_gemini_mcp_config, contains_semantic_plugin_hook_commands,
};
#[cfg(test)]
pub(crate) use common::is_generic_validation_excluded_path;
#[cfg(test)]
pub(crate) use github_actions::contains_semantic_github_workflow_yaml;
#[cfg(test)]
pub(crate) use server_json::contains_semantic_server_json;
#[cfg(test)]
pub(crate) use tool_json::contains_semantic_tool_descriptor_json;

pub(crate) fn verify_repo_admission(
    package: ValidationPackage,
    repo: &ShortlistRepo,
    repo_root: &Path,
) -> Result<(), String> {
    let detected = match package {
        ValidationPackage::Canonical => return Ok(()),
        ValidationPackage::ToolJsonExtension => admitted_tool_descriptor_paths(repo_root)?,
        ValidationPackage::ServerJsonExtension => admitted_server_json_paths(repo_root)?,
        ValidationPackage::GithubActionsExtension => admitted_github_workflow_paths(repo_root)?,
        ValidationPackage::AiNativeDiscovery => admitted_ai_native_paths(repo_root)?,
    };

    if repo.admission_paths.is_empty() {
        return Err(format!(
            "{} repo `{}` must declare at least one admission path",
            common::package_label(package),
            repo.repo
        ));
    }

    let expected = repo
        .admission_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual = detected.iter().cloned().collect::<BTreeSet<_>>();

    if expected != actual {
        return Err(format!(
            "{} admission mismatch for `{}`: expected {:?}, got {:?}",
            common::package_label(package),
            repo.repo,
            expected,
            actual
        ));
    }

    Ok(())
}
