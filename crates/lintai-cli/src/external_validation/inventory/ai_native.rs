mod admission;
mod plugin_targets;
mod semantic;

pub(crate) use admission::{
    admitted_ai_native_paths, gemini_surface_label, is_ai_native_docker_config_path,
};
#[cfg(test)]
pub(crate) use semantic::contains_semantic_claude_command_settings;
pub(crate) use semantic::{
    contains_semantic_docker_mcp_launch, contains_semantic_gemini_mcp_config,
    contains_semantic_plugin_hook_commands,
};
