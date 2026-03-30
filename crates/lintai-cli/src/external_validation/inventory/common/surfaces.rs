use super::super::super::*;
use super::super::ai_native::{
    contains_semantic_docker_mcp_launch, contains_semantic_gemini_mcp_config,
    contains_semantic_plugin_hook_commands, gemini_surface_label, is_ai_native_docker_config_path,
};
use super::paths::is_fixture_like_path;

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct InventoryArtifact {
    pub(crate) surfaces_present: Vec<String>,
}

pub(crate) fn inventory_surfaces(repo_root: &Path) -> Result<InventoryArtifact, String> {
    let mut surfaces = BTreeSet::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry = result.map_err(|error| format!("inventory walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize inventory path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        if normalized.ends_with("SKILL.md") {
            surfaces.insert("SKILL.md".to_owned());
        }
        if normalized.ends_with("CLAUDE.md") {
            surfaces.insert("CLAUDE.md".to_owned());
        }
        if normalized.ends_with(".mdc") {
            surfaces.insert(".mdc".to_owned());
        }
        if normalized.ends_with(".cursorrules") {
            surfaces.insert(".cursorrules".to_owned());
        }
        if normalized == "mcp.json" {
            surfaces.insert("mcp.json".to_owned());
        }
        if normalized.ends_with(".mcp.json") {
            surfaces.insert(".mcp.json".to_owned());
        }
        if normalized.ends_with(".cursor/mcp.json") {
            insert_expanded_mcp_variant_surface(&mut surfaces, &normalized, ".cursor/mcp.json");
        }
        if normalized.ends_with(".vscode/mcp.json") {
            insert_expanded_mcp_variant_surface(&mut surfaces, &normalized, ".vscode/mcp.json");
        }
        if normalized.ends_with(".roo/mcp.json") {
            insert_expanded_mcp_variant_surface(&mut surfaces, &normalized, ".roo/mcp.json");
        }
        if normalized.ends_with(".kiro/settings/mcp.json") {
            insert_expanded_mcp_variant_surface(
                &mut surfaces,
                &normalized,
                ".kiro/settings/mcp.json",
            );
        }
        if is_ai_native_docker_config_path(&normalized) {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                if contains_semantic_gemini_mcp_config(&text) {
                    insert_expanded_mcp_variant_surface(
                        &mut surfaces,
                        &normalized,
                        gemini_surface_label(&normalized),
                    );
                }
            }
        }
        if normalized.contains(".claude/mcp/") && normalized.ends_with(".json") {
            surfaces.insert(".claude/mcp/*.json".to_owned());
        }
        if normalized == ".claude/settings.json" {
            surfaces.insert(".claude/settings.json".to_owned());
        }
        if normalized == "claude/settings.json" {
            surfaces.insert("claude/settings.json".to_owned());
        }
        if is_mcp_config_path(&normalized) {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                if contains_semantic_docker_mcp_launch(&text) {
                    insert_docker_mcp_launch_surface(&mut surfaces, &normalized);
                }
            }
        }
        if normalized.ends_with("server.json") {
            surfaces.insert("server.json".to_owned());
        }
        if normalized.contains(".github/workflows/")
            && (normalized.ends_with(".yml") || normalized.ends_with(".yaml"))
        {
            surfaces.insert(".github/workflows/*.yml".to_owned());
        }
        if normalized.ends_with("tools.json")
            || normalized.ends_with(".tool.json")
            || normalized.ends_with(".tools.json")
            || normalized.rsplit('/').next().is_some_and(|file_name| {
                file_name.ends_with(".json") && file_name.contains("tools")
            })
        {
            surfaces.insert("tool_descriptor_json".to_owned());
        }
        if normalized.ends_with(".cursor-plugin/plugin.json") {
            surfaces.insert(".cursor-plugin/plugin.json".to_owned());
        }
        if normalized.ends_with(".cursor-plugin/hooks.json") {
            surfaces.insert(".cursor-plugin/hooks.json".to_owned());
        }
        if normalized.ends_with("/hooks.json") && !normalized.contains("/.cursor-plugin/") {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                if contains_semantic_plugin_hook_commands(&text) {
                    surfaces.insert("plugin_root_hooks.json".to_owned());
                }
            }
        }
        if normalized.contains(".cursor-plugin/hooks/") && normalized.ends_with(".sh") {
            surfaces.insert(".cursor-plugin/hooks/**/*.sh".to_owned());
        }
        if normalized.contains(".cursor-plugin/commands/") && normalized.ends_with(".md") {
            surfaces.insert(".cursor-plugin/commands/**/*.md".to_owned());
        }
        if normalized.contains(".cursor-plugin/agents/") && normalized.ends_with(".md") {
            surfaces.insert(".cursor-plugin/agents/**/*.md".to_owned());
        }
        if normalized.contains("/agents/")
            && normalized.ends_with(".md")
            && !normalized.contains("/.cursor-plugin/agents/")
        {
            surfaces.insert("plugin_root_agents/*.md".to_owned());
        }
        if normalized.contains("/commands/")
            && normalized.ends_with(".md")
            && !normalized.contains("/.cursor-plugin/commands/")
            && !normalized.contains("/.claude/commands/")
        {
            surfaces.insert("plugin_root_commands/*.md".to_owned());
        }
    }

    Ok(InventoryArtifact {
        surfaces_present: surfaces.into_iter().collect(),
    })
}

pub(crate) fn insert_expanded_mcp_variant_surface(
    surfaces: &mut BTreeSet<String>,
    normalized_path: &str,
    label: &str,
) {
    if is_fixture_like_path(normalized_path) {
        surfaces.insert(format!("{label} (fixture-like)"));
        surfaces.insert("expanded_mcp_client_variant_fixture_only".to_owned());
    } else {
        surfaces.insert(label.to_owned());
    }
}

pub(crate) fn insert_docker_mcp_launch_surface(
    surfaces: &mut BTreeSet<String>,
    normalized_path: &str,
) {
    if is_expanded_mcp_client_variant_path(normalized_path) && is_fixture_like_path(normalized_path)
    {
        surfaces.insert("docker_mcp_launch (fixture-like)".to_owned());
        surfaces.insert("docker_mcp_launch_fixture_only".to_owned());
    } else {
        surfaces.insert("docker_mcp_launch".to_owned());
    }
}

fn is_mcp_config_path(normalized_path: &str) -> bool {
    normalized_path == "mcp.json"
        || normalized_path.ends_with(".mcp.json")
        || normalized_path.ends_with(".cursor/mcp.json")
        || normalized_path.ends_with(".vscode/mcp.json")
        || normalized_path.ends_with(".roo/mcp.json")
        || normalized_path.ends_with(".kiro/settings/mcp.json")
        || normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with(".gemini/settings.json")
        || normalized_path.ends_with("vscode.settings.json")
        || (normalized_path.contains(".claude/mcp/") && normalized_path.ends_with(".json"))
}

fn is_expanded_mcp_client_variant_path(normalized_path: &str) -> bool {
    normalized_path.ends_with(".cursor/mcp.json")
        || normalized_path.ends_with(".vscode/mcp.json")
        || normalized_path.ends_with(".roo/mcp.json")
        || normalized_path.ends_with(".kiro/settings/mcp.json")
        || normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with(".gemini/settings.json")
        || normalized_path.ends_with("vscode.settings.json")
}
