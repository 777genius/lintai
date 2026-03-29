use super::super::*;
use super::ai_native::{
    contains_semantic_gemini_mcp_config, contains_semantic_plugin_hook_commands,
    gemini_surface_label, is_ai_native_docker_config_path,
};

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
                if super::ai_native::contains_semantic_docker_mcp_launch(&text) {
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
    if normalized_path
        .split('/')
        .any(|segment| FIXTURE_PATH_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()))
    {
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
    if is_expanded_mcp_client_variant_path(normalized_path)
        && normalized_path
            .split('/')
            .any(|segment| FIXTURE_PATH_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()))
    {
        surfaces.insert("docker_mcp_launch (fixture-like)".to_owned());
        surfaces.insert("docker_mcp_launch_fixture_only".to_owned());
    } else {
        surfaces.insert("docker_mcp_launch".to_owned());
    }
}

pub(crate) fn is_mcp_config_path(normalized_path: &str) -> bool {
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

pub(crate) fn is_expanded_mcp_client_variant_path(normalized_path: &str) -> bool {
    normalized_path.ends_with(".cursor/mcp.json")
        || normalized_path.ends_with(".vscode/mcp.json")
        || normalized_path.ends_with(".roo/mcp.json")
        || normalized_path.ends_with(".kiro/settings/mcp.json")
        || normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with(".gemini/settings.json")
        || normalized_path.ends_with("vscode.settings.json")
}

pub(crate) fn is_generic_validation_excluded_path(normalized_path: &str) -> bool {
    normalized_path
        .split('/')
        .flat_map(segment_tokens)
        .any(|token| {
            FIXTURE_PATH_SEGMENTS
                .iter()
                .any(|reserved| token.eq_ignore_ascii_case(reserved))
                || DOCISH_PATH_SEGMENTS
                    .iter()
                    .any(|reserved| token.eq_ignore_ascii_case(reserved))
        })
}

pub(crate) fn is_tool_json_excluded_path(normalized_path: &str) -> bool {
    is_generic_validation_excluded_path(normalized_path)
}

pub(crate) fn package_label(package: ValidationPackage) -> &'static str {
    match package {
        ValidationPackage::Canonical => "canonical",
        ValidationPackage::ToolJsonExtension => "tool-json extension",
        ValidationPackage::ServerJsonExtension => "server-json extension",
        ValidationPackage::GithubActionsExtension => "github-actions extension",
        ValidationPackage::AiNativeDiscovery => "ai-native discovery",
    }
}

pub(crate) fn segment_tokens(segment: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let bytes = segment.as_bytes();
    let mut start = 0usize;
    for index in 0..bytes.len() {
        let byte = bytes[index];
        let is_delimiter = matches!(byte, b'_' | b'-' | b'.');
        let is_camel_boundary =
            index > start && bytes[index - 1].is_ascii_lowercase() && byte.is_ascii_uppercase();
        if is_delimiter || is_camel_boundary {
            if start < index {
                tokens.push(&segment[start..index]);
            }
            start = if is_delimiter { index + 1 } else { index };
        }
    }
    if start < segment.len() {
        tokens.push(&segment[start..]);
    }
    tokens
        .into_iter()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect()
}

pub(crate) fn json_descendants<'a>(value: &'a Value) -> Box<dyn Iterator<Item = &'a Value> + 'a> {
    match value {
        Value::Array(items) => {
            Box::new(std::iter::once(value).chain(items.iter().flat_map(json_descendants)))
        }
        Value::Object(map) => {
            Box::new(std::iter::once(value).chain(map.values().flat_map(json_descendants)))
        }
        _ => Box::new(std::iter::once(value)),
    }
}
