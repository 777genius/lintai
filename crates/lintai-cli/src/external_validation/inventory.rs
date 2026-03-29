use super::*;

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
        if is_ai_native_docker_config_path(&normalized)
            && let Ok(text) = std::fs::read_to_string(entry.path())
            && contains_semantic_gemini_mcp_config(&text)
        {
            insert_expanded_mcp_variant_surface(
                &mut surfaces,
                &normalized,
                gemini_surface_label(&normalized),
            );
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
        if is_mcp_config_path(&normalized)
            && let Ok(text) = std::fs::read_to_string(entry.path())
            && contains_semantic_docker_mcp_launch(&text)
        {
            insert_docker_mcp_launch_surface(&mut surfaces, &normalized);
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
        if normalized.ends_with("/hooks.json")
            && !normalized.contains("/.cursor-plugin/")
            && let Ok(text) = std::fs::read_to_string(entry.path())
            && contains_semantic_plugin_hook_commands(&text)
        {
            surfaces.insert("plugin_root_hooks.json".to_owned());
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

pub(crate) fn gemini_surface_label(normalized_path: &str) -> &'static str {
    if normalized_path.ends_with(".gemini/settings.json") {
        ".gemini/settings.json"
    } else if normalized_path.ends_with("gemini.settings.json") {
        "gemini.settings.json"
    } else if normalized_path.ends_with("vscode.settings.json") {
        "vscode.settings.json"
    } else {
        "gemini-extension.json"
    }
}

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
            package_label(package),
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
            package_label(package),
            repo.repo,
            expected,
            actual
        ));
    }

    Ok(())
}

pub(crate) fn admitted_tool_descriptor_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let detector = FileTypeDetector::default();
    let mut admitted = Vec::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry = result.map_err(|error| format!("tool-json admission walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize tool-json path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        if is_tool_json_excluded_path(&normalized) {
            continue;
        }
        let Some(detected) = detector.detect(relative, &normalized) else {
            continue;
        };
        if detected.kind != ArtifactKind::ToolDescriptorJson {
            continue;
        }
        let text = fs::read_to_string(entry.path()).map_err(|error| {
            format!(
                "failed to read candidate tool descriptor JSON {}: {error}",
                entry.path().display()
            )
        })?;
        if contains_semantic_tool_descriptor_json(&text) {
            admitted.push(normalized);
        }
    }
    admitted.sort();
    admitted.dedup();
    if admitted.is_empty() {
        return Err(
            "no committed non-fixture ToolDescriptorJson paths passed semantic confirmation"
                .to_owned(),
        );
    }
    Ok(admitted)
}

pub(crate) fn admitted_server_json_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let detector = FileTypeDetector::default();
    let mut admitted = Vec::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry =
            result.map_err(|error| format!("server-json admission walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize server-json path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        if is_generic_validation_excluded_path(&normalized) {
            continue;
        }
        let Some(detected) = detector.detect(relative, &normalized) else {
            continue;
        };
        if detected.kind != ArtifactKind::ServerRegistryConfig {
            continue;
        }
        let text = fs::read_to_string(entry.path()).map_err(|error| {
            format!(
                "failed to read candidate server.json {}: {error}",
                entry.path().display()
            )
        })?;
        if contains_semantic_server_json(&text) {
            admitted.push(normalized);
        }
    }
    admitted.sort();
    admitted.dedup();
    if admitted.is_empty() {
        return Err(
            "no committed non-fixture server.json paths passed semantic confirmation".to_owned(),
        );
    }
    Ok(admitted)
}

pub(crate) fn admitted_github_workflow_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let detector = FileTypeDetector::default();
    let mut admitted = Vec::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry =
            result.map_err(|error| format!("github-workflow admission walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize github-workflow path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        let Some(detected) = detector.detect(relative, &normalized) else {
            continue;
        };
        if detected.kind != ArtifactKind::GitHubWorkflow {
            continue;
        }
        let text = fs::read_to_string(entry.path()).map_err(|error| {
            format!(
                "failed to read candidate github workflow {}: {error}",
                entry.path().display()
            )
        })?;
        if contains_semantic_github_workflow_yaml(&text) {
            admitted.push(normalized);
        }
    }
    admitted.sort();
    admitted.dedup();
    if admitted.is_empty() {
        return Err("no semantically confirmed GitHub workflow paths passed admission".to_owned());
    }
    Ok(admitted)
}

pub(crate) fn admitted_ai_native_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let mut admitted = Vec::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry = result.map_err(|error| format!("ai-native admission walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize ai-native path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        if is_generic_validation_excluded_path(&normalized) {
            continue;
        }
        if is_ai_native_docker_config_path(&normalized) {
            let text = fs::read_to_string(entry.path()).map_err(|error| {
                format!(
                    "failed to read candidate AI-native docker config {}: {error}",
                    entry.path().display()
                )
            })?;
            if contains_semantic_docker_mcp_launch(&text) {
                admitted.push(normalized);
            }
            continue;
        }
        if is_ai_native_claude_settings_path(&normalized) {
            let text = fs::read_to_string(entry.path()).map_err(|error| {
                format!(
                    "failed to read candidate Claude settings {}: {error}",
                    entry.path().display()
                )
            })?;
            if contains_semantic_claude_command_settings(&text) {
                admitted.push(normalized);
            }
            continue;
        }
        if normalized.ends_with(".cursor-plugin/plugin.json") {
            let text = fs::read_to_string(entry.path()).map_err(|error| {
                format!(
                    "failed to read candidate plugin manifest {}: {error}",
                    entry.path().display()
                )
            })?;
            admitted.extend(admitted_plugin_execution_targets(
                repo_root, relative, &text,
            )?);
        }
    }
    admitted.sort();
    admitted.dedup();
    if admitted.is_empty() {
        return Err(
            "no AI-native docker or plugin execution paths passed discovery admission".to_owned(),
        );
    }
    Ok(admitted)
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

pub(crate) fn is_ai_native_docker_config_path(normalized_path: &str) -> bool {
    normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with("vscode.settings.json")
}

pub(crate) fn is_ai_native_claude_settings_path(normalized_path: &str) -> bool {
    normalized_path == ".claude/settings.json" || normalized_path == "claude/settings.json"
}

pub(crate) fn contains_semantic_tool_descriptor_json(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(is_tool_descriptor_shape)
}

pub(crate) fn contains_semantic_docker_mcp_launch(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(|candidate| {
        let Some(object) = candidate.as_object() else {
            return false;
        };
        let Some(command) = object.get("command").and_then(Value::as_str) else {
            return false;
        };
        if !command.eq_ignore_ascii_case("docker") {
            return false;
        }
        object
            .get("args")
            .and_then(Value::as_array)
            .and_then(|args| args.first())
            .and_then(Value::as_str)
            .is_some_and(|arg| arg.eq_ignore_ascii_case("run"))
    })
}

pub(crate) fn contains_semantic_gemini_mcp_config(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("mcpServers")
        .and_then(Value::as_object)
        .is_some_and(|servers| {
            servers.values().any(|server| {
                server
                    .as_object()
                    .and_then(|entry| entry.get("command"))
                    .and_then(Value::as_str)
                    .is_some()
            })
        })
}

pub(crate) fn contains_semantic_server_json(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("name").and_then(Value::as_str).is_some()
        && object.get("version").and_then(Value::as_str).is_some()
        && (object.get("remotes").and_then(Value::as_array).is_some()
            || object.get("packages").and_then(Value::as_array).is_some())
}

pub(crate) fn contains_semantic_claude_command_settings(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(|candidate| {
        let Some(object) = candidate.as_object() else {
            return false;
        };
        let Some(kind) = object.get("type").and_then(Value::as_str) else {
            return false;
        };
        kind.eq_ignore_ascii_case("command")
            && object.get("command").and_then(Value::as_str).is_some()
    })
}

pub(crate) fn contains_semantic_plugin_hook_commands(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(|hooks| {
            hooks.values().any(|entries| {
                entries.as_array().is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry
                            .as_object()
                            .and_then(|entry| entry.get("command"))
                            .and_then(Value::as_str)
                            .is_some()
                    })
                })
            })
        })
}

pub(crate) fn admitted_plugin_execution_targets(
    repo_root: &Path,
    manifest_relative: &Path,
    text: &str,
) -> Result<Vec<String>, String> {
    let mut admitted = Vec::new();
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Ok(admitted);
    };
    let Some(object) = value.as_object() else {
        return Ok(admitted);
    };
    let Some(dot_cursor_plugin_dir) = manifest_relative.parent() else {
        return Ok(admitted);
    };
    let Some(plugin_root_relative) = dot_cursor_plugin_dir.parent() else {
        return Ok(admitted);
    };
    let plugin_root_fs = repo_root.join(plugin_root_relative);

    for key in ["hooks", "agents", "commands"] {
        let Some(target_value) = object.get(key) else {
            continue;
        };
        for target in manifest_target_strings(target_value) {
            let resolved = plugin_root_fs.join(&target);
            if key == "commands" && has_glob_metacharacters(&target) {
                let normalized_pattern =
                    normalize_rel_path(resolved.strip_prefix(repo_root).unwrap_or(&resolved));
                if !is_repo_local_validation_path(&normalized_pattern) {
                    continue;
                }
                let Ok(glob) = globset::Glob::new(&normalized_pattern) else {
                    continue;
                };
                let matcher = glob.compile_matcher();
                let mut builder = WalkBuilder::new(repo_root);
                builder
                    .hidden(false)
                    .git_ignore(false)
                    .git_exclude(false)
                    .parents(false);
                for result in builder.build() {
                    let entry = result.map_err(|error| {
                        format!(
                            "plugin command glob walk failed for {}: {error}",
                            repo_root.display()
                        )
                    })?;
                    if !entry
                        .file_type()
                        .is_some_and(|file_type| file_type.is_file())
                    {
                        continue;
                    }
                    let normalized =
                        normalize_rel_path(entry.path().strip_prefix(repo_root).map_err(
                            |error| format!("failed to relativize plugin command target: {error}"),
                        )?);
                    if normalized.ends_with(".md")
                        && matcher.is_match(normalized.as_str())
                        && !is_generic_validation_excluded_path(&normalized)
                    {
                        admitted.push(normalized);
                    }
                }
                continue;
            }

            if !resolved.exists() {
                continue;
            }
            if resolved.is_file() {
                let normalized = normalize_rel_path(
                    resolved
                        .strip_prefix(repo_root)
                        .map_err(|error| format!("failed to relativize plugin target: {error}"))?,
                );
                if is_generic_validation_excluded_path(&normalized) {
                    continue;
                }
                match key {
                    "hooks" => {
                        let file_text = fs::read_to_string(&resolved).map_err(|error| {
                            format!(
                                "failed to read plugin execution target {}: {error}",
                                resolved.display()
                            )
                        })?;
                        if contains_semantic_plugin_hook_commands(&file_text) {
                            admitted.push(normalized);
                        }
                    }
                    "commands" => {
                        if normalized.ends_with(".md") {
                            admitted.push(normalized);
                        }
                    }
                    _ => {}
                }
                continue;
            }
            if resolved.is_dir() && matches!(key, "agents" | "commands") {
                let mut builder = WalkBuilder::new(&resolved);
                builder
                    .hidden(false)
                    .git_ignore(false)
                    .git_exclude(false)
                    .parents(false);
                for result in builder.build() {
                    let entry = result.map_err(|error| {
                        format!(
                            "plugin target walk failed for {}: {error}",
                            resolved.display()
                        )
                    })?;
                    if !entry
                        .file_type()
                        .is_some_and(|file_type| file_type.is_file())
                    {
                        continue;
                    }
                    if entry.path().extension().and_then(|ext| ext.to_str()) != Some("md") {
                        continue;
                    }
                    let normalized =
                        normalize_rel_path(entry.path().strip_prefix(repo_root).map_err(
                            |error| format!("failed to relativize plugin markdown target: {error}"),
                        )?);
                    if !is_generic_validation_excluded_path(&normalized) {
                        admitted.push(normalized);
                    }
                }
            }
        }
    }

    admitted.sort();
    admitted.dedup();
    Ok(admitted)
}

pub(crate) fn manifest_target_strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn has_glob_metacharacters(target: &str) -> bool {
    target.contains('*') || target.contains('?') || target.contains('[')
}

pub(crate) fn is_repo_local_validation_path(path: &str) -> bool {
    !path.starts_with('/') && !path.starts_with("../") && path != ".."
}

pub(crate) fn contains_semantic_github_workflow_yaml(text: &str) -> bool {
    let Ok(value) = serde_yaml_bw::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("jobs").and_then(Value::as_object).is_some()
        && (object.contains_key("on")
            || object.contains_key("permissions")
            || object.values().any(value_contains_workflow_steps))
}

pub(crate) fn value_contains_workflow_steps(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(value_contains_workflow_steps),
        Value::Object(object) => {
            object.contains_key("uses")
                || object.contains_key("run")
                || object.values().any(value_contains_workflow_steps)
        }
        _ => false,
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

pub(crate) fn is_tool_descriptor_shape(value: &Value) -> bool {
    let Value::Object(map) = value else {
        return false;
    };
    let has_name = map.get("name").is_some_and(Value::is_string);
    let has_tool_schema = map.contains_key("inputSchema")
        || map.contains_key("input_schema")
        || map.contains_key("parameters");
    let has_function_parameters = map
        .get("function")
        .and_then(Value::as_object)
        .is_some_and(|function| function.get("parameters").is_some());
    has_name && (has_tool_schema || has_function_parameters)
}
