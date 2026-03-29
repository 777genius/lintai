use super::super::*;

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
