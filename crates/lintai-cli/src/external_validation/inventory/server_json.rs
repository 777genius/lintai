use super::super::*;
use super::common::is_generic_validation_excluded_path;

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
