use super::super::*;
use super::common::{is_tool_json_excluded_path, json_descendants};

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

pub(crate) fn contains_semantic_tool_descriptor_json(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(is_tool_descriptor_shape)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_workspace_root() -> PathBuf {
        let unique_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "lintai-tool-json-inventory-tests-{unique_id}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn cleanup(path: &PathBuf) {
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn admits_tool_descriptor_with_semantic_shape() {
        let workspace = make_workspace_root();
        fs::write(
            workspace.join("tools.json"),
            r#"{"name":"x","inputSchema":{"type":"object"}}"#,
        )
        .unwrap();

        let discovered = admitted_tool_descriptor_paths(&workspace).unwrap();

        cleanup(&workspace);
        assert_eq!(discovered, vec!["tools.json".to_owned()]);
    }

    #[test]
    fn rejects_tool_descriptor_without_semantic_shape() {
        let workspace = make_workspace_root();
        fs::write(workspace.join("tools.json"), r#"{"not_name":"x"}"#).unwrap();
        let discovered = admitted_tool_descriptor_paths(&workspace).unwrap_err();
        cleanup(&workspace);
        assert_eq!(
            discovered,
            "no committed non-fixture ToolDescriptorJson paths passed semantic confirmation"
                .to_owned()
        );
    }

    #[test]
    fn contains_semantic_tool_descriptor_json_matches_object_variants() {
        assert!(contains_semantic_tool_descriptor_json(
            r#"{"name":"x","function":{"parameters":{"type":"object"}}}"#
        ));
        assert!(contains_semantic_tool_descriptor_json(
            r#"{"name":"x","input_schema":{"type":"object"}}"#
        ));
        assert!(!contains_semantic_tool_descriptor_json(r#"{"name":"x"}"#));
        assert!(!contains_semantic_tool_descriptor_json("not-json"));
    }

    #[test]
    fn is_tool_descriptor_shape_checks_nested_function_parameters() {
        let direct = serde_json::from_str::<Value>(
            r#"{"name":"x","function":{"parameters":{"type":"object"}}}"#,
        )
        .unwrap();
        let indirect =
            serde_json::from_str::<Value>(r#"{"name":"x","inputSchema":{"type":"object"}}"#)
                .unwrap();
        let missing = serde_json::from_str::<Value>(r#"{"name":"x","version":"1"}"#).unwrap();

        assert!(is_tool_descriptor_shape(&direct));
        assert!(is_tool_descriptor_shape(&indirect));
        assert!(!is_tool_descriptor_shape(&missing));
    }
}
