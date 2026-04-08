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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_validation::normalize_rel_path;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_workspace_root() -> PathBuf {
        let unique_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_nanos())
            .unwrap_or(0);
        let workspace = env::temp_dir().join(format!(
            "lintai-github-actions-tests-{unique_id}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&workspace).unwrap();
        workspace
    }

    fn cleanup(workspace: &PathBuf) {
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn workflow_steps_recognizes_steps_in_nested_objects() {
        let value: Value = serde_yaml_bw::from_str(
            r#"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"#,
        )
        .unwrap();
        assert!(contains_semantic_github_workflow_yaml(&serde_yaml_bw::to_string(&value).unwrap()));
        assert!(value_contains_workflow_steps(&value));
    }

    #[test]
    fn workflow_steps_recognizes_array_containing_runs_step() {
        let value: Value = serde_yaml_bw::from_str("- {uses: echo}\n").unwrap();
        assert!(value_contains_workflow_steps(&value));
    }

    #[test]
    fn admitted_github_workflow_paths_collects_only_semantic_workflows() {
        let workspace_root = make_workspace_root();
        let repo_root = workspace_root.join("repo");
        let workflow_dir = repo_root.join(".github").join("workflows");
        fs::create_dir_all(&workflow_dir).unwrap();

        let semantic = workflow_dir.join("ci.yml");
        let non_semantic = workflow_dir.join("plain.yml");
        fs::write(
            semantic,
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        )
        .unwrap();
        fs::write(non_semantic, "name: example\nvalues:\n  - x\n").unwrap();

        let discovered = admitted_github_workflow_paths(&repo_root).unwrap();
        let expected = vec![normalize_rel_path(&PathBuf::from(".github/workflows/ci.yml"))];
        assert_eq!(discovered, expected);
        cleanup(&workspace_root);
    }

    #[test]
    fn admitted_github_workflow_paths_errors_when_no_admission() {
        let workspace_root = make_workspace_root();
        let repo_root = workspace_root.join("repo-empty");
        let workflow_dir = repo_root.join(".github").join("workflows");
        fs::create_dir_all(&workflow_dir).unwrap();
        fs::write(workflow_dir.join("plain.yml"), "name: demo\n").unwrap();

        let error = admitted_github_workflow_paths(&repo_root).unwrap_err();
        assert_eq!(
            error,
            "no semantically confirmed GitHub workflow paths passed admission".to_owned()
        );
        cleanup(&workspace_root);
    }
}
