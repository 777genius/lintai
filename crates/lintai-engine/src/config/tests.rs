use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::{ArtifactKind, Category, Severity};

use super::{DEFAULT_INCLUDE_PATTERNS, OutputFormat, explain_file_config, load_workspace_config};

#[test]
fn rejects_unknown_top_level_keys() {
    let temp_dir = unique_temp_dir("lintai-config-unknown");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(
        temp_dir.join("lintai.toml"),
        "[project]\nroot = true\n[unknown]\nvalue = 1\n",
    )
    .unwrap();

    let error = load_workspace_config(&temp_dir).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unknown top-level key `unknown`")
    );
}

#[test]
fn rejects_project_root_false() {
    let temp_dir = unique_temp_dir("lintai-config-root-false");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("lintai.toml"), "[project]\nroot = false\n").unwrap();

    let error = load_workspace_config(&temp_dir).unwrap_err();
    assert!(error.to_string().contains("project.root = false"));
}

#[test]
fn resolves_overrides_for_specific_file() {
    let temp_dir = unique_temp_dir("lintai-config-overrides");
    std::fs::create_dir_all(temp_dir.join("docs")).unwrap();
    std::fs::write(
        temp_dir.join("lintai.toml"),
        r#"
[files]
include = ["**/*.md"]

[categories]
security = "warn"

[rules]
SEC201 = "allow"

[[overrides]]
files = ["docs/**/*.md"]
categories = { security = "deny" }
rules = { SEC201 = "deny" }
"#,
    )
    .unwrap();

    let workspace = load_workspace_config(&temp_dir).unwrap();
    let resolved = explain_file_config(&workspace, &temp_dir.join("docs/SKILL.md"));

    assert!(resolved.included);
    assert_eq!(resolved.output_format, OutputFormat::Text);
    assert_eq!(
        resolved.category_overrides.get(&Category::Security),
        Some(&Severity::Deny)
    );
    assert_eq!(resolved.rule_overrides.get("SEC201"), Some(&Severity::Deny));
    assert_eq!(
        resolved.applied_overrides,
        vec![vec!["docs/**/*.md".to_owned()]]
    );
}

#[test]
fn does_not_cascade_to_parent_config() {
    let root_dir = unique_temp_dir("lintai-config-no-cascade");
    let child_dir = root_dir.join("nested");
    std::fs::create_dir_all(&child_dir).unwrap();
    std::fs::write(
        root_dir.join("lintai.toml"),
        "[files]\ninclude = [\"**/*.md\"]\n",
    )
    .unwrap();

    let workspace = load_workspace_config(&child_dir).unwrap();

    assert!(workspace.source_path.is_none());
    let expected = DEFAULT_INCLUDE_PATTERNS
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        workspace.engine_config.include_patterns(),
        expected.as_slice()
    );
}

#[test]
fn explain_config_reports_detection_override_and_capabilities() {
    let temp_dir = unique_temp_dir("lintai-config-detection");
    std::fs::create_dir_all(temp_dir.join("custom")).unwrap();
    std::fs::write(
        temp_dir.join("lintai.toml"),
        r#"
[capabilities]
network = "none"

[policy]
capability_conflicts = "deny"

[[detection.overrides]]
files = ["custom/**/*.md"]
kind = "cursor_plugin_agent"
format = "markdown"
"#,
    )
    .unwrap();
    std::fs::write(temp_dir.join("custom/agent.md"), "# custom\n").unwrap();

    let workspace = load_workspace_config(&temp_dir).unwrap();
    let resolved = explain_file_config(&workspace, &temp_dir.join("custom/agent.md"));

    assert_eq!(
        resolved
            .project_capabilities
            .as_ref()
            .and_then(|value| value.network),
        Some(lintai_api::NetworkCapability::None)
    );
    assert_eq!(
        resolved.capability_conflict_mode,
        lintai_api::CapabilityConflictMode::Deny
    );
    assert_eq!(
        resolved.detected_kind,
        Some(lintai_api::ArtifactKind::CursorPluginAgent)
    );
    assert_eq!(
        resolved.detected_format,
        Some(lintai_api::SourceFormat::Markdown)
    );
}

#[test]
fn add_detection_override_for_kind_uses_canonical_route() {
    let mut config = super::EngineConfig::default();
    let patterns = vec!["custom/**/*.md".to_owned()];

    config
        .add_detection_override_for_kind(&patterns, ArtifactKind::CursorPluginAgent)
        .unwrap();

    assert_eq!(config.detection_overrides.len(), 1);
    let override_spec = &config.detection_overrides[0];
    assert_eq!(override_spec.kind, ArtifactKind::CursorPluginAgent);
    assert_eq!(override_spec.format, lintai_api::SourceFormat::Markdown);
}

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{nanos}-{sequence}",
        std::process::id()
    ))
}
