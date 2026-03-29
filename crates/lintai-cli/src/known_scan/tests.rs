use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_adapters::route_for_artifact_kind;
use lintai_api::{
    Category, Confidence, Evidence, EvidenceKind, Location, RuleTier, Severity, Span,
};
use lintai_engine::{
    ProviderExecutionMetric, ProviderExecutionPhase, RuntimeErrorKind, ScanDiagnostic,
    ScanRuntimeError,
};

use super::*;

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn manifest_requires_kind_hint_for_lintable_surface() {
    let error = registry_from_str(
        r#"
[[surface]]
client_id = "cursor"
surface_id = "skills"
scope = "project"
path_template = "{project_root}/.cursor/skills"
artifact_mode = "lintable"
"#,
    )
    .unwrap_err();
    assert!(error.contains("missing artifact_kind_hint"));
}

#[test]
fn manifest_rejects_duplicate_scope_path_pairs() {
    let error = registry_from_str(
        r#"
[[surface]]
client_id = "cursor"
surface_id = "skills"
scope = "project"
path_template = "{project_root}/.cursor/skills"
artifact_mode = "lintable"
artifact_kind_hint = "skill"

[[surface]]
client_id = "codex"
surface_id = "same"
scope = "project"
path_template = "{project_root}/.cursor/skills"
artifact_mode = "lintable"
artifact_kind_hint = "skill"
"#,
    )
    .unwrap_err();
    assert!(error.contains("duplicates scope/path"));
}

#[test]
fn lintable_known_root_hints_have_canonical_routes() {
    let registry = registry().unwrap();
    for surface in &registry.surfaces {
        if !matches!(surface.artifact_mode, ArtifactMode::Lintable) {
            continue;
        }
        let artifact_kind = surface
            .artifact_kind_hint
            .expect("lintable surface should declare artifact kind hint");
        assert!(
            route_for_artifact_kind(artifact_kind).is_some(),
            "missing canonical route for {:?} on {}:{}",
            artifact_kind,
            surface.client_id,
            surface.surface_id
        );
    }
}

#[test]
fn discover_known_roots_respects_scope_filters_and_existing_paths() {
    let temp_dir = unique_temp_dir("lintai-known-roots");
    let project_root = temp_dir.join("project");
    let home_dir = temp_dir.join("home");
    let xdg_dir = temp_dir.join("xdg");
    fs::create_dir_all(project_root.join(".agents/skills/demo")).unwrap();
    fs::create_dir_all(home_dir.join(".cursor/skills/demo")).unwrap();
    fs::create_dir_all(xdg_dir.join("opencode/skills/demo")).unwrap();

    let env = EnvironmentPaths {
        home_dir: Some(home_dir),
        xdg_config_home: Some(xdg_dir),
    };
    let filters = ["codex", "opencode"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let roots = discover_known_roots_with_env(
        Ok(registry().unwrap()),
        Some(&project_root),
        KnownScope::Both,
        &filters,
        &env,
    )
    .unwrap();

    assert_eq!(roots.len(), 2);
    assert!(
        roots
            .iter()
            .any(|root| root.client == "codex" && root.scope == KnownRootScope::Project)
    );
    assert!(
        roots
            .iter()
            .any(|root| root.client == "opencode" && root.scope == KnownRootScope::Global)
    );
}

#[test]
fn inventory_lintable_root_splits_unrecognized_binary_and_excluded_files() {
    let temp_dir = unique_temp_dir("lintai-known-root-inventory");
    fs::create_dir_all(temp_dir.join(".agents/skills/demo/scripts")).unwrap();
    fs::create_dir_all(temp_dir.join(".agents/skills/demo/assets")).unwrap();
    fs::write(temp_dir.join(".agents/skills/demo/SKILL.md"), "# Demo\n").unwrap();
    fs::write(
        temp_dir.join(".agents/skills/demo/scripts/helper.sh"),
        "#!/bin/sh\necho hi\n",
    )
    .unwrap();
    fs::write(
        temp_dir.join(".agents/skills/demo/assets/logo.png"),
        [0u8, 159, 146, 150],
    )
    .unwrap();
    fs::write(
        temp_dir.join(".agents/skills/demo/license.txt"),
        "license\n",
    )
    .unwrap();

    let root = KnownRoot {
        client: "codex".to_owned(),
        scope: KnownRootScope::Project,
        surface: "skills".to_owned(),
        path: temp_dir.join(".agents/skills"),
        mode: ArtifactMode::Lintable,
        artifact_kind_hint: Some(ArtifactKind::Skill),
        notes: None,
    };
    let workspace = WorkspaceConfig {
        source_path: None,
        engine_config: lintai_engine::EngineConfig::default(),
    };

    let inventory = inventory_lintable_root(&root, &workspace).unwrap();
    assert_eq!(inventory.unrecognized_files, 1);
    assert_eq!(inventory.binary_files, 0);
    assert_eq!(inventory.unreadable_files, 0);
    assert_eq!(inventory.excluded_files, 2);
}

#[test]
fn merge_summary_rewrites_paths_to_absolute_locations() {
    let base = PathBuf::from("/tmp/demo");
    let metadata = lintai_api::RuleMetadata::new(
        "SEC999",
        "demo",
        Category::Security,
        Severity::Warn,
        Confidence::High,
        RuleTier::Stable,
    );
    let mut finding = Finding::new(
        &metadata,
        Location::new("skills/demo/SKILL.md", Span::new(0, 4)),
        "demo finding",
    );
    finding.evidence.push(Evidence::new(
        EvidenceKind::ObservedBehavior,
        "evidence",
        Some(Location::new("skills/demo/SKILL.md", Span::new(0, 4))),
    ));
    finding.related.push(lintai_api::RelatedFinding::new(
        "SEC998",
        "skills/demo/SKILL.md",
        Span::new(1, 2),
    ));

    let summary = ScanSummary {
        scanned_files: 1,
        skipped_files: 0,
        findings: vec![finding],
        diagnostics: vec![ScanDiagnostic {
            normalized_path: "mcp.json".to_owned(),
            severity: lintai_engine::DiagnosticSeverity::Warn,
            code: Some("demo".to_owned()),
            message: "diag".to_owned(),
        }],
        runtime_errors: vec![ScanRuntimeError {
            normalized_path: "mcp.json".to_owned(),
            kind: RuntimeErrorKind::Read,
            provider_id: None,
            phase: None,
            message: "err".to_owned(),
        }],
        provider_metrics: vec![ProviderExecutionMetric {
            normalized_path: "mcp.json".to_owned(),
            provider_id: "provider".to_owned(),
            phase: ProviderExecutionPhase::File,
            elapsed_us: 10,
            findings_emitted: 1,
            errors_emitted: 0,
        }],
    };

    let mut aggregate = ScanSummary::default();
    merge_summary_with_absolute_paths(&mut aggregate, summary, &base);

    assert_eq!(
        aggregate.findings[0].location.normalized_path,
        "/tmp/demo/skills/demo/SKILL.md"
    );
    assert_eq!(
        aggregate.findings[0].stable_key.normalized_path,
        "/tmp/demo/skills/demo/SKILL.md"
    );
    assert_eq!(
        aggregate.findings[0].evidence[1]
            .location
            .as_ref()
            .unwrap()
            .normalized_path,
        "/tmp/demo/skills/demo/SKILL.md"
    );
    assert_eq!(
        aggregate.findings[0].related[0].normalized_path,
        "/tmp/demo/skills/demo/SKILL.md"
    );
    assert_eq!(
        aggregate.diagnostics[0].normalized_path,
        "/tmp/demo/mcp.json"
    );
    assert_eq!(
        aggregate.runtime_errors[0].normalized_path,
        "/tmp/demo/mcp.json"
    );
    assert_eq!(
        aggregate.provider_metrics[0].normalized_path,
        "/tmp/demo/mcp.json"
    );
}
