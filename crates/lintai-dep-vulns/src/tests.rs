use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_engine::{Engine, EngineBuilder, load_workspace_config};
use lintai_runtime::InProcessWorkspaceProviderBackend;
use lintai_testing::{WorkspaceHarness, assert_case_summary, discover_case_dirs};

use crate::provider::DependencyVulnProvider;

#[test]
fn finds_vulnerable_package_lock_dependency() {
    let summary = run_workspace_scan(
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/lodash": { "version": "4.17.20" }
          }
        }"#,
    );

    assert_eq!(summary.findings.len(), 1);
    assert_eq!(summary.findings[0].rule_code, "SEC756");
    assert!(summary.findings[0].message.contains("lodash"));
}

#[test]
fn ignores_fixed_package_lock_dependency() {
    let summary = run_workspace_scan(
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/lodash": { "version": "4.17.21" }
          }
        }"#,
    );

    assert!(summary.findings.is_empty());
}

#[test]
fn finds_vulnerable_pnpm_dependency() {
    let summary = run_workspace_scan(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.20:\n    resolution: {integrity: sha512-demo}\n",
    );

    assert_eq!(summary.findings.len(), 1);
    assert!(summary.findings[0].message.contains("lodash"));
}

#[test]
fn finds_vulnerable_npm_shrinkwrap_dependency() {
    let summary = run_workspace_scan(
        "npm-shrinkwrap.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 2,
          "dependencies": {
            "minimist": { "version": "1.2.5" }
          }
        }"#,
    );

    assert_eq!(summary.findings.len(), 1);
    assert!(summary.findings[0].message.contains("minimist"));
}

#[test]
fn deduplicates_across_multiple_lockfiles_and_keeps_all_paths() {
    let summary = run_workspace_scan_many(&[
        (
            "package-lock.json",
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "demo", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.20" }
              }
            }"#,
        ),
        (
            "pnpm-lock.yaml",
            r#"lockfileVersion: '9.0'
packages:
  lodash@4.17.20:
    resolution: {integrity: sha512-demo}
"#,
        ),
    ]);

    assert_eq!(summary.findings.len(), 1);
    let finding = &summary.findings[0];
    assert_eq!(finding.evidence.len(), 3);
    let metadata = finding.metadata.as_ref().unwrap();
    let paths = metadata["affected_paths"].as_array().unwrap();
    assert_eq!(paths.len(), 2);
    assert!(
        paths.iter().any(|path| path == "package-lock.json")
            && paths.iter().any(|path| path == "pnpm-lock.yaml")
    );
}

#[test]
fn finding_metadata_includes_fixed_versions_and_snapshot_provenance() {
    let summary = run_workspace_scan(
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/lodash": { "version": "4.17.20" }
          }
        }"#,
    );

    let finding = &summary.findings[0];
    let metadata = finding.metadata.as_ref().unwrap();
    assert_eq!(metadata["fixed_versions"][0], "4.17.21");
    assert_eq!(metadata["snapshot_source"], "bundled-curated-snapshot");
    assert_eq!(metadata["snapshot_revision"], "npm-advisories.v1");
    assert_eq!(metadata["affected_paths"][0], "package-lock.json");
}

#[test]
fn invalid_semver_for_advisory_tracked_package_fails_closed() {
    let summary = run_workspace_scan_many_allowing_runtime_errors(&[(
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/lodash": { "version": "not-a-semver" }
          }
        }"#,
    )]);

    assert!(summary.findings.is_empty());
    assert_eq!(summary.runtime_errors.len(), 1);
    assert!(
        summary.runtime_errors[0]
            .message
            .contains("installed version `not-a-semver` is not valid semver")
    );
}

#[test]
fn missing_version_for_advisory_tracked_package_fails_closed() {
    let summary = run_workspace_scan_many_allowing_runtime_errors(&[(
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/lodash": { "version": "" }
          }
        }"#,
    )]);

    assert!(summary.findings.is_empty());
    assert_eq!(summary.runtime_errors.len(), 1);
    assert!(
        summary.runtime_errors[0]
            .message
            .contains("missing a valid installed version")
    );
}

#[test]
fn malformed_pnpm_key_for_advisory_tracked_package_fails_closed() {
    let summary = run_workspace_scan_many_allowing_runtime_errors(&[(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages:\n  lodash@:\n    resolution: {integrity: sha512-demo}\n",
    )]);

    assert!(summary.findings.is_empty());
    assert_eq!(summary.runtime_errors.len(), 1);
    assert!(
        summary.runtime_errors[0]
            .message
            .contains("missing a valid installed version")
    );
}

#[test]
fn invalid_semver_for_non_tracked_package_does_not_fail_scan() {
    let summary = run_workspace_scan(
        "package-lock.json",
        r#"{
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/local-demo": { "version": "workspace:*" }
          }
        }"#,
    );

    assert!(summary.findings.is_empty());
}

#[test]
fn dep_vuln_corpus_malicious_cases_trigger_expected_findings() {
    for case_dir in discover_case_dirs(&corpus_root("malicious")).unwrap() {
        let manifest = lintai_testing::CaseManifest::load(&case_dir).unwrap();
        let summary = harness().scan_case(&case_dir).unwrap();
        assert_case_summary(&manifest, &summary);
    }
}

#[test]
fn dep_vuln_corpus_benign_cases_scan_cleanly() {
    for case_dir in discover_case_dirs(&corpus_root("benign")).unwrap() {
        let manifest = lintai_testing::CaseManifest::load(&case_dir).unwrap();
        let summary = harness().scan_case(&case_dir).unwrap();
        assert_case_summary(&manifest, &summary);
    }
}

fn run_workspace_scan(entry_name: &str, contents: &str) -> lintai_engine::ScanSummary {
    run_workspace_scan_many(&[(entry_name, contents)])
}

fn run_workspace_scan_many(entries: &[(&str, &str)]) -> lintai_engine::ScanSummary {
    let summary = run_workspace_scan_many_allowing_runtime_errors(entries);
    assert!(summary.runtime_errors.is_empty());
    summary
}

fn run_workspace_scan_many_allowing_runtime_errors(
    entries: &[(&str, &str)],
) -> lintai_engine::ScanSummary {
    let root = unique_temp_dir("lintai-dep-vulns");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("lintai.toml"),
        "[presets]\nenable = [\"advisory\"]\n",
    )
    .unwrap();
    for (entry_name, contents) in entries {
        let path = root.join(entry_name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    let workspace = load_workspace_config(&root).unwrap();
    let engine: Engine = EngineBuilder::default()
        .with_config(workspace.engine_config)
        .with_backend(Arc::new(InProcessWorkspaceProviderBackend::new(Arc::new(
            DependencyVulnProvider,
        ))))
        .build();
    engine.scan_path(&root).unwrap()
}

fn corpus_root(bucket: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(bucket)
}

fn harness() -> WorkspaceHarness {
    WorkspaceHarness::builder()
        .with_backend(Arc::new(InProcessWorkspaceProviderBackend::new(Arc::new(
            DependencyVulnProvider,
        ))))
        .build()
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
