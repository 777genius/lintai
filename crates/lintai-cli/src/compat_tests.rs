use lintai_engine::{explain_file_config, load_workspace_config};
use lintai_testing::{OutputHarness, WorkspaceHarness, discover_case_dirs};
use std::path::PathBuf;

use crate::builtin_providers::product_provider_set;
use crate::commands::explain_config::format_explain_config;
use crate::output::{build_envelope, format_json, format_sarif};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-cli")
}

fn compat_root() -> PathBuf {
    repo_root().join("corpus/compat")
}

fn compat_case(case_name: &str) -> PathBuf {
    compat_root().join(case_name)
}

fn harness() -> WorkspaceHarness {
    WorkspaceHarness::builder()
        .with_backends(product_provider_set())
        .build()
}

fn sanitize_explain_config(output: &str) -> String {
    output
        .lines()
        .map(|line| {
            if line.starts_with("config_source=") {
                "config_source=<case-root>/lintai.toml".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn compat_case_dirs_are_discoverable() {
    let cases = discover_case_dirs(&compat_root()).unwrap();
    let names = cases
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            "explain-config-detection",
            "json-report-shape",
            "sarif-report-shape",
            "stable-key-shape",
        ]
    );
}

#[test]
fn json_report_snapshot_matches() {
    let case_dir = compat_case("json-report-shape");
    let manifest = harness().load_manifest(&case_dir).unwrap();
    let summary = harness().scan_case(&case_dir).unwrap();
    let report = build_envelope(&summary, None, None);
    let actual = format_json(&report).unwrap() + "\n";

    OutputHarness::assert_snapshot(&case_dir, &manifest.snapshot, &actual).unwrap();
}

#[test]
fn sarif_report_snapshot_matches() {
    let case_dir = compat_case("sarif-report-shape");
    let manifest = harness().load_manifest(&case_dir).unwrap();
    let summary = harness().scan_case(&case_dir).unwrap();
    let report = build_envelope(&summary, None, None);
    let actual = format_sarif(&report).unwrap() + "\n";

    OutputHarness::assert_snapshot(&case_dir, &manifest.snapshot, &actual).unwrap();
}

#[test]
fn explain_config_snapshot_matches() {
    let case_dir = compat_case("explain-config-detection");
    let manifest = harness().load_manifest(&case_dir).unwrap();
    let entry_root = manifest.entry_root(&case_dir);
    let workspace = load_workspace_config(&entry_root).unwrap();
    let target = entry_root.join("custom/agent.md");
    let resolved = explain_file_config(&workspace, &target);
    let actual = sanitize_explain_config(&format_explain_config(
        workspace.source_path.as_deref(),
        &resolved,
    ));

    OutputHarness::assert_snapshot(&case_dir, &manifest.snapshot, &actual).unwrap();
}

#[test]
fn stable_key_snapshot_matches() {
    let case_dir = compat_case("stable-key-shape");
    let manifest = harness().load_manifest(&case_dir).unwrap();
    let summary = harness().scan_case(&case_dir).unwrap();
    let actual = OutputHarness::stable_keys_text(&summary);

    OutputHarness::assert_snapshot(&case_dir, &manifest.snapshot, &actual).unwrap();
}

#[test]
fn format_explain_config_preserves_current_line_order() {
    let temp_dir = repo_root().join("corpus/compat/explain-config-detection/repo");
    let workspace = load_workspace_config(&temp_dir).unwrap();
    let resolved = explain_file_config(&workspace, &temp_dir.join("custom/agent.md"));
    let formatted = format_explain_config(workspace.source_path.as_deref(), &resolved);

    let lines = formatted.lines().collect::<Vec<_>>();
    assert_eq!(
        lines[0],
        format!(
            "config_source={}",
            workspace.source_path.as_ref().unwrap().display()
        )
    );
    assert_eq!(lines[1], "normalized_path=custom/agent.md");
    assert!(lines[2].starts_with("included="));
    assert!(lines[3].starts_with("detected_kind="));
    assert!(lines[4].starts_with("detected_format="));
    assert!(lines[5].starts_with("output="));
}
