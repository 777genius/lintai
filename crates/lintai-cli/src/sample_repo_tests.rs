use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use lintai_api::EvidenceKind;
use lintai_engine::{WorkspaceConfig, explain_file_config, load_workspace_config};
use lintai_testing::{
    CaseManifest, OutputHarness, WorkspaceHarness, assert_case_summary, discover_case_dirs,
};

use crate::builtin_providers::product_provider_set;
use crate::commands::explain_config::format_explain_config;
use crate::output::{build_envelope, format_json, format_sarif, format_text};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-cli")
}

fn sample_repos_root() -> PathBuf {
    repo_root().join("sample-repos")
}

fn sample_repo(name: &str) -> PathBuf {
    sample_repos_root().join(name)
}

fn load_case(case_dir: &Path) -> CaseManifest {
    CaseManifest::load(case_dir).expect("sample repo manifest should load")
}

fn harness() -> WorkspaceHarness {
    WorkspaceHarness::builder()
        .with_backends(product_provider_set())
        .build()
}

fn load_workspace(entry_root: &Path) -> WorkspaceConfig {
    load_workspace_config(entry_root).expect("sample repo workspace config should load")
}

fn build_real_report<'a>(
    summary: &'a lintai_engine::ScanSummary,
    workspace: &WorkspaceConfig,
) -> crate::output::ReportEnvelope<'a> {
    build_envelope(
        summary,
        workspace.source_path.as_deref(),
        workspace.engine_config.project_root.as_deref(),
    )
}

fn sample_repo_rule_codes(summary: &lintai_engine::ScanSummary) -> BTreeSet<&str> {
    summary
        .findings
        .iter()
        .map(|finding| finding.rule_code.as_str())
        .collect()
}

#[test]
fn sample_repo_dirs_are_discoverable() {
    let cases = discover_case_dirs(&sample_repos_root()).unwrap();
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
            "clean",
            "cursor-plugin",
            "fixable-comments",
            "mcp-heavy",
            "policy-mismatch"
        ]
    );
}

#[test]
fn sample_repo_manifests_match_real_scans() {
    let harness = harness();

    for case_dir in discover_case_dirs(&sample_repos_root()).unwrap() {
        let manifest = load_case(&case_dir);
        let summary = harness
            .scan_case(&case_dir)
            .unwrap_or_else(|error| panic!("sample repo {} failed to scan: {error}", manifest.id));
        assert_case_summary(&manifest, &summary);
    }
}

#[test]
fn sample_repos_render_all_real_output_formats() {
    let harness = harness();

    for case_dir in discover_case_dirs(&sample_repos_root()).unwrap() {
        let manifest = load_case(&case_dir);
        let entry_root = manifest.entry_root(&case_dir);
        let workspace = load_workspace(&entry_root);
        let summary = harness.scan_case(&case_dir).unwrap();
        let report = build_real_report(&summary, &workspace);

        let text = format_text(&report);
        assert!(
            text.starts_with("scanned "),
            "sample repo {} text output missing summary line: {text}",
            manifest.id
        );

        let json = format_json(&report).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(json_value["schema_version"], 1);
        assert_eq!(
            json_value["findings"].as_array().unwrap().len(),
            summary.findings.len()
        );
        assert_eq!(
            json_value["runtime_errors"].as_array().unwrap().len(),
            summary.runtime_errors.len()
        );

        let sarif = format_sarif(&report).unwrap();
        let sarif_value: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = sarif_value["runs"][0]["results"].as_array().unwrap();
        let rules = sarif_value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(results.len(), summary.findings.len());
        for result in results {
            assert!(result.get("ruleId").is_some());
            assert!(result["partialFingerprints"].get("stableKey").is_some());
        }
        if !summary.findings.is_empty() {
            assert!(
                rules.iter().any(|rule| rule.get("helpUri").is_some()),
                "sample repo {} sarif output should expose public docs links",
                manifest.id
            );
        }
    }
}

#[test]
fn sample_repos_are_deterministic_by_stable_key() {
    let harness = harness();

    for case_dir in discover_case_dirs(&sample_repos_root()).unwrap() {
        let first = harness.scan_case(&case_dir).unwrap();
        let second = harness.scan_case(&case_dir).unwrap();

        assert_eq!(
            OutputHarness::stable_keys_text(&first),
            OutputHarness::stable_keys_text(&second),
            "sample repo {} stable key output drifted between scans",
            case_dir.display()
        );
        assert_eq!(first.runtime_errors.len(), second.runtime_errors.len());
        assert_eq!(first.diagnostics.len(), second.diagnostics.len());
    }
}

#[test]
fn clean_sample_repo_stays_clean() {
    let case_dir = sample_repo("clean");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();
    let workspace = load_workspace(&manifest.entry_root(&case_dir));
    let report = build_real_report(&summary, &workspace);
    let text = format_text(&report);

    assert_case_summary(&manifest, &summary);
    assert!(summary.findings.is_empty());
    assert!(text.contains("found 0 finding(s)"));
}

#[test]
fn mcp_heavy_sample_repo_emits_mcp_rule_set() {
    let case_dir = sample_repo("mcp-heavy");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();
    let workspace = load_workspace(&manifest.entry_root(&case_dir));
    let report = build_real_report(&summary, &workspace);
    let text = format_text(&report);

    assert_case_summary(&manifest, &summary);
    assert_eq!(
        sample_repo_rule_codes(&summary),
        BTreeSet::from(["SEC301", "SEC302"])
    );
    for rule_code in ["SEC301", "SEC302"] {
        assert!(text.contains(rule_code));
        assert!(text.contains("  suggest:"));
        let finding = summary
            .findings
            .iter()
            .find(|finding| finding.rule_code == rule_code)
            .unwrap();
        assert!(!finding.suggestions.is_empty());
        match rule_code {
            "SEC302" => assert!(finding.suggestions[0].fix.is_some()),
            _ => assert!(finding.suggestions[0].fix.is_none()),
        }
    }
}

#[test]
fn fixable_comments_sample_repo_emits_fixable_comment_rules() {
    let case_dir = sample_repo("fixable-comments");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();
    let workspace = load_workspace(&manifest.entry_root(&case_dir));
    let report = build_real_report(&summary, &workspace);
    let text = format_text(&report);

    assert_case_summary(&manifest, &summary);
    assert_eq!(
        sample_repo_rule_codes(&summary),
        BTreeSet::from(["SEC101", "SEC103"])
    );
    assert!(
        text.contains("docs: https://777genius.github.io/lintai/rules/lintai-ai-security/sec101")
    );
    assert!(
        text.contains("docs: https://777genius.github.io/lintai/rules/lintai-ai-security/sec103")
    );
    for rule_code in ["SEC101", "SEC103"] {
        assert!(text.contains(rule_code));
        let finding = summary
            .findings
            .iter()
            .find(|finding| finding.rule_code == rule_code)
            .unwrap();
        assert!(finding.fix.is_some());
    }
}

#[test]
fn cursor_plugin_sample_repo_emits_plugin_rule_set() {
    let case_dir = sample_repo("cursor-plugin");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();
    let workspace = load_workspace(&manifest.entry_root(&case_dir));
    let report = build_real_report(&summary, &workspace);
    let text = format_text(&report);

    assert_case_summary(&manifest, &summary);
    assert_eq!(
        sample_repo_rule_codes(&summary),
        BTreeSet::from(["SEC201", "SEC202", "SEC203", "SEC205"])
    );
    assert!(
        text.contains("docs: https://777genius.github.io/lintai/rules/lintai-ai-security/sec202")
    );
    for rule_code in ["SEC201", "SEC202", "SEC203", "SEC205"] {
        assert!(text.contains(rule_code));
        assert!(text.contains("  suggest:"));
        let finding = summary
            .findings
            .iter()
            .find(|finding| finding.rule_code == rule_code)
            .unwrap();
        assert!(!finding.suggestions.is_empty());
        match rule_code {
            "SEC205" => assert!(finding.suggestions[0].fix.is_none()),
            _ => assert!(finding.suggestions[0].fix.is_some()),
        }
    }
}

#[test]
fn policy_mismatch_sample_repo_emits_preview_and_stable_findings() {
    let case_dir = sample_repo("policy-mismatch");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();
    let workspace = load_workspace(&manifest.entry_root(&case_dir));
    let report = build_real_report(&summary, &workspace);
    let text = format_text(&report);

    assert_case_summary(&manifest, &summary);
    assert_eq!(
        sample_repo_rule_codes(&summary),
        BTreeSet::from(["SEC401", "SEC402", "SEC403"])
    );
    assert!(
        text.contains(
            "docs: https://777genius.github.io/lintai/rules/lintai-policy-mismatch/sec401"
        )
    );

    for rule_code in ["SEC401", "SEC402", "SEC403"] {
        let finding = summary
            .findings
            .iter()
            .find(|finding| finding.rule_code == rule_code)
            .unwrap();
        assert!(
            finding
                .evidence
                .iter()
                .any(|evidence| matches!(evidence.kind, EvidenceKind::Claim))
        );
        assert!(
            finding
                .evidence
                .iter()
                .any(|evidence| matches!(evidence.kind, EvidenceKind::ObservedBehavior))
        );
    }
}

#[test]
fn policy_mismatch_explain_config_is_informative() {
    let case_dir = sample_repo("policy-mismatch");
    let manifest = load_case(&case_dir);
    let entry_root = manifest.entry_root(&case_dir);
    let workspace = load_workspace(&entry_root);
    let resolved = explain_file_config(&workspace, &entry_root.join("custom/agent.md"));
    let formatted = format_explain_config(workspace.source_path.as_deref(), &resolved);

    assert!(formatted.contains("normalized_path=custom/agent.md"));
    assert!(formatted.contains("detected_kind=Some(CursorPluginAgent)"));
    assert!(formatted.contains("detected_format=Some(Markdown)"));
    assert!(formatted.contains("enabled_presets=[\"base\", \"compat\"]"));
    assert!(formatted.contains("relevant_surface_presets=[\"skills\"]"));
    assert!(formatted.contains("active_rule_count="));
    assert!(formatted.contains("capability_conflict_mode=Deny"));
    assert!(formatted.contains("project_capabilities=Some("));
    assert!(formatted.contains("applied_overrides=[[\"custom/**/*.md\"]]"));
    assert!(formatted.contains("category_overrides={Security: Deny}"));
    assert!(formatted.contains("rule_overrides={\"SEC201\": Deny}"));
}
