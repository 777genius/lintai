use std::path::{Path, PathBuf};

use super::{
    CaseManifest, HarnessError, HarnessOutputFormat, OutputHarness, SnapshotExpectation,
    SnapshotKind, WorkspaceHarness, assert_case_summary, discover_case_dirs, repo_root,
    unique_temp_dir,
};
use lintai_api::{Category, Confidence, Finding, Location, RuleMetadata, RuleTier, Severity, Span};
use lintai_engine::{RuntimeErrorKind, ScanRuntimeError};

#[test]
fn parses_valid_case_manifest() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "skill-clean-basic"
kind = "benign"
entry_path = "repo"
expected_output = ["text", "json", "sarif"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();

    assert_eq!(manifest.id, "skill-clean-basic");
    assert_eq!(manifest.entry_path, std::path::PathBuf::from("repo"));
    assert_eq!(
        manifest.expected_output,
        vec![
            HarnessOutputFormat::Text,
            HarnessOutputFormat::Json,
            HarnessOutputFormat::Sarif,
        ]
    );
    assert!(manifest.expected_runtime_error_kinds.is_empty());
    assert_eq!(manifest.snapshot.kind, SnapshotKind::None);
}

#[test]
fn rejects_manifest_missing_id() {
    let error = CaseManifest::from_toml(
        r#"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("id"));
}

#[test]
fn rejects_manifest_with_invalid_kind() {
    let error = CaseManifest::from_toml(
        r#"
id = "bad-kind"
kind = "unknown"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("kind"));
}

#[test]
fn load_rejects_legacy_bucket_scoped_manifest_shapes() {
    let bucket_root = unique_temp_dir("lintai-legacy-case-manifest-reject");
    let case_dir = bucket_root
        .join("malicious")
        .join("skill-pip-http-git-install");
    std::fs::create_dir_all(case_dir.join("repo")).unwrap();
    std::fs::write(
        case_dir.join("case.toml"),
        r#"
id = "skill-pip-http-git-install"
kind = "Skill"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 1
expected_findings = [
  { rule_code = "SEC455", min_evidence_count = 1, tier = "stable" },
]
expected_absent_rules = []
snapshot = { kind = "none", name = "" }
"#,
    )
    .unwrap();

    let error = CaseManifest::load(&case_dir).unwrap_err();
    assert!(
        error.to_string().contains("failed to parse case manifest"),
        "strict canonical loader should reject legacy shorthand manifests: {error}"
    );
}

#[test]
fn rejects_manifest_with_invalid_snapshot_kind() {
    CaseManifest::from_toml(
        r#"
id = "bad-snapshot"
kind = "compat"
entry_path = "repo"
expected_output = ["json"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "xml"
name = "report"
"#,
    )
    .unwrap_err();
}

#[test]
fn parses_manifest_with_stable_key_snapshot_kind() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "stable-key-shape"
kind = "compat"
entry_path = "repo"
expected_output = ["json"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "stable-key"
name = "stable-key-shape"
"#,
    )
    .unwrap();

    assert_eq!(manifest.snapshot.kind, SnapshotKind::StableKey);
}

#[test]
fn rejects_manifest_with_invalid_runtime_error_kind() {
    let error = CaseManifest::from_toml(
        r#"
id = "bad-runtime-kind"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 1
expected_runtime_error_kinds = ["explode"]
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("expected_runtime_error_kinds"));
}

#[test]
fn top_level_iteration_one_directories_exist() {
    let root = repo_root();

    for relative in [
        "corpus/benign",
        "corpus/malicious",
        "corpus/edge",
        "corpus/compat",
        "sample-repos/clean",
        "sample-repos/mcp-heavy",
        "sample-repos/cursor-plugin",
        "sample-repos/fixable-comments",
        "sample-repos/policy-mismatch",
        "tests/integration",
        ".github/workflows",
    ] {
        assert!(
            root.join(relative).is_dir(),
            "expected {} to exist",
            root.join(relative).display()
        );
    }
}

#[test]
fn discover_case_dirs_returns_sorted_case_roots() {
    let benign_root = repo_root().join("corpus/benign");
    let cases = discover_case_dirs(&benign_root).unwrap();
    let names = cases
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();

    let mut sorted_names = names.clone();
    sorted_names.sort();
    assert_eq!(
        names, sorted_names,
        "discover_case_dirs should return sorted case roots"
    );

    for required in [
        "cursor-plugin-clean-basic",
        "mcp-safe-basic",
        "mixed-clean-workspace",
        "policy-truthful-basic",
        "skill-clean-basic",
        "tool-json-openai-strict-locked",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "expected benign corpus to contain representative case {required}"
        );
    }

    assert!(
        names.len() >= 10,
        "expected benign corpus to contain a non-trivial checked-in case set"
    );
}

#[test]
fn checked_in_case_manifests_are_canonical() {
    let case_dirs = super::checked_in_case_dirs().unwrap();
    assert!(
        !case_dirs.is_empty(),
        "expected checked-in corpus/sample repos to contain manifests"
    );

    for case_dir in case_dirs {
        let manifest_path = case_dir.join("case.toml");
        CaseManifest::load(&case_dir).unwrap_or_else(|error| {
            panic!(
                "checked-in manifest {} must stay canonical: {error}",
                manifest_path.display()
            )
        });
    }
}

#[test]
fn placeholder_cases_are_discoverable() {
    let root = repo_root();
    let harness = WorkspaceHarness::builder().build();

    for relative in [
        "corpus/benign/skill-clean-basic",
        "corpus/malicious/hook-download-exec",
        "corpus/edge/bom-frontmatter-skill",
        "corpus/compat/json-report-shape",
        "sample-repos/clean",
        "sample-repos/mcp-heavy",
        "sample-repos/fixable-comments",
        "sample-repos/cursor-plugin",
        "sample-repos/policy-mismatch",
    ] {
        let case_dir = root.join(relative);
        let manifest = harness.load_manifest(&case_dir).unwrap();
        assert!(
            manifest.entry_root(&case_dir).exists(),
            "expected entry root {} to exist",
            manifest.entry_root(&case_dir).display()
        );
    }
}

#[test]
fn scan_case_reports_invalid_case_root() {
    let temp_dir = unique_temp_dir("lintai-invalid-case");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(
        temp_dir.join("case.toml"),
        r#"
id = "invalid-root"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();

    let error = WorkspaceHarness::builder()
        .build()
        .scan_case(&temp_dir)
        .unwrap_err();
    assert!(matches!(error, HarnessError::InvalidCaseRoot { .. }));
}

#[test]
fn scan_case_uses_real_workspace_config_path() {
    let temp_dir = unique_temp_dir("lintai-configured-case");
    std::fs::create_dir_all(temp_dir.join("repo/docs")).unwrap();
    std::fs::write(
        temp_dir.join("case.toml"),
        r#"
id = "configured-case"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();
    std::fs::write(
        temp_dir.join("repo/lintai.toml"),
        "[files]\ninclude = [\"docs/**/*.md\"]\n",
    )
    .unwrap();
    std::fs::write(temp_dir.join("repo/docs/SKILL.md"), "# Configured\n").unwrap();

    let summary = WorkspaceHarness::builder()
        .build()
        .scan_case(&temp_dir)
        .unwrap();
    assert_eq!(summary.scanned_files, 1);
    assert!(summary.findings.is_empty());
}

#[test]
fn assert_case_summary_accepts_expected_empty_summary() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "empty"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = ["SEC101"]

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();

    assert_case_summary(&manifest, &lintai_engine::ScanSummary::default());
}

#[test]
fn snapshot_path_uses_expected_extensions() {
    let case_dir = Path::new("/tmp/case");

    let json = OutputHarness::snapshot_path(
        case_dir,
        &SnapshotExpectation {
            kind: SnapshotKind::Json,
            name: "report".to_owned(),
        },
    )
    .unwrap();
    let sarif = OutputHarness::snapshot_path(
        case_dir,
        &SnapshotExpectation {
            kind: SnapshotKind::Sarif,
            name: "report".to_owned(),
        },
    )
    .unwrap();
    let explain = OutputHarness::snapshot_path(
        case_dir,
        &SnapshotExpectation {
            kind: SnapshotKind::ExplainConfig,
            name: "report".to_owned(),
        },
    )
    .unwrap();
    let stable_key = OutputHarness::snapshot_path(
        case_dir,
        &SnapshotExpectation {
            kind: SnapshotKind::StableKey,
            name: "report".to_owned(),
        },
    )
    .unwrap();

    assert_eq!(json, PathBuf::from("/tmp/case/snapshots/report.json"));
    assert_eq!(
        sarif,
        PathBuf::from("/tmp/case/snapshots/report.sarif.json")
    );
    assert_eq!(explain, PathBuf::from("/tmp/case/snapshots/report.txt"));
    assert_eq!(stable_key, PathBuf::from("/tmp/case/snapshots/report.txt"));
}

#[test]
fn assert_snapshot_passes_on_exact_match() {
    let temp_dir = unique_temp_dir("lintai-snapshot-match");
    std::fs::create_dir_all(temp_dir.join("snapshots")).unwrap();
    std::fs::write(
        temp_dir.join("snapshots/report.json"),
        "{\n  \"ok\": true\n}\n",
    )
    .unwrap();

    OutputHarness::assert_snapshot(
        &temp_dir,
        &SnapshotExpectation {
            kind: SnapshotKind::Json,
            name: "report".to_owned(),
        },
        "{\n  \"ok\": true\n}\n",
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "snapshot mismatch")]
fn assert_snapshot_rejects_drift() {
    let temp_dir = unique_temp_dir("lintai-snapshot-drift");
    std::fs::create_dir_all(temp_dir.join("snapshots")).unwrap();
    std::fs::write(temp_dir.join("snapshots/report.txt"), "expected\n").unwrap();

    OutputHarness::assert_snapshot(
        &temp_dir,
        &SnapshotExpectation {
            kind: SnapshotKind::ExplainConfig,
            name: "report".to_owned(),
        },
        "actual\n",
    )
    .unwrap();
}

#[test]
fn stable_keys_text_is_deterministic_and_ordered() {
    let meta = RuleMetadata::new(
        "SEC900",
        "demo",
        Category::Security,
        Severity::Warn,
        Confidence::High,
        RuleTier::Stable,
    );
    let first = Finding::new(&meta, Location::new("a.md", Span::new(0, 1)), "first");
    let second = Finding::new(&meta, Location::new("b.md", Span::new(1, 2)), "second");
    let summary = lintai_engine::ScanSummary {
        findings: vec![first, second],
        ..lintai_engine::ScanSummary::default()
    };

    assert_eq!(
        OutputHarness::stable_keys_text(&summary),
        "SEC900:a.md:0:1:\nSEC900:b.md:1:2:\n"
    );
}

#[test]
fn assert_case_summary_accepts_expected_parse_runtime_error() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "parse-error"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 1
expected_runtime_error_kinds = ["parse"]
expected_diagnostics = 0
expected_scanned_files = 0
expected_skipped_files = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();
    let mut summary = lintai_engine::ScanSummary::default();
    summary.runtime_errors.push(ScanRuntimeError {
        normalized_path: "docs/SKILL.md".to_owned(),
        kind: RuntimeErrorKind::Parse,
        provider_id: None,
        phase: None,
        message: "unterminated frontmatter".to_owned(),
    });

    assert_case_summary(&manifest, &summary);
}

#[test]
#[should_panic(expected = "expected rule `SEC101` to stay absent")]
fn assert_case_summary_rejects_unexpected_present_rule() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "present-rule"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = ["SEC101"]

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();

    let finding = lintai_api::Finding::new(
        &lintai_api::RuleMetadata::new(
            "SEC101",
            "demo",
            lintai_api::Category::Security,
            lintai_api::Severity::Warn,
            lintai_api::Confidence::High,
            RuleTier::Stable,
        ),
        lintai_api::Location::new("docs/SKILL.md", lintai_api::Span::new(0, 1)),
        "demo",
    );
    let mut summary = lintai_engine::ScanSummary::default();
    summary.findings.push(finding);

    assert_case_summary(&manifest, &summary);
}

#[test]
#[should_panic(expected = "runtime error count mismatch")]
fn assert_case_summary_rejects_runtime_error_mismatch() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "runtime-errors"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();

    let mut summary = lintai_engine::ScanSummary::default();
    summary
        .runtime_errors
        .push(lintai_engine::ScanRuntimeError {
            normalized_path: "docs/SKILL.md".to_owned(),
            kind: lintai_engine::RuntimeErrorKind::Read,
            provider_id: None,
            phase: None,
            message: "boom".to_owned(),
        });

    assert_case_summary(&manifest, &summary);
}

#[test]
#[should_panic(expected = "diagnostics count mismatch")]
fn assert_case_summary_rejects_diagnostics_mismatch() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "diagnostics"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();

    let mut summary = lintai_engine::ScanSummary::default();
    summary.diagnostics.push(lintai_engine::ScanDiagnostic {
        normalized_path: "docs/SKILL.md".to_owned(),
        severity: lintai_engine::DiagnosticSeverity::Warn,
        code: Some("demo".to_owned()),
        message: "boom".to_owned(),
    });

    assert_case_summary(&manifest, &summary);
}

#[test]
#[should_panic(expected = "runtime error kind mismatch")]
fn assert_case_summary_rejects_wrong_runtime_error_kind() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "wrong-runtime-kind"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 1
expected_runtime_error_kinds = ["parse"]
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();
    let mut summary = lintai_engine::ScanSummary::default();
    summary.runtime_errors.push(ScanRuntimeError {
        normalized_path: "docs/SKILL.md".to_owned(),
        kind: RuntimeErrorKind::Read,
        provider_id: None,
        phase: None,
        message: "io".to_owned(),
    });

    assert_case_summary(&manifest, &summary);
}

#[test]
#[should_panic(expected = "scanned file count mismatch")]
fn assert_case_summary_rejects_wrong_scanned_file_count() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "wrong-scanned"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_scanned_files = 1
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();

    assert_case_summary(&manifest, &lintai_engine::ScanSummary::default());
}

#[test]
#[should_panic(expected = "skipped file count mismatch")]
fn assert_case_summary_rejects_wrong_skipped_file_count() {
    let manifest = CaseManifest::from_toml(
        r#"
id = "wrong-skipped"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_skipped_files = 1
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();

    assert_case_summary(&manifest, &lintai_engine::ScanSummary::default());
}
