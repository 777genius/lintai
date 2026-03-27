use std::sync::Arc;

use lintai_engine::{EngineBuilder, RuntimeErrorKind};
use lintai_testing::{CaseManifest, assert_case_summary, discover_case_dirs};

use super::{corpus_root, harness, load_case, provider_set, unique_temp_dir};

#[test]
fn checked_in_edge_case_dirs_are_discoverable() {
    let cases = discover_case_dirs(&corpus_root("edge")).unwrap();
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
        vec!["bom-frontmatter-skill", "unterminated-frontmatter-skill"]
    );
}

#[test]
fn checked_in_edge_cases_match_expected_runtime_behavior() {
    let harness = harness();

    for case_dir in discover_case_dirs(&corpus_root("edge")).unwrap() {
        let manifest = load_case(&case_dir);
        let summary = harness
            .scan_case(&case_dir)
            .unwrap_or_else(|error| panic!("case {} failed to scan: {error}", manifest.id));
        assert_case_summary(&manifest, &summary);
    }
}

#[test]
fn generated_crlf_case_stays_clean() {
    let case_dir = unique_temp_dir("lintai-edge-crlf");
    std::fs::create_dir_all(case_dir.join("repo/docs")).unwrap();
    std::fs::write(
        case_dir.join("case.toml"),
        r#"
id = "generated-crlf"
kind = "edge"
entry_path = "repo"
expected_output = ["text", "json", "sarif"]
expected_runtime_errors = 0
expected_runtime_error_kinds = []
expected_diagnostics = 0
expected_scanned_files = 1
expected_skipped_files = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
    )
    .unwrap();
    std::fs::write(
        case_dir.join("repo/docs/SKILL.md"),
        b"---\r\nname: crlf-demo\r\n---\r\n# Title\r\n",
    )
    .unwrap();

    let manifest = CaseManifest::load(&case_dir).unwrap();
    let summary = harness().scan_case(&case_dir).unwrap();
    assert_case_summary(&manifest, &summary);
}

#[test]
fn generated_invalid_utf8_case_reports_invalid_utf8_runtime_error() {
    let case_dir = unique_temp_dir("lintai-edge-invalid-utf8");
    std::fs::create_dir_all(case_dir.join("repo")).unwrap();
    std::fs::write(
        case_dir.join("case.toml"),
        r#"
id = "generated-invalid-utf8"
kind = "edge"
entry_path = "repo"
expected_output = ["text", "json", "sarif"]
expected_runtime_errors = 1
expected_runtime_error_kinds = ["invalid_utf8"]
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
    std::fs::write(case_dir.join("repo/SKILL.md"), [0xFF, 0xFE, 0x23]).unwrap();

    let manifest = CaseManifest::load(&case_dir).unwrap();
    let summary = harness().scan_case(&case_dir).unwrap();
    assert_case_summary(&manifest, &summary);
    assert_eq!(
        summary.runtime_errors[0].kind,
        RuntimeErrorKind::InvalidUtf8
    );
}

#[cfg(any(unix, windows))]
#[test]
fn generated_symlink_escape_case_reports_outside_root_read_error() {
    let temp_dir = unique_temp_dir("lintai-edge-symlink");
    let outside_path = unique_temp_dir("lintai-edge-symlink-target").join("outside.md");
    std::fs::create_dir_all(temp_dir.join("docs")).unwrap();
    std::fs::create_dir_all(outside_path.parent().unwrap()).unwrap();
    std::fs::write(&outside_path, b"# outside\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_path, temp_dir.join("docs/SKILL.md")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&outside_path, temp_dir.join("docs/SKILL.md")).unwrap();

    let mut config = lintai_engine::EngineConfig::default();
    config.project_root = Some(temp_dir.clone());
    let mut builder = EngineBuilder::default().with_config(config);
    for backend in provider_set() {
        builder = builder.with_backend(Arc::clone(&backend));
    }

    let summary = builder
        .build()
        .scan_path(&temp_dir.join("docs/SKILL.md"))
        .unwrap();

    assert_eq!(summary.scanned_files, 0);
    assert_eq!(summary.runtime_errors.len(), 1);
    assert_eq!(summary.runtime_errors[0].kind, RuntimeErrorKind::Read);
    assert!(
        summary.runtime_errors[0]
            .message
            .contains("outside project root")
    );
}
