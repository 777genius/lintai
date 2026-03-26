use std::path::{Path, PathBuf};
use std::sync::Arc;

use lintai_api::RuleProvider;
use lintai_testing::{
    CaseManifest, WorkspaceHarness, assert_case_summary, discover_case_dirs,
};

use crate::{AiSecurityProvider, PolicyMismatchProvider};

fn benign_provider_set() -> Vec<Arc<dyn RuleProvider>> {
    vec![
        Arc::new(AiSecurityProvider::default()),
        Arc::new(PolicyMismatchProvider),
    ]
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-ai-security")
}

fn benign_root() -> PathBuf {
    repo_root().join("corpus/benign")
}

fn benign_case(case_name: &str) -> PathBuf {
    benign_root().join(case_name)
}

fn load_case(case_dir: &Path) -> CaseManifest {
    CaseManifest::load(case_dir).expect("benign corpus manifest should load")
}

fn benign_harness() -> WorkspaceHarness {
    WorkspaceHarness::builder()
        .with_providers(benign_provider_set())
        .build()
}

#[test]
fn benign_corpus_case_dirs_are_discoverable() {
    let cases = discover_case_dirs(&benign_root()).unwrap();
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
            "cursor-plugin-clean-basic",
            "mcp-safe-basic",
            "mixed-clean-workspace",
            "policy-truthful-basic",
            "skill-clean-basic",
            "skill-html-comment-safe",
        ]
    );
}

#[test]
fn benign_corpus_cases_scan_cleanly() {
    let harness = benign_harness();

    for case_dir in discover_case_dirs(&benign_root()).unwrap() {
        let manifest = load_case(&case_dir);
        let summary = harness
            .scan_case(&case_dir)
            .unwrap_or_else(|error| panic!("case {} failed to scan: {error}", manifest.id));
        assert_case_summary(&manifest, &summary);
    }
}

#[test]
fn mixed_clean_workspace_stays_clean() {
    let case_dir = benign_case("mixed-clean-workspace");
    let manifest = load_case(&case_dir);
    let summary = benign_harness().scan_case(&case_dir).unwrap();

    assert_case_summary(&manifest, &summary);
    assert!(summary.findings.is_empty());
}

#[test]
fn policy_truthful_workspace_stays_clean() {
    let case_dir = benign_case("policy-truthful-basic");
    let manifest = load_case(&case_dir);
    let summary = benign_harness().scan_case(&case_dir).unwrap();

    assert_case_summary(&manifest, &summary);
    assert!(
        summary
            .findings
            .iter()
            .all(|finding| !matches!(finding.rule_code.as_str(), "SEC401" | "SEC402" | "SEC403"))
    );
}
