use lintai_testing::{assert_case_summary, discover_case_dirs};

use super::{case_dir, corpus_root, harness, load_case};

#[test]
fn benign_corpus_case_dirs_are_discoverable() {
    let cases = discover_case_dirs(&corpus_root("benign")).unwrap();
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
            "cursor-plugin-tls-verified-basic",
            "hook-auth-dynamic-safe",
            "mcp-authorization-placeholder-safe",
            "mcp-safe-basic",
            "mcp-trust-verified-basic",
            "mixed-clean-workspace",
            "policy-truthful-basic",
            "skill-clean-basic",
            "skill-html-comment-safe",
        ]
    );
}

#[test]
fn benign_corpus_cases_scan_cleanly() {
    let harness = harness();

    for case_dir in discover_case_dirs(&corpus_root("benign")).unwrap() {
        let manifest = load_case(&case_dir);
        let summary = harness
            .scan_case(&case_dir)
            .unwrap_or_else(|error| panic!("case {} failed to scan: {error}", manifest.id));
        assert_case_summary(&manifest, &summary);
    }
}

#[test]
fn mixed_clean_workspace_stays_clean() {
    let case_dir = case_dir("benign", "mixed-clean-workspace");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();

    assert_case_summary(&manifest, &summary);
    assert!(summary.findings.is_empty());
}

#[test]
fn policy_truthful_workspace_stays_clean() {
    let case_dir = case_dir("benign", "policy-truthful-basic");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();

    assert_case_summary(&manifest, &summary);
    assert!(
        summary
            .findings
            .iter()
            .all(|finding| !matches!(finding.rule_code.as_str(), "SEC401" | "SEC402" | "SEC403"))
    );
}
