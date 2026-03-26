use lintai_api::EvidenceKind;
use lintai_testing::{assert_case_summary, discover_case_dirs};

use super::{case_dir, corpus_root, harness, load_case};

#[test]
fn malicious_corpus_case_dirs_are_discoverable() {
    let cases = discover_case_dirs(&corpus_root("malicious")).unwrap();
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
            "hook-download-exec",
            "hook-plain-http-secret-exfil",
            "hook-secret-exfil",
            "mcp-credential-env-passthrough",
            "mcp-plain-http",
            "mcp-shell-wrapper",
            "policy-exec-network-mismatch",
            "policy-frontmatter-conflict",
            "skill-hidden-directive",
            "skill-html-comment-download-exec",
            "skill-markdown-download-exec",
        ]
    );
}

#[test]
fn malicious_corpus_cases_trigger_expected_findings() {
    let harness = harness();

    for case_dir in discover_case_dirs(&corpus_root("malicious")).unwrap() {
        let manifest = load_case(&case_dir);
        let summary = harness
            .scan_case(&case_dir)
            .unwrap_or_else(|error| panic!("case {} failed to scan: {error}", manifest.id));
        assert_case_summary(&manifest, &summary);
    }
}

#[test]
fn hook_plain_http_secret_exfil_triggers_both_rules() {
    let case_dir = case_dir("malicious", "hook-plain-http-secret-exfil");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();

    assert_case_summary(&manifest, &summary);
    assert!(summary.findings.iter().any(|finding| finding.rule_code == "SEC202"));
    assert!(summary.findings.iter().any(|finding| finding.rule_code == "SEC203"));
}

#[test]
fn policy_exec_network_mismatch_emits_preview_evidence() {
    let case_dir = case_dir("malicious", "policy-exec-network-mismatch");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();

    assert_case_summary(&manifest, &summary);
    for rule_code in ["SEC401", "SEC402"] {
        let finding = summary
            .findings
            .iter()
            .find(|finding| finding.rule_code == rule_code)
            .unwrap();
        assert!(finding.evidence.len() >= 2);
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
fn policy_frontmatter_conflict_emits_preview_evidence() {
    let case_dir = case_dir("malicious", "policy-frontmatter-conflict");
    let manifest = load_case(&case_dir);
    let summary = harness().scan_case(&case_dir).unwrap();

    assert_case_summary(&manifest, &summary);
    let finding = summary
        .findings
        .iter()
        .find(|finding| finding.rule_code == "SEC403")
        .unwrap();
    assert!(finding.evidence.len() >= 2);
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
