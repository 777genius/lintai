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
            "agents-human-approval-bypass",
            "agents-pr-body-override",
            "claude-markdown-mutable-mcp-launcher",
            "claude-sensitive-action-without-permission",
            "claude-settings-bash-wildcard",
            "claude-settings-bypass-permissions",
            "claude-settings-command-tls-bypass",
            "claude-settings-dangerous-http-hook-host",
            "claude-settings-http-hook-url",
            "claude-settings-home-directory-hook-path",
            "claude-settings-inline-download-exec",
            "claude-settings-missing-schema",
            "claude-settings-mutable-launcher",
            "claude-settings-repo-external-absolute-hook-path",
            "claude-settings-webfetch-wildcard",
            "copilot-instructions-too-long",
            "copilot-path-specific-missing-applyto",
            "copilot-webpage-system-prompt-promotion",
            "cursor-plugin-unsafe-path",
            "cursor-rule-alwaysapply-nonboolean",
            "cursor-rule-globs-scalar",
            "gemini-mcp-docker-pull-always",
            "gemini-mcp-docker-unpinned-image",
            "gemini-mcp-fixture-suppressed",
            "github-workflow-direct-run-interpolation",
            "github-workflow-pull-request-target-head-checkout",
            "github-workflow-third-party-unpinned-action",
            "github-workflow-write-all-permissions",
            "github-workflow-write-capable-third-party-action",
            "hook-base64-exec",
            "hook-download-exec",
            "hook-plain-http-secret-exfil",
            "hook-secret-exfil",
            "hook-static-auth-userinfo",
            "hook-tls-bypass",
            "mcp-command-tls-bypass",
            "mcp-credential-env-passthrough",
            "mcp-docker-host-escape",
            "mcp-docker-sensitive-mount",
            "mcp-docker-unpinned-image",
            "mcp-expanded-client-envfile-fixture-suppressed",
            "mcp-expanded-client-envfile-preview",
            "mcp-hidden-instruction",
            "mcp-inline-download-exec",
            "mcp-literal-secret-config",
            "mcp-metadata-host-literal",
            "mcp-mutable-launcher",
            "mcp-plain-http",
            "mcp-sensitive-env-reference",
            "mcp-shell-wrapper",
            "mcp-static-authorization",
            "mcp-suspicious-endpoint",
            "mcp-trust-verification-disabled",
            "plugin-agent-hooks-frontmatter",
            "plugin-agent-mcpservers-frontmatter",
            "plugin-agent-permission-mode-frontmatter",
            "plugin-command-markdown-covered",
            "plugin-hook-command-inline-download-exec",
            "plugin-hook-command-mutable-launcher",
            "plugin-hook-command-tls-bypass",
            "policy-exec-network-mismatch",
            "policy-frontmatter-conflict",
            "server-json-insecure-remote-url",
            "server-json-literal-auth-header",
            "server-json-unresolved-header-variable",
            "server-json-unresolved-remote-variable",
            "skill-approval-bypass-directive",
            "skill-docker-host-network",
            "skill-docker-multiline-mutable-image",
            "skill-docker-privileged-runtime",
            "skill-docker-socket-bind-mount",
            "skill-docker-unpinned-registry-image",
            "skill-fenced-pipe-shell",
            "skill-hidden-directive",
            "skill-html-comment-download-exec",
            "skill-markdown-base64-exec",
            "skill-markdown-download-exec",
            "skill-markdown-path-traversal",
            "skill-mcp-config-mutable-launcher",
            "skill-mcp-config-pipx-run-launcher",
            "skill-metadata-service-access",
            "skill-private-key-pem",
            "skill-tool-output-developer-instructions",
            "skill-unscoped-bash-allowed-tools",
            "skill-wildcard-tools-frontmatter",
            "tool-json-anthropic-strict-open-schema",
            "tool-json-duplicate-tool-names",
            "tool-json-mcp-missing-machine-fields",
            "tool-json-openai-strict-additional-properties",
            "tool-json-openai-strict-required-coverage",
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
    assert!(
        summary
            .findings
            .iter()
            .any(|finding| finding.rule_code == "SEC202")
    );
    assert!(
        summary
            .findings
            .iter()
            .any(|finding| finding.rule_code == "SEC203")
    );
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
