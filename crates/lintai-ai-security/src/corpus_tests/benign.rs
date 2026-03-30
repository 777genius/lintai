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
            "agents-autonomy-without-bypass-safe",
            "agents-untrusted-input-warning-safe",
            "claude-never-header-approval-safe",
            "claude-settings-bash-specific-safe",
            "claude-settings-bypass-fixture-safe",
            "claude-settings-bypass-safe",
            "claude-settings-dangerous-http-hook-fixture-safe",
            "claude-settings-dangerous-http-hook-safe",
            "claude-settings-http-hook-fixture-safe",
            "claude-settings-http-hook-loopback-safe",
            "claude-settings-http-hook-safe",
            "claude-settings-home-directory-fixture-safe",
            "claude-settings-home-directory-redirect-safe",
            "claude-settings-home-directory-safe-project-scoped",
            "claude-settings-network-command-safe",
            "claude-settings-network-tls-verified-safe",
            "claude-settings-pinned-launcher-safe",
            "claude-settings-repo-external-absolute-hook-fixture-safe",
            "claude-settings-repo-external-absolute-hook-safe",
            "claude-settings-schema-fixture-safe",
            "claude-settings-schema-present-safe",
            "claude-settings-webfetch-specific-safe",
            "claude-settings-webfetch-wildcard-fixture-safe",
            "claude-settings-write-specific-safe",
            "claude-settings-write-wildcard-fixture-safe",
            "copilot-instructions-too-long-fixture-safe",
            "copilot-instructions-within-limit-safe",
            "copilot-path-specific-fixture-safe",
            "copilot-path-specific-with-applyto-safe",
            "copilot-untrusted-input-generic-safe",
            "cursor-plugin-clean-basic",
            "cursor-plugin-safe-paths",
            "cursor-plugin-tls-verified-basic",
            "cursor-rule-alwaysapply-boolean-safe",
            "cursor-rule-alwaysapply-fixture-safe",
            "cursor-rule-globs-fixture-safe",
            "cursor-rule-globs-sequence-safe",
            "gemini-mcp-docker-digest-pinned-safe",
            "github-workflow-env-indirected-safe",
            "github-workflow-pinned-third-party-action",
            "github-workflow-pull-request-target-safe-checkout",
            "github-workflow-read-only-permissions",
            "github-workflow-third-party-action-read-only-safe",
            "hook-auth-dynamic-safe",
            "hook-base64-decode-safe",
            "mcp-authorization-placeholder-safe",
            "mcp-description-safe",
            "mcp-docker-digest-pinned-safe",
            "mcp-docker-named-volume-safe",
            "mcp-docker-safe-run",
            "mcp-network-command-safe",
            "mcp-network-tls-verified-command-safe",
            "mcp-nonsensitive-env-reference-safe",
            "mcp-pinned-launcher-safe",
            "mcp-public-endpoint-safe",
            "mcp-safe-basic",
            "mcp-safe-client-envfile-config",
            "mcp-secret-placeholder-safe",
            "mcp-trust-verified-basic",
            "mcp-trusted-endpoint-safe",
            "mcp-vscode-placeholder-envfile-safe",
            "mixed-clean-workspace",
            "plugin-agent-hooks-fixture-safe",
            "plugin-agent-markdown-covered",
            "plugin-agent-mcpservers-fixture-safe",
            "plugin-agent-permission-mode-fixture-safe",
            "plugin-agent-without-permission-mode-safe",
            "plugin-hook-command-safe",
            "policy-truthful-basic",
            "server-json-auth-header-placeholder-safe",
            "server-json-header-variable-defined",
            "server-json-loopback-package-transport-safe",
            "server-json-remote-variable-defined",
            "skill-base64-fenced-safe",
            "skill-clean-basic",
            "skill-command-snippet-bare-npx-safe",
            "skill-command-snippet-without-mcp-context-safe",
            "skill-docker-digest-pinned-safe",
            "skill-docker-host-escape-safe-ordinary-run",
            "skill-docker-local-image-safe",
            "skill-explicit-approval-required-safe",
            "skill-fenced-pipe-shell-safe",
            "skill-generic-npx-safe",
            "skill-html-comment-safe",
            "skill-metadata-service-deny-list-safe",
            "skill-mutable-mcp-launcher-safety-guidance-safe",
            "skill-project-scoped-path-safe",
            "skill-public-key-pem-safe",
            "skill-scoped-bash-allowed-tools-safe",
            "skill-unscoped-bash-fixture-safe",
            "skill-untrusted-input-negated-safe",
            "skill-wildcard-tools-explicit-allowlist-safe",
            "skill-wildcard-tools-fixture-safe",
            "tool-json-anthropic-strict-locked",
            "tool-json-mcp-valid-tool",
            "tool-json-openai-strict-locked",
            "tool-json-openai-strict-required-complete",
            "tool-json-unique-tool-names",
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
