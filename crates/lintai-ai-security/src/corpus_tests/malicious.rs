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
            "claude-settings-curl-permission",
            "claude-settings-dangerous-http-hook-host",
            "claude-settings-destructive-git-permissions",
            "claude-settings-edit-wildcard",
            "claude-settings-enabled-mcpjson-servers",
            "claude-settings-gh-api-delete-permission",
            "claude-settings-gh-api-patch-permission",
            "claude-settings-gh-api-put-permission",
            "claude-settings-gh-mutation-permissions",
            "claude-settings-gh-pr-permission",
            "claude-settings-gh-repo-edit-release-create-permissions",
            "claude-settings-gh-repo-release-delete-permissions",
            "claude-settings-gh-repo-transfer-release-upload-permissions",
            "claude-settings-gh-secret-variable-workflow-permissions",
            "claude-settings-git-add-permission",
            "claude-settings-git-branch-permission",
            "claude-settings-git-checkout-permission",
            "claude-settings-git-clone-permission",
            "claude-settings-git-commit-permission",
            "claude-settings-git-config-permission",
            "claude-settings-git-fetch-permission",
            "claude-settings-git-ls-remote-permission",
            "claude-settings-git-push-permission",
            "claude-settings-git-stash-permission",
            "claude-settings-git-tag-permission",
            "claude-settings-glob-grep-unsafe-path-permissions",
            "claude-settings-glob-wildcard",
            "claude-settings-grep-wildcard",
            "claude-settings-home-directory-hook-path",
            "claude-settings-hook-device-capture",
            "claude-settings-hook-device-capture-exfil",
            "claude-settings-hook-env-dump",
            "claude-settings-hook-env-dump-cloud-exfil",
            "claude-settings-hook-env-dump-exfil",
            "claude-settings-hook-keylogger",
            "claude-settings-hook-keylogger-exfil",
            "claude-settings-hook-local-data-exfil",
            "claude-settings-hook-local-data-theft",
            "claude-settings-hook-persistence-escalation",
            "claude-settings-hook-privilege-escalation-payloads",
            "claude-settings-hook-screen-capture",
            "claude-settings-hook-screen-capture-exfil",
            "claude-settings-hook-secret-exfil-payloads",
            "claude-settings-hook-sensitive-file-exfil",
            "claude-settings-hook-sensitive-file-rclone-exfil",
            "claude-settings-hook-service-persistence",
            "claude-settings-http-hook-url",
            "claude-settings-inline-download-exec",
            "claude-settings-matcher-on-stop-event",
            "claude-settings-missing-hook-timeout",
            "claude-settings-missing-required-matcher",
            "claude-settings-missing-schema",
            "claude-settings-mutable-launcher",
            "claude-settings-mutable-runner-permissions",
            "claude-settings-npm-exec-bunx-permissions",
            "claude-settings-npx-permission",
            "claude-settings-package-install-permission",
            "claude-settings-pip-install-permission",
            "claude-settings-read-wildcard",
            "claude-settings-repo-external-absolute-hook-path",
            "claude-settings-unsafe-path-permissions",
            "claude-settings-unscoped-tool-family",
            "claude-settings-unscoped-websearch",
            "claude-settings-webfetch-raw-github-permission",
            "claude-settings-webfetch-wildcard",
            "claude-settings-websearch-wildcard",
            "claude-settings-wget-permission",
            "claude-settings-write-wildcard",
            "claude-transcript-bare-pip-install",
            "claude-unpinned-pip-git-install",
            "copilot-instructions-too-long",
            "copilot-path-specific-invalid-applyto",
            "copilot-path-specific-invalid-applyto-glob",
            "copilot-path-specific-missing-applyto",
            "copilot-path-specific-wrong-suffix",
            "copilot-webpage-system-prompt-promotion",
            "cursor-plugin-unsafe-path",
            "cursor-rule-alwaysapply-nonboolean",
            "cursor-rule-alwaysapply-redundant-globs",
            "cursor-rule-globs-scalar",
            "cursor-rule-missing-description",
            "cursor-rule-unknown-frontmatter-key",
            "gemini-mcp-docker-pull-always",
            "gemini-mcp-docker-unpinned-image",
            "gemini-mcp-fixture-suppressed",
            "github-workflow-direct-run-interpolation",
            "github-workflow-pull-request-target-head-checkout",
            "github-workflow-third-party-unpinned-action",
            "github-workflow-write-all-permissions",
            "github-workflow-write-capable-third-party-action",
            "hook-base64-exec",
            "hook-device-capture",
            "hook-device-capture-exfil",
            "hook-download-exec",
            "hook-env-dump",
            "hook-env-dump-cloud-exfil",
            "hook-env-dump-exfil",
            "hook-keylogger",
            "hook-keylogger-exfil",
            "hook-local-data-exfil",
            "hook-local-data-theft",
            "hook-persistence-escalation",
            "hook-plain-http-secret-exfil",
            "hook-privilege-escalation-payloads",
            "hook-screen-capture",
            "hook-screen-capture-exfil",
            "hook-secret-exfil",
            "hook-sensitive-file-exfil",
            "hook-sensitive-file-rclone-exfil",
            "hook-service-persistence",
            "hook-static-auth-userinfo",
            "hook-tls-bypass",
            "hook-webhook-secret-exfil",
            "mcp-args-sudo",
            "mcp-autoapprove-bash-wildcard",
            "mcp-autoapprove-curl-wget",
            "mcp-autoapprove-gh-api-mutation-family",
            "mcp-autoapprove-gh-delete-family",
            "mcp-autoapprove-gh-mutation-family",
            "mcp-autoapprove-gh-release-transfer-family",
            "mcp-autoapprove-git-destructive-family",
            "mcp-autoapprove-git-history-family",
            "mcp-autoapprove-git-push-gh-api-post",
            "mcp-autoapprove-mutable-runner-family",
            "mcp-autoapprove-package-install-family",
            "mcp-autoapprove-persistence-family",
            "mcp-autoapprove-privileged-shell-family",
            "mcp-autoapprove-repo-fetch-family",
            "mcp-autoapprove-repo-management-family",
            "mcp-autoapprove-sudo-rm",
            "mcp-autoapprove-tools-true",
            "mcp-autoapprove-unsafe-path-family",
            "mcp-autoapprove-unscoped-tool-family",
            "mcp-autoapprove-webfetch-raw-github",
            "mcp-autoapprove-wildcard",
            "mcp-autoapprove-wildcard-tool-family",
            "mcp-capabilities-wildcard",
            "mcp-command-device-capture",
            "mcp-command-device-capture-exfil",
            "mcp-command-env-dump",
            "mcp-command-env-dump-cloud-exfil",
            "mcp-command-env-dump-exfil",
            "mcp-command-keylogger",
            "mcp-command-keylogger-exfil",
            "mcp-command-local-data-exfil",
            "mcp-command-local-data-theft",
            "mcp-command-persistence-escalation",
            "mcp-command-privilege-escalation-payloads",
            "mcp-command-screen-capture",
            "mcp-command-screen-capture-exfil",
            "mcp-command-secret-exfil-payloads",
            "mcp-command-sensitive-file-exfil",
            "mcp-command-sensitive-file-rclone-exfil",
            "mcp-command-service-persistence",
            "mcp-command-sudo",
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
            "mcp-sandbox-disabled",
            "mcp-sensitive-env-reference",
            "mcp-shell-wrapper",
            "mcp-shell-wrapper-args0",
            "mcp-static-authorization",
            "mcp-suspicious-endpoint",
            "mcp-trust-tools-true",
            "mcp-trust-verification-disabled",
            "package-manifest-dangerous-lifecycle-script",
            "package-manifest-git-url-dependency",
            "package-manifest-unbounded-dependency",
            "plugin-agent-hooks-frontmatter",
            "plugin-agent-mcpservers-frontmatter",
            "plugin-agent-permission-mode-frontmatter",
            "plugin-command-markdown-covered",
            "plugin-hook-command-device-capture",
            "plugin-hook-command-device-capture-exfil",
            "plugin-hook-command-env-dump",
            "plugin-hook-command-env-dump-cloud-exfil",
            "plugin-hook-command-env-dump-exfil",
            "plugin-hook-command-inline-download-exec",
            "plugin-hook-command-keylogger",
            "plugin-hook-command-keylogger-exfil",
            "plugin-hook-command-local-data-exfil",
            "plugin-hook-command-local-data-theft",
            "plugin-hook-command-mutable-launcher",
            "plugin-hook-command-persistence-escalation",
            "plugin-hook-command-privilege-escalation-payloads",
            "plugin-hook-command-screen-capture",
            "plugin-hook-command-screen-capture-exfil",
            "plugin-hook-command-secret-exfil-payloads",
            "plugin-hook-command-sensitive-file-exfil",
            "plugin-hook-command-sensitive-file-rclone-exfil",
            "plugin-hook-command-service-persistence",
            "plugin-hook-command-tls-bypass",
            "policy-exec-network-mismatch",
            "policy-frontmatter-conflict",
            "server-json-insecure-remote-url",
            "server-json-literal-auth-header",
            "server-json-unresolved-header-variable",
            "server-json-unresolved-remote-variable",
            "skill-approval-bypass-directive",
            "skill-bash-wildcard-allowed-tools",
            "skill-cargo-http-git-install",
            "skill-cargo-http-index",
            "skill-chgrp-allowed-tools",
            "skill-chmod-allowed-tools",
            "skill-chown-allowed-tools",
            "skill-core-wildcard-allowed-tools",
            "skill-curl-allowed-tools",
            "skill-docker-host-network",
            "skill-docker-multiline-mutable-image",
            "skill-docker-privileged-runtime",
            "skill-docker-socket-bind-mount",
            "skill-docker-unpinned-registry-image",
            "skill-edit-unsafe-path-allowed-tools",
            "skill-fenced-pipe-shell",
            "skill-gh-api-delete-allowed-tools",
            "skill-gh-api-patch-allowed-tools",
            "skill-gh-api-put-allowed-tools",
            "skill-gh-mutation-allowed-tools",
            "skill-gh-pr-allowed-tools",
            "skill-gh-repo-edit-release-create-allowed-tools",
            "skill-gh-repo-release-delete-allowed-tools",
            "skill-gh-repo-transfer-release-upload-allowed-tools",
            "skill-gh-secret-variable-workflow-allowed-tools",
            "skill-git-add-allowed-tools",
            "skill-git-am-allowed-tools",
            "skill-git-apply-allowed-tools",
            "skill-git-branch-allowed-tools",
            "skill-git-cherry-pick-allowed-tools",
            "skill-git-clean-allowed-tools",
            "skill-git-clone-allowed-tools",
            "skill-git-config-allowed-tools",
            "skill-git-fetch-allowed-tools",
            "skill-git-http-clone",
            "skill-git-http-remote",
            "skill-git-inline-sslverify-false",
            "skill-git-merge-allowed-tools",
            "skill-git-rebase-allowed-tools",
            "skill-git-reset-allowed-tools",
            "skill-git-restore-allowed-tools",
            "skill-git-ssl-no-verify",
            "skill-git-sslverify-false",
            "skill-git-tag-allowed-tools",
            "skill-glob-unsafe-path-allowed-tools",
            "skill-hidden-directive",
            "skill-html-comment-download-exec",
            "skill-js-package-config-http-registry",
            "skill-js-package-strict-ssl-false",
            "skill-markdown-base64-exec",
            "skill-markdown-download-exec",
            "skill-markdown-network-tls-bypass",
            "skill-markdown-network-tls-bypass-powershell",
            "skill-markdown-path-traversal",
            "skill-mcp-config-mutable-launcher",
            "skill-mcp-config-pipx-run-launcher",
            "skill-metadata-service-access",
            "skill-npm-exec-bunx-allowed-tools",
            "skill-npm-http-registry",
            "skill-npm-http-source",
            "skill-npx-git-ls-remote-allowed-tools",
            "skill-package-install-allowed-tools",
            "skill-pip-config-http-find-links",
            "skill-pip-config-http-index",
            "skill-pip-config-trusted-host",
            "skill-pip-http-find-links",
            "skill-pip-http-git-install",
            "skill-pip-http-index",
            "skill-pip-http-source",
            "skill-pip-trusted-host",
            "skill-private-key-pem",
            "skill-read-unsafe-path-allowed-tools",
            "skill-risky-frontmatter-tool-grants",
            "skill-rm-allowed-tools",
            "skill-su-allowed-tools",
            "skill-sudo-allowed-tools",
            "skill-tool-output-developer-instructions",
            "skill-unscoped-bash-allowed-tools",
            "skill-unscoped-edit-allowed-tools",
            "skill-unscoped-glob-allowed-tools",
            "skill-unscoped-grep-allowed-tools",
            "skill-unscoped-read-allowed-tools",
            "skill-unscoped-webfetch-allowed-tools",
            "skill-unscoped-write-allowed-tools",
            "skill-uvx-dlx-pipx-allowed-tools",
            "skill-webfetch-raw-github-allowed-tools",
            "skill-wget-allowed-tools",
            "skill-wildcard-tools-frontmatter",
            "skill-write-unsafe-path-allowed-tools",
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

#[test]
fn package_manifest_supply_chain_cases_trigger_expected_findings() {
    for case_name in [
        "package-manifest-dangerous-lifecycle-script",
        "package-manifest-git-url-dependency",
        "package-manifest-unbounded-dependency",
    ] {
        let case_dir = case_dir("malicious", case_name);
        let manifest = load_case(&case_dir);
        let summary = harness().scan_case(&case_dir).unwrap();
        assert_case_summary(&manifest, &summary);
    }
}
