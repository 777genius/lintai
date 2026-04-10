use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::markdown_rules::{
    check_approval_bypass_instruction, check_bunx_allowed_tools, check_chgrp_allowed_tools,
    check_chmod_allowed_tools, check_chown_allowed_tools,
    check_copilot_instruction_invalid_apply_to, check_copilot_instruction_invalid_apply_to_glob,
    check_copilot_instruction_missing_apply_to, check_copilot_instruction_too_long,
    check_copilot_instruction_wrong_suffix, check_curl_allowed_tools,
    check_cursor_rule_always_apply_type, check_cursor_rule_globs_type,
    check_cursor_rule_missing_description, check_cursor_rule_redundant_globs,
    check_cursor_rule_unknown_frontmatter_key, check_edit_unsafe_path_allowed_tools,
    check_gh_api_delete_allowed_tools, check_gh_api_patch_allowed_tools,
    check_gh_api_post_allowed_tools, check_gh_api_put_allowed_tools,
    check_gh_issue_create_allowed_tools, check_gh_pr_allowed_tools,
    check_gh_release_create_allowed_tools, check_gh_release_delete_allowed_tools,
    check_gh_release_upload_allowed_tools, check_gh_repo_create_allowed_tools,
    check_gh_repo_delete_allowed_tools, check_gh_repo_edit_allowed_tools,
    check_gh_repo_transfer_allowed_tools, check_gh_secret_delete_allowed_tools,
    check_gh_secret_set_allowed_tools, check_gh_variable_delete_allowed_tools,
    check_gh_variable_set_allowed_tools, check_gh_workflow_disable_allowed_tools,
    check_gh_workflow_run_allowed_tools, check_git_add_allowed_tools, check_git_am_allowed_tools,
    check_git_apply_allowed_tools, check_git_branch_allowed_tools,
    check_git_checkout_allowed_tools, check_git_cherry_pick_allowed_tools,
    check_git_clean_allowed_tools, check_git_clone_allowed_tools, check_git_commit_allowed_tools,
    check_git_config_allowed_tools, check_git_fetch_allowed_tools,
    check_git_ls_remote_allowed_tools, check_git_merge_allowed_tools, check_git_push_allowed_tools,
    check_git_rebase_allowed_tools, check_git_reset_allowed_tools, check_git_restore_allowed_tools,
    check_git_stash_allowed_tools, check_git_tag_allowed_tools,
    check_glob_unsafe_path_allowed_tools, check_html_comment_directive,
    check_html_comment_download_exec, check_markdown_base64_exec,
    check_markdown_cargo_http_git_install, check_markdown_cargo_http_index,
    check_markdown_claude_bare_pip_install, check_markdown_docker_host_escape,
    check_markdown_download_exec, check_markdown_fenced_pipe_shell, check_markdown_git_http_clone,
    check_markdown_git_http_remote, check_markdown_git_inline_sslverify_false,
    check_markdown_git_ssl_no_verify, check_markdown_git_sslverify_false,
    check_markdown_js_package_config_http_registry, check_markdown_js_package_strict_ssl_false,
    check_markdown_metadata_service_access, check_markdown_mutable_docker_image,
    check_markdown_mutable_mcp_launcher, check_markdown_network_tls_bypass,
    check_markdown_npm_http_registry, check_markdown_npm_http_source,
    check_markdown_path_traversal, check_markdown_pip_config_http_find_links,
    check_markdown_pip_config_http_index, check_markdown_pip_config_trusted_host,
    check_markdown_pip_http_find_links, check_markdown_pip_http_git_install,
    check_markdown_pip_http_index, check_markdown_pip_http_source, check_markdown_pip_trusted_host,
    check_markdown_private_key_pem, check_markdown_unpinned_pip_git_install,
    check_npm_exec_allowed_tools, check_npx_allowed_tools, check_package_install_allowed_tools,
    check_pipx_run_allowed_tools, check_plugin_agent_hooks_frontmatter,
    check_plugin_agent_mcp_servers_frontmatter, check_plugin_agent_permission_mode,
    check_pnpm_dlx_allowed_tools, check_read_unsafe_path_allowed_tools, check_rm_allowed_tools,
    check_su_allowed_tools, check_sudo_allowed_tools, check_unscoped_bash_allowed_tools,
    check_unscoped_edit_allowed_tools, check_unscoped_glob_allowed_tools,
    check_unscoped_grep_allowed_tools, check_unscoped_read_allowed_tools,
    check_unscoped_webfetch_allowed_tools, check_unscoped_websearch_allowed_tools,
    check_unscoped_write_allowed_tools, check_untrusted_instruction_promotion,
    check_uvx_allowed_tools, check_webfetch_raw_github_allowed_tools, check_wget_allowed_tools,
    check_wildcard_bash_allowed_tools, check_wildcard_edit_allowed_tools,
    check_wildcard_glob_allowed_tools, check_wildcard_grep_allowed_tools,
    check_wildcard_read_allowed_tools, check_wildcard_tool_access,
    check_wildcard_webfetch_allowed_tools, check_wildcard_websearch_allowed_tools,
    check_wildcard_write_allowed_tools, check_write_unsafe_path_allowed_tools,
    check_yarn_dlx_allowed_tools,
};

declare_rule! {
    pub struct HtmlCommentDirectiveRule {
        code: "SEC101",
        summary: "Hidden HTML comment contains dangerous agent instructions",
        doc_title: "HTML comment: dangerous instructions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownDownloadExecRule {
        code: "SEC102",
        summary: "Markdown contains remote download-and-execute instruction outside code blocks",
        doc_title: "Markdown: remote execution instruction",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct HtmlCommentDownloadExecRule {
        code: "SEC103",
        summary: "Hidden HTML comment contains remote download-and-execute instruction",
        doc_title: "HTML comment: remote execution instruction",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownBase64ExecRule {
        code: "SEC104",
        summary: "Markdown contains a base64-decoded executable payload outside code blocks",
        doc_title: "Markdown: base64 executable payload",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownPathTraversalRule {
        code: "SEC105",
        summary: "Markdown instructions reference parent-directory traversal for file access",
        doc_title: "Markdown: parent-directory file access",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownMetadataServiceAccessRule {
        code: "SEC335",
        summary: "AI-native markdown contains a direct cloud metadata-service access example",
        doc_title: "AI markdown: metadata-service access",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownMutableMcpLauncherRule {
        code: "SEC347",
        summary: "AI-native markdown example launches MCP through a mutable package runner",
        doc_title: "AI markdown: MCP via mutable package runner",
        category: Category::Hardening,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownClaudeBarePipInstallRule {
        code: "SEC416",
        summary: "AI-native markdown models Claude package installation with bare `pip install` despite explicit `uv` preference guidance",
        doc_title: "AI markdown: Claude bare pip install",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownUnpinnedPipGitInstallRule {
        code: "SEC417",
        summary: "AI-native markdown installs Python packages from an unpinned `git+https://` source",
        doc_title: "AI markdown: unpinned pip git install",
        category: Category::Hardening,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownPipHttpGitInstallRule {
        code: "SEC455",
        summary: "AI-native markdown installs Python packages from an insecure `git+http://` source",
        doc_title: "AI markdown: pip http git install",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownPipTrustedHostRule {
        code: "SEC448",
        summary: "AI-native markdown installs Python packages with `--trusted-host`",
        doc_title: "AI markdown: pip trusted-host",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownPipHttpIndexRule {
        code: "SEC449",
        summary: "AI-native markdown installs Python packages from an insecure `http://` package index",
        doc_title: "AI markdown: pip http index",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownPipHttpFindLinksRule {
        code: "SEC456",
        summary: "AI-native markdown installs Python packages with insecure `http://` find-links",
        doc_title: "AI markdown: pip http find-links",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownPipConfigHttpIndexRule {
        code: "SEC458",
        summary: "AI-native markdown configures Python package resolution with an insecure `http://` package index",
        doc_title: "AI markdown: pip config http index",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownPipConfigHttpFindLinksRule {
        code: "SEC460",
        summary: "AI-native markdown configures Python package discovery with insecure `http://` find-links",
        doc_title: "AI markdown: pip config http find-links",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownNpmHttpRegistryRule {
        code: "SEC450",
        summary: "AI-native markdown installs JavaScript packages from an insecure `http://` registry",
        doc_title: "AI markdown: npm http registry",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownPipConfigTrustedHostRule {
        code: "SEC461",
        summary: "AI-native markdown configures Python package resolution with `trusted-host`",
        doc_title: "AI markdown: pip config trusted-host",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownNetworkTlsBypassRule {
        code: "SEC462",
        summary: "AI-native markdown disables TLS verification for a network-capable command",
        doc_title: "AI markdown: network TLS bypass",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownJsPackageConfigHttpRegistryRule {
        code: "SEC459",
        summary: "AI-native markdown configures a JavaScript package manager with an insecure `http://` registry",
        doc_title: "AI markdown: js package config http registry",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownJsPackageStrictSslFalseRule {
        code: "SEC457",
        summary: "AI-native markdown disables strict SSL verification for JavaScript package manager config",
        doc_title: "AI markdown: js package strict-ssl false",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownCargoHttpGitInstallRule {
        code: "SEC451",
        summary: "AI-native markdown installs Rust packages from an insecure `http://` git source",
        doc_title: "AI markdown: cargo http git install",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownCargoHttpIndexRule {
        code: "SEC452",
        summary: "AI-native markdown installs Rust packages from an insecure `http://` index",
        doc_title: "AI markdown: cargo http index",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownGitHttpCloneRule {
        code: "SEC464",
        summary: "AI-native markdown clones a Git repository from an insecure `http://` source",
        doc_title: "AI markdown: git http clone",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownGitHttpRemoteRule {
        code: "SEC465",
        summary: "AI-native markdown configures a Git remote with an insecure `http://` source",
        doc_title: "AI markdown: git http remote",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownGitSslVerifyFalseRule {
        code: "SEC471",
        summary: "AI-native markdown disables Git TLS verification with `http.sslVerify false`",
        doc_title: "AI markdown: git sslVerify false",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownGitSslNoVerifyRule {
        code: "SEC472",
        summary: "AI-native markdown disables Git TLS verification with `GIT_SSL_NO_VERIFY`",
        doc_title: "AI markdown: GIT_SSL_NO_VERIFY",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownGitInlineSslVerifyFalseRule {
        code: "SEC473",
        summary: "AI-native markdown disables Git TLS verification with `git -c http.sslVerify=false`",
        doc_title: "AI markdown: git inline sslVerify false",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownPipHttpSourceRule {
        code: "SEC453",
        summary: "AI-native markdown installs Python packages from an insecure direct `http://` source",
        doc_title: "AI markdown: pip http source",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownNpmHttpSourceRule {
        code: "SEC454",
        summary: "AI-native markdown installs JavaScript packages from an insecure direct `http://` source",
        doc_title: "AI markdown: npm http source",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownMutableDockerImageRule {
        code: "SEC348",
        summary: "AI-native markdown Docker example uses a mutable registry image",
        doc_title: "AI markdown: mutable Docker image",
        category: Category::Hardening,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownDockerHostEscapeRule {
        code: "SEC349",
        summary: "AI-native markdown Docker example uses a host-escape or privileged runtime pattern",
        doc_title: "AI markdown: privileged Docker pattern",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct UntrustedInstructionPromotionRule {
        code: "SEC350",
        summary: "Instruction markdown promotes untrusted external content to developer/system-level instructions",
        doc_title: "Instruction markdown: untrusted content promoted",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ApprovalBypassInstructionRule {
        code: "SEC351",
        summary: "AI-native instruction explicitly disables user approval or confirmation",
        doc_title: "AI instruction: disables user approval",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct UnscopedBashAllowedToolsRule {
        code: "SEC352",
        summary: "AI-native markdown frontmatter grants unscoped Bash tool access",
        doc_title: "AI markdown: unscoped Bash tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct UnscopedWebSearchAllowedToolsRule {
        code: "SEC389",
        summary: "AI-native markdown frontmatter grants bare `WebSearch` tool access",
        doc_title: "AI markdown: bare WebSearch tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GitPushAllowedToolsRule {
        code: "SEC390",
        summary: "AI-native markdown frontmatter grants `Bash(git push)` tool access",
        doc_title: "AI markdown: shared git push tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GitCheckoutAllowedToolsRule {
        code: "SEC391",
        summary: "AI-native markdown frontmatter grants `Bash(git checkout:*)` tool access",
        doc_title: "AI markdown: shared git checkout tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GitCommitAllowedToolsRule {
        code: "SEC392",
        summary: "AI-native markdown frontmatter grants `Bash(git commit:*)` tool access",
        doc_title: "AI markdown: shared git commit tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GitStashAllowedToolsRule {
        code: "SEC393",
        summary: "AI-native markdown frontmatter grants `Bash(git stash:*)` tool access",
        doc_title: "AI markdown: shared git stash tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GhPrAllowedToolsRule {
        code: "SEC474",
        summary: "AI-native markdown frontmatter grants `Bash(gh pr:*)` tool access",
        doc_title: "AI markdown: shared gh pr tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct NpmExecAllowedToolsRule {
        code: "SEC494",
        summary: "AI-native markdown frontmatter grants `Bash(npm exec:*)` tool access",
        doc_title: "AI markdown: shared npm exec tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct BunxAllowedToolsRule {
        code: "SEC495",
        summary: "AI-native markdown frontmatter grants `Bash(bunx:*)` tool access",
        doc_title: "AI markdown: shared bunx tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct UvxAllowedToolsRule {
        code: "SEC496",
        summary: "AI-native markdown frontmatter grants `Bash(uvx:*)` tool access",
        doc_title: "AI markdown: shared uvx tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct PnpmDlxAllowedToolsRule {
        code: "SEC497",
        summary: "AI-native markdown frontmatter grants `Bash(pnpm dlx:*)` tool access",
        doc_title: "AI markdown: shared pnpm dlx tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct YarnDlxAllowedToolsRule {
        code: "SEC498",
        summary: "AI-native markdown frontmatter grants `Bash(yarn dlx:*)` tool access",
        doc_title: "AI markdown: shared yarn dlx tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct PipxRunAllowedToolsRule {
        code: "SEC499",
        summary: "AI-native markdown frontmatter grants `Bash(pipx run:*)` tool access",
        doc_title: "AI markdown: shared pipx run tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct NpxAllowedToolsRule {
        code: "SEC500",
        summary: "AI-native markdown frontmatter grants `Bash(npx:*)` tool access",
        doc_title: "AI markdown: shared npx tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GitLsRemoteAllowedToolsRule {
        code: "SEC501",
        summary: "AI-native markdown frontmatter grants `Bash(git ls-remote:*)` tool access",
        doc_title: "AI markdown: shared git ls-remote tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GhApiPostAllowedToolsRule {
        code: "SEC505",
        summary: "AI-native markdown frontmatter grants `Bash(gh api --method POST:*)` tool access",
        doc_title: "AI markdown: shared gh api POST tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhApiDeleteAllowedToolsRule {
        code: "SEC529",
        summary: "AI-native markdown frontmatter grants `Bash(gh api --method DELETE:*)` tool access",
        doc_title: "AI markdown: shared gh api DELETE tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhApiPatchAllowedToolsRule {
        code: "SEC532",
        summary: "AI-native markdown frontmatter grants `Bash(gh api --method PATCH:*)` tool access",
        doc_title: "AI markdown: shared gh api PATCH tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhApiPutAllowedToolsRule {
        code: "SEC533",
        summary: "AI-native markdown frontmatter grants `Bash(gh api --method PUT:*)` tool access",
        doc_title: "AI markdown: shared gh api PUT tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhIssueCreateAllowedToolsRule {
        code: "SEC506",
        summary: "AI-native markdown frontmatter grants `Bash(gh issue create:*)` tool access",
        doc_title: "AI markdown: shared gh issue create tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhRepoCreateAllowedToolsRule {
        code: "SEC507",
        summary: "AI-native markdown frontmatter grants `Bash(gh repo create:*)` tool access",
        doc_title: "AI markdown: shared gh repo create tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhSecretSetAllowedToolsRule {
        code: "SEC511",
        summary: "AI-native markdown frontmatter grants `Bash(gh secret set:*)` tool access",
        doc_title: "AI markdown: shared gh secret set tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhRepoDeleteAllowedToolsRule {
        code: "SEC535",
        summary: "AI-native markdown frontmatter grants `Bash(gh repo delete:*)` tool access",
        doc_title: "AI markdown: shared gh repo delete tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhRepoEditAllowedToolsRule {
        code: "SEC539",
        summary: "AI-native markdown frontmatter grants `Bash(gh repo edit:*)` tool access",
        doc_title: "AI markdown: shared gh repo edit tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhRepoTransferAllowedToolsRule {
        code: "SEC543",
        summary: "AI-native markdown frontmatter grants `Bash(gh repo transfer:*)` tool access",
        doc_title: "AI markdown: shared gh repo transfer tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhReleaseCreateAllowedToolsRule {
        code: "SEC541",
        summary: "AI-native markdown frontmatter grants `Bash(gh release create:*)` tool access",
        doc_title: "AI markdown: shared gh release create tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhReleaseUploadAllowedToolsRule {
        code: "SEC545",
        summary: "AI-native markdown frontmatter grants `Bash(gh release upload:*)` tool access",
        doc_title: "AI markdown: shared gh release upload tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhReleaseDeleteAllowedToolsRule {
        code: "SEC537",
        summary: "AI-native markdown frontmatter grants `Bash(gh release delete:*)` tool access",
        doc_title: "AI markdown: shared gh release delete tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhVariableSetAllowedToolsRule {
        code: "SEC512",
        summary: "AI-native markdown frontmatter grants `Bash(gh variable set:*)` tool access",
        doc_title: "AI markdown: shared gh variable set tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhWorkflowRunAllowedToolsRule {
        code: "SEC513",
        summary: "AI-native markdown frontmatter grants `Bash(gh workflow run:*)` tool access",
        doc_title: "AI markdown: shared gh workflow run tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhSecretDeleteAllowedToolsRule {
        code: "SEC517",
        summary: "AI-native markdown frontmatter grants `Bash(gh secret delete:*)` tool access",
        doc_title: "AI markdown: shared gh secret delete tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhVariableDeleteAllowedToolsRule {
        code: "SEC518",
        summary: "AI-native markdown frontmatter grants `Bash(gh variable delete:*)` tool access",
        doc_title: "AI markdown: shared gh variable delete tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GhWorkflowDisableAllowedToolsRule {
        code: "SEC519",
        summary: "AI-native markdown frontmatter grants `Bash(gh workflow disable:*)` tool access",
        doc_title: "AI markdown: shared gh workflow disable tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WildcardReadAllowedToolsRule {
        code: "SEC520",
        summary: "AI-native markdown frontmatter grants `Read(*)` wildcard access",
        doc_title: "AI markdown: `Read(*)` wildcard tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WildcardBashAllowedToolsRule {
        code: "SEC527",
        summary: "AI-native markdown frontmatter grants `Bash(*)` wildcard access",
        doc_title: "AI markdown: `Bash(*)` wildcard tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WildcardWriteAllowedToolsRule {
        code: "SEC521",
        summary: "AI-native markdown frontmatter grants `Write(*)` wildcard access",
        doc_title: "AI markdown: `Write(*)` wildcard tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WildcardEditAllowedToolsRule {
        code: "SEC522",
        summary: "AI-native markdown frontmatter grants `Edit(*)` wildcard access",
        doc_title: "AI markdown: `Edit(*)` wildcard tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WildcardGlobAllowedToolsRule {
        code: "SEC523",
        summary: "AI-native markdown frontmatter grants `Glob(*)` wildcard access",
        doc_title: "AI markdown: `Glob(*)` wildcard tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WildcardGrepAllowedToolsRule {
        code: "SEC524",
        summary: "AI-native markdown frontmatter grants `Grep(*)` wildcard access",
        doc_title: "AI markdown: `Grep(*)` wildcard tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WildcardWebFetchAllowedToolsRule {
        code: "SEC525",
        summary: "AI-native markdown frontmatter grants `WebFetch(*)` wildcard access",
        doc_title: "AI markdown: `WebFetch(*)` wildcard tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WildcardWebSearchAllowedToolsRule {
        code: "SEC526",
        summary: "AI-native markdown frontmatter grants `WebSearch(*)` wildcard access",
        doc_title: "AI markdown: `WebSearch(*)` wildcard tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct UnscopedWebFetchAllowedToolsRule {
        code: "SEC404",
        summary: "AI-native markdown frontmatter grants bare `WebFetch` tool access",
        doc_title: "AI markdown: bare WebFetch tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CopilotInstructionTooLongRule {
        code: "SEC353",
        summary: "GitHub Copilot instruction markdown exceeds the 4000-character guidance limit",
        doc_title: "Copilot instructions: exceeds 4000 chars",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CopilotInstructionMissingApplyToRule {
        code: "SEC354",
        summary: "Path-specific GitHub Copilot instruction markdown is missing `applyTo` frontmatter",
        doc_title: "Copilot instructions: missing `applyTo`",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CopilotInstructionWrongSuffixRule {
        code: "SEC370",
        summary: "Path-specific GitHub Copilot instruction markdown under `.github/instructions/` uses the wrong file suffix",
        doc_title: "Copilot instructions: wrong path-specific suffix",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CopilotInstructionInvalidApplyToRule {
        code: "SEC371",
        summary: "Path-specific GitHub Copilot instruction markdown has an invalid `applyTo` shape",
        doc_title: "Copilot instructions: invalid `applyTo` shape",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CopilotInstructionInvalidApplyToGlobRule {
        code: "SEC377",
        summary: "Path-specific GitHub Copilot instruction markdown has an invalid `applyTo` glob pattern",
        doc_title: "Copilot instructions: invalid `applyTo` glob",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct WildcardToolAccessRule {
        code: "SEC355",
        summary: "AI-native markdown frontmatter grants wildcard tool access",
        doc_title: "AI markdown: wildcard tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CurlAllowedToolsRule {
        code: "SEC419",
        summary: "AI-native markdown frontmatter grants `Bash(curl:*)` authority",
        doc_title: "AI markdown: `Bash(curl:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct WgetAllowedToolsRule {
        code: "SEC420",
        summary: "AI-native markdown frontmatter grants `Bash(wget:*)` authority",
        doc_title: "AI markdown: `Bash(wget:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct SudoAllowedToolsRule {
        code: "SEC463",
        summary: "AI-native markdown frontmatter grants `Bash(sudo:*)` authority",
        doc_title: "AI markdown: `Bash(sudo:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct RmAllowedToolsRule {
        code: "SEC466",
        summary: "AI-native markdown frontmatter grants `Bash(rm:*)` authority",
        doc_title: "AI markdown: `Bash(rm:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ChmodAllowedToolsRule {
        code: "SEC467",
        summary: "AI-native markdown frontmatter grants `Bash(chmod:*)` authority",
        doc_title: "AI markdown: `Bash(chmod:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ChownAllowedToolsRule {
        code: "SEC468",
        summary: "AI-native markdown frontmatter grants `Bash(chown:*)` authority",
        doc_title: "AI markdown: `Bash(chown:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ChgrpAllowedToolsRule {
        code: "SEC469",
        summary: "AI-native markdown frontmatter grants `Bash(chgrp:*)` authority",
        doc_title: "AI markdown: `Bash(chgrp:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct SuAllowedToolsRule {
        code: "SEC470",
        summary: "AI-native markdown frontmatter grants `Bash(su:*)` authority",
        doc_title: "AI markdown: `Bash(su:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitCloneAllowedToolsRule {
        code: "SEC421",
        summary: "AI-native markdown frontmatter grants `Bash(git clone:*)` authority",
        doc_title: "AI markdown: `Bash(git clone:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GitAddAllowedToolsRule {
        code: "SEC432",
        summary: "AI-native markdown frontmatter grants `Bash(git add:*)` authority",
        doc_title: "AI markdown: `Bash(git add:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitFetchAllowedToolsRule {
        code: "SEC433",
        summary: "AI-native markdown frontmatter grants `Bash(git fetch:*)` authority",
        doc_title: "AI markdown: `Bash(git fetch:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WebFetchRawGithubAllowedToolsRule {
        code: "SEC434",
        summary: "AI-native markdown frontmatter grants `WebFetch(domain:raw.githubusercontent.com)` authority",
        doc_title: "AI markdown: raw.githubusercontent.com WebFetch grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitConfigAllowedToolsRule {
        code: "SEC435",
        summary: "AI-native markdown frontmatter grants `Bash(git config:*)` authority",
        doc_title: "AI markdown: `Bash(git config:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitTagAllowedToolsRule {
        code: "SEC436",
        summary: "AI-native markdown frontmatter grants `Bash(git tag:*)` authority",
        doc_title: "AI markdown: `Bash(git tag:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitBranchAllowedToolsRule {
        code: "SEC437",
        summary: "AI-native markdown frontmatter grants `Bash(git branch:*)` authority",
        doc_title: "AI markdown: `Bash(git branch:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitResetAllowedToolsRule {
        code: "SEC438",
        summary: "AI-native markdown frontmatter grants `Bash(git reset:*)` authority",
        doc_title: "AI markdown: `Bash(git reset:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitCleanAllowedToolsRule {
        code: "SEC439",
        summary: "AI-native markdown frontmatter grants `Bash(git clean:*)` authority",
        doc_title: "AI markdown: `Bash(git clean:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitRestoreAllowedToolsRule {
        code: "SEC440",
        summary: "AI-native markdown frontmatter grants `Bash(git restore:*)` authority",
        doc_title: "AI markdown: `Bash(git restore:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitRebaseAllowedToolsRule {
        code: "SEC441",
        summary: "AI-native markdown frontmatter grants `Bash(git rebase:*)` authority",
        doc_title: "AI markdown: `Bash(git rebase:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitMergeAllowedToolsRule {
        code: "SEC442",
        summary: "AI-native markdown frontmatter grants `Bash(git merge:*)` authority",
        doc_title: "AI markdown: `Bash(git merge:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitCherryPickAllowedToolsRule {
        code: "SEC443",
        summary: "AI-native markdown frontmatter grants `Bash(git cherry-pick:*)` authority",
        doc_title: "AI markdown: `Bash(git cherry-pick:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitApplyAllowedToolsRule {
        code: "SEC444",
        summary: "AI-native markdown frontmatter grants `Bash(git apply:*)` authority",
        doc_title: "AI markdown: `Bash(git apply:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GitAmAllowedToolsRule {
        code: "SEC445",
        summary: "AI-native markdown frontmatter grants `Bash(git am:*)` authority",
        doc_title: "AI markdown: `Bash(git am:*)` tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PackageInstallAllowedToolsRule {
        code: "SEC447",
        summary: "AI-native markdown frontmatter grants package installation authority",
        doc_title: "AI markdown: package installation tool grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct UnscopedReadAllowedToolsRule {
        code: "SEC423",
        summary: "AI-native markdown frontmatter grants bare `Read` tool access",
        doc_title: "AI markdown: bare Read tool grant",
        category: Category::Hardening,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct UnscopedWriteAllowedToolsRule {
        code: "SEC424",
        summary: "AI-native markdown frontmatter grants bare `Write` tool access",
        doc_title: "AI markdown: bare Write tool grant",
        category: Category::Hardening,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct UnscopedEditAllowedToolsRule {
        code: "SEC425",
        summary: "AI-native markdown frontmatter grants bare `Edit` tool access",
        doc_title: "AI markdown: bare Edit tool grant",
        category: Category::Hardening,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct UnscopedGlobAllowedToolsRule {
        code: "SEC426",
        summary: "AI-native markdown frontmatter grants bare `Glob` tool access",
        doc_title: "AI markdown: bare Glob tool grant",
        category: Category::Hardening,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct UnscopedGrepAllowedToolsRule {
        code: "SEC427",
        summary: "AI-native markdown frontmatter grants bare `Grep` tool access",
        doc_title: "AI markdown: bare Grep tool grant",
        category: Category::Hardening,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ReadUnsafePathAllowedToolsRule {
        code: "SEC428",
        summary: "AI-native markdown frontmatter grants `Read(...)` over an unsafe repo-external path",
        doc_title: "AI markdown: unsafe Read path grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct WriteUnsafePathAllowedToolsRule {
        code: "SEC429",
        summary: "AI-native markdown frontmatter grants `Write(...)` over an unsafe repo-external path",
        doc_title: "AI markdown: unsafe Write path grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct EditUnsafePathAllowedToolsRule {
        code: "SEC430",
        summary: "AI-native markdown frontmatter grants `Edit(...)` over an unsafe repo-external path",
        doc_title: "AI markdown: unsafe Edit path grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GlobUnsafePathAllowedToolsRule {
        code: "SEC431",
        summary: "AI-native markdown frontmatter grants `Glob(...)` over an unsafe repo-external path",
        doc_title: "AI markdown: unsafe Glob path grant",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginAgentPermissionModeRule {
        code: "SEC356",
        summary: "Plugin agent frontmatter sets `permissionMode`",
        doc_title: "Plugin agent: `permissionMode` in frontmatter",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct PluginAgentHooksFrontmatterRule {
        code: "SEC357",
        summary: "Plugin agent frontmatter sets `hooks`",
        doc_title: "Plugin agent: `hooks` in frontmatter",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct PluginAgentMcpServersFrontmatterRule {
        code: "SEC358",
        summary: "Plugin agent frontmatter sets `mcpServers`",
        doc_title: "Plugin agent: `mcpServers` in frontmatter",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CursorRuleAlwaysApplyTypeRule {
        code: "SEC359",
        summary: "Cursor rule frontmatter `alwaysApply` must be boolean",
        doc_title: "Cursor rule: `alwaysApply` type",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CursorRuleGlobsTypeRule {
        code: "SEC360",
        summary: "Cursor rule frontmatter `globs` must be a sequence of patterns",
        doc_title: "Cursor rule: `globs` type",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CursorRuleRedundantGlobsRule {
        code: "SEC378",
        summary: "Cursor rule frontmatter should not set `globs` when `alwaysApply` is `true`",
        doc_title: "Cursor rule: redundant `globs` with `alwaysApply`",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CursorRuleUnknownFrontmatterKeyRule {
        code: "SEC379",
        summary: "Cursor rule frontmatter contains an unknown key",
        doc_title: "Cursor rule: unknown frontmatter key",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CursorRuleMissingDescriptionRule {
        code: "SEC380",
        summary: "Cursor rule frontmatter should include `description`",
        doc_title: "Cursor rule: missing `description`",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct MarkdownPrivateKeyPemRule {
        code: "SEC312",
        summary: "Markdown contains committed private key material",
        doc_title: "Markdown: private key material",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownFencedPipeShellRule {
        code: "SEC313",
        summary: "Fenced shell example pipes remote content directly into a shell",
        doc_title: "Shell example: remote content piped to shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

pub(crate) static RULE_SPECS: [NativeRuleSpec; 124] = [
    NativeRuleSpec {
        metadata: HtmlCommentDirectiveRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on suspicious phrase heuristics inside hidden HTML comments.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_html_comment_directive,
        safe_fix: Some(remove_hidden_comment_fix),
        suggestion_message: None,
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownDownloadExecRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on prose command heuristics outside code blocks.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "rewrite the command as inert prose or move it into a fenced example block",
        ),
        suggestion_fix: Some(markdown_inline_code_fix),
    },
    NativeRuleSpec {
        metadata: HtmlCommentDownloadExecRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on hidden-comment command heuristics rather than a structural execution model.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_html_comment_download_exec,
        safe_fix: Some(remove_hidden_download_exec_comment_fix),
        suggestion_message: None,
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownBase64ExecRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on prose base64-and-exec text heuristics.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_base64_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove or rewrite the base64 decode-and-exec flow as inert prose or a fenced example",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPathTraversalRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on prose path-traversal and access-verb heuristics.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_path_traversal,
        safe_fix: None,
        suggestion_message: Some(
            "replace parent-directory traversal instructions with project-scoped paths or explicit safe inputs",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownMetadataServiceAccessRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Metadata-service access examples are strong threat-review signals, but labs and cloud-security training content can still reference them legitimately.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_metadata_service_access,
        safe_fix: None,
        suggestion_message: Some(
            "replace direct metadata-service access examples with redacted placeholders or add explicit safety framing",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownMutableMcpLauncherRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Mutable MCP launcher examples in markdown can be legitimate setup guidance, so the first release stays in the explicit supply-chain lane while broader field validation continues.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_mutable_mcp_launcher,
        safe_fix: None,
        suggestion_message: Some(
            "replace mutable MCP launcher examples with pinned alternatives or add explicit supply-chain safety framing",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownClaudeBarePipInstallRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "This rule depends on transcript-shaped markdown plus explicit `uv` preference context in the same AI-native document, so the first release stays guidance-only while broader ecosystem usefulness is measured.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_claude_bare_pip_install,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `pip install` Claude transcript examples with `uv pip install` or mark them as intentionally incorrect pre-correction behavior",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownUnpinnedPipGitInstallRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `pip install` examples that pull directly from mutable git+https sources without commit pinning.",
            malicious_case_ids: &["claude-unpinned-pip-git-install"],
            benign_case_ids: &["claude-unpinned-pip-git-install-commit-pinned-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `pip install` plus `git+https://` token analysis with commit-pin detection inside parsed markdown regions.",
        },
        check: check_markdown_unpinned_pip_git_install,
        safe_fix: None,
        suggestion_message: Some(
            "replace the unpinned `git+https://` install with a commit-pinned reference or a published package release",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPipHttpGitInstallRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `pip install` examples that fetch Python packages from an insecure `git+http://` source.",
            malicious_case_ids: &["skill-pip-http-git-install"],
            benign_case_ids: &["skill-pip-https-git-install-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `pip install` token analysis with `git+http://` detection inside parsed markdown regions.",
        },
        check: check_markdown_pip_http_git_install,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `git+http://` source with a normal TLS-verified `git+https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPipTrustedHostRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `pip install` examples that disable host trust checks with `--trusted-host`.",
            malicious_case_ids: &["skill-pip-trusted-host"],
            benign_case_ids: &["skill-pip-index-url-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `pip install` token analysis with `--trusted-host` detection inside parsed markdown regions.",
        },
        check: check_markdown_pip_trusted_host,
        safe_fix: None,
        suggestion_message: Some(
            "remove `--trusted-host` and use a normal TLS-verified Python package source instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPipHttpIndexRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `pip install` examples that point package index resolution at `http://` sources.",
            malicious_case_ids: &["skill-pip-http-index"],
            benign_case_ids: &["skill-pip-https-index-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `pip install` token analysis with `--index-url http://` or `--extra-index-url http://` detection inside parsed markdown regions.",
        },
        check: check_markdown_pip_http_index,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` package index with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPipHttpFindLinksRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `pip install` examples that point package discovery at `http://` find-links sources.",
            malicious_case_ids: &["skill-pip-http-find-links"],
            benign_case_ids: &["skill-pip-https-find-links-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `pip install` token analysis with `--find-links http://`, `--find-links=http://`, or `-f http://` detection inside parsed markdown regions.",
        },
        check: check_markdown_pip_http_find_links,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` find-links source with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPipConfigHttpIndexRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `pip config set` commands that point package index configuration at `http://` sources.",
            malicious_case_ids: &["skill-pip-config-http-index"],
            benign_case_ids: &["skill-pip-config-https-index-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `pip config set`, `pip3 config set`, or `python -m pip config set` token analysis with `global.index-url http://` or `global.extra-index-url http://` detection inside parsed markdown regions.",
        },
        check: check_markdown_pip_config_http_index,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` package index config with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPipConfigHttpFindLinksRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `pip config set` commands that point package discovery configuration at `http://` find-links sources.",
            malicious_case_ids: &["skill-pip-config-http-find-links"],
            benign_case_ids: &["skill-pip-config-https-find-links-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `pip config set`, `pip3 config set`, or `python -m pip config set` token analysis with `global.find-links http://` detection inside parsed markdown regions.",
        },
        check: check_markdown_pip_config_http_find_links,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` find-links config with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownNpmHttpRegistryRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `npm`, `pnpm`, `yarn`, and `bun` install examples that point dependency resolution at `http://` registries.",
            malicious_case_ids: &["skill-npm-http-registry"],
            benign_case_ids: &["skill-npm-https-registry-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `npm install`, `npm i`, `pnpm add/install`, `yarn add`, or `bun add` token analysis with `--registry http://` detection inside parsed markdown regions.",
        },
        check: check_markdown_npm_http_registry,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` registry with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPipConfigTrustedHostRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `pip config set` commands that configure trusted-host bypass behavior.",
            malicious_case_ids: &["skill-pip-config-trusted-host"],
            benign_case_ids: &["skill-pip-config-unrelated-key-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `pip config set`, `pip3 config set`, or `python -m pip config set` token analysis with `global.trusted-host` detection inside parsed markdown regions.",
        },
        check: check_markdown_pip_config_trusted_host,
        safe_fix: None,
        suggestion_message: Some(
            "remove the trusted-host config and rely on normal TLS-verified Python package sources instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownNetworkTlsBypassRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for exact network-command examples that disable TLS verification, including PowerShell certificate-bypass forms.",
            malicious_case_ids: &[
                "skill-markdown-network-tls-bypass",
                "skill-markdown-network-tls-bypass-powershell",
            ],
            benign_case_ids: &[
                "skill-markdown-network-tls-bypass-warning-safe",
                "skill-markdown-network-tls-bypass-powershell-warning-safe",
            ],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact command-token analysis with `--insecure`, `-k`, `--no-check-certificate`, `-SkipCertificateCheck`, or `NODE_TLS_REJECT_UNAUTHORIZED=0` detection inside parsed markdown regions, with safety-guidance suppression.",
        },
        check: check_markdown_network_tls_bypass,
        safe_fix: None,
        suggestion_message: Some(
            "remove the TLS-bypass flag or env override and keep normal certificate verification enabled for the network command",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownJsPackageConfigHttpRegistryRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for JavaScript package-manager config commands that point registry configuration at `http://` sources.",
            malicious_case_ids: &["skill-js-package-config-http-registry"],
            benign_case_ids: &["skill-js-package-config-https-registry-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `npm config set`, `pnpm config set`, or `yarn config set` token analysis with `registry http://` or `registry=http://` detection inside parsed markdown regions.",
        },
        check: check_markdown_js_package_config_http_registry,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` registry config with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownJsPackageStrictSslFalseRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for JavaScript package-manager config commands that explicitly disable strict SSL verification.",
            malicious_case_ids: &["skill-js-package-strict-ssl-false"],
            benign_case_ids: &["skill-js-package-strict-ssl-true-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `npm config set`, `pnpm config set`, or `yarn config set` token analysis with `strict-ssl false` or `strict-ssl=false` detection inside parsed markdown regions.",
        },
        check: check_markdown_js_package_strict_ssl_false,
        safe_fix: None,
        suggestion_message: Some(
            "remove the strict-ssl disable and keep normal certificate verification enabled for package manager config",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPipHttpSourceRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `pip install` examples that fetch a direct package source over `http://`.",
            malicious_case_ids: &["skill-pip-http-source"],
            benign_case_ids: &["skill-pip-https-source-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `pip install` token analysis with direct `http://` source detection inside parsed markdown regions, excluding `--index-url` and `--extra-index-url` forms already covered by SEC449.",
        },
        check: check_markdown_pip_http_source,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure direct `http://` source with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownNpmHttpSourceRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `npm`, `pnpm`, `yarn`, and `bun` install examples that fetch a direct package source over `http://`.",
            malicious_case_ids: &["skill-npm-http-source"],
            benign_case_ids: &["skill-npm-https-source-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `npm install`, `npm i`, `pnpm add/install`, `yarn add`, or `bun add` token analysis with direct `http://` source detection inside parsed markdown regions, excluding `--registry http://` forms already covered by SEC450.",
        },
        check: check_markdown_npm_http_source,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure direct `http://` source with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownCargoHttpGitInstallRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `cargo install` examples that fetch a crate directly from an `http://` git source.",
            malicious_case_ids: &["skill-cargo-http-git-install"],
            benign_case_ids: &["skill-cargo-https-git-install-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `cargo install` token analysis with `--git http://` detection inside parsed markdown regions.",
        },
        check: check_markdown_cargo_http_git_install,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` git source with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownCargoHttpIndexRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `cargo install` examples that resolve crates through an `http://` index.",
            malicious_case_ids: &["skill-cargo-http-index"],
            benign_case_ids: &["skill-cargo-https-index-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `cargo install` token analysis with `--index http://` detection inside parsed markdown regions.",
        },
        check: check_markdown_cargo_http_index,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` index with a normal TLS-verified `https://` source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownGitHttpCloneRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `git clone` examples that fetch repositories directly from an insecure `http://` source.",
            malicious_case_ids: &["skill-git-http-clone"],
            benign_case_ids: &["skill-git-https-clone-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `git clone` token analysis with direct `http://` source detection inside parsed markdown regions.",
        },
        check: check_markdown_git_http_clone,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` clone source with a normal TLS-verified `https://` repository URL",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownGitHttpRemoteRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for `git remote add` examples that configure a repository remote through an insecure `http://` source.",
            malicious_case_ids: &["skill-git-http-remote"],
            benign_case_ids: &["skill-git-https-remote-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `git remote add` token analysis with direct `http://` source detection inside parsed markdown regions.",
        },
        check: check_markdown_git_http_remote,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure `http://` remote source with a normal TLS-verified `https://` repository URL",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownGitSslVerifyFalseRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for exact `git config` examples that disable Git TLS verification through `http.sslVerify false`.",
            malicious_case_ids: &["skill-git-sslverify-false"],
            benign_case_ids: &["skill-git-sslverify-true-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `git config` token analysis with `http.sslVerify false` or `http.sslVerify=false` detection inside parsed markdown regions, excluding safety-warning phrasing.",
        },
        check: check_markdown_git_sslverify_false,
        safe_fix: None,
        suggestion_message: Some(
            "remove `http.sslVerify false` and keep Git transport verification enabled instead of teaching a shared TLS-bypass workflow",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownGitSslNoVerifyRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for exact Git command examples that disable TLS verification through `GIT_SSL_NO_VERIFY`.",
            malicious_case_ids: &["skill-git-ssl-no-verify"],
            benign_case_ids: &["skill-git-ssl-no-verify-disabled-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `GIT_SSL_NO_VERIFY=1` or `GIT_SSL_NO_VERIFY=true` token analysis when a Git command appears in the same parsed markdown region, excluding safety-warning phrasing.",
        },
        check: check_markdown_git_ssl_no_verify,
        safe_fix: None,
        suggestion_message: Some(
            "remove `GIT_SSL_NO_VERIFY` and keep Git transport verification enabled instead of teaching a shared TLS-bypass workflow",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownGitInlineSslVerifyFalseRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown for exact `git -c` examples that disable Git TLS verification inline through `http.sslVerify=false`.",
            malicious_case_ids: &["skill-git-inline-sslverify-false"],
            benign_case_ids: &["skill-git-inline-sslverify-true-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact `git -c http.sslVerify=false` token analysis inside parsed markdown regions, excluding safety-warning phrasing.",
        },
        check: check_markdown_git_inline_sslverify_false,
        safe_fix: None,
        suggestion_message: Some(
            "remove inline `http.sslVerify=false` and keep Git transport verification enabled instead of teaching a shared TLS-bypass workflow",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownMutableDockerImageRule::METADATA,
        surface: Surface::Markdown,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Mutable Docker image examples in markdown can be legitimate setup guidance, so the first release stays in the explicit supply-chain lane rather than a stronger default posture.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_mutable_docker_image,
        safe_fix: None,
        suggestion_message: Some(
            "replace mutable Docker image examples with digest-pinned alternatives or add explicit reproducibility guidance",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownDockerHostEscapeRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Docker host-escape examples are strong threat-review signals, but infra-debugging and lab material can still document them intentionally.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_docker_host_escape,
        safe_fix: None,
        suggestion_message: Some(
            "replace host-escape Docker examples with safer alternatives or add explicit risk framing and isolation guidance",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: UntrustedInstructionPromotionRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Instruction-boundary promotion in markdown is prose-aware and needs external usefulness review before any stronger posture.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_untrusted_instruction_promotion,
        safe_fix: None,
        suggestion_message: Some(
            "rewrite the instruction so external content stays untrusted context and cannot override developer/system guidance",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ApprovalBypassInstructionRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Approval-bypass guidance in markdown is prose-aware and needs external usefulness review before any stronger posture.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_approval_bypass_instruction,
        safe_fix: None,
        suggestion_message: Some(
            "rewrite the instruction so risky actions require explicit approval or confirmation instead of bypassing it",
        ),
        suggestion_fix: None,
    },
    stable_native_message_rule_spec! {
        metadata: UnscopedBashAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact bare `Bash` grants that expose unconstrained shell authority as shared default policy.",
        malicious_case_ids: &["skill-unscoped-bash-allowed-tools"],
        benign_case_ids: &["skill-scoped-bash-allowed-tools-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `Bash` inside allowed-tools or allowed_tools.",
        check: check_unscoped_bash_allowed_tools,
        suggestion_message: "scope Bash to explicit command patterns like `Bash(git:*)` instead of granting the full Bash tool",
    },
    stable_native_message_rule_spec! {
        metadata: UnscopedWebSearchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for bare WebSearch grants that omit a reviewed search scope.",
        malicious_case_ids: &["skill-risky-frontmatter-tool-grants"],
        benign_case_ids: &["skill-reviewed-frontmatter-tool-grants-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `WebSearch` inside allowed-tools or allowed_tools.",
        check: check_unscoped_websearch_allowed_tools,
        suggestion_message: "replace bare `WebSearch` with a narrower reviewed search pattern or remove broad search authority from the shared frontmatter grant",
    },
    preview_native_message_rule_spec! {
        metadata: GitPushAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        blocker: "Shared git push grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.",
        promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        check: check_git_push_allowed_tools,
        suggestion_message: "review whether shared `Bash(git push)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    preview_native_message_rule_spec! {
        metadata: GitCheckoutAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        blocker: "Shared git checkout grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.",
        promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        check: check_git_checkout_allowed_tools,
        suggestion_message: "review whether shared `Bash(git checkout:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    preview_native_message_rule_spec! {
        metadata: GitCommitAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        blocker: "Shared git commit grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.",
        promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        check: check_git_commit_allowed_tools,
        suggestion_message: "review whether shared `Bash(git commit:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    preview_native_message_rule_spec! {
        metadata: GitStashAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        blocker: "Shared git stash grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.",
        promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        check: check_git_stash_allowed_tools,
        suggestion_message: "review whether shared `Bash(git stash:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: GhPrAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact GitHub pull-request authority through `allowed-tools`.",
        malicious_case_ids: &["skill-gh-pr-allowed-tools"],
        benign_case_ids: &["skill-gh-pr-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh pr:*)` in allowed-tools entries.",
        check: check_gh_pr_allowed_tools,
        suggestion_message: "review whether shared `Bash(gh pr:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: GhApiPostAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact GitHub API POST mutation authority through `allowed-tools`.",
        malicious_case_ids: &["skill-gh-mutation-allowed-tools"],
        benign_case_ids: &["skill-gh-mutation-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh api --method POST:*)` in allowed-tools entries.",
        check: check_gh_api_post_allowed_tools,
        suggestion_message: "review whether shared `Bash(gh api --method POST:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps remote GitHub mutations under explicit user control",
    },
    stable_native_message_rule_spec! {
        metadata: GhApiDeleteAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact GitHub API DELETE mutation authority through `allowed-tools`.",
        malicious_case_ids: &["skill-gh-api-delete-allowed-tools"],
        benign_case_ids: &["skill-gh-api-delete-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh api --method DELETE:*)` in allowed-tools entries.",
        check: check_gh_api_delete_allowed_tools,
        suggestion_message: "review whether shared `Bash(gh api --method DELETE:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps destructive remote GitHub mutations under explicit user control",
    },
    stable_native_message_rule_spec! {
        metadata: GhApiPatchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact GitHub API PATCH mutation authority through `allowed-tools`.",
        malicious_case_ids: &["skill-gh-api-patch-allowed-tools"],
        benign_case_ids: &["skill-gh-api-patch-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh api --method PATCH:*)` in allowed-tools entries.",
        check: check_gh_api_patch_allowed_tools,
        suggestion_message: "review whether shared `Bash(gh api --method PATCH:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps remote GitHub mutations under explicit user control",
    },
    stable_native_message_rule_spec! {
        metadata: GhApiPutAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact GitHub API PUT mutation authority through `allowed-tools`.",
        malicious_case_ids: &["skill-gh-api-put-allowed-tools"],
        benign_case_ids: &["skill-gh-api-put-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh api --method PUT:*)` in allowed-tools entries.",
        check: check_gh_api_put_allowed_tools,
        suggestion_message: "review whether shared `Bash(gh api --method PUT:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps remote GitHub mutations under explicit user control",
    },
    NativeRuleSpec {
        metadata: GhIssueCreateAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub issue creation authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-mutation-allowed-tools"],
            benign_case_ids: &["skill-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh issue create:*)` in allowed-tools entries.",
        },
        check: check_gh_issue_create_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh issue create:*)` access is really needed, or replace it with a narrower reviewed workflow-specific permission",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhRepoCreateAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub repository creation authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-mutation-allowed-tools"],
            benign_case_ids: &["skill-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh repo create:*)` in allowed-tools entries.",
        },
        check: check_gh_repo_create_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh repo create:*)` access is really needed, or replace it with a narrower reviewed workflow-specific permission",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhRepoDeleteAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub repository deletion authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-repo-release-delete-allowed-tools"],
            benign_case_ids: &["skill-gh-repo-release-delete-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh repo delete:*)` in allowed-tools entries.",
        },
        check: check_gh_repo_delete_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh repo delete:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps repository deletion under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhRepoEditAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub repository settings mutation authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-repo-edit-release-create-allowed-tools"],
            benign_case_ids: &["skill-gh-repo-edit-release-create-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh repo edit:*)` in allowed-tools entries.",
        },
        check: check_gh_repo_edit_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh repo edit:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps repository settings mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhRepoTransferAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub repository transfer authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-repo-transfer-release-upload-allowed-tools"],
            benign_case_ids: &["skill-gh-repo-transfer-release-upload-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh repo transfer:*)` in allowed-tools entries.",
        },
        check: check_gh_repo_transfer_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh repo transfer:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps repository transfer under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhReleaseCreateAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub release creation authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-repo-edit-release-create-allowed-tools"],
            benign_case_ids: &["skill-gh-repo-edit-release-create-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh release create:*)` in allowed-tools entries.",
        },
        check: check_gh_release_create_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh release create:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps release publishing under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhReleaseUploadAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub release asset upload authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-repo-transfer-release-upload-allowed-tools"],
            benign_case_ids: &["skill-gh-repo-transfer-release-upload-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh release upload:*)` in allowed-tools entries.",
        },
        check: check_gh_release_upload_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh release upload:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps release asset mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhReleaseDeleteAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub release deletion authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-repo-release-delete-allowed-tools"],
            benign_case_ids: &["skill-gh-repo-release-delete-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh release delete:*)` in allowed-tools entries.",
        },
        check: check_gh_release_delete_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh release delete:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps release deletion under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhSecretSetAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub secret mutation authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-secret-variable-workflow-allowed-tools"],
            benign_case_ids: &["skill-gh-secret-variable-workflow-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh secret set:*)` in allowed-tools entries.",
        },
        check: check_gh_secret_set_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh secret set:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps secret mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhVariableSetAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub variable mutation authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-secret-variable-workflow-allowed-tools"],
            benign_case_ids: &["skill-gh-secret-variable-workflow-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh variable set:*)` in allowed-tools entries.",
        },
        check: check_gh_variable_set_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh variable set:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps GitHub variable mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhWorkflowRunAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub workflow dispatch authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-secret-variable-workflow-allowed-tools"],
            benign_case_ids: &["skill-gh-secret-variable-workflow-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh workflow run:*)` in allowed-tools entries.",
        },
        check: check_gh_workflow_run_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh workflow run:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps remote workflow dispatch under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhSecretDeleteAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub secret deletion authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-mutation-allowed-tools"],
            benign_case_ids: &["skill-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh secret delete:*)` in allowed-tools entries.",
        },
        check: check_gh_secret_delete_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh secret delete:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps secret deletion under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhVariableDeleteAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub variable deletion authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-mutation-allowed-tools"],
            benign_case_ids: &["skill-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh variable delete:*)` in allowed-tools entries.",
        },
        check: check_gh_variable_delete_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh variable delete:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps variable deletion under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GhWorkflowDisableAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native markdown frontmatter for exact GitHub workflow disable authority through `allowed-tools`.",
            malicious_case_ids: &["skill-gh-mutation-allowed-tools"],
            benign_case_ids: &["skill-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(gh workflow disable:*)` in allowed-tools entries.",
        },
        check: check_gh_workflow_disable_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(gh workflow disable:*)` access is really needed, or replace it with a narrower reviewed workflow that keeps workflow disabling under explicit user control",
        ),
        suggestion_fix: None,
    },
    stable_native_message_rule_spec! {
        metadata: WildcardReadAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact `Read(*)` grants that expose unconstrained reading as shared default policy.",
        malicious_case_ids: &["skill-core-wildcard-allowed-tools"],
        benign_case_ids: &["skill-core-wildcard-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Read(*)` inside allowed-tools or allowed_tools.",
        check: check_wildcard_read_allowed_tools,
        suggestion_message: "replace `Read(*)` with narrower reviewed read patterns like `Read(./docs/**)` or remove blanket shared read authority",
    },
    stable_native_message_rule_spec! {
        metadata: WildcardBashAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact `Bash(*)` grants that expose unconstrained shell execution as shared default policy.",
        malicious_case_ids: &["skill-bash-wildcard-allowed-tools"],
        benign_case_ids: &["skill-bash-wildcard-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(*)` inside allowed-tools or allowed_tools.",
        check: check_wildcard_bash_allowed_tools,
        suggestion_message: "replace `Bash(*)` with narrower reviewed command patterns like `Bash(git status:*)` or remove blanket shared shell authority",
    },
    stable_native_message_rule_spec! {
        metadata: WildcardWriteAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact `Write(*)` grants that expose unconstrained mutation as shared default policy.",
        malicious_case_ids: &["skill-core-wildcard-allowed-tools"],
        benign_case_ids: &["skill-core-wildcard-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Write(*)` inside allowed-tools or allowed_tools.",
        check: check_wildcard_write_allowed_tools,
        suggestion_message: "replace `Write(*)` with narrower reviewed write patterns like `Write(./artifacts/**)` or remove blanket shared write authority",
    },
    stable_native_message_rule_spec! {
        metadata: WildcardEditAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact `Edit(*)` grants that expose unconstrained editing as shared default policy.",
        malicious_case_ids: &["skill-core-wildcard-allowed-tools"],
        benign_case_ids: &["skill-core-wildcard-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Edit(*)` inside allowed-tools or allowed_tools.",
        check: check_wildcard_edit_allowed_tools,
        suggestion_message: "replace `Edit(*)` with narrower reviewed edit patterns like `Edit(./docs/**)` or remove blanket shared edit authority",
    },
    stable_native_message_rule_spec! {
        metadata: WildcardGlobAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact `Glob(*)` grants that expose unconstrained file discovery as shared default policy.",
        malicious_case_ids: &["skill-core-wildcard-allowed-tools"],
        benign_case_ids: &["skill-core-wildcard-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Glob(*)` inside allowed-tools or allowed_tools.",
        check: check_wildcard_glob_allowed_tools,
        suggestion_message: "replace `Glob(*)` with narrower reviewed discovery patterns like `Glob(./docs/**)` or remove blanket shared discovery authority",
    },
    stable_native_message_rule_spec! {
        metadata: WildcardGrepAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact `Grep(*)` grants that expose unconstrained content search as shared default policy.",
        malicious_case_ids: &["skill-core-wildcard-allowed-tools"],
        benign_case_ids: &["skill-core-wildcard-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Grep(*)` inside allowed-tools or allowed_tools.",
        check: check_wildcard_grep_allowed_tools,
        suggestion_message: "replace `Grep(*)` with narrower reviewed search patterns like `Grep(todo:)` or remove blanket shared search authority",
    },
    stable_native_message_rule_spec! {
        metadata: WildcardWebFetchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact `WebFetch(*)` grants that expose unconstrained remote fetch authority as shared default policy.",
        malicious_case_ids: &["skill-core-wildcard-allowed-tools"],
        benign_case_ids: &["skill-core-wildcard-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `WebFetch(*)` inside allowed-tools or allowed_tools.",
        check: check_wildcard_webfetch_allowed_tools,
        suggestion_message: "replace `WebFetch(*)` with narrower reviewed fetch scopes like `WebFetch(domain:docs.example.com)` or remove blanket shared network fetch authority",
    },
    stable_native_message_rule_spec! {
        metadata: WildcardWebSearchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact `WebSearch(*)` grants that expose unconstrained search authority as shared default policy.",
        malicious_case_ids: &["skill-core-wildcard-allowed-tools"],
        benign_case_ids: &["skill-core-wildcard-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `WebSearch(*)` inside allowed-tools or allowed_tools.",
        check: check_wildcard_websearch_allowed_tools,
        suggestion_message: "replace `WebSearch(*)` with narrower reviewed search scopes like `WebSearch(site:docs.example.com)` or remove blanket shared search authority",
    },
    stable_native_message_rule_spec! {
        metadata: NpmExecAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact mutable `npm exec` authority through `allowed-tools`.",
        malicious_case_ids: &["skill-npm-exec-bunx-allowed-tools"],
        benign_case_ids: &["skill-npm-exec-bunx-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(npm exec:*)` in allowed-tools entries.",
        check: check_npm_exec_allowed_tools,
        suggestion_message: "review whether shared `Bash(npm exec:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: BunxAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact mutable `bunx` authority through `allowed-tools`.",
        malicious_case_ids: &["skill-npm-exec-bunx-allowed-tools"],
        benign_case_ids: &["skill-npm-exec-bunx-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(bunx:*)` in allowed-tools entries.",
        check: check_bunx_allowed_tools,
        suggestion_message: "review whether shared `Bash(bunx:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: UvxAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact mutable `uvx` authority through `allowed-tools`.",
        malicious_case_ids: &["skill-uvx-dlx-pipx-allowed-tools"],
        benign_case_ids: &["skill-uvx-dlx-pipx-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(uvx:*)` in allowed-tools entries.",
        check: check_uvx_allowed_tools,
        suggestion_message: "review whether shared `Bash(uvx:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: PnpmDlxAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact mutable `pnpm dlx` authority through `allowed-tools`.",
        malicious_case_ids: &["skill-uvx-dlx-pipx-allowed-tools"],
        benign_case_ids: &["skill-uvx-dlx-pipx-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(pnpm dlx:*)` in allowed-tools entries.",
        check: check_pnpm_dlx_allowed_tools,
        suggestion_message: "review whether shared `Bash(pnpm dlx:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: YarnDlxAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact mutable `yarn dlx` authority through `allowed-tools`.",
        malicious_case_ids: &["skill-uvx-dlx-pipx-allowed-tools"],
        benign_case_ids: &["skill-uvx-dlx-pipx-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(yarn dlx:*)` in allowed-tools entries.",
        check: check_yarn_dlx_allowed_tools,
        suggestion_message: "review whether shared `Bash(yarn dlx:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: PipxRunAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact mutable `pipx run` authority through `allowed-tools`.",
        malicious_case_ids: &["skill-uvx-dlx-pipx-allowed-tools"],
        benign_case_ids: &["skill-uvx-dlx-pipx-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(pipx run:*)` in allowed-tools entries.",
        check: check_pipx_run_allowed_tools,
        suggestion_message: "review whether shared `Bash(pipx run:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: NpxAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact mutable `npx` authority through `allowed-tools`.",
        malicious_case_ids: &["skill-npx-git-ls-remote-allowed-tools"],
        benign_case_ids: &["skill-npx-git-ls-remote-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(npx:*)` in allowed-tools entries.",
        check: check_npx_allowed_tools,
        suggestion_message: "review whether shared `Bash(npx:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: GitLsRemoteAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native markdown frontmatter for exact remote repository inspection authority through `allowed-tools`.",
        malicious_case_ids: &["skill-npx-git-ls-remote-allowed-tools"],
        benign_case_ids: &["skill-npx-git-ls-remote-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter string detection for `Bash(git ls-remote:*)` in allowed-tools entries.",
        check: check_git_ls_remote_allowed_tools,
        suggestion_message: "review whether shared `Bash(git ls-remote:*)` access is really needed, or replace it with a narrower workflow-specific permission",
    },
    stable_native_message_rule_spec! {
        metadata: UnscopedWebFetchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for exact bare `WebFetch` grants that expose unconstrained remote fetch authority as shared default policy.",
        malicious_case_ids: &["skill-unscoped-webfetch-allowed-tools"],
        benign_case_ids: &["skill-scoped-webfetch-allowed-tools-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `WebFetch` inside allowed-tools or allowed_tools.",
        check: check_unscoped_webfetch_allowed_tools,
        suggestion_message: "replace bare `WebFetch` with a narrower reviewed fetch pattern or remove broad fetch authority from the shared frontmatter grant",
    },
    stable_native_message_rule_spec! {
        metadata: CurlAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for explicit wildcard curl grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-curl-allowed-tools"],
        benign_case_ids: &["skill-curl-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(curl:*)` inside allowed-tools or allowed_tools.",
        check: check_curl_allowed_tools,
        suggestion_message: "review whether shared `Bash(curl:*)` authority is really needed, or replace it with a narrower reviewed fetch workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: WgetAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for explicit wildcard wget grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-wget-allowed-tools"],
        benign_case_ids: &["skill-wget-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(wget:*)` inside allowed-tools or allowed_tools.",
        check: check_wget_allowed_tools,
        suggestion_message: "review whether shared `Bash(wget:*)` authority is really needed, or replace it with a narrower reviewed fetch workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: SudoAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for explicit wildcard sudo grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-sudo-allowed-tools"],
        benign_case_ids: &["skill-sudo-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(sudo:*)` inside allowed-tools or allowed_tools.",
        check: check_sudo_allowed_tools,
        suggestion_message: "review whether shared `Bash(sudo:*)` authority is really needed, or replace it with a narrower reviewed privileged workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: RmAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for explicit wildcard rm grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-rm-allowed-tools"],
        benign_case_ids: &["skill-rm-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(rm:*)` inside allowed-tools or allowed_tools.",
        check: check_rm_allowed_tools,
        suggestion_message: "review whether shared `Bash(rm:*)` authority is really needed, or replace it with a narrower reviewed cleanup workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: ChmodAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for explicit wildcard chmod grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-chmod-allowed-tools"],
        benign_case_ids: &["skill-chmod-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(chmod:*)` inside allowed-tools or allowed_tools.",
        check: check_chmod_allowed_tools,
        suggestion_message: "review whether shared `Bash(chmod:*)` authority is really needed, or replace it with a narrower reviewed permission-change workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: ChownAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for explicit wildcard chown grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-chown-allowed-tools"],
        benign_case_ids: &["skill-chown-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(chown:*)` inside allowed-tools or allowed_tools.",
        check: check_chown_allowed_tools,
        suggestion_message: "review whether shared `Bash(chown:*)` authority is really needed, or replace it with a narrower reviewed ownership-change workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: ChgrpAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for explicit wildcard chgrp grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-chgrp-allowed-tools"],
        benign_case_ids: &["skill-chgrp-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(chgrp:*)` inside allowed-tools or allowed_tools.",
        check: check_chgrp_allowed_tools,
        suggestion_message: "review whether shared `Bash(chgrp:*)` authority is really needed, or replace it with a narrower reviewed group-change workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: SuAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for explicit wildcard su grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-su-allowed-tools"],
        benign_case_ids: &["skill-su-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(su:*)` inside allowed-tools or allowed_tools.",
        check: check_su_allowed_tools,
        suggestion_message: "review whether shared `Bash(su:*)` authority is really needed, or replace it with a narrower reviewed privilege-switch workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: GitCloneAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for wildcard git clone grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-git-clone-allowed-tools"],
        benign_case_ids: &["skill-git-clone-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git clone:*)` inside allowed-tools or allowed_tools.",
        check: check_git_clone_allowed_tools,
        suggestion_message: "review whether shared `Bash(git clone:*)` authority is really needed, or replace it with a narrower reviewed fetch workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: GitAddAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for wildcard git add grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-git-add-allowed-tools"],
        benign_case_ids: &["skill-git-add-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git add:*)` inside allowed-tools or allowed_tools.",
        check: check_git_add_allowed_tools,
        suggestion_message: "review whether shared `Bash(git add:*)` authority is really needed, or replace it with a narrower reviewed staging workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: GitFetchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for wildcard git fetch grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-git-fetch-allowed-tools"],
        benign_case_ids: &["skill-git-fetch-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git fetch:*)` inside allowed-tools or allowed_tools.",
        check: check_git_fetch_allowed_tools,
        suggestion_message: "review whether shared `Bash(git fetch:*)` authority is really needed, or replace it with a narrower reviewed fetch workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: WebFetchRawGithubAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for explicit raw GitHub content fetch grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-webfetch-raw-github-allowed-tools"],
        benign_case_ids: &["skill-webfetch-raw-github-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `WebFetch(domain:raw.githubusercontent.com)` inside allowed-tools or allowed_tools.",
        check: check_webfetch_raw_github_allowed_tools,
        suggestion_message: "replace `WebFetch(domain:raw.githubusercontent.com)` with a narrower reviewed documentation host or remove broad raw GitHub fetch authority from shared frontmatter",
    },
    stable_native_message_rule_spec! {
        metadata: GitConfigAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for wildcard git config grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-git-config-allowed-tools"],
        benign_case_ids: &["skill-git-config-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git config:*)` inside allowed-tools or allowed_tools.",
        check: check_git_config_allowed_tools,
        suggestion_message: "review whether shared `Bash(git config:*)` authority is really needed, or replace it with a narrower reviewed config workflow instead of a default team-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: GitTagAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for wildcard git tag grants in shared allowed-tools policy.",
        malicious_case_ids: &["skill-git-tag-allowed-tools"],
        benign_case_ids: &["skill-git-tag-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git tag:*)` inside allowed-tools or allowed_tools.",
        check: check_git_tag_allowed_tools,
        suggestion_message: "review whether shared `Bash(git tag:*)` authority is really needed, or replace it with a narrower reviewed tagging workflow instead of a default team-wide grant",
    },
    NativeRuleSpec {
        metadata: GitBranchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git branch grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-branch-allowed-tools"],
            benign_case_ids: &["skill-git-branch-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git branch:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_branch_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git branch:*)` authority is really needed, or replace it with a narrower reviewed branch workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitResetAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git reset grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-reset-allowed-tools"],
            benign_case_ids: &["skill-git-reset-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git reset:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_reset_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git reset:*)` authority is really needed, or replace it with a narrower reviewed reset workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitCleanAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git clean grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-clean-allowed-tools"],
            benign_case_ids: &["skill-git-clean-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git clean:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_clean_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git clean:*)` authority is really needed, or replace it with a narrower reviewed cleanup workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitRestoreAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git restore grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-restore-allowed-tools"],
            benign_case_ids: &["skill-git-restore-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git restore:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_restore_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git restore:*)` authority is really needed, or replace it with a narrower reviewed restore workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitRebaseAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git rebase grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-rebase-allowed-tools"],
            benign_case_ids: &["skill-git-rebase-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git rebase:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_rebase_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git rebase:*)` authority is really needed, or replace it with a narrower reviewed history-rewrite workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitMergeAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git merge grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-merge-allowed-tools"],
            benign_case_ids: &["skill-git-merge-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git merge:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_merge_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git merge:*)` authority is really needed, or replace it with a narrower reviewed merge workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitCherryPickAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git cherry-pick grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-cherry-pick-allowed-tools"],
            benign_case_ids: &["skill-git-cherry-pick-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git cherry-pick:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_cherry_pick_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git cherry-pick:*)` authority is really needed, or replace it with a narrower reviewed cherry-pick workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitApplyAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git apply grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-apply-allowed-tools"],
            benign_case_ids: &["skill-git-apply-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git apply:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_apply_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git apply:*)` authority is really needed, or replace it with a narrower reviewed patch-application workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitAmAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git am grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-am-allowed-tools"],
            benign_case_ids: &["skill-git-am-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git am:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_am_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git am:*)` authority is really needed, or replace it with a narrower reviewed email-patch workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PackageInstallAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for shared package-install grants in allowed-tools policy.",
            malicious_case_ids: &["skill-package-install-allowed-tools"],
            benign_case_ids: &["skill-package-command-allowed-tools-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for package-install permissions such as `Bash(pip install)` and `Bash(npm install)` inside allowed-tools or allowed_tools.",
        },
        check: check_package_install_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace shared package-install authority with a narrower reviewed workflow or remove install privileges from shared frontmatter",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: UnscopedReadAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for bare Read grants that omit a reviewed repo-local scope.",
            malicious_case_ids: &["skill-unscoped-read-allowed-tools"],
            benign_case_ids: &["skill-unscoped-read-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `Read` inside allowed-tools or allowed_tools.",
        },
        check: check_unscoped_read_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared bare `Read` authority is really needed, or replace it with a narrower workflow-specific read scope instead of a default repo-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: UnscopedWriteAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for bare Write grants that omit a reviewed repo-local scope.",
            malicious_case_ids: &["skill-unscoped-write-allowed-tools"],
            benign_case_ids: &["skill-unscoped-write-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `Write` inside allowed-tools or allowed_tools.",
        },
        check: check_unscoped_write_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared bare `Write` authority is really needed, or replace it with a narrower workflow-specific write scope instead of a default repo-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: UnscopedEditAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for bare Edit grants that omit a reviewed repo-local scope.",
            malicious_case_ids: &["skill-unscoped-edit-allowed-tools"],
            benign_case_ids: &["skill-unscoped-edit-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `Edit` inside allowed-tools or allowed_tools.",
        },
        check: check_unscoped_edit_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared bare `Edit` authority is really needed, or replace it with a narrower workflow-specific edit scope instead of a default repo-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CopilotInstructionTooLongRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Long Copilot instruction files can still be intentional, so the first release stays guidance-only while usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_copilot_instruction_too_long,
        safe_fix: None,
        suggestion_message: Some(
            "split repository-level Copilot instructions into shorter shared guidance plus path-specific `.instructions.md` files",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CopilotInstructionMissingApplyToRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Missing `applyTo` on path-specific Copilot instruction files is deterministic, but the first release stays guidance-only while external usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_copilot_instruction_missing_apply_to,
        safe_fix: None,
        suggestion_message: Some(
            "add `applyTo` frontmatter to path-specific Copilot instructions or move the content into shared `.github/copilot-instructions.md` guidance",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CopilotInstructionWrongSuffixRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wrong suffix on path-specific Copilot instruction files is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_copilot_instruction_wrong_suffix,
        safe_fix: None,
        suggestion_message: Some(
            "rename path-specific Copilot instructions to `*.instructions.md` or move repository-wide guidance into `.github/copilot-instructions.md`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CopilotInstructionInvalidApplyToRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Invalid `applyTo` shape on path-specific Copilot instruction files is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_copilot_instruction_invalid_apply_to,
        safe_fix: None,
        suggestion_message: Some(
            "set `applyTo` to a non-empty string or a sequence of non-empty glob strings so Copilot can target files consistently",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CopilotInstructionInvalidApplyToGlobRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Invalid `applyTo` glob patterns on path-specific Copilot instruction files are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_copilot_instruction_invalid_apply_to_glob,
        safe_fix: None,
        suggestion_message: Some(
            "replace `applyTo` with valid glob patterns so Copilot can target files consistently",
        ),
        suggestion_fix: None,
    },
    stable_native_message_rule_spec! {
        metadata: UnscopedGlobAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for bare Glob grants that omit a reviewed repo-local discovery scope.",
        malicious_case_ids: &["skill-unscoped-glob-allowed-tools"],
        benign_case_ids: &["skill-unscoped-glob-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `Glob` inside allowed-tools or allowed_tools.",
        check: check_unscoped_glob_allowed_tools,
        suggestion_message: "review whether shared bare `Glob` authority is really needed, or replace it with narrower workflow-specific discovery patterns instead of a default repo-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: UnscopedGrepAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for bare Grep grants that omit a reviewed search scope.",
        malicious_case_ids: &["skill-unscoped-grep-allowed-tools"],
        benign_case_ids: &["skill-unscoped-grep-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `Grep` inside allowed-tools or allowed_tools.",
        check: check_unscoped_grep_allowed_tools,
        suggestion_message: "review whether shared bare `Grep` authority is really needed, or replace it with narrower workflow-specific search patterns instead of a default repo-wide grant",
    },
    stable_native_message_rule_spec! {
        metadata: ReadUnsafePathAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for `Read(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.",
        malicious_case_ids: &["skill-read-unsafe-path-allowed-tools"],
        benign_case_ids: &["skill-read-unsafe-path-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token analysis for `Read(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.",
        check: check_read_unsafe_path_allowed_tools,
        suggestion_message: "replace repo-external `Read(...)` grants with narrower repo-local paths like `Read(./docs/**)` or remove shared read access outside the project",
    },
    stable_native_message_rule_spec! {
        metadata: WriteUnsafePathAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for `Write(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.",
        malicious_case_ids: &["skill-write-unsafe-path-allowed-tools"],
        benign_case_ids: &["skill-write-unsafe-path-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token analysis for `Write(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.",
        check: check_write_unsafe_path_allowed_tools,
        suggestion_message: "replace repo-external `Write(...)` grants with narrower repo-local paths like `Write(./artifacts/**)` or remove shared write access outside the project",
    },
    stable_native_message_rule_spec! {
        metadata: EditUnsafePathAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for `Edit(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.",
        malicious_case_ids: &["skill-edit-unsafe-path-allowed-tools"],
        benign_case_ids: &["skill-edit-unsafe-path-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token analysis for `Edit(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.",
        check: check_edit_unsafe_path_allowed_tools,
        suggestion_message: "replace repo-external `Edit(...)` grants with narrower repo-local paths like `Edit(./docs/**)` or remove shared edit access outside the project",
    },
    stable_native_message_rule_spec! {
        metadata: GlobUnsafePathAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Checks AI-native frontmatter for `Glob(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.",
        malicious_case_ids: &["skill-glob-unsafe-path-allowed-tools"],
        benign_case_ids: &["skill-glob-unsafe-path-allowed-tools-specific-safe"],
        deterministic_signal_basis: "MarkdownSignals exact frontmatter token analysis for `Glob(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.",
        check: check_glob_unsafe_path_allowed_tools,
        suggestion_message: "replace repo-external `Glob(...)` grants with narrower repo-local discovery patterns like `Glob(./docs/**)` or remove shared file-discovery access outside the project",
    },
    NativeRuleSpec {
        metadata: WildcardToolAccessRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard tool grants in AI-native frontmatter can still appear in convenience-oriented docs, so the first release stays least-privilege guidance-only.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_wildcard_tool_access,
        safe_fix: None,
        suggestion_message: Some(
            "replace wildcard tool access with an explicit allowlist of only the tools the workflow actually needs",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginAgentPermissionModeRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Plugin agent frontmatter can still include unsupported permission policy experiments, so the first release stays spec-guidance-only.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_plugin_agent_permission_mode,
        safe_fix: None,
        suggestion_message: Some(
            "remove `permissionMode` from plugin agent frontmatter and manage permissions in plugin or user-level configuration instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginAgentHooksFrontmatterRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Plugin agent frontmatter can still include unsupported hook experiments, so the first release stays spec-guidance-only.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_plugin_agent_hooks_frontmatter,
        safe_fix: None,
        suggestion_message: Some(
            "remove `hooks` from plugin agent frontmatter and keep hook execution in plugin-level hook configuration instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginAgentMcpServersFrontmatterRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Plugin agent frontmatter can still include unsupported MCP server experiments, so the first release stays spec-guidance-only.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_plugin_agent_mcp_servers_frontmatter,
        safe_fix: None,
        suggestion_message: Some(
            "remove `mcpServers` from plugin agent frontmatter and define MCP servers in plugin or client configuration instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CursorRuleAlwaysApplyTypeRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Cursor rule frontmatter shape mismatches are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_cursor_rule_always_apply_type,
        safe_fix: None,
        suggestion_message: Some(
            "set `alwaysApply` to a boolean like `true` or `false` so Cursor rule loaders interpret the file consistently",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CursorRuleGlobsTypeRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Cursor rule path-matching shape mismatches are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_cursor_rule_globs_type,
        safe_fix: None,
        suggestion_message: Some(
            "set `globs` to a YAML sequence like `[\"**/*.ts\", \"**/*.tsx\"]` so Cursor rule loaders interpret path targeting consistently",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CursorRuleRedundantGlobsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Redundant `globs` alongside `alwaysApply: true` is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_cursor_rule_redundant_globs,
        safe_fix: None,
        suggestion_message: Some(
            "remove `globs` when `alwaysApply` is `true`, or set `alwaysApply: false` if the rule should stay path-scoped",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CursorRuleUnknownFrontmatterKeyRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Unknown Cursor rule frontmatter keys are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_cursor_rule_unknown_frontmatter_key,
        safe_fix: None,
        suggestion_message: Some(
            "remove unknown frontmatter keys or migrate them to supported Cursor rule fields like `description`, `globs`, or `alwaysApply`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CursorRuleMissingDescriptionRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GUIDANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Missing `description` on Cursor rules is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_cursor_rule_missing_description,
        safe_fix: None,
        suggestion_message: Some(
            "add a short `description` explaining when the Cursor rule should apply so shared rule packs stay reviewable",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownPrivateKeyPemRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit committed private-key PEM markers inside agent markdown surfaces.",
            malicious_case_ids: &["skill-private-key-pem"],
            benign_case_ids: &["skill-public-key-pem-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals private-key marker observation across parsed markdown regions excluding placeholder examples.",
        },
        check: check_markdown_private_key_pem,
        safe_fix: None,
        suggestion_message: Some(
            "remove committed private key material and replace it with redacted or placeholder guidance",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: MarkdownFencedPipeShellRule::METADATA,
        surface: Surface::Markdown,
        default_presets: THREAT_REVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on fenced shell-example command heuristics and still needs broader external precision review.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_markdown_fenced_pipe_shell,
        safe_fix: None,
        suggestion_message: Some(
            "rewrite the fenced example to download first or explain the command without piping directly into a shell",
        ),
        suggestion_fix: None,
    },
];

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    &RULE_SPECS
}
