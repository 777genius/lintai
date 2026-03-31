use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::markdown_rules::{
    check_approval_bypass_instruction, check_copilot_instruction_invalid_apply_to,
    check_copilot_instruction_invalid_apply_to_glob, check_copilot_instruction_missing_apply_to,
    check_copilot_instruction_too_long, check_copilot_instruction_wrong_suffix,
    check_curl_allowed_tools, check_cursor_rule_always_apply_type, check_cursor_rule_globs_type,
    check_cursor_rule_missing_description, check_cursor_rule_redundant_globs,
    check_cursor_rule_unknown_frontmatter_key, check_edit_unsafe_path_allowed_tools,
    check_git_add_allowed_tools, check_git_am_allowed_tools, check_git_apply_allowed_tools,
    check_git_branch_allowed_tools, check_git_checkout_allowed_tools,
    check_git_cherry_pick_allowed_tools, check_git_clean_allowed_tools,
    check_git_clone_allowed_tools, check_git_commit_allowed_tools, check_git_config_allowed_tools,
    check_git_fetch_allowed_tools, check_git_merge_allowed_tools, check_git_push_allowed_tools,
    check_git_rebase_allowed_tools, check_git_reset_allowed_tools, check_git_restore_allowed_tools,
    check_git_stash_allowed_tools, check_git_tag_allowed_tools,
    check_glob_unsafe_path_allowed_tools, check_html_comment_directive,
    check_html_comment_download_exec, check_markdown_base64_exec,
    check_markdown_claude_bare_pip_install, check_markdown_docker_host_escape,
    check_markdown_download_exec, check_markdown_fenced_pipe_shell,
    check_markdown_metadata_service_access, check_markdown_mutable_docker_image,
    check_markdown_mutable_mcp_launcher, check_markdown_path_traversal,
    check_markdown_private_key_pem, check_markdown_unpinned_pip_git_install,
    check_package_install_allowed_tools, check_plugin_agent_hooks_frontmatter,
    check_plugin_agent_mcp_servers_frontmatter, check_plugin_agent_permission_mode,
    check_read_unsafe_path_allowed_tools, check_unscoped_bash_allowed_tools,
    check_unscoped_edit_allowed_tools, check_unscoped_glob_allowed_tools,
    check_unscoped_grep_allowed_tools, check_unscoped_read_allowed_tools,
    check_unscoped_webfetch_allowed_tools, check_unscoped_websearch_allowed_tools,
    check_unscoped_write_allowed_tools, check_untrusted_instruction_promotion,
    check_webfetch_raw_github_allowed_tools, check_wget_allowed_tools, check_wildcard_tool_access,
    check_write_unsafe_path_allowed_tools,
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
        category: Category::Security,
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
        category: Category::Security,
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
        category: Category::Security,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Stable,
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
        tier: RuleTier::Stable,
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
        category: Category::Security,
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
        category: Category::Security,
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
        category: Category::Security,
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
        category: Category::Security,
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
        category: Category::Security,
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
        category: Category::Security,
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
        category: Category::Security,
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
        category: Category::Security,
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

pub(crate) const RULE_SPECS: [NativeRuleSpec; 63] = [
    NativeRuleSpec {
        metadata: HtmlCommentDirectiveRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Metadata-service examples can appear in legitimate security training content, so the first release stays guidance-only.",
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
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Mutable MCP launcher examples in markdown can be legitimate setup guidance, so the first release stays guidance-only.",
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        metadata: MarkdownMutableDockerImageRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Mutable Docker image examples in markdown can be legitimate setup guidance, so the first release stays guidance-only.",
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
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Docker host-escape examples in markdown can be legitimate ops guidance, so the first release stays guidance-only.",
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
    NativeRuleSpec {
        metadata: UnscopedBashAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "External validation now shows strong usefulness, but promotion still requires the completed stable checklist and one broader cross-cohort precision pass.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_unscoped_bash_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "scope Bash to explicit command patterns like `Bash(git:*)` instead of granting the full Bash tool",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: UnscopedWebSearchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Bare WebSearch grants in AI-native frontmatter are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_unscoped_websearch_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `WebSearch` with a narrower reviewed search pattern or remove broad search authority from the shared frontmatter grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitPushAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git push grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_git_push_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git push)` access is really needed, or replace it with a narrower workflow-specific permission",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitCheckoutAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git checkout grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_git_checkout_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git checkout:*)` access is really needed, or replace it with a narrower workflow-specific permission",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitCommitAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git commit grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_git_commit_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git commit:*)` access is really needed, or replace it with a narrower workflow-specific permission",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitStashAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: GOVERNANCE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git stash grants in AI-native frontmatter can be legitimate workflow policy, so the first release stays in the opt-in governance lane while usefulness and default posture are measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_git_stash_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git stash:*)` access is really needed, or replace it with a narrower workflow-specific permission",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: UnscopedWebFetchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Bare WebFetch grants in AI-native frontmatter are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_unscoped_webfetch_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `WebFetch` with a narrower reviewed fetch pattern or remove broad fetch authority from the shared frontmatter grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CurlAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for explicit wildcard curl grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-curl-allowed-tools"],
            benign_case_ids: &["skill-curl-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(curl:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_curl_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(curl:*)` authority is really needed, or replace it with a narrower reviewed fetch workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: WgetAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for explicit wildcard wget grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-wget-allowed-tools"],
            benign_case_ids: &["skill-wget-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(wget:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_wget_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(wget:*)` authority is really needed, or replace it with a narrower reviewed fetch workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitCloneAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git clone grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-clone-allowed-tools"],
            benign_case_ids: &["skill-git-clone-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git clone:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_clone_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git clone:*)` authority is really needed, or replace it with a narrower reviewed fetch workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitAddAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git add grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-add-allowed-tools"],
            benign_case_ids: &["skill-git-add-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git add:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_add_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git add:*)` authority is really needed, or replace it with a narrower reviewed staging workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitFetchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git fetch grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-fetch-allowed-tools"],
            benign_case_ids: &["skill-git-fetch-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git fetch:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_fetch_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git fetch:*)` authority is really needed, or replace it with a narrower reviewed fetch workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: WebFetchRawGithubAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for explicit raw GitHub content fetch grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-webfetch-raw-github-allowed-tools"],
            benign_case_ids: &["skill-webfetch-raw-github-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `WebFetch(domain:raw.githubusercontent.com)` inside allowed-tools or allowed_tools.",
        },
        check: check_webfetch_raw_github_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace `WebFetch(domain:raw.githubusercontent.com)` with a narrower reviewed documentation host or remove broad raw GitHub fetch authority from shared frontmatter",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitConfigAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git config grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-config-allowed-tools"],
            benign_case_ids: &["skill-git-config-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git config:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_config_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git config:*)` authority is really needed, or replace it with a narrower reviewed config workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitTagAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for wildcard git tag grants in shared allowed-tools policy.",
            malicious_case_ids: &["skill-git-tag-allowed-tools"],
            benign_case_ids: &["skill-git-tag-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for `Bash(git tag:*)` inside allowed-tools or allowed_tools.",
        },
        check: check_git_tag_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "review whether shared `Bash(git tag:*)` authority is really needed, or replace it with a narrower reviewed tagging workflow instead of a default team-wide grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GitBranchAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
            "replace bare `Read` with a narrower reviewed read pattern or remove broad file-read authority from the shared frontmatter grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: UnscopedWriteAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
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
            "replace bare `Write` with a narrower reviewed write pattern or remove broad file-write authority from the shared frontmatter grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: UnscopedEditAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
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
            "replace bare `Edit` with a narrower reviewed edit pattern or remove broad file-edit authority from the shared frontmatter grant",
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
    NativeRuleSpec {
        metadata: UnscopedGlobAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for bare Glob grants that omit a reviewed repo-local discovery scope.",
            malicious_case_ids: &["skill-unscoped-glob-allowed-tools"],
            benign_case_ids: &["skill-unscoped-glob-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `Glob` inside allowed-tools or allowed_tools.",
        },
        check: check_unscoped_glob_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `Glob` with narrower reviewed glob patterns or remove broad file-discovery authority from the shared frontmatter grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: UnscopedGrepAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for bare Grep grants that omit a reviewed search scope.",
            malicious_case_ids: &["skill-unscoped-grep-allowed-tools"],
            benign_case_ids: &["skill-unscoped-grep-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token detection for bare `Grep` inside allowed-tools or allowed_tools.",
        },
        check: check_unscoped_grep_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `Grep` with narrower reviewed grep patterns or remove broad content-search authority from the shared frontmatter grant",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ReadUnsafePathAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for `Read(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.",
            malicious_case_ids: &["skill-read-unsafe-path-allowed-tools"],
            benign_case_ids: &["skill-read-unsafe-path-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token analysis for `Read(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.",
        },
        check: check_read_unsafe_path_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace repo-external `Read(...)` grants with narrower repo-local paths like `Read(./docs/**)` or remove shared read access outside the project",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: WriteUnsafePathAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for `Write(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.",
            malicious_case_ids: &["skill-write-unsafe-path-allowed-tools"],
            benign_case_ids: &["skill-write-unsafe-path-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token analysis for `Write(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.",
        },
        check: check_write_unsafe_path_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace repo-external `Write(...)` grants with narrower repo-local paths like `Write(./artifacts/**)` or remove shared write access outside the project",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: EditUnsafePathAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for `Edit(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.",
            malicious_case_ids: &["skill-edit-unsafe-path-allowed-tools"],
            benign_case_ids: &["skill-edit-unsafe-path-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token analysis for `Edit(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.",
        },
        check: check_edit_unsafe_path_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace repo-external `Edit(...)` grants with narrower repo-local paths like `Edit(./docs/**)` or remove shared edit access outside the project",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GlobUnsafePathAllowedToolsRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks AI-native frontmatter for `Glob(...)` grants scoped to absolute, home-relative, drive-letter, or parent-traversing paths outside the repository boundary.",
            malicious_case_ids: &["skill-glob-unsafe-path-allowed-tools"],
            benign_case_ids: &["skill-glob-unsafe-path-allowed-tools-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "MarkdownSignals exact frontmatter token analysis for `Glob(...)` scopes with absolute, home-relative, drive-letter, or parent-traversing path markers.",
        },
        check: check_glob_unsafe_path_allowed_tools,
        safe_fix: None,
        suggestion_message: Some(
            "replace repo-external `Glob(...)` grants with narrower repo-local discovery patterns like `Glob(./docs/**)` or remove shared file-discovery access outside the project",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: WildcardToolAccessRule::METADATA,
        surface: Surface::Markdown,
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
        default_presets: BASE_SKILLS_PRESETS,
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
        default_presets: PREVIEW_SKILLS_PRESETS,
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
