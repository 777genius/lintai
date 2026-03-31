use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_html_comment_directive(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.directive_comment_spans.as_slice())
            .unwrap_or(&[]),
        "dangerous hidden instructions in HTML comment",
    )
}

pub(crate) fn check_markdown_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.prose_download_exec_spans.as_slice())
            .unwrap_or(&[]),
        "remote download-and-execute instruction outside a code block",
    )
}

pub(crate) fn check_markdown_base64_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.prose_base64_exec_spans.as_slice())
            .unwrap_or(&[]),
        "base64-decoded payload is executed outside a code block",
    )
}

pub(crate) fn check_markdown_path_traversal(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.prose_path_traversal_spans.as_slice())
            .unwrap_or(&[]),
        "instruction references parent-directory traversal for file access",
    )
}

pub(crate) fn check_html_comment_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.comment_download_exec_spans.as_slice())
            .unwrap_or(&[]),
        "hidden HTML comment contains a download-and-execute instruction",
    )
}

pub(crate) fn check_markdown_private_key_pem(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.private_key_spans.as_slice())
            .unwrap_or(&[]),
        "markdown contains committed private key material",
    )
}

pub(crate) fn check_markdown_fenced_pipe_shell(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.fenced_pipe_shell_spans.as_slice())
            .unwrap_or(&[]),
        "fenced shell example pipes remote content directly into a shell",
    )
}

pub(crate) fn check_markdown_metadata_service_access(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.metadata_service_access_spans.as_slice())
            .unwrap_or(&[]),
        "markdown example targets a cloud metadata service literal",
    )
}

pub(crate) fn check_markdown_mutable_mcp_launcher(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.mutable_mcp_launcher_spans.as_slice())
            .unwrap_or(&[]),
        "markdown example launches MCP through a mutable package runner",
    )
}

pub(crate) fn check_markdown_claude_bare_pip_install(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.claude_bare_pip_install_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown models Claude package installation with bare `pip install` despite explicit `uv` preference guidance",
    )
}

pub(crate) fn check_markdown_unpinned_pip_git_install(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.unpinned_pip_git_install_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs Python packages from an unpinned `git+https://` source",
    )
}

pub(crate) fn check_markdown_pip_http_git_install(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.pip_http_git_install_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs Python packages from an insecure `git+http://` source",
    )
}

pub(crate) fn check_markdown_pip_trusted_host(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.pip_trusted_host_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs Python packages with `--trusted-host`",
    )
}

pub(crate) fn check_markdown_pip_http_index(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.pip_http_index_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs Python packages from an insecure `http://` package index",
    )
}

pub(crate) fn check_markdown_pip_http_find_links(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.pip_http_find_links_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs Python packages with insecure `http://` find-links",
    )
}

pub(crate) fn check_markdown_pip_config_http_index(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.pip_config_http_index_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown configures Python package resolution with an insecure `http://` package index",
    )
}

pub(crate) fn check_markdown_pip_config_http_find_links(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.pip_config_http_find_links_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown configures Python package discovery with insecure `http://` find-links",
    )
}

pub(crate) fn check_markdown_pip_config_trusted_host(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.pip_config_trusted_host_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown configures Python package resolution with `trusted-host`",
    )
}

pub(crate) fn check_markdown_pip_http_source(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.pip_http_source_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs Python packages from an insecure direct `http://` source",
    )
}

pub(crate) fn check_markdown_js_package_config_http_registry(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.js_package_config_http_registry_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown configures a JavaScript package manager with an insecure `http://` registry",
    )
}

pub(crate) fn check_markdown_npm_http_registry(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.npm_http_registry_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs JavaScript packages from an insecure `http://` registry",
    )
}

pub(crate) fn check_markdown_js_package_strict_ssl_false(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.js_package_strict_ssl_false_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown disables strict SSL verification for JavaScript package manager config",
    )
}

pub(crate) fn check_markdown_npm_http_source(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.npm_http_source_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs JavaScript packages from an insecure direct `http://` source",
    )
}

pub(crate) fn check_markdown_cargo_http_git_install(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.cargo_http_git_install_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs Rust packages from an insecure `http://` git source",
    )
}

pub(crate) fn check_markdown_cargo_http_index(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.cargo_http_index_spans.as_slice())
            .unwrap_or(&[]),
        "AI-native markdown installs Rust packages from an insecure `http://` index",
    )
}

pub(crate) fn check_markdown_mutable_docker_image(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.mutable_docker_image_spans.as_slice())
            .unwrap_or(&[]),
        "markdown docker example uses a mutable registry image",
    )
}

pub(crate) fn check_markdown_docker_host_escape(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.docker_host_escape_spans.as_slice())
            .unwrap_or(&[]),
        "markdown docker example uses a host-escape or privileged runtime pattern",
    )
}

pub(crate) fn check_untrusted_instruction_promotion(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.untrusted_instruction_promotion_spans.as_slice())
            .unwrap_or(&[]),
        "instruction markdown promotes untrusted external content to developer/system-level instructions",
    )
}

pub(crate) fn check_approval_bypass_instruction(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.approval_bypass_instruction_spans.as_slice())
            .unwrap_or(&[]),
        "instruction markdown explicitly disables user approval or confirmation",
    )
}

pub(crate) fn check_copilot_instruction_wrong_suffix(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.copilot_instruction_wrong_suffix_spans.as_slice())
            .unwrap_or(&[]),
        "path-specific GitHub Copilot instruction markdown under `.github/instructions/` must end with `.instructions.md`",
    )
}

pub(crate) fn check_copilot_instruction_invalid_apply_to(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| {
                signals
                    .copilot_instruction_invalid_apply_to_spans
                    .as_slice()
            })
            .unwrap_or(&[]),
        "path-specific GitHub Copilot instruction markdown `applyTo` must be a non-empty string or sequence of non-empty strings",
    )
}

pub(crate) fn check_copilot_instruction_invalid_apply_to_glob(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| {
                signals
                    .copilot_instruction_invalid_apply_to_glob_spans
                    .as_slice()
            })
            .unwrap_or(&[]),
        "path-specific GitHub Copilot instruction markdown `applyTo` must use valid glob patterns",
    )
}

pub(crate) fn check_unscoped_bash_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.unscoped_bash_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants unscoped Bash tool access",
    )
}

pub(crate) fn check_unscoped_websearch_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.unscoped_websearch_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants bare WebSearch tool access",
    )
}

pub(crate) fn check_unscoped_webfetch_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.unscoped_webfetch_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants bare WebFetch tool access",
    )
}

pub(crate) fn check_git_push_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_push_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git push)` tool access",
    )
}

pub(crate) fn check_git_checkout_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_checkout_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git checkout:*)` tool access",
    )
}

pub(crate) fn check_git_commit_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_commit_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git commit:*)` tool access",
    )
}

pub(crate) fn check_git_stash_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_stash_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git stash:*)` tool access",
    )
}

pub(crate) fn check_curl_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.curl_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(curl:*)` authority",
    )
}

pub(crate) fn check_wget_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.wget_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(wget:*)` authority",
    )
}

pub(crate) fn check_git_clone_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_clone_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git clone:*)` authority",
    )
}

pub(crate) fn check_git_add_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_add_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git add:*)` authority",
    )
}

pub(crate) fn check_git_fetch_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_fetch_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git fetch:*)` authority",
    )
}

pub(crate) fn check_webfetch_raw_github_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.webfetch_raw_github_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `WebFetch(domain:raw.githubusercontent.com)` authority",
    )
}

pub(crate) fn check_git_config_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_config_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git config:*)` authority",
    )
}

pub(crate) fn check_git_tag_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_tag_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git tag:*)` authority",
    )
}

pub(crate) fn check_git_branch_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_branch_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git branch:*)` authority",
    )
}

pub(crate) fn check_git_reset_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_reset_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git reset:*)` authority",
    )
}

pub(crate) fn check_git_clean_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_clean_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git clean:*)` authority",
    )
}

pub(crate) fn check_git_restore_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_restore_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git restore:*)` authority",
    )
}

pub(crate) fn check_git_rebase_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_rebase_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git rebase:*)` authority",
    )
}

pub(crate) fn check_git_merge_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_merge_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git merge:*)` authority",
    )
}

pub(crate) fn check_git_cherry_pick_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_cherry_pick_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git cherry-pick:*)` authority",
    )
}

pub(crate) fn check_git_apply_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_apply_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git apply:*)` authority",
    )
}

pub(crate) fn check_git_am_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.git_am_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Bash(git am:*)` authority",
    )
}

pub(crate) fn check_package_install_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.package_install_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants package installation authority",
    )
}

pub(crate) fn check_unscoped_read_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.unscoped_read_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants bare Read tool access",
    )
}

pub(crate) fn check_unscoped_write_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.unscoped_write_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants bare Write tool access",
    )
}

pub(crate) fn check_unscoped_edit_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.unscoped_edit_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants bare Edit tool access",
    )
}

pub(crate) fn check_unscoped_glob_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.unscoped_glob_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants bare Glob tool access",
    )
}

pub(crate) fn check_unscoped_grep_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.unscoped_grep_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants bare Grep tool access",
    )
}

pub(crate) fn check_read_unsafe_path_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.read_unsafe_path_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Read(...)` over an unsafe absolute, home-relative, or parent-traversing path",
    )
}

pub(crate) fn check_write_unsafe_path_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.write_unsafe_path_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Write(...)` over an unsafe absolute, home-relative, or parent-traversing path",
    )
}

pub(crate) fn check_edit_unsafe_path_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.edit_unsafe_path_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Edit(...)` over an unsafe absolute, home-relative, or parent-traversing path",
    )
}

pub(crate) fn check_glob_unsafe_path_allowed_tools(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.glob_unsafe_path_allowed_tools_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants `Glob(...)` over an unsafe absolute, home-relative, or parent-traversing path",
    )
}

pub(crate) fn check_wildcard_tool_access(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.wildcard_tool_access_spans.as_slice())
            .unwrap_or(&[]),
        "frontmatter grants wildcard tool access",
    )
}

pub(crate) fn check_plugin_agent_permission_mode(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.plugin_agent_permission_mode_spans.as_slice())
            .unwrap_or(&[]),
        "plugin agent frontmatter sets `permissionMode`",
    )
}

pub(crate) fn check_plugin_agent_hooks_frontmatter(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.plugin_agent_hooks_spans.as_slice())
            .unwrap_or(&[]),
        "plugin agent frontmatter sets `hooks`",
    )
}

pub(crate) fn check_plugin_agent_mcp_servers_frontmatter(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.plugin_agent_mcp_servers_spans.as_slice())
            .unwrap_or(&[]),
        "plugin agent frontmatter sets `mcpServers`",
    )
}

pub(crate) fn check_cursor_rule_always_apply_type(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.cursor_rule_always_apply_type_spans.as_slice())
            .unwrap_or(&[]),
        "Cursor rule frontmatter `alwaysApply` must be boolean",
    )
}

pub(crate) fn check_cursor_rule_globs_type(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.cursor_rule_globs_type_spans.as_slice())
            .unwrap_or(&[]),
        "Cursor rule frontmatter `globs` must be a sequence of patterns",
    )
}

pub(crate) fn check_cursor_rule_redundant_globs(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.cursor_rule_redundant_globs_spans.as_slice())
            .unwrap_or(&[]),
        "Cursor rule frontmatter should not set `globs` when `alwaysApply` is `true`",
    )
}

pub(crate) fn check_cursor_rule_unknown_frontmatter_key(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.cursor_rule_unknown_frontmatter_key_spans.as_slice())
            .unwrap_or(&[]),
        "Cursor rule frontmatter contains an unknown key",
    )
}

pub(crate) fn check_cursor_rule_missing_description(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.cursor_rule_missing_description_spans.as_slice())
            .unwrap_or(&[]),
        "Cursor rule frontmatter should include `description`",
    )
}

pub(crate) fn check_copilot_instruction_too_long(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| signals.copilot_instruction_too_long_spans.as_slice())
            .unwrap_or(&[]),
        "GitHub Copilot instruction markdown exceeds the 4000-character guidance limit",
    )
}

pub(crate) fn check_copilot_instruction_missing_apply_to(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| {
                signals
                    .copilot_instruction_missing_apply_to_spans
                    .as_slice()
            })
            .unwrap_or(&[]),
        "path-specific GitHub Copilot instruction markdown is missing `applyTo` frontmatter",
    )
}

fn findings_for_spans(
    ctx: &ScanContext,
    meta: RuleMetadata,
    spans: &[Span],
    message: &'static str,
) -> Vec<Finding> {
    spans
        .iter()
        .map(|span| finding_for_region(&meta, ctx, span, message))
        .collect()
}
