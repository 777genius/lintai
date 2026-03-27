use lintai_api::{
    Category, Confidence, Finding, RuleMetadata, RuleTier, ScanContext, Severity, declare_rule,
};

use crate::hook_rules::{
    check_hook_download_exec, check_hook_plain_http_exfil, check_hook_secret_exfil,
    check_hook_tls_bypass,
};
use crate::json_rules::{
    check_mcp_credential_env_passthrough, check_mcp_shell_wrapper, check_plain_http_config,
    check_trust_verification_disabled_config,
};
use crate::markdown_rules::{
    check_html_comment_directive, check_html_comment_download_exec, check_markdown_download_exec,
};

declare_rule! {
    pub struct HtmlCommentDirectiveRule {
        code: "SEC101",
        summary: "Hidden HTML comment contains dangerous agent instructions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct MarkdownDownloadExecRule {
        code: "SEC102",
        summary: "Markdown contains remote download-and-execute instruction outside code blocks",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HtmlCommentDownloadExecRule {
        code: "SEC103",
        summary: "Hidden HTML comment contains remote download-and-execute instruction",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookDownloadExecRule {
        code: "SEC201",
        summary: "Hook script downloads remote code and executes it",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookSecretExfilRule {
        code: "SEC202",
        summary: "Hook script appears to exfiltrate secrets through a network call",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookPlainHttpExfilRule {
        code: "SEC203",
        summary: "Hook script sends secret material to an insecure http:// endpoint",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookTlsBypassRule {
        code: "SEC204",
        summary: "Hook script disables TLS or certificate verification for a network call",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpShellWrapperRule {
        code: "SEC301",
        summary: "MCP configuration shells out through sh -c or bash -c",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PlainHttpConfigRule {
        code: "SEC302",
        summary: "Configuration contains an insecure http:// endpoint",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpCredentialEnvPassthroughRule {
        code: "SEC303",
        summary: "MCP configuration passes through credential environment variables",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct TrustVerificationDisabledConfigRule {
        code: "SEC304",
        summary: "Configuration disables TLS or certificate verification",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct NativeRuleEntry {
    pub(crate) metadata: RuleMetadata,
    pub(crate) check: fn(&ScanContext, &RuleMetadata) -> Vec<Finding>,
}

pub(crate) const RULES: [NativeRuleEntry; 11] = [
    NativeRuleEntry {
        metadata: HtmlCommentDirectiveRule::METADATA,
        check: check_html_comment_directive,
    },
    NativeRuleEntry {
        metadata: MarkdownDownloadExecRule::METADATA,
        check: check_markdown_download_exec,
    },
    NativeRuleEntry {
        metadata: HtmlCommentDownloadExecRule::METADATA,
        check: check_html_comment_download_exec,
    },
    NativeRuleEntry {
        metadata: HookDownloadExecRule::METADATA,
        check: check_hook_download_exec,
    },
    NativeRuleEntry {
        metadata: HookSecretExfilRule::METADATA,
        check: check_hook_secret_exfil,
    },
    NativeRuleEntry {
        metadata: HookPlainHttpExfilRule::METADATA,
        check: check_hook_plain_http_exfil,
    },
    NativeRuleEntry {
        metadata: HookTlsBypassRule::METADATA,
        check: check_hook_tls_bypass,
    },
    NativeRuleEntry {
        metadata: McpShellWrapperRule::METADATA,
        check: check_mcp_shell_wrapper,
    },
    NativeRuleEntry {
        metadata: PlainHttpConfigRule::METADATA,
        check: check_plain_http_config,
    },
    NativeRuleEntry {
        metadata: McpCredentialEnvPassthroughRule::METADATA,
        check: check_mcp_credential_env_passthrough,
    },
    NativeRuleEntry {
        metadata: TrustVerificationDisabledConfigRule::METADATA,
        check: check_trust_verification_disabled_config,
    },
];

pub(crate) const RULE_METADATA: [RuleMetadata; 11] = [
    HtmlCommentDirectiveRule::METADATA,
    MarkdownDownloadExecRule::METADATA,
    HtmlCommentDownloadExecRule::METADATA,
    HookDownloadExecRule::METADATA,
    HookSecretExfilRule::METADATA,
    HookPlainHttpExfilRule::METADATA,
    HookTlsBypassRule::METADATA,
    McpShellWrapperRule::METADATA,
    PlainHttpConfigRule::METADATA,
    McpCredentialEnvPassthroughRule::METADATA,
    TrustVerificationDisabledConfigRule::METADATA,
];
