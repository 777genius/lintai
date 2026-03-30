use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::markdown_rules::{
    check_approval_bypass_instruction, check_copilot_instruction_missing_apply_to,
    check_copilot_instruction_too_long, check_html_comment_directive,
    check_html_comment_download_exec, check_markdown_base64_exec,
    check_markdown_docker_host_escape, check_markdown_download_exec,
    check_markdown_fenced_pipe_shell, check_markdown_metadata_service_access,
    check_markdown_mutable_docker_image, check_markdown_mutable_mcp_launcher,
    check_markdown_path_traversal, check_markdown_private_key_pem,
    check_plugin_agent_hooks_frontmatter, check_plugin_agent_mcp_servers_frontmatter,
    check_plugin_agent_permission_mode, check_unscoped_bash_allowed_tools,
    check_untrusted_instruction_promotion, check_wildcard_tool_access,
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

pub(crate) const RULE_SPECS: [NativeRuleSpec; 20] = [
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
            blocker: "Broad Bash grants in AI-native frontmatter can be intentional, so the first release stays least-privilege guidance-only.",
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
