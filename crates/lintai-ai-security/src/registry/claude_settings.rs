use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::claude_settings_rules::{
    check_claude_settings_bash_wildcard, check_claude_settings_bypass_permissions,
    check_claude_settings_dangerous_http_hook_host,
    check_claude_settings_external_absolute_hook_command,
    check_claude_settings_home_directory_hook_command, check_claude_settings_inline_download_exec,
    check_claude_settings_insecure_http_hook_url, check_claude_settings_missing_schema,
    check_claude_settings_mutable_launcher, check_claude_settings_network_tls_bypass,
    check_claude_settings_read_wildcard, check_claude_settings_webfetch_wildcard,
    check_claude_settings_write_wildcard,
};
use crate::registry::presets::PREVIEW_CLAUDE_PRESETS;

declare_rule! {
    pub struct ClaudeSettingsWriteWildcardRule {
        code: "SEC369",
        summary: "Claude settings permissions allow `Write(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Write permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsReadWildcardRule {
        code: "SEC372",
        summary: "Claude settings permissions allow `Read(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Read permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsExternalAbsoluteHookCommandRule {
        code: "SEC368",
        summary: "Claude settings hook command uses a repo-external absolute path in a shared committed config",
        doc_title: "Claude settings: repo-external absolute hook path",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsWebFetchWildcardRule {
        code: "SEC367",
        summary: "Claude settings permissions allow `WebFetch(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard WebFetch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsDangerousHttpHookHostRule {
        code: "SEC366",
        summary: "Claude settings allow dangerous host literals in `allowedHttpHookUrls`",
        doc_title: "Claude settings: dangerous HTTP hook host literal",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsInsecureHttpHookUrlRule {
        code: "SEC365",
        summary: "Claude settings allow non-HTTPS HTTP hook URLs in a shared committed config",
        doc_title: "Claude settings: non-HTTPS allowed HTTP hook URL",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsBypassPermissionsRule {
        code: "SEC364",
        summary: "Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config",
        doc_title: "Claude settings: bypassPermissions default mode",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsHomeDirectoryHookCommandRule {
        code: "SEC363",
        summary: "Claude settings hook command uses a home-directory path in a shared committed config",
        doc_title: "Claude settings: home-directory hook path",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsBashWildcardRule {
        code: "SEC362",
        summary: "Claude settings permissions allow `Bash(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsMissingSchemaRule {
        code: "SEC361",
        summary: "Claude settings file is missing a top-level `$schema` reference",
        doc_title: "Claude settings: missing `$schema`",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsMutableLauncherRule {
        code: "SEC340",
        summary: "Claude settings command hook uses a mutable package launcher",
        doc_title: "Claude hook: mutable package launcher",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsInlineDownloadExecRule {
        code: "SEC341",
        summary: "Claude settings command hook downloads remote content and pipes it into a shell",
        doc_title: "Claude hook: remote content piped to shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsNetworkTlsBypassRule {
        code: "SEC342",
        summary: "Claude settings command hook disables TLS verification in a network-capable execution path",
        doc_title: "Claude hook: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 13] = [
    NativeRuleSpec {
        metadata: ClaudeSettingsWriteWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Write grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_write_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Write(*)` with a narrower allowlist of reviewed write patterns or remove broad write access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsReadWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Read grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_read_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Read(*)` with a narrower allowlist of reviewed read patterns or remove broad read access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsExternalAbsoluteHookCommandRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Repo-external absolute hook paths in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_external_absolute_hook_command,
        safe_fix: None,
        suggestion_message: Some(
            "replace the repo-external absolute hook path with a project-scoped wrapper or a repo-relative path rooted in `$CLAUDE_PROJECT_DIR`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsWebFetchWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard WebFetch grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_webfetch_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `WebFetch(*)` with a narrower allowlist of reviewed fetch patterns or remove broad network access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsDangerousHttpHookHostRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Committed Claude settings with dangerous host literals in `allowedHttpHookUrls` are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_dangerous_http_hook_host,
        safe_fix: None,
        suggestion_message: Some(
            "remove metadata or private-network host literals from `allowedHttpHookUrls` and replace them with reviewed public endpoints",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsInsecureHttpHookUrlRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Committed Claude settings with non-HTTPS `allowedHttpHookUrls` entries are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_insecure_http_hook_url,
        safe_fix: None,
        suggestion_message: Some(
            "replace non-HTTPS `allowedHttpHookUrls` entries with reviewed `https://` endpoints or remove them from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsBypassPermissionsRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Committed Claude settings with `permissions.defaultMode = bypassPermissions` are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_bypass_permissions,
        safe_fix: None,
        suggestion_message: Some(
            "replace `permissions.defaultMode = bypassPermissions` with a narrower shared permissions mode and explicit reviewed allowlists",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsHomeDirectoryHookCommandRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Home-directory hook paths in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_home_directory_hook_command,
        safe_fix: None,
        suggestion_message: Some(
            "replace the home-directory hook path with a project-scoped wrapper or a repo-relative path rooted in `$CLAUDE_PROJECT_DIR`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsBashWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Bash grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_bash_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Bash(*)` with a narrower allowlist of reviewed command patterns in the committed Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMissingSchemaRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Schema references in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_missing_schema,
        safe_fix: None,
        suggestion_message: Some(
            "add the Claude settings SchemaStore URL as top-level `$schema`, for example `https://json.schemastore.org/claude-code-settings.json`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMutableLauncherRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: BASE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for mutable package launcher forms such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.",
            malicious_case_ids: &["claude-settings-mutable-launcher"],
            benign_case_ids: &["claude-settings-pinned-launcher-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook analysis over committed .claude/settings.json or claude/settings.json objects with type == command under hooks.",
        },
        check: check_claude_settings_mutable_launcher,
        safe_fix: None,
        suggestion_message: Some(
            "replace the mutable package launcher in the committed Claude hook with a vendored, pinned, or otherwise reproducible execution path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsInlineDownloadExecRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: BASE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit curl|shell or wget|shell execution chains.",
            malicious_case_ids: &["claude-settings-inline-download-exec"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, limited to explicit download-pipe-shell patterns.",
        },
        check: check_claude_settings_inline_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove the inline download-and-exec flow from the committed Claude hook command and pin or vendor the fetched content instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsNetworkTlsBypassRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: BASE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit TLS-bypass tokens in a network-capable execution context.",
            malicious_case_ids: &["claude-settings-command-tls-bypass"],
            benign_case_ids: &["claude-settings-network-tls-verified-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, gated by network markers plus TLS-bypass tokens.",
        },
        check: check_claude_settings_network_tls_bypass,
        safe_fix: None,
        suggestion_message: Some(
            "remove TLS-bypass flags or NODE_TLS_REJECT_UNAUTHORIZED=0 from the network-capable Claude hook command",
        ),
        suggestion_fix: None,
    },
];
