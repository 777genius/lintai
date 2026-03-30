use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::claude_settings_rules::{
    check_claude_settings_bash_wildcard, check_claude_settings_bypass_permissions,
    check_claude_settings_dangerous_http_hook_host, check_claude_settings_edit_wildcard,
    check_claude_settings_enabled_mcpjson_servers,
    check_claude_settings_external_absolute_hook_command,
    check_claude_settings_git_checkout_permission, check_claude_settings_git_commit_permission,
    check_claude_settings_git_push_permission, check_claude_settings_git_stash_permission,
    check_claude_settings_glob_wildcard, check_claude_settings_grep_wildcard,
    check_claude_settings_home_directory_hook_command, check_claude_settings_inline_download_exec,
    check_claude_settings_insecure_http_hook_url, check_claude_settings_invalid_hook_matcher_event,
    check_claude_settings_missing_hook_timeout,
    check_claude_settings_missing_required_hook_matcher, check_claude_settings_missing_schema,
    check_claude_settings_mutable_launcher, check_claude_settings_network_tls_bypass,
    check_claude_settings_npx_permission, check_claude_settings_read_wildcard,
    check_claude_settings_unscoped_websearch, check_claude_settings_webfetch_wildcard,
    check_claude_settings_websearch_wildcard, check_claude_settings_write_wildcard,
};
use crate::registry::presets::PREVIEW_CLAUDE_PRESETS;

declare_rule! {
    pub struct ClaudeSettingsMissingHookTimeoutRule {
        code: "SEC381",
        summary: "Claude settings command hook should set `timeout` in a shared committed config",
        doc_title: "Claude settings: command hook missing `timeout`",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsInvalidHookMatcherEventRule {
        code: "SEC382",
        summary: "Claude settings should not use `matcher` on unsupported hook events",
        doc_title: "Claude settings: `matcher` on unsupported hook event",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsMissingRequiredHookMatcherRule {
        code: "SEC383",
        summary: "Claude settings should set `matcher` on matcher-capable hook events",
        doc_title: "Claude settings: missing `matcher` on matcher-capable hook event",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

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
    pub struct ClaudeSettingsEditWildcardRule {
        code: "SEC373",
        summary: "Claude settings permissions allow `Edit(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Edit permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsWebSearchWildcardRule {
        code: "SEC374",
        summary: "Claude settings permissions allow `WebSearch(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard WebSearch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUnscopedWebSearchRule {
        code: "SEC384",
        summary: "Claude settings permissions allow bare `WebSearch` in a shared committed config",
        doc_title: "Claude settings: bare WebSearch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitPushPermissionRule {
        code: "SEC385",
        summary: "Claude settings permissions allow `Bash(git push)` in a shared committed config",
        doc_title: "Claude settings: shared git push permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsEnabledMcpjsonServersRule {
        code: "SEC400",
        summary: "Claude settings enable `enabledMcpjsonServers` in a shared committed config",
        doc_title: "Claude settings: shared enabledMcpjsonServers",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsNpxPermissionRule {
        code: "SEC399",
        summary: "Claude settings permissions allow `Bash(npx ...)` in a shared committed config",
        doc_title: "Claude settings: shared npx Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitCheckoutPermissionRule {
        code: "SEC386",
        summary: "Claude settings permissions allow `Bash(git checkout:*)` in a shared committed config",
        doc_title: "Claude settings: shared git checkout permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitCommitPermissionRule {
        code: "SEC387",
        summary: "Claude settings permissions allow `Bash(git commit:*)` in a shared committed config",
        doc_title: "Claude settings: shared git commit permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitStashPermissionRule {
        code: "SEC388",
        summary: "Claude settings permissions allow `Bash(git stash:*)` in a shared committed config",
        doc_title: "Claude settings: shared git stash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGlobWildcardRule {
        code: "SEC375",
        summary: "Claude settings permissions allow `Glob(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Glob permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGrepWildcardRule {
        code: "SEC376",
        summary: "Claude settings permissions allow `Grep(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Grep permissions",
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

pub(crate) const RULE_SPECS: [NativeRuleSpec; 27] = [
    NativeRuleSpec {
        metadata: ClaudeSettingsInvalidHookMatcherEventRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Unsupported hook-event matchers in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_invalid_hook_matcher_event,
        safe_fix: None,
        suggestion_message: Some(
            "remove `matcher` from unsupported hook events or move the hook under a matcher-capable event like `PreToolUse` or `PostToolUse`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMissingRequiredHookMatcherRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Missing matchers on matcher-capable Claude hook events are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_missing_required_hook_matcher,
        safe_fix: None,
        suggestion_message: Some(
            "add an explicit `matcher` to each shared `PreToolUse` or `PostToolUse` hook entry, or move the hook under a broader event if scoped matching is not intended",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMissingHookTimeoutRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Missing command-hook timeouts in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_missing_hook_timeout,
        safe_fix: None,
        suggestion_message: Some(
            "add an explicit `timeout` to each shared command hook so hook execution stays bounded and reviewable",
        ),
        suggestion_fix: None,
    },
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
        metadata: ClaudeSettingsEditWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Edit grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_edit_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Edit(*)` with a narrower allowlist of reviewed edit patterns or remove broad edit access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsWebSearchWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard WebSearch grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_websearch_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `WebSearch(*)` with a narrower allowlist of reviewed search patterns or remove broad search access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUnscopedWebSearchRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Bare WebSearch grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_unscoped_websearch,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `WebSearch` with a narrower reviewed permission pattern or remove broad search access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitPushPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git push permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_git_push_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git push)` permissions, or replace them with a narrower reviewed workflow that does not grant direct push authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsEnabledMcpjsonServersRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `enabledMcpjsonServers` in committed Claude settings is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_enabled_mcpjson_servers,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `enabledMcpjsonServers` defaults or keep MCP server enablement as a locally reviewed opt-in step",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsNpxPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `Bash(npx ...)` permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_npx_permission,
        safe_fix: None,
        suggestion_message: Some(
            "replace shared `Bash(npx ...)` permissions with a pinned wrapper or a narrower reviewed command permission that does not grant mutable package execution by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitCheckoutPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git checkout permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_git_checkout_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git checkout:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad checkout authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitCommitPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git commit permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_git_commit_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git commit:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad commit authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitStashPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git stash permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_git_stash_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git stash:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad stash authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGlobWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Glob grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_glob_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Glob(*)` with a narrower allowlist of reviewed glob patterns or remove broad file-discovery access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGrepWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Grep grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_grep_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Grep(*)` with a narrower allowlist of reviewed grep patterns or remove broad content-search access from the shared Claude settings file",
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
