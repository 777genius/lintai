use super::*;

pub(crate) const RULE_SPECS: [NativeRuleSpec; 3] = [
    NativeRuleSpec {
        metadata: ClaudeSettingsMutableLauncherRule::METADATA,
        surface: Surface::ClaudeSettings,
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
