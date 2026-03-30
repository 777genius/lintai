use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::hook_rules::{
    check_hook_base64_exec, check_hook_download_exec, check_hook_plain_http_exfil,
    check_hook_secret_exfil, check_hook_static_auth_exposure, check_hook_tls_bypass,
};

declare_rule! {
    pub struct HookDownloadExecRule {
        code: "SEC201",
        summary: "Hook script downloads remote code and executes it",
        doc_title: "Hook script: remote code execution",
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
        doc_title: "Hook script: secret exfiltration",
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
        doc_title: "Hook script: insecure HTTP secret send",
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
        doc_title: "Hook script: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookStaticAuthExposureRule {
        code: "SEC205",
        summary: "Hook script embeds static authentication material in a network call",
        doc_title: "Hook script: hardcoded auth in network call",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookBase64ExecRule {
        code: "SEC206",
        summary: "Hook script decodes a base64 payload and executes it",
        doc_title: "Hook script: base64 payload execution",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 6] = [
    NativeRuleSpec {
        metadata: HookDownloadExecRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit remote download-and-execute behavior in hook shell lines, not prose text.",
            malicious_case_ids: &["hook-download-exec"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals download-and-execute observation over non-comment hook lines.",
        },
        check: check_hook_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "vendor or pin the script locally instead of downloading and executing it inline",
        ),
        suggestion_fix: Some(hook_download_exec_fix),
    },
    NativeRuleSpec {
        metadata: HookSecretExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches secret-bearing network exfil behavior in executable hook lines.",
            malicious_case_ids: &["hook-secret-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals secret exfil observation from network markers plus secret markers on non-comment lines.",
        },
        check: check_hook_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing network exfil flow and keep secret access local",
        ),
        suggestion_fix: Some(hook_secret_exfil_fix),
    },
    NativeRuleSpec {
        metadata: HookPlainHttpExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches insecure HTTP transport on a secret-bearing hook exfil path.",
            malicious_case_ids: &["hook-plain-http-secret-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals precise http:// span observation gated by concurrent secret exfil markers.",
        },
        check: check_hook_plain_http_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove insecure HTTP secret exfil and keep secret handling local or over HTTPS",
        ),
        suggestion_fix: Some(hook_plain_http_exfil_fix),
    },
    NativeRuleSpec {
        metadata: HookTlsBypassRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit TLS verification bypass tokens in executable hook network context.",
            malicious_case_ids: &["hook-tls-bypass"],
            benign_case_ids: &["cursor-plugin-tls-verified-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals TLS-bypass token observation over parsed hook line tokens and network context.",
        },
        check: check_hook_tls_bypass,
        safe_fix: None,
        suggestion_message: Some(
            "remove TLS-bypass flags or env overrides and use normal certificate verification",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookStaticAuthExposureRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches literal static auth material in hook URLs or authorization headers.",
            malicious_case_ids: &["hook-static-auth-userinfo"],
            benign_case_ids: &["hook-auth-dynamic-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals userinfo/header literal extraction excluding dynamic references.",
        },
        check: check_hook_static_auth_exposure,
        safe_fix: None,
        suggestion_message: Some(
            "move embedded credentials out of URLs and headers into environment or provider-local auth configuration",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookBase64ExecRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit base64 decode-and-execute behavior in executable hook lines.",
            malicious_case_ids: &["hook-base64-exec"],
            benign_case_ids: &["hook-base64-decode-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals base64-decode plus exec observation over non-comment hook lines.",
        },
        check: check_hook_base64_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove the obfuscated base64 decode-and-exec flow from the hook script",
        ),
        suggestion_fix: Some(hook_base64_exec_fix),
    },
];
