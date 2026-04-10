use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::server_json_rules::{
    check_server_json_auth_header_policy_mismatch, check_server_json_insecure_remote_url,
    check_server_json_literal_auth_header, check_server_json_unresolved_header_variable,
    check_server_json_unresolved_remote_variable,
};

declare_rule! {
    pub struct ServerJsonInsecureRemoteUrlRule {
        code: "SEC319",
        summary: "server.json remotes entry uses an insecure or non-public remote URL",
        doc_title: "server.json remotes: insecure or private URL",
        category: Category::Hardening,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ServerJsonUnresolvedRemoteVariableRule {
        code: "SEC320",
        summary: "server.json remotes URL references an undefined template variable",
        doc_title: "server.json remotes: undefined template variable",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ServerJsonLiteralAuthHeaderRule {
        code: "SEC321",
        summary: "server.json remotes header commits literal authentication material",
        doc_title: "server.json remotes: literal auth header",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ServerJsonUnresolvedHeaderVariableRule {
        code: "SEC322",
        summary: "server.json remotes header value references an undefined template variable",
        doc_title: "server.json remotes: undefined header variable",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ServerJsonAuthHeaderPolicyMismatchRule {
        code: "SEC323",
        summary: "server.json auth header carries material without an explicit secret flag",
        doc_title: "server.json auth: missing explicit secret flag",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 5] = [
    NativeRuleSpec {
        metadata: ServerJsonInsecureRemoteUrlRule::METADATA,
        surface: Surface::ServerJson,
        default_presets: SUPPLY_CHAIN_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks MCP registry remotes[] URLs for insecure HTTP and non-public host literals without inspecting local package transport URLs.",
            malicious_case_ids: &["server-json-insecure-remote-url"],
            benign_case_ids: &["server-json-loopback-package-transport-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ServerJsonSignals remotes[] URL analysis limited to streamable-http and sse entries.",
        },
        check: check_server_json_insecure_remote_url,
        safe_fix: None,
        suggestion_message: Some(
            "use a public https remote URL or remove the non-public literal from the registry remote entry",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ServerJsonUnresolvedRemoteVariableRule::METADATA,
        surface: Surface::ServerJson,
        default_presets: COMPAT_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks server.json remotes[] URL templates for placeholder/variables contract mismatches on the same remote entry.",
            malicious_case_ids: &["server-json-unresolved-remote-variable"],
            benign_case_ids: &["server-json-remote-variable-defined"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ServerJsonSignals placeholder extraction over remotes[] URLs compared with remotes[].variables keys.",
        },
        check: check_server_json_unresolved_remote_variable,
        safe_fix: None,
        suggestion_message: Some(
            "define every URL placeholder under remotes[].variables or remove the unresolved placeholder from the remote URL",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ServerJsonLiteralAuthHeaderRule::METADATA,
        surface: Surface::ServerJson,
        default_presets: THREAT_REVIEW_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks remotes[].headers[] auth-like values for literal bearer/basic material or literal API key style values.",
            malicious_case_ids: &["server-json-literal-auth-header"],
            benign_case_ids: &["server-json-auth-header-placeholder-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ServerJsonSignals inspects remotes[].headers[] auth-like names and value literals without looking at packages[].transport.",
        },
        check: check_server_json_literal_auth_header,
        safe_fix: None,
        suggestion_message: Some(
            "replace the literal auth header value with a placeholder-backed variable in the same remote header entry",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ServerJsonUnresolvedHeaderVariableRule::METADATA,
        surface: Surface::ServerJson,
        default_presets: COMPAT_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks auth-like remotes[].headers[].value placeholders against variables defined on the same header object so registry consumers do not ship broken header templates.",
            malicious_case_ids: &["server-json-unresolved-header-variable"],
            benign_case_ids: &["server-json-header-variable-defined"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ServerJsonSignals placeholder extraction over remotes[].headers[].value compared with headers[].variables keys.",
        },
        check: check_server_json_unresolved_header_variable,
        safe_fix: None,
        suggestion_message: Some(
            "define every auth header placeholder under the same remotes[].headers[].variables object",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ServerJsonAuthHeaderPolicyMismatchRule::METADATA,
        surface: Surface::ServerJson,
        default_presets: COMPAT_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Registry producers do not all enforce the same explicit secret-marker contract, so this remains a compatibility review signal until wider producer evidence converges.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_server_json_auth_header_policy_mismatch,
        safe_fix: None,
        suggestion_message: Some(
            "mark auth-carrying header entries with isSecret/is_secret=true when they carry value or variables",
        ),
        suggestion_fix: None,
    },
];

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    &RULE_SPECS
}
