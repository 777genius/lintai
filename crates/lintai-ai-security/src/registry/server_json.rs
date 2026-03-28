use super::*;

pub(crate) const RULE_SPECS: [NativeRuleSpec; 5] = [
    NativeRuleSpec {
        metadata: ServerJsonInsecureRemoteUrlRule::METADATA,
        surface: Surface::ServerJson,
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
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks server.json remotes[] URL templates against variables defined on the same remote entry.",
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
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks auth-like remotes[].headers[].value placeholders against variables defined on the same header object.",
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
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Secret policy expectations can vary across registry producers, so the first release keeps this as guidance-only.",
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
