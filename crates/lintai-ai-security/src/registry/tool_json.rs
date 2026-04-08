use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::tool_json_rules::{
    check_tool_json_anthropic_strict_locked_input_schema, check_tool_json_duplicate_mcp_tool_names,
    check_tool_json_mcp_missing_machine_fields,
    check_tool_json_openai_strict_additional_properties,
    check_tool_json_openai_strict_required_coverage,
};

declare_rule! {
    pub struct McpToolRequiredFieldsRule {
        code: "SEC314",
        summary: "MCP-style tool descriptor is missing required machine fields",
        doc_title: "Tool descriptor: missing machine fields",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpDuplicateToolNamesRule {
        code: "SEC315",
        summary: "MCP-style tool descriptor collection contains duplicate tool names",
        doc_title: "Tool descriptors: duplicate tool names",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct OpenAiStrictAdditionalPropertiesRule {
        code: "SEC316",
        summary: "OpenAI strict tool schema omits recursive additionalProperties: false",
        doc_title: "OpenAI strict schema: missing additionalProperties false",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct OpenAiStrictRequiredCoverageRule {
        code: "SEC317",
        summary: "OpenAI strict tool schema does not require every declared property",
        doc_title: "OpenAI strict schema: properties not all required",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct AnthropicStrictInputSchemaRule {
        code: "SEC318",
        summary: "Anthropic strict tool input schema omits additionalProperties: false",
        doc_title: "Anthropic strict schema: missing additionalProperties false",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 5] = [
    NativeRuleSpec {
        metadata: McpToolRequiredFieldsRule::METADATA,
        surface: Surface::ToolJson,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks unambiguous MCP-style tool descriptors for missing machine fields instead of relying on prose heuristics.",
            malicious_case_ids: &["tool-json-mcp-missing-machine-fields"],
            benign_case_ids: &["tool-json-mcp-valid-tool"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals MCP collection analysis over parsed tool descriptor JSON.",
        },
        check: check_tool_json_mcp_missing_machine_fields,
        safe_fix: None,
        suggestion_message: Some(
            "add the missing machine field so the exported MCP tool remains explicit and deterministic",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpDuplicateToolNamesRule::METADATA,
        surface: Surface::ToolJson,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks structured MCP-style tool collections for duplicate names that can shadow one another.",
            malicious_case_ids: &["tool-json-duplicate-tool-names"],
            benign_case_ids: &["tool-json-unique-tool-names"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals duplicate-name detection over MCP-style tool collections.",
        },
        check: check_tool_json_duplicate_mcp_tool_names,
        safe_fix: None,
        suggestion_message: Some(
            "rename the duplicated tool so each exported machine identifier is unique",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: OpenAiStrictAdditionalPropertiesRule::METADATA,
        surface: Surface::ToolJson,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks OpenAI strict tool schemas for recursive object locking with additionalProperties: false.",
            malicious_case_ids: &["tool-json-openai-strict-additional-properties"],
            benign_case_ids: &["tool-json-openai-strict-locked"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals recursive schema walk over OpenAI function.parameters when strict mode is enabled.",
        },
        check: check_tool_json_openai_strict_additional_properties,
        safe_fix: None,
        suggestion_message: Some(
            "lock every object node in the strict OpenAI tool schema with additionalProperties: false",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: OpenAiStrictRequiredCoverageRule::METADATA,
        surface: Surface::ToolJson,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks OpenAI strict tool schemas for full required coverage of declared properties.",
            malicious_case_ids: &["tool-json-openai-strict-required-coverage"],
            benign_case_ids: &["tool-json-openai-strict-required-complete"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals recursive required-versus-properties comparison over strict OpenAI schemas.",
        },
        check: check_tool_json_openai_strict_required_coverage,
        safe_fix: None,
        suggestion_message: Some(
            "include every declared property in required when strict mode is enabled",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: AnthropicStrictInputSchemaRule::METADATA,
        surface: Surface::ToolJson,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks Anthropic strict tool input_schema objects for explicit additionalProperties: false.",
            malicious_case_ids: &["tool-json-anthropic-strict-open-schema"],
            benign_case_ids: &["tool-json-anthropic-strict-locked"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ToolJsonSignals recursive schema walk over Anthropic input_schema when strict mode is enabled.",
        },
        check: check_tool_json_anthropic_strict_locked_input_schema,
        safe_fix: None,
        suggestion_message: Some(
            "lock the Anthropic input_schema with additionalProperties: false on every object node",
        ),
        suggestion_fix: None,
    },
];

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    &RULE_SPECS
}
