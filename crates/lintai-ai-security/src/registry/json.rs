use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::json_rules::{
    check_json_dangerous_endpoint_host, check_json_hidden_instruction, check_json_literal_secret,
    check_json_sensitive_env_reference, check_json_suspicious_remote_endpoint,
    check_json_unsafe_plugin_path, check_mcp_autoapprove_tools_true,
    check_mcp_autoapprove_wildcard, check_mcp_broad_env_file, check_mcp_capabilities_wildcard,
    check_mcp_credential_env_passthrough, check_mcp_dangerous_docker_flag,
    check_mcp_inline_download_exec, check_mcp_mutable_docker_pull, check_mcp_mutable_launcher,
    check_mcp_network_tls_bypass_command, check_mcp_sandbox_disabled,
    check_mcp_sensitive_docker_mount, check_mcp_shell_wrapper, check_mcp_trust_tools_true,
    check_mcp_unpinned_docker_image, check_plain_http_config,
    check_plugin_hook_inline_download_exec, check_plugin_hook_mutable_launcher,
    check_plugin_hook_network_tls_bypass, check_static_auth_exposure_config,
    check_trust_verification_disabled_config,
};

declare_rule! {
    pub struct McpShellWrapperRule {
        code: "SEC301",
        summary: "MCP configuration shells out through sh -c or bash -c",
        doc_title: "MCP config: shell trampoline",
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
        doc_title: "Config: insecure HTTP endpoint",
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
        doc_title: "MCP config: credential env passthrough",
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
        doc_title: "Config: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct StaticAuthExposureConfigRule {
        code: "SEC305",
        summary: "Configuration embeds static authentication material in a connection or auth value",
        doc_title: "Config: hardcoded auth material",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct JsonHiddenInstructionRule {
        code: "SEC306",
        summary: "JSON configuration description contains override-style hidden instructions",
        doc_title: "JSON config: hidden override instructions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct JsonSensitiveEnvReferenceRule {
        code: "SEC307",
        summary: "Configuration forwards sensitive environment variable references",
        doc_title: "Config: sensitive env forwarding",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct JsonSuspiciousRemoteEndpointRule {
        code: "SEC308",
        summary: "Configuration points at a suspicious remote endpoint",
        doc_title: "Config: suspicious remote endpoint",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct JsonLiteralSecretRule {
        code: "SEC309",
        summary: "Configuration commits literal secret material in env, auth, or header values",
        doc_title: "Config: literal secrets in config",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct JsonDangerousEndpointHostRule {
        code: "SEC310",
        summary: "Configuration endpoint targets a metadata or private-network host literal",
        doc_title: "Config: metadata or private-network host",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct CursorPluginUnsafePathRule {
        code: "SEC311",
        summary: "Cursor plugin manifest contains an unsafe absolute or parent-traversing path",
        doc_title: "Cursor plugin: unsafe path traversal",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpMutableLauncherRule {
        code: "SEC329",
        summary: "MCP configuration launches tooling through a mutable package runner",
        doc_title: "MCP config: mutable package runner",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpInlineDownloadExecRule {
        code: "SEC330",
        summary: "MCP configuration command downloads remote content and pipes it into a shell",
        doc_title: "MCP config: remote content piped to shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpNetworkTlsBypassCommandRule {
        code: "SEC331",
        summary: "MCP configuration command disables TLS verification in a network-capable execution path",
        doc_title: "MCP config: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpBroadEnvFileRule {
        code: "SEC336",
        summary: "Repo-local MCP client config loads a broad dotenv-style envFile",
        doc_title: "MCP client config: broad envFile",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct McpAutoApproveWildcardRule {
        code: "SEC394",
        summary: "MCP configuration auto-approves all tools with `autoApprove: [\"*\"]`",
        doc_title: "MCP config: wildcard auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveToolsTrueRule {
        code: "SEC395",
        summary: "MCP configuration auto-approves all tools with `autoApproveTools: true`",
        doc_title: "MCP config: autoApproveTools true",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpTrustToolsTrueRule {
        code: "SEC396",
        summary: "MCP configuration fully trusts tools with `trustTools: true`",
        doc_title: "MCP config: trustTools true",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSandboxDisabledRule {
        code: "SEC397",
        summary: "MCP configuration disables sandboxing with `sandbox: false` or `disableSandbox: true`",
        doc_title: "MCP config: sandbox disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpCapabilitiesWildcardRule {
        code: "SEC398",
        summary: "MCP configuration grants all capabilities with `capabilities: [\"*\"]` or `capabilities: \"*\"`",
        doc_title: "MCP config: wildcard capabilities",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpUnpinnedDockerImageRule {
        code: "SEC337",
        summary: "MCP configuration launches Docker with an image reference that is not digest-pinned",
        doc_title: "MCP config: Docker image not digest-pinned",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSensitiveDockerMountRule {
        code: "SEC338",
        summary: "MCP configuration launches Docker with a bind mount of sensitive host material",
        doc_title: "MCP config: sensitive host bind mount",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpDangerousDockerFlagRule {
        code: "SEC339",
        summary: "MCP configuration launches Docker with a host-escape or privileged runtime flag",
        doc_title: "MCP config: privileged Docker flags",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpMutableDockerPullRule {
        code: "SEC346",
        summary: "MCP configuration forces Docker to refresh from a mutable registry source",
        doc_title: "MCP config: mutable registry refresh",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookMutableLauncherRule {
        code: "SEC343",
        summary: "Plugin hook command uses a mutable package launcher",
        doc_title: "Plugin hook: mutable package launcher",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookInlineDownloadExecRule {
        code: "SEC344",
        summary: "Plugin hook command downloads remote content and pipes it into a shell",
        doc_title: "Plugin hook: remote content piped to shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookNetworkTlsBypassRule {
        code: "SEC345",
        summary: "Plugin hook command disables TLS verification in a network-capable execution path",
        doc_title: "Plugin hook: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 27] = [
    NativeRuleSpec {
        metadata: McpShellWrapperRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit shell-wrapper command structure in JSON config.",
            malicious_case_ids: &["mcp-shell-wrapper"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command and args structure observation for sh -c or bash -c wrappers.",
        },
        check: check_mcp_shell_wrapper,
        safe_fix: None,
        suggestion_message: Some(
            "replace the shell wrapper with a direct command and explicit args",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PlainHttpConfigRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit insecure http:// endpoints in configuration values.",
            malicious_case_ids: &["mcp-plain-http"],
            benign_case_ids: &["mcp-trusted-endpoint-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals precise http:// endpoint span resolution from parsed JSON location map.",
        },
        check: check_plain_http_config,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure http:// endpoint with https:// or a local/stdio transport",
        ),
        suggestion_fix: Some(https_rewrite_fix),
    },
    NativeRuleSpec {
        metadata: McpCredentialEnvPassthroughRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit credential env passthrough by key inside configuration env maps.",
            malicious_case_ids: &["mcp-credential-env-passthrough"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals env-map key observation for credential passthrough keys.",
        },
        check: check_mcp_credential_env_passthrough,
        safe_fix: None,
        suggestion_message: Some(
            "remove credential env passthrough and configure secrets only inside the target service",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: TrustVerificationDisabledConfigRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit TLS or certificate verification disable flags in configuration.",
            malicious_case_ids: &["mcp-trust-verification-disabled"],
            benign_case_ids: &["mcp-trust-verified-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals boolean and key observation for trust-verification disable settings.",
        },
        check: check_trust_verification_disabled_config,
        safe_fix: None,
        suggestion_message: Some(
            "re-enable certificate verification and use trusted HTTPS or local/stdio transport",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: StaticAuthExposureConfigRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches literal static auth material embedded directly in configuration values.",
            malicious_case_ids: &["mcp-static-authorization"],
            benign_case_ids: &["mcp-authorization-placeholder-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals literal authorization or userinfo span extraction excluding dynamic placeholders.",
        },
        check: check_static_auth_exposure_config,
        safe_fix: None,
        suggestion_message: Some(
            "remove embedded credentials from config values and source auth from environment or provider-local secret configuration",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonHiddenInstructionRule::METADATA,
        surface: Surface::Json,
        default_presets: PREVIEW_MCP_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on descriptive-field phrase heuristics in JSON text.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_json_hidden_instruction,
        safe_fix: None,
        suggestion_message: Some(
            "remove override-style instructions from descriptive JSON fields and keep tool or plugin metadata declarative",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonSensitiveEnvReferenceRule::METADATA,
        surface: Surface::Json,
        default_presets: PREVIEW_MCP_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on sensitive env-name heuristics in forwarded references.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_json_sensitive_env_reference,
        safe_fix: None,
        suggestion_message: Some(
            "stop forwarding sensitive env references through config and resolve secrets only inside the target service",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonSuspiciousRemoteEndpointRule::METADATA,
        surface: Surface::Json,
        default_presets: PREVIEW_MCP_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on suspicious host-marker heuristics for remote endpoints.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_json_suspicious_remote_endpoint,
        safe_fix: None,
        suggestion_message: Some(
            "replace the suspicious remote endpoint with a trusted internal, verified, or pinned service endpoint",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonLiteralSecretRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches literal secret material committed into env, header, or auth-like JSON fields.",
            malicious_case_ids: &["mcp-literal-secret-config"],
            benign_case_ids: &["mcp-secret-placeholder-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals literal secret observation over env, header, and auth-like keys excluding dynamic placeholders.",
        },
        check: check_json_literal_secret,
        safe_fix: None,
        suggestion_message: Some(
            "replace committed secret literals with environment or input indirection before shipping the config",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonDangerousEndpointHostRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit metadata-service or private-network host literals in endpoint-like configuration values.",
            malicious_case_ids: &["mcp-metadata-host-literal"],
            benign_case_ids: &["mcp-public-endpoint-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals endpoint-host extraction over URL-like endpoint fields with metadata/private-host classification.",
        },
        check: check_json_dangerous_endpoint_host,
        safe_fix: None,
        suggestion_message: Some(
            "replace metadata or private-network host literals with a trusted public endpoint or local stdio transport",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CursorPluginUnsafePathRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches absolute or parent-traversing paths in committed Cursor plugin manifest path fields.",
            malicious_case_ids: &["cursor-plugin-unsafe-path"],
            benign_case_ids: &["cursor-plugin-safe-paths"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals plugin-manifest path observation limited to known plugin path fields.",
        },
        check: check_json_unsafe_plugin_path,
        safe_fix: None,
        suggestion_message: Some(
            "keep plugin manifest paths project-relative and inside the plugin root",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpMutableLauncherRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config command launchers for mutable package-runner forms such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.",
            malicious_case_ids: &["mcp-mutable-launcher"],
            benign_case_ids: &["mcp-pinned-launcher-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command/args analysis over ArtifactKind::McpConfig objects with launcher-specific argument gating.",
        },
        check: check_mcp_mutable_launcher,
        safe_fix: None,
        suggestion_message: Some(
            "replace the mutable launcher with a vendored, pinned, or otherwise reproducible MCP execution path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpInlineDownloadExecRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config command and args values for explicit curl|shell or wget|shell execution chains.",
            malicious_case_ids: &["mcp-inline-download-exec"],
            benign_case_ids: &["mcp-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command/args string analysis over ArtifactKind::McpConfig objects, limited to explicit download-pipe-shell patterns.",
        },
        check: check_mcp_inline_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove the inline download-and-exec flow from the MCP command and pin or vendor the fetched content instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpNetworkTlsBypassCommandRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config command and args values for explicit TLS-bypass tokens in a network-capable execution context.",
            malicious_case_ids: &["mcp-command-tls-bypass"],
            benign_case_ids: &["mcp-network-tls-verified-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command/args string analysis over ArtifactKind::McpConfig objects gated by network markers plus TLS-bypass tokens.",
        },
        check: check_mcp_network_tls_bypass_command,
        safe_fix: None,
        suggestion_message: Some(
            "remove TLS-bypass flags or NODE_TLS_REJECT_UNAUTHORIZED=0 from the network-capable MCP command path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpBroadEnvFileRule::METADATA,
        surface: Surface::Json,
        default_presets: PREVIEW_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Broad envFile loading is useful review signal, but whether it is materially risky still depends on repo-local review policy and env contents.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_mcp_broad_env_file,
        safe_fix: None,
        suggestion_message: Some(
            "prefer narrower env injection over broad repo-local .env files for committed MCP client configs",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit wildcard auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-wildcard"],
            benign_case_ids: &["mcp-autoapprove-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"*\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "remove wildcard auto-approval and explicitly list only narrowly reviewed MCP tools",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveToolsTrueRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit blanket auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-tools-true"],
            benign_case_ids: &["mcp-autoapprove-tools-false-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact boolean detection for `autoApproveTools: true` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_tools_true,
        safe_fix: None,
        suggestion_message: Some(
            "disable blanket auto-approval and require explicit review or narrowly scoped tool allowlists",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpTrustToolsTrueRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit blanket tool trust in MCP client config.",
            malicious_case_ids: &["mcp-trust-tools-true"],
            benign_case_ids: &["mcp-trust-tools-false-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact boolean detection for `trustTools: true` on parsed MCP configuration.",
        },
        check: check_mcp_trust_tools_true,
        safe_fix: None,
        suggestion_message: Some(
            "disable blanket tool trust and require explicit review or narrower tool approval settings",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpSandboxDisabledRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit MCP config booleans that disable sandbox isolation.",
            malicious_case_ids: &["mcp-sandbox-disabled"],
            benign_case_ids: &["mcp-sandbox-enabled-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact boolean detection for `sandbox: false` or `disableSandbox: true` on parsed MCP configuration.",
        },
        check: check_mcp_sandbox_disabled,
        safe_fix: None,
        suggestion_message: Some(
            "re-enable sandboxing and prefer reviewed, least-privilege MCP isolation settings",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpCapabilitiesWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit wildcard capability grants in MCP config.",
            malicious_case_ids: &["mcp-capabilities-wildcard"],
            benign_case_ids: &["mcp-capabilities-scoped-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact wildcard detection for `capabilities` scalar or array values on parsed MCP configuration.",
        },
        check: check_mcp_capabilities_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace wildcard capabilities with only the narrowly reviewed MCP capabilities that are actually required",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpUnpinnedDockerImageRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config Docker launch paths for image references that are not pinned by digest, including tag-only refs such as :latest or :1.2.3.",
            malicious_case_ids: &["mcp-docker-unpinned-image"],
            benign_case_ids: &["mcp-docker-digest-pinned-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to command == docker plus args beginning with run.",
        },
        check: check_mcp_unpinned_docker_image,
        safe_fix: None,
        suggestion_message: Some(
            "pin the Docker image by digest in the committed MCP launch path instead of relying on a mutable tag or floating reference",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpSensitiveDockerMountRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config Docker launch paths for bind mounts of sensitive host sources such as docker.sock, SSH material, cloud credentials, and kubeconfig directories.",
            malicious_case_ids: &["mcp-docker-sensitive-mount"],
            benign_case_ids: &["mcp-docker-named-volume-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to -v/--volume and --mount bind forms with sensitive host-path markers.",
        },
        check: check_mcp_sensitive_docker_mount,
        safe_fix: None,
        suggestion_message: Some(
            "remove the sensitive host bind mount from the MCP Docker launch path or replace it with a narrower, non-secret volume strategy",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpDangerousDockerFlagRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config Docker launch paths for privileged or host-escape runtime flags such as --privileged, --network host, --pid host, and --ipc host.",
            malicious_case_ids: &["mcp-docker-host-escape"],
            benign_case_ids: &["mcp-docker-safe-run"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit privileged and host namespace flags.",
        },
        check: check_mcp_dangerous_docker_flag,
        safe_fix: None,
        suggestion_message: Some(
            "remove privileged or host-namespace flags from the committed MCP Docker launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpMutableDockerPullRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config Docker launch paths for explicit --pull always refresh policies that force a mutable registry fetch at runtime.",
            malicious_case_ids: &["gemini-mcp-docker-pull-always"],
            benign_case_ids: &["gemini-mcp-docker-digest-pinned-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit --pull=always or --pull always forms.",
        },
        check: check_mcp_mutable_docker_pull,
        safe_fix: None,
        suggestion_message: Some(
            "remove the forced Docker pull policy from the committed MCP client config and prefer pinned, reproducible image references",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookMutableLauncherRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for mutable package launchers such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.",
            malicious_case_ids: &["plugin-hook-command-mutable-launcher"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects limited to actual hook command values.",
        },
        check: check_plugin_hook_mutable_launcher,
        safe_fix: None,
        suggestion_message: Some(
            "replace the mutable hook launcher with a vendored, pinned, or otherwise reproducible execution path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookInlineDownloadExecRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit curl|shell or wget|shell execution chains.",
            malicious_case_ids: &["plugin-hook-command-inline-download-exec"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects, limited to explicit download-pipe-shell patterns.",
        },
        check: check_plugin_hook_inline_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove the inline download-and-exec flow from the plugin hook command and pin or vendor the fetched content instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookNetworkTlsBypassRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit TLS-bypass tokens in a network-capable execution context.",
            malicious_case_ids: &["plugin-hook-command-tls-bypass"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects gated by network markers plus TLS-bypass tokens.",
        },
        check: check_plugin_hook_network_tls_bypass,
        safe_fix: None,
        suggestion_message: Some(
            "remove TLS-bypass flags or NODE_TLS_REJECT_UNAUTHORIZED=0 from the network-capable plugin hook command",
        ),
        suggestion_fix: None,
    },
];
