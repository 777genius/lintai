use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::devcontainer_rules::{
    check_devcontainer_initialize_command, check_devcontainer_sensitive_bind_mount,
};

declare_rule! {
    pub struct DevcontainerInitializeCommandRule {
        code: "SEC754",
        summary: "Devcontainer config defines a host-side initializeCommand",
        doc_title: "Devcontainer: host-side initializeCommand",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct DevcontainerSensitiveBindMountRule {
        code: "SEC755",
        summary: "Devcontainer config bind-mounts sensitive local host material",
        doc_title: "Devcontainer: sensitive local bind mount",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 2] = [
    NativeRuleSpec {
        metadata: DevcontainerInitializeCommandRule::METADATA,
        surface: Surface::Devcontainer,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed devcontainer configs for non-empty `initializeCommand`, which executes on the local host before container startup.",
            malicious_case_ids: &["devcontainer-initialize-command-host"],
            benign_case_ids: &["devcontainer-no-initialize-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "DevcontainerSignals semantic JSON parsing plus exact value-span resolution for a non-empty top-level `initializeCommand` in `.devcontainer.json` or `.devcontainer/devcontainer.json`.",
        },
        check: check_devcontainer_initialize_command,
        safe_fix: None,
        suggestion_message: Some(
            "remove host-side initializeCommand from committed devcontainer config or move setup into reviewed container build steps",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: DevcontainerSensitiveBindMountRule::METADATA,
        surface: Surface::Devcontainer,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed devcontainer configs for bind mounts of sensitive local material such as SSH keys, cloud credentials, kubeconfig, or docker.sock.",
            malicious_case_ids: &["devcontainer-sensitive-bind-mount"],
            benign_case_ids: &["devcontainer-safe-workspace-mount"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "DevcontainerSignals semantic JSON parsing plus exact value-span resolution for sensitive bind mounts in `workspaceMount`, `mounts`, or Docker-style `runArgs` mount flags.",
        },
        check: check_devcontainer_sensitive_bind_mount,
        safe_fix: None,
        suggestion_message: Some(
            "remove sensitive host bind mounts from committed devcontainer config and keep secrets outside the container definition",
        ),
        suggestion_fix: None,
    },
];

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    &RULE_SPECS
}
