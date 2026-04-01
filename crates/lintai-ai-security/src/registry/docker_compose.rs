use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::docker_compose_rules::{
    check_docker_compose_latest_image, check_docker_compose_mutable_image,
    check_docker_compose_privileged_runtime,
};

declare_rule! {
    pub struct DockerComposePrivilegedRuntimeRule {
        code: "SEC748",
        summary: "Docker Compose service enables privileged container runtime or host namespace access",
        doc_title: "Docker Compose: privileged service runtime",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct DockerComposeMutableImageRule {
        code: "SEC750",
        summary: "Docker Compose service image uses a mutable registry reference without a digest pin",
        doc_title: "Docker Compose: mutable service image",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct DockerComposeLatestImageRule {
        code: "SEC752",
        summary: "Docker Compose service image uses a latest or implicit-latest tag",
        doc_title: "Docker Compose: latest or implicit-latest service image tag",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 3] = [
    NativeRuleSpec {
        metadata: DockerComposePrivilegedRuntimeRule::METADATA,
        surface: Surface::DockerCompose,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Docker Compose service definitions for privileged runtime, dangerous capability grants, or host namespace access.",
            malicious_case_ids: &["docker-compose-privileged-runtime"],
            benign_case_ids: &["docker-compose-safe-runtime"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "DockerComposeSignals combines semantic confirmation of a Compose `services` map with indentation-aware line matching for `privileged: true`, `cap_add: [ALL|SYS_ADMIN]`, and `network_mode`/`pid`/`ipc: host` inside service blocks.",
        },
        check: check_docker_compose_privileged_runtime,
        safe_fix: None,
        suggestion_message: Some(
            "remove privileged runtime flags, dangerous capability grants, and host namespaces from committed Compose services",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: DockerComposeMutableImageRule::METADATA,
        surface: Surface::DockerCompose,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Docker Compose services for registry-distributed image references that are not digest pinned.",
            malicious_case_ids: &["docker-compose-mutable-image"],
            benign_case_ids: &["docker-compose-digest-pinned-image"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "DockerComposeSignals combines semantic confirmation of `services.*.image` values with indentation-aware line matching and conservative registry-image plus digest-pin detection.",
        },
        check: check_docker_compose_mutable_image,
        safe_fix: None,
        suggestion_message: Some(
            "pin Compose service images by digest to improve reproducibility and reviewability",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: DockerComposeLatestImageRule::METADATA,
        surface: Surface::DockerCompose,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Docker Compose services for images that rely on `latest` or the implicit default latest tag.",
            malicious_case_ids: &["docker-compose-latest-image"],
            benign_case_ids: &["docker-compose-tagged-image-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "DockerComposeSignals semantic `services.*.image` detection combined with indentation-aware line matching and deterministic detection of explicit `:latest` tags or missing tags on non-digest image references.",
        },
        check: check_docker_compose_latest_image,
        safe_fix: None,
        suggestion_message: Some(
            "replace latest or implicit-latest service images with a reviewed explicit version or digest pin",
        ),
        suggestion_fix: None,
    },
];
