use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::dockerfile_rules::{
    check_dockerfile_final_stage_root_user, check_dockerfile_latest_image,
    check_dockerfile_mutable_image, check_dockerfile_run_download_exec,
};

declare_rule! {
    pub struct DockerfileRunDownloadExecRule {
        code: "SEC746",
        summary: "Dockerfile RUN downloads remote code and executes it",
        doc_title: "Dockerfile: remote script execution in RUN",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct DockerfileFinalStageRootUserRule {
        code: "SEC747",
        summary: "Dockerfile final stage explicitly runs as root",
        doc_title: "Dockerfile: final stage runs as root",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct DockerfileMutableImageRule {
        code: "SEC749",
        summary: "Dockerfile FROM uses a mutable registry image without a digest pin",
        doc_title: "Dockerfile: mutable registry image in FROM",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct DockerfileLatestImageRule {
        code: "SEC751",
        summary: "Dockerfile FROM uses a latest or implicit-latest image tag",
        doc_title: "Dockerfile: latest or implicit-latest base image tag",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 4] = [
    NativeRuleSpec {
        metadata: DockerfileRunDownloadExecRule::METADATA,
        surface: Surface::Dockerfile,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Dockerfiles for RUN instructions that fetch remote content and pipe it into a shell.",
            malicious_case_ids: &["dockerfile-run-download-exec"],
            benign_case_ids: &["dockerfile-safe-run"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "DockerfileSignals line analysis over `RUN` instructions for download-exec patterns such as `curl` or `wget` piped to `sh` or `bash`.",
        },
        check: check_dockerfile_run_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove remote script execution from RUN and vendor or pin reviewed build inputs instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: DockerfileFinalStageRootUserRule::METADATA,
        surface: Surface::Dockerfile,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks the final Dockerfile stage for an explicit root runtime user while ignoring earlier build stages that later drop privileges.",
            malicious_case_ids: &["dockerfile-final-stage-root-user"],
            benign_case_ids: &["dockerfile-final-stage-nonroot-user"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "DockerfileSignals tracks `FROM` stage boundaries and the effective explicit `USER` in the final stage, flagging only `root`, `root:*`, `0`, or `0:*` in the last stage.",
        },
        check: check_dockerfile_final_stage_root_user,
        safe_fix: None,
        suggestion_message: Some(
            "drop privileges in the final image stage with a dedicated non-root USER",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: DockerfileMutableImageRule::METADATA,
        surface: Surface::Dockerfile,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Dockerfiles for registry-distributed base images that are not digest pinned.",
            malicious_case_ids: &["dockerfile-mutable-base-image"],
            benign_case_ids: &["dockerfile-digest-pinned-base-image"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "DockerfileSignals exact `FROM` token analysis with conservative registry-image matching and digest-pin detection on the selected image token.",
        },
        check: check_dockerfile_mutable_image,
        safe_fix: None,
        suggestion_message: Some(
            "pin Dockerfile base images by digest to improve reproducibility and reviewability",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: DockerfileLatestImageRule::METADATA,
        surface: Surface::Dockerfile,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Dockerfiles for base images that rely on `latest` or the implicit default latest tag.",
            malicious_case_ids: &["dockerfile-latest-base-image"],
            benign_case_ids: &["dockerfile-tagged-base-image-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "DockerfileSignals exact `FROM` token analysis with prior-stage alias tracking plus deterministic detection of explicit `:latest` tags or missing tags on non-digest image references.",
        },
        check: check_dockerfile_latest_image,
        safe_fix: None,
        suggestion_message: Some(
            "replace latest or implicit-latest base images with a reviewed explicit version or digest pin",
        ),
        suggestion_fix: None,
    },
];
