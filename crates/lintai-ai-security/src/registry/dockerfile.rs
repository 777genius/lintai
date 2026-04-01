use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::dockerfile_rules::check_dockerfile_run_download_exec;

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

pub(crate) const RULE_SPECS: [NativeRuleSpec; 1] = [NativeRuleSpec {
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
}];
