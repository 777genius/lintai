use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::github_workflow_rules::{
    check_github_workflow_pull_request_target_head_checkout,
    check_github_workflow_unpinned_third_party_action,
    check_github_workflow_untrusted_run_interpolation, check_github_workflow_write_all_permissions,
    check_github_workflow_write_capable_third_party_action,
};

declare_rule! {
    pub struct GithubWorkflowUnpinnedThirdPartyActionRule {
        code: "SEC324",
        summary: "GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA",
        doc_title: "GitHub Actions: unpinned third-party action",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GithubWorkflowUntrustedRunInterpolationRule {
        code: "SEC325",
        summary: "GitHub Actions workflow interpolates untrusted expression data directly inside a run command",
        doc_title: "GitHub Actions: untrusted expression in run",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct GithubWorkflowPullRequestTargetHeadCheckoutRule {
        code: "SEC326",
        summary: "GitHub Actions pull_request_target workflow checks out untrusted pull request head content",
        doc_title: "GitHub Actions: pull_request_target checkout",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GithubWorkflowWriteAllPermissionsRule {
        code: "SEC327",
        summary: "GitHub Actions workflow grants GITHUB_TOKEN write-all permissions",
        doc_title: "GitHub Actions: write-all token",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct GithubWorkflowWriteCapableThirdPartyActionRule {
        code: "SEC328",
        summary: "GitHub Actions workflow combines explicit write-capable permissions with a third-party action",
        doc_title: "GitHub Actions: write-capable third-party action",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 5] = [
    NativeRuleSpec {
        metadata: GithubWorkflowUnpinnedThirdPartyActionRule::METADATA,
        surface: Surface::GithubWorkflow,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks workflow uses: entries for third-party actions that rely on mutable refs instead of immutable commit SHAs; positioned as a supply-chain hardening control rather than a direct exploit claim.",
            malicious_case_ids: &["github-workflow-third-party-unpinned-action"],
            benign_case_ids: &["github-workflow-pinned-third-party-action"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "GithubWorkflowSignals line-level uses: extraction gated by semantically confirmed workflow YAML.",
        },
        check: check_github_workflow_unpinned_third_party_action,
        safe_fix: None,
        suggestion_message: Some(
            "pin third-party GitHub actions to a full 40-character commit SHA",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GithubWorkflowUntrustedRunInterpolationRule::METADATA,
        surface: Surface::GithubWorkflow,
        default_presets: PREVIEW_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shell safety depends on how the interpolated expression is consumed inside the run command.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_github_workflow_untrusted_run_interpolation,
        safe_fix: None,
        suggestion_message: Some(
            "avoid interpolating github.event or inputs values directly inside run commands; route them through validated env handling first",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GithubWorkflowPullRequestTargetHeadCheckoutRule::METADATA,
        surface: Surface::GithubWorkflow,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks pull_request_target workflows for actions/checkout steps that explicitly pull untrusted pull request head refs instead of the safer default merge context.",
            malicious_case_ids: &["github-workflow-pull-request-target-head-checkout"],
            benign_case_ids: &["github-workflow-pull-request-target-safe-checkout"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "GithubWorkflowSignals event gating plus line-level checkout ref extraction for pull_request_target workflows.",
        },
        check: check_github_workflow_pull_request_target_head_checkout,
        safe_fix: None,
        suggestion_message: Some(
            "avoid checking out github.event.pull_request.head.* or github.head_ref in pull_request_target workflows",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GithubWorkflowWriteAllPermissionsRule::METADATA,
        surface: Surface::GithubWorkflow,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks workflow permissions for the explicit write-all shortcut, which exceeds least-privilege guidance for GITHUB_TOKEN.",
            malicious_case_ids: &["github-workflow-write-all-permissions"],
            benign_case_ids: &["github-workflow-read-only-permissions"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "GithubWorkflowSignals line-level permissions extraction for semantically confirmed workflow YAML.",
        },
        check: check_github_workflow_write_all_permissions,
        safe_fix: None,
        suggestion_message: Some(
            "replace write-all with the minimal explicit permissions your workflow actually needs",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: GithubWorkflowWriteCapableThirdPartyActionRule::METADATA,
        surface: Surface::GithubWorkflow,
        default_presets: PREVIEW_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Write-capable token scopes and third-party action usage are compositional and need more corpus-backed precision review before a stable launch.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_github_workflow_write_capable_third_party_action,
        safe_fix: None,
        suggestion_message: Some(
            "review whether write-capable token permissions are necessary when the workflow runs third-party actions",
        ),
        suggestion_fix: None,
    },
];
