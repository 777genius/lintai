use lintai_api::{
    ArtifactKind, CapabilityConflictMode, CapabilityProfile, Evidence, EvidenceKind,
    ExecCapability, Finding, Location, NetworkCapability, ProviderScanResult, RuleMetadata,
    RuleProvider, RuleTier, Span, WorkspaceArtifact, WorkspaceScanContext, declare_rule,
};

use crate::helpers::workspace_json_semantics;
use crate::registry::{
    DetectionClass, RemediationSupport, RuleLifecycle, Surface, WORKSPACE_PREVIEW_REQUIREMENTS,
};

pub(crate) const PROVIDER_ID: &str = "lintai-policy-mismatch";

declare_rule! {
    pub struct ProjectExecMismatchRule {
        code: "SEC401",
        summary: "Project policy forbids execution, but repository contains executable behavior",
        category: lintai_api::Category::Security,
        default_severity: lintai_api::Severity::Warn,
        default_confidence: lintai_api::Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ProjectNetworkMismatchRule {
        code: "SEC402",
        summary: "Project policy forbids network access, but repository contains network behavior",
        category: lintai_api::Category::Security,
        default_severity: lintai_api::Severity::Warn,
        default_confidence: lintai_api::Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct CapabilityConflictRule {
        code: "SEC403",
        summary: "Skill frontmatter capabilities conflict with project policy",
        category: lintai_api::Category::Security,
        default_severity: lintai_api::Severity::Warn,
        default_confidence: lintai_api::Confidence::High,
        tier: RuleTier::Preview,
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct PolicyRuleSpec {
    pub(crate) metadata: RuleMetadata,
    pub(crate) surface: Surface,
    pub(crate) detection_class: DetectionClass,
    pub(crate) lifecycle: RuleLifecycle,
    pub(crate) remediation_support: RemediationSupport,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const POLICY_RULE_SPECS: [PolicyRuleSpec; 3] = [
    PolicyRuleSpec {
        metadata: ProjectExecMismatchRule::METADATA,
        surface: Surface::Workspace,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Needs workspace-level precision review and linked graduation corpus before promotion to Stable.",
            promotion_requirements: WORKSPACE_PREVIEW_REQUIREMENTS,
        },
        remediation_support: RemediationSupport::None,
    },
    PolicyRuleSpec {
        metadata: ProjectNetworkMismatchRule::METADATA,
        surface: Surface::Workspace,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Needs workspace-level network precision review and linked graduation corpus before promotion to Stable.",
            promotion_requirements: WORKSPACE_PREVIEW_REQUIREMENTS,
        },
        remediation_support: RemediationSupport::None,
    },
    PolicyRuleSpec {
        metadata: CapabilityConflictRule::METADATA,
        surface: Surface::Workspace,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Needs workspace-level capability-conflict precision review and linked graduation corpus before promotion to Stable.",
            promotion_requirements: WORKSPACE_PREVIEW_REQUIREMENTS,
        },
        remediation_support: RemediationSupport::None,
    },
];

const POLICY_RULES: [RuleMetadata; 3] = [
    POLICY_RULE_SPECS[0].metadata,
    POLICY_RULE_SPECS[1].metadata,
    POLICY_RULE_SPECS[2].metadata,
];

pub struct PolicyMismatchProvider;

impl RuleProvider for PolicyMismatchProvider {
    fn id(&self) -> &str {
        PROVIDER_ID
    }

    fn rules(&self) -> &[RuleMetadata] {
        &POLICY_RULES
    }

    fn check_result(&self, _ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(Vec::new(), Vec::new())
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        let Some(project_capabilities) = ctx.project_capabilities.as_ref() else {
            return ProviderScanResult::new(Vec::new(), Vec::new());
        };

        let mut findings = Vec::new();
        for artifact in &ctx.artifacts {
            if exec_forbidden(project_capabilities) && artifact_observes_exec(artifact) {
                findings.push(policy_finding(
                    &ProjectExecMismatchRule::METADATA,
                    artifact,
                    "project policy declares `exec: none`, but this artifact contains executable behavior",
                    ctx.capability_conflict_mode,
                ));
            }

            if network_forbidden(project_capabilities) && artifact_observes_network(artifact) {
                findings.push(policy_finding(
                    &ProjectNetworkMismatchRule::METADATA,
                    artifact,
                    "project policy declares `network: none`, but this artifact contains network behavior",
                    ctx.capability_conflict_mode,
                ));
            }

            if let Some(frontmatter_caps) = artifact.capabilities.as_ref() {
                if capabilities_conflict(project_capabilities, &frontmatter_caps) {
                    findings.push(policy_finding(
                        &CapabilityConflictRule::METADATA,
                        artifact,
                        "skill frontmatter capabilities conflict with project policy",
                        ctx.capability_conflict_mode,
                    ));
                }
            }
        }

        ProviderScanResult::new(findings, Vec::new())
    }
}

fn policy_finding(
    meta: &RuleMetadata,
    artifact: &WorkspaceArtifact,
    message: &'static str,
    conflict_mode: CapabilityConflictMode,
) -> Finding {
    let mut finding = Finding::new(
        meta,
        artifact.location_hint.clone().unwrap_or_else(|| {
            Location::new(
                artifact.artifact.normalized_path.clone(),
                Span::new(0, artifact.content.len()),
            )
        }),
        message,
    );
    finding.evidence.clear();
    finding.evidence.push(Evidence::new(
        EvidenceKind::Claim,
        "project policy claims this capability is forbidden",
        None,
    ));
    finding.evidence.push(Evidence::new(
        EvidenceKind::ObservedBehavior,
        observed_message(meta.code),
        observed_location(artifact),
    ));
    if matches!(conflict_mode, CapabilityConflictMode::Deny) {
        finding.severity = lintai_api::Severity::Deny;
    }
    finding
}

fn exec_forbidden(profile: &CapabilityProfile) -> bool {
    matches!(profile.exec, Some(ExecCapability::None))
}

fn network_forbidden(profile: &CapabilityProfile) -> bool {
    matches!(profile.network, Some(NetworkCapability::None))
}

fn observed_message(rule_code: &str) -> &'static str {
    match rule_code {
        "SEC401" => "artifact contains executable behavior",
        "SEC402" => "artifact contains network behavior",
        "SEC403" => "artifact frontmatter capabilities conflict with project policy",
        _ => "artifact behavior conflicts with project policy",
    }
}

fn artifact_observes_exec(ctx: &WorkspaceArtifact) -> bool {
    match ctx.artifact.kind {
        ArtifactKind::CursorHookScript => true,
        ArtifactKind::McpConfig => workspace_json_semantics(ctx)
            .map(|json| contains_shell_wrapper(&json.value))
            .unwrap_or(false),
        _ => false,
    }
}

fn artifact_observes_network(ctx: &WorkspaceArtifact) -> bool {
    match ctx.artifact.kind {
        ArtifactKind::CursorHookScript => {
            let lowered = ctx.content.to_lowercase();
            lowered.contains("curl ")
                || lowered.contains("wget ")
                || lowered.contains("http://")
                || lowered.contains("https://")
        }
        ArtifactKind::McpConfig
        | ArtifactKind::CursorPluginManifest
        | ArtifactKind::CursorPluginHooks => workspace_json_semantics(ctx)
            .map(|json| contains_network_reference(&json.value))
            .unwrap_or(false),
        _ => false,
    }
}

fn capabilities_conflict(project: &CapabilityProfile, skill: &CapabilityProfile) -> bool {
    if exec_forbidden(project) && !matches!(skill.exec, None | Some(ExecCapability::None)) {
        return true;
    }
    if network_forbidden(project) && !matches!(skill.network, None | Some(NetworkCapability::None))
    {
        return true;
    }
    false
}

fn observed_location(ctx: &WorkspaceArtifact) -> Option<Location> {
    if matches!(ctx.artifact.kind, ArtifactKind::CursorHookScript) {
        return first_match_location(
            &ctx.artifact.normalized_path,
            &ctx.content,
            &["curl ", "wget ", "http://", "https://", "sh ", "bash "],
        );
    }

    if matches!(
        ctx.artifact.kind,
        ArtifactKind::McpConfig
            | ArtifactKind::CursorPluginManifest
            | ArtifactKind::CursorPluginHooks
    ) {
        return first_match_location(
            &ctx.artifact.normalized_path,
            &ctx.content,
            &[
                "http://",
                "https://",
                "\"command\"",
                "\"args\"",
                "\"sh\"",
                "\"bash\"",
            ],
        );
    }

    first_match_location(
        &ctx.artifact.normalized_path,
        &ctx.content,
        &["capabilities"],
    )
}

fn first_match_location(
    normalized_path: &str,
    content: &str,
    needles: &[&str],
) -> Option<Location> {
    let start = needles
        .iter()
        .filter_map(|needle| content.find(needle))
        .min()?;
    let end = needles
        .iter()
        .filter_map(|needle| content.find(needle).map(|offset| offset + needle.len()))
        .find(|offset| *offset >= start)
        .unwrap_or(start + 1);
    Some(Location::new(
        normalized_path.to_owned(),
        Span::new(start, end),
    ))
}

fn contains_shell_wrapper(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            let command = map
                .get("command")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let args = map
                .get("args")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            ((command == "sh" || command == "bash") && args.contains(&"-c"))
                || map.values().any(contains_shell_wrapper)
        }
        serde_json::Value::Array(items) => items.iter().any(contains_shell_wrapper),
        _ => false,
    }
}

fn contains_network_reference(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => {
            text.starts_with("http://") || text.starts_with("https://")
        }
        serde_json::Value::Array(items) => items.iter().any(contains_network_reference),
        serde_json::Value::Object(map) => map.values().any(contains_network_reference),
        _ => false,
    }
}
