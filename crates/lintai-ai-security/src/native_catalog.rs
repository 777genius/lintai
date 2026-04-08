use lintai_api::{
    CatalogDetectionClass, CatalogPublicLane, CatalogRemediationSupport, CatalogRuleEntry,
    CatalogRuleLifecycle, CatalogRuleScope, CatalogSurface, RuleMetadata,
    builtin_public_lane_for_presets,
};

use crate::registry::{
    DetectionClass, PROVIDER_ID, RemediationSupport, RuleLifecycle, Surface, rule_specs,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCatalogSurface {
    Markdown,
    Hook,
    Devcontainer,
    DockerCompose,
    Dockerfile,
    Json,
    ClaudeSettings,
    ToolJson,
    ServerJson,
    GithubWorkflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCatalogDetectionClass {
    Structural,
    Heuristic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCatalogRuleLifecycle {
    Preview {
        blocker: &'static str,
        promotion_requirements: &'static str,
    },
    Stable {
        rationale: &'static str,
        malicious_case_ids: &'static [&'static str],
        benign_case_ids: &'static [&'static str],
        requires_structured_evidence: bool,
        remediation_reviewed: bool,
        deterministic_signal_basis: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCatalogRemediationSupport {
    SafeFix,
    Suggestion,
    MessageOnly,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRuleCatalogEntry {
    pub metadata: RuleMetadata,
    pub provider_id: &'static str,
    pub surface: NativeCatalogSurface,
    pub default_presets: &'static [&'static str],
    pub public_lane: CatalogPublicLane,
    pub detection_class: NativeCatalogDetectionClass,
    pub lifecycle: NativeCatalogRuleLifecycle,
    pub remediation_support: NativeCatalogRemediationSupport,
}

pub fn ai_security_rule_catalog_entries() -> Vec<CatalogRuleEntry> {
    rule_specs()
        .iter()
        .map(|spec| CatalogRuleEntry {
            metadata: spec.metadata,
            provider_id: PROVIDER_ID,
            scope: CatalogRuleScope::PerFile,
            surface: map_catalog_surface(spec.surface),
            default_presets: spec.default_presets,
            public_lane: public_lane_for_presets(spec.default_presets),
            detection_class: map_catalog_detection_class(spec.detection_class),
            lifecycle: map_catalog_lifecycle(spec.lifecycle),
            remediation_support: map_catalog_remediation(spec.remediation_support()),
        })
        .collect()
}

pub fn native_rule_catalog_entries() -> Vec<NativeRuleCatalogEntry> {
    ai_security_rule_catalog_entries()
        .into_iter()
        .map(NativeRuleCatalogEntry::from)
        .collect()
}

impl From<CatalogRuleEntry> for NativeRuleCatalogEntry {
    fn from(entry: CatalogRuleEntry) -> Self {
        assert!(
            entry.scope == CatalogRuleScope::PerFile,
            "ai-security shared catalog entry {} unexpectedly declared {:?} scope",
            entry.metadata.code,
            entry.scope
        );
        Self {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            surface: map_native_surface(entry.surface),
            default_presets: entry.default_presets,
            public_lane: entry.public_lane,
            detection_class: map_native_detection_class(entry.detection_class),
            lifecycle: map_native_lifecycle(entry.lifecycle),
            remediation_support: map_native_remediation(entry.remediation_support),
        }
    }
}

impl From<NativeRuleCatalogEntry> for CatalogRuleEntry {
    fn from(entry: NativeRuleCatalogEntry) -> Self {
        Self {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: CatalogRuleScope::PerFile,
            surface: map_catalog_surface_from_native(entry.surface),
            default_presets: entry.default_presets,
            public_lane: entry.public_lane,
            detection_class: map_catalog_detection_class_from_native(entry.detection_class),
            lifecycle: map_catalog_lifecycle_from_native(entry.lifecycle),
            remediation_support: map_catalog_remediation_from_native(entry.remediation_support),
        }
    }
}

pub(crate) fn public_lane_for_presets(
    default_presets: &'static [&'static str],
) -> CatalogPublicLane {
    builtin_public_lane_for_presets(default_presets)
}

fn map_catalog_surface(surface: Surface) -> CatalogSurface {
    match surface {
        Surface::Markdown => CatalogSurface::Markdown,
        Surface::Hook => CatalogSurface::Hook,
        Surface::Devcontainer => CatalogSurface::Devcontainer,
        Surface::DockerCompose => CatalogSurface::DockerCompose,
        Surface::Dockerfile => CatalogSurface::Dockerfile,
        Surface::Json => CatalogSurface::Json,
        Surface::ClaudeSettings => CatalogSurface::ClaudeSettings,
        Surface::ToolJson => CatalogSurface::ToolJson,
        Surface::ServerJson => CatalogSurface::ServerJson,
        Surface::GithubWorkflow => CatalogSurface::GithubWorkflow,
        Surface::Workspace => unreachable!("workspace rules do not belong to lintai-ai-security"),
    }
}

fn map_native_surface(surface: CatalogSurface) -> NativeCatalogSurface {
    match surface {
        CatalogSurface::Markdown => NativeCatalogSurface::Markdown,
        CatalogSurface::Hook => NativeCatalogSurface::Hook,
        CatalogSurface::Devcontainer => NativeCatalogSurface::Devcontainer,
        CatalogSurface::DockerCompose => NativeCatalogSurface::DockerCompose,
        CatalogSurface::Dockerfile => NativeCatalogSurface::Dockerfile,
        CatalogSurface::Json => NativeCatalogSurface::Json,
        CatalogSurface::ClaudeSettings => NativeCatalogSurface::ClaudeSettings,
        CatalogSurface::ToolJson => NativeCatalogSurface::ToolJson,
        CatalogSurface::ServerJson => NativeCatalogSurface::ServerJson,
        CatalogSurface::GithubWorkflow => NativeCatalogSurface::GithubWorkflow,
        CatalogSurface::Workspace => {
            unreachable!("workspace rules do not belong to lintai-ai-security")
        }
    }
}

fn map_catalog_surface_from_native(surface: NativeCatalogSurface) -> CatalogSurface {
    match surface {
        NativeCatalogSurface::Markdown => CatalogSurface::Markdown,
        NativeCatalogSurface::Hook => CatalogSurface::Hook,
        NativeCatalogSurface::Devcontainer => CatalogSurface::Devcontainer,
        NativeCatalogSurface::DockerCompose => CatalogSurface::DockerCompose,
        NativeCatalogSurface::Dockerfile => CatalogSurface::Dockerfile,
        NativeCatalogSurface::Json => CatalogSurface::Json,
        NativeCatalogSurface::ClaudeSettings => CatalogSurface::ClaudeSettings,
        NativeCatalogSurface::ToolJson => CatalogSurface::ToolJson,
        NativeCatalogSurface::ServerJson => CatalogSurface::ServerJson,
        NativeCatalogSurface::GithubWorkflow => CatalogSurface::GithubWorkflow,
    }
}

fn map_catalog_detection_class(class: DetectionClass) -> CatalogDetectionClass {
    match class {
        DetectionClass::Structural => CatalogDetectionClass::Structural,
        DetectionClass::Heuristic => CatalogDetectionClass::Heuristic,
    }
}

fn map_native_detection_class(class: CatalogDetectionClass) -> NativeCatalogDetectionClass {
    match class {
        CatalogDetectionClass::Structural => NativeCatalogDetectionClass::Structural,
        CatalogDetectionClass::Heuristic => NativeCatalogDetectionClass::Heuristic,
    }
}

fn map_catalog_detection_class_from_native(
    class: NativeCatalogDetectionClass,
) -> CatalogDetectionClass {
    match class {
        NativeCatalogDetectionClass::Structural => CatalogDetectionClass::Structural,
        NativeCatalogDetectionClass::Heuristic => CatalogDetectionClass::Heuristic,
    }
}

fn map_catalog_lifecycle(lifecycle: RuleLifecycle) -> CatalogRuleLifecycle {
    match lifecycle {
        RuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        } => CatalogRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        },
        RuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        } => CatalogRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        },
    }
}

fn map_native_lifecycle(lifecycle: CatalogRuleLifecycle) -> NativeCatalogRuleLifecycle {
    match lifecycle {
        CatalogRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        } => NativeCatalogRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        },
        CatalogRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        } => NativeCatalogRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        },
    }
}

fn map_catalog_lifecycle_from_native(
    lifecycle: NativeCatalogRuleLifecycle,
) -> CatalogRuleLifecycle {
    match lifecycle {
        NativeCatalogRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        } => CatalogRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        },
        NativeCatalogRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        } => CatalogRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        },
    }
}

fn map_catalog_remediation(remediation: RemediationSupport) -> CatalogRemediationSupport {
    match remediation {
        RemediationSupport::SafeFix => CatalogRemediationSupport::SafeFix,
        RemediationSupport::Suggestion => CatalogRemediationSupport::Suggestion,
        RemediationSupport::MessageOnly => CatalogRemediationSupport::MessageOnly,
        RemediationSupport::None => CatalogRemediationSupport::None,
    }
}

fn map_native_remediation(
    remediation: CatalogRemediationSupport,
) -> NativeCatalogRemediationSupport {
    match remediation {
        CatalogRemediationSupport::SafeFix => NativeCatalogRemediationSupport::SafeFix,
        CatalogRemediationSupport::Suggestion => NativeCatalogRemediationSupport::Suggestion,
        CatalogRemediationSupport::MessageOnly => NativeCatalogRemediationSupport::MessageOnly,
        CatalogRemediationSupport::None => NativeCatalogRemediationSupport::None,
    }
}

fn map_catalog_remediation_from_native(
    remediation: NativeCatalogRemediationSupport,
) -> CatalogRemediationSupport {
    match remediation {
        NativeCatalogRemediationSupport::SafeFix => CatalogRemediationSupport::SafeFix,
        NativeCatalogRemediationSupport::Suggestion => CatalogRemediationSupport::Suggestion,
        NativeCatalogRemediationSupport::MessageOnly => CatalogRemediationSupport::MessageOnly,
        NativeCatalogRemediationSupport::None => CatalogRemediationSupport::None,
    }
}

#[cfg(test)]
mod tests {
    use lintai_api::{
        CatalogDetectionClass, CatalogRemediationSupport, CatalogRuleEntry, CatalogRuleLifecycle,
        CatalogRuleScope, CatalogSurface,
    };

    use super::{
        NativeCatalogDetectionClass, NativeCatalogRemediationSupport, NativeCatalogRuleLifecycle,
        NativeCatalogSurface, NativeRuleCatalogEntry, ai_security_rule_catalog_entries,
        native_rule_catalog_entries,
    };

    #[test]
    fn native_catalog_entries_convert_to_shared_catalog_entries() {
        for entry in native_rule_catalog_entries() {
            let converted = CatalogRuleEntry::from(entry);
            assert_eq!(converted.metadata, entry.metadata);
            assert_eq!(converted.provider_id, entry.provider_id);
            assert_eq!(converted.scope, CatalogRuleScope::PerFile);
            assert_eq!(converted.default_presets, entry.default_presets);
            assert_eq!(
                converted.surface.slug(),
                match entry.surface {
                    NativeCatalogSurface::Markdown => CatalogSurface::Markdown.slug(),
                    NativeCatalogSurface::Hook => CatalogSurface::Hook.slug(),
                    NativeCatalogSurface::Devcontainer => CatalogSurface::Devcontainer.slug(),
                    NativeCatalogSurface::DockerCompose => CatalogSurface::DockerCompose.slug(),
                    NativeCatalogSurface::Dockerfile => CatalogSurface::Dockerfile.slug(),
                    NativeCatalogSurface::Json => CatalogSurface::Json.slug(),
                    NativeCatalogSurface::ClaudeSettings => CatalogSurface::ClaudeSettings.slug(),
                    NativeCatalogSurface::ToolJson => CatalogSurface::ToolJson.slug(),
                    NativeCatalogSurface::ServerJson => CatalogSurface::ServerJson.slug(),
                    NativeCatalogSurface::GithubWorkflow => {
                        CatalogSurface::GithubWorkflow.slug()
                    }
                }
            );
            assert_eq!(
                converted.detection_class,
                match entry.detection_class {
                    NativeCatalogDetectionClass::Structural => CatalogDetectionClass::Structural,
                    NativeCatalogDetectionClass::Heuristic => CatalogDetectionClass::Heuristic,
                }
            );
            assert_eq!(
                converted.remediation_support,
                match entry.remediation_support {
                    NativeCatalogRemediationSupport::SafeFix => CatalogRemediationSupport::SafeFix,
                    NativeCatalogRemediationSupport::Suggestion => {
                        CatalogRemediationSupport::Suggestion
                    }
                    NativeCatalogRemediationSupport::MessageOnly => {
                        CatalogRemediationSupport::MessageOnly
                    }
                    NativeCatalogRemediationSupport::None => CatalogRemediationSupport::None,
                }
            );
            match (entry.lifecycle, converted.lifecycle) {
                (
                    NativeCatalogRuleLifecycle::Preview {
                        blocker: expected_blocker,
                        promotion_requirements: expected_requirements,
                    },
                    CatalogRuleLifecycle::Preview {
                        blocker,
                        promotion_requirements,
                    },
                ) => {
                    assert_eq!(blocker, expected_blocker);
                    assert_eq!(promotion_requirements, expected_requirements);
                }
                (
                    NativeCatalogRuleLifecycle::Stable {
                        rationale: expected_rationale,
                        malicious_case_ids: expected_malicious,
                        benign_case_ids: expected_benign,
                        requires_structured_evidence: expected_structured_evidence,
                        remediation_reviewed: expected_reviewed,
                        deterministic_signal_basis: expected_signal_basis,
                    },
                    CatalogRuleLifecycle::Stable {
                        rationale,
                        malicious_case_ids,
                        benign_case_ids,
                        requires_structured_evidence,
                        remediation_reviewed,
                        deterministic_signal_basis,
                    },
                ) => {
                    assert_eq!(rationale, expected_rationale);
                    assert_eq!(malicious_case_ids, expected_malicious);
                    assert_eq!(benign_case_ids, expected_benign);
                    assert_eq!(requires_structured_evidence, expected_structured_evidence);
                    assert_eq!(remediation_reviewed, expected_reviewed);
                    assert_eq!(deterministic_signal_basis, expected_signal_basis);
                }
                _ => panic!(
                    "native lifecycle conversion drifted for {}",
                    entry.metadata.code
                ),
            }
        }
    }

    #[test]
    fn shared_catalog_entries_stay_in_sync_with_native_catalog_entries() {
        let shared = ai_security_rule_catalog_entries();
        let native = native_rule_catalog_entries();
        assert_eq!(shared.len(), native.len());

        for (shared_entry, native_entry) in shared.into_iter().zip(native) {
            assert_eq!(NativeRuleCatalogEntry::from(shared_entry), native_entry);
        }
    }
}
