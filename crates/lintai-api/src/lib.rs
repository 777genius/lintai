mod catalog;
mod catalog_validation;
mod context;
mod finding;
mod parsed;
mod preset;
mod rule;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use catalog::{
    CatalogDetectionClass, CatalogPublicLane, CatalogRemediationSupport, CatalogRuleEntry,
    CatalogRuleLifecycle, CatalogRuleScope, CatalogSurface,
};
pub use catalog_validation::{
    CatalogDetectionClassKind, CatalogLifecycleClass, CatalogLifecycleDetails, CatalogRuleIdentity,
    validate_group_ids, validate_rule_identities, validate_rule_presets,
    validate_rule_quality_contract,
};
pub use context::{
    CapabilityConflictMode, CapabilityProfile, ExecCapability, FileSystemCapability, McpCapability,
    NetworkCapability, ScanContext, SecretCapability, WorkspaceArtifact, WorkspaceScanContext,
};
pub use finding::{
    Applicability, Evidence, EvidenceKind, Finding, Fix, LineColumn, Location, RelatedFinding,
    Severity, Span, StableKey, Suggestion,
};
pub use parsed::{
    Artifact, ArtifactKind, DocumentSemantics, FrontmatterFormat, FrontmatterSemantics,
    JsonSemantics, MarkdownSemantics, ParsedDocument, RegionKind, ShellSemantics, SourceFormat,
    TextRegion, YamlSemantics,
};
pub use preset::{
    BuiltinPresetKind, BuiltinPresetSpec, builtin_membership_preset_ids, builtin_preset_ids,
    builtin_presets, builtin_public_lane_for_presets,
};
pub use rule::{
    FileRuleProvider, ProviderError, ProviderErrorKind, ProviderScanResult, RuleMetadata,
    RuleProvider, RuleTier, ScanScope, WorkspaceRuleProvider,
};

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Critical,
    Security,
    Hardening,
    Quality,
    Audit,
    Nursery,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }
}

#[macro_export]
macro_rules! declare_rule {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            code: $code:literal,
            summary: $summary:literal,
            $(doc_title: $doc_title:literal,)?
            category: $category:expr,
            default_severity: $severity:expr,
            default_confidence: $confidence:expr,
            $(tier: $tier:expr,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default)]
        $vis struct $name;

        impl $name {
            pub const METADATA: $crate::RuleMetadata =
                $crate::RuleMetadata::new_with_doc_title(
                    $code,
                    $summary,
                    $crate::declare_rule!(@doc_title $summary $(, $doc_title )?),
                    $category,
                    $severity,
                    $confidence,
                    $crate::declare_rule!(@tier $( $tier )?),
                );

            pub fn metadata(&self) -> &'static $crate::RuleMetadata {
                &Self::METADATA
            }
        }
    };
    (@tier $tier:expr) => {
        $tier
    };
    (@tier) => {
        $crate::RuleTier::Stable
    };
    (@doc_title $summary:expr, $doc_title:expr) => {
        $doc_title
    };
    (@doc_title $summary:expr) => {
        $summary
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    declare_rule! {
        struct SampleRule {
            code: "SEC999",
            summary: "sample",
            doc_title: "Sample rule",
            category: Category::Security,
            default_severity: Severity::Warn,
            default_confidence: Confidence::High,
            tier: RuleTier::Stable,
        }
    }

    #[test]
    fn declare_rule_exposes_static_metadata() {
        let rule = SampleRule;
        let metadata = rule.metadata();

        assert_eq!(metadata.code, "SEC999");
        assert_eq!(metadata.summary, "sample");
        assert_eq!(metadata.doc_title, "Sample rule");
        assert_eq!(metadata.category, Category::Security);
        assert_eq!(metadata.default_severity, Severity::Warn);
        assert_eq!(metadata.default_confidence, Confidence::High);
        assert_eq!(metadata.tier, RuleTier::Stable);
    }

    #[test]
    fn confidence_labels_and_slugs_are_stable() {
        assert_eq!(Confidence::High.slug(), "high");
        assert_eq!(Confidence::Medium.label(), "Medium");
    }
}
