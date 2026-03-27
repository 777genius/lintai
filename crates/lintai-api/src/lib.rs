mod context;
mod finding;
mod parsed;
mod rule;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    TextRegion,
};
pub use rule::{
    ProviderError, ProviderErrorKind, ProviderScanResult, RuleMetadata, RuleProvider, RuleTier,
    ScanScope,
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

#[macro_export]
macro_rules! declare_rule {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            code: $code:literal,
            summary: $summary:literal,
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
                $crate::RuleMetadata::new(
                    $code,
                    $summary,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    declare_rule! {
        struct SampleRule {
            code: "SEC999",
            summary: "sample",
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
        assert_eq!(metadata.category, Category::Security);
        assert_eq!(metadata.default_severity, Severity::Warn);
        assert_eq!(metadata.default_confidence, Confidence::High);
        assert_eq!(metadata.tier, RuleTier::Stable);
    }
}
