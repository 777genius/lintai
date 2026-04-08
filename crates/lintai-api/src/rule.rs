use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Category, Confidence, Finding, ScanContext, Severity, WorkspaceScanContext};

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleTier {
    Stable,
    Preview,
}

impl RuleTier {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Stable => "Stable",
            Self::Preview => "Preview",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct RuleMetadata {
    pub code: &'static str,
    pub summary: &'static str,
    pub doc_title: &'static str,
    pub category: Category,
    pub default_severity: Severity,
    pub default_confidence: Confidence,
    pub tier: RuleTier,
}

impl RuleMetadata {
    pub const fn new(
        code: &'static str,
        summary: &'static str,
        category: Category,
        default_severity: Severity,
        default_confidence: Confidence,
        tier: RuleTier,
    ) -> Self {
        Self::new_with_doc_title(
            code,
            summary,
            summary,
            category,
            default_severity,
            default_confidence,
            tier,
        )
    }

    pub const fn new_with_doc_title(
        code: &'static str,
        summary: &'static str,
        doc_title: &'static str,
        category: Category,
        default_severity: Severity,
        default_confidence: Confidence,
        tier: RuleTier,
    ) -> Self {
        Self {
            code,
            summary,
            doc_title,
            category,
            default_severity,
            default_confidence,
            tier,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanScope {
    #[default]
    PerFile,
    Workspace,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ProviderError {
    pub provider_id: String,
    #[serde(default)]
    pub kind: ProviderErrorKind,
    pub message: String,
}

impl ProviderError {
    pub fn new(provider_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            kind: ProviderErrorKind::Execution,
            message: message.into(),
        }
    }

    pub fn timeout(provider_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            kind: ProviderErrorKind::Timeout,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    #[default]
    Execution,
    Timeout,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ProviderScanResult {
    pub findings: Vec<Finding>,
    pub errors: Vec<ProviderError>,
}

impl ProviderScanResult {
    pub fn new(findings: Vec<Finding>, errors: Vec<ProviderError>) -> Self {
        Self { findings, errors }
    }
}

pub trait FileRuleProvider: Send + Sync {
    fn id(&self) -> &str;
    fn rules(&self) -> &[RuleMetadata];
    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult;
}

pub trait WorkspaceRuleProvider: Send + Sync {
    fn id(&self) -> &str;
    fn rules(&self) -> &[RuleMetadata];
    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult;
}

pub trait RuleProvider: Send + Sync {
    fn id(&self) -> &str;
    fn rules(&self) -> &[RuleMetadata];
    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult;

    fn check_workspace_result(&self, _ctx: &WorkspaceScanContext) -> ProviderScanResult {
        ProviderScanResult::new(Vec::new(), Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Artifact, ArtifactKind, CapabilityConflictMode, ParsedDocument, SourceFormat};
    use super::*;
    use std::mem;

    #[derive(Default)]
    struct TestRuleProvider;

    impl RuleProvider for TestRuleProvider {
        fn id(&self) -> &str {
            "test-provider"
        }

        fn rules(&self) -> &[RuleMetadata] {
            static RULES: [RuleMetadata; 1] = [RuleMetadata::new(
                "TEST001",
                "sample rule",
                Category::Security,
                Severity::Warn,
                Confidence::High,
                RuleTier::Preview,
            )];

            &RULES
        }

        fn check_result(&self, _ctx: &ScanContext) -> ProviderScanResult {
            ProviderScanResult::new(Vec::new(), Vec::new())
        }
    }

    #[test]
    fn rule_metadata_helpers_match_contract() {
        let rule = RuleMetadata::new(
            "SEC001",
            "summary",
            Category::Audit,
            Severity::Allow,
            Confidence::Low,
            RuleTier::Preview,
        );
        assert_eq!(rule.code, "SEC001");
        assert_eq!(rule.summary, "summary");
        assert_eq!(rule.doc_title, "summary");
        assert_eq!(rule.default_confidence, Confidence::Low);
        let rule_with_title = RuleMetadata::new_with_doc_title(
            "SEC002",
            "summary",
            "Doc title",
            Category::Quality,
            Severity::Warn,
            Confidence::Medium,
            RuleTier::Stable,
        );
        assert_eq!(rule_with_title.doc_title, "Doc title");
    }

    #[test]
    fn scan_scope_helpers_are_stable() {
        assert!(matches!(ScanScope::PerFile, ScanScope::PerFile));
        assert!(matches!(ScanScope::Workspace, ScanScope::Workspace));
        assert_ne!(mem::discriminant(&ScanScope::PerFile), mem::discriminant(&ScanScope::Workspace));
        assert_eq!(RuleTier::Stable.label(), "Stable");
        assert_eq!(RuleTier::Preview.label(), "Preview");
    }

    #[test]
    fn provider_error_and_scan_result_cover_defaults() {
        let err = ProviderError::new("p", "oops");
        let timeout_err = ProviderError::timeout("p", "timeout");
        assert_eq!(err.provider_id, "p");
        assert_eq!(timeout_err.kind, ProviderErrorKind::Timeout);
        assert_eq!(err.kind, ProviderErrorKind::Execution);

        let findings = Vec::new();
        let errors = vec![err.clone(), timeout_err];
        let result = ProviderScanResult::new(findings.clone(), errors.clone());
        assert_eq!(result.findings, findings);
        assert_eq!(result.errors, errors);
    }

    #[test]
    fn rule_provider_default_workspace_result_is_empty() {
        let provider = TestRuleProvider;
        let empty_document = ParsedDocument::new(Vec::new(), None);
        let ctx = ScanContext::new(
            Artifact::new("repo/test.md", ArtifactKind::Instructions, SourceFormat::Markdown),
            "content",
            empty_document,
            None,
        );
        let result = provider.check_workspace_result(&WorkspaceScanContext::new(
            None,
            Vec::new(),
            None,
            CapabilityConflictMode::Warn,
        ));
        assert!(result.findings.is_empty());
        assert!(result.errors.is_empty());
        let check_result = provider.check_result(&ctx);
        assert_eq!(check_result.findings.len(), 0);
        assert_eq!(check_result.errors.len(), 0);
    }
}
