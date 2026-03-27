use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Category, Confidence, Finding, Fix, ScanContext, Severity, WorkspaceScanContext};

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleTier {
    Stable,
    Preview,
    Deprecated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct RuleMetadata {
    pub code: &'static str,
    pub summary: &'static str,
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
        Self {
            code,
            summary,
            category,
            default_severity,
            default_confidence,
            tier,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ProviderCapabilities {
    pub supports_incremental: bool,
    pub supports_streaming: bool,
}

impl ProviderCapabilities {
    pub fn new(supports_incremental: bool, supports_streaming: bool) -> Self {
        Self {
            supports_incremental,
            supports_streaming,
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

pub trait RuleProvider: Send + Sync {
    fn id(&self) -> &str;
    fn rules(&self) -> &[RuleMetadata];
    fn check(&self, ctx: &ScanContext) -> Vec<Finding>;

    fn scan_scope(&self) -> ScanScope {
        ScanScope::PerFile
    }

    fn check_workspace(&self, _ctx: &WorkspaceScanContext) -> Vec<Finding> {
        Vec::new()
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(self.check(ctx), Vec::new())
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        ProviderScanResult::new(self.check_workspace(ctx), Vec::new())
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn supports_fix(&self) -> bool {
        false
    }

    fn fix(&self, _ctx: &ScanContext, _finding: &Finding) -> Option<Fix> {
        None
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }

    fn on_start(&self) -> Result<(), ProviderError> {
        Ok(())
    }

    fn on_finish(&self) -> Result<(), ProviderError> {
        Ok(())
    }
}
