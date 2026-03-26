use std::collections::BTreeMap;
use std::path::PathBuf;

use globset::GlobSet;
use lintai_api::{
    ArtifactKind, CapabilityConflictMode, CapabilityProfile, Category, Confidence, Severity,
    SourceFormat,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub(crate) const DEFAULT_INCLUDE_PATTERNS: &[&str] = &[
    "*.md",
    "**/*.md",
    "*.mdc",
    "**/*.mdc",
    ".cursorrules",
    "**/.cursorrules",
    "*.json",
    "**/*.json",
    "*.sh",
    "**/*.sh",
];

pub(crate) const DEFAULT_EXCLUDE_PATTERNS: &[&str] = &[];

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiPolicy {
    pub fail_on: Severity,
    pub min_confidence: Confidence,
}

impl Default for CiPolicy {
    fn default() -> Self {
        Self {
            fail_on: Severity::Deny,
            min_confidence: Confidence::Medium,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SuppressPolicy {
    pub require_reason: bool,
    pub report_unused: bool,
    pub max_per_file: usize,
}

impl Default for SuppressPolicy {
    fn default() -> Self {
        Self {
            require_reason: true,
            report_unused: true,
            max_per_file: 10,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FileOverride {
    pub(crate) patterns: Vec<String>,
    pub(crate) matcher: GlobSet,
    pub(crate) category_overrides: BTreeMap<Category, Severity>,
    pub(crate) rule_overrides: BTreeMap<String, Severity>,
}

#[derive(Clone, Debug)]
pub struct DetectionOverride {
    pub(crate) matcher: GlobSet,
    pub kind: ArtifactKind,
    pub format: SourceFormat,
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub project_root: Option<PathBuf>,
    pub follow_symlinks: bool,
    pub output_format: OutputFormat,
    pub ci_policy: CiPolicy,
    pub suppress_policy: SuppressPolicy,
    pub capability_profile: Option<CapabilityProfile>,
    pub capability_conflict_mode: CapabilityConflictMode,
    pub(crate) include_patterns: Vec<String>,
    pub(crate) include_matcher: GlobSet,
    pub(crate) exclude_patterns: Vec<String>,
    pub(crate) exclude_matcher: GlobSet,
    pub(crate) category_overrides: BTreeMap<Category, Severity>,
    pub(crate) rule_overrides: BTreeMap<String, Severity>,
    pub(crate) overrides: Vec<FileOverride>,
    pub(crate) detection_overrides: Vec<DetectionOverride>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedFileConfig {
    pub normalized_path: String,
    pub included: bool,
    pub output_format: OutputFormat,
    pub ci_policy: CiPolicy,
    pub suppress_policy: SuppressPolicy,
    pub project_capabilities: Option<CapabilityProfile>,
    pub capability_conflict_mode: CapabilityConflictMode,
    pub applied_overrides: Vec<Vec<String>>,
    pub category_overrides: BTreeMap<Category, Severity>,
    pub rule_overrides: BTreeMap<String, Severity>,
    pub detected_kind: Option<ArtifactKind>,
    pub detected_format: Option<SourceFormat>,
}

impl ResolvedFileConfig {
    pub fn severity_for(&self, rule_code: &str, category: Category, default: Severity) -> Severity {
        self.rule_overrides
            .get(rule_code)
            .copied()
            .or_else(|| self.category_overrides.get(&category).copied())
            .unwrap_or(default)
    }
}

#[derive(Clone, Debug)]
pub struct WorkspaceConfig {
    pub source_path: Option<PathBuf>,
    pub engine_config: EngineConfig,
}

#[derive(Debug)]
pub struct ConfigError {
    message: String,
}

impl ConfigError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ConfigError {}
