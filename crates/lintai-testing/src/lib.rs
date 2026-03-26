use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::{ArtifactKind, Finding, RuleProvider, RuleTier, SourceFormat};
use lintai_engine::{
    EngineBuilder, EngineConfig, NoopSuppressionMatcher, ScanSummary, SuppressionMatcher,
};
use serde::Deserialize;

pub struct ProviderHarness;

impl ProviderHarness {
    pub fn run(
        provider: Arc<dyn RuleProvider>,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> Vec<Finding> {
        Self::run_summary(provider, artifact_kind, format, content).findings
    }

    pub fn run_summary(
        provider: Arc<dyn RuleProvider>,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> ScanSummary {
        ProviderHarnessBuilder::new(provider).run_summary(artifact_kind, format, content)
    }
}

pub struct ProviderHarnessBuilder {
    provider: Arc<dyn RuleProvider>,
    config: EngineConfig,
    suppressions: Arc<dyn SuppressionMatcher>,
}

impl ProviderHarnessBuilder {
    pub fn new(provider: Arc<dyn RuleProvider>) -> Self {
        Self {
            provider,
            config: EngineConfig::default(),
            suppressions: Arc::new(NoopSuppressionMatcher),
        }
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_suppressions(mut self, suppressions: Arc<dyn SuppressionMatcher>) -> Self {
        self.suppressions = suppressions;
        self
    }

    pub fn run_summary(
        self,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> ScanSummary {
        let temp_dir = unique_temp_dir("lintai-provider-harness");
        let fixture_path = temp_dir.join(fixture_path_for(artifact_kind, format));
        std::fs::create_dir_all(
            fixture_path
                .parent()
                .expect("fixture path should always have a parent"),
        )
        .expect("fixture directory creation should succeed");
        std::fs::write(&fixture_path, content.into()).expect("fixture file write should succeed");

        let mut config = self.config;
        if config.project_root.is_none() {
            config.project_root = Some(temp_dir.clone());
        }

        let engine = EngineBuilder::default()
            .with_config(config)
            .with_suppressions(self.suppressions)
            .with_provider(self.provider)
            .build();
        let summary = engine
            .scan_path(&temp_dir)
            .expect("fixture scan should complete without fatal engine error");

        assert!(
            summary.runtime_errors.is_empty(),
            "fixture scan produced runtime errors: {:?}",
            summary.runtime_errors
        );

        summary
    }
}

pub struct RuleTester {
    provider: Arc<dyn RuleProvider>,
}

impl RuleTester {
    pub fn new(provider: Arc<dyn RuleProvider>) -> Self {
        Self { provider }
    }

    pub fn run_fixture(
        &self,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> Vec<Finding> {
        ProviderHarness::run(Arc::clone(&self.provider), artifact_kind, format, content)
    }

    pub fn assert_triggers(
        &self,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
        rule_code: &str,
    ) {
        let findings = self.run_fixture(artifact_kind, format, content);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_code == rule_code),
            "expected rule {rule_code} to trigger, got {findings:?}"
        );
    }

    pub fn assert_not_triggers(
        &self,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
        rule_code: &str,
    ) {
        let findings = self.run_fixture(artifact_kind, format, content);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_code != rule_code),
            "expected rule {rule_code} not to trigger, got {findings:?}"
        );
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CaseKind {
    Benign,
    Malicious,
    Edge,
    Compat,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HarnessOutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotKind {
    None,
    Json,
    Sarif,
    #[serde(rename = "explain-config")]
    ExplainConfig,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ExpectedFinding {
    pub rule_code: String,
    pub stable_key: Option<String>,
    pub tier: Option<RuleTier>,
    pub min_evidence_count: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SnapshotExpectation {
    pub kind: SnapshotKind,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CaseManifest {
    pub id: String,
    pub kind: CaseKind,
    pub entry_path: PathBuf,
    pub expected_output: Vec<HarnessOutputFormat>,
    pub expected_runtime_errors: usize,
    pub expected_diagnostics: usize,
    #[serde(default)]
    pub expected_findings: Vec<ExpectedFinding>,
    pub expected_absent_rules: Vec<String>,
    pub snapshot: SnapshotExpectation,
}

impl CaseManifest {
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    pub fn load(case_dir: &Path) -> Result<Self, ManifestLoadError> {
        let manifest_path = case_dir.join("case.toml");
        let contents = std::fs::read_to_string(&manifest_path).map_err(|source| {
            ManifestLoadError::Io {
                path: manifest_path.clone(),
                source,
            }
        })?;
        Self::from_toml(&contents).map_err(|source| ManifestLoadError::Parse {
            path: manifest_path,
            source,
        })
    }

    pub fn entry_root(&self, case_dir: &Path) -> PathBuf {
        case_dir.join(&self.entry_path)
    }
}

#[derive(Debug)]
pub enum ManifestLoadError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

impl fmt::Display for ManifestLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    f,
                    "failed to read case manifest at {}: {source}",
                    path.display()
                )
            }
            Self::Parse { path, source } => {
                write!(
                    f,
                    "failed to parse case manifest at {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ManifestLoadError {}

#[derive(Debug)]
pub enum HarnessError {
    Manifest(ManifestLoadError),
    NotImplemented(&'static str),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => error.fmt(f),
            Self::NotImplemented(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HarnessError {}

impl From<ManifestLoadError> for HarnessError {
    fn from(value: ManifestLoadError) -> Self {
        Self::Manifest(value)
    }
}

pub struct WorkspaceHarness {
    config: EngineConfig,
    suppressions: Arc<dyn SuppressionMatcher>,
}

impl Default for WorkspaceHarness {
    fn default() -> Self {
        Self {
            config: EngineConfig::default(),
            suppressions: Arc::new(NoopSuppressionMatcher),
        }
    }
}

impl WorkspaceHarness {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_suppressions(mut self, suppressions: Arc<dyn SuppressionMatcher>) -> Self {
        self.suppressions = suppressions;
        self
    }

    pub fn load_manifest(&self, case_dir: &Path) -> Result<CaseManifest, HarnessError> {
        let _ = &self.config;
        let _ = &self.suppressions;
        Ok(CaseManifest::load(case_dir)?)
    }

    pub fn scan_case(&self, case_dir: &Path) -> Result<ScanSummary, HarnessError> {
        let _ = self.load_manifest(case_dir)?;
        Err(HarnessError::NotImplemented(
            "workspace harness scanning is introduced in iteration 2",
        ))
    }
}

pub struct OutputHarness;

impl OutputHarness {
    pub fn render(
        _summary: &ScanSummary,
        _format: HarnessOutputFormat,
    ) -> Result<String, HarnessError> {
        Err(HarnessError::NotImplemented(
            "output harness rendering is introduced in iteration 4",
        ))
    }
}

fn fixture_path_for(artifact_kind: ArtifactKind, format: SourceFormat) -> &'static Path {
    match (artifact_kind, format) {
        (ArtifactKind::Skill, SourceFormat::Markdown) => Path::new("docs/SKILL.md"),
        (ArtifactKind::Instructions, SourceFormat::Markdown) => Path::new("CLAUDE.md"),
        (ArtifactKind::CursorRules, SourceFormat::Markdown) => Path::new("rules.mdc"),
        (ArtifactKind::McpConfig, SourceFormat::Json) => Path::new("mcp.json"),
        (ArtifactKind::CursorPluginManifest, SourceFormat::Json) => {
            Path::new(".cursor-plugin/plugin.json")
        }
        (ArtifactKind::CursorPluginHooks, SourceFormat::Json) => {
            Path::new(".cursor-plugin/hooks.json")
        }
        (ArtifactKind::CursorHookScript, SourceFormat::Shell) => {
            Path::new(".cursor-plugin/hooks/install.sh")
        }
        (ArtifactKind::CursorPluginCommand, SourceFormat::Markdown) => {
            Path::new(".cursor-plugin/commands/setup.md")
        }
        (ArtifactKind::CursorPluginAgent, SourceFormat::Markdown) => {
            Path::new(".cursor-plugin/agents/reviewer.md")
        }
        _ => panic!("unsupported fixture artifact/format combination"),
    }
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{nanos}-{sequence}",
        std::process::id()
    ))
}

#[cfg(test)]
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-testing")
}

#[cfg(test)]
mod tests {
    use super::{
        CaseManifest, HarnessOutputFormat, SnapshotKind, WorkspaceHarness, repo_root,
    };

    #[test]
    fn parses_valid_case_manifest() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "skill-clean-basic"
kind = "benign"
entry_path = "repo"
expected_output = ["text", "json", "sarif"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap();

        assert_eq!(manifest.id, "skill-clean-basic");
        assert_eq!(manifest.entry_path, std::path::PathBuf::from("repo"));
        assert_eq!(
            manifest.expected_output,
            vec![
                HarnessOutputFormat::Text,
                HarnessOutputFormat::Json,
                HarnessOutputFormat::Sarif,
            ]
        );
        assert_eq!(manifest.snapshot.kind, SnapshotKind::None);
    }

    #[test]
    fn rejects_manifest_missing_id() {
        let error = CaseManifest::from_toml(
            r#"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("id"));
    }

    #[test]
    fn rejects_manifest_with_invalid_kind() {
        let error = CaseManifest::from_toml(
            r#"
id = "bad-kind"
kind = "unknown"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("kind"));
    }

    #[test]
    fn rejects_manifest_with_invalid_snapshot_kind() {
        CaseManifest::from_toml(
            r#"
id = "bad-snapshot"
kind = "compat"
entry_path = "repo"
expected_output = ["json"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "xml"
name = "report"
"#,
        )
        .unwrap_err();
    }

    #[test]
    fn top_level_iteration_one_directories_exist() {
        let root = repo_root();

        for relative in [
            "corpus/benign",
            "corpus/malicious",
            "corpus/edge",
            "corpus/compat",
            "sample-repos/clean",
            "sample-repos/mcp-heavy",
            "sample-repos/cursor-plugin",
            "sample-repos/policy-mismatch",
            "tests/integration",
            ".github/workflows",
        ] {
            assert!(
                root.join(relative).is_dir(),
                "expected {} to exist",
                root.join(relative).display()
            );
        }
    }

    #[test]
    fn placeholder_cases_are_discoverable() {
        let root = repo_root();
        let harness = WorkspaceHarness::new();

        for relative in [
            "corpus/benign/skill-clean-basic",
            "corpus/malicious/hook-download-exec",
            "corpus/edge/crlf-skill",
            "corpus/compat/json-report-shape",
            "sample-repos/clean",
            "sample-repos/mcp-heavy",
            "sample-repos/cursor-plugin",
            "sample-repos/policy-mismatch",
        ] {
            let case_dir = root.join(relative);
            let manifest = harness.load_manifest(&case_dir).unwrap();
            assert!(
                manifest.entry_root(&case_dir).exists(),
                "expected entry root {} to exist",
                manifest.entry_root(&case_dir).display()
            );
        }
    }
}
