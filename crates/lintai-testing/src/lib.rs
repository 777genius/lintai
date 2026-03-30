use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::{ArtifactKind, Finding, RuleProvider, RuleTier, SourceFormat};
use lintai_engine::{
    ConfigError, EngineBuilder, EngineConfig, EngineError, FileSuppressions,
    NoopSuppressionMatcher, ProviderExecutionPhase, RuntimeErrorKind, ScanSummary,
    SuppressionMatcher, load_workspace_config,
};
use lintai_runtime::{InProcessProviderBackend, ProviderBackend};
use serde::Deserialize;
use std::collections::BTreeMap;

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
        ProviderHarnessBuilder::new(Arc::new(InProcessProviderBackend::new(provider))).run_summary(
            artifact_kind,
            format,
            content,
        )
    }
}

struct ProviderHarnessBuilder {
    backend: Arc<dyn ProviderBackend>,
    config: EngineConfig,
    suppressions: Arc<dyn SuppressionMatcher>,
}

impl ProviderHarnessBuilder {
    fn new(backend: Arc<dyn ProviderBackend>) -> Self {
        Self {
            backend,
            config: EngineConfig::default(),
            suppressions: Arc::new(NoopSuppressionMatcher),
        }
    }

    fn run_summary(
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
            .with_backend(self.backend)
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
    #[serde(rename = "stable-key")]
    StableKey,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedRuntimeErrorKind {
    Read,
    InvalidUtf8,
    Parse,
    ProviderExecution,
    ProviderTimeout,
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
    #[serde(default)]
    pub expected_runtime_error_kinds: Vec<ExpectedRuntimeErrorKind>,
    pub expected_diagnostics: usize,
    pub expected_scanned_files: Option<usize>,
    pub expected_skipped_files: Option<usize>,
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
        let contents =
            std::fs::read_to_string(&manifest_path).map_err(|source| ManifestLoadError::Io {
                path: manifest_path.clone(),
                source,
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
    Config(ConfigError),
    Engine(EngineError),
    InvalidCaseRoot {
        case_dir: PathBuf,
        entry_root: PathBuf,
    },
    NotImplemented(&'static str),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => error.fmt(f),
            Self::Config(error) => error.fmt(f),
            Self::Engine(error) => error.fmt(f),
            Self::InvalidCaseRoot {
                case_dir,
                entry_root,
            } => write!(
                f,
                "case root {} resolves to missing or invalid entry root {}",
                case_dir.display(),
                entry_root.display()
            ),
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

impl From<ConfigError> for HarnessError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<EngineError> for HarnessError {
    fn from(value: EngineError) -> Self {
        Self::Engine(value)
    }
}

pub struct WorkspaceHarnessBuilder {
    backends: Vec<Arc<dyn ProviderBackend>>,
    override_config: Option<EngineConfig>,
    override_suppressions: Option<Arc<dyn SuppressionMatcher>>,
}

impl Default for WorkspaceHarnessBuilder {
    fn default() -> Self {
        Self {
            backends: Vec::new(),
            override_config: None,
            override_suppressions: None,
        }
    }
}

impl WorkspaceHarnessBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_backend(mut self, backend: Arc<dyn ProviderBackend>) -> Self {
        self.backends.push(backend);
        self
    }

    pub fn with_backends<I>(mut self, backends: I) -> Self
    where
        I: IntoIterator<Item = Arc<dyn ProviderBackend>>,
    {
        self.backends.extend(backends);
        self
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.override_config = Some(config);
        self
    }

    pub fn with_suppressions(mut self, suppressions: Arc<dyn SuppressionMatcher>) -> Self {
        self.override_suppressions = Some(suppressions);
        self
    }

    pub fn build(self) -> WorkspaceHarness {
        WorkspaceHarness {
            backends: self.backends,
            override_config: self.override_config,
            override_suppressions: self.override_suppressions,
        }
    }
}

pub struct WorkspaceHarness {
    backends: Vec<Arc<dyn ProviderBackend>>,
    override_config: Option<EngineConfig>,
    override_suppressions: Option<Arc<dyn SuppressionMatcher>>,
}

impl WorkspaceHarness {
    pub fn builder() -> WorkspaceHarnessBuilder {
        WorkspaceHarnessBuilder::new()
    }

    pub fn load_manifest(&self, case_dir: &Path) -> Result<CaseManifest, HarnessError> {
        let _ = &self.backends;
        Ok(CaseManifest::load(case_dir)?)
    }

    pub fn scan_case(&self, case_dir: &Path) -> Result<ScanSummary, HarnessError> {
        let manifest = self.load_manifest(case_dir)?;
        let entry_root = manifest.entry_root(case_dir);
        if !entry_root.is_dir() {
            return Err(HarnessError::InvalidCaseRoot {
                case_dir: case_dir.to_path_buf(),
                entry_root,
            });
        }

        let workspace = load_workspace_config(&entry_root)?;
        let effective_config = self
            .override_config
            .clone()
            .unwrap_or(workspace.engine_config);
        let suppressions: Arc<dyn SuppressionMatcher> =
            if let Some(overridden) = self.override_suppressions.clone() {
                overridden
            } else {
                Arc::new(FileSuppressions::load(&effective_config)?)
            };

        let mut builder = EngineBuilder::default()
            .with_config(effective_config)
            .with_suppressions(suppressions);
        for backend in &self.backends {
            builder = builder.with_backend(Arc::clone(backend));
        }

        Ok(builder.build().scan_path(&entry_root)?)
    }
}

pub fn discover_case_dirs(bucket_root: &Path) -> Result<Vec<PathBuf>, HarnessError> {
    let mut case_dirs = std::fs::read_dir(bucket_root)
        .map_err(|source| {
            HarnessError::Manifest(ManifestLoadError::Io {
                path: bucket_root.to_path_buf(),
                source,
            })
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && path.join("case.toml").is_file())
        .collect::<Vec<_>>();

    case_dirs.sort_by(|left, right| {
        let left_name = left
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or_default();
        let right_name = right
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or_default();
        left_name.cmp(right_name).then_with(|| left.cmp(right))
    });
    Ok(case_dirs)
}

pub fn assert_case_summary(manifest: &CaseManifest, summary: &ScanSummary) {
    assert_eq!(
        summary.runtime_errors.len(),
        manifest.expected_runtime_errors,
        "case `{}` runtime error count mismatch: {:?}",
        manifest.id,
        summary.runtime_errors
    );
    assert_eq!(
        runtime_error_kind_counts(&summary.runtime_errors),
        expected_runtime_error_kind_counts(&manifest.expected_runtime_error_kinds),
        "case `{}` runtime error kind mismatch: {:?}",
        manifest.id,
        summary.runtime_errors
    );
    assert_eq!(
        summary.diagnostics.len(),
        manifest.expected_diagnostics,
        "case `{}` diagnostics count mismatch: {:?}",
        manifest.id,
        summary.diagnostics
    );
    if let Some(expected_scanned_files) = manifest.expected_scanned_files {
        assert_eq!(
            summary.scanned_files, expected_scanned_files,
            "case `{}` scanned file count mismatch",
            manifest.id
        );
    }
    if let Some(expected_skipped_files) = manifest.expected_skipped_files {
        assert_eq!(
            summary.skipped_files, expected_skipped_files,
            "case `{}` skipped file count mismatch",
            manifest.id
        );
    }

    for expected in &manifest.expected_findings {
        let Some(found) = summary.findings.iter().find(|finding| {
            if finding.rule_code != expected.rule_code {
                return false;
            }
            if let Some(expected_stable_key) = &expected.stable_key {
                if format_stable_key(&finding.stable_key) != *expected_stable_key {
                    return false;
                }
            }
            if let Some(min_evidence_count) = expected.min_evidence_count {
                if finding.evidence.len() < min_evidence_count {
                    return false;
                }
            }
            true
        }) else {
            panic!(
                "case `{}` expected finding `{}` but no such finding was emitted; got {:?}",
                manifest.id, expected.rule_code, summary.findings
            );
        };

        if let Some(expected_stable_key) = &expected.stable_key {
            let actual = format_stable_key(&found.stable_key);
            assert_eq!(
                actual, *expected_stable_key,
                "case `{}` finding `{}` stable key mismatch",
                manifest.id, expected.rule_code
            );
        }

        if let Some(expected_tier) = expected.tier {
            let actual_tier = known_rule_tier(&expected.rule_code).unwrap_or_else(|| {
                panic!(
                    "case `{}` expected tier for unknown rule `{}`",
                    manifest.id, expected.rule_code
                )
            });
            assert_eq!(
                actual_tier, expected_tier,
                "case `{}` rule tier mismatch for `{}`",
                manifest.id, expected.rule_code
            );
        }

        if let Some(min_evidence_count) = expected.min_evidence_count {
            assert!(
                found.evidence.len() >= min_evidence_count,
                "case `{}` finding `{}` evidence count too small: {} < {}",
                manifest.id,
                expected.rule_code,
                found.evidence.len(),
                min_evidence_count
            );
        }
    }

    for absent_rule in &manifest.expected_absent_rules {
        assert!(
            summary
                .findings
                .iter()
                .all(|finding| finding.rule_code != *absent_rule),
            "case `{}` expected rule `{}` to stay absent, got {:?}",
            manifest.id,
            absent_rule,
            summary.findings
        );
    }
}

pub struct OutputHarness;

impl OutputHarness {
    fn snapshot_path(
        case_dir: &Path,
        snapshot: &SnapshotExpectation,
    ) -> Result<PathBuf, HarnessError> {
        let file_name = match snapshot.kind {
            SnapshotKind::None => {
                return Err(HarnessError::NotImplemented(
                    "snapshot path resolution requires a concrete snapshot kind",
                ));
            }
            SnapshotKind::Json => format!("{}.json", snapshot.name),
            SnapshotKind::Sarif => format!("{}.sarif.json", snapshot.name),
            SnapshotKind::ExplainConfig | SnapshotKind::StableKey => {
                format!("{}.txt", snapshot.name)
            }
        };
        Ok(case_dir.join("snapshots").join(file_name))
    }

    pub fn assert_snapshot(
        case_dir: &Path,
        snapshot: &SnapshotExpectation,
        actual: &str,
    ) -> Result<(), HarnessError> {
        let snapshot_path = Self::snapshot_path(case_dir, snapshot)?;
        let expected = std::fs::read_to_string(&snapshot_path).map_err(|source| {
            HarnessError::Manifest(ManifestLoadError::Io {
                path: snapshot_path.clone(),
                source,
            })
        })?;
        assert_eq!(
            expected,
            actual,
            "snapshot mismatch for {}",
            snapshot_path.display()
        );
        Ok(())
    }

    pub fn stable_keys_text(summary: &ScanSummary) -> String {
        let mut lines = summary
            .findings
            .iter()
            .map(|finding| format_stable_key(&finding.stable_key))
            .collect::<Vec<_>>();
        if lines.is_empty() {
            return String::new();
        }
        lines.push(String::new());
        lines.join("\n")
    }

    pub fn provider_metrics_text(summary: &ScanSummary) -> String {
        let mut buckets: BTreeMap<(&str, ProviderExecutionPhase), (usize, usize, usize)> =
            BTreeMap::new();
        for metric in &summary.provider_metrics {
            let entry = buckets
                .entry((metric.provider_id.as_str(), metric.phase))
                .or_default();
            entry.0 += 1;
            entry.1 += metric.findings_emitted;
            entry.2 += metric.errors_emitted;
        }

        if buckets.is_empty() {
            return String::new();
        }

        let mut lines = buckets
            .into_iter()
            .map(|((provider_id, phase), (invocations, findings, errors))| {
                format!(
                    "provider={} phase={} invocations={} findings={} errors={}",
                    provider_id,
                    provider_phase_label(phase),
                    invocations,
                    findings,
                    errors
                )
            })
            .collect::<Vec<_>>();
        lines.push(String::new());
        lines.join("\n")
    }
}

fn provider_phase_label(phase: ProviderExecutionPhase) -> &'static str {
    match phase {
        ProviderExecutionPhase::File => "file",
        ProviderExecutionPhase::Workspace => "workspace",
    }
}

fn known_rule_tier(rule_code: &str) -> Option<RuleTier> {
    match rule_code {
        "SEC201" | "SEC202" | "SEC203" | "SEC204" | "SEC205" | "SEC206" | "SEC301" | "SEC302"
        | "SEC303" | "SEC304" | "SEC305" | "SEC309" | "SEC310" | "SEC311" | "SEC312" | "SEC314"
        | "SEC315" | "SEC316" | "SEC317" | "SEC318" | "SEC319" | "SEC320" | "SEC321" | "SEC322"
        | "SEC324" | "SEC326" | "SEC327" | "SEC329" | "SEC330" | "SEC331" | "SEC337" | "SEC338"
        | "SEC339" | "SEC340" | "SEC341" | "SEC342" | "SEC343" | "SEC344" | "SEC345" | "SEC346" => {
            Some(RuleTier::Stable)
        }
        "SEC101" | "SEC102" | "SEC103" | "SEC104" | "SEC105" | "SEC306" | "SEC307" | "SEC308"
        | "SEC313" | "SEC323" | "SEC325" | "SEC328" | "SEC335" | "SEC336" | "SEC347" | "SEC348"
        | "SEC349" | "SEC350" | "SEC351" | "SEC352" | "SEC353" | "SEC354" | "SEC355" | "SEC356"
        | "SEC357" | "SEC358" | "SEC359" | "SEC360" | "SEC361" | "SEC362" | "SEC363" | "SEC364"
        | "SEC365" | "SEC366" | "SEC367" | "SEC368" | "SEC369" | "SEC370" | "SEC371" | "SEC372"
        | "SEC373" | "SEC374" | "SEC375" | "SEC376" | "SEC377" | "SEC401" | "SEC402" | "SEC403" => {
            Some(RuleTier::Preview)
        }
        _ => None,
    }
}

fn format_stable_key(stable_key: &lintai_api::StableKey) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        stable_key.rule_code,
        stable_key.normalized_path,
        stable_key.span.start_byte,
        stable_key.span.end_byte,
        stable_key.subject_id.as_deref().unwrap_or("")
    )
}

fn fixture_path_for(artifact_kind: ArtifactKind, format: SourceFormat) -> &'static Path {
    match (artifact_kind, format) {
        (ArtifactKind::Skill, SourceFormat::Markdown) => Path::new("docs/SKILL.md"),
        (ArtifactKind::Instructions, SourceFormat::Markdown) => Path::new("CLAUDE.md"),
        (ArtifactKind::CursorRules, SourceFormat::Markdown) => Path::new("rules.mdc"),
        (ArtifactKind::McpConfig, SourceFormat::Json) => Path::new("mcp.json"),
        (ArtifactKind::ClaudeSettings, SourceFormat::Json) => Path::new(".claude/settings.json"),
        (ArtifactKind::ServerRegistryConfig, SourceFormat::Json) => Path::new("server.json"),
        (ArtifactKind::ToolDescriptorJson, SourceFormat::Json) => {
            Path::new("pkg/mcp/toolsets-full-tools.json")
        }
        (ArtifactKind::GitHubWorkflow, SourceFormat::Yaml) => Path::new(".github/workflows/ci.yml"),
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

fn expected_runtime_error_kind_counts(
    expected_kinds: &[ExpectedRuntimeErrorKind],
) -> BTreeMap<ExpectedRuntimeErrorKind, usize> {
    let mut counts = BTreeMap::new();
    for kind in expected_kinds {
        *counts.entry(*kind).or_insert(0) += 1;
    }
    counts
}

fn runtime_error_kind_counts(
    runtime_errors: &[lintai_engine::ScanRuntimeError],
) -> BTreeMap<ExpectedRuntimeErrorKind, usize> {
    let mut counts = BTreeMap::new();
    for error in runtime_errors {
        let kind = match error.kind {
            RuntimeErrorKind::Read => ExpectedRuntimeErrorKind::Read,
            RuntimeErrorKind::InvalidUtf8 => ExpectedRuntimeErrorKind::InvalidUtf8,
            RuntimeErrorKind::Parse => ExpectedRuntimeErrorKind::Parse,
            RuntimeErrorKind::ProviderExecution => ExpectedRuntimeErrorKind::ProviderExecution,
            RuntimeErrorKind::ProviderTimeout => ExpectedRuntimeErrorKind::ProviderTimeout,
        };
        *counts.entry(kind).or_insert(0) += 1;
    }
    counts
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
    use std::path::{Path, PathBuf};

    use super::{
        CaseManifest, HarnessError, HarnessOutputFormat, OutputHarness, SnapshotExpectation,
        SnapshotKind, WorkspaceHarness, assert_case_summary, discover_case_dirs, repo_root,
        unique_temp_dir,
    };
    use lintai_api::{
        Category, Confidence, Finding, Location, RuleMetadata, RuleTier, Severity, Span,
    };
    use lintai_engine::{RuntimeErrorKind, ScanRuntimeError};

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
        assert!(manifest.expected_runtime_error_kinds.is_empty());
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
    fn parses_manifest_with_stable_key_snapshot_kind() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "stable-key-shape"
kind = "compat"
entry_path = "repo"
expected_output = ["json"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "stable-key"
name = "stable-key-shape"
"#,
        )
        .unwrap();

        assert_eq!(manifest.snapshot.kind, SnapshotKind::StableKey);
    }

    #[test]
    fn rejects_manifest_with_invalid_runtime_error_kind() {
        let error = CaseManifest::from_toml(
            r#"
id = "bad-runtime-kind"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 1
expected_runtime_error_kinds = ["explode"]
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("expected_runtime_error_kinds"));
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
            "sample-repos/fixable-comments",
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
    fn discover_case_dirs_returns_sorted_case_roots() {
        let benign_root = repo_root().join("corpus/benign");
        let cases = discover_case_dirs(&benign_root).unwrap();
        let names = cases
            .iter()
            .map(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();

        let mut sorted_names = names.clone();
        sorted_names.sort();
        assert_eq!(
            names, sorted_names,
            "discover_case_dirs should return sorted case roots"
        );

        for required in [
            "cursor-plugin-clean-basic",
            "mcp-safe-basic",
            "mixed-clean-workspace",
            "policy-truthful-basic",
            "skill-clean-basic",
            "tool-json-openai-strict-locked",
        ] {
            assert!(
                names.iter().any(|name| name == required),
                "expected benign corpus to contain representative case {required}"
            );
        }

        assert!(
            names.len() >= 10,
            "expected benign corpus to contain a non-trivial checked-in case set"
        );
    }

    #[test]
    fn placeholder_cases_are_discoverable() {
        let root = repo_root();
        let harness = WorkspaceHarness::builder().build();

        for relative in [
            "corpus/benign/skill-clean-basic",
            "corpus/malicious/hook-download-exec",
            "corpus/edge/bom-frontmatter-skill",
            "corpus/compat/json-report-shape",
            "sample-repos/clean",
            "sample-repos/mcp-heavy",
            "sample-repos/fixable-comments",
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

    #[test]
    fn scan_case_reports_invalid_case_root() {
        let temp_dir = unique_temp_dir("lintai-invalid-case");
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::fs::write(
            temp_dir.join("case.toml"),
            r#"
id = "invalid-root"
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
        .unwrap();

        let error = WorkspaceHarness::builder()
            .build()
            .scan_case(&temp_dir)
            .unwrap_err();
        assert!(matches!(error, HarnessError::InvalidCaseRoot { .. }));
    }

    #[test]
    fn scan_case_uses_real_workspace_config_path() {
        let temp_dir = unique_temp_dir("lintai-configured-case");
        std::fs::create_dir_all(temp_dir.join("repo/docs")).unwrap();
        std::fs::write(
            temp_dir.join("case.toml"),
            r#"
id = "configured-case"
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
        .unwrap();
        std::fs::write(
            temp_dir.join("repo/lintai.toml"),
            "[files]\ninclude = [\"docs/**/*.md\"]\n",
        )
        .unwrap();
        std::fs::write(temp_dir.join("repo/docs/SKILL.md"), "# Configured\n").unwrap();

        let summary = WorkspaceHarness::builder()
            .build()
            .scan_case(&temp_dir)
            .unwrap();
        assert_eq!(summary.scanned_files, 1);
        assert!(summary.findings.is_empty());
    }

    #[test]
    fn assert_case_summary_accepts_expected_empty_summary() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "empty"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = ["SEC101"]

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap();

        assert_case_summary(&manifest, &lintai_engine::ScanSummary::default());
    }

    #[test]
    fn snapshot_path_uses_expected_extensions() {
        let case_dir = Path::new("/tmp/case");

        let json = OutputHarness::snapshot_path(
            case_dir,
            &SnapshotExpectation {
                kind: SnapshotKind::Json,
                name: "report".to_owned(),
            },
        )
        .unwrap();
        let sarif = OutputHarness::snapshot_path(
            case_dir,
            &SnapshotExpectation {
                kind: SnapshotKind::Sarif,
                name: "report".to_owned(),
            },
        )
        .unwrap();
        let explain = OutputHarness::snapshot_path(
            case_dir,
            &SnapshotExpectation {
                kind: SnapshotKind::ExplainConfig,
                name: "report".to_owned(),
            },
        )
        .unwrap();
        let stable_key = OutputHarness::snapshot_path(
            case_dir,
            &SnapshotExpectation {
                kind: SnapshotKind::StableKey,
                name: "report".to_owned(),
            },
        )
        .unwrap();

        assert_eq!(json, PathBuf::from("/tmp/case/snapshots/report.json"));
        assert_eq!(
            sarif,
            PathBuf::from("/tmp/case/snapshots/report.sarif.json")
        );
        assert_eq!(explain, PathBuf::from("/tmp/case/snapshots/report.txt"));
        assert_eq!(stable_key, PathBuf::from("/tmp/case/snapshots/report.txt"));
    }

    #[test]
    fn assert_snapshot_passes_on_exact_match() {
        let temp_dir = unique_temp_dir("lintai-snapshot-match");
        std::fs::create_dir_all(temp_dir.join("snapshots")).unwrap();
        std::fs::write(
            temp_dir.join("snapshots/report.json"),
            "{\n  \"ok\": true\n}\n",
        )
        .unwrap();

        OutputHarness::assert_snapshot(
            &temp_dir,
            &SnapshotExpectation {
                kind: SnapshotKind::Json,
                name: "report".to_owned(),
            },
            "{\n  \"ok\": true\n}\n",
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "snapshot mismatch")]
    fn assert_snapshot_rejects_drift() {
        let temp_dir = unique_temp_dir("lintai-snapshot-drift");
        std::fs::create_dir_all(temp_dir.join("snapshots")).unwrap();
        std::fs::write(temp_dir.join("snapshots/report.txt"), "expected\n").unwrap();

        OutputHarness::assert_snapshot(
            &temp_dir,
            &SnapshotExpectation {
                kind: SnapshotKind::ExplainConfig,
                name: "report".to_owned(),
            },
            "actual\n",
        )
        .unwrap();
    }

    #[test]
    fn stable_keys_text_is_deterministic_and_ordered() {
        let meta = RuleMetadata::new(
            "SEC900",
            "demo",
            Category::Security,
            Severity::Warn,
            Confidence::High,
            RuleTier::Stable,
        );
        let first = Finding::new(&meta, Location::new("a.md", Span::new(0, 1)), "first");
        let second = Finding::new(&meta, Location::new("b.md", Span::new(1, 2)), "second");
        let summary = lintai_engine::ScanSummary {
            findings: vec![first, second],
            ..lintai_engine::ScanSummary::default()
        };

        assert_eq!(
            OutputHarness::stable_keys_text(&summary),
            "SEC900:a.md:0:1:\nSEC900:b.md:1:2:\n"
        );
    }

    #[test]
    fn assert_case_summary_accepts_expected_parse_runtime_error() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "parse-error"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 1
expected_runtime_error_kinds = ["parse"]
expected_diagnostics = 0
expected_scanned_files = 0
expected_skipped_files = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap();
        let mut summary = lintai_engine::ScanSummary::default();
        summary.runtime_errors.push(ScanRuntimeError {
            normalized_path: "docs/SKILL.md".to_owned(),
            kind: RuntimeErrorKind::Parse,
            provider_id: None,
            phase: None,
            message: "unterminated frontmatter".to_owned(),
        });

        assert_case_summary(&manifest, &summary);
    }

    #[test]
    #[should_panic(expected = "expected rule `SEC101` to stay absent")]
    fn assert_case_summary_rejects_unexpected_present_rule() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "present-rule"
kind = "benign"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_absent_rules = ["SEC101"]

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap();

        let finding = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC101",
                "demo",
                lintai_api::Category::Security,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                RuleTier::Stable,
            ),
            lintai_api::Location::new("docs/SKILL.md", lintai_api::Span::new(0, 1)),
            "demo",
        );
        let mut summary = lintai_engine::ScanSummary::default();
        summary.findings.push(finding);

        assert_case_summary(&manifest, &summary);
    }

    #[test]
    #[should_panic(expected = "runtime error count mismatch")]
    fn assert_case_summary_rejects_runtime_error_mismatch() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "runtime-errors"
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
        .unwrap();

        let mut summary = lintai_engine::ScanSummary::default();
        summary
            .runtime_errors
            .push(lintai_engine::ScanRuntimeError {
                normalized_path: "docs/SKILL.md".to_owned(),
                kind: lintai_engine::RuntimeErrorKind::Read,
                provider_id: None,
                phase: None,
                message: "boom".to_owned(),
            });

        assert_case_summary(&manifest, &summary);
    }

    #[test]
    #[should_panic(expected = "diagnostics count mismatch")]
    fn assert_case_summary_rejects_diagnostics_mismatch() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "diagnostics"
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
        .unwrap();

        let mut summary = lintai_engine::ScanSummary::default();
        summary.diagnostics.push(lintai_engine::ScanDiagnostic {
            normalized_path: "docs/SKILL.md".to_owned(),
            severity: lintai_engine::DiagnosticSeverity::Warn,
            code: Some("demo".to_owned()),
            message: "boom".to_owned(),
        });

        assert_case_summary(&manifest, &summary);
    }

    #[test]
    #[should_panic(expected = "runtime error kind mismatch")]
    fn assert_case_summary_rejects_wrong_runtime_error_kind() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "wrong-runtime-kind"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 1
expected_runtime_error_kinds = ["parse"]
expected_diagnostics = 0
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap();
        let mut summary = lintai_engine::ScanSummary::default();
        summary.runtime_errors.push(ScanRuntimeError {
            normalized_path: "docs/SKILL.md".to_owned(),
            kind: RuntimeErrorKind::Read,
            provider_id: None,
            phase: None,
            message: "io".to_owned(),
        });

        assert_case_summary(&manifest, &summary);
    }

    #[test]
    #[should_panic(expected = "scanned file count mismatch")]
    fn assert_case_summary_rejects_wrong_scanned_file_count() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "wrong-scanned"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_scanned_files = 1
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap();

        assert_case_summary(&manifest, &lintai_engine::ScanSummary::default());
    }

    #[test]
    #[should_panic(expected = "skipped file count mismatch")]
    fn assert_case_summary_rejects_wrong_skipped_file_count() {
        let manifest = CaseManifest::from_toml(
            r#"
id = "wrong-skipped"
kind = "edge"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 0
expected_skipped_files = 1
expected_absent_rules = []

[snapshot]
kind = "none"
name = ""
"#,
        )
        .unwrap();

        assert_case_summary(&manifest, &lintai_engine::ScanSummary::default());
    }
}
