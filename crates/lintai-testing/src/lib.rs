use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::{
    ArtifactKind, Finding, RuleProvider, RuleTier, SourceFormat, builtin_membership_preset_ids,
};
use lintai_engine::{
    ConfigError, EngineBuilder, EngineConfig, EngineError, FileSuppressions,
    NoopSuppressionMatcher, ProviderExecutionPhase, RuntimeErrorKind, ScanSummary,
    SuppressionMatcher, load_workspace_config,
};
use lintai_runtime::{InProcessProviderBackend, ProviderBackend};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
            std::fs::write(
                temp_dir.join("lintai.toml"),
                provider_harness_presets_config(),
            )
            .expect("provider harness config write should succeed");
            config = load_workspace_config(&temp_dir)
                .expect("provider harness workspace config should load")
                .engine_config;
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

fn provider_harness_presets_config() -> String {
    let enabled = builtin_membership_preset_ids()
        .into_iter()
        .map(|preset| format!("\"{preset}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[presets]\nenable = [{enabled}]\n")
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CaseKind {
    Benign,
    Malicious,
    Edge,
    Compat,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HarnessOutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedRuntimeErrorKind {
    Read,
    InvalidUtf8,
    Parse,
    ProviderExecution,
    ProviderTimeout,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExpectedFinding {
    pub rule_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stable_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<RuleTier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_evidence_count: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SnapshotExpectation {
    pub kind: SnapshotKind,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CaseManifest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub kind: CaseKind,
    pub entry_path: PathBuf,
    pub expected_output: Vec<HarnessOutputFormat>,
    pub expected_runtime_errors: usize,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub expected_runtime_error_kinds: Vec<ExpectedRuntimeErrorKind>,
    pub expected_diagnostics: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_scanned_files: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_skipped_files: Option<usize>,
    #[serde(default)]
    pub expected_findings: Vec<ExpectedFinding>,
    pub expected_absent_rules: Vec<String>,
    pub snapshot: SnapshotExpectation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CaseManifestDialectFlag {
    LegacyCaseSection,
    LegacyPathKeys,
    LegacyExpectKeys,
    ImplicitCanonicalDefaults,
    BucketScopedArtifactProviderKeys,
    ArtifactListShorthand,
    BucketScopedArtifactKind,
    BucketScopedExpectedRules,
    BucketScopedExpectations,
    BucketScopedExpectSection,
    BucketScopedSourcePath,
    BucketScopedSingleRule,
    StringExpectedFindings,
    RuleAliasExpectedFindings,
}

impl CaseManifestDialectFlag {
    pub fn label(self) -> &'static str {
        match self {
            Self::LegacyCaseSection => "legacy_case_section",
            Self::LegacyPathKeys => "legacy_path_keys",
            Self::LegacyExpectKeys => "legacy_expect_keys",
            Self::ImplicitCanonicalDefaults => "implicit_canonical_defaults",
            Self::BucketScopedArtifactProviderKeys => "bucket_scoped_artifact_provider_keys",
            Self::ArtifactListShorthand => "artifact_list_shorthand",
            Self::BucketScopedArtifactKind => "bucket_scoped_artifact_kind",
            Self::BucketScopedExpectedRules => "bucket_scoped_expected_rules",
            Self::BucketScopedExpectations => "bucket_scoped_expectations",
            Self::BucketScopedExpectSection => "bucket_scoped_expect_section",
            Self::BucketScopedSourcePath => "bucket_scoped_source_path",
            Self::BucketScopedSingleRule => "bucket_scoped_single_rule",
            Self::StringExpectedFindings => "string_expected_findings",
            Self::RuleAliasExpectedFindings => "rule_alias_expected_findings",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct LegacyExpectedAbsent {
    rule: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct LegacyCaseSection {
    id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct LegacyCaseManifest {
    case: Option<LegacyCaseSection>,
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    path: Option<PathBuf>,
    entry: Option<PathBuf>,
    entrypoint: Option<PathBuf>,
    expect_findings: Option<Vec<String>>,
    expect_absent: Option<Vec<LegacyExpectedAbsent>>,
}

#[derive(Clone, Debug, Deserialize)]
struct BucketScopedCaseManifest {
    id: String,
    #[allow(dead_code)]
    kind: Option<String>,
    description: Option<String>,
    #[allow(dead_code)]
    rule: Option<String>,
    #[allow(dead_code)]
    severity: Option<String>,
    #[allow(dead_code)]
    category: Option<String>,
    #[allow(dead_code)]
    expected: Option<usize>,
    entry_path: Option<PathBuf>,
    expected_output: Option<Vec<HarnessOutputFormat>>,
    #[serde(default)]
    expected_runtime_errors: usize,
    #[serde(default)]
    expected_runtime_error_kinds: Vec<ExpectedRuntimeErrorKind>,
    #[serde(default)]
    expected_diagnostics: usize,
    expected_scanned_files: Option<usize>,
    expected_skipped_files: Option<usize>,
    expected_findings: Option<toml::Value>,
    #[serde(default)]
    expected_rules: Vec<String>,
    #[serde(default)]
    expectations: Vec<BucketScopedExpectation>,
    source: Option<BucketScopedSource>,
    expect: Option<BucketScopedExpect>,
    #[serde(default)]
    expected_absent_rules: Option<Vec<String>>,
    snapshot: Option<SnapshotExpectation>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct BucketScopedExpectation {
    rule: String,
    tier: Option<RuleTier>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct BucketScopedSource {
    path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct BucketScopedExpect {
    #[serde(default)]
    findings: Vec<String>,
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

    pub fn load_with_legacy_compat(case_dir: &Path) -> Result<Self, ManifestLoadError> {
        let manifest_path = case_dir.join("case.toml");
        let contents =
            std::fs::read_to_string(&manifest_path).map_err(|source| ManifestLoadError::Io {
                path: manifest_path.clone(),
                source,
            })?;
        match Self::from_toml(&contents) {
            Ok(manifest) => Ok(manifest),
            Err(source) => Self::from_bucket_scoped_toml(case_dir, &contents)
                .or_else(|| Self::from_legacy_toml(case_dir, &contents))
                .ok_or(ManifestLoadError::Parse {
                    path: manifest_path,
                    source,
                }),
        }
    }

    pub fn entry_root(&self, case_dir: &Path) -> PathBuf {
        case_dir.join(&self.entry_path)
    }

    pub fn to_canonical_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    fn from_legacy_toml(case_dir: &Path, input: &str) -> Option<Self> {
        let legacy = toml::from_str::<LegacyCaseManifest>(input).ok()?;
        let id = legacy.id.or(legacy.name).or_else(|| {
            legacy
                .case
                .as_ref()
                .and_then(|section| section.id.as_ref().cloned())
        })?;
        let raw_entry = legacy
            .entry
            .or(legacy.entrypoint)
            .or(legacy.path)
            .unwrap_or_else(|| PathBuf::from("repo"));
        let entry_path = default_case_entry_path(case_dir, Some(raw_entry));
        let kind = case_kind_from_dir(case_dir)?;
        let expected_findings = legacy
            .expect_findings
            .unwrap_or_default()
            .into_iter()
            .map(|rule_code| ExpectedFinding {
                tier: known_rule_tier(&rule_code),
                rule_code,
                stable_key: None,
                min_evidence_count: Some(1),
            })
            .collect();
        let expected_absent_rules = legacy
            .expect_absent
            .unwrap_or_default()
            .into_iter()
            .map(|entry| entry.rule)
            .collect();

        Some(Self {
            id,
            description: legacy.description,
            kind,
            entry_path,
            expected_output: default_case_output_formats(),
            expected_runtime_errors: 0,
            expected_runtime_error_kinds: Vec::new(),
            expected_diagnostics: 0,
            expected_scanned_files: None,
            expected_skipped_files: None,
            expected_findings,
            expected_absent_rules,
            snapshot: SnapshotExpectation {
                kind: SnapshotKind::None,
                name: "none".to_owned(),
            },
        })
    }

    fn from_bucket_scoped_toml(case_dir: &Path, input: &str) -> Option<Self> {
        let manifest = toml::from_str::<BucketScopedCaseManifest>(input).ok()?;
        let inferred_entry_path = manifest
            .source
            .as_ref()
            .and_then(|source| infer_entry_path_from_source(&source.path));
        Some(Self {
            id: manifest.id,
            description: manifest.description,
            kind: case_kind_from_dir(case_dir)?,
            entry_path: manifest
                .entry_path
                .or(inferred_entry_path)
                .unwrap_or_else(|| default_case_entry_path(case_dir, None)),
            expected_output: manifest
                .expected_output
                .unwrap_or_else(default_case_output_formats),
            expected_runtime_errors: manifest.expected_runtime_errors,
            expected_runtime_error_kinds: manifest.expected_runtime_error_kinds,
            expected_diagnostics: manifest.expected_diagnostics,
            expected_scanned_files: manifest.expected_scanned_files,
            expected_skipped_files: manifest.expected_skipped_files,
            expected_findings: normalize_bucket_expected_findings(
                manifest.expected_findings,
                &manifest.expected_rules,
                &manifest.expectations,
                manifest.rule.as_deref(),
                manifest
                    .expected
                    .or_else(|| manifest.expect.as_ref().map(|expect| expect.findings.len())),
                manifest.expect.as_ref(),
            )?,
            expected_absent_rules: normalize_bucket_expected_absent_rules(
                manifest.expected_absent_rules,
                manifest.rule.as_deref(),
                manifest
                    .expected
                    .or_else(|| manifest.expect.as_ref().map(|expect| expect.findings.len())),
            ),
            snapshot: manifest.snapshot.unwrap_or(SnapshotExpectation {
                kind: SnapshotKind::None,
                name: String::new(),
            }),
        })
    }
}

pub fn case_manifest_dialect_flags(input: &str) -> BTreeSet<CaseManifestDialectFlag> {
    let mut flags = BTreeSet::new();
    let Ok(value) = toml::from_str::<toml::Value>(input) else {
        return flags;
    };
    let Some(table) = value.as_table() else {
        return flags;
    };

    if table.contains_key("case") {
        flags.insert(CaseManifestDialectFlag::LegacyCaseSection);
    }
    if table.contains_key("path") || table.contains_key("entry") || table.contains_key("entrypoint")
    {
        flags.insert(CaseManifestDialectFlag::LegacyPathKeys);
    }
    if table.contains_key("expect_findings") || table.contains_key("expect_absent") {
        flags.insert(CaseManifestDialectFlag::LegacyExpectKeys);
    }
    if [
        "kind",
        "entry_path",
        "expected_output",
        "expected_runtime_errors",
        "expected_diagnostics",
        "expected_absent_rules",
        "snapshot",
    ]
    .iter()
    .any(|key| !table.contains_key(*key))
    {
        flags.insert(CaseManifestDialectFlag::ImplicitCanonicalDefaults);
    }
    if table.contains_key("artifact_kind") || table.contains_key("provider") {
        flags.insert(CaseManifestDialectFlag::BucketScopedArtifactProviderKeys);
    }
    if table
        .get("artifacts")
        .and_then(|value| value.as_array())
        .is_some_and(|items| !items.is_empty())
    {
        flags.insert(CaseManifestDialectFlag::ArtifactListShorthand);
    }
    if table
        .get("kind")
        .and_then(|value| value.as_str())
        .is_some_and(|kind| !matches!(kind, "benign" | "malicious" | "edge" | "compat"))
    {
        flags.insert(CaseManifestDialectFlag::BucketScopedArtifactKind);
    }
    if table
        .get("expected_rules")
        .and_then(|value| value.as_array())
        .is_some_and(|items| !items.is_empty())
    {
        flags.insert(CaseManifestDialectFlag::BucketScopedExpectedRules);
    }
    if table
        .get("expectations")
        .and_then(|value| value.as_array())
        .is_some_and(|items| !items.is_empty())
    {
        flags.insert(CaseManifestDialectFlag::BucketScopedExpectations);
    }
    if table
        .get("expect")
        .and_then(|value| value.as_table())
        .and_then(|expect| expect.get("findings"))
        .and_then(|value| value.as_array())
        .is_some_and(|items| !items.is_empty())
    {
        flags.insert(CaseManifestDialectFlag::BucketScopedExpectSection);
    }
    if table
        .get("source")
        .and_then(|value| value.as_table())
        .is_some_and(|source| source.contains_key("path"))
    {
        flags.insert(CaseManifestDialectFlag::BucketScopedSourcePath);
    }
    if table.contains_key("rule") || table.contains_key("expected") {
        flags.insert(CaseManifestDialectFlag::BucketScopedSingleRule);
    }
    if let Some(entries) = table
        .get("expected_findings")
        .and_then(|value| value.as_array())
    {
        if entries.iter().any(toml::Value::is_str) {
            flags.insert(CaseManifestDialectFlag::StringExpectedFindings);
        }
        if entries.iter().any(|entry| {
            entry
                .as_table()
                .is_some_and(|item| item.contains_key("rule") && !item.contains_key("rule_code"))
        }) {
            flags.insert(CaseManifestDialectFlag::RuleAliasExpectedFindings);
        }
    }

    flags
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-testing")
}

pub fn checked_in_case_dirs() -> Result<Vec<PathBuf>, HarnessError> {
    let root = workspace_root();
    let roots = [
        root.join("corpus/benign"),
        root.join("corpus/malicious"),
        root.join("corpus/edge"),
        root.join("corpus/compat"),
        root.join("sample-repos"),
        root.join("crates/lintai-dep-vulns/corpus/benign"),
        root.join("crates/lintai-dep-vulns/corpus/malicious"),
    ];
    let mut case_dirs = Vec::new();
    for bucket_root in roots {
        case_dirs.extend(discover_case_dirs(&bucket_root)?);
    }
    case_dirs.sort();
    Ok(case_dirs)
}

fn case_kind_from_dir(case_dir: &Path) -> Option<CaseKind> {
    match case_dir.parent()?.file_name()?.to_str()? {
        "benign" => Some(CaseKind::Benign),
        "malicious" => Some(CaseKind::Malicious),
        "edge" => Some(CaseKind::Edge),
        "compat" => Some(CaseKind::Compat),
        _ => None,
    }
}

fn default_case_output_formats() -> Vec<HarnessOutputFormat> {
    vec![
        HarnessOutputFormat::Text,
        HarnessOutputFormat::Json,
        HarnessOutputFormat::Sarif,
    ]
}

fn default_case_entry_path(case_dir: &Path, raw_entry: Option<PathBuf>) -> PathBuf {
    if case_dir.join("repo").is_dir() {
        PathBuf::from("repo")
    } else if raw_entry.as_deref() == Some(Path::new("repo")) {
        PathBuf::from("repo")
    } else {
        PathBuf::from(".")
    }
}

fn normalize_bucket_expected_findings(
    value: Option<toml::Value>,
    expected_rules: &[String],
    expectations: &[BucketScopedExpectation],
    single_rule: Option<&str>,
    expected_count: Option<usize>,
    expect: Option<&BucketScopedExpect>,
) -> Option<Vec<ExpectedFinding>> {
    let Some(value) = value else {
        if let Some(expect) = expect {
            return Some(
                expect
                    .findings
                    .iter()
                    .map(|rule_code| ExpectedFinding {
                        tier: None,
                        rule_code: rule_code.clone(),
                        stable_key: None,
                        min_evidence_count: Some(1),
                    })
                    .collect(),
            );
        }
        if !expectations.is_empty() {
            return Some(
                expectations
                    .iter()
                    .map(|expectation| ExpectedFinding {
                        tier: expectation.tier,
                        rule_code: expectation.rule.clone(),
                        stable_key: None,
                        min_evidence_count: Some(1),
                    })
                    .collect(),
            );
        }
        if let Some(rule_code) = single_rule {
            if expected_count.unwrap_or(0) > 0 {
                return Some(vec![ExpectedFinding {
                    tier: None,
                    rule_code: rule_code.to_owned(),
                    stable_key: None,
                    min_evidence_count: Some(1),
                }]);
            }
        }
        return Some(
            expected_rules
                .iter()
                .map(|rule_code| ExpectedFinding {
                    tier: None,
                    rule_code: rule_code.clone(),
                    stable_key: None,
                    min_evidence_count: Some(1),
                })
                .collect(),
        );
    };
    let entries = value.as_array()?;
    let mut findings = Vec::with_capacity(entries.len());

    for entry in entries {
        if let Some(rule_code) = entry.as_str() {
            findings.push(ExpectedFinding {
                tier: None,
                rule_code: rule_code.to_owned(),
                stable_key: None,
                min_evidence_count: Some(1),
            });
            continue;
        }

        let table = entry.as_table()?;
        if let Some(rule_code) = table.get("rule_code").and_then(|value| value.as_str()) {
            findings.push(ExpectedFinding {
                rule_code: rule_code.to_owned(),
                stable_key: table
                    .get("stable_key")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned),
                tier: table
                    .get("tier")
                    .and_then(|value| value.as_str())
                    .and_then(parse_rule_tier),
                min_evidence_count: table
                    .get("min_evidence_count")
                    .and_then(|value| value.as_integer())
                    .and_then(|value| usize::try_from(value).ok()),
            });
            continue;
        }

        if let Some(rule_code) = table.get("rule").and_then(|value| value.as_str()) {
            findings.push(ExpectedFinding {
                tier: table
                    .get("tier")
                    .and_then(|value| value.as_str())
                    .and_then(parse_rule_tier),
                rule_code: rule_code.to_owned(),
                stable_key: None,
                min_evidence_count: table
                    .get("min_evidence_count")
                    .and_then(|value| value.as_integer())
                    .and_then(|value| usize::try_from(value).ok())
                    .or(Some(1)),
            });
            continue;
        }

        return None;
    }

    Some(findings)
}

fn normalize_bucket_expected_absent_rules(
    expected_absent_rules: Option<Vec<String>>,
    single_rule: Option<&str>,
    expected_count: Option<usize>,
) -> Vec<String> {
    let mut absent_rules = expected_absent_rules.unwrap_or_default();
    if absent_rules.is_empty() && expected_count == Some(0) {
        if let Some(rule_code) = single_rule {
            absent_rules.push(rule_code.to_owned());
        }
    }
    absent_rules
}

fn infer_entry_path_from_source(path: &Path) -> Option<PathBuf> {
    let first = path.components().next()?.as_os_str();
    Some(PathBuf::from(first))
}

fn parse_rule_tier(value: &str) -> Option<RuleTier> {
    match value {
        "preview" => Some(RuleTier::Preview),
        "stable" => Some(RuleTier::Stable),
        _ => None,
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
        "SEC381" | "SEC382" | "SEC383" | "SEC385" | "SEC386" | "SEC387" | "SEC388" | "SEC389"
        | "SEC399" | "SEC404" | "SEC406" | "SEC407" | "SEC408" | "SEC409" | "SEC410" | "SEC419"
        | "SEC420" | "SEC421" | "SEC474" | "SEC478" | "SEC479" | "SEC480" | "SEC481" | "SEC482"
        | "SEC483" | "SEC484" | "SEC485" | "SEC488" | "SEC489" | "SEC490" | "SEC491" | "SEC492"
        | "SEC493" | "SEC494" | "SEC495" | "SEC496" | "SEC497" | "SEC498" | "SEC499" | "SEC500"
        | "SEC501" | "SEC756" => Some(RuleTier::Preview),
        "SEC201" | "SEC202" | "SEC203" | "SEC204" | "SEC205" | "SEC206" | "SEC301" | "SEC302"
        | "SEC303" | "SEC304" | "SEC305" | "SEC309" | "SEC310" | "SEC311" | "SEC312" | "SEC314"
        | "SEC315" | "SEC316" | "SEC317" | "SEC318" | "SEC319" | "SEC320" | "SEC321" | "SEC322"
        | "SEC324" | "SEC326" | "SEC327" | "SEC329" | "SEC330" | "SEC331" | "SEC337" | "SEC338"
        | "SEC339" | "SEC340" | "SEC341" | "SEC342" | "SEC343" | "SEC344" | "SEC345" | "SEC346"
        | "SEC394" | "SEC395" | "SEC396" | "SEC397" | "SEC398" | "SEC411" | "SEC412" | "SEC413"
        | "SEC414" | "SEC415" | "SEC417" | "SEC418" | "SEC422" | "SEC423" | "SEC424" | "SEC425"
        | "SEC426" | "SEC427" | "SEC428" | "SEC429" | "SEC430" | "SEC431" | "SEC432" | "SEC433"
        | "SEC434" | "SEC435" | "SEC436" | "SEC437" | "SEC438" | "SEC439" | "SEC440" | "SEC441"
        | "SEC442" | "SEC443" | "SEC444" | "SEC445" | "SEC446" | "SEC447" | "SEC448" | "SEC449"
        | "SEC450" | "SEC451" | "SEC452" | "SEC453" | "SEC454" | "SEC455" | "SEC456" | "SEC457"
        | "SEC458" | "SEC459" | "SEC460" | "SEC461" | "SEC462" | "SEC352" | "SEC463" | "SEC464"
        | "SEC465" | "SEC466" | "SEC467" | "SEC468" | "SEC469" | "SEC470" | "SEC471" | "SEC472"
        | "SEC473" | "SEC520" | "SEC521" | "SEC522" | "SEC523" | "SEC524" | "SEC525" | "SEC526"
        | "SEC527" | "SEC362" | "SEC364" | "SEC367" | "SEC369" | "SEC372" | "SEC373" | "SEC374"
        | "SEC375" | "SEC376" | "SEC384" | "SEC405" | "SEC475" | "SEC476" | "SEC477" | "SEC486"
        | "SEC487" | "SEC502" | "SEC503" | "SEC504" | "SEC505" | "SEC506" | "SEC507" | "SEC508"
        | "SEC509" | "SEC510" | "SEC511" | "SEC512" | "SEC513" | "SEC514" | "SEC515" | "SEC516"
        | "SEC517" | "SEC518" | "SEC519" | "SEC528" | "SEC529" | "SEC530" | "SEC531" | "SEC532"
        | "SEC533" | "SEC534" | "SEC535" | "SEC536" | "SEC537" | "SEC538" | "SEC539" | "SEC540"
        | "SEC541" | "SEC542" | "SEC543" | "SEC544" | "SEC545" | "SEC626" | "SEC627" | "SEC628"
        | "SEC629" | "SEC630" | "SEC631" | "SEC632" | "SEC633" | "SEC634" | "SEC635" | "SEC636"
        | "SEC637" | "SEC638" | "SEC639" | "SEC640" | "SEC641" | "SEC642" | "SEC643" | "SEC644"
        | "SEC645" | "SEC646" | "SEC647" | "SEC648" | "SEC649" | "SEC650" | "SEC651" | "SEC652"
        | "SEC653" | "SEC654" | "SEC655" | "SEC656" | "SEC657" | "SEC658" | "SEC659" | "SEC660"
        | "SEC661" | "SEC662" | "SEC663" | "SEC664" | "SEC665" | "SEC666" | "SEC667" | "SEC668"
        | "SEC669" | "SEC670" | "SEC671" | "SEC672" | "SEC673" | "SEC674" | "SEC675" | "SEC676"
        | "SEC677" | "SEC678" | "SEC679" | "SEC680" | "SEC681" | "SEC682" | "SEC683" | "SEC684"
        | "SEC685" | "SEC686" | "SEC687" | "SEC688" | "SEC689" | "SEC690" | "SEC691" | "SEC692"
        | "SEC693" | "SEC694" | "SEC695" | "SEC696" | "SEC697" | "SEC698" | "SEC699" | "SEC700"
        | "SEC701" | "SEC702" | "SEC703" | "SEC704" | "SEC705" | "SEC706" | "SEC707" | "SEC708"
        | "SEC709" | "SEC710" | "SEC711" | "SEC712" | "SEC713" | "SEC714" | "SEC715" | "SEC716"
        | "SEC717" | "SEC718" | "SEC719" | "SEC720" | "SEC721" | "SEC722" | "SEC723" | "SEC724"
        | "SEC725" | "SEC726" | "SEC727" | "SEC728" | "SEC729" | "SEC730" | "SEC731" | "SEC732"
        | "SEC733" | "SEC734" | "SEC735" | "SEC736" | "SEC737" | "SEC738" | "SEC739" | "SEC740"
        | "SEC741" | "SEC742" | "SEC743" | "SEC744" | "SEC745" | "SEC746" | "SEC747" | "SEC748"
        | "SEC749" | "SEC750" | "SEC751" | "SEC752" | "SEC753" | "SEC754" | "SEC755" => {
            Some(RuleTier::Stable)
        }
        "SEC618" | "SEC619" | "SEC620" | "SEC621" | "SEC622" | "SEC623" | "SEC624" | "SEC625" => {
            Some(RuleTier::Stable)
        }
        "SEC101" | "SEC102" | "SEC103" | "SEC104" | "SEC105" | "SEC306" | "SEC307" | "SEC308"
        | "SEC313" | "SEC323" | "SEC325" | "SEC328" | "SEC335" | "SEC336" | "SEC347" | "SEC348"
        | "SEC349" | "SEC350" | "SEC351" | "SEC353" | "SEC354" | "SEC355" | "SEC356" | "SEC357"
        | "SEC358" | "SEC359" | "SEC360" | "SEC361" | "SEC363" | "SEC365" | "SEC366" | "SEC368"
        | "SEC370" | "SEC371" | "SEC377" | "SEC378" | "SEC379" | "SEC380" | "SEC390" | "SEC391"
        | "SEC392" | "SEC393" | "SEC416" | "SEC401" | "SEC402" | "SEC403" => {
            Some(RuleTier::Preview)
        }
        "SEC400" => Some(RuleTier::Stable),
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
        (ArtifactKind::PackageManifest, SourceFormat::Json) => Path::new("package.json"),
        (ArtifactKind::NpmPackageLock, SourceFormat::Json) => Path::new("package-lock.json"),
        (ArtifactKind::NpmShrinkwrap, SourceFormat::Json) => Path::new("npm-shrinkwrap.json"),
        (ArtifactKind::DevcontainerConfig, SourceFormat::Json) => {
            Path::new(".devcontainer/devcontainer.json")
        }
        (ArtifactKind::ClaudeSettings, SourceFormat::Json) => Path::new(".claude/settings.json"),
        (ArtifactKind::ServerRegistryConfig, SourceFormat::Json) => Path::new("server.json"),
        (ArtifactKind::ToolDescriptorJson, SourceFormat::Json) => {
            Path::new("pkg/mcp/toolsets-full-tools.json")
        }
        (ArtifactKind::GitHubWorkflow, SourceFormat::Yaml) => Path::new(".github/workflows/ci.yml"),
        (ArtifactKind::DockerCompose, SourceFormat::Yaml) => Path::new("docker-compose.yml"),
        (ArtifactKind::PnpmLock, SourceFormat::Yaml) => Path::new("pnpm-lock.yaml"),
        (ArtifactKind::CursorPluginManifest, SourceFormat::Json) => {
            Path::new(".cursor-plugin/plugin.json")
        }
        (ArtifactKind::CursorPluginHooks, SourceFormat::Json) => {
            Path::new(".cursor-plugin/hooks.json")
        }
        (ArtifactKind::Dockerfile, SourceFormat::Shell) => Path::new("Dockerfile"),
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
    workspace_root()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        CaseManifest, HarnessError, HarnessOutputFormat, OutputHarness, SnapshotExpectation,
        SnapshotKind, WorkspaceHarness, assert_case_summary, case_manifest_dialect_flags,
        discover_case_dirs, repo_root, unique_temp_dir,
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
    fn load_with_legacy_compat_preserves_expected_findings_for_bucket_scoped_manifests() {
        let bucket_root = unique_temp_dir("lintai-bucket-scoped-manifest");
        let case_dir = bucket_root
            .join("malicious")
            .join("skill-pip-http-git-install");
        std::fs::create_dir_all(case_dir.join("repo")).unwrap();
        std::fs::write(
            case_dir.join("case.toml"),
            r#"
id = "skill-pip-http-git-install"
kind = "Skill"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 1
expected_findings = [
  { rule_code = "SEC455", min_evidence_count = 1, tier = "stable" },
]
expected_absent_rules = []
snapshot = { kind = "none", name = "" }
"#,
        )
        .unwrap();

        let manifest = CaseManifest::load_with_legacy_compat(&case_dir).unwrap();
        assert_eq!(manifest.kind, super::CaseKind::Malicious);
        assert_eq!(manifest.expected_findings.len(), 1);
        assert_eq!(manifest.expected_findings[0].rule_code, "SEC455");
        assert_eq!(manifest.expected_findings[0].tier, Some(RuleTier::Stable));
        assert!(manifest.expected_absent_rules.is_empty());
    }

    #[test]
    fn load_rejects_legacy_bucket_scoped_manifest_shapes() {
        let bucket_root = unique_temp_dir("lintai-legacy-case-manifest-reject");
        let case_dir = bucket_root
            .join("malicious")
            .join("skill-pip-http-git-install");
        std::fs::create_dir_all(case_dir.join("repo")).unwrap();
        std::fs::write(
            case_dir.join("case.toml"),
            r#"
id = "skill-pip-http-git-install"
kind = "Skill"
entry_path = "repo"
expected_output = ["text"]
expected_runtime_errors = 0
expected_diagnostics = 1
expected_findings = [
  { rule_code = "SEC455", min_evidence_count = 1, tier = "stable" },
]
expected_absent_rules = []
snapshot = { kind = "none", name = "" }
"#,
        )
        .unwrap();

        let error = CaseManifest::load(&case_dir).unwrap_err();
        assert!(
            error.to_string().contains("failed to parse case manifest"),
            "strict canonical loader should reject legacy shorthand manifests: {error}"
        );
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
    fn checked_in_case_manifests_are_canonical() {
        let case_dirs = super::checked_in_case_dirs().unwrap();
        assert!(
            !case_dirs.is_empty(),
            "expected checked-in corpus/sample repos to contain manifests"
        );

        for case_dir in case_dirs {
            let manifest_path = case_dir.join("case.toml");
            let raw = std::fs::read_to_string(&manifest_path).unwrap();
            let flags = case_manifest_dialect_flags(&raw);
            assert!(
                flags.is_empty(),
                "checked-in manifest {} still uses legacy dialect flags: {:?}",
                manifest_path.display(),
                flags
            );
            CaseManifest::from_toml(&raw).unwrap_or_else(|error| {
                panic!(
                    "checked-in manifest {} must parse through the canonical contract: {error}",
                    manifest_path.display()
                )
            });
        }
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
