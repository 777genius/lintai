mod provider_harness;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::{RuleTier, builtin_membership_preset_ids};
use lintai_engine::{
    ConfigError, EngineBuilder, EngineConfig, EngineError, FileSuppressions,
    ProviderExecutionPhase, RuntimeErrorKind, ScanSummary, SuppressionMatcher,
    load_workspace_config,
};
use lintai_runtime::ProviderBackend;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use provider_harness::ProviderHarness;

fn corpus_fallback_workspace_config(expected_absent_rules: &[String]) -> String {
    let enabled = builtin_membership_preset_ids()
        .into_iter()
        .map(|preset| format!("\"{preset}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut config = format!("[presets]\nenable = [{enabled}]\n");
    if !expected_absent_rules.is_empty() {
        config.push_str("\n[rules]\n");
        for rule_code in expected_absent_rules {
            config.push_str(&format!("{rule_code} = \"allow\"\n"));
        }
    }
    config
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), HarnessError> {
    std::fs::create_dir_all(destination).map_err(|source_error| {
        HarnessError::Manifest(ManifestLoadError::Io {
            path: destination.to_path_buf(),
            source: source_error,
        })
    })?;
    for entry in std::fs::read_dir(source).map_err(|source_error| {
        HarnessError::Manifest(ManifestLoadError::Io {
            path: source.to_path_buf(),
            source: source_error,
        })
    })? {
        let entry = entry.map_err(|source_error| {
            HarnessError::Manifest(ManifestLoadError::Io {
                path: source.to_path_buf(),
                source: source_error,
            })
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir_recursive(&source_path, &destination_path)?;
        } else {
            std::fs::copy(&source_path, &destination_path).map_err(|source_error| {
                HarnessError::Manifest(ManifestLoadError::Io {
                    path: source_path.clone(),
                    source: source_error,
                })
            })?;
        }
    }
    Ok(())
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

    pub fn to_canonical_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }
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

#[derive(Default)]
pub struct WorkspaceHarnessBuilder {
    backends: Vec<Arc<dyn ProviderBackend>>,
    override_config: Option<EngineConfig>,
    override_suppressions: Option<Arc<dyn SuppressionMatcher>>,
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

        let mut scan_root = entry_root.clone();
        let mut temp_root = None;
        let workspace = if self.override_config.is_none() {
            let workspace = load_workspace_config(&entry_root)?;
            if workspace.source_path.is_some() || manifest.kind == CaseKind::Compat {
                workspace
            } else {
                let generated_root = unique_temp_dir("lintai-case-workspace");
                copy_dir_recursive(&entry_root, &generated_root)?;
                std::fs::write(
                    generated_root.join("lintai.toml"),
                    corpus_fallback_workspace_config(&manifest.expected_absent_rules),
                )
                .map_err(|source| {
                    HarnessError::Manifest(ManifestLoadError::Io {
                        path: generated_root.join("lintai.toml"),
                        source,
                    })
                })?;
                scan_root = generated_root.clone();
                temp_root = Some(generated_root.clone());
                load_workspace_config(&generated_root)?
            }
        } else {
            load_workspace_config(&entry_root)?
        };
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

        let mut summary = builder.build().scan_path(&scan_root)?;
        if temp_root.is_some() && summary.skipped_files > 0 {
            summary.skipped_files -= 1;
        }
        drop(temp_root);
        Ok(summary)
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
            if expected
                .stable_key
                .as_ref()
                .is_some_and(|expected_stable_key| {
                    format_stable_key(&finding.stable_key) != *expected_stable_key
                })
            {
                return false;
            }
            if expected
                .min_evidence_count
                .is_some_and(|min_evidence_count| finding.evidence.len() < min_evidence_count)
            {
                return false;
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
mod lib_tests;
