use std::fmt;
use std::path::{Path, PathBuf};

use lintai_api::RuleTier;
use serde::{Deserialize, Serialize};

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
