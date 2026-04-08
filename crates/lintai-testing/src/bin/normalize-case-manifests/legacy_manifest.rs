use std::path::{Path, PathBuf};

use lintai_api::RuleTier;
use lintai_testing::{
    CaseKind, CaseManifest, ExpectedFinding, ExpectedRuntimeErrorKind, HarnessOutputFormat,
    ManifestLoadError, SnapshotExpectation, SnapshotKind,
};
use serde::Deserialize;

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
    rule: Option<String>,
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

pub(crate) fn load_case_manifest_with_legacy_compat(
    case_dir: &Path,
) -> Result<CaseManifest, ManifestLoadError> {
    let manifest_path = case_dir.join("case.toml");
    let contents =
        std::fs::read_to_string(&manifest_path).map_err(|source| ManifestLoadError::Io {
            path: manifest_path.clone(),
            source,
        })?;
    match CaseManifest::from_toml(&contents) {
        Ok(manifest) => Ok(manifest),
        Err(source) => from_bucket_scoped_toml(case_dir, &contents)
            .or_else(|| from_legacy_toml(case_dir, &contents))
            .ok_or(ManifestLoadError::Parse {
                path: manifest_path,
                source,
            }),
    }
}

fn from_legacy_toml(case_dir: &Path, input: &str) -> Option<CaseManifest> {
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
    let expected_findings = legacy
        .expect_findings
        .unwrap_or_default()
        .into_iter()
        .map(|rule_code| ExpectedFinding {
            tier: None,
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

    Some(CaseManifest {
        id,
        description: legacy.description,
        kind: case_kind_from_dir(case_dir)?,
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

fn from_bucket_scoped_toml(case_dir: &Path, input: &str) -> Option<CaseManifest> {
    let manifest = toml::from_str::<BucketScopedCaseManifest>(input).ok()?;
    let inferred_entry_path = manifest
        .source
        .as_ref()
        .and_then(|source| infer_entry_path_from_source(&source.path));
    Some(CaseManifest {
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
    if case_dir.join("repo").is_dir() || raw_entry.as_deref() == Some(Path::new("repo")) {
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
        if let Some(rule_code) = single_rule
            && expected_count.unwrap_or(0) > 0
        {
            return Some(vec![ExpectedFinding {
                tier: None,
                rule_code: rule_code.to_owned(),
                stable_key: None,
                min_evidence_count: Some(1),
            }]);
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
    if absent_rules.is_empty()
        && expected_count == Some(0)
        && let Some(rule_code) = single_rule
    {
        absent_rules.push(rule_code.to_owned());
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
