#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::Mutex;

use globset::{Glob, GlobSet, GlobSetBuilder};
use lintai_api::{Finding, ScanContext};

use crate::{DiagnosticSeverity, EngineConfig, ScanDiagnostic, config::ConfigError};

pub trait SuppressionMatcher: Send + Sync {
    fn is_suppressed(&self, ctx: &ScanContext, finding: &Finding) -> bool;
    fn finalize(&self) -> Vec<ScanDiagnostic> {
        Vec::new()
    }
}

#[derive(Default)]
pub struct NoopSuppressionMatcher;

impl SuppressionMatcher for NoopSuppressionMatcher {
    fn is_suppressed(&self, _ctx: &ScanContext, _finding: &Finding) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
struct SuppressionEntry {
    patterns: Vec<String>,
    matcher: GlobSet,
    rule: String,
    reason: String,
}

pub struct FileSuppressions {
    policy: crate::SuppressPolicy,
    entries: Vec<SuppressionEntry>,
    state: Mutex<SuppressionState>,
}

#[derive(Default)]
struct SuppressionState {
    used_entries: Vec<bool>,
    used_per_file: BTreeMap<String, usize>,
}

impl Default for FileSuppressions {
    fn default() -> Self {
        Self {
            policy: crate::SuppressPolicy::default(),
            entries: Vec::new(),
            state: Mutex::new(SuppressionState::default()),
        }
    }
}

impl FileSuppressions {
    pub fn load(config: &EngineConfig) -> Result<Self, ConfigError> {
        let Some(project_root) = config.project_root.as_ref() else {
            return Ok(Self::default());
        };
        let path = project_root.join(".lintai").join("suppress.toml");
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path).map_err(|error| {
            ConfigError::new(format!("failed to read {}: {error}", path.display()))
        })?;
        let raw: RawSuppressFile = toml::from_str(&content)
            .map_err(|error| ConfigError::new(format!("invalid suppress TOML: {error}")))?;

        let entries = raw
            .suppress
            .into_iter()
            .map(|entry| SuppressionEntry::try_from_raw(entry, config))
            .collect::<Result<Vec<_>, ConfigError>>()?;

        Ok(Self {
            policy: config.suppress_policy.clone(),
            state: Mutex::new(SuppressionState {
                used_entries: vec![false; entries.len()],
                used_per_file: BTreeMap::new(),
            }),
            entries,
        })
    }
}

impl SuppressionMatcher for FileSuppressions {
    fn is_suppressed(&self, ctx: &ScanContext, finding: &Finding) -> bool {
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.rule == finding.rule_code
                && entry.matcher.is_match(&ctx.artifact.normalized_path)
            {
                let mut state = self.state.lock().expect("suppression state poisoned");
                state.used_entries[index] = true;
                *state
                    .used_per_file
                    .entry(ctx.artifact.normalized_path.clone())
                    .or_insert(0) += 1;
                return true;
            }
        }

        false
    }

    fn finalize(&self) -> Vec<ScanDiagnostic> {
        let state = self.state.lock().expect("suppression state poisoned");
        let mut diagnostics = Vec::new();

        if self.policy.report_unused {
            diagnostics.extend(self.unused_entry_diagnostics(&state));
        }
        diagnostics.extend(self.per_file_limit_diagnostics(&state));
        diagnostics
    }
}

impl FileSuppressions {
    fn unused_entry_diagnostics(&self, state: &SuppressionState) -> Vec<ScanDiagnostic> {
        let mut diagnostics = Vec::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if !state.used_entries.get(index).copied().unwrap_or(false) {
                diagnostics.push(ScanDiagnostic {
                    normalized_path: entry.patterns.join(","),
                    severity: DiagnosticSeverity::Warn,
                    code: Some("unused_suppress".to_owned()),
                    message: format!(
                        "unused suppress rule={} files=[{}] reason={}",
                        entry.rule,
                        entry.patterns.join(", "),
                        entry.reason
                    ),
                });
            }
        }
        diagnostics
    }

    fn per_file_limit_diagnostics(&self, state: &SuppressionState) -> Vec<ScanDiagnostic> {
        let mut diagnostics = Vec::new();
        for (normalized_path, count) in &state.used_per_file {
            if *count > self.policy.max_per_file {
                diagnostics.push(ScanDiagnostic {
                    normalized_path: normalized_path.clone(),
                    severity: DiagnosticSeverity::Warn,
                    code: Some("suppress_limit".to_owned()),
                    message: format!(
                        "suppressed findings exceed max_per_file: {count} > {}",
                        self.policy.max_per_file
                    ),
                });
            }
        }
        diagnostics
    }
}

impl SuppressionEntry {
    fn try_from_raw(raw: RawSuppressEntry, config: &EngineConfig) -> Result<Self, ConfigError> {
        if config.suppress_policy.require_reason && raw.reason.trim().is_empty() {
            return Err(ConfigError::new(format!(
                "suppress entry for rule `{}` is missing a reason",
                raw.rule
            )));
        }

        let matcher = compile_globset(&raw.files)?;
        Ok(Self {
            patterns: raw.files,
            matcher,
            rule: raw.rule,
            reason: raw.reason,
        })
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSuppressFile {
    #[serde(default)]
    suppress: Vec<RawSuppressEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSuppressEntry {
    files: Vec<String>,
    rule: String,
    reason: String,
}

fn compile_globset(patterns: &[String]) -> Result<GlobSet, ConfigError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern).map_err(|error| {
            ConfigError::new(format!("invalid suppress glob `{pattern}`: {error}"))
        })?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|error| ConfigError::new(format!("invalid suppress globset: {error}")))
}
