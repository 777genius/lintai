mod glob;
mod parse;
mod raw;

use std::path::{Path, PathBuf};

use lintai_api::{Confidence, Severity};

use super::{
    CiPolicy, ConfigError, DEFAULT_EXCLUDE_PATTERNS, DEFAULT_INCLUDE_PATTERNS, DetectionOverride,
    EngineConfig, FileOverride, OutputFormat, SuppressPolicy, WorkspaceConfig,
};

use self::glob::compile_globset_vec;
use self::parse::{parse_rules, validate_top_level_keys};
use self::raw::RawRootConfig;

pub fn load_workspace_config(target: &Path) -> Result<WorkspaceConfig, ConfigError> {
    let source_path = find_config_path(target);
    let Some(source_path) = source_path else {
        return Ok(WorkspaceConfig {
            source_path: None,
            engine_config: EngineConfig::default(),
        });
    };

    let content = std::fs::read_to_string(&source_path).map_err(|error| {
        ConfigError::new(format!("failed to read {}: {error}", source_path.display()))
    })?;
    let value = content
        .parse::<toml::Value>()
        .map_err(|error| ConfigError::new(format!("invalid TOML: {error}")))?;
    validate_top_level_keys(&value)?;
    let rules = parse_rules(value.get("rules"))?;
    let raw: RawRootConfig = value
        .try_into()
        .map_err(|error| ConfigError::new(format!("invalid config shape: {error}")))?;
    if matches!(
        raw.project.as_ref().and_then(|project| project.root),
        Some(false)
    ) {
        return Err(ConfigError::new(
            "`project.root = false` is not supported in this release",
        ));
    }
    let _rules_section = raw.rules.as_ref();
    let config_dir = source_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let include_patterns = raw
        .files
        .as_ref()
        .and_then(|files| files.include.clone())
        .unwrap_or_else(|| {
            DEFAULT_INCLUDE_PATTERNS
                .iter()
                .map(|p| (*p).to_owned())
                .collect()
        });
    let exclude_patterns = raw
        .files
        .as_ref()
        .and_then(|files| files.exclude.clone())
        .unwrap_or_else(|| {
            DEFAULT_EXCLUDE_PATTERNS
                .iter()
                .map(|p| (*p).to_owned())
                .collect()
        });

    let include_matcher = compile_globset_vec(&include_patterns)?;
    let exclude_matcher = compile_globset_vec(&exclude_patterns)?;
    let overrides = raw
        .overrides
        .unwrap_or_default()
        .into_iter()
        .map(|override_entry| {
            let matcher = compile_globset_vec(&override_entry.files)?;
            Ok(FileOverride {
                patterns: override_entry.files,
                matcher,
                category_overrides: override_entry.categories.unwrap_or_default(),
                rule_overrides: override_entry.rules.unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
    let detection_overrides = raw
        .detection
        .and_then(|detection| detection.overrides)
        .unwrap_or_default()
        .into_iter()
        .map(|override_entry| {
            let matcher = compile_globset_vec(&override_entry.files)?;
            Ok(DetectionOverride {
                matcher,
                kind: override_entry.kind,
                format: override_entry.format,
            })
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;

    let suppress_policy = raw
        .suppress
        .map(|policy| SuppressPolicy {
            require_reason: policy.require_reason.unwrap_or(true),
            report_unused: policy.report_unused.unwrap_or(true),
            max_per_file: policy.max_per_file.unwrap_or(10),
        })
        .unwrap_or_default();

    Ok(WorkspaceConfig {
        source_path: Some(source_path),
        engine_config: EngineConfig {
            project_root: Some(config_dir),
            follow_symlinks: false,
            output_format: raw
                .output
                .and_then(|output| output.format)
                .unwrap_or(OutputFormat::Text),
            ci_policy: CiPolicy {
                fail_on: raw
                    .ci
                    .as_ref()
                    .and_then(|ci| ci.fail_on)
                    .unwrap_or(Severity::Deny),
                min_confidence: raw
                    .ci
                    .and_then(|ci| ci.min_confidence)
                    .unwrap_or(Confidence::Medium),
            },
            suppress_policy,
            capability_profile: raw.capabilities,
            capability_conflict_mode: raw
                .policy
                .and_then(|policy| policy.capability_conflicts)
                .unwrap_or_default(),
            include_patterns,
            include_matcher,
            exclude_patterns,
            exclude_matcher,
            category_overrides: raw.categories.unwrap_or_default(),
            rule_overrides: rules,
            overrides,
            detection_overrides,
        },
    })
}

pub(crate) use glob::compile_globset;
pub(crate) use raw::RawRootConfig as SchemaRawRootConfig;

fn find_config_path(target: &Path) -> Option<PathBuf> {
    let config_dir = if target.is_dir() {
        target
    } else {
        target.parent().unwrap_or(target)
    };

    for file_name in ["lintai.toml", ".lintai.toml"] {
        let candidate = config_dir.join(file_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}
