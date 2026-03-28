use std::path::Path;

use crate::normalize::normalize_path;

use super::{
    DEFAULT_EXCLUDE_PATTERNS, DEFAULT_INCLUDE_PATTERNS, EngineConfig, ResolvedFileConfig,
    WorkspaceConfig,
};

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            project_root: None,
            follow_symlinks: false,
            output_format: super::OutputFormat::Text,
            ci_policy: super::CiPolicy::default(),
            suppress_policy: super::SuppressPolicy::default(),
            capability_profile: None,
            capability_conflict_mode: lintai_api::CapabilityConflictMode::Warn,
            include_patterns: DEFAULT_INCLUDE_PATTERNS
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect(),
            include_matcher: super::load::compile_globset(DEFAULT_INCLUDE_PATTERNS)
                .expect("default include"),
            exclude_patterns: DEFAULT_EXCLUDE_PATTERNS
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect(),
            exclude_matcher: super::load::compile_globset(DEFAULT_EXCLUDE_PATTERNS)
                .expect("default exclude"),
            category_overrides: Default::default(),
            rule_overrides: Default::default(),
            overrides: Vec::new(),
            detection_overrides: Vec::new(),
        }
    }
}

impl EngineConfig {
    pub fn add_include_patterns(&mut self, patterns: &[String]) -> Result<(), super::ConfigError> {
        let mut changed = false;
        for pattern in patterns {
            if self.include_patterns.contains(pattern) {
                continue;
            }
            self.include_patterns.push(pattern.clone());
            changed = true;
        }

        if changed {
            let mut builder = globset::GlobSetBuilder::new();
            for pattern in &self.include_patterns {
                let glob = globset::Glob::new(pattern).map_err(|error| {
                    super::ConfigError::new(format!("invalid glob `{pattern}`: {error}"))
                })?;
                builder.add(glob);
            }
            self.include_matcher = builder
                .build()
                .map_err(|error| super::ConfigError::new(format!("invalid globset: {error}")))?;
        }
        Ok(())
    }

    pub fn set_project_root(&mut self, project_root: Option<std::path::PathBuf>) {
        self.project_root = project_root;
    }

    pub fn add_detection_override(
        &mut self,
        patterns: &[String],
        kind: lintai_api::ArtifactKind,
        format: lintai_api::SourceFormat,
    ) -> Result<(), super::ConfigError> {
        let mut builder = globset::GlobSetBuilder::new();
        for pattern in patterns {
            let glob = globset::Glob::new(pattern).map_err(|error| {
                super::ConfigError::new(format!("invalid glob `{pattern}`: {error}"))
            })?;
            builder.add(glob);
        }
        let matcher = builder
            .build()
            .map_err(|error| super::ConfigError::new(format!("invalid globset: {error}")))?;
        self.detection_overrides.push(super::DetectionOverride {
            matcher,
            kind,
            format,
        });
        Ok(())
    }

    pub fn resolve_for(&self, normalized_path: &str) -> ResolvedFileConfig {
        let mut category_overrides = self.category_overrides.clone();
        let mut rule_overrides = self.rule_overrides.clone();
        let mut applied_overrides = Vec::new();
        for file_override in &self.overrides {
            if file_override.matcher.is_match(normalized_path) {
                category_overrides.extend(file_override.category_overrides.clone().into_iter());
                rule_overrides.extend(file_override.rule_overrides.clone().into_iter());
                applied_overrides.push(file_override.patterns.clone());
            }
        }

        let included = self.include_matcher.is_match(normalized_path)
            && !self.exclude_matcher.is_match(normalized_path);

        ResolvedFileConfig {
            normalized_path: normalized_path.to_owned(),
            included,
            output_format: self.output_format,
            ci_policy: self.ci_policy.clone(),
            suppress_policy: self.suppress_policy.clone(),
            project_capabilities: self.capability_profile.clone(),
            capability_conflict_mode: self.capability_conflict_mode,
            applied_overrides,
            category_overrides,
            rule_overrides,
            detected_kind: None,
            detected_format: None,
        }
    }

    pub fn include_patterns(&self) -> &[String] {
        &self.include_patterns
    }

    pub fn exclude_patterns(&self) -> &[String] {
        &self.exclude_patterns
    }
}

pub fn explain_file_config(config: &WorkspaceConfig, file: &Path) -> ResolvedFileConfig {
    let normalized_path = config.engine_config.project_root.as_ref().map_or_else(
        || file.to_string_lossy().into_owned(),
        |root| normalize_path(root, file),
    );
    let mut resolved = config.engine_config.resolve_for(&normalized_path);
    let detector = crate::FileTypeDetector::new(&config.engine_config);
    if let Some(detected) = detector.detect(file, &normalized_path) {
        resolved.detected_kind = Some(detected.kind);
        resolved.detected_format = Some(detected.format);
    }
    resolved
}
