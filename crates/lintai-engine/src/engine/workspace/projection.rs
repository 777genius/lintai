use lintai_api::{WorkspaceArtifact, WorkspaceScanContext};

use crate::workspace_index::{WorkspaceEntry, WorkspaceIndex, full_artifact_location};
use crate::{EngineConfig, ResolvedFileConfig};

use super::super::ScannedArtifact;

pub(super) struct WorkspaceProjection {
    pub(super) workspace: WorkspaceScanContext,
    index: WorkspaceIndex,
}

pub(super) struct WorkspaceResolvedArtifact<'a> {
    pub(super) artifact: &'a WorkspaceArtifact,
    pub(super) file_config: &'a ResolvedFileConfig,
}

impl WorkspaceProjection {
    pub(super) fn build(config: &EngineConfig, scanned_artifacts: Vec<ScannedArtifact>) -> Self {
        // Build the workspace view once so provider execution only consumes stable projections.
        let mut workspace_artifacts = Vec::with_capacity(scanned_artifacts.len());
        let mut workspace_entries = Vec::with_capacity(scanned_artifacts.len());

        for scanned in scanned_artifacts {
            let normalized_path = scanned.context.artifact.normalized_path.clone();
            let location_hint =
                full_artifact_location(normalized_path.clone(), &scanned.context.content);
            let artifact_index = workspace_artifacts.len();
            workspace_artifacts.push(
                WorkspaceArtifact::new(
                    scanned.context.artifact,
                    scanned.context.content,
                    scanned.context.document,
                    scanned.context.semantics,
                )
                .with_location_hint(location_hint),
            );
            workspace_entries.push(WorkspaceEntry {
                artifact_index,
                normalized_path,
                file_config: scanned.file_config,
            });
        }

        let workspace = WorkspaceScanContext::new(
            config
                .project_root
                .as_ref()
                .map(|path| crate::normalize::normalize_path_string(path)),
            workspace_artifacts,
            config.capability_profile.clone(),
            config.capability_conflict_mode,
        )
        .with_active_rule_codes(config.active_rule_codes.clone());

        Self {
            workspace,
            index: WorkspaceIndex::new(workspace_entries),
        }
    }

    pub(super) fn project_root_owned(&self) -> String {
        self.workspace
            .project_root
            .clone()
            .unwrap_or_else(|| ".".to_owned())
    }

    pub(super) fn resolve(&self, normalized_path: &str) -> Option<WorkspaceResolvedArtifact<'_>> {
        let entry = self.index.get(normalized_path)?;
        let artifact = self.workspace.artifacts.get(entry.artifact_index)?;
        Some(WorkspaceResolvedArtifact {
            artifact,
            file_config: &entry.file_config,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use lintai_api::Span;
    use lintai_api::{Artifact, ArtifactKind, ParsedDocument, ScanContext, SourceFormat};

    use super::*;

    fn scanned_artifact(path: &str, content: &str, config: &EngineConfig) -> ScannedArtifact {
        ScannedArtifact {
            context: ScanContext::new(
                Artifact::new(path, ArtifactKind::Instructions, SourceFormat::Markdown),
                content,
                ParsedDocument::new(vec![], None),
                None,
            ),
            file_config: config.resolve_for(path),
        }
    }

    #[test]
    fn workspace_projection_keeps_workspace_mapping_and_active_rules() {
        let mut config = EngineConfig {
            project_root: Some(PathBuf::from("/tmp/lintai-workspace-projection")),
            ..EngineConfig::default()
        };
        config.active_rule_codes = BTreeSet::from(["SEC324".to_owned()]);

        let projection = WorkspaceProjection::build(
            &config,
            vec![
                scanned_artifact("SKILL.md", "# title\n", &config),
                scanned_artifact("nested/CLAUDE.md", "hello", &config),
            ],
        );

        assert_eq!(
            projection.workspace.project_root.as_ref(),
            config
                .project_root
                .as_ref()
                .map(|path| crate::normalize::normalize_path_string(path))
                .as_ref()
        );
        assert_eq!(projection.workspace.artifacts.len(), 2);
        assert_eq!(
            projection.workspace.active_rule_codes.as_ref(),
            Some(&BTreeSet::from(["SEC324".to_owned()]))
        );

        let first = projection.resolve("SKILL.md").expect("first artifact");
        assert_eq!(first.artifact.artifact.normalized_path, "SKILL.md");
        assert_eq!(first.file_config.normalized_path, "SKILL.md");
        assert_eq!(
            first
                .artifact
                .location_hint
                .as_ref()
                .map(|location| location.span.clone()),
            Some(Span::new(0, "# title\n".len()))
        );

        let second = projection
            .resolve("nested/CLAUDE.md")
            .expect("second artifact");
        assert_eq!(second.artifact.artifact.normalized_path, "nested/CLAUDE.md");
        assert_eq!(
            projection.workspace.project_root.as_deref(),
            Some(projection.project_root_owned().as_str())
        );
        assert!(projection.resolve("missing.md").is_none());
    }
}
