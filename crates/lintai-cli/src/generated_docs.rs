use std::fs;
use std::path::{Path, PathBuf};

use crate::{render_security_rules_catalog, render_site_catalog_json};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GeneratedDocArtifact {
    pub(crate) relative_path: &'static str,
    pub(crate) contents: String,
}

pub(crate) fn generated_doc_artifacts() -> Vec<GeneratedDocArtifact> {
    vec![
        GeneratedDocArtifact {
            relative_path: "docs/.generated/catalog.json",
            contents: render_site_catalog_json(),
        },
        GeneratedDocArtifact {
            relative_path: "docs/SECURITY_RULES.md",
            contents: render_security_rules_catalog(),
        },
    ]
}

pub(crate) fn write_generated_doc_artifacts(repo_root: &Path) -> Result<Vec<PathBuf>, String> {
    let artifacts = generated_doc_artifacts();
    let mut written_paths = Vec::with_capacity(artifacts.len());

    for artifact in artifacts {
        let output_path = repo_root.join(artifact.relative_path);
        let parent = output_path
            .parent()
            .ok_or_else(|| format!("missing parent directory for {}", output_path.display()))?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;

        let file_name = output_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("invalid file name for {}", output_path.display()))?;
        let temp_path = parent.join(format!("{file_name}.tmp"));
        fs::write(&temp_path, artifact.contents)
            .map_err(|error| format!("failed to write {}: {error}", temp_path.display()))?;
        fs::rename(&temp_path, &output_path).map_err(|error| {
            format!(
                "failed to move {} into place as {}: {error}",
                temp_path.display(),
                output_path.display()
            )
        })?;
        written_paths.push(output_path);
    }

    Ok(written_paths)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::generated_doc_artifacts;

    #[test]
    fn generated_doc_artifacts_cover_expected_outputs_once() {
        let artifacts = generated_doc_artifacts();
        let paths = artifacts
            .iter()
            .map(|artifact| artifact.relative_path)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec!["docs/.generated/catalog.json", "docs/SECURITY_RULES.md"]
        );

        let unique_paths = paths.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(unique_paths.len(), paths.len());
        assert!(
            artifacts
                .iter()
                .all(|artifact| !artifact.contents.is_empty())
        );
    }
}
