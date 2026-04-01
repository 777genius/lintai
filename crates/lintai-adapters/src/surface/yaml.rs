use lintai_api::{ArtifactKind, SourceFormat};

use super::{SurfaceSpec, parse_yaml_surface};
use crate::detection::DetectionRuleSpec;

const DOCKER_COMPOSE_RULES: &[DetectionRuleSpec] = &[
    DetectionRuleSpec {
        priority: 2,
        file_name: Some("docker-compose.yml"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::DockerCompose,
        format: SourceFormat::Yaml,
    },
    DetectionRuleSpec {
        priority: 2,
        file_name: Some("docker-compose.yaml"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::DockerCompose,
        format: SourceFormat::Yaml,
    },
    DetectionRuleSpec {
        priority: 2,
        file_name: Some("compose.yml"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::DockerCompose,
        format: SourceFormat::Yaml,
    },
    DetectionRuleSpec {
        priority: 2,
        file_name: Some("compose.yaml"),
        file_name_fragment: None,
        suffix: None,
        parent_dir: None,
        path_fragment: None,
        artifact_kind: ArtifactKind::DockerCompose,
        format: SourceFormat::Yaml,
    },
];

const GITHUB_WORKFLOW_RULES: &[DetectionRuleSpec] = &[
    DetectionRuleSpec {
        priority: 2,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".yml"),
        parent_dir: None,
        path_fragment: Some(".github/workflows/"),
        artifact_kind: ArtifactKind::GitHubWorkflow,
        format: SourceFormat::Yaml,
    },
    DetectionRuleSpec {
        priority: 2,
        file_name: None,
        file_name_fragment: None,
        suffix: Some(".yaml"),
        parent_dir: None,
        path_fragment: Some(".github/workflows/"),
        artifact_kind: ArtifactKind::GitHubWorkflow,
        format: SourceFormat::Yaml,
    },
];

pub(super) const SURFACE_SPECS: [SurfaceSpec; 2] = [
    SurfaceSpec {
        id: "github_workflow_yaml",
        artifact_kind: ArtifactKind::GitHubWorkflow,
        format: SourceFormat::Yaml,
        detection_rules: GITHUB_WORKFLOW_RULES,
        parse_fn: parse_yaml_surface,
    },
    SurfaceSpec {
        id: "docker_compose_yaml",
        artifact_kind: ArtifactKind::DockerCompose,
        format: SourceFormat::Yaml,
        detection_rules: DOCKER_COMPOSE_RULES,
        parse_fn: parse_yaml_surface,
    },
];
