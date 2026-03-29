use crate::external_validation::*;
use lintai_engine::FileTypeDetector;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub(super) struct AiNativeCoverageSummary {
    pub(super) total_admission_paths: usize,
    pub(super) covered_admission_paths: usize,
    pub(super) discovery_only_admission_paths: usize,
    pub(super) plugin_root_hook_paths: usize,
    pub(super) plugin_root_agent_paths: usize,
    pub(super) plugin_root_command_paths: usize,
    pub(super) gemini_client_paths: usize,
    pub(super) covered_repos: Vec<(String, Vec<String>)>,
    pub(super) discovery_only_repos: Vec<(String, Vec<String>)>,
}

pub(super) fn coverage_summary(shortlist: &RepoShortlist) -> AiNativeCoverageSummary {
    let detector = FileTypeDetector::default();
    let mut summary = AiNativeCoverageSummary::default();
    for repo in &shortlist.repos {
        let mut covered = Vec::new();
        let mut discovery_only = Vec::new();
        for path in &repo.admission_paths {
            summary.total_admission_paths += 1;
            if detector.detect(Path::new(path), path).is_some()
                || is_manifest_backed_plugin_target_path(path)
                || is_ai_native_docker_config_path(path)
            {
                summary.covered_admission_paths += 1;
                if is_manifest_backed_plugin_hooks_path(path) {
                    summary.plugin_root_hook_paths += 1;
                }
                if is_manifest_backed_plugin_agent_path(path) {
                    summary.plugin_root_agent_paths += 1;
                }
                if is_manifest_backed_plugin_command_path(path) {
                    summary.plugin_root_command_paths += 1;
                }
                if is_ai_native_docker_config_path(path) {
                    summary.gemini_client_paths += 1;
                }
                covered.push(path.clone());
            } else {
                summary.discovery_only_admission_paths += 1;
                discovery_only.push(path.clone());
            }
        }
        if !covered.is_empty() {
            summary.covered_repos.push((repo.repo.clone(), covered));
        }
        if !discovery_only.is_empty() {
            summary
                .discovery_only_repos
                .push((repo.repo.clone(), discovery_only));
        }
    }
    summary
}

pub(super) fn append_coverage_status(output: &mut String, coverage: &AiNativeCoverageSummary) {
    output.push_str("## Coverage Status\n\n");
    output.push_str(&format!(
        "- `{}` total admitted paths\n",
        coverage.total_admission_paths
    ));
    output.push_str(&format!(
        "- `{}` admitted paths are currently covered by shipped detector kinds\n",
        coverage.covered_admission_paths
    ));
    output.push_str(&format!("- `{}` admitted paths are discovery-only and not directly scanned by current detector kinds\n", coverage.discovery_only_admission_paths));
    output.push_str(&format!(
        "- `{}` repos have at least one currently covered admission path\n",
        coverage.covered_repos.len()
    ));
    output.push_str(&format!(
        "- `{}` repos are discovery-only under current detector coverage\n\n",
        coverage.discovery_only_repos.len()
    ));
    output.push_str(&format!(
        "- `{}` plugin-root hook admission paths are now covered\n",
        coverage.plugin_root_hook_paths
    ));
    output.push_str(&format!(
        "- `{}` plugin-root agent markdown admission paths are now covered\n\n",
        coverage.plugin_root_agent_paths
    ));
    output.push_str(&format!(
        "- `{}` plugin-root command markdown admission paths are now covered\n\n",
        coverage.plugin_root_command_paths
    ));
    output.push_str(&format!(
        "- `{}` Gemini-style MCP client admission paths are now covered\n\n",
        coverage.gemini_client_paths
    ));
    if !coverage.covered_repos.is_empty() {
        output.push_str("Currently covered admission paths:\n\n");
        for (repo, paths) in &coverage.covered_repos {
            output.push_str(&format!("- `{repo}`: {}\n", format_rule_codes(paths)));
        }
        output.push('\n');
    }
    if !coverage.discovery_only_repos.is_empty() {
        output.push_str("Discovery-only admission paths:\n\n");
        for (repo, paths) in &coverage.discovery_only_repos {
            output.push_str(&format!("- `{repo}`: {}\n", format_rule_codes(paths)));
        }
        output.push('\n');
    }

    for repo_name in [
        "hashicorp/terraform-mcp-server",
        "SonarSource/sonarqube-mcp-server",
    ] {
        let status = if coverage
            .covered_repos
            .iter()
            .any(|(repo, _)| repo == repo_name)
        {
            "covered"
        } else {
            "discovery-only"
        };
        output.push_str(&format!(
            "- `{repo_name}` is now `{status}` under shipped AI-native detector coverage\n"
        ));
    }
    output.push('\n');
}

fn is_manifest_backed_plugin_target_path(path: &str) -> bool {
    is_manifest_backed_plugin_hooks_path(path)
        || is_manifest_backed_plugin_agent_path(path)
        || is_manifest_backed_plugin_command_path(path)
}

fn is_manifest_backed_plugin_hooks_path(path: &str) -> bool {
    path.ends_with("/hooks.json") && !path.contains("/.cursor-plugin/")
}

fn is_manifest_backed_plugin_agent_path(path: &str) -> bool {
    path.contains("/agents/") && path.ends_with(".md") && !path.contains("/.cursor-plugin/agents/")
}

fn is_manifest_backed_plugin_command_path(path: &str) -> bool {
    path.contains("/commands/")
        && path.ends_with(".md")
        && !path.contains("/.cursor-plugin/commands/")
        && !path.contains("/.claude/commands/")
}
