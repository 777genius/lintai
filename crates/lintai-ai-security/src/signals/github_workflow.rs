use lintai_api::{ArtifactKind, ScanContext};

use crate::helpers::yaml_semantics;

use super::shared::*;
use super::{GithubWorkflowSignals, SignalWorkBudget};

impl GithubWorkflowSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::GitHubWorkflow {
            return None;
        }

        let value = &yaml_semantics(ctx)?.value;
        let Some(root) = value.as_object() else {
            return None;
        };
        if !is_semantic_github_workflow(root) {
            return None;
        }

        let mut signals = Self::default();
        let has_pull_request_target = workflow_has_event(root.get("on"), "pull_request_target");
        let has_explicit_write_permissions = workflow_has_explicit_write_permissions(root);
        let mut saw_checkout_step = false;
        let mut current_checkout_indent = None;
        let mut offset = 0usize;
        for segment in ctx.content.split_inclusive('\n') {
            let line = segment.strip_suffix('\n').unwrap_or(segment);
            metrics.markdown_regions_visited += 1;
            collect_github_workflow_line(
                &mut signals,
                line,
                offset,
                has_pull_request_target,
                has_explicit_write_permissions,
                &mut saw_checkout_step,
                &mut current_checkout_indent,
            );
            offset += segment.len();
        }
        if offset < ctx.content.len() {
            collect_github_workflow_line(
                &mut signals,
                &ctx.content[offset..],
                offset,
                has_pull_request_target,
                has_explicit_write_permissions,
                &mut saw_checkout_step,
                &mut current_checkout_indent,
            );
        }
        Some(signals)
    }
}
