use lintai_api::{ArtifactKind, ScanContext, Span};

use super::shared::common::has_download_exec;
use super::{DockerfileSignals, SignalWorkBudget};

impl DockerfileSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::Dockerfile {
            return None;
        }

        let mut signals = Self::default();
        let mut start = 0usize;

        for segment in ctx.content.split_inclusive('\n') {
            let line = segment.strip_suffix('\n').unwrap_or(segment);
            let next_start = start + segment.len();
            collect_dockerfile_line(&mut signals, line, start, metrics);
            start = next_start;
        }

        if start < ctx.content.len() {
            collect_dockerfile_line(&mut signals, &ctx.content[start..], start, metrics);
        }

        Some(signals)
    }
}

fn collect_dockerfile_line(
    signals: &mut DockerfileSignals,
    line: &str,
    offset: usize,
    metrics: &mut SignalWorkBudget,
) {
    metrics.hook_lines_visited += 1;
    if signals.download_exec_span.is_some() {
        return;
    }

    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return;
    }

    let lowered = trimmed.to_ascii_lowercase();
    if !lowered.starts_with("run ") {
        return;
    }
    if has_download_exec(&lowered) {
        signals.download_exec_span = Some(Span::new(offset, offset + line.len()));
    }
}
