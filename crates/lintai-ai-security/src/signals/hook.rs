use lintai_api::{ArtifactKind, ScanContext};

use super::shared::*;
use super::{HookSignals, SignalWorkBudget};

impl HookSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::CursorHookScript {
            return None;
        }

        let mut signals = Self::default();
        let mut start = 0usize;

        for segment in ctx.content.split_inclusive('\n') {
            let line = segment.strip_suffix('\n').unwrap_or(segment);
            let next_start = start + segment.len();
            collect_hook_line(&mut signals, line, start, metrics);
            start = next_start;
        }

        if start < ctx.content.len() {
            collect_hook_line(&mut signals, &ctx.content[start..], start, metrics);
        }

        Some(signals)
    }
}
