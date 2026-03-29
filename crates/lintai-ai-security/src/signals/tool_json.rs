use lintai_api::{ArtifactKind, ScanContext};

use crate::helpers::json_semantics;
use crate::json_locator::JsonLocationMap;

use super::shared::*;
use super::{SignalWorkBudget, ToolJsonSignals};

impl ToolJsonSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::ToolDescriptorJson {
            return None;
        }

        let value = &json_semantics(ctx)?.value;
        let locator = JsonLocationMap::parse(&ctx.content);
        if locator.is_some() {
            metrics.json_locator_builds += 1;
        }
        let locator_ref = locator.clone();

        let mut signals = Self {
            locator,
            fixture_like_path: is_fixture_like_tool_json_path(&ctx.artifact.normalized_path),
            ..Self::default()
        };

        visit_tool_json_value(
            value,
            &ctx.artifact.normalized_path,
            locator_ref.as_ref(),
            ctx.content.len(),
            &mut signals,
            metrics,
        );

        Some(signals)
    }
}
