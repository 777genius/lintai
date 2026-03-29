use lintai_api::{ArtifactKind, ScanContext};

use crate::helpers::json_semantics;
use crate::json_locator::JsonLocationMap;

use super::shared::*;
use super::{ClaudeSettingsSignals, SignalWorkBudget};

impl ClaudeSettingsSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::ClaudeSettings {
            return None;
        }

        let value = &json_semantics(ctx)?.value;
        let locator = JsonLocationMap::parse(&ctx.content);
        if locator.is_some() {
            metrics.json_locator_builds += 1;
        }
        let fallback_len = ctx.content.len();
        let locator_ref = locator.clone();
        let mut signals = Self {
            locator,
            fixture_like_path: is_fixture_like_claude_settings_path(&ctx.artifact.normalized_path),
            ..Self::default()
        };
        if signals.fixture_like_path {
            return Some(signals);
        }
        let mut path = Vec::new();
        visit_claude_settings_value(
            value,
            &mut path,
            locator_ref.as_ref(),
            fallback_len,
            &mut signals,
            metrics,
        );
        Some(signals)
    }
}
