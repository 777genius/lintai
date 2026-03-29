use lintai_api::{ArtifactKind, ScanContext};

use crate::helpers::json_semantics;
use crate::json_locator::JsonLocationMap;

use super::shared::*;
use super::{JsonSignals, SignalWorkBudget};

impl JsonSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if !matches!(
            ctx.artifact.kind,
            ArtifactKind::McpConfig
                | ArtifactKind::CursorPluginManifest
                | ArtifactKind::CursorPluginHooks
        ) {
            return None;
        }

        let value = &json_semantics(ctx)?.value;
        let locator = JsonLocationMap::parse(&ctx.content);
        if locator.is_some() {
            metrics.json_locator_builds += 1;
        }
        let fallback_len = ctx.content.len();
        let mut signals = Self {
            expanded_mcp_client_variant: is_expanded_mcp_client_variant_path(
                &ctx.artifact.normalized_path,
            ),
            fixture_like_expanded_mcp_client_variant:
                is_fixture_like_expanded_mcp_client_variant_path(&ctx.artifact.normalized_path),
            ..Self::default()
        };
        if signals.fixture_like_expanded_mcp_client_variant {
            signals.locator = locator;
            return Some(signals);
        }
        let mut path = Vec::new();
        visit_json_value(
            value,
            &mut path,
            locator.as_ref(),
            fallback_len,
            ctx.artifact.kind,
            &mut signals,
            metrics,
        );
        signals.locator = locator;
        Some(signals)
    }
}
