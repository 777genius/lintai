use lintai_api::{ArtifactKind, ScanContext, Span};

use crate::helpers::json_semantics;
use crate::json_locator::{JsonLocationMap, JsonPathSegment};

use super::shared::{
    json::visit_claude_settings_value, markdown::is_fixture_like_claude_settings_path,
};
use super::{ClaudeSettingsSignals, SignalWorkBudget};

fn leading_json_file_relative_span(content: &str) -> Option<Span> {
    content
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(index, ch)| Span::new(index, index + ch.len_utf8()))
}

fn resolve_permissions_allow_bash_wildcard_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
) -> Option<Span> {
    let allow = value
        .get("permissions")
        .and_then(|permissions| permissions.get("allow"))
        .and_then(serde_json::Value::as_array)?;
    let index = allow
        .iter()
        .position(|entry| entry.as_str() == Some("Bash(*)"))?;
    let path = vec![
        JsonPathSegment::Key("permissions".to_owned()),
        JsonPathSegment::Key("allow".to_owned()),
        JsonPathSegment::Index(index),
    ];
    locator.and_then(|locator| locator.value_span(&path).cloned())
}

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
        if value.is_object() && !value.get("$schema").is_some() {
            signals.missing_schema_span = leading_json_file_relative_span(&ctx.content);
        }
        signals.bash_wildcard_span =
            resolve_permissions_allow_bash_wildcard_span(value, locator_ref.as_ref());
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
