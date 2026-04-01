use lintai_api::{ArtifactKind, ScanContext};
use serde_json::Value;

use crate::helpers::json_semantics;
use crate::json_locator::JsonLocationMap;

use super::shared::{common::*, json::*, markdown::*};
use super::{JsonSignals, SignalWorkBudget};

impl JsonSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if !matches!(
            ctx.artifact.kind,
            ArtifactKind::McpConfig
                | ArtifactKind::PackageManifest
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
        if ctx.artifact.kind == ArtifactKind::PackageManifest {
            analyze_package_manifest(value, locator.as_ref(), fallback_len, &mut signals);
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

const AUTO_RUN_LIFECYCLE_KEYS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];
const DEPENDENCY_SECTION_KEYS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

fn analyze_package_manifest(
    value: &Value,
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    signals: &mut JsonSignals,
) {
    let Some(root) = value.as_object() else {
        return;
    };

    if let Some(scripts) = root.get("scripts").and_then(Value::as_object) {
        for key in AUTO_RUN_LIFECYCLE_KEYS {
            if signals.dangerous_lifecycle_script_span.is_some() {
                break;
            }
            let Some(script) = scripts.get(*key).and_then(Value::as_str) else {
                continue;
            };
            if looks_like_dangerous_lifecycle_script(script) {
                let path = with_child_key(&with_child_key(&[], "scripts"), key);
                signals.dangerous_lifecycle_script_span =
                    Some(resolve_value_span(&path, locator, fallback_len));
            }
        }
    }

    for key in DEPENDENCY_SECTION_KEYS {
        if signals.git_dependency_span.is_some()
            && signals.unbounded_dependency_span.is_some()
            && signals.direct_url_dependency_span.is_some()
        {
            break;
        }
        let Some(section) = root.get(*key).and_then(Value::as_object) else {
            continue;
        };
        for (name, spec) in section {
            let Some(spec) = spec.as_str() else {
                continue;
            };
            if signals.git_dependency_span.is_none() && looks_like_git_dependency_spec(spec) {
                let path = with_child_key(&with_child_key(&[], key), name);
                signals.git_dependency_span =
                    Some(resolve_value_span(&path, locator, fallback_len));
            }
            if signals.unbounded_dependency_span.is_none()
                && looks_like_unbounded_dependency_spec(spec)
            {
                let path = with_child_key(&with_child_key(&[], key), name);
                signals.unbounded_dependency_span =
                    Some(resolve_value_span(&path, locator, fallback_len));
            }
            if signals.direct_url_dependency_span.is_none()
                && looks_like_direct_url_dependency_spec(spec)
            {
                let path = with_child_key(&with_child_key(&[], key), name);
                signals.direct_url_dependency_span =
                    Some(resolve_value_span(&path, locator, fallback_len));
            }
        }
    }
}
