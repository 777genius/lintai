use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_tool_json_mcp_missing_machine_fields(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    tool_finding_from_span(
        ctx,
        meta,
        signals
            .tool_json()
            .and_then(|signals| signals.mcp_missing_machine_field_span.clone()),
        "tool descriptor is missing required MCP machine fields",
    )
}

pub(crate) fn check_tool_json_duplicate_mcp_tool_names(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    tool_finding_from_span(
        ctx,
        meta,
        signals
            .tool_json()
            .and_then(|signals| signals.duplicate_mcp_tool_name_span.clone()),
        "tool descriptor collection contains duplicate MCP tool names",
    )
}

pub(crate) fn check_tool_json_openai_strict_additional_properties(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    tool_finding_from_span(
        ctx,
        meta,
        signals
            .tool_json()
            .and_then(|signals| signals.openai_strict_additional_properties_span.clone()),
        "OpenAI strict tool schema omits recursive additionalProperties: false",
    )
}

pub(crate) fn check_tool_json_openai_strict_required_coverage(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    tool_finding_from_span(
        ctx,
        meta,
        signals
            .tool_json()
            .and_then(|signals| signals.openai_strict_required_span.clone()),
        "OpenAI strict tool schema does not require every declared property",
    )
}

pub(crate) fn check_tool_json_anthropic_strict_locked_input_schema(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    tool_finding_from_span(
        ctx,
        meta,
        signals.tool_json().and_then(|signals| {
            signals
                .anthropic_strict_locked_input_schema_span
                .clone()
        }),
        "Anthropic strict tool input_schema omits additionalProperties: false",
    )
}

fn tool_finding_from_span(
    ctx: &ScanContext,
    meta: RuleMetadata,
    span: Option<Span>,
    message: &'static str,
) -> Vec<Finding> {
    if ctx.artifact.kind != lintai_api::ArtifactKind::ToolDescriptorJson {
        return Vec::new();
    }

    span.into_iter()
        .map(|span| finding_for_region(&meta, ctx, &span, message))
        .collect()
}
