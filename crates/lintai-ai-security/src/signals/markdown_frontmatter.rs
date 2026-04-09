use lintai_api::{ArtifactKind, RegionKind, ScanContext, Span};

use crate::helpers::{markdown_semantics, span_text};

use super::MarkdownSignals;
use super::shared::markdown::*;

pub(super) fn apply_frontmatter_signals(ctx: &ScanContext, signals: &mut MarkdownSignals) {
    let Some(scope) = FrontmatterScope::from_context(ctx) else {
        return;
    };

    if !matches!(
        ctx.artifact.kind,
        ArtifactKind::Skill
            | ArtifactKind::Instructions
            | ArtifactKind::CursorPluginCommand
            | ArtifactKind::CursorPluginAgent
    ) || is_fixture_like_markdown_instruction_path(&ctx.artifact.normalized_path)
    {
        return;
    }

    let Some(allowed_tools_value) = scope.allowed_tools_value() else {
        return;
    };

    record_allowed_tool_detection(
        &scope,
        signals,
        allowed_tools_value,
        frontmatter_has_unscoped_bash_allowed_tools,
        find_unscoped_bash_allowed_tools_frontmatter_relative_span,
        |signals, span| signals.unscoped_bash_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(*)",
        |signals, span| {
            signals.wildcard_bash_allowed_tools_spans.push(span);
        },
    );
    record_allowed_tool_detection(
        &scope,
        signals,
        allowed_tools_value,
        frontmatter_has_unscoped_websearch_allowed_tools,
        find_unscoped_websearch_allowed_tools_frontmatter_relative_span,
        |signals, span| signals.unscoped_websearch_allowed_tools_spans.push(span),
    );
    record_allowed_tool_detection(
        &scope,
        signals,
        allowed_tools_value,
        frontmatter_has_unscoped_webfetch_allowed_tools,
        find_unscoped_webfetch_allowed_tools_frontmatter_relative_span,
        |signals, span| signals.unscoped_webfetch_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(git push)",
        |signals, span| signals.git_push_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(git checkout:*)",
        |signals, span| signals.git_checkout_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(git commit:*)",
        |signals, span| signals.git_commit_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(git stash:*)",
        |signals, span| signals.git_stash_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(gh pr:*)",
        |signals, span| {
            signals.gh_pr_allowed_tools_spans.push(span);
        },
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(gh api --method POST:*)",
        |signals, span| signals.gh_api_post_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(gh api --method DELETE:*)",
        |signals, span| signals.gh_api_delete_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(gh api --method PATCH:*)",
        |signals, span| signals.gh_api_patch_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(gh api --method PUT:*)",
        |signals, span| signals.gh_api_put_allowed_tools_spans.push(span),
    );
    record_exact_allowed_tool_span(
        &scope,
        signals,
        allowed_tools_value,
        "Bash(gh issue create:*)",
        |signals, span| signals.gh_issue_create_allowed_tools_spans.push(span),
    );
}

struct FrontmatterScope<'a> {
    snippet: &'a str,
    region_span: &'a Span,
    parsed_frontmatter: &'a serde_json::Value,
}

impl<'a> FrontmatterScope<'a> {
    fn from_context(ctx: &'a ScanContext) -> Option<Self> {
        let region = ctx
            .document
            .regions
            .iter()
            .find(|region| matches!(region.kind, RegionKind::Frontmatter))?;
        let snippet = span_text(&ctx.content, &region.span)?;
        let parsed_frontmatter = markdown_semantics(ctx)
            .and_then(|markdown| markdown.frontmatter.as_ref())
            .map(|frontmatter| &frontmatter.value)?;
        Some(Self {
            snippet,
            region_span: &region.span,
            parsed_frontmatter,
        })
    }

    fn absolute_span(&self, relative: Span) -> Span {
        Span::new(
            self.region_span.start_byte + relative.start_byte,
            self.region_span.start_byte + relative.end_byte,
        )
    }

    fn allowed_tools_value(&self) -> Option<&serde_json::Value> {
        self.parsed_frontmatter
            .get("allowed-tools")
            .or_else(|| self.parsed_frontmatter.get("allowed_tools"))
    }
}

fn record_allowed_tool_detection(
    scope: &FrontmatterScope<'_>,
    signals: &mut MarkdownSignals,
    allowed_tools_value: &serde_json::Value,
    predicate: fn(&serde_json::Value) -> bool,
    relative_finder: fn(&str) -> Option<Span>,
    record: impl FnOnce(&mut MarkdownSignals, Span),
) {
    if predicate(allowed_tools_value)
        && let Some(relative) = relative_finder(scope.snippet)
    {
        record(signals, scope.absolute_span(relative));
    }
}

fn record_exact_allowed_tool_span(
    scope: &FrontmatterScope<'_>,
    signals: &mut MarkdownSignals,
    allowed_tools_value: &serde_json::Value,
    tool: &str,
    record: impl FnOnce(&mut MarkdownSignals, Span),
) {
    if frontmatter_has_exact_allowed_tool(allowed_tools_value, tool)
        && let Some(relative) =
            find_exact_allowed_tool_frontmatter_relative_span(scope.snippet, tool)
    {
        record(signals, scope.absolute_span(relative));
    }
}
