use std::collections::BTreeSet;

use lintai_api::{ArtifactKind, ScanContext, Span};

use super::shared::common::{
    docker_image_uses_latest_or_implicit_tag, has_download_exec,
    looks_like_registry_image_reference,
};
use super::shared::markdown::is_digest_pinned_docker_image;
use super::{DockerfileSignals, SignalWorkBudget};

impl DockerfileSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::Dockerfile {
            return None;
        }

        let mut signals = Self::default();
        let mut current_stage_root_user_span = None;
        let mut prior_stage_aliases = BTreeSet::new();
        let mut start = 0usize;

        for segment in ctx.content.split_inclusive('\n') {
            let line = segment.strip_suffix('\n').unwrap_or(segment);
            let next_start = start + segment.len();
            collect_dockerfile_line(
                &mut signals,
                &mut current_stage_root_user_span,
                &mut prior_stage_aliases,
                line,
                start,
                metrics,
            );
            start = next_start;
        }

        if start < ctx.content.len() {
            collect_dockerfile_line(
                &mut signals,
                &mut current_stage_root_user_span,
                &mut prior_stage_aliases,
                &ctx.content[start..],
                start,
                metrics,
            );
        }

        signals.final_stage_root_user_span = current_stage_root_user_span;
        Some(signals)
    }
}

fn collect_dockerfile_line(
    signals: &mut DockerfileSignals,
    current_stage_root_user_span: &mut Option<Span>,
    prior_stage_aliases: &mut BTreeSet<String>,
    line: &str,
    offset: usize,
    metrics: &mut SignalWorkBudget,
) {
    metrics.hook_lines_visited += 1;
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }

    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("from ") {
        *current_stage_root_user_span = None;
    }

    if let Some(user_value) = parse_user_value(trimmed, &lowered) {
        *current_stage_root_user_span = if is_explicit_root_user(user_value) {
            Some(Span::new(offset, offset + line.len()))
        } else {
            None
        };
        return;
    }

    if signals.mutable_image_span.is_none()
        && let Some((image_start, image_end)) =
            find_mutable_from_image_span(trimmed, &lowered, prior_stage_aliases)
    {
        let line_offset = line.len() - trimmed.len();
        signals.mutable_image_span = Some(Span::new(
            offset + line_offset + image_start,
            offset + line_offset + image_end,
        ));
    }

    if signals.latest_image_span.is_none()
        && let Some((image_start, image_end)) =
            find_latest_from_image_span(trimmed, &lowered, prior_stage_aliases)
    {
        let line_offset = line.len() - trimmed.len();
        signals.latest_image_span = Some(Span::new(
            offset + line_offset + image_start,
            offset + line_offset + image_end,
        ));
    }

    if signals.download_exec_span.is_some() {
        if let Some(alias) = parse_from_alias(trimmed, &lowered) {
            prior_stage_aliases.insert(alias.to_ascii_lowercase());
        }
        return;
    }

    if !lowered.starts_with("run ") {
        return;
    }
    if has_download_exec(&lowered) {
        signals.download_exec_span = Some(Span::new(offset, offset + line.len()));
    }

    if let Some(alias) = parse_from_alias(trimmed, &lowered) {
        prior_stage_aliases.insert(alias.to_ascii_lowercase());
    }
}

fn parse_user_value<'a>(line: &'a str, lowered: &str) -> Option<&'a str> {
    if !lowered.starts_with("user ") {
        return None;
    }
    let rest = &line[4..];
    let value = rest.trim();
    if value.is_empty() { None } else { Some(value) }
}

fn is_explicit_root_user(user_value: &str) -> bool {
    let primary_token = user_value.split_whitespace().next().unwrap_or_default();
    let user_part = primary_token.split(':').next().unwrap_or(primary_token);
    user_part.eq_ignore_ascii_case("root") || user_part == "0"
}

fn find_mutable_from_image_span(
    line: &str,
    lowered: &str,
    prior_stage_aliases: &BTreeSet<String>,
) -> Option<(usize, usize)> {
    if !lowered.starts_with("from ") {
        return None;
    }

    let mut index = 4usize;
    while index < line.len() && line.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }

    while index < line.len() {
        let token_start = index;
        while index < line.len() && !line.as_bytes()[index].is_ascii_whitespace() {
            index += 1;
        }
        let token_end = index;
        let token = &line[token_start..token_end];
        if token.starts_with("--") {
            while index < line.len() && line.as_bytes()[index].is_ascii_whitespace() {
                index += 1;
            }
            continue;
        }
        let normalized = token.trim_matches(|ch| matches!(ch, '"' | '\''));
        if prior_stage_aliases.contains(&normalized.to_ascii_lowercase()) {
            return None;
        }
        if looks_like_registry_image_reference(normalized)
            && !is_digest_pinned_docker_image(normalized)
        {
            return Some((token_start, token_end));
        }
        return None;
    }
    None
}

fn find_latest_from_image_span(
    line: &str,
    lowered: &str,
    prior_stage_aliases: &BTreeSet<String>,
) -> Option<(usize, usize)> {
    if !lowered.starts_with("from ") {
        return None;
    }

    let mut index = 4usize;
    while index < line.len() && line.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }

    while index < line.len() {
        let token_start = index;
        while index < line.len() && !line.as_bytes()[index].is_ascii_whitespace() {
            index += 1;
        }
        let token_end = index;
        let token = &line[token_start..token_end];
        if token.starts_with("--") {
            while index < line.len() && line.as_bytes()[index].is_ascii_whitespace() {
                index += 1;
            }
            continue;
        }
        let normalized = token.trim_matches(|ch| matches!(ch, '"' | '\''));
        if prior_stage_aliases.contains(&normalized.to_ascii_lowercase()) {
            return None;
        }
        if docker_image_uses_latest_or_implicit_tag(normalized) {
            return Some((token_start, token_end));
        }
        return None;
    }
    None
}

fn parse_from_alias<'a>(line: &'a str, lowered: &str) -> Option<&'a str> {
    if !lowered.starts_with("from ") {
        return None;
    }

    let mut previous = None;
    for token in line.split_whitespace().skip(1) {
        if previous.is_some_and(|value: &str| value.eq_ignore_ascii_case("as")) {
            return Some(token.trim_matches(|ch| matches!(ch, '"' | '\'' | '`')));
        }
        previous = Some(token);
    }
    None
}
