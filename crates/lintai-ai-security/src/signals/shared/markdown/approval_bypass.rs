use lintai_api::Span;

pub(crate) const MARKDOWN_APPROVAL_BYPASS_DIRECTIVE_MARKERS: &[&str] = &[
    "do not ask the user for permission",
    "do not ask the user for confirmation",
    "don't wait for human approval",
    "no human approval needed",
];
pub(crate) const MARKDOWN_APPROVAL_BYPASS_SUFFIX_MARKERS: &[&str] = &[
    "without asking",
    "without permission",
    "without approval",
    "without confirmation",
];
pub(crate) const MARKDOWN_APPROVAL_SENSITIVE_ACTION_MARKERS: &[&str] = &[
    "kill process",
    "kill processes",
    "rm -rf",
    "git clean",
    "git checkout .",
    "git commit",
    "commit periodically",
    "push",
    "deploy",
    "start server",
    "start servers",
    "change env vars",
    "modify env vars",
    "change environment variables",
    "modify environment variables",
];
pub(crate) const MARKDOWN_APPROVAL_SAFETY_MARKERS: &[&str] = &[
    "ask before",
    "confirm before",
    "requires explicit approval",
    "approval first",
    "must confirm",
    "must ask",
];
pub(crate) const MARKDOWN_APPROVAL_NEGATED_ACTION_PREFIX_MARKERS: &[&str] =
    &["never ", "do not ", "don't ", "must not "];
pub(crate) const MARKDOWN_NEGATIVE_SECTION_HEADERS: &[&str] =
    &["**never:**", "**must not:**", "never:", "must not:"];
pub(crate) fn find_approval_bypass_instruction_relative_span(
    full_content: &str,
    region_start: usize,
    text: &str,
) -> Option<Span> {
    let lowered = text.to_ascii_lowercase();

    for marker in MARKDOWN_APPROVAL_BYPASS_DIRECTIVE_MARKERS {
        if let Some(start) = lowered.find(marker) {
            let marker_span = Span::new(start, start + marker.len());
            if approval_marker_is_suppressed(
                full_content,
                region_start,
                text,
                &lowered,
                &marker_span,
            ) {
                continue;
            }
            return Some(marker_span);
        }
    }

    for marker in MARKDOWN_APPROVAL_BYPASS_SUFFIX_MARKERS {
        if let Some(start) = lowered.find(marker) {
            let marker_span = Span::new(start, start + marker.len());
            if approval_marker_is_suppressed(
                full_content,
                region_start,
                text,
                &lowered,
                &marker_span,
            ) {
                continue;
            }

            let window = local_marker_window(&lowered, &marker_span, 96);
            if has_negated_sensitive_action(window) {
                continue;
            }
            if MARKDOWN_APPROVAL_SENSITIVE_ACTION_MARKERS
                .iter()
                .any(|candidate| window.contains(candidate))
            {
                return Some(marker_span);
            }
        }
    }

    None
}

pub(crate) fn approval_marker_is_suppressed(
    full_content: &str,
    region_start: usize,
    text: &str,
    lowered: &str,
    marker_span: &Span,
) -> bool {
    let window = local_marker_window(lowered, marker_span, 96);
    MARKDOWN_APPROVAL_SAFETY_MARKERS
        .iter()
        .any(|marker| window.contains(marker))
        || has_nearby_negative_section_header(
            full_content,
            region_start,
            text,
            marker_span.start_byte,
        )
}

pub(crate) fn local_marker_window<'a>(text: &'a str, marker_span: &Span, radius: usize) -> &'a str {
    let start = marker_span.start_byte.saturating_sub(radius);
    let end = (marker_span.end_byte + radius).min(text.len());
    &text[start..end]
}

pub(crate) fn has_negated_sensitive_action(window: &str) -> bool {
    MARKDOWN_APPROVAL_SENSITIVE_ACTION_MARKERS
        .iter()
        .flat_map(|action| {
            window
                .match_indices(action)
                .map(move |(start, _)| &window[start.saturating_sub(32)..start])
        })
        .any(|prefix| {
            MARKDOWN_APPROVAL_NEGATED_ACTION_PREFIX_MARKERS
                .iter()
                .any(|marker| prefix.contains(marker))
        })
}

pub(crate) fn has_nearby_negative_section_header(
    full_content: &str,
    region_start: usize,
    text: &str,
    marker_start: usize,
) -> bool {
    if has_local_negative_section_header(&text[..marker_start]) {
        return true;
    }

    let lookback_start = region_start.saturating_sub(160);
    has_local_negative_section_header(&full_content[lookback_start..region_start])
}

pub(crate) fn has_local_negative_section_header(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    MARKDOWN_NEGATIVE_SECTION_HEADERS
        .iter()
        .filter_map(|marker| lowered.rfind(marker).map(|position| (marker, position)))
        .max_by_key(|(_, position)| *position)
        .is_some_and(|(marker, position)| !lowered[position + marker.len()..].contains("\n\n"))
}
