use lintai_api::Span;

pub(crate) const MARKDOWN_UNTRUSTED_INPUT_MARKERS: &[&str] = &[
    "tool output",
    "tool result",
    "command output",
    "shell output",
    "terminal output",
    "web page",
    "webpage",
    "page content",
    "fetched page",
    "search results",
    "issue body",
    "issue text",
    "pull request",
    "pr description",
    "commit message",
    "retrieved context",
    "retrieved content",
    "retrieved document",
    "rag",
    "@import",
    "!command output",
];
pub(crate) const MARKDOWN_INSTRUCTION_AUTHORITY_MARKERS: &[&str] = &[
    "developer message",
    "developer prompt",
    "system message",
    "system prompt",
    "system instructions",
    "developer instructions",
    "highest priority",
    "authoritative instructions",
];
pub(crate) const MARKDOWN_INSTRUCTION_PROMOTION_VERBS_WITH_AS: &[&str] =
    &["treat", "use", "consider"];
pub(crate) const MARKDOWN_INSTRUCTION_PROMOTION_MARKERS: &[&str] = &[
    "follow",
    "obey",
    "merge into",
    "append to",
    "override",
    "overrides",
];
pub(crate) const MARKDOWN_PROMOTION_NEGATION_MARKERS: &[&str] =
    &["do not", "don't", "never", "must not", "should not"];
pub(crate) fn find_untrusted_instruction_promotion_relative_span(text: &str) -> Option<Span> {
    let lowered = text.to_ascii_lowercase();
    let authority_position = MARKDOWN_INSTRUCTION_AUTHORITY_MARKERS
        .iter()
        .filter_map(|marker| lowered.find(marker))
        .min()?;
    let promotion_position = find_instruction_promotion_position(&lowered)?;

    if MARKDOWN_PROMOTION_NEGATION_MARKERS
        .iter()
        .filter_map(|marker| lowered.find(marker))
        .any(|position| position < promotion_position)
    {
        return None;
    }

    let anchor = authority_position.min(promotion_position);
    let search_window_start = anchor.saturating_sub(160);
    let search_window_end = (anchor + 160).min(lowered.len());
    let window = &lowered[search_window_start..search_window_end];

    MARKDOWN_UNTRUSTED_INPUT_MARKERS
        .iter()
        .find_map(|marker| {
            window.find(marker).map(|start| {
                Span::new(
                    search_window_start + start,
                    search_window_start + start + marker.len(),
                )
            })
        })
        .or_else(|| {
            MARKDOWN_UNTRUSTED_INPUT_MARKERS
                .iter()
                .find_map(|marker| lowered.find(marker).map(|start| (marker, start)))
                .map(|(marker, start)| Span::new(start, start + marker.len()))
        })
}

pub(crate) fn find_instruction_promotion_position(text: &str) -> Option<usize> {
    let with_as = MARKDOWN_INSTRUCTION_PROMOTION_VERBS_WITH_AS
        .iter()
        .filter_map(|verb| {
            text.find(verb)
                .and_then(|position| text[position + verb.len()..].find(" as ").map(|_| position))
        })
        .min();
    let direct = MARKDOWN_INSTRUCTION_PROMOTION_MARKERS
        .iter()
        .filter_map(|marker| text.find(marker))
        .min();

    match (with_as, direct) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}
