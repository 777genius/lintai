use lintai_api::{
    DocumentSemantics, Evidence, EvidenceKind, Finding, JsonSemantics, Location, RuleMetadata,
    ScanContext, Span, YamlSemantics,
};

pub(crate) fn json_semantics(ctx: &ScanContext) -> Option<&JsonSemantics> {
    match ctx.semantics.as_ref() {
        Some(DocumentSemantics::Json(value)) => Some(value),
        _ => None,
    }
}

pub(crate) fn yaml_semantics(ctx: &ScanContext) -> Option<&YamlSemantics> {
    match ctx.semantics.as_ref() {
        Some(DocumentSemantics::Yaml(value)) => Some(value),
        _ => None,
    }
}

pub(crate) fn finding_for_region(
    meta: &RuleMetadata,
    ctx: &ScanContext,
    span: &Span,
    message: &'static str,
) -> Finding {
    Finding::new(
        meta,
        Location::new(ctx.artifact.normalized_path.clone(), span.clone()),
        message,
    )
    .with_evidence(Evidence::new(
        EvidenceKind::Context,
        "matched artifact content",
        Some(Location::new(
            ctx.artifact.normalized_path.clone(),
            span.clone(),
        )),
    ))
}

pub(crate) fn span_text<'a>(content: &'a str, span: &Span) -> Option<&'a str> {
    content.get(span.start_byte..span.end_byte)
}

pub(crate) fn contains_dynamic_reference(text: &str) -> bool {
    text.contains('$')
}

pub(crate) fn find_url_userinfo_span(text: &str) -> Option<Span> {
    let lowered = text.to_lowercase();
    let mut search_start = 0usize;

    while search_start < lowered.len() {
        let http_rel = lowered[search_start..].find("http://");
        let https_rel = lowered[search_start..].find("https://");
        let (scheme_rel, scheme_len) = match (http_rel, https_rel) {
            (Some(left), Some(right)) => {
                if left <= right {
                    (left, "http://".len())
                } else {
                    (right, "https://".len())
                }
            }
            (Some(left), None) => (left, "http://".len()),
            (None, Some(right)) => (right, "https://".len()),
            (None, None) => return None,
        };

        let scheme_start = search_start + scheme_rel;
        let credential_start = scheme_start + scheme_len;
        let mut found_at = None;

        for (rel_index, ch) in text[credential_start..].char_indices() {
            match ch {
                '@' => {
                    found_at = Some(credential_start + rel_index);
                    break;
                }
                '/' | '?' | '#' | '"' | '\'' | ' ' | '\t' | '\r' | '\n' => break,
                _ => {}
            }
        }

        if let Some(at_index) = found_at {
            let userinfo = &text[credential_start..at_index];
            if !userinfo.is_empty() && !contains_dynamic_reference(userinfo) {
                return Some(Span::new(credential_start, at_index));
            }
            search_start = at_index + 1;
        } else {
            search_start = credential_start;
        }
    }

    None
}
