use lintai_api::{
    DocumentSemantics, Evidence, EvidenceKind, Finding, JsonSemantics, Location, RuleMetadata,
    ScanContext, Span, WorkspaceArtifact,
};

pub(crate) fn json_semantics(ctx: &ScanContext) -> Option<&JsonSemantics> {
    match ctx.semantics.as_ref() {
        Some(DocumentSemantics::Json(value)) => Some(value),
        _ => None,
    }
}

pub(crate) fn workspace_json_semantics(ctx: &WorkspaceArtifact) -> Option<&JsonSemantics> {
    match ctx.semantics.as_ref() {
        Some(DocumentSemantics::Json(value)) => Some(value),
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
