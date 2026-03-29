use lintai_api::{
    ArtifactKind, CapabilityConflictMode, Evidence, EvidenceKind, Finding, Location, RuleMetadata,
    WorkspaceArtifact,
};

pub(crate) fn policy_finding(
    meta: &RuleMetadata,
    artifact: &WorkspaceArtifact,
    message: &'static str,
    conflict_mode: CapabilityConflictMode,
) -> Finding {
    let mut finding = Finding::new(
        meta,
        artifact.location_hint.clone().unwrap_or_else(|| {
            Location::new(
                artifact.artifact.normalized_path.clone(),
                lintai_api::Span::new(0, artifact.content.len()),
            )
        }),
        message,
    );
    finding.evidence.clear();
    finding.evidence.push(Evidence::new(
        EvidenceKind::Claim,
        "project policy claims this capability is forbidden",
        None,
    ));
    finding.evidence.push(Evidence::new(
        EvidenceKind::ObservedBehavior,
        observed_message(meta.code),
        observed_location(artifact),
    ));
    if matches!(conflict_mode, CapabilityConflictMode::Deny) {
        finding.severity = lintai_api::Severity::Deny;
    }
    finding
}

pub(crate) fn observed_message(rule_code: &str) -> &'static str {
    match rule_code {
        "SEC401" => "artifact contains executable behavior",
        "SEC402" => "artifact contains network behavior",
        "SEC403" => "artifact frontmatter capabilities conflict with project policy",
        _ => "artifact behavior conflicts with project policy",
    }
}

pub(crate) fn observed_location(ctx: &WorkspaceArtifact) -> Option<Location> {
    if matches!(ctx.artifact.kind, ArtifactKind::CursorHookScript) {
        return first_match_location(
            &ctx.artifact.normalized_path,
            &ctx.content,
            &["curl ", "wget ", "http://", "https://", "sh ", "bash "],
        );
    }

    if matches!(
        ctx.artifact.kind,
        ArtifactKind::McpConfig
            | ArtifactKind::CursorPluginManifest
            | ArtifactKind::CursorPluginHooks
    ) {
        return first_match_location(
            &ctx.artifact.normalized_path,
            &ctx.content,
            &[
                "http://",
                "https://",
                "\"command\"",
                "\"args\"",
                "\"sh\"",
                "\"bash\"",
            ],
        );
    }

    first_match_location(
        &ctx.artifact.normalized_path,
        &ctx.content,
        &["capabilities"],
    )
}

pub(crate) fn first_match_location(
    normalized_path: &str,
    content: &str,
    needles: &[&str],
) -> Option<Location> {
    let start = needles
        .iter()
        .filter_map(|needle| content.find(needle))
        .min()?;
    let end = needles
        .iter()
        .filter_map(|needle| content.find(needle).map(|offset| offset + needle.len()))
        .find(|offset| *offset >= start)
        .unwrap_or(start + 1);
    Some(Location::new(
        normalized_path.to_owned(),
        lintai_api::Span::new(start, end),
    ))
}
