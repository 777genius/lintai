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

#[cfg(test)]
mod tests {
    use super::*;
    use lintai_api::{
        Artifact, ArtifactKind, CapabilityConflictMode, Category, Confidence, EvidenceKind,
        Location, ParsedDocument, RuleMetadata, RuleTier, Severity, SourceFormat, Span,
        WorkspaceArtifact,
    };

    fn mk_artifact(
        kind: ArtifactKind,
        content: &str,
    ) -> WorkspaceArtifact {
        WorkspaceArtifact::new(
            Artifact::new("repo/file.txt", kind, SourceFormat::Markdown),
            content,
            ParsedDocument::new(Vec::new(), None),
            None,
        )
    }

    fn metadata(code: &'static str) -> RuleMetadata {
        RuleMetadata::new(
            code,
            "summary",
            Category::Audit,
            Severity::Warn,
            Confidence::High,
            RuleTier::Preview,
        )
    }

    #[test]
    fn observed_message_maps_known_rules() {
        assert_eq!(
            observed_message("SEC401"),
            "artifact contains executable behavior"
        );
        assert_eq!(
            observed_message("SEC402"),
            "artifact contains network behavior"
        );
        assert_eq!(
            observed_message("SEC403"),
            "artifact frontmatter capabilities conflict with project policy"
        );
        assert_eq!(
            observed_message("SEC999"),
            "artifact behavior conflicts with project policy"
        );
    }

    #[test]
    fn first_match_location_returns_the_first_matching_span() {
        let location = first_match_location("repo/file.txt", "barxxcurl", &["bar", "curl"]);
        assert_eq!(location.expect("match expected").span, Span::new(0, 3));
    }

    #[test]
    fn first_match_location_returns_none_when_no_needle_matches() {
        assert!(first_match_location("repo/file.txt", "abc", &["curl"]).is_none());
    }

    #[test]
    fn observed_location_targets_hook_needles() {
        let artifact = mk_artifact(
            ArtifactKind::CursorHookScript,
            "echo\ncurl https://example.com/file",
        );
        let location = observed_location(&artifact).expect("location expected");
        assert_eq!(location.normalized_path, "repo/file.txt");
        assert_eq!(location.span.start_byte, 5);
    }

    #[test]
    fn observed_location_targets_jsonish_artifact_needles() {
        let artifact = mk_artifact(
            ArtifactKind::CursorPluginManifest,
            r#"{ "command": "python", "args": ["-c"] }"#,
        );
        let location = observed_location(&artifact).expect("location expected");
        assert_eq!(location.normalized_path, "repo/file.txt");
        assert!(location.span.start_byte > 0);
    }

    #[test]
    fn observed_location_defaults_to_capability_keyword_for_other_artifacts() {
        let artifact = mk_artifact(ArtifactKind::Skill, "some capabilities are set");
        let location = observed_location(&artifact).expect("location expected");
        assert_eq!(location.span.start_byte, 5);
    }

    #[test]
    fn policy_finding_uses_hint_location_when_present() {
        let artifact = mk_artifact(ArtifactKind::CursorHookScript, "payload")
            .with_location_hint(Location::new("repo/hint.txt", Span::new(2, 4)));
        let finding = policy_finding(
            &metadata("SEC401"),
            &artifact,
            "hook uses exec",
            CapabilityConflictMode::Warn,
        );

        assert_eq!(finding.location, Location::new("repo/hint.txt", Span::new(2, 4)));
        assert_eq!(finding.stable_key.normalized_path, "repo/hint.txt");
        assert_eq!(finding.stable_key.span, Span::new(2, 4));
    }

    #[test]
    fn policy_finding_uses_full_content_span_without_hint() {
        let artifact = mk_artifact(ArtifactKind::CursorHookScript, "abc");
        let finding = policy_finding(
            &metadata("SEC401"),
            &artifact,
            "hook uses exec",
            CapabilityConflictMode::Warn,
        );

        assert_eq!(finding.location.span, Span::new(0, 3));
        assert_eq!(finding.stable_key.span, Span::new(0, 3));
    }

    #[test]
    fn policy_finding_warn_mode_keeps_default_severity() {
        let artifact = mk_artifact(ArtifactKind::CursorHookScript, "abc");
        let finding = policy_finding(
            &metadata("SEC402"),
            &artifact,
            "network",
            CapabilityConflictMode::Warn,
        );
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.evidence.len(), 2);
        assert_eq!(finding.evidence[0].kind, EvidenceKind::Claim);
        assert_eq!(finding.evidence[1].kind, EvidenceKind::ObservedBehavior);
        assert_eq!(finding.evidence[1].message, observed_message("SEC402"));
    }

    #[test]
    fn policy_finding_deny_mode_forces_deny_severity() {
        let artifact = mk_artifact(ArtifactKind::CursorHookScript, "abc");
        let finding = policy_finding(
            &metadata("SEC403"),
            &artifact,
            "conflict",
            CapabilityConflictMode::Deny,
        );
        assert_eq!(finding.severity, Severity::Deny);
    }
}
