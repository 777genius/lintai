#[test]
fn architecture_decisions_match_current_exit_code_contract() {
    let text = include_str!("../../../docs/ARCHITECTURE_DECISIONS.md");

    assert!(
        !text.contains("- `0` — ошибок нет, findings нет"),
        "stale scan exit code wording should not remain in ARCHITECTURE_DECISIONS.md"
    );
    assert!(
        text.contains("- `scan`: `0` — blocking findings нет, `1` — есть хотя бы один effective severity = deny finding"),
        "ARCHITECTURE_DECISIONS.md should document current scan exit code behavior"
    );
    assert!(
        text.contains("- `fix`: `0` — preview/apply завершён успешно, `1` — один или несколько выбранных safe fixes были пропущены безопасно"),
        "ARCHITECTURE_DECISIONS.md should document current fix exit code behavior"
    );
}

#[test]
fn architecture_decisions_document_current_fix_surface() {
    let text = include_str!("../../../docs/ARCHITECTURE_DECISIONS.md");

    assert!(text.contains("Safe autofix"));
    assert!(text.contains("`SEC101` и `SEC103`"));
    assert!(text.contains("message suggestions"));
    assert!(text.contains("preview-only candidate patch suggestions"));
}

#[test]
fn index_does_not_contain_stale_iteration_seven_status() {
    let text = include_str!("../../../docs/INDEX.md");

    assert!(
        !text.contains("iterations 1-6 already landed; iteration 7 = docs hardening + dry release"),
        "INDEX.md should not carry stale pre-certification status text"
    );
}

#[test]
fn index_links_security_rules_catalog() {
    let text = include_str!("../../../docs/INDEX.md");

    assert!(
        text.contains("[SECURITY_RULES.md](SECURITY_RULES.md)"),
        "INDEX.md should link the generated security rules catalog"
    );
}

#[test]
fn docs_policy_mentions_graduation_gates() {
    let quality = include_str!("../../../docs/RULE_QUALITY_POLICY.md");
    let architecture = include_str!("../../../docs/ARCHITECTURE_DECISIONS.md");

    assert!(
        quality.contains("Stable` требует **completed graduation metadata**")
            || quality.contains("`Stable` требует **completed graduation metadata**"),
        "RULE_QUALITY_POLICY.md should document stable graduation metadata"
    );
    assert!(
        quality.contains("`Preview` требует **explicit blocker**"),
        "RULE_QUALITY_POLICY.md should document preview blockers"
    );
    assert!(
        architecture.contains("Graduation to `Stable` requires completed lifecycle metadata"),
        "ARCHITECTURE_DECISIONS.md should document lifecycle graduation gates"
    );
}

#[test]
fn architecture_decisions_match_current_provider_backend_model() {
    let text = include_str!("../../../docs/ARCHITECTURE_DECISIONS.md");

    assert!(
        !text.contains("Workspace rules use `ScanScope::{PerFile, Workspace}`"),
        "ARCHITECTURE_DECISIONS.md should not describe scan scope as RuleProvider-owned"
    );
    assert!(
        text.contains("Backend execution mode carries `ScanScope::{PerFile, Workspace}`"),
        "ARCHITECTURE_DECISIONS.md should describe scan scope as backend-owned"
    );
    assert!(
        !text.contains("logical FORMAT/DOMAIN split only for now"),
        "ARCHITECTURE_DECISIONS.md should not describe adapters as a pre-split crate anymore"
    );
    assert!(
        text.contains("`lintai-parse` (internal)") && text.contains("`lintai-adapters` (internal)"),
        "ARCHITECTURE_DECISIONS.md should document the current parse/adapters split"
    );
}
