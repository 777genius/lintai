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
fn index_links_positioning_and_scope_doc() {
    let text = include_str!("../../../docs/INDEX.md");

    assert!(
        text.contains("[POSITIONING_AND_SCOPE.md](POSITIONING_AND_SCOPE.md)"),
        "INDEX.md should link the canonical positioning and scope doc"
    );
}

#[test]
fn index_links_public_beta_release_doc() {
    let text = include_str!("../../../docs/INDEX.md");

    assert!(
        text.contains("[PUBLIC_BETA_RELEASE.md](PUBLIC_BETA_RELEASE.md)"),
        "INDEX.md should link the canonical public beta release doc"
    );
}

#[test]
fn index_links_public_beta_shipping_checklist() {
    let text = include_str!("../../../docs/INDEX.md");

    assert!(
        text.contains("[PUBLIC_BETA_SHIPPING_CHECKLIST.md](PUBLIC_BETA_SHIPPING_CHECKLIST.md)"),
        "INDEX.md should link the canonical public beta shipping checklist"
    );
}

#[test]
fn index_links_beta_to_1_0_roadmap() {
    let text = include_str!("../../../docs/INDEX.md");

    assert!(
        text.contains("[BETA_TO_1_0_ROADMAP.md](BETA_TO_1_0_ROADMAP.md)"),
        "INDEX.md should link the canonical post-v0.1 roadmap"
    );
}

#[test]
fn beta_to_1_0_roadmap_documents_precision_first_sequence() {
    let text = include_str!("../../../docs/BETA_TO_1_0_ROADMAP.md");

    assert!(
        text.contains("Phase 1 — Precision Hardening Sprint"),
        "BETA_TO_1_0_ROADMAP.md should start with a precision-hardening first phase"
    );
    assert!(
        text.contains("Phase 2 — External Validation Wave 2"),
        "BETA_TO_1_0_ROADMAP.md should document the second external validation wave"
    );
    assert!(
        text.contains("Phase 3 — Public Beta Release"),
        "BETA_TO_1_0_ROADMAP.md should document the public beta milestone"
    );
    assert!(
        text.contains("Phase 5 — `1.0` Gate and `v0.2+`"),
        "BETA_TO_1_0_ROADMAP.md should document the explicit 1.0 gate"
    );
    assert!(
        text.contains(
            "Immediate default priority: **Phase 1 first, not new broad rule expansion**."
        ),
        "BETA_TO_1_0_ROADMAP.md should lock the precision-first execution priority"
    );
}

#[test]
fn readme_documents_current_positioning_posture() {
    let text = include_str!("../../../README.md");

    assert!(
        text.contains("strong public beta / early-adopter tool"),
        "README.md should document the current release posture honestly"
    );
    assert!(
        text.contains("Not the goal in `v0.1`"),
        "README.md should explicitly call out current non-goals"
    );
    assert!(
        text.contains("docs/POSITIONING_AND_SCOPE.md"),
        "README.md should link the canonical positioning doc"
    );
    assert!(
        text.contains("Public beta release: `v0.1.0-beta.1`"),
        "README.md should expose the current beta release name"
    );
    assert!(
        text.contains("GitHub Releases"),
        "README.md should document GitHub-binaries-only beta distribution"
    );
    assert!(
        text.contains("does not yet promise Homebrew, npm, or `cargo install`"),
        "README.md should explicitly document unsupported beta packaging channels"
    );
    assert!(
        text.contains("Treat `diagnostics` separately from findings"),
        "README.md should explain beta evaluation guidance around diagnostics"
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

#[test]
fn public_beta_release_doc_exists_and_matches_current_posture() {
    let text = include_str!("../../../docs/PUBLIC_BETA_RELEASE.md");

    assert!(text.contains("v0.1.0-beta.1"));
    assert!(text.contains("public beta"));
    assert!(text.contains("GitHub Releases with prebuilt binaries only"));
    assert!(text.contains("lintai-installer.sh"));
    assert!(text.contains("lintai-installer.ps1"));
    assert!(text.contains("release promise for this phase is intentionally limited"));
    assert!(text.contains("`lintai-api` remains the only stable publishable crate"));
    assert!(text.contains("EXTERNAL_VALIDATION_REPORT.md"));
    assert!(text.contains("does **not** promise Homebrew, npm, or `cargo install`"));
    assert!(text.contains("positioned as `1.0`"));
    assert!(text.contains("PUBLIC_BETA_SHIPPING_CHECKLIST.md"));
}

#[test]
fn beta_roadmap_and_shipping_checklist_lock_release_only_distribution() {
    let roadmap = include_str!("../../../docs/BETA_TO_1_0_ROADMAP.md");
    let checklist = include_str!("../../../docs/PUBLIC_BETA_SHIPPING_CHECKLIST.md");
    let index = include_str!("../../../docs/INDEX.md");

    assert!(
        roadmap.contains("ship through GitHub Release assets only"),
        "BETA_TO_1_0_ROADMAP.md should treat GitHub Release assets as the explicit beta distribution posture"
    );
    assert!(
        roadmap.contains("additional installer channels as post-beta follow-up work"),
        "BETA_TO_1_0_ROADMAP.md should defer installer channels until after the beta loop"
    );
    assert!(
        checklist.contains("no parallel package-manager or registry publication step"),
        "PUBLIC_BETA_SHIPPING_CHECKLIST.md should forbid parallel package-manager publication outside the GitHub Release asset set"
    );
    assert!(
        checklist.contains("alternative installation channel beyond downloading the published GitHub Release assets"),
        "PUBLIC_BETA_SHIPPING_CHECKLIST.md should keep the release-assets-only truth check explicit"
    );
    assert!(
        index.contains("GitHub Release assets only"),
        "INDEX.md should summarize the release-only beta distribution decision"
    );
    assert!(
        checklist.contains("lintai-installer.sh") && checklist.contains("lintai-installer.ps1"),
        "PUBLIC_BETA_SHIPPING_CHECKLIST.md should list the installer assets"
    );
}

#[test]
fn readme_and_release_note_document_download_then_run_installers() {
    let readme = include_str!("../../../README.md");
    let release_note = include_str!("../../../docs/releases/v0.1.0-beta.1.md");

    assert!(readme.contains("lintai-installer.sh"));
    assert!(readme.contains("lintai-installer.ps1"));
    assert!(readme.contains("curl -fsSLO"));
    assert!(readme.contains("Manual archive install"));
    assert!(readme.contains("Post-install verification"));
    assert!(release_note.contains("download `lintai-installer.sh` or `lintai-installer.ps1`"));
    assert!(release_note.contains("no `curl | sh` install contract"));
}

#[test]
fn beta_release_note_is_checked_in_and_grounded_in_wave_two() {
    let text = include_str!("../../../docs/releases/v0.1.0-beta.1.md");

    assert!(text.contains("`v0.1.0-beta.1`"));
    assert!(text.contains("`0` stable findings"));
    assert!(text.contains("`0` preview findings"));
    assert!(text.contains("`0` runtime parser errors"));
    assert!(text.contains("`2` recoverable diagnostics"));
    assert!(text.contains("Datadog `SEC105`"));
    assert!(text.contains("cursor/plugins"));
    assert!(text.contains("Emmraan/agent-skills"));
}

#[test]
fn public_beta_shipping_checklist_is_checked_in() {
    let text = include_str!("../../../docs/PUBLIC_BETA_SHIPPING_CHECKLIST.md");

    assert!(text.contains("`v0.1.0-beta.1`"));
    assert!(text.contains("public-beta-release.yml"));
    assert!(text.contains("x86_64-unknown-linux-gnu"));
    assert!(text.contains("x86_64-unknown-linux-musl"));
    assert!(text.contains("aarch64-apple-darwin"));
    assert!(text.contains("x86_64-pc-windows-msvc"));
    assert!(text.contains("SHA256SUMS"));
}

#[test]
fn workflow_readme_mentions_public_beta_release_workflow() {
    let text = include_str!("../../../.github/workflows/README.md");

    assert!(text.contains("public-beta-release.yml"));
    assert!(text.contains("v*-beta.*"));
    assert!(text.contains("SHA256SUMS"));
}

#[test]
fn public_beta_release_workflow_matches_shipping_contract() {
    let text = include_str!("../../../.github/workflows/public-beta-release.yml");

    assert!(text.contains("name: Public Beta Release"));
    assert!(text.contains("workflow_dispatch"));
    assert!(text.contains("v*-beta.*"));
    assert!(text.contains("softprops/action-gh-release"));
    assert!(text.contains("prerelease: true"));
    assert!(text.contains("release_notes_path"));
    assert!(text.contains("SHA256SUMS"));
}
