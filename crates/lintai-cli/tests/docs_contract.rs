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
