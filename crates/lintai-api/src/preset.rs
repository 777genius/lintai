#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinPresetKind {
    Membership,
    Overlay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuiltinPresetSpec {
    pub id: &'static str,
    pub kind: BuiltinPresetKind,
    pub description: &'static str,
    pub extends: &'static [&'static str],
}

const BUILTIN_PRESETS: &[BuiltinPresetSpec] = &[
    BuiltinPresetSpec {
        id: "recommended",
        kind: BuiltinPresetKind::Membership,
        description: "Quiet practical default for most teams: curated high-signal checks for AI-native repos.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "base",
        kind: BuiltinPresetKind::Membership,
        description: "Minimal stable baseline for explicit compatibility-focused setups.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "preview",
        kind: BuiltinPresetKind::Membership,
        description: "Deeper-review rules that expand coverage beyond the recommended default.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "compat",
        kind: BuiltinPresetKind::Membership,
        description: "Policy and compatibility checks that compare declared workspace posture against repository behavior.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "skills",
        kind: BuiltinPresetKind::Membership,
        description: "Rules for instruction and skills markdown that remain inside the core agent-artifact surface.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "mcp",
        kind: BuiltinPresetKind::Membership,
        description: "Rules for MCP, tool, and server JSON configs, including preview-only coverage.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "claude",
        kind: BuiltinPresetKind::Membership,
        description: "Rules for Claude settings and command-hook configuration.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "guidance",
        kind: BuiltinPresetKind::Membership,
        description: "Advice-oriented guidance rules that are useful, but intentionally not part of the core security baseline.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "governance",
        kind: BuiltinPresetKind::Membership,
        description: "Opt-in review rules for shared mutation authority and broad bare tool grants that should not read like headline security findings.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "supply-chain",
        kind: BuiltinPresetKind::Membership,
        description: "Sidecar supply-chain hardening rules, including GitHub Actions workflow checks.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "advisory",
        kind: BuiltinPresetKind::Membership,
        description: "Offline dependency vulnerability checks that match installed lockfile versions against the active advisory snapshot.",
        extends: &[],
    },
    BuiltinPresetSpec {
        id: "strict",
        kind: BuiltinPresetKind::Overlay,
        description: "Severity overlay for active security rules; paired with the recommended default rather than activating rules by itself.",
        extends: &["recommended"],
    },
];

pub fn builtin_presets() -> &'static [BuiltinPresetSpec] {
    BUILTIN_PRESETS
}

pub fn builtin_preset_ids() -> Vec<&'static str> {
    builtin_presets().iter().map(|preset| preset.id).collect()
}

pub fn builtin_membership_preset_ids() -> Vec<&'static str> {
    builtin_presets()
        .iter()
        .filter(|preset| preset.kind == BuiltinPresetKind::Membership)
        .map(|preset| preset.id)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{BuiltinPresetKind, builtin_membership_preset_ids, builtin_presets};

    #[test]
    fn builtin_presets_have_unique_ids_and_known_overlay_shape() {
        let mut ids = BTreeSet::new();
        for preset in builtin_presets() {
            assert!(ids.insert(preset.id), "duplicate preset id {}", preset.id);
        }

        let strict = builtin_presets()
            .iter()
            .find(|preset| preset.id == "strict")
            .expect("strict preset should exist");
        assert_eq!(strict.kind, BuiltinPresetKind::Overlay);
        assert_eq!(strict.extends, &["recommended"]);
    }

    #[test]
    fn membership_preset_ids_exclude_overlay_presets() {
        let membership_ids = builtin_membership_preset_ids();
        assert!(membership_ids.contains(&"recommended"));
        assert!(membership_ids.contains(&"base"));
        assert!(membership_ids.contains(&"compat"));
        assert!(!membership_ids.contains(&"strict"));
    }
}
