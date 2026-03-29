use super::*;

pub fn build_inventory_snapshot(
    inventory_roots: &[InventoryRoot],
    inventory_stats: &InventoryStats,
    findings: &[Finding],
) -> InventorySnapshot {
    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    InventorySnapshot {
        schema_version: INVENTORY_SNAPSHOT_SCHEMA_VERSION,
        generated_at,
        inventory_roots: inventory_roots.to_vec(),
        inventory_stats: inventory_stats.clone(),
        findings: findings.to_vec(),
    }
}

pub fn write_inventory_snapshot(path: &Path, snapshot: &InventorySnapshot) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(snapshot)
        .map_err(|error| format!("failed to encode baseline snapshot: {error}"))?;
    fs::write(path, bytes)
        .map_err(|error| format!("failed to write baseline {}: {error}", path.display()))
}

pub fn load_inventory_snapshot(path: &Path) -> Result<InventorySnapshot, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read baseline {}: {error}", path.display()))?;
    let snapshot: InventorySnapshot = serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse baseline {}: {error}", path.display()))?;
    if snapshot.schema_version != INVENTORY_SNAPSHOT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported baseline schema_version {} in {} (expected {})",
            snapshot.schema_version,
            path.display(),
            INVENTORY_SNAPSHOT_SCHEMA_VERSION
        ));
    }
    Ok(snapshot)
}

pub fn diff_inventory_snapshots(
    baseline: &InventorySnapshot,
    current: &InventorySnapshot,
) -> InventoryDiff {
    let baseline_roots = baseline
        .inventory_roots
        .iter()
        .map(|root| (inventory_root_identity(root), root))
        .collect::<BTreeMap<_, _>>();
    let current_roots = current
        .inventory_roots
        .iter()
        .map(|root| (inventory_root_identity(root), root))
        .collect::<BTreeMap<_, _>>();

    let baseline_finding_keys = baseline
        .findings
        .iter()
        .map(finding_identity)
        .collect::<BTreeSet<_>>();
    let mut diff = InventoryDiff::default();

    for (key, current_root) in &current_roots {
        let Some(baseline_root) = baseline_roots.get(key) else {
            diff.new_roots.push((*current_root).clone());
            continue;
        };

        if baseline_root.mode != "lintable" && current_root.mode == "lintable" {
            diff.new_lintable_roots.push((*current_root).clone());
        }

        if risk_rank(&current_root.risk_level) > risk_rank(&baseline_root.risk_level) {
            diff.risk_increased_roots.push(InventoryRiskIncrease {
                client: current_root.client.clone(),
                surface: current_root.surface.clone(),
                path: current_root.path.clone(),
                old_risk_level: baseline_root.risk_level.clone(),
                new_risk_level: current_root.risk_level.clone(),
            });
        }

        if root_changed(baseline_root, current_root)
            || findings_for_root(baseline, baseline_root)
                != findings_for_root(current, current_root)
        {
            diff.changed_roots.push(InventoryChangedRoot {
                client: current_root.client.clone(),
                surface: current_root.surface.clone(),
                path: current_root.path.clone(),
                old_mode: baseline_root.mode.clone(),
                new_mode: current_root.mode.clone(),
                old_risk_level: baseline_root.risk_level.clone(),
                new_risk_level: current_root.risk_level.clone(),
                old_path_type: baseline_root.provenance.path_type.clone(),
                new_path_type: current_root.provenance.path_type.clone(),
                old_mtime_epoch_s: baseline_root.provenance.mtime_epoch_s,
                new_mtime_epoch_s: current_root.provenance.mtime_epoch_s,
            });
        }
    }

    for (key, baseline_root) in &baseline_roots {
        if !current_roots.contains_key(key) {
            diff.removed_roots.push((*baseline_root).clone());
        }
    }

    diff.new_findings = current
        .findings
        .iter()
        .filter(|finding| !baseline_finding_keys.contains(&finding_identity(finding)))
        .cloned()
        .collect();

    sort_inventory_diff(&mut diff);
    diff
}
pub(crate) fn inventory_origin_scope(scope: KnownRootScope) -> InventoryOriginScope {
    match scope {
        KnownRootScope::Project => InventoryOriginScope::Project,
        KnownRootScope::Global => InventoryOriginScope::User,
    }
}

pub(crate) fn path_type_for_path(path: &Path) -> InventoryPathType {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return InventoryPathType::Other,
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        InventoryPathType::Symlink
    } else if file_type.is_dir() {
        InventoryPathType::Directory
    } else if file_type.is_file() {
        InventoryPathType::File
    } else {
        InventoryPathType::Other
    }
}

pub(crate) fn target_path_for_symlink(path: &Path) -> Option<String> {
    let target = fs::read_link(path).ok()?;
    let resolved = if target.is_absolute() {
        target
    } else {
        path.parent().unwrap_or_else(|| Path::new("")).join(target)
    };
    Some(normalize_path_string(&resolved))
}

#[cfg(unix)]
pub(crate) fn owner_for_path(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path).ok()?;
    Some(metadata.uid().to_string())
}

#[cfg(not(unix))]
pub(crate) fn owner_for_path(_path: &Path) -> Option<String> {
    None
}

pub(crate) fn mtime_epoch_s_for_path(path: &Path) -> Option<u64> {
    let metadata = fs::symlink_metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

pub(crate) fn inventory_provenance_for_path(
    scope: KnownRootScope,
    path: &Path,
) -> InventoryProvenance {
    let path_type = path_type_for_path(path);
    InventoryProvenance {
        origin_scope: inventory_origin_scope(scope).as_str().to_owned(),
        path_type: path_type.as_str().to_owned(),
        target_path: if path_type == InventoryPathType::Symlink {
            target_path_for_symlink(path)
        } else {
            None
        },
        owner: owner_for_path(path),
        mtime_epoch_s: mtime_epoch_s_for_path(path),
    }
}

pub(crate) fn risk_level_for_root(root: &KnownRoot) -> RiskLevel {
    if matches!(root.mode, ArtifactMode::DiscoveredOnly) {
        return match root.surface.as_str() {
            "plugin-root" | "project-agents" | "global-agents" => RiskLevel::High,
            "config" | "config-yaml" | "settings" | "profiles" => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };
    }

    match root.artifact_kind_hint {
        Some(
            ArtifactKind::McpConfig
            | ArtifactKind::CursorHookScript
            | ArtifactKind::CursorPluginHooks,
        ) => RiskLevel::High,
        Some(
            ArtifactKind::Instructions
            | ArtifactKind::CursorRules
            | ArtifactKind::Skill
            | ArtifactKind::CursorPluginManifest
            | ArtifactKind::CursorPluginCommand
            | ArtifactKind::CursorPluginAgent,
        ) => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

pub(crate) fn inventory_root_identity(root: &InventoryRoot) -> String {
    format!("{}|{}|{}", root.client, root.surface, root.path)
}

pub(crate) fn root_changed(baseline: &InventoryRoot, current: &InventoryRoot) -> bool {
    baseline.mode != current.mode
        || baseline.risk_level != current.risk_level
        || baseline.provenance.path_type != current.provenance.path_type
        || baseline.provenance.mtime_epoch_s != current.provenance.mtime_epoch_s
}

pub(crate) fn root_contains_finding(root: &InventoryRoot, finding: &Finding) -> bool {
    let root_path = Path::new(&root.path);
    let finding_path = Path::new(&finding.location.normalized_path);
    match root.provenance.path_type.as_str() {
        "directory" => finding_path == root_path || finding_path.starts_with(root_path),
        _ => normalize_path_string(finding_path) == root.path,
    }
}

pub(crate) fn findings_for_root(
    snapshot: &InventorySnapshot,
    root: &InventoryRoot,
) -> BTreeSet<String> {
    snapshot
        .findings
        .iter()
        .filter(|finding| root_contains_finding(root, finding))
        .map(finding_identity)
        .collect()
}

pub(crate) fn finding_identity(finding: &Finding) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        finding.rule_code,
        finding.location.normalized_path,
        finding.location.span.start_byte,
        finding.location.span.end_byte,
        finding.stable_key.subject_id.as_deref().unwrap_or("")
    )
}

pub(crate) fn risk_rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

pub(crate) fn sort_inventory_diff(diff: &mut InventoryDiff) {
    diff.new_roots
        .sort_by(|left, right| inventory_root_identity(left).cmp(&inventory_root_identity(right)));
    diff.removed_roots
        .sort_by(|left, right| inventory_root_identity(left).cmp(&inventory_root_identity(right)));
    diff.new_lintable_roots
        .sort_by(|left, right| inventory_root_identity(left).cmp(&inventory_root_identity(right)));
    diff.changed_roots.sort_by(|left, right| {
        (&left.client, &left.surface, &left.path).cmp(&(&right.client, &right.surface, &right.path))
    });
    diff.risk_increased_roots.sort_by(|left, right| {
        (&left.client, &left.surface, &left.path).cmp(&(&right.client, &right.surface, &right.path))
    });
    diff.new_findings
        .sort_by(|left, right| finding_identity(left).cmp(&finding_identity(right)));
}
