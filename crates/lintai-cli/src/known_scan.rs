use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ignore::WalkBuilder;
use lintai_api::{ArtifactKind, Finding, SourceFormat};
use lintai_engine::{normalize_path_string, FileTypeDetector, ScanSummary, WorkspaceConfig};
use serde::{Deserialize, Serialize};

const KNOWN_ROOTS_MANIFEST: &str = include_str!("../known_roots.toml");
const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    "vendor",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownScope {
    Project,
    Global,
    Both,
}

impl KnownScope {
    pub fn includes_project(self) -> bool {
        matches!(self, Self::Project | Self::Both)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryOsScope {
    User,
    System,
    Both,
}

impl InventoryOsScope {
    pub fn includes_user(self) -> bool {
        matches!(self, Self::User | Self::Both)
    }

    pub fn includes_system(self) -> bool {
        matches!(self, Self::System | Self::Both)
    }
}

#[derive(Clone, Debug)]
pub struct ScanKnownArgs {
    pub format_override: Option<lintai_engine::OutputFormat>,
    pub scope: KnownScope,
    pub client_filters: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct InventoryOsArgs {
    pub format_override: Option<lintai_engine::OutputFormat>,
    pub scope: InventoryOsScope,
    pub client_filters: BTreeSet<String>,
    pub path_root: Option<PathBuf>,
    pub write_baseline: Option<PathBuf>,
    pub diff_against: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownRootScope {
    Project,
    Global,
}

impl KnownRootScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactMode {
    Lintable,
    DiscoveredOnly,
}

impl ArtifactMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lintable => "lintable",
            Self::DiscoveredOnly => "discovered_only",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiscoveredRoot {
    pub client: String,
    pub scope: String,
    pub surface: String,
    pub path: String,
    pub mode: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DiscoveryStats {
    pub lintable_roots: usize,
    pub discovered_only_roots: usize,
    pub supported_artifacts_scanned: usize,
    pub non_target_files_in_lintable_roots: usize,
    pub excluded_files: usize,
    pub binary_files: usize,
    pub unreadable_files: usize,
    pub unrecognized_files: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryOriginScope {
    Project,
    User,
    #[allow(dead_code)]
    System,
}

impl InventoryOriginScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::User => "user",
            Self::System => "system",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryPathType {
    File,
    Directory,
    Symlink,
    Other,
}

impl InventoryPathType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    High,
    Medium,
    Low,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryProvenance {
    pub origin_scope: String,
    pub path_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime_epoch_s: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryRoot {
    pub client: String,
    pub surface: String,
    pub path: String,
    pub mode: String,
    pub risk_level: String,
    pub provenance: InventoryProvenance,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryStats {
    pub user_roots: usize,
    pub system_roots: usize,
    pub lintable_roots: usize,
    pub discovered_only_roots: usize,
    pub high_risk_roots: usize,
    pub medium_risk_roots: usize,
    pub low_risk_roots: usize,
    pub supported_artifacts_scanned: usize,
    pub non_target_files_in_lintable_roots: usize,
    pub excluded_files: usize,
    pub binary_files: usize,
    pub unreadable_files: usize,
    pub unrecognized_files: usize,
}

pub const INVENTORY_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventorySnapshot {
    pub schema_version: u32,
    pub generated_at: u64,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub inventory_roots: Vec<InventoryRoot>,
    pub inventory_stats: InventoryStats,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct InventoryDiff {
    pub new_roots: Vec<InventoryRoot>,
    pub removed_roots: Vec<InventoryRoot>,
    pub changed_roots: Vec<InventoryChangedRoot>,
    pub new_lintable_roots: Vec<InventoryRoot>,
    pub risk_increased_roots: Vec<InventoryRiskIncrease>,
    pub new_findings: Vec<Finding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryChangedRoot {
    pub client: String,
    pub surface: String,
    pub path: String,
    pub old_mode: String,
    pub new_mode: String,
    pub old_risk_level: String,
    pub new_risk_level: String,
    pub old_path_type: String,
    pub new_path_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_mtime_epoch_s: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_mtime_epoch_s: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryRiskIncrease {
    pub client: String,
    pub surface: String,
    pub path: String,
    pub old_risk_level: String,
    pub new_risk_level: String,
}

impl InventoryStats {
    pub fn non_target_total(&self) -> usize {
        self.non_target_files_in_lintable_roots
            + self.excluded_files
            + self.binary_files
            + self.unreadable_files
    }

    pub fn record_root(&mut self, root: &KnownRoot) {
        match inventory_origin_scope(root.scope) {
            InventoryOriginScope::Project => {}
            InventoryOriginScope::User => self.user_roots += 1,
            InventoryOriginScope::System => self.system_roots += 1,
        }
        match root.mode {
            ArtifactMode::Lintable => self.lintable_roots += 1,
            ArtifactMode::DiscoveredOnly => self.discovered_only_roots += 1,
        }
        match risk_level_for_root(root) {
            RiskLevel::High => self.high_risk_roots += 1,
            RiskLevel::Medium => self.medium_risk_roots += 1,
            RiskLevel::Low => self.low_risk_roots += 1,
        }
    }

    pub fn record_lintable_inventory(&mut self, inventory: &LintableInventoryStats) {
        self.non_target_files_in_lintable_roots += inventory.unrecognized_files;
        self.excluded_files += inventory.excluded_files;
        self.binary_files += inventory.binary_files;
        self.unreadable_files += inventory.unreadable_files;
        self.unrecognized_files += inventory.unrecognized_files;
    }
}

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

impl DiscoveryStats {
    pub fn non_target_total(&self) -> usize {
        self.non_target_files_in_lintable_roots
            + self.excluded_files
            + self.binary_files
            + self.unreadable_files
    }

    pub fn record_root(&mut self, mode: ArtifactMode) {
        match mode {
            ArtifactMode::Lintable => self.lintable_roots += 1,
            ArtifactMode::DiscoveredOnly => self.discovered_only_roots += 1,
        }
    }

    pub fn record_lintable_inventory(&mut self, inventory: &LintableInventoryStats) {
        self.non_target_files_in_lintable_roots += inventory.unrecognized_files;
        self.excluded_files += inventory.excluded_files;
        self.binary_files += inventory.binary_files;
        self.unreadable_files += inventory.unreadable_files;
        self.unrecognized_files += inventory.unrecognized_files;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownRoot {
    pub client: String,
    pub scope: KnownRootScope,
    pub surface: String,
    pub path: PathBuf,
    pub mode: ArtifactMode,
    pub artifact_kind_hint: Option<ArtifactKind>,
    pub notes: Option<String>,
}

impl KnownRoot {
    pub fn to_report(&self) -> DiscoveredRoot {
        DiscoveredRoot {
            client: self.client.clone(),
            scope: self.scope.as_str().to_owned(),
            surface: self.surface.clone(),
            path: normalize_path_string(&self.path),
            mode: self.mode.as_str().to_owned(),
        }
    }

    pub fn to_inventory_report(&self) -> InventoryRoot {
        let provenance = inventory_provenance_for_path(self.scope, &self.path);
        InventoryRoot {
            client: self.client.clone(),
            surface: self.surface.clone(),
            path: normalize_path_string(&self.path),
            mode: self.mode.as_str().to_owned(),
            risk_level: risk_level_for_root(self).as_str().to_owned(),
            provenance,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LintableInventoryStats {
    pub excluded_files: usize,
    pub binary_files: usize,
    pub unreadable_files: usize,
    pub unrecognized_files: usize,
}

#[derive(Clone, Debug, Default)]
struct EnvironmentPaths {
    home_dir: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
}

impl EnvironmentPaths {
    fn from_process() -> Self {
        let home_dir = std::env::var_os("HOME").map(PathBuf::from);
        let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir.as_ref().map(|home| home.join(".config")));
        Self {
            home_dir,
            xdg_config_home,
        }
    }

    fn from_path_root(path_root: &Path) -> Self {
        Self {
            home_dir: Some(path_root.to_path_buf()),
            xdg_config_home: Some(path_root.join(".config")),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct KnownRootsManifest {
    #[serde(rename = "surface")]
    surfaces: Vec<KnownSurfaceSpec>,
}

#[derive(Clone, Debug, Deserialize)]
struct KnownSurfaceSpec {
    client_id: String,
    surface_id: String,
    scope: KnownRootScope,
    path_template: String,
    artifact_mode: ArtifactMode,
    artifact_kind_hint: Option<ArtifactKind>,
    notes: Option<String>,
}

#[derive(Clone, Debug)]
struct KnownRegistry {
    surfaces: Vec<KnownSurfaceSpec>,
}

static KNOWN_REGISTRY: OnceLock<Result<KnownRegistry, String>> = OnceLock::new();

pub(crate) fn discover_known_roots(
    project_root: Option<&Path>,
    scope: KnownScope,
    client_filters: &BTreeSet<String>,
) -> Result<Vec<KnownRoot>, String> {
    discover_known_roots_with_env(
        registry(),
        project_root,
        scope,
        client_filters,
        &EnvironmentPaths::from_process(),
    )
}

pub(crate) fn discover_inventory_roots(
    scope: InventoryOsScope,
    client_filters: &BTreeSet<String>,
    path_root: Option<&Path>,
) -> Result<Vec<KnownRoot>, String> {
    let env = match path_root {
        Some(path_root) => EnvironmentPaths::from_path_root(path_root),
        None => EnvironmentPaths::from_process(),
    };
    let mut roots = Vec::new();
    if scope.includes_user() {
        roots.extend(discover_known_roots_with_env(
            registry(),
            None,
            KnownScope::Global,
            client_filters,
            &env,
        )?);
    }
    if scope.includes_system() {
        roots.extend(discover_system_known_roots()?);
    }
    roots.sort_by(|left, right| {
        (
            left.client.as_str(),
            left.surface.as_str(),
            normalize_path_string(&left.path),
        )
            .cmp(&(
                right.client.as_str(),
                right.surface.as_str(),
                normalize_path_string(&right.path),
            ))
    });
    Ok(roots)
}

pub(crate) fn inventory_lintable_root(
    root: &KnownRoot,
    workspace: &WorkspaceConfig,
) -> Result<LintableInventoryStats, String> {
    let detector = FileTypeDetector::new(&workspace.engine_config);
    let base_path = absolute_base_for_scan(&root.path, workspace);
    let canonical_project_root = workspace
        .engine_config
        .project_root
        .as_deref()
        .map(std::fs::canonicalize)
        .transpose()
        .map_err(|error| format!("project root resolution failed: {error}"))?;

    let mut inventory = LintableInventoryStats::default();
    for entry in walk_root(
        &root.path,
        workspace.engine_config.follow_symlinks,
        canonical_project_root.as_deref(),
    ) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                inventory.unreadable_files += 1;
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let normalized_path = normalize_known_path(&base_path, path);
        let file_config = workspace.engine_config.resolve_for(&normalized_path);
        if !file_config.included {
            inventory.excluded_files += 1;
            continue;
        }

        if detector.detect(path, &normalized_path).is_none() {
            inventory.unrecognized_files += 1;
            continue;
        }

        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => {
                inventory.unreadable_files += 1;
                continue;
            }
        };
        if looks_binary(&bytes) {
            inventory.binary_files += 1;
            continue;
        }
        if String::from_utf8(bytes).is_err() {
            inventory.unreadable_files += 1;
        }
    }

    Ok(inventory)
}

pub(crate) fn workspace_for_known_root(
    root: &KnownRoot,
    base_workspace: &WorkspaceConfig,
) -> Result<WorkspaceConfig, String> {
    let mut workspace = base_workspace.clone();
    if matches!(root.scope, KnownRootScope::Global) {
        workspace
            .engine_config
            .set_project_root(Some(scan_root_base(root)));
    }

    let Some(artifact_kind) = root.artifact_kind_hint else {
        return Ok(workspace);
    };
    let (patterns, format) = match artifact_kind {
        ArtifactKind::McpConfig => (
            mcp_detection_override_patterns(root, &workspace)?,
            SourceFormat::Json,
        ),
        ArtifactKind::Instructions | ArtifactKind::CursorRules => (
            markdown_detection_override_patterns(root, &workspace),
            SourceFormat::Markdown,
        ),
        _ => return Ok(workspace),
    };
    if patterns.is_empty() {
        return Ok(workspace);
    }
    if matches!(
        artifact_kind,
        ArtifactKind::CursorRules | ArtifactKind::Instructions
    ) {
        workspace
            .engine_config
            .add_include_patterns(&patterns)
            .map_err(|error| format!("include override failed: {error}"))?;
    }

    workspace
        .engine_config
        .add_detection_override(&patterns, artifact_kind, format)
        .map_err(|error| format!("detection override failed: {error}"))?;
    Ok(workspace)
}

pub(crate) fn absolute_base_for_scan(target: &Path, workspace: &WorkspaceConfig) -> PathBuf {
    if let Some(project_root) = workspace.engine_config.project_root.as_ref() {
        return project_root.clone();
    }

    if target.is_file() {
        return target
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    }

    target.to_path_buf()
}

pub(crate) fn merge_summary_with_absolute_paths(
    aggregate: &mut ScanSummary,
    mut summary: ScanSummary,
    absolute_base: &Path,
) {
    rewrite_summary_paths(&mut summary, absolute_base);

    aggregate.scanned_files += summary.scanned_files;
    aggregate.skipped_files += summary.skipped_files;
    aggregate.findings.extend(summary.findings);
    aggregate.diagnostics.extend(summary.diagnostics);
    aggregate.runtime_errors.extend(summary.runtime_errors);
    aggregate.provider_metrics.extend(summary.provider_metrics);
}

fn registry() -> Result<&'static KnownRegistry, String> {
    match KNOWN_REGISTRY.get_or_init(|| registry_from_str(KNOWN_ROOTS_MANIFEST)) {
        Ok(registry) => Ok(registry),
        Err(error) => Err(error.clone()),
    }
}

fn registry_from_str(input: &str) -> Result<KnownRegistry, String> {
    let manifest: KnownRootsManifest = toml::from_str(input)
        .map_err(|error| format!("known roots manifest parse failed: {error}"))?;
    validate_manifest(&manifest)?;
    Ok(KnownRegistry {
        surfaces: manifest.surfaces,
    })
}

fn validate_manifest(manifest: &KnownRootsManifest) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for surface in &manifest.surfaces {
        if !ids.insert((
            surface.client_id.clone(),
            surface.surface_id.clone(),
            surface.scope,
        )) {
            return Err(format!(
                "known roots manifest duplicates ({}, {}, {:?})",
                surface.client_id, surface.surface_id, surface.scope
            ));
        }
        if !paths.insert((surface.scope, surface.path_template.clone())) {
            return Err(format!(
                "known roots manifest duplicates scope/path ({:?}, {})",
                surface.scope, surface.path_template
            ));
        }

        let has_hint = surface.artifact_kind_hint.is_some();
        match surface.artifact_mode {
            ArtifactMode::Lintable if !has_hint => {
                return Err(format!(
                    "lintable surface {}:{} is missing artifact_kind_hint",
                    surface.client_id, surface.surface_id
                ));
            }
            ArtifactMode::DiscoveredOnly if has_hint => {
                return Err(format!(
                    "discovered-only surface {}:{} must not declare artifact_kind_hint",
                    surface.client_id, surface.surface_id
                ));
            }
            _ => {}
        }

        validate_path_template(&surface.path_template).map_err(|error| {
            format!(
                "invalid path_template for {}:{}: {error}",
                surface.client_id, surface.surface_id
            )
        })?;
    }

    Ok(())
}

fn validate_path_template(template: &str) -> Result<(), String> {
    let valid_prefixes = ["{project_root}", "{home}", "{xdg_config_home}", "/"];
    if !valid_prefixes
        .iter()
        .any(|prefix| template.starts_with(prefix))
    {
        return Err("must start with {project_root}, {home}, {xdg_config_home}, or /".to_owned());
    }

    for placeholder in ["{project_root}", "{home}", "{xdg_config_home}"] {
        if template.starts_with(placeholder) {
            let suffix = &template[placeholder.len()..];
            if suffix.contains('{') || suffix.contains('}') {
                return Err("path_template may only contain one leading placeholder".to_owned());
            }
            return Ok(());
        }
    }

    if template.contains('{') || template.contains('}') {
        return Err("path_template contains unmatched braces".to_owned());
    }

    Ok(())
}

fn discover_known_roots_with_env(
    registry: Result<&KnownRegistry, String>,
    project_root: Option<&Path>,
    scope: KnownScope,
    client_filters: &BTreeSet<String>,
    env: &EnvironmentPaths,
) -> Result<Vec<KnownRoot>, String> {
    let registry = registry?;
    let mut by_path = BTreeMap::<String, KnownRoot>::new();

    for surface in &registry.surfaces {
        if !scope_matches(scope, surface.scope) {
            continue;
        }
        if !client_filters.is_empty() && !client_filters.contains(surface.client_id.as_str()) {
            continue;
        }

        let Some(candidate) = resolve_path_template(&surface.path_template, project_root, env)
        else {
            continue;
        };
        if !candidate.exists() {
            continue;
        }

        let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate.clone());
        let key = normalize_path_string(&canonical);
        match by_path.get(&key) {
            Some(existing) if !should_replace_known_root(existing.mode, surface.artifact_mode) => {}
            _ => {
                by_path.insert(
                    key,
                    KnownRoot {
                        client: surface.client_id.clone(),
                        scope: surface.scope,
                        surface: surface.surface_id.clone(),
                        path: canonical,
                        mode: surface.artifact_mode,
                        artifact_kind_hint: surface.artifact_kind_hint,
                        notes: surface.notes.clone(),
                    },
                );
            }
        }
    }

    Ok(by_path.into_values().collect())
}

fn should_replace_known_root(existing: ArtifactMode, candidate: ArtifactMode) -> bool {
    matches!(
        (existing, candidate),
        (ArtifactMode::DiscoveredOnly, ArtifactMode::Lintable)
    )
}

fn discover_system_known_roots() -> Result<Vec<KnownRoot>, String> {
    registry()?;
    Ok(Vec::new())
}

fn resolve_path_template(
    template: &str,
    project_root: Option<&Path>,
    env: &EnvironmentPaths,
) -> Option<PathBuf> {
    if let Some(suffix) = template.strip_prefix("{project_root}") {
        return Some(join_template_suffix(project_root?, suffix));
    }
    if let Some(suffix) = template.strip_prefix("{home}") {
        return Some(join_template_suffix(env.home_dir.as_deref()?, suffix));
    }
    if let Some(suffix) = template.strip_prefix("{xdg_config_home}") {
        return Some(join_template_suffix(
            env.xdg_config_home.as_deref()?,
            suffix,
        ));
    }
    Some(PathBuf::from(template))
}

fn join_template_suffix(base: &Path, suffix: &str) -> PathBuf {
    let mut resolved = base.to_path_buf();
    for component in suffix.trim_start_matches('/').split('/') {
        if component.is_empty() {
            continue;
        }
        resolved.push(component);
    }
    resolved
}

fn scope_matches(filter: KnownScope, scope: KnownRootScope) -> bool {
    match filter {
        KnownScope::Project => scope == KnownRootScope::Project,
        KnownScope::Global => scope == KnownRootScope::Global,
        KnownScope::Both => true,
    }
}

fn normalize_known_path(base_path: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(base_path).unwrap_or(path);
    normalize_path_string(relative)
}

fn scan_root_base(root: &KnownRoot) -> PathBuf {
    if root.path.is_file() {
        return root
            .path
            .parent()
            .map_or_else(|| root.path.clone(), Path::to_path_buf);
    }
    root.path
        .parent()
        .map_or_else(|| root.path.clone(), Path::to_path_buf)
}

fn mcp_detection_override_patterns(
    root: &KnownRoot,
    workspace: &WorkspaceConfig,
) -> Result<Vec<String>, String> {
    let Some(base_path) = workspace.engine_config.project_root.as_deref() else {
        return Ok(Vec::new());
    };
    let detector = FileTypeDetector::new(&workspace.engine_config);
    let mut patterns = BTreeSet::new();

    for path in mcp_candidate_files(root, workspace)? {
        let normalized_path = normalize_known_path(base_path, &path);
        if detector.detect(&path, &normalized_path).is_some() {
            continue;
        }
        if !is_mcp_like_json_file(&path)? {
            continue;
        }
        patterns.insert(normalized_path);
    }

    Ok(patterns.into_iter().collect())
}

fn markdown_detection_override_patterns(
    root: &KnownRoot,
    workspace: &WorkspaceConfig,
) -> Vec<String> {
    let Some(base_path) = workspace.engine_config.project_root.as_deref() else {
        return Vec::new();
    };
    let detector = FileTypeDetector::new(&workspace.engine_config);
    let mut patterns = BTreeSet::new();

    if root.path.is_file() {
        let normalized_path = normalize_known_path(base_path, &root.path);
        if detector.detect(&root.path, &normalized_path).is_none() {
            patterns.insert(normalized_path);
        }
        return patterns.into_iter().collect();
    }

    let canonical_project_root = workspace
        .engine_config
        .project_root
        .as_deref()
        .and_then(|project_root| std::fs::canonicalize(project_root).ok());
    for entry in walk_root(
        &root.path,
        workspace.engine_config.follow_symlinks,
        canonical_project_root.as_deref(),
    ) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
        {
            continue;
        }

        let normalized_path = normalize_known_path(base_path, path);
        if detector.detect(path, &normalized_path).is_some() {
            continue;
        }
        patterns.insert(normalized_path);
    }

    patterns.into_iter().collect()
}

fn mcp_candidate_files(
    root: &KnownRoot,
    workspace: &WorkspaceConfig,
) -> Result<Vec<PathBuf>, String> {
    if root.path.is_file() {
        return Ok(vec![root.path.clone()]);
    }

    let canonical_project_root = workspace
        .engine_config
        .project_root
        .as_deref()
        .map(std::fs::canonicalize)
        .transpose()
        .map_err(|error| format!("project root resolution failed: {error}"))?;
    let mut candidates = Vec::new();
    for entry in walk_root(
        &root.path,
        workspace.engine_config.follow_symlinks,
        canonical_project_root.as_deref(),
    ) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            candidates.push(path.to_path_buf());
        }
    }
    Ok(candidates)
}

fn is_mcp_like_json_file(path: &Path) -> Result<bool, String> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return Ok(false),
    };
    let value = match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    Ok(matches_mcp_like_json_value(&value))
}

fn matches_mcp_like_json_value(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.keys().any(|key| is_mcp_like_top_level_key(key))
}

fn is_mcp_like_top_level_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("mcpServers")
        || key.eq_ignore_ascii_case("mcpservers")
        || key.eq_ignore_ascii_case("servers")
        || key.eq_ignore_ascii_case("command")
        || key.eq_ignore_ascii_case("args")
        || key.eq_ignore_ascii_case("env")
        || key.eq_ignore_ascii_case("url")
        || key.eq_ignore_ascii_case("headers")
        || key.eq_ignore_ascii_case("transport")
        || key.eq_ignore_ascii_case("type")
        || key.eq_ignore_ascii_case("cwd")
}

fn walk_root<'a>(
    root: &'a Path,
    follow_symlinks: bool,
    canonical_project_root: Option<&'a Path>,
) -> ignore::Walk {
    let mut walker = WalkBuilder::new(root);
    walker.hidden(false);
    walker.follow_links(follow_symlinks);
    walker.git_ignore(true);
    walker.git_global(true);
    walker.git_exclude(true);
    if let Some(project_root) = canonical_project_root {
        let project_root = project_root.to_path_buf();
        walker.filter_entry(move |entry| {
            should_visit_path(entry.path(), Some(project_root.as_path()))
        });
    } else {
        walker.filter_entry(|entry| should_visit_path(entry.path(), None));
    }
    walker.build()
}

fn should_skip_path(path: &Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        DEFAULT_EXCLUDED_DIRS.contains(&value.as_ref())
    })
}

fn should_visit_path(path: &Path, project_root: Option<&Path>) -> bool {
    if should_skip_path(path) {
        return false;
    }

    let Some(project_root) = project_root else {
        return true;
    };

    match std::fs::canonicalize(path) {
        Ok(canonical_path) => {
            canonical_path == project_root || canonical_path.starts_with(project_root)
        }
        Err(_) => true,
    }
}

fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(1024).any(|byte| *byte == 0)
}

fn inventory_origin_scope(scope: KnownRootScope) -> InventoryOriginScope {
    match scope {
        KnownRootScope::Project => InventoryOriginScope::Project,
        KnownRootScope::Global => InventoryOriginScope::User,
    }
}

fn path_type_for_path(path: &Path) -> InventoryPathType {
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

fn target_path_for_symlink(path: &Path) -> Option<String> {
    let target = fs::read_link(path).ok()?;
    let resolved = if target.is_absolute() {
        target
    } else {
        path.parent().unwrap_or_else(|| Path::new("")).join(target)
    };
    Some(normalize_path_string(&resolved))
}

#[cfg(unix)]
fn owner_for_path(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path).ok()?;
    Some(metadata.uid().to_string())
}

#[cfg(not(unix))]
fn owner_for_path(_path: &Path) -> Option<String> {
    None
}

fn mtime_epoch_s_for_path(path: &Path) -> Option<u64> {
    let metadata = fs::symlink_metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn inventory_provenance_for_path(scope: KnownRootScope, path: &Path) -> InventoryProvenance {
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

fn risk_level_for_root(root: &KnownRoot) -> RiskLevel {
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

fn inventory_root_identity(root: &InventoryRoot) -> String {
    format!("{}|{}|{}", root.client, root.surface, root.path)
}

fn root_changed(baseline: &InventoryRoot, current: &InventoryRoot) -> bool {
    baseline.mode != current.mode
        || baseline.risk_level != current.risk_level
        || baseline.provenance.path_type != current.provenance.path_type
        || baseline.provenance.mtime_epoch_s != current.provenance.mtime_epoch_s
}

fn root_contains_finding(root: &InventoryRoot, finding: &Finding) -> bool {
    let root_path = Path::new(&root.path);
    let finding_path = Path::new(&finding.location.normalized_path);
    match root.provenance.path_type.as_str() {
        "directory" => finding_path == root_path || finding_path.starts_with(root_path),
        _ => normalize_path_string(finding_path) == root.path,
    }
}

fn findings_for_root(snapshot: &InventorySnapshot, root: &InventoryRoot) -> BTreeSet<String> {
    snapshot
        .findings
        .iter()
        .filter(|finding| root_contains_finding(root, finding))
        .map(finding_identity)
        .collect()
}

fn finding_identity(finding: &Finding) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        finding.rule_code,
        finding.location.normalized_path,
        finding.location.span.start_byte,
        finding.location.span.end_byte,
        finding.stable_key.subject_id.as_deref().unwrap_or("")
    )
}

fn risk_rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn sort_inventory_diff(diff: &mut InventoryDiff) {
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

fn rewrite_summary_paths(summary: &mut ScanSummary, absolute_base: &Path) {
    for finding in &mut summary.findings {
        rewrite_finding_paths(finding, absolute_base);
    }
    for diagnostic in &mut summary.diagnostics {
        diagnostic.normalized_path = absolutize_path(absolute_base, &diagnostic.normalized_path);
    }
    for error in &mut summary.runtime_errors {
        error.normalized_path = absolutize_path(absolute_base, &error.normalized_path);
    }
    for metric in &mut summary.provider_metrics {
        metric.normalized_path = absolutize_path(absolute_base, &metric.normalized_path);
    }
}

fn rewrite_finding_paths(finding: &mut Finding, absolute_base: &Path) {
    let location_path = absolutize_path(absolute_base, &finding.location.normalized_path);
    finding.location.normalized_path = location_path.clone();
    finding.stable_key.normalized_path = location_path;

    for evidence in &mut finding.evidence {
        if let Some(location) = &mut evidence.location {
            location.normalized_path = absolutize_path(absolute_base, &location.normalized_path);
        }
    }

    for related in &mut finding.related {
        related.normalized_path = absolutize_path(absolute_base, &related.normalized_path);
    }
}

fn absolutize_path(absolute_base: &Path, normalized_path: &str) -> String {
    normalize_path_string(&absolute_base.join(normalized_path))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use lintai_api::{
        Category, Confidence, Evidence, EvidenceKind, Location, RuleTier, Severity, Span,
    };
    use lintai_engine::{
        ProviderExecutionMetric, ProviderExecutionPhase, RuntimeErrorKind, ScanDiagnostic,
        ScanRuntimeError,
    };

    use super::*;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{suffix}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn manifest_requires_kind_hint_for_lintable_surface() {
        let error = registry_from_str(
            r#"
[[surface]]
client_id = "cursor"
surface_id = "skills"
scope = "project"
path_template = "{project_root}/.cursor/skills"
artifact_mode = "lintable"
"#,
        )
        .unwrap_err();
        assert!(error.contains("missing artifact_kind_hint"));
    }

    #[test]
    fn manifest_rejects_duplicate_scope_path_pairs() {
        let error = registry_from_str(
            r#"
[[surface]]
client_id = "cursor"
surface_id = "skills"
scope = "project"
path_template = "{project_root}/.cursor/skills"
artifact_mode = "lintable"
artifact_kind_hint = "skill"

[[surface]]
client_id = "codex"
surface_id = "same"
scope = "project"
path_template = "{project_root}/.cursor/skills"
artifact_mode = "lintable"
artifact_kind_hint = "skill"
"#,
        )
        .unwrap_err();
        assert!(error.contains("duplicates scope/path"));
    }

    #[test]
    fn discover_known_roots_respects_scope_filters_and_existing_paths() {
        let temp_dir = unique_temp_dir("lintai-known-roots");
        let project_root = temp_dir.join("project");
        let home_dir = temp_dir.join("home");
        let xdg_dir = temp_dir.join("xdg");
        fs::create_dir_all(project_root.join(".agents/skills/demo")).unwrap();
        fs::create_dir_all(home_dir.join(".cursor/skills/demo")).unwrap();
        fs::create_dir_all(xdg_dir.join("opencode/skills/demo")).unwrap();

        let env = EnvironmentPaths {
            home_dir: Some(home_dir),
            xdg_config_home: Some(xdg_dir),
        };
        let filters = ["codex", "opencode"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let roots = discover_known_roots_with_env(
            Ok(registry().unwrap()),
            Some(&project_root),
            KnownScope::Both,
            &filters,
            &env,
        )
        .unwrap();

        assert_eq!(roots.len(), 2);
        assert!(roots
            .iter()
            .any(|root| root.client == "codex" && root.scope == KnownRootScope::Project));
        assert!(roots
            .iter()
            .any(|root| root.client == "opencode" && root.scope == KnownRootScope::Global));
    }

    #[test]
    fn inventory_lintable_root_splits_unrecognized_binary_and_excluded_files() {
        let temp_dir = unique_temp_dir("lintai-known-root-inventory");
        fs::create_dir_all(temp_dir.join(".agents/skills/demo/scripts")).unwrap();
        fs::create_dir_all(temp_dir.join(".agents/skills/demo/assets")).unwrap();
        fs::write(temp_dir.join(".agents/skills/demo/SKILL.md"), "# Demo\n").unwrap();
        fs::write(
            temp_dir.join(".agents/skills/demo/scripts/helper.sh"),
            "#!/bin/sh\necho hi\n",
        )
        .unwrap();
        fs::write(
            temp_dir.join(".agents/skills/demo/assets/logo.png"),
            [0u8, 159, 146, 150],
        )
        .unwrap();
        fs::write(
            temp_dir.join(".agents/skills/demo/license.txt"),
            "license\n",
        )
        .unwrap();

        let root = KnownRoot {
            client: "codex".to_owned(),
            scope: KnownRootScope::Project,
            surface: "skills".to_owned(),
            path: temp_dir.join(".agents/skills"),
            mode: ArtifactMode::Lintable,
            artifact_kind_hint: Some(ArtifactKind::Skill),
            notes: None,
        };
        let workspace = WorkspaceConfig {
            source_path: None,
            engine_config: lintai_engine::EngineConfig::default(),
        };

        let inventory = inventory_lintable_root(&root, &workspace).unwrap();
        assert_eq!(inventory.unrecognized_files, 1);
        assert_eq!(inventory.binary_files, 0);
        assert_eq!(inventory.unreadable_files, 0);
        assert_eq!(inventory.excluded_files, 2);
    }

    #[test]
    fn merge_summary_rewrites_paths_to_absolute_locations() {
        let base = PathBuf::from("/tmp/demo");
        let metadata = lintai_api::RuleMetadata::new(
            "SEC999",
            "demo",
            Category::Security,
            Severity::Warn,
            Confidence::High,
            RuleTier::Stable,
        );
        let mut finding = Finding::new(
            &metadata,
            Location::new("skills/demo/SKILL.md", Span::new(0, 4)),
            "demo finding",
        );
        finding.evidence.push(Evidence::new(
            EvidenceKind::ObservedBehavior,
            "evidence",
            Some(Location::new("skills/demo/SKILL.md", Span::new(0, 4))),
        ));
        finding.related.push(lintai_api::RelatedFinding::new(
            "SEC998",
            "skills/demo/SKILL.md",
            Span::new(1, 2),
        ));

        let summary = ScanSummary {
            scanned_files: 1,
            skipped_files: 0,
            findings: vec![finding],
            diagnostics: vec![ScanDiagnostic {
                normalized_path: "mcp.json".to_owned(),
                severity: lintai_engine::DiagnosticSeverity::Warn,
                code: Some("demo".to_owned()),
                message: "diag".to_owned(),
            }],
            runtime_errors: vec![ScanRuntimeError {
                normalized_path: "mcp.json".to_owned(),
                kind: RuntimeErrorKind::Read,
                provider_id: None,
                phase: None,
                message: "err".to_owned(),
            }],
            provider_metrics: vec![ProviderExecutionMetric {
                normalized_path: "mcp.json".to_owned(),
                provider_id: "provider".to_owned(),
                phase: ProviderExecutionPhase::File,
                elapsed_us: 10,
                findings_emitted: 1,
                errors_emitted: 0,
            }],
        };

        let mut aggregate = ScanSummary::default();
        merge_summary_with_absolute_paths(&mut aggregate, summary, &base);

        assert_eq!(
            aggregate.findings[0].location.normalized_path,
            "/tmp/demo/skills/demo/SKILL.md"
        );
        assert_eq!(
            aggregate.findings[0].stable_key.normalized_path,
            "/tmp/demo/skills/demo/SKILL.md"
        );
        assert_eq!(
            aggregate.findings[0].evidence[1]
                .location
                .as_ref()
                .unwrap()
                .normalized_path,
            "/tmp/demo/skills/demo/SKILL.md"
        );
        assert_eq!(
            aggregate.findings[0].related[0].normalized_path,
            "/tmp/demo/skills/demo/SKILL.md"
        );
        assert_eq!(
            aggregate.diagnostics[0].normalized_path,
            "/tmp/demo/mcp.json"
        );
        assert_eq!(
            aggregate.runtime_errors[0].normalized_path,
            "/tmp/demo/mcp.json"
        );
        assert_eq!(
            aggregate.provider_metrics[0].normalized_path,
            "/tmp/demo/mcp.json"
        );
    }
}
