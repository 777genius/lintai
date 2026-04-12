use super::*;
use crate::output::ColorMode;

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
    pub preset_ids: Vec<String>,
    pub color_mode: ColorMode,
}

#[derive(Clone, Debug)]
pub struct InventoryOsArgs {
    pub format_override: Option<lintai_engine::OutputFormat>,
    pub scope: InventoryOsScope,
    pub client_filters: BTreeSet<String>,
    pub preset_ids: Vec<String>,
    pub color_mode: ColorMode,
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
