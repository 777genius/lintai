use std::path::{Path, PathBuf};

use super::*;
use crate::internal_bin::{
    BinaryResolutionSource, ResolvedBinary, resolve_lintai_driver_path_with_source,
};

#[derive(Clone, Debug)]
pub(crate) struct LaneScanArtifact {
    pub(crate) lane_id: String,
    pub(crate) text: String,
    pub(crate) parsed: JsonScanEnvelope,
}

pub(crate) trait ExternalValidationWorkspacePort {
    fn workspace_root(&self) -> Result<PathBuf, String>;
    fn load_shortlist(
        &self,
        workspace_root: &Path,
        package: ValidationPackage,
    ) -> Result<RepoShortlist, String>;
    fn load_ledger(&self, path: &Path) -> Result<ExternalValidationLedger, String>;
    fn ensure_dir(&self, path: &Path, label: &str) -> Result<(), String>;
    fn materialize_repo(&self, repo: &ShortlistRepo, local_dir: &Path) -> Result<(), String>;
    fn verify_repo_admission(
        &self,
        package: ValidationPackage,
        repo: &ShortlistRepo,
        repo_root: &Path,
    ) -> Result<(), String>;
    fn inventory_surfaces(&self, repo_root: &Path) -> Result<InventoryArtifact, String>;
    fn write_scan_artifacts(
        &self,
        repo_raw_root: &Path,
        lane_artifacts: &[LaneScanArtifact],
    ) -> Result<(), String>;
    fn write_inventory_artifact(
        &self,
        repo_raw_root: &Path,
        inventory: &InventoryArtifact,
    ) -> Result<(), String>;
    fn write_candidate_ledger(
        &self,
        path: &Path,
        ledger: &ExternalValidationLedger,
    ) -> Result<(), String>;
}

pub(crate) trait ExternalValidationScanPort {
    fn resolve_rerun_lintai_driver(
        &self,
        workspace_root: &Path,
        lintai_bin: Option<&Path>,
    ) -> Result<ResolvedBinary, String>;

    fn collect_lane_artifacts(
        &self,
        lintai_bin: &Path,
        repo_dir: &Path,
        preset_matrix: &[&str],
    ) -> Result<Vec<LaneScanArtifact>, String>;
}

pub(crate) struct FilesystemValidationWorkspace;

impl ExternalValidationWorkspacePort for FilesystemValidationWorkspace {
    fn workspace_root(&self) -> Result<PathBuf, String> {
        workspace_root()
    }

    fn load_shortlist(
        &self,
        workspace_root: &Path,
        package: ValidationPackage,
    ) -> Result<RepoShortlist, String> {
        load_shortlist(workspace_root, package)
    }

    fn load_ledger(&self, path: &Path) -> Result<ExternalValidationLedger, String> {
        load_ledger(path)
    }

    fn ensure_dir(&self, path: &Path, label: &str) -> Result<(), String> {
        fs::create_dir_all(path)
            .map_err(|error| format!("failed to create {label} {}: {error}", path.display()))
    }

    fn materialize_repo(&self, repo: &ShortlistRepo, local_dir: &Path) -> Result<(), String> {
        materialize_repo(repo, local_dir)
    }

    fn verify_repo_admission(
        &self,
        package: ValidationPackage,
        repo: &ShortlistRepo,
        repo_root: &Path,
    ) -> Result<(), String> {
        verify_repo_admission(package, repo, repo_root)
    }

    fn inventory_surfaces(&self, repo_root: &Path) -> Result<InventoryArtifact, String> {
        inventory_surfaces(repo_root)
    }

    fn write_scan_artifacts(
        &self,
        repo_raw_root: &Path,
        lane_artifacts: &[LaneScanArtifact],
    ) -> Result<(), String> {
        write_scan_artifacts(repo_raw_root, lane_artifacts)
    }

    fn write_inventory_artifact(
        &self,
        repo_raw_root: &Path,
        inventory: &InventoryArtifact,
    ) -> Result<(), String> {
        let inventory_text = toml::to_string_pretty(inventory)
            .map_err(|error| format!("failed to serialize inventory artifact: {error}"))?;
        fs::write(repo_raw_root.join("inventory.toml"), inventory_text)
            .map_err(|error| format!("failed to write inventory artifact: {error}"))
    }

    fn write_candidate_ledger(
        &self,
        path: &Path,
        ledger: &ExternalValidationLedger,
    ) -> Result<(), String> {
        let text = toml::to_string_pretty(ledger)
            .map_err(|error| format!("failed to serialize candidate ledger: {error}"))?;
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| "candidate ledger path should have a parent".to_owned())?,
        )
        .map_err(|error| format!("failed to create candidate ledger directory: {error}"))?;
        fs::write(path, text).map_err(|error| format!("failed to write candidate ledger: {error}"))
    }
}

pub(crate) struct ProcessValidationScanner;

impl ExternalValidationScanPort for ProcessValidationScanner {
    fn resolve_rerun_lintai_driver(
        &self,
        workspace_root: &Path,
        lintai_bin: Option<&Path>,
    ) -> Result<ResolvedBinary, String> {
        resolve_rerun_lintai_driver(workspace_root, lintai_bin)
    }

    fn collect_lane_artifacts(
        &self,
        lintai_bin: &Path,
        repo_dir: &Path,
        preset_matrix: &[&str],
    ) -> Result<Vec<LaneScanArtifact>, String> {
        collect_lane_artifacts(lintai_bin, repo_dir, preset_matrix)
    }
}

// Application layer for external validation. It owns orchestration while ports keep
// filesystem and process behavior at the edges.
pub(crate) struct ExternalValidationApplication<W, S> {
    workspace: W,
    scanner: S,
}

impl<W, S> ExternalValidationApplication<W, S> {
    pub(crate) fn new(workspace: W, scanner: S) -> Self {
        Self { workspace, scanner }
    }
}

impl<W, S> ExternalValidationApplication<W, S>
where
    W: ExternalValidationWorkspacePort,
    S: ExternalValidationScanPort,
{
    pub(crate) fn rerun(&self, options: RerunOptions) -> Result<(), String> {
        let workspace_root = self.workspace.workspace_root()?;
        let package = options.package;
        let shortlist = self.workspace.load_shortlist(&workspace_root, package)?;
        let template = self
            .workspace
            .load_ledger(&workspace_root.join(package.ledger_path()))?;
        let repo_root = workspace_root.join("target/external-validation/repos");
        let raw_root = workspace_root.join(package.raw_output_root());
        self.workspace.ensure_dir(&repo_root, "repo cache root")?;
        self.workspace.ensure_dir(&raw_root, "raw output root")?;

        let lintai_driver = self
            .scanner
            .resolve_rerun_lintai_driver(&workspace_root, options.lintai_bin.as_deref())?;
        let tier_map = current_rule_tiers();
        let template_entries = template_map(&template);
        let preset_matrix = package.scan_preset_matrix();

        let mut candidate = ExternalValidationLedger {
            version: 1,
            wave: package.default_wave(),
            baseline: package.baseline_reference().map(str::to_owned),
            evaluations: Vec::new(),
        };

        for repo in &shortlist.repos {
            let local_dir = repo_root.join(repo_dir_name(&repo.repo));
            self.workspace.materialize_repo(repo, &local_dir)?;
            self.workspace
                .verify_repo_admission(package, repo, &local_dir)?;
            let inventory = self.workspace.inventory_surfaces(&local_dir)?;
            let repo_raw_root = raw_root.join(repo_dir_name(&repo.repo));
            self.workspace
                .ensure_dir(&repo_raw_root, "raw output dir")?;

            let lane_artifacts = self.scanner.collect_lane_artifacts(
                &lintai_driver.path,
                &local_dir,
                preset_matrix,
            )?;
            self.workspace
                .write_scan_artifacts(&repo_raw_root, &lane_artifacts)?;
            self.workspace
                .write_inventory_artifact(&repo_raw_root, &inventory)?;

            let mut entry = template_entries
                .get(&repo.repo)
                .cloned()
                .unwrap_or_else(|| default_entry_from_shortlist(repo));
            let parsed_lanes = lane_artifacts
                .iter()
                .map(|artifact| ParsedLaneScan {
                    lane_id: artifact.lane_id.as_str(),
                    parsed: &artifact.parsed,
                })
                .collect::<Vec<_>>();
            fill_auto_fields(
                &mut entry,
                repo,
                inventory.surfaces_present.clone(),
                &parsed_lanes,
                &tier_map,
            )?;
            candidate.evaluations.push(entry);
        }

        self.workspace.write_candidate_ledger(
            &workspace_root.join(package.candidate_ledger_path()),
            &candidate,
        )?;

        Ok(())
    }

    pub(crate) fn render_report(&self, options: RenderReportOptions) -> Result<String, String> {
        let workspace_root = self.workspace.workspace_root()?;
        match options.package {
            ValidationPackage::Canonical => {
                let baseline = self
                    .workspace
                    .load_ledger(&workspace_root.join(ARCHIVED_WAVE2_LEDGER_PATH))?;
                let current = self
                    .workspace
                    .load_ledger(&workspace_root.join(LEDGER_PATH))?;
                validate_canonical_precision_contract(&current)?;
                Ok(render_report_from_ledgers(
                    &workspace_root,
                    &baseline,
                    &current,
                ))
            }
            ValidationPackage::ToolJsonExtension => {
                let shortlist = self
                    .workspace
                    .load_shortlist(&workspace_root, options.package)?;
                let baseline = self.workspace.load_ledger(
                    &workspace_root.join(TOOL_JSON_EXTENSION_ARCHIVED_WAVE3_LEDGER_PATH),
                )?;
                let current = self
                    .workspace
                    .load_ledger(&workspace_root.join(options.package.ledger_path()))?;
                Ok(render_tool_json_extension_report(
                    &shortlist, &baseline, &current,
                ))
            }
            ValidationPackage::ServerJsonExtension => {
                let shortlist = self
                    .workspace
                    .load_shortlist(&workspace_root, options.package)?;
                let baseline = self.workspace.load_ledger(
                    &workspace_root.join(SERVER_JSON_EXTENSION_ARCHIVED_WAVE1_LEDGER_PATH),
                )?;
                let current = self
                    .workspace
                    .load_ledger(&workspace_root.join(options.package.ledger_path()))?;
                Ok(render_server_json_extension_report(
                    &shortlist, &baseline, &current,
                ))
            }
            ValidationPackage::GithubActionsExtension => {
                let shortlist = self
                    .workspace
                    .load_shortlist(&workspace_root, options.package)?;
                let current = self
                    .workspace
                    .load_ledger(&workspace_root.join(options.package.ledger_path()))?;
                Ok(render_github_actions_extension_report(&shortlist, &current))
            }
            ValidationPackage::AiNativeDiscovery => {
                let shortlist = self
                    .workspace
                    .load_shortlist(&workspace_root, options.package)?;
                let current = self
                    .workspace
                    .load_ledger(&workspace_root.join(options.package.ledger_path()))?;
                Ok(render_ai_native_discovery_report(
                    &workspace_root,
                    &shortlist,
                    &current,
                ))
            }
        }
    }
}

pub(crate) fn default_external_validation_application()
-> ExternalValidationApplication<FilesystemValidationWorkspace, ProcessValidationScanner> {
    ExternalValidationApplication::new(FilesystemValidationWorkspace, ProcessValidationScanner)
}

fn resolve_rerun_lintai_driver(
    workspace_root: &Path,
    lintai_bin: Option<&Path>,
) -> Result<ResolvedBinary, String> {
    let resolved = if let Some(path) = lintai_bin {
        if !path.exists() {
            return Err(format!(
                "external validation rerun received --lintai-bin={}, but that path does not exist",
                path.display()
            ));
        }
        ResolvedBinary {
            path: path.to_path_buf(),
            source: BinaryResolutionSource::PreferredEnv,
        }
    } else {
        resolve_lintai_driver_path_with_source().map_err(|error| {
            format!("failed to resolve lintai binary for external validation rerun: {error}")
        })?
    };

    validate_rerun_driver_contract(workspace_root, &resolved)?;
    Ok(resolved)
}

fn validate_rerun_driver_contract(
    workspace_root: &Path,
    lintai_driver: &ResolvedBinary,
) -> Result<(), String> {
    let current = std::env::current_exe()
        .map_err(|error| format!("failed to resolve current executable: {error}"))?;
    if requires_explicit_rerun_driver(workspace_root, &current, lintai_driver.source) {
        return Err(format!(
            "external validation rerun refuses implicit sibling driver resolution from {}; pass --lintai-bin=/absolute/path/to/lintai or set LINTAI_SELF_EXE to avoid stale scan evidence",
            lintai_driver.path.display()
        ));
    }
    Ok(())
}

pub(crate) fn requires_explicit_rerun_driver(
    workspace_root: &Path,
    current_exe: &Path,
    source: BinaryResolutionSource,
) -> bool {
    matches!(source, BinaryResolutionSource::SiblingCandidate)
        && current_exe.starts_with(workspace_root.join("target"))
}

fn collect_lane_artifacts(
    lintai_bin: &Path,
    repo_dir: &Path,
    preset_matrix: &[&str],
) -> Result<Vec<LaneScanArtifact>, String> {
    let mut artifacts = Vec::new();

    if preset_matrix.is_empty() {
        let text = run_scan(lintai_bin, repo_dir, false, &[])?;
        let json = run_scan(lintai_bin, repo_dir, true, &[])?;
        let parsed = serde_json::from_str(&json).map_err(|error| {
            format!(
                "failed to parse scan JSON for {}: {error}",
                repo_dir.display()
            )
        })?;
        artifacts.push(LaneScanArtifact {
            lane_id: "default".to_owned(),
            text,
            parsed,
        });
        return Ok(artifacts);
    }

    for preset_id in preset_matrix {
        let text = run_scan(lintai_bin, repo_dir, false, &[*preset_id])?;
        let json = run_scan(lintai_bin, repo_dir, true, &[*preset_id])?;
        let parsed = serde_json::from_str(&json).map_err(|error| {
            format!(
                "failed to parse scan JSON for {} preset `{}`: {error}",
                repo_dir.display(),
                preset_id
            )
        })?;
        artifacts.push(LaneScanArtifact {
            lane_id: (*preset_id).to_owned(),
            text,
            parsed,
        });
    }

    Ok(artifacts)
}

fn write_scan_artifacts(
    repo_raw_root: &Path,
    lane_artifacts: &[LaneScanArtifact],
) -> Result<(), String> {
    let aggregate_json = serde_json::to_string_pretty(&merge_lane_scan_envelope(lane_artifacts))
        .map_err(|error| format!("failed to serialize aggregated scan artifact: {error}"))?;
    let aggregate_text = render_aggregate_scan_text(lane_artifacts);
    fs::write(repo_raw_root.join("scan.txt"), aggregate_text)
        .map_err(|error| format!("failed to write text scan artifact: {error}"))?;
    fs::write(repo_raw_root.join("scan.json"), aggregate_json)
        .map_err(|error| format!("failed to write JSON scan artifact: {error}"))?;

    if lane_artifacts.len() > 1 {
        for artifact in lane_artifacts {
            let lane_root = repo_raw_root.join("lanes").join(&artifact.lane_id);
            fs::create_dir_all(&lane_root).map_err(|error| {
                format!(
                    "failed to create lane raw output dir {}: {error}",
                    lane_root.display()
                )
            })?;
            fs::write(lane_root.join("scan.txt"), &artifact.text)
                .map_err(|error| format!("failed to write lane text scan artifact: {error}"))?;
            let lane_json = serde_json::to_string_pretty(&artifact.parsed)
                .map_err(|error| format!("failed to serialize lane scan artifact: {error}"))?;
            fs::write(lane_root.join("scan.json"), lane_json)
                .map_err(|error| format!("failed to write lane JSON scan artifact: {error}"))?;
        }
    }

    Ok(())
}

fn render_aggregate_scan_text(lane_artifacts: &[LaneScanArtifact]) -> String {
    if let [artifact] = lane_artifacts {
        return artifact.text.clone();
    }

    let mut output = String::new();
    for artifact in lane_artifacts {
        output.push_str(&format!("== {} ==\n", artifact.lane_id));
        output.push_str(artifact.text.trim_end());
        output.push_str("\n\n");
    }
    output
}

fn merge_lane_scan_envelope(lane_artifacts: &[LaneScanArtifact]) -> JsonScanEnvelope {
    let mut findings = BTreeMap::new();
    let mut diagnostics = BTreeMap::new();
    let mut runtime_errors = BTreeMap::new();

    for artifact in lane_artifacts {
        for finding in &artifact.parsed.findings {
            findings
                .entry(stable_key_fingerprint(&finding.stable_key))
                .or_insert_with(|| finding.clone());
        }
        for diagnostic in &artifact.parsed.diagnostics {
            diagnostics
                .entry((
                    diagnostic.normalized_path.clone(),
                    diagnostic.severity.clone(),
                    diagnostic.code.clone(),
                    diagnostic.message.clone(),
                ))
                .or_insert_with(|| diagnostic.clone());
        }
        for error in &artifact.parsed.runtime_errors {
            runtime_errors
                .entry((
                    error.normalized_path.clone(),
                    error.kind.clone(),
                    error.message.clone(),
                ))
                .or_insert_with(|| error.clone());
        }
    }

    JsonScanEnvelope {
        findings: findings.into_values().collect(),
        diagnostics: diagnostics.into_values().collect(),
        runtime_errors: runtime_errors.into_values().collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use lintai_api::{Location, Span, StableKey};

    use super::*;

    #[derive(Default)]
    struct FakeWorkspaceState {
        created_dirs: RefCell<Vec<(PathBuf, String)>>,
        materialized_repos: RefCell<Vec<(String, PathBuf)>>,
        verified_repos: RefCell<Vec<(ValidationPackage, String, PathBuf)>>,
        raw_artifact_writes: RefCell<Vec<(PathBuf, Vec<String>)>>,
        inventory_writes: RefCell<Vec<(PathBuf, Vec<String>)>>,
        candidate_writes: RefCell<Vec<(PathBuf, ExternalValidationLedger)>>,
    }

    struct FakeWorkspacePort {
        root: PathBuf,
        shortlist: RepoShortlist,
        ledgers: BTreeMap<PathBuf, ExternalValidationLedger>,
        inventory: InventoryArtifact,
        state: Rc<FakeWorkspaceState>,
    }

    impl ExternalValidationWorkspacePort for FakeWorkspacePort {
        fn workspace_root(&self) -> Result<PathBuf, String> {
            Ok(self.root.clone())
        }

        fn load_shortlist(
            &self,
            workspace_root: &Path,
            package: ValidationPackage,
        ) -> Result<RepoShortlist, String> {
            assert_eq!(workspace_root, self.root);
            assert_eq!(package, ValidationPackage::ToolJsonExtension);
            Ok(self.shortlist.clone())
        }

        fn load_ledger(&self, path: &Path) -> Result<ExternalValidationLedger, String> {
            self.ledgers
                .get(path)
                .cloned()
                .ok_or_else(|| format!("missing fake ledger {}", path.display()))
        }

        fn ensure_dir(&self, path: &Path, label: &str) -> Result<(), String> {
            self.state
                .created_dirs
                .borrow_mut()
                .push((path.to_path_buf(), label.to_owned()));
            Ok(())
        }

        fn materialize_repo(&self, repo: &ShortlistRepo, local_dir: &Path) -> Result<(), String> {
            self.state
                .materialized_repos
                .borrow_mut()
                .push((repo.repo.clone(), local_dir.to_path_buf()));
            Ok(())
        }

        fn verify_repo_admission(
            &self,
            package: ValidationPackage,
            repo: &ShortlistRepo,
            repo_root: &Path,
        ) -> Result<(), String> {
            self.state.verified_repos.borrow_mut().push((
                package,
                repo.repo.clone(),
                repo_root.to_path_buf(),
            ));
            Ok(())
        }

        fn inventory_surfaces(&self, _repo_root: &Path) -> Result<InventoryArtifact, String> {
            Ok(self.inventory.clone())
        }

        fn write_scan_artifacts(
            &self,
            repo_raw_root: &Path,
            lane_artifacts: &[LaneScanArtifact],
        ) -> Result<(), String> {
            self.state.raw_artifact_writes.borrow_mut().push((
                repo_raw_root.to_path_buf(),
                lane_artifacts
                    .iter()
                    .map(|artifact| artifact.lane_id.clone())
                    .collect(),
            ));
            Ok(())
        }

        fn write_inventory_artifact(
            &self,
            repo_raw_root: &Path,
            inventory: &InventoryArtifact,
        ) -> Result<(), String> {
            self.state.inventory_writes.borrow_mut().push((
                repo_raw_root.to_path_buf(),
                inventory.surfaces_present.clone(),
            ));
            Ok(())
        }

        fn write_candidate_ledger(
            &self,
            path: &Path,
            ledger: &ExternalValidationLedger,
        ) -> Result<(), String> {
            self.state
                .candidate_writes
                .borrow_mut()
                .push((path.to_path_buf(), ledger.clone()));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeScannerState {
        resolved_requests: RefCell<Vec<(PathBuf, Option<PathBuf>)>>,
        scan_requests: RefCell<Vec<(PathBuf, PathBuf, Vec<String>)>>,
    }

    struct FakeScanPort {
        lane_artifacts: Vec<LaneScanArtifact>,
        state: Rc<FakeScannerState>,
    }

    impl ExternalValidationScanPort for FakeScanPort {
        fn resolve_rerun_lintai_driver(
            &self,
            workspace_root: &Path,
            lintai_bin: Option<&Path>,
        ) -> Result<ResolvedBinary, String> {
            self.state.resolved_requests.borrow_mut().push((
                workspace_root.to_path_buf(),
                lintai_bin.map(Path::to_path_buf),
            ));
            Ok(ResolvedBinary {
                path: PathBuf::from("/tooling/lintai"),
                source: BinaryResolutionSource::PreferredEnv,
            })
        }

        fn collect_lane_artifacts(
            &self,
            lintai_bin: &Path,
            repo_dir: &Path,
            preset_matrix: &[&str],
        ) -> Result<Vec<LaneScanArtifact>, String> {
            self.state.scan_requests.borrow_mut().push((
                lintai_bin.to_path_buf(),
                repo_dir.to_path_buf(),
                preset_matrix
                    .iter()
                    .map(|preset| (*preset).to_owned())
                    .collect(),
            ));
            Ok(self.lane_artifacts.clone())
        }
    }

    #[test]
    fn rerun_application_coordinates_ports_and_writes_candidate_ledger() {
        let workspace_root = PathBuf::from("/workspace");
        let package = ValidationPackage::ToolJsonExtension;
        let repo = ShortlistRepo {
            repo: "acme/example".to_owned(),
            url: "https://github.com/acme/example".to_owned(),
            pinned_ref: "deadbeef".to_owned(),
            ownership: "community".to_owned(),
            category: "tooling".to_owned(),
            subtype: "tool-json".to_owned(),
            status: "candidate".to_owned(),
            surfaces_present: vec!["tool_descriptor_json".to_owned()],
            admission_paths: vec!["tools.json".to_owned()],
            rationale: "fixture".to_owned(),
        };
        let state = Rc::new(FakeWorkspaceState::default());
        let scanner_state = Rc::new(FakeScannerState::default());
        let app = ExternalValidationApplication::new(
            FakeWorkspacePort {
                root: workspace_root.clone(),
                shortlist: RepoShortlist {
                    version: 1,
                    repos: vec![repo.clone()],
                },
                ledgers: BTreeMap::from([(
                    workspace_root.join(package.ledger_path()),
                    ExternalValidationLedger {
                        version: 1,
                        wave: 0,
                        baseline: None,
                        evaluations: Vec::new(),
                    },
                )]),
                inventory: InventoryArtifact {
                    surfaces_present: vec!["tool_descriptor_json".to_owned()],
                },
                state: state.clone(),
            },
            FakeScanPort {
                lane_artifacts: vec![LaneScanArtifact {
                    lane_id: "default".to_owned(),
                    text: "scan output".to_owned(),
                    parsed: JsonScanEnvelope {
                        findings: vec![JsonFinding {
                            rule_code: "SEC324".to_owned(),
                            stable_key: StableKey::new(
                                "SEC324",
                                "tools.json",
                                Span::new(0, 4),
                                None,
                            ),
                            location: Location::new("tools.json", Span::new(0, 4)),
                        }],
                        diagnostics: Vec::new(),
                        runtime_errors: Vec::new(),
                    },
                }],
                state: scanner_state.clone(),
            },
        );

        app.rerun(RerunOptions {
            package,
            lintai_bin: Some(PathBuf::from("/custom/lintai")),
        })
        .unwrap();

        assert_eq!(
            scanner_state.resolved_requests.borrow().as_slice(),
            &[(
                workspace_root.clone(),
                Some(PathBuf::from("/custom/lintai"))
            )]
        );
        assert_eq!(
            state.created_dirs.borrow().as_slice(),
            &[
                (
                    workspace_root.join("target/external-validation/repos"),
                    "repo cache root".to_owned()
                ),
                (
                    workspace_root.join(package.raw_output_root()),
                    "raw output root".to_owned()
                ),
                (
                    workspace_root
                        .join(package.raw_output_root())
                        .join("acme__example"),
                    "raw output dir".to_owned()
                )
            ]
        );
        assert_eq!(
            state.materialized_repos.borrow().as_slice(),
            &[(
                "acme/example".to_owned(),
                workspace_root
                    .join("target/external-validation/repos")
                    .join("acme__example")
            )]
        );
        assert_eq!(
            state.verified_repos.borrow().as_slice(),
            &[(
                package,
                "acme/example".to_owned(),
                workspace_root
                    .join("target/external-validation/repos")
                    .join("acme__example")
            )]
        );
        assert_eq!(
            scanner_state.scan_requests.borrow().as_slice(),
            &[(
                PathBuf::from("/tooling/lintai"),
                workspace_root
                    .join("target/external-validation/repos")
                    .join("acme__example"),
                Vec::<String>::new()
            )]
        );

        let candidate_writes = state.candidate_writes.borrow();
        assert_eq!(candidate_writes.len(), 1);
        let (candidate_path, candidate) = &candidate_writes[0];
        assert_eq!(
            candidate_path,
            &workspace_root.join(package.candidate_ledger_path())
        );
        assert_eq!(candidate.wave, package.default_wave());
        assert_eq!(
            candidate.baseline,
            package.baseline_reference().map(str::to_owned)
        );
        assert_eq!(candidate.evaluations.len(), 1);
        let entry = &candidate.evaluations[0];
        assert_eq!(entry.repo, "acme/example");
        assert_eq!(entry.status, "evaluated");
        assert_eq!(
            entry.surfaces_present,
            vec!["tool_descriptor_json".to_owned()]
        );
        assert_eq!(entry.stable_findings, 1);
        assert_eq!(entry.stable_rule_codes, vec!["SEC324".to_owned()]);
        assert!(entry.preview_rule_codes.is_empty());
        assert_eq!(entry.repo_verdict, "strong_fit");
    }
}
