use super::*;

#[derive(Clone, Debug, Default)]
pub(crate) struct EnvironmentPaths {
    pub(crate) home_dir: Option<PathBuf>,
    pub(crate) xdg_config_home: Option<PathBuf>,
}

impl EnvironmentPaths {
    pub(crate) fn from_process() -> Self {
        let home_dir = std::env::var_os("HOME").map(PathBuf::from);
        let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir.as_ref().map(|home| home.join(".config")));
        Self {
            home_dir,
            xdg_config_home,
        }
    }

    pub(crate) fn from_path_root(path_root: &Path) -> Self {
        Self {
            home_dir: Some(path_root.to_path_buf()),
            xdg_config_home: Some(path_root.join(".config")),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct KnownRootsManifest {
    #[serde(rename = "surface")]
    surfaces: Vec<KnownSurfaceSpec>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct KnownSurfaceSpec {
    pub(crate) client_id: String,
    pub(crate) surface_id: String,
    pub(crate) scope: KnownRootScope,
    pub(crate) path_template: String,
    pub(crate) artifact_mode: ArtifactMode,
    pub(crate) artifact_kind_hint: Option<ArtifactKind>,
    pub(crate) notes: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct KnownRegistry {
    pub(crate) surfaces: Vec<KnownSurfaceSpec>,
}

pub(crate) static KNOWN_REGISTRY: OnceLock<Result<KnownRegistry, String>> = OnceLock::new();

pub(crate) fn registry() -> Result<&'static KnownRegistry, String> {
    match KNOWN_REGISTRY.get_or_init(|| registry_from_str(KNOWN_ROOTS_MANIFEST)) {
        Ok(registry) => Ok(registry),
        Err(error) => Err(error.clone()),
    }
}

pub(crate) fn registry_from_str(input: &str) -> Result<KnownRegistry, String> {
    let manifest: KnownRootsManifest = toml::from_str(input)
        .map_err(|error| format!("known roots manifest parse failed: {error}"))?;
    validate_manifest(&manifest)?;
    Ok(KnownRegistry {
        surfaces: manifest.surfaces,
    })
}

pub(crate) fn validate_manifest(manifest: &KnownRootsManifest) -> Result<(), String> {
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

pub(crate) fn validate_path_template(template: &str) -> Result<(), String> {
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
