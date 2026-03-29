use super::*;

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

pub(crate) fn discover_known_roots_with_env(
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

pub(crate) fn should_replace_known_root(existing: ArtifactMode, candidate: ArtifactMode) -> bool {
    matches!(
        (existing, candidate),
        (ArtifactMode::DiscoveredOnly, ArtifactMode::Lintable)
    )
}

pub(crate) fn discover_system_known_roots() -> Result<Vec<KnownRoot>, String> {
    registry()?;
    Ok(Vec::new())
}

pub(crate) fn resolve_path_template(
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

pub(crate) fn join_template_suffix(base: &Path, suffix: &str) -> PathBuf {
    let mut resolved = base.to_path_buf();
    for component in suffix.trim_start_matches('/').split('/') {
        if component.is_empty() {
            continue;
        }
        resolved.push(component);
    }
    resolved
}

pub(crate) fn scope_matches(filter: KnownScope, scope: KnownRootScope) -> bool {
    match filter {
        KnownScope::Project => scope == KnownRootScope::Project,
        KnownScope::Global => scope == KnownRootScope::Global,
        KnownScope::Both => true,
    }
}
