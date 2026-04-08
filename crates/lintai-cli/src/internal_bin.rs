use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BinaryResolutionSource {
    PreferredEnv,
    CargoEnv,
    CurrentExe,
    SiblingCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedBinary {
    pub(crate) path: PathBuf,
    pub(crate) source: BinaryResolutionSource,
}

pub(crate) fn resolve_named_binary(
    binary_stem: &str,
    preferred_env_vars: &[&str],
) -> Result<PathBuf, String> {
    Ok(resolve_named_binary_with_source(binary_stem, preferred_env_vars)?.path)
}

pub(crate) fn resolve_named_binary_with_source(
    binary_stem: &str,
    preferred_env_vars: &[&str],
) -> Result<ResolvedBinary, String> {
    for env_var in preferred_env_vars {
        if let Some(path) = std::env::var_os(env_var) {
            let path = PathBuf::from(path);
            if path.exists() {
                return Ok(ResolvedBinary {
                    path,
                    source: BinaryResolutionSource::PreferredEnv,
                });
            }
        }
    }

    let cargo_env = format!("CARGO_BIN_EXE_{binary_stem}");
    if let Some(path) = std::env::var_os(&cargo_env) {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(ResolvedBinary {
                path,
                source: BinaryResolutionSource::CargoEnv,
            });
        }
    }

    let current = std::env::current_exe()
        .map_err(|error| format!("failed to resolve current executable: {error}"))?;
    if current
        .file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name == binary_stem)
    {
        return Ok(ResolvedBinary {
            path: current,
            source: BinaryResolutionSource::CurrentExe,
        });
    }

    let binary_name = format!("{binary_stem}{}", std::env::consts::EXE_SUFFIX);
    let mut candidates = Vec::new();
    if let Some(parent) = current.parent() {
        candidates.push(parent.join(&binary_name));
        if parent.file_name().is_some_and(|name| name == "deps")
            && let Some(grandparent) = parent.parent()
        {
            candidates.push(grandparent.join(&binary_name));
        }
    }

    for candidate in candidates {
        if candidate.exists() {
            return Ok(ResolvedBinary {
                path: candidate,
                source: BinaryResolutionSource::SiblingCandidate,
            });
        }
    }

    Err(format!(
        "failed to locate {binary_stem} executable near {}",
        current.display()
    ))
}

pub(crate) fn resolve_lintai_driver_path() -> Result<PathBuf, String> {
    resolve_named_binary("lintai", &["LINTAI_SELF_EXE"])
}

pub(crate) fn resolve_lintai_driver_path_with_source() -> Result<ResolvedBinary, String> {
    resolve_named_binary_with_source("lintai", &["LINTAI_SELF_EXE"])
}
