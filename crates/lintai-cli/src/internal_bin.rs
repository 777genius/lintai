use std::path::PathBuf;

pub(crate) fn resolve_named_binary(
    binary_stem: &str,
    preferred_env_vars: &[&str],
) -> Result<PathBuf, String> {
    for env_var in preferred_env_vars {
        if let Some(path) = std::env::var_os(env_var) {
            let path = PathBuf::from(path);
            if path.exists() {
                return Ok(path);
            }
        }
    }

    let cargo_env = format!("CARGO_BIN_EXE_{binary_stem}");
    if let Some(path) = std::env::var_os(&cargo_env) {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    let current = std::env::current_exe()
        .map_err(|error| format!("failed to resolve current executable: {error}"))?;
    if current
        .file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name == binary_stem)
    {
        return Ok(current);
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
            return Ok(candidate);
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
