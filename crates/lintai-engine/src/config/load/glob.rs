use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::ConfigError;

pub(crate) fn compile_globset(patterns: &[&str]) -> Result<GlobSet, ConfigError> {
    compile_globset_vec(&patterns.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>())
}

pub(super) fn compile_globset_vec(patterns: &[String]) -> Result<GlobSet, ConfigError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .map_err(|error| ConfigError::new(format!("invalid glob `{pattern}`: {error}")))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|error| ConfigError::new(format!("invalid globset: {error}")))
}
