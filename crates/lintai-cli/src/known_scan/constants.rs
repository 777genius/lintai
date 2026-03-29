pub(crate) const KNOWN_ROOTS_MANIFEST: &str = include_str!("../../known_roots.toml");
pub(crate) const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    "vendor",
];
