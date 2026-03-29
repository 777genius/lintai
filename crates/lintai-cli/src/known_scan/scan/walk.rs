use super::super::*;

pub(super) fn walk_root<'a>(
    root: &'a Path,
    follow_symlinks: bool,
    canonical_project_root: Option<&'a Path>,
) -> ignore::Walk {
    let mut walker = WalkBuilder::new(root);
    walker.hidden(false);
    walker.follow_links(follow_symlinks);
    walker.git_ignore(true);
    walker.git_global(false);
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
