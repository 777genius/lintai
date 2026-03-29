use std::path::Path;

use ignore::WalkBuilder;

use super::filter::should_visit_path;

pub(super) fn build_walker<'a>(
    root: &'a Path,
    follow_symlinks: bool,
    canonical_project_root: Option<&'a Path>,
) -> ignore::Walk {
    let mut walker = WalkBuilder::new(root);
    walker.hidden(false);
    walker.follow_links(follow_symlinks);
    walker.parents(false);
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
