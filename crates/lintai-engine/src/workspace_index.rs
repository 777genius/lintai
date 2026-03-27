use std::collections::BTreeMap;

use lintai_api::{Location, Span};

use crate::ResolvedFileConfig;

#[derive(Clone)]
pub(crate) struct WorkspaceEntry {
    pub(crate) artifact_index: usize,
    pub(crate) normalized_path: String,
    pub(crate) file_config: ResolvedFileConfig,
}

pub(crate) struct WorkspaceIndex {
    entries: Vec<WorkspaceEntry>,
    by_path: BTreeMap<String, usize>,
}

impl WorkspaceIndex {
    pub(crate) fn new(entries: Vec<WorkspaceEntry>) -> Self {
        let by_path = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.normalized_path.clone(), index))
            .collect();
        Self { entries, by_path }
    }

    pub(crate) fn get(&self, normalized_path: &str) -> Option<&WorkspaceEntry> {
        self.by_path
            .get(normalized_path)
            .and_then(|index| self.entries.get(*index))
    }
}

pub(crate) fn full_artifact_location(path: impl Into<String>, content: &str) -> Location {
    Location::new(path, Span::new(0, content.len()))
}
