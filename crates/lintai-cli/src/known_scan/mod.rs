use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ignore::WalkBuilder;
use lintai_api::{ArtifactKind, Finding};
use lintai_engine::{FileTypeDetector, ScanSummary, WorkspaceConfig, normalize_path_string};
use serde::{Deserialize, Serialize};

mod constants;
mod discovery;
mod inventory;
mod manifest;
mod model;
mod scan;

pub(crate) use constants::*;
pub(crate) use discovery::*;
pub(crate) use inventory::*;
pub(crate) use manifest::*;
pub(crate) use model::*;
pub(crate) use scan::*;

#[cfg(test)]
mod tests;
