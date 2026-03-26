use std::path::Path;

use lintai_api::{Finding, LineColumn};

pub(crate) fn normalize_path(base_path: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(base_path).unwrap_or(path);
    normalize_path_string(relative)
}

pub(crate) fn normalize_text(mut text: String) -> String {
    if text.starts_with('\u{feff}') {
        text.remove(0);
    }
    if text.contains('\r') {
        text = text.replace("\r\n", "\n").replace('\r', "\n");
    }
    text
}

pub(crate) fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(1024).any(|byte| *byte == 0)
}

pub(crate) fn populate_line_columns(content: &str, finding: &mut Finding) {
    if finding.location.start.is_none() {
        finding.location.start = line_column_for_offset(content, finding.location.span.start_byte);
    }
    if finding.location.end.is_none() {
        finding.location.end = line_column_for_offset(content, finding.location.span.end_byte);
    }
}

pub(crate) fn line_column_for_offset(content: &str, offset: usize) -> Option<LineColumn> {
    if offset > content.len() || !content.is_char_boundary(offset) {
        return None;
    }

    let mut line = 1usize;
    let mut column = 1usize;
    for ch in content[..offset].chars() {
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    Some(LineColumn::new(line, column))
}

pub fn normalize_path_string(path: &Path) -> String {
    let mut prefix = None;
    let mut absolute = false;
    let mut segments = Vec::new();

    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Prefix(value) => {
                prefix = Some(value.as_os_str().to_string_lossy().into_owned());
            }
            std::path::Component::RootDir => absolute = true,
            std::path::Component::ParentDir => {
                if let Some(last) = segments.last() {
                    if last != ".." {
                        segments.pop();
                    } else if !absolute {
                        segments.push("..".to_owned());
                    }
                } else if !absolute {
                    segments.push("..".to_owned());
                }
            }
            std::path::Component::Normal(value) => {
                segments.push(value.to_string_lossy().into_owned());
            }
        }
    }

    let mut normalized = String::new();
    if let Some(prefix) = prefix {
        normalized.push_str(&prefix);
    }
    if absolute && !normalized.ends_with('/') {
        normalized.push('/');
    }
    for segment in segments {
        if !normalized.is_empty() && !normalized.ends_with('/') {
            normalized.push('/');
        }
        normalized.push_str(&segment);
    }

    if normalized.is_empty() {
        ".".to_owned()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{normalize_path, normalize_path_string};

    #[test]
    fn normalizes_paths_to_relative_forward_slashes() {
        let base = Path::new("/tmp/project");
        let path = Path::new("/tmp/project/nested/SKILL.md");

        assert_eq!(normalize_path(base, path), "nested/SKILL.md");
        assert_eq!(
            normalize_path(Path::new("."), Path::new("./nested/SKILL.md")),
            "nested/SKILL.md"
        );
    }

    #[test]
    fn normalizes_absolute_paths_for_display() {
        assert_eq!(
            normalize_path_string(Path::new("/tmp/lintai/./docs/../docs/SKILL.md")),
            "/tmp/lintai/docs/SKILL.md"
        );
    }
}
