use std::thread;

const FORCE_SEQUENTIAL_SCAN_ENV: &str = "LINTAI_FORCE_SEQUENTIAL_SCAN";
const MIN_FILES_FOR_PARALLEL_SCAN: usize = 4;

pub(crate) fn scan_worker_count(file_count: usize) -> usize {
    if should_scan_sequentially(file_count) {
        1
    } else {
        file_count
            .min(
                thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1),
            )
            .max(1)
    }
}

fn should_scan_sequentially(file_count: usize) -> bool {
    file_count < MIN_FILES_FOR_PARALLEL_SCAN || force_sequential_scans()
}

fn force_sequential_scans() -> bool {
    matches!(
        std::env::var(FORCE_SEQUENTIAL_SCAN_ENV),
        Ok(value) if matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")
    )
}
