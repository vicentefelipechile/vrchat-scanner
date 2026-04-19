use std::path::Path;
use std::time::Instant;

use crate::analysis::run_all_analyses;
use crate::ingestion::{extractor, FileRecord, FileType};
use crate::ingestion::type_detection::detect_type;
use crate::report::ScanReport;
use crate::scoring::{apply_context_reductions, compute_score};

/// The full scan pipeline: ingest → extract → analyze → score → report.
/// Returns the completed ScanReport.
pub fn run_scan(path: &Path) -> crate::utils::Result<ScanReport> {
    let start = Instant::now();

    // Stage 0: File ingestion
    let file_record = FileRecord::from_path(path)?;
    let data = std::fs::read(path)?;

    run_scan_with_record(data, file_record, start)
}

/// Scan from raw bytes with a synthetic file_id (used by the server).
pub fn run_scan_bytes(data: &[u8], file_id: &str) -> crate::utils::Result<ScanReport> {
    let start = Instant::now();

    let fake_path = Path::new(file_id);
    let file_type: FileType = detect_type(data, fake_path);

    use sha2::{Digest, Sha256};
    use md5::Md5;
    use sha1::Sha1;

    let sha256 = hex::encode(Sha256::digest(data));
    let md5    = hex::encode(Md5::digest(data));
    let sha1   = hex::encode(Sha1::digest(data));

    let file_record = FileRecord {
        path: file_id.to_string(),
        size_bytes: data.len() as u64,
        file_type: file_type.clone(),
        sha256,
        md5,
        sha1,
        timestamp: chrono::Utc::now(),
    };

    run_scan_with_record(data.to_vec(), file_record, start)
}

fn run_scan_with_record(
    data: Vec<u8>,
    file_record: FileRecord,
    start: Instant,
) -> crate::utils::Result<ScanReport> {
    let file_type = file_record.file_type.clone();

    // Stage 1: Extract / build package tree
    let tree = extractor::extract(&data, &file_type)?;

    // Stages 2-5: Run all analyses in parallel
    let (mut findings, counts, context) = run_all_analyses(&tree);

    // Stage 6: Apply context-aware score reductions
    apply_context_reductions(&mut findings, &context);

    // Compute final score
    let (score, level) = compute_score(&findings);

    let duration_ms = start.elapsed().as_millis();

    // Stage 7: Build report
    let report = ScanReport::build(file_record, findings, score, level, counts, duration_ms);

    Ok(report)
}
