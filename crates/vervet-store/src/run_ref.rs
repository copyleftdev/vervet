//! A reference to one stored receipt.

use std::path::PathBuf;

/// Where a receipt landed and how to name it: the engagement it belongs to, its
/// content-addressed run id, and the file path on disk.
#[derive(Clone, Debug)]
pub struct RunRef {
    pub engagement_id: String,
    pub run_id: String,
    pub path: PathBuf,
}
