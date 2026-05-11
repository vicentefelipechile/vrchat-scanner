use std::sync::Mutex;

/// Persistent in-memory state for the Tauri app.
/// History and settings are persisted to disk via tauri-plugin-store,
/// but we keep a hot copy here so commands can access them without
/// reading the file on every call.
#[derive(Default)]
pub struct AppState {
    /// Cached list of SHA-256 hashes that have already been submitted
    /// to the community endpoint (so we suppress duplicate prompts).
    #[allow(dead_code)]
    pub submitted_hashes: Mutex<Vec<String>>,
}
