mod commands;
mod state;

use commands::{scan, sanitize, export, tree};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .manage(state::AppState::default())
        .invoke_handler(tauri::generate_handler![
            scan::scan_file,
            scan::collect_packages,
            scan::save_report,
            scan::generate_txt_report,
            sanitize::sanitize_file,
            export::export_file,
            tree::get_tree,
            tree::export_tree,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
