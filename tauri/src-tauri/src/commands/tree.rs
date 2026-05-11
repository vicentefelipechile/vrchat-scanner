use serde::{Deserialize, Serialize};
use vrcstorage_scanner::tree::{run_tree, TreeFormat, TreeOptions};

/// Serializable tree node for the frontend.
/// Deserialized directly from the JSON output of the tree module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerTreeNode {
    pub name: String,
    #[serde(rename = "type")]
    pub node_type: Option<String>,
    pub size_bytes: Option<usize>,
    pub has_meta: Option<bool>,
    pub children: Option<Vec<SerTreeNode>>,
}

/// Build the interactive tree for a package (returns structured data for UI rendering).
///
/// Internally runs tree with JSON format and parses the "tree" key out of the result.
#[tauri::command]
pub async fn get_tree(path: String) -> Result<SerTreeNode, String> {
    tokio::task::spawn_blocking(move || {
        let (_, json_str) = run_tree(
            std::path::Path::new(&path),
            &TreeFormat::Json,
            &TreeOptions { pretty: false },
        )
        .map_err(|e| e.to_string())?;

        // The JSON output has the shape:
        // { "file": "...", "total_entries": N, "tree": { <TreeNode> } }
        let val: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
        let tree_val = val
            .get("tree")
            .cloned()
            .ok_or_else(|| "Missing 'tree' key in JSON output".to_string())?;
        serde_json::from_value::<SerTreeNode>(tree_val).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Export the tree as TXT / JSON / XML and return as a string (for save-file dialog).
///
/// `format`: "txt" | "json" | "xml"
#[tauri::command]
pub async fn export_tree(path: String, format: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let fmt = match format.to_lowercase().as_str() {
            "json" => TreeFormat::Json,
            "xml" => TreeFormat::Xml,
            _ => TreeFormat::Txt,
        };
        let options = TreeOptions { pretty: true };
        let (_, output) =
            run_tree(std::path::Path::new(&path), &fmt, &options).map_err(|e| e.to_string())?;
        Ok(output)
    })
    .await
    .map_err(|e| e.to_string())?
}
