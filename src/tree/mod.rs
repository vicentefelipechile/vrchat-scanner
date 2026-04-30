//! Tree module: renders the internal file-tree of a Unity package
//! as a structured tree in TXT, JSON, or XML format.
//!
//! # Usage
//! ```text
//! vrcstorage-scanner tree <FILE> [--export txt|json|xml] [--pretty]
//! ```

use std::path::Path;

use crate::ingestion::extractor::{self, AssetType, PackageTree};
use crate::ingestion::file_record::FileType;
use crate::ingestion::type_detection::detect_type;

// ─── Public types ────────────────────────────────────────────────────────────

/// Output format for the tree rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeFormat {
    Txt,
    Json,
    Xml,
}

/// Configuration options for tree rendering.
#[derive(Debug, Clone)]
pub struct TreeOptions {
    /// Use Unicode box-drawing characters in TXT output.
    pub pretty: bool,
}

/// A single node in the file-tree.
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub name: String,
    /// `None` for directories, `Some("<type>")` for files.
    pub asset_type: Option<String>,
    /// File size in bytes (`None` for directories or empty entries).
    pub size_bytes: Option<usize>,
    /// Whether this entry has an associated `.meta` file.
    pub has_meta: bool,
    /// Child nodes (subdirectories, files, and .meta entries).
    pub children: Vec<TreeNode>,
}

/// Summary produced by a tree export.
#[derive(Debug)]
pub struct TreeReport {
    pub total_entries: usize,
}

// ─── Public entry point ──────────────────────────────────────────────────────

/// Build and render the file-tree of a `.unitypackage` or `.zip` file.
///
/// Returns `(TreeReport, rendered_output_string)`.
pub fn run_tree(
    input_path: &Path,
    format: &TreeFormat,
    options: &TreeOptions,
) -> crate::utils::Result<(TreeReport, String)> {
    let data = std::fs::read(input_path)?;
    let file_type = detect_type(&data, input_path);

    if file_type != FileType::UnityPackage && file_type != FileType::ZipArchive {
        return Err(crate::utils::ScannerError::ExportError(format!(
            "File is not a UnityPackage or ZIP archive (detected: {:?})",
            file_type
        )));
    }

    let pkg_tree = extractor::extract(&data, &file_type)?;
    let root_name = input_path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let root = build_tree(&pkg_tree, &root_name);
    let total_entries = pkg_tree.entries.len();

    let output = match format {
        TreeFormat::Txt => render_txt(&root, options, total_entries),
        TreeFormat::Json => render_json(&root, total_entries, &root_name),
        TreeFormat::Xml => render_xml(&root, total_entries, &root_name),
    };

    Ok((
        TreeReport { total_entries },
        output,
    ))
}

// ─── Tree building ───────────────────────────────────────────────────────────

fn build_tree(tree: &PackageTree, root_name: &str) -> TreeNode {
    let mut root = TreeNode {
        name: root_name.to_string(),
        asset_type: None,
        size_bytes: None,
        has_meta: false,
        children: Vec::new(),
    };

    for entry in tree.all_entries() {
        let path = entry
            .original_path
            .trim_start_matches('/')
            .trim_start_matches('\\');
        if path.is_empty() {
            continue;
        }
        let segments: Vec<&str> = path.split('/').collect();
        if segments.is_empty() {
            continue;
        }
        insert_entry(&mut root, &segments, entry);
    }

    sort_tree(&mut root);
    root
}

fn insert_entry(node: &mut TreeNode, segments: &[&str], entry: &extractor::PackageEntry) {
    if segments.is_empty() {
        return;
    }

    let name = segments[0].to_string();

    if segments.len() == 1 {
        let mut file_node = TreeNode {
            name,
            asset_type: Some(asset_type_label(&entry.asset_type).to_string()),
            size_bytes: if entry.bytes.is_empty() {
                None
            } else {
                Some(entry.bytes.len())
            },
            has_meta: entry.meta_content.is_some(),
            children: Vec::new(),
        };

        if let Some(ref meta_content) = entry.meta_content {
            let meta_name = format!("{}.meta", segments[0]);
            let meta_node = TreeNode {
                name: meta_name,
                asset_type: Some("Meta".to_string()),
                size_bytes: Some(meta_content.len()),
                has_meta: false,
                children: Vec::new(),
            };
            file_node.children.push(meta_node);
        }

        node.children.push(file_node);
    } else {
        let pos = node
            .children
            .iter()
            .position(|c| c.name == name && c.asset_type.is_none());

        match pos {
            Some(idx) => {
                insert_entry(&mut node.children[idx], &segments[1..], entry);
            }
            None => {
                let mut dir_node = TreeNode {
                    name,
                    asset_type: None,
                    size_bytes: None,
                    has_meta: false,
                    children: Vec::new(),
                };
                insert_entry(&mut dir_node, &segments[1..], entry);
                node.children.push(dir_node);
            }
        }
    }
}

fn sort_tree(node: &mut TreeNode) {
    node.children.sort_by(|a, b| {
        let a_is_dir = a.asset_type.is_none();
        let b_is_dir = b.asset_type.is_none();
        if a_is_dir && !b_is_dir {
            std::cmp::Ordering::Less
        } else if !a_is_dir && b_is_dir {
            std::cmp::Ordering::Greater
        } else {
            a.name.to_lowercase().cmp(&b.name.to_lowercase())
        }
    });
    for child in &mut node.children {
        sort_tree(child);
    }
}

// ─── TXT rendering ──────────────────────────────────────────────────────────

fn render_txt(root: &TreeNode, options: &TreeOptions, total_entries: usize) -> String {
    let mut output = String::new();

    output.push_str(&format!("{} ({} entries)\n", root.name, total_entries));

    let count = root.children.len();
    for (i, child) in root.children.iter().enumerate() {
        let is_last = i == count - 1;
        write_txt_node(child, &mut output, "", is_last, options.pretty);
    }

    output
}

fn write_txt_node(
    node: &TreeNode,
    output: &mut String,
    prefix: &str,
    is_last: bool,
    pretty: bool,
) {
    let (connector, child_prefix) = if pretty {
        if is_last {
            ("\u{2514}\u{2500}\u{2500} ", "    ")
        } else {
            ("\u{251C}\u{2500}\u{2500} ", "\u{2502}   ")
        }
    } else if is_last {
        ("`-- ", "    ")
    } else {
        ("|-- ", "|   ")
    };

    let full_prefix = format!("{}{}", prefix, child_prefix);

    if node.asset_type.is_none() {
        output.push_str(&format!("{}{}{}/\n", prefix, connector, node.name));
    } else {
        let type_label = node.asset_type.as_deref().unwrap_or("?");
        let size = node
            .size_bytes
            .map(format_size)
            .unwrap_or_else(|| "empty".to_string());
        output.push_str(&format!(
            "{}{}{} [{}] ({})\n",
            prefix, connector, node.name, type_label, size
        ));
    }

    let count = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        let child_is_last = i == count - 1;
        write_txt_node(child, output, &full_prefix, child_is_last, pretty);
    }
}

// ─── JSON rendering ──────────────────────────────────────────────────────────

fn render_json(root: &TreeNode, total_entries: usize, file_name: &str) -> String {
    let mut output = String::new();
    output.push_str("{\n");
    output.push_str(&format!("  \"file\": \"{}\",\n", json_escape(file_name)));
    output.push_str(&format!("  \"total_entries\": {},\n", total_entries));
    output.push_str("  \"tree\": ");
    write_json_node(root, &mut output, 2);
    output.push('\n');
    output.push_str("}\n");
    output
}

fn write_json_node(node: &TreeNode, output: &mut String, indent: usize) {
    let pad = "  ".repeat(indent);
    let inner_pad = "  ".repeat(indent + 1);

    output.push_str("{\n");
    output.push_str(&format!("{}\"name\": \"{}\",\n", inner_pad, json_escape(&node.name)));

    match &node.asset_type {
        Some(at) => {
            output.push_str(&format!("{}\"type\": \"{}\",\n", inner_pad, json_escape(at)));
        }
        None => {
            output.push_str(&format!("{}\"type\": \"directory\",\n", inner_pad));
        }
    }

    if let Some(size) = node.size_bytes {
        output.push_str(&format!("{}\"size_bytes\": {},\n", inner_pad, size));
    }

    output.push_str(&format!("{}\"has_meta\": {},\n", inner_pad, node.has_meta));

    output.push_str(&format!("{}\"children\": ", inner_pad));
    if node.children.is_empty() {
        output.push_str("[]\n");
    } else {
        output.push_str("[\n");
        let child_count = node.children.len();
        for (i, child) in node.children.iter().enumerate() {
            output.push_str(&"  ".repeat(indent + 2));
            write_json_node(child, output, indent + 2);
            if i < child_count - 1 {
                output.push_str(",\n");
            } else {
                output.push('\n');
            }
        }
        output.push_str(&format!("{}]\n", &"  ".repeat(indent + 1)));
    }

    output.push_str(&format!("{}}}", pad));
}

// ─── XML rendering ───────────────────────────────────────────────────────────

fn render_xml(root: &TreeNode, total_entries: usize, file_name: &str) -> String {
    let mut output = String::new();
    output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    write_xml_node(root, &mut output, total_entries, file_name);
    output
}

fn write_xml_node(node: &TreeNode, output: &mut String, total_entries: usize, file_name: &str) {
    write_xml_node_indent(node, output, 0, total_entries, file_name);
}

fn write_xml_node_indent(
    node: &TreeNode,
    output: &mut String,
    indent: usize,
    total_entries: usize,
    file_name: &str,
) {
    let pad = "  ".repeat(indent);

    if indent == 0 {
        output.push_str(&format!(
            "<package name=\"{}\" total_entries=\"{}\">\n",
            escape_xml(file_name),
            total_entries
        ));
        for child in &node.children {
            write_xml_node_indent(child, output, indent + 1, total_entries, "");
        }
        output.push_str("</package>\n");
    } else if node.asset_type.is_none() {
        output.push_str(&format!(
            "{}<directory name=\"{}\">\n",
            pad,
            escape_xml(&node.name)
        ));
        for child in &node.children {
            write_xml_node_indent(child, output, indent + 1, total_entries, "");
        }
        output.push_str(&format!("{}</directory>\n", pad));
    } else {
        let at = node.asset_type.as_deref().unwrap_or("Other");
        let size_attr = node
            .size_bytes
            .map(|s| format!(" size_bytes=\"{}\"", s))
            .unwrap_or_default();
        let meta_attr = if node.has_meta {
            " has_meta=\"true\""
        } else {
            ""
        };

        if !node.children.is_empty() {
            output.push_str(&format!(
                "{}<file name=\"{}\" type=\"{}\"{}{}>\n",
                pad,
                escape_xml(&node.name),
                escape_xml(at),
                size_attr,
                meta_attr,
            ));
            for child in &node.children {
                write_xml_node_indent(child, output, indent + 1, total_entries, "");
            }
            output.push_str(&format!("{}</file>\n", pad));
        } else {
            output.push_str(&format!(
                "{}<file name=\"{}\" type=\"{}\"{}{}/>\n",
                pad,
                escape_xml(&node.name),
                escape_xml(at),
                size_attr,
                meta_attr,
            ));
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

pub(crate) fn asset_type_label(at: &AssetType) -> &str {
    match at {
        AssetType::Script => "C#",
        AssetType::Dll => "DLL",
        AssetType::Shader => "Shader",
        AssetType::Prefab => "Prefab",
        AssetType::ScriptableObject => "SO",
        AssetType::Texture => "Tex",
        AssetType::Audio => "Audio",
        AssetType::AnimationClip => "Anim",
        AssetType::Meta => "Meta",
        AssetType::Other(s) => s,
    }
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingestion::extractor::{AssetType, PackageEntry, PackageTree};

    fn build_test_tree() -> TreeNode {
        let mut tree = PackageTree::new();

        let paths = vec![
            ("Assets/Scripts/MyScript.cs", AssetType::Script),
            ("Assets/Scripts/Utils.cs", AssetType::Script),
            ("Assets/Plugins/MyLib.dll", AssetType::Dll),
            ("Assets/Textures/logo.png", AssetType::Texture),
            ("Assets/Prefabs/MyPrefab.prefab", AssetType::Prefab),
        ];

        for (path, at) in paths {
            let meta_content = format!("meta for {path}");
            tree.entries.insert(
                path.replace('/', "_"),
                PackageEntry {
                    original_path: path.to_string(),
                    asset_type: at,
                    bytes: vec![0u8; 42],
                    meta_content: Some(meta_content),
                },
            );
        }

        build_tree(&tree, "testpackage")
    }

    #[test]
    fn tree_root_name_matches() {
        let root = build_test_tree();
        assert_eq!(root.name, "testpackage");
        assert_eq!(root.asset_type, None);
    }

    #[test]
    fn directories_before_files() {
        let root = build_test_tree();
        for child in root.children.windows(2) {
            let first_is_dir = child[0].asset_type.is_none();
            let second_is_dir = child[1].asset_type.is_none();
            if !first_is_dir && second_is_dir {
                panic!(
                    "Directory {} found after file {}",
                    child[1].name, child[0].name
                );
            }
        }
    }

    #[test]
    fn txt_pretty_uses_unicode() {
        let root = build_test_tree();
        let opts = TreeOptions { pretty: true };
        let output = render_txt(&root, &opts, 5);
        assert!(output.contains('\u{251C}') || output.contains('\u{2514}'));
        assert!(!output.contains("|--"));
        assert!(!output.contains("`--"));
    }

    #[test]
    fn txt_ascii_no_unicode() {
        let root = build_test_tree();
        let opts = TreeOptions { pretty: false };
        let output = render_txt(&root, &opts, 5);
        assert!(!output.contains('\u{251C}'));
        assert!(!output.contains('\u{2514}'));
        assert!(output.contains("|--") || output.contains("`--"));
    }

    #[test]
    fn txt_contains_entry_names() {
        let root = build_test_tree();
        let opts = TreeOptions { pretty: true };
        let output = render_txt(&root, &opts, 5);
        assert!(output.contains("MyScript.cs"));
        assert!(output.contains("Utils.cs"));
        assert!(output.contains("MyLib.dll"));
        assert!(output.contains("logo.png"));
        assert!(output.contains("MyPrefab.prefab"));
    }

    #[test]
    fn json_is_valid() {
        let root = build_test_tree();
        let output = render_json(&root, 5, "testpackage");
        let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
        assert_eq!(parsed["file"], "testpackage");
        assert_eq!(parsed["total_entries"], 5);
        assert!(parsed["tree"]["children"].is_array());
    }

    #[test]
    fn json_contains_types() {
        let root = build_test_tree();
        let output = render_json(&root, 5, "testpackage");
        assert!(output.contains("\"type\": \"C#\""));
        assert!(output.contains("\"type\": \"DLL\""));
        assert!(output.contains("\"type\": \"Tex\""));
        assert!(output.contains("\"type\": \"directory\""));
    }

    #[test]
    fn xml_is_well_formed() {
        let root = build_test_tree();
        let output = render_xml(&root, 5, "testpackage");
        assert!(output.starts_with("<?xml"));
        assert!(output.contains("<package name=\"testpackage\""));
        assert!(output.contains("</package>"));
        assert!(output.contains("<directory"));
        assert!(output.contains("</directory>"));
        assert!(output.contains("<file"));
    }

    #[test]
    fn xml_contains_types() {
        let root = build_test_tree();
        let output = render_xml(&root, 5, "testpackage");
        assert!(output.contains("type=\"C#\""));
        assert!(output.contains("type=\"DLL\""));
        assert!(output.contains("type=\"Tex\""));
    }

    #[test]
    fn xml_escapes_special_chars() {
        let root = build_test_tree();
        let output = render_xml(&root, 5, "test & package");
        assert!(output.contains("test &amp; package"));
    }

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
    }

    #[test]
    fn empty_package_tree() {
        let tree = PackageTree::new();
        let root = build_tree(&tree, "empty");
        assert_eq!(root.name, "empty");
        assert!(root.children.is_empty());
    }

    #[test]
    fn entry_without_meta() {
        let mut tree = PackageTree::new();
        tree.entries.insert(
            "guid1".to_string(),
            PackageEntry {
                original_path: "Assets/NoMeta.cs".to_string(),
                asset_type: AssetType::Script,
                bytes: vec![0u8; 10],
                meta_content: None,
            },
        );

        let root = build_tree(&tree, "test");
        let output = render_txt(&root, &TreeOptions { pretty: false }, 1);
        // Should show the file but not a .meta child
        assert!(output.contains("NoMeta.cs"));
        assert!(!output.contains(".meta"));
    }

    #[test]
    fn meta_content_adds_child() {
        let mut tree = PackageTree::new();
        tree.entries.insert(
            "guid1".to_string(),
            PackageEntry {
                original_path: "Assets/HasMeta.cs".to_string(),
                asset_type: AssetType::Script,
                bytes: vec![0u8; 10],
                meta_content: Some("guid: abc123".to_string()),
            },
        );

        let root = build_tree(&tree, "test");
        let output = render_txt(&root, &TreeOptions { pretty: false }, 1);
        assert!(output.contains("HasMeta.cs"));
        assert!(output.contains(".meta"));
    }
}
