/**
 * Tree viewer component — interactive collapsible file-tree rendered from TreeNode data.
 *
 * Key invariants (matching the Rust tree module):
 *  - Directory nodes have  type === "directory"  (set explicitly by render_json).
 *  - File nodes have a specific asset type label: "C#", "DLL", "Tex", "Prefab",
 *    "SO", "Audio", "Anim", "Meta", or "Other(<ext>)".
 *  - Unity packages store folders as real GUID assets too, so the Rust tree builder
 *    may emit BOTH a directory node AND a file node with the same name at the same level.
 *    The file-node duplicate is always redundant and must be filtered out.
 */

import { Icons, formatBytes } from "../icons.js";
import type { TreeNode } from "../types.js";

// ── Colour per Rust asset-type label ─────────────────────────────────────────

const TYPE_COLOR: Record<string, string> = {
  // Rust labels (as emitted by asset_type_label())
  "c#":     "text-cyan-400",
  "dll":    "text-red-400",
  "prefab": "text-violet-400",
  "so":     "text-violet-300",
  "tex":    "text-emerald-400",
  "audio":  "text-amber-400",
  "shader": "text-fuchsia-400",
  "anim":   "text-sky-400",
  "fbx":    "text-orange-400",
  "mat":    "text-orange-300",
  "meta":   "text-slate-600",
  "other":  "text-slate-400",
};

// ── Icon per Rust asset-type label ────────────────────────────────────────────

function typeIcon(type?: string): string {
  switch (type?.toLowerCase()) {
    case "c#":      return "fileCode";
    case "dll":     return "cpu";
    case "prefab":  return "box";
    case "so":      return "box";
    case "tex":     return "image";
    case "audio":   return "music";
    case "shader":  return "layers";
    case "anim":    return "file";
    case "fbx":     return "box";      // 3-D mesh
    case "mat":     return "layers";   // material / surface
    case "meta":    return "file";
    default:        return "file";
  }
}

function nodeColor(type?: string): string {
  const key = type?.toLowerCase() ?? "";
  return TYPE_COLOR[key] ?? "text-slate-400";
}

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ── Node classification ───────────────────────────────────────────────────────

/**
 * A node is a TRUE directory only when the Rust JSON renderer set type = "directory".
 * That only happens for intermediate path-split nodes (asset_type = None in Rust).
 *
 * Unity packages also store each folder as a real GUID asset. Those entries end up
 * as leaf file nodes with type = "" (AssetType::Other("") → empty label) or some
 * concrete type — they are NOT real directories and must be treated as file nodes.
 */
function isDirectory(node: TreeNode): boolean {
  // Treat missing type (null/undefined) as directory for safety, but NOT empty string.
  return node.type === "directory" || node.type == null;
}

// ── renderNode ────────────────────────────────────────────────────────────────

function renderNode(node: TreeNode, depth: number, autoExpand: boolean): string {
  const indent = depth * 14;

  // 1. Strip .meta children — implementation detail, not user-facing assets.
  const withoutMeta = (node.children ?? []).filter(
    (c) => c.type?.toLowerCase() !== "meta"
  );

  // 2. Collect names of TRUE directory children (type === "directory" or no type).
  //    Unity packages often emit a folder as both a directory node (from path splitting)
  //    AND a file-asset node (the folder's own GUID entry, type = "Other" or similar).
  //    We remove the redundant file-asset copy whenever a same-named directory exists.
  const dirChildNames = new Set(
    withoutMeta.filter(isDirectory).map((c) => c.name)
  );

  const visibleChildren = withoutMeta.filter((c) => {
    // Always keep true directories.
    if (isDirectory(c)) return true;
    // For file nodes: suppress if a same-named directory already exists at this level.
    return !dirChildNames.has(c.name);
  });

  // 3. Determine whether THIS node is a directory.
  const thisIsDir = isDirectory(node);

  const expanded = autoExpand && depth < 2;

  // ── Directory branch ───────────────────────────────────────────────────────
  if (thisIsDir) {
    // Root node with no children → render a simple placeholder.
    if (visibleChildren.length === 0 && depth === 0) {
      return `<div class="flex items-center justify-center h-full text-slate-600 text-xs">Package is empty</div>`;
    }

    const childrenHtml = visibleChildren
      .map((child) => renderNode(child, depth + 1, autoExpand))
      .join("");

    return `
      <div class="tree-dir" data-expanded="${expanded}">
        <div class="tree-dir-header flex items-center gap-1.5 min-w-0 overflow-hidden px-2 py-1 text-xs hover:bg-white/[0.04] cursor-pointer transition-colors duration-100 group" style="padding-left:${indent + 8}px">
          <span class="text-slate-600 dir-chevron flex-shrink-0">${expanded ? Icons.chevronDown("w-3.5 h-3.5") : Icons.chevronRight("w-3.5 h-3.5")}</span>
          <span class="text-amber-400 flex-shrink-0">${Icons.folder("w-3.5 h-3.5")}</span>
          <span class="font-medium text-slate-300 group-hover:text-slate-100 truncate min-w-0">${escHtml(node.name)}</span>
          <span class="ml-auto flex-shrink-0 text-[10px] text-slate-700 pl-2">${visibleChildren.length} items</span>
        </div>
        <div class="tree-dir-children ${expanded ? "" : "hidden"}">${childrenHtml}</div>
      </div>`;
  }

  // ── File leaf ──────────────────────────────────────────────────────────────
  const color   = nodeColor(node.type);
  const iconKey = typeIcon(node.type);
  const iconSvg = (Icons[iconKey as keyof typeof Icons] as (cls: string) => string)("w-3.5 h-3.5");

  const HIDDEN_BADGE = new Set(["other", "directory", ""]);
  const typeStr = node.type?.toLowerCase() ?? "";
  const badge = node.type && !HIDDEN_BADGE.has(typeStr)
    ? `<span class="flex-shrink-0 ml-1 rounded px-1 py-0.5 text-[9px] font-semibold uppercase tracking-wider bg-white/[0.04] ${color}">${node.type}</span>`
    : "";

  const size = node.size_bytes
    ? `<span class="flex-shrink-0 text-[10px] text-slate-700 pl-1">${formatBytes(node.size_bytes)}</span>`
    : "";

  const noMeta = node.has_meta === false
    ? `<span class="flex-shrink-0 rounded bg-amber-500/10 px-1 py-0.5 text-[9px] text-amber-600">no .meta</span>`
    : "";

  return `
    <div class="flex items-center gap-1.5 min-w-0 overflow-hidden px-2 py-1 text-xs hover:bg-white/[0.03]" style="padding-left:${indent + 8}px">
      <span class="w-3.5 flex-shrink-0"></span>
      <span class="${color} flex-shrink-0">${iconSvg}</span>
      <span class="truncate text-slate-400 min-w-0">${escHtml(node.name)}</span>
      ${badge}${size}${noMeta}
    </div>`;
}

// ── Public mount function ─────────────────────────────────────────────────────

export function mountTreeViewer(container: HTMLElement, root: TreeNode) {
  container.innerHTML = `
    <div class="h-full overflow-auto p-3">
      ${renderNode(root, 0, true)}
    </div>`;

  // Bind click handlers for directory toggle
  container.querySelectorAll<HTMLElement>(".tree-dir-header").forEach((header) => {
    header.addEventListener("click", () => {
      const dir = header.closest<HTMLElement>(".tree-dir")!;
      const expanded = dir.dataset.expanded === "true";
      dir.dataset.expanded = String(!expanded);

      const children = dir.querySelector<HTMLElement>(".tree-dir-children")!;
      children.classList.toggle("hidden", expanded);

      const chevron = header.querySelector(".dir-chevron");
      if (chevron) {
        chevron.innerHTML = !expanded
          ? Icons.chevronDown("w-3.5 h-3.5")
          : Icons.chevronRight("w-3.5 h-3.5");
      }
    });
  });
}
