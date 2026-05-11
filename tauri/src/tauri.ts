/**
 * Typed wrappers around Tauri's invoke() for every backend command.
 * Import these instead of calling invoke() directly.
 */

import { invoke, Channel } from "@tauri-apps/api/core";
import type { ScanReport, ScanProgress, SanitizeResult, ExportResult, TreeNode } from "./types.js";

// ── Scan ─────────────────────────────────────────────────────────────────────

export async function scanFile(
  path: string,
  index: number,
  total: number,
  onProgress: (p: ScanProgress) => void
): Promise<ScanReport> {
  const channel = new Channel<ScanProgress>();
  channel.onmessage = onProgress;
  return invoke<ScanReport>("scan_file", { path, index, total, onProgress: channel });
}

export async function collectPackages(paths: string[]): Promise<string[]> {
  return invoke<string[]>("collect_packages", { paths });
}

export async function saveReport(content: string, path: string): Promise<void> {
  return invoke<void>("save_report", { content, path });
}

export async function generateTxtReport(report: any): Promise<string> {
  return invoke<string>("generate_txt_report", { report });
}

// ── Sanitize ─────────────────────────────────────────────────────────────────

export async function sanitizeFile(
  path: string,
  outputPath: string,
  minSeverity: string,
  dryRun: boolean
): Promise<SanitizeResult> {
  return invoke<SanitizeResult>("sanitize_file", { path, outputPath, minSeverity, dryRun });
}

// ── Export ───────────────────────────────────────────────────────────────────

export async function exportFile(
  path: string,
  outputType: string,
  outDir: string,
  skipMeta: boolean
): Promise<ExportResult> {
  return invoke<ExportResult>("export_file", { path, outputType, outDir, skipMeta });
}

// ── Tree ─────────────────────────────────────────────────────────────────────

export async function getTree(path: string): Promise<TreeNode> {
  return invoke<TreeNode>("get_tree", { path });
}

export async function exportTree(path: string, format: string): Promise<string> {
  return invoke<string>("export_tree", { path, format });
}

// ── Filesystem helpers ────────────────────────────────────────────────────────

/** Returns true if the file/directory at `path` exists on disk. */
export async function fileExists(path: string): Promise<boolean> {
  const { exists } = await import("@tauri-apps/plugin-fs");
  return exists(path);
}
