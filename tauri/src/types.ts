// ─── Shared TypeScript types ──────────────────────────────────────────────────
// Mirror the Rust structs serialized over Tauri IPC.

export type Severity = "Low" | "Medium" | "High" | "Critical";
export type RiskLevel = "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "ERROR";

// ── Scan report ───────────────────────────────────────────────────────────────

export interface Finding {
  id: string;
  severity: Severity;
  points: number;
  location: string;
  detail: string;
  context?: string;
  line_numbers?: number[];
}

export interface RiskSummary {
  score: number;
  level: RiskLevel;
  recommendation: string;
}

export interface AssetCounts {
  total: number;
  dlls: number;
  scripts: number;
  textures: number;
  prefabs: number;
  audio: number;
  other: number;
}

export interface FileRecord {
  path: string;
  size_bytes: number;
  file_type: string;
  sha256: string;
  md5: string;
  sha1: string;
  timestamp: string;
}

export interface ScanReport {
  schema_version: string;
  scanner: string;
  file: FileRecord;
  risk: RiskSummary;
  findings: Finding[];
  assets_analyzed: AssetCounts;
  scan_duration_ms: number;
  file_tree?: FlatEntry[];
}

export interface FlatEntry {
  path: string;
  asset_type: string;
  size_bytes: number;
  has_meta: boolean;
}

export interface ScanProgress {
  path: string;
  status: "scanning" | "done" | "error";
  result?: ScanReport;
  error?: string;
  index: number;
  total: number;
}

// ── Per-file UI state ─────────────────────────────────────────────────────────

export type FileStatus = "pending" | "scanning" | "done" | "error";

export interface ScanItem {
  path: string;
  filename: string;
  status: FileStatus;
  report?: ScanReport;
  error?: string;
}

// ── Sanitize ─────────────────────────────────────────────────────────────────

export interface SanitizeResult {
  neutralized_count: number;
  removed_count: number;
  skipped_count: number;
  kept_count: number;
  original_score: number;
  residual_score: number;
  output_path?: string;
  dry_run: boolean;
  threshold: string;
}

// ── Export ───────────────────────────────────────────────────────────────────

export interface ExportResult {
  output_path: string;
  output_type: "folder" | "zip";
  skip_meta: boolean;
  total_entries: number;
  exported_assets: number;
  exported_meta: number;
  skipped_empty: number;
  skipped_unsafe: number;
  warnings: string[];
}

// ── Tree ─────────────────────────────────────────────────────────────────────

export interface TreeNode {
  name: string;
  type?: string;
  size_bytes?: number;
  has_meta?: boolean;
  children?: TreeNode[];
}

// ── History ──────────────────────────────────────────────────────────────────

export interface HistoryEntry {
  sha256: string;
  filename: string;
  scanned_at: string;
  risk_level: RiskLevel;
  score: number;
  finding_count: number;
  report: ScanReport;
  /** Cached file tree — populated after first load, avoids re-fetching from Rust. */
  tree?: TreeNode;
}

// ── Settings ─────────────────────────────────────────────────────────────────

export interface AppSettings {
  defaultMinSeverity: Severity;
  defaultOutputFormat: "txt" | "json";
  verboseFindings: boolean;
  autoSaveReport: boolean;
  theme: "dark" | "light" | "system";
  shareResults: "ask" | "always" | "never";
  skipMeta: boolean;
  exportType: "folder" | "zip";
  dryRunSanitize: boolean;
}

export const DEFAULT_SETTINGS: AppSettings = {
  defaultMinSeverity: "High",
  defaultOutputFormat: "txt",
  verboseFindings: false,
  autoSaveReport: false,
  theme: "dark",
  shareResults: "ask",
  skipMeta: false,
  exportType: "folder",
  dryRunSanitize: false,
};
