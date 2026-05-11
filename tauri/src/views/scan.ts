/**
 * Scan view — two modes:
 *   • "drop"   — drop zone + inline options (shown before and between scans)
 *   • "result" — full-height results + integrated file tree (shown after scan)
 *
 * The view switches to "result" mode as soon as any scan completes.
 * A "← New Scan" button at the top of the result view returns to "drop" mode.
 */

import { mountDropZone } from "../components/drop-zone.js";
import { mountResultsCard } from "../components/results-card.js";
import { mountSanitizePanel } from "../components/sanitize-panel.js";
import { mountTreeViewer } from "../components/tree-viewer.js";
import { scanFile, collectPackages, saveReport, generateTxtReport, sanitizeFile, exportFile, getTree, exportTree, fileExists } from "../tauri.js";
import { store } from "../store.js";
import { Icons, basename } from "../icons.js";
import { persistScanResult, updateTreeCache } from "./history.js";
import { showView, onViewChange } from "../router.js";
import type { ScanItem, ScanReport, TreeNode } from "../types.js";
import type { HistoryEntry } from "../types.js";

const container = () => document.getElementById("view-scan")!;

// ─── Small helpers ──────────────────────────────────────────────────────────

function riskBadge(level: string): string {
  const cls: Record<string, string> = {
    CLEAN:    "border border-green-500  text-green-400",
    LOW:      "border border-blue-500   text-blue-400",
    MEDIUM:   "border border-yellow-500 text-yellow-400",
    HIGH:     "border border-orange-500 text-orange-400",
    CRITICAL: "border border-red-500    text-red-400",
    ERROR:    "border border-slate-500  text-slate-400",
  };
  return `<span class="px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${cls[level] ?? cls.ERROR}">${level}</span>`;
}

function progressRowHtml(item: ScanItem): string {
  const spinner = `<span class="spinner text-slate-500">${Icons.spinner("w-4 h-4")}</span>`;
  const check   = Icons.checkCircle("w-4 h-4 text-green-500");
  const err     = Icons.alertCircle("w-4 h-4 text-red-400");

  const icon = item.status === "scanning" ? spinner
             : item.status === "done"     ? check
             : item.status === "error"    ? err
             : Icons.clock("w-4 h-4 text-slate-700");

  const badge = item.report ? riskBadge(item.report.risk.level) : "";

  return `
    <div class="flex items-center gap-3 border-b border-white/[0.06] px-3 py-2.5" data-path="${item.path}">
      <span>${icon}</span>
      <span class="flex-1 truncate text-sm text-slate-400">${basename(item.path)}</span>
      ${badge}
      ${item.error ? `<span class="text-xs text-red-400 truncate max-w-[200px]">${item.error}</span>` : ""}
    </div>`;
}

// ─── Module state ────────────────────────────────────────────────────────────

let dropZoneHandle: ReturnType<typeof mountDropZone> | null = null;
let lastReport: ScanReport | null = null;
let lastPath:   string | null = null;

// ─── Drop mode ───────────────────────────────────────────────────────────────

function renderDropMode() {
  const el = container();
  el.innerHTML = `
    <div class="w-full flex flex-col gap-5 overflow-y-auto flex-1">
      <h2 class="text-base font-semibold uppercase tracking-widest text-slate-300">Scan</h2>

      <div id="sv-dropzone"></div>

      <!-- Progress queue (shown during multi-file scans) -->
      <div id="sv-queue" class="border border-white/[0.06] hidden"></div>
    </div>`;

  const dzEl = document.getElementById("sv-dropzone")!;
  dropZoneHandle = mountDropZone(dzEl, { onDrop: handleDrop });
}

// ─── Result mode ─────────────────────────────────────────────────────────────

type ResultOrigin = "drop" | "history";

function renderResultMode(
  report: ScanReport,
  path: string,
  origin: ResultOrigin = "drop",
  cachedTree?: TreeNode
) {
  const el = container();
  const backLabel = origin === "history" ? "History" : "New Scan";

  el.innerHTML = `
    <div class="flex flex-col gap-0 h-full min-h-0">

      <!-- Top bar -->
      <div class="flex items-center gap-3 mb-4 flex-shrink-0">
        <button id="sv-back" class="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors">
          ${Icons.chevronLeft("w-4 h-4")}
          <span>${backLabel}</span>
        </button>
        <span class="text-slate-700">|</span>
        <span class="text-xs text-slate-500 truncate">${basename(path)}</span>
      </div>

      <!-- Two-column layout: results left, tree right -->
      <div class="flex gap-4 flex-1 min-h-0 overflow-hidden">

        <!-- Left: results card + sanitize panel -->
        <div class="flex flex-col gap-4 overflow-y-auto flex-shrink-0" style="width:55%">
          <div id="sv-results"></div>
          <div id="sv-sanitize"></div>
        </div>

        <!-- Right: file tree (fills all remaining height) -->
        <div class="flex flex-col flex-1 min-h-0 min-w-0 border border-white/[0.06]">
          <div class="flex items-center gap-3 px-3 py-2 border-b border-white/[0.06] flex-shrink-0">
            <p class="text-[11px] font-semibold uppercase tracking-widest text-slate-400">File Tree</p>
            <div class="ml-auto flex gap-1.5" id="sv-tree-exports"></div>
          </div>
          <div id="sv-tree-content" class="flex-1 overflow-auto min-h-0"></div>
        </div>

      </div>
    </div>`;

  // Back button — returns to the correct origin
  document.getElementById("sv-back")?.addEventListener("click", () => {
    if (origin === "history") {
      showView("history");
      renderDropMode(); // reset scan view silently so it's clean for next use
    } else {
      lastReport = null;
      lastPath   = null;
      renderDropMode();
    }
  });

  // Mount results card
  const resultsEl = document.getElementById("sv-results")!;
  mountResultsCard(resultsEl, report, {
    onSave:     () => handleSave(report),
    onSanitize: () => handleSanitize(path, report),
    onExport:   () => handleExport(path),
  });

  // Load file tree (uses cache when available)
  loadTree(path, cachedTree);
}

/**
 * Open a scan report in the full result view.
 * Called by the history view when the user clicks on a past scan.
 * Navigates to the scan panel and renders it in result mode.
 */
export function openReportDetail(entry: HistoryEntry) {
  showView("scan", "history");
  renderResultMode(entry.report, entry.filename, "history", entry.tree);
}

async function loadTree(path: string, cachedTree?: TreeNode) {
  const treeContent = document.getElementById("sv-tree-content");
  const treeExports = document.getElementById("sv-tree-exports");
  if (!treeContent) return;

  // Use cached tree immediately — no spinner, no Rust call
  if (cachedTree) {
    mountTreeViewer(treeContent, cachedTree);
    mountTreeExportButtons(treeExports, path);
    return;
  }

  treeContent.innerHTML = `
    <div class="flex items-center justify-center h-full text-slate-600 gap-2">
      <span class="spinner">${Icons.spinner("w-4 h-4")}</span>
      <span class="text-xs">Loading tree…</span>
    </div>`;

  try {
    const tree = await getTree(path);
    mountTreeViewer(treeContent, tree);
    mountTreeExportButtons(treeExports, path);

    // Persist tree into the matching HistoryEntry so next open is instant
    updateTreeCache(path, tree);
  } catch (e) {
    if (treeContent) {
      treeContent.innerHTML = `<div class="flex items-center justify-center h-full text-red-400 text-xs">Tree failed: ${e}</div>`;
    }
  }
}

function mountTreeExportButtons(container: HTMLElement | null, path: string) {
  if (!container) return;
  container.innerHTML = ["txt","json","xml"].map(fmt =>
    `<button class="tree-export-btn border border-white/10 px-2 py-0.5 text-[11px] text-slate-400 hover:text-slate-200 hover:border-white/20 transition-colors" data-fmt="${fmt}">${fmt.toUpperCase()}</button>`
  ).join("");

  container.querySelectorAll<HTMLButtonElement>(".tree-export-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const fmt = btn.dataset.fmt!;
      const content = await exportTree(path, fmt);
      const { save } = await import("@tauri-apps/plugin-dialog");
      const dest = await save({ filters: [{ name: "Tree", extensions: [fmt] }] });
      if (dest) await saveReport(content, dest);
    });
  });
}

// ─── Scan orchestration ───────────────────────────────────────────────────────

async function handleDrop(rawPaths: string[]) {
  const paths = await collectPackages(rawPaths);
  if (paths.length === 0) {
    showDropError("No scannable files found in the dropped items.");
    return;
  }

  const items: ScanItem[] = paths.map((p) => ({
    path: p,
    filename: basename(p),
    status: "pending",
  }));
  store.setScanItems(items);
  store.setScanning(true);
  dropZoneHandle?.setScanning(true);
  renderQueue();

  for (let i = 0; i < paths.length; i++) {
    const path = paths[i];
    store.updateScanItem(path, { status: "scanning" });
    renderQueue();

    try {
      const report = await scanFile(path, i, paths.length, (progress) => {
        if (progress.status === "done" && progress.result) {
          store.updateScanItem(path, { status: "done", report: progress.result });
          renderQueue();
        }
      });

      store.updateScanItem(path, { status: "done", report });
      lastReport = report;
      lastPath   = path;

      // Persist to history immediately after each successful scan
      const entry: HistoryEntry = {
        sha256:       report.file.sha256,
        filename:     path,
        scanned_at:   new Date().toISOString(),
        risk_level:   report.risk.level,
        score:        report.risk.score,
        finding_count: report.findings.length,
        report,
        // tree will be written by loadTree() after it resolves
      };
      persistScanResult(entry).catch(console.error);
    } catch (e) {
      store.updateScanItem(path, { status: "error", error: String(e) });
    }
    renderQueue();
  }

  store.setScanning(false);

  // Switch to result mode
  if (lastReport && lastPath) {
    renderResultMode(lastReport, lastPath);
  } else {
    dropZoneHandle?.setScanning(false);
  }
}

function renderQueue() {
  const queue = document.getElementById("sv-queue");
  if (!queue) return;
  const items = store.scanItems;
  if (items.length === 0) { queue.classList.add("hidden"); return; }
  queue.classList.remove("hidden");
  queue.innerHTML = items.map(progressRowHtml).join("");
}

function showDropError(msg: string) {
  const el = document.getElementById("sv-queue");
  if (!el) return;
  el.classList.remove("hidden");
  el.innerHTML = `<div class="px-4 py-3 text-sm text-red-400">${msg}</div>`;
}

// ─── Action handlers ──────────────────────────────────────────────────────────

async function handleSave(report: ScanReport) {
  const { save } = await import("@tauri-apps/plugin-dialog");
  const { settings } = store;
  const ext = settings.defaultOutputFormat;

  // Default filename: "MyPackage.unitypackage - report 2026-05-11.txt"
  const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const name = basename(report.file.path);
  const defaultPath = `${name}-scan-report-${date}.${ext}`;

  const dest = await save({ defaultPath, filters: [{ name: "Report", extensions: [ext] }] });
  if (!dest) return;
  const content = ext === "json"
    ? JSON.stringify(report, null, 2)
    : await generateTxtReport(report);
  await saveReport(content, dest);
}

async function handleSanitize(path: string, _report: ScanReport) {
  // Guard: source file must still exist
  if (!await fileExists(path)) {
    const panel = document.getElementById("sv-sanitize")!;
    panel.innerHTML = `<div class="flex items-center gap-2 border border-red-500/20 bg-red-500/[0.04] px-4 py-3 text-sm text-red-400">
      ${Icons.alertCircle("w-4 h-4")} Cannot sanitize — original file no longer exists: <span class="font-mono text-xs ml-1 truncate">${basename(path)}</span>
    </div>`;
    return;
  }

  const { save } = await import("@tauri-apps/plugin-dialog");
  const { settings } = store;
  const baseName = basename(path).replace(/\.unitypackage$/, "");
  const dest = await save({
    defaultPath: `${baseName}-sanitized.unitypackage`,
    filters: [{ name: "Unity Package", extensions: ["unitypackage"] }],
  });
  if (!dest && !settings.dryRunSanitize) return;

  try {
    const result = await sanitizeFile(
      path,
      dest ?? path,
      settings.defaultMinSeverity,
      settings.dryRunSanitize
    );
    const panel = document.getElementById("sv-sanitize")!;
    mountSanitizePanel(panel, result);
    panel.scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    const panel = document.getElementById("sv-sanitize")!;
    panel.innerHTML = `<div class="px-4 py-3 text-sm text-red-400">Sanitize failed: ${e}</div>`;
  }
}

async function handleExport(path: string) {
  // Guard: source file must still exist
  if (!await fileExists(path)) {
    const panel = document.getElementById("sv-sanitize")!;
    panel.innerHTML = `<div class="flex items-center gap-2 border border-red-500/20 bg-red-500/[0.04] px-4 py-3 text-sm text-red-400">
      ${Icons.alertCircle("w-4 h-4")} Cannot export — original file no longer exists: <span class="font-mono text-xs ml-1 truncate">${basename(path)}</span>
    </div>`;
    return;
  }

  const { save, open } = await import("@tauri-apps/plugin-dialog");
  const { settings } = store;
  let dest: string | null = null;

  if (settings.exportType === "zip") {
    dest = await save({ filters: [{ name: "ZIP", extensions: ["zip"] }] });
  } else {
    const result = await open({ directory: true });
    dest = Array.isArray(result) ? result[0] : result;
  }
  if (!dest) return;

  try {
    await exportFile(path, settings.exportType, dest, settings.skipMeta);
    const panel = document.getElementById("sv-sanitize")!;
    panel.innerHTML = `<div class="flex items-center gap-2 border border-green-500/20 bg-green-500/[0.04] px-4 py-3 text-sm text-green-400">
      ${Icons.checkCircle("w-4 h-4")}Export complete → ${dest}
    </div>`;
  } catch (e) {
    const panel = document.getElementById("sv-sanitize")!;
    panel.innerHTML = `<div class="px-4 py-3 text-sm text-red-400">Export failed: ${e}</div>`;
  }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export function initScanView() {
  renderDropMode();

  // Reset to drop mode whenever the user navigates directly to Scan.
  // When origin is history (nav === "history"), the panel shows a detail view
  // so we must NOT reset it — the condition on `nav` guards that.
  onViewChange((v, nav) => {
    if (v === "scan" && nav === "scan" && !store.scanning) {
      lastReport = null;
      lastPath   = null;
      renderDropMode();
    }
  });
}
