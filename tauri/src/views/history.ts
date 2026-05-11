/**
 * History view — table layout matching the web version.
 * Columns: DATE | FILE | HASH | RISK | SCORE | FINDINGS
 */

import { Icons, basename } from "../icons.js";
import { store } from "../store.js";
import { openReportDetail } from "./scan.js";
import type { HistoryEntry, RiskLevel, TreeNode } from "../types.js";

const HISTORY_STORE_KEY = "scan_history";
let pluginStore: Awaited<ReturnType<typeof loadStore>> | null = null;

async function loadStore() {
  const { load } = await import("@tauri-apps/plugin-store");
  return load("vrcstorage.bin", { defaults: {}, autoSave: true });
}

/** Colored bordered badge — same style as the web */
function riskBadge(level: RiskLevel): string {
  const cls: Record<RiskLevel, string> = {
    CLEAN: "border border-green-500  text-green-400",
    LOW: "border border-blue-500   text-blue-400",
    MEDIUM: "border border-yellow-500 text-yellow-400",
    HIGH: "border border-orange-500 text-orange-400",
    CRITICAL: "border border-red-500    text-red-400",
    ERROR: "border border-slate-500  text-slate-400",
  };
  return `<span class="px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${cls[level] ?? cls.ERROR}">${level}</span>`;
}

export async function initHistoryView() {
  const el = document.getElementById("view-history")!;
  el.innerHTML = `
    <div class="w-full flex flex-col gap-4">
      <!-- Header -->
      <div class="flex items-center gap-4">
        <h2 class="text-base font-semibold uppercase tracking-widest text-slate-300">Scan History</h2>
        <button id="hv-clear" class="ml-auto flex items-center gap-1.5 border border-white/10 px-2.5 py-1 text-xs text-slate-400 hover:text-red-400 hover:border-red-500/30 transition-colors">
          ${Icons.trash("w-3.5 h-3.5")} Clear all
        </button>
      </div>

      <!-- Table -->
      <div id="hv-list"></div>
    </div>`;

  pluginStore = await loadStore();
  const raw = await pluginStore.get<HistoryEntry[]>(HISTORY_STORE_KEY);
  store.setHistory(raw ?? []);

  renderList();

  // Re-render whenever a new scan is persisted (e.g. from the scan view)
  store.on("history", () => renderList());

  document.getElementById("hv-clear")?.addEventListener("click", async () => {
    store.setHistory([]);
    await pluginStore!.set(HISTORY_STORE_KEY, []);
    renderList();
  });
}

function renderList() {
  const list = document.getElementById("hv-list")!;
  const entries = store.history;

  if (entries.length === 0) {
    list.innerHTML = `
      <div class="flex flex-col items-center gap-2 py-16 text-slate-700">
        ${Icons.history("w-8 h-8")}
        <p class="text-sm">No scans yet — drop a file in the Scan tab.</p>
      </div>`;
    return;
  }

  // Table header
  const thCls = "px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500";
  const header = `
    <div class="grid grid-cols-[120px_1fr_130px_90px_70px_80px] border-b border-white/[0.08]">
      <span class="${thCls}">Date</span>
      <span class="${thCls}">File</span>
      <span class="${thCls}">Hash</span>
      <span class="${thCls}">Risk</span>
      <span class="${thCls}">Score</span>
      <span class="${thCls}">Findings</span>
    </div>`;

  const rows = entries.map((entry, idx) => {
    const date = new Date(entry.scanned_at);
    const relDate = formatRelDate(date);
    const hash = entry.report.file.sha256.slice(0, 8) + "...";
    // const dur = formatDuration(entry.report.scan_duration_ms);

    return `
      <button
        class="history-row grid grid-cols-[120px_1fr_130px_90px_70px_80px] w-full text-left border-b border-white/[0.05] hover:bg-white/[0.03] transition-colors"
        data-idx="${idx}"
      >
        <span class="px-4 py-3 text-xs text-slate-500">${relDate}</span>
        <span class="px-4 py-3 truncate text-sm text-slate-300">${basename(entry.filename)}</span>
        <span class="px-4 py-3 font-mono text-xs text-slate-600">${hash}</span>
        <span class="px-4 py-3">${riskBadge(entry.risk_level)}</span>
        <span class="px-4 py-3 text-xs tabular-nums text-slate-400">${entry.score}</span>
        <span class="px-4 py-3 text-xs tabular-nums text-slate-400">${entry.finding_count}</span>
      </button>`;
  }).join("");

  list.innerHTML = header + rows;

  list.querySelectorAll<HTMLButtonElement>(".history-row").forEach((btn) => {
    btn.addEventListener("click", () => {
      const entry = store.history[Number(btn.dataset.idx)];
      openReportDetail(entry);
    });
  });
}

function formatRelDate(d: Date): string {
  const diff = Date.now() - d.getTime();
  const h = Math.floor(diff / 3_600_000);
  if (h < 1) return "Just now";
  if (h < 24) return `${h}h ago`;
  const days = Math.floor(h / 24);
  if (days < 7) return `${days}d ago`;
  return d.toLocaleDateString();
}

/**
 * Called from scan view after a successful scan to persist the result.
 */
export async function persistScanResult(entry: HistoryEntry) {
  store.prependHistory(entry);
  if (!pluginStore) pluginStore = await loadStore();
  await pluginStore.set(HISTORY_STORE_KEY, store.history);
}

/**
 * Called by loadTree() after the tree is fetched for the first time.
 * Patches the in-memory HistoryEntry and flushes to disk so subsequent
 * opens of the same scan are instant (no Rust re-fetch).
 */
export async function updateTreeCache(filename: string, tree: TreeNode) {
  const idx = store.history.findIndex((e) => e.filename === filename);
  if (idx === -1) return; // scan not in history (e.g. direct drop without save)

  // Patch in-memory entry
  const updated: HistoryEntry = { ...store.history[idx], tree };
  const next = [...store.history];
  next[idx] = updated;
  store.setHistory(next);

  // Flush to disk
  if (!pluginStore) pluginStore = await loadStore();
  await pluginStore.set(HISTORY_STORE_KEY, store.history);
}
