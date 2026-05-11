/**
 * AppStore — module-level reactive state backed by a plain EventTarget.
 *
 * Components call store.on('change', handler) to subscribe.
 * Mutations go through store.set*() helpers which always dispatch 'change'.
 */

import type { AppSettings, HistoryEntry, ScanItem } from "./types.js";
import { DEFAULT_SETTINGS } from "./types.js";

class AppStore extends EventTarget {
  // ── Active scan session ─────────────────────────────────────────────────
  scanItems: ScanItem[] = [];
  scanning = false;

  // ── History ─────────────────────────────────────────────────────────────
  history: HistoryEntry[] = [];

  // ── Settings ─────────────────────────────────────────────────────────────
  settings: AppSettings = { ...DEFAULT_SETTINGS };

  // ── Mutation helpers ─────────────────────────────────────────────────────

  setScanItems(items: ScanItem[]) {
    this.scanItems = items;
    this._emit("scanItems");
  }

  setScanning(v: boolean) {
    this.scanning = v;
    this._emit("scanning");
  }

  updateScanItem(path: string, patch: Partial<ScanItem>) {
    const idx = this.scanItems.findIndex((i) => i.path === path);
    if (idx !== -1) {
      this.scanItems[idx] = { ...this.scanItems[idx], ...patch };
      this._emit("scanItems");
    }
  }

  setHistory(entries: HistoryEntry[]) {
    this.history = entries;
    this._emit("history");
  }

  prependHistory(entry: HistoryEntry) {
    this.history = [entry, ...this.history].slice(0, 500);
    this._emit("history");
  }

  applySettings(patch: Partial<AppSettings>) {
    this.settings = { ...this.settings, ...patch };
    this._emit("settings");
  }

  /** Subscribe to a specific key change or all changes (key = '*'). */
  on(key: string, handler: (key: string) => void): () => void {
    const listener = (e: Event) => {
      const detail = (e as CustomEvent<{ key: string }>).detail;
      if (key === "*" || detail.key === key) handler(detail.key);
    };
    this.addEventListener("change", listener);
    return () => this.removeEventListener("change", listener);
  }

  private _emit(key: string) {
    this.dispatchEvent(new CustomEvent("change", { detail: { key } }));
  }
}

export const store = new AppStore();
