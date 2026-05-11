/**
 * Application entry point.
 * Mounts sidebar, initialises router, and bootstraps all views.
 */

import "./app.css";
import { mountSidebar } from "./components/sidebar.js";
import { initRouter } from "./router.js";
import { initScanView } from "./views/scan.js";
import { initHistoryView } from "./views/history.js";
import { initSettingsView } from "./views/settings.js";

// ── Keyboard shortcuts ────────────────────────────────────────────────────────

import { showView } from "./router.js";

document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key === "o") { e.preventDefault(); document.getElementById("dz-browse")?.click(); }
  if (e.key === "Escape")   { showView("scan"); }
});

// ── Bootstrap ─────────────────────────────────────────────────────────────────

async function main() {
  mountSidebar();
  initRouter();
  initScanView();

  // History and settings load async (need plugin-store)
  await Promise.all([
    initHistoryView(),
    initSettingsView(),
  ]);
}

main().catch(console.error);
