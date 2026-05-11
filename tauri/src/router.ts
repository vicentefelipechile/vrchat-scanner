/**
 * Router — shows one view panel at a time.
 *
 * Views are plain divs in index.html with ids: #view-scan, #view-history, #view-settings
 * The active view's class "hidden" is removed; all others get it.
 */

export type ViewId = "scan" | "history" | "settings";

const VIEW_IDS: ViewId[] = ["scan", "history", "settings"];
let _current: ViewId = "scan";
let _activeNav: ViewId = "scan";
const _listeners: Array<(v: ViewId, nav: ViewId) => void> = [];

/**
 * Show a DOM panel (id) and optionally highlight a different sidebar item (activeNav).
 * If activeNav is omitted it defaults to id — normal navigation behaviour.
 */
export function showView(id: ViewId, activeNav?: ViewId) {
  _current = id;
  _activeNav = activeNav ?? id;
  VIEW_IDS.forEach((v) => {
    const el = document.getElementById(`view-${v}`);
    if (el) el.classList.toggle("hidden", v !== id);
  });
  _listeners.forEach((fn) => fn(id, _activeNav));
}

export function currentView(): ViewId {
  return _current;
}

/** Subscribe to view changes (e.g. so sidebar can highlight active nav item). */
export function onViewChange(fn: (v: ViewId, nav: ViewId) => void): () => void {
  _listeners.push(fn);
  return () => _listeners.splice(_listeners.indexOf(fn), 1);
}

export function initRouter() {
  showView("scan"); // default view on startup
}
