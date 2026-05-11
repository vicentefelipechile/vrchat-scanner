/**
 * Sidebar component — matches the web version aesthetic exactly.
 * Flat dark surfaces, no gradients, no rounded excess, sharp nav items.
 */

import { Icons } from "../icons.js";
import { showView, onViewChange, type ViewId } from "../router.js";

const NAV_ITEMS: { id: ViewId; label: string; icon: () => string }[] = [
  { id: "scan",     label: "Scan",          icon: () => Icons.upload("w-4 h-4 flex-shrink-0") },
  { id: "history",  label: "History",        icon: () => Icons.history("w-4 h-4 flex-shrink-0") },
  { id: "settings", label: "Settings",       icon: () => Icons.settings("w-4 h-4 flex-shrink-0") },
];

function navItemHtml(item: typeof NAV_ITEMS[number], active: boolean): string {
  const base = "flex items-center gap-2.5 px-3 py-2 text-sm w-full text-left transition-colors duration-100";
  const cls = active
    ? `${base} text-white bg-white/[0.07]`
    : `${base} text-slate-400 hover:text-slate-200 hover:bg-white/[0.04]`;

  return `
    <button class="${cls}" data-nav="${item.id}">
      ${item.icon()}
      <span>${item.label}</span>
    </button>`;
}

function sidebarHtml(activeView: ViewId): string {
  return `
    <!-- Logo — matches web exactly -->
    <div class="px-4 py-5 border-b border-white/[0.06]">
      <div class="flex items-center gap-2.5">
        <div class="flex h-8 w-8 items-center justify-center bg-white/10 border border-white/10">
          <span class="text-xs font-bold text-white">VRC</span>
        </div>
        <div>
          <p class="text-sm font-bold leading-tight text-white">vrcstorage-scanner</p>
          <p class="text-[10px] font-medium tracking-widest text-slate-500 uppercase">Package Analyzer</p>
        </div>
      </div>
    </div>

    <!-- Nav -->
    <div class="px-2 py-3">
      <p class="px-3 mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">Main</p>
      <nav id="sidebar-nav" class="flex flex-col gap-0.5">
        ${NAV_ITEMS.map(item => navItemHtml(item, item.id === activeView)).join("")}
      </nav>
    </div>

    <!-- Version -->
    <div class="mt-auto border-t border-white/[0.06] px-4 py-3">
      <p class="text-[10px] text-slate-500">Made by <span class="text-slate-400">SummerTYT</span> · vrcstorage.lat</p>
    </div>`;
}

function bindSidebarEvents(el: HTMLElement) {
  el.querySelectorAll<HTMLButtonElement>("[data-nav]").forEach((btn) => {
    btn.addEventListener("click", () => {
      showView(btn.dataset.nav as ViewId);
    });
  });
}

export function mountSidebar() {
  const el = document.getElementById("sidebar")!;

  function render(activeView: ViewId) {
    el.innerHTML = sidebarHtml(activeView);
    bindSidebarEvents(el);
  }

  render("scan");
  // Use `nav` (second arg) — not the DOM panel id — for the active highlight
  onViewChange((_v, nav) => render(nav));
}
