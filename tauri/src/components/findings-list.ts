/**
 * Findings list component — flat rows, sharp borders, no rounded excess.
 */

import { Icons } from "../icons.js";
import type { Finding, Severity } from "../types.js";

type FilterSev = Severity | "All";

/** Border-only badges matching web style */
const SEV_BADGE: Record<Severity, string> = {
  Critical: "border border-red-500    text-red-400",
  High:     "border border-orange-500 text-orange-400",
  Medium:   "border border-yellow-500 text-yellow-400",
  Low:      "border border-blue-500   text-blue-400",
};

const SEV_ICON: Record<Severity, () => string> = {
  Critical: () => Icons.alertCircle("w-3.5 h-3.5 text-red-400 flex-shrink-0"),
  High:     () => Icons.alertTriangle("w-3.5 h-3.5 text-orange-400 flex-shrink-0"),
  Medium:   () => Icons.alertTriangle("w-3.5 h-3.5 text-yellow-400 flex-shrink-0"),
  Low:      () => Icons.info("w-3.5 h-3.5 text-blue-400 flex-shrink-0"),
};

function countBySev(findings: Finding[], sev: Severity): number {
  return findings.filter((f) => f.severity === sev).length;
}

function filterTabHtml(sev: FilterSev, active: boolean, count: number): string {
  const base = "px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider transition-colors";
  const cls = active
    ? `${base} border border-white/20 text-slate-200 bg-white/[0.06]`
    : `${base} text-slate-600 hover:text-slate-400`;
  return `<button class="${cls}" data-filter="${sev}">${sev} <span class="opacity-50">(${count})</span></button>`;
}

function findingRowHtml(f: Finding, idx: number): string {
  const badge = SEV_BADGE[f.severity];
  const icon  = SEV_ICON[f.severity]();
  const lines = f.line_numbers?.length
    ? `<p class="text-[11px] text-slate-500 mt-1">Line${f.line_numbers.length > 1 ? "s" : ""}: ${f.line_numbers.join(", ")}</p>`
    : "";
  const ctx = f.context
    ? `<div class="bg-black/30 px-3 py-2 mt-1"><p class="font-mono text-[11px] text-slate-400 whitespace-pre-wrap break-all">${escHtml(f.context)}</p></div>`
    : "";

  return `
    <div class="finding-row border-b border-white/[0.06] hover:bg-white/[0.02] transition-colors" data-finding="${idx}">
      <div class="flex items-center gap-3 px-3 py-2.5 cursor-pointer">
        ${icon}
        <div class="min-w-0 flex-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-mono text-[10px] font-bold tracking-wider px-1.5 py-0.5 ${badge}">${escHtml(f.id)}</span>
            ${f.points > 0 ? `<span class="text-[10px] text-slate-700">+${f.points} pts</span>` : ""}
          </div>
          <p class="mt-0.5 truncate text-xs text-slate-500">${escHtml(f.location)}</p>
        </div>
        <span class="flex-shrink-0 text-slate-700 chevron-icon">${Icons.chevronRight("w-4 h-4")}</span>
      </div>
      <div class="finding-detail border-t border-white/[0.05] bg-black/20 px-3 py-2.5 space-y-1.5">
        <p class="text-xs text-slate-400">${escHtml(f.detail)}</p>
        ${ctx}${lines}
      </div>
    </div>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function mountFindingsList(container: HTMLElement, findings: Finding[]) {
  let activeFilter: FilterSev = "All";

  function filtered(): Finding[] {
    return activeFilter === "All" ? findings : findings.filter((f) => f.severity === activeFilter);
  }

  function render() {
    const f = filtered();
    const filters: FilterSev[] = ["All", "Critical", "High", "Medium", "Low"];

    const tabsHtml = filters.map((sev) => {
      const count = sev === "All" ? findings.length : countBySev(findings, sev as Severity);
      return filterTabHtml(sev, sev === activeFilter, count);
    }).join("");

    const rowsHtml = f.length === 0
      ? `<div class="flex flex-col items-center gap-2 py-8 text-slate-500">
           ${Icons.shieldCheck("w-7 h-7")}
           <p class="text-sm">No findings at this severity level</p>
         </div>`
      : f.map((finding, i) => findingRowHtml(finding, i)).join("");

    container.innerHTML = `
      <div class="flex flex-wrap gap-1.5 mb-3" id="findings-filters">${tabsHtml}</div>
      <div class="border border-white/[0.06]" id="findings-rows">${rowsHtml}</div>`;

    bindEvents();
  }

  function bindEvents() {
    container.querySelectorAll<HTMLButtonElement>("[data-filter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeFilter = btn.dataset.filter as FilterSev;
        render();
      });
    });

    container.querySelectorAll<HTMLElement>(".finding-row").forEach((row) => {
      row.querySelector(".flex")?.addEventListener("click", () => {
        row.classList.toggle("open");
        const chevron = row.querySelector(".chevron-icon");
        if (chevron) {
          chevron.innerHTML = row.classList.contains("open")
            ? Icons.chevronDown("w-4 h-4")
            : Icons.chevronRight("w-4 h-4");
        }
      });
    });
  }

  render();
}
