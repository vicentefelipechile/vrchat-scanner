/**
 * Sanitize result panel — shows neutralized/removed/kept counts and score delta.
 */

import { Icons } from "../icons.js";
import type { SanitizeResult } from "../types.js";

export function mountSanitizePanel(container: HTMLElement, result: SanitizeResult) {
  const delta = result.original_score - result.residual_score;

  const stat = (icon: string, label: string, value: number, color: string) => `
    <div class="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 text-center">
      <span class="${color} flex justify-center mb-1">${icon}</span>
      <p class="text-lg font-bold tabular-nums text-slate-200">${value}</p>
      <p class="text-[10px] uppercase tracking-wider text-slate-600">${label}</p>
    </div>`;

  container.innerHTML = `
    <div class="rounded-2xl border border-orange-500/20 bg-orange-500/5 p-5">
      <div class="mb-4 flex items-center gap-2">
        ${Icons.shieldCheck("w-5 h-5 text-orange-400")}
        <p class="text-sm font-semibold text-orange-300">
          Sanitize ${result.dry_run ? "Preview (Dry Run)" : "Complete"}
        </p>
      </div>

      <div class="grid grid-cols-2 gap-2 sm:grid-cols-4">
        ${stat(Icons.shieldCheck("w-4 h-4"), "Neutralized", result.neutralized_count, "text-orange-400")}
        ${stat(Icons.trash("w-4 h-4"),       "Removed",     result.removed_count,     "text-red-400")}
        ${stat(Icons.x("w-4 h-4"),           "Skipped",     result.skipped_count,     "text-slate-500")}
        ${stat(Icons.checkCircle("w-4 h-4"), "Kept",        result.kept_count,        "text-emerald-400")}
      </div>

      <!-- Score delta -->
      <div class="mt-4 flex items-center gap-3 rounded-xl border border-white/[0.05] bg-black/20 px-4 py-3">
        <div class="text-center">
          <p class="text-xs text-slate-600">Before</p>
          <p class="text-xl font-bold tabular-nums text-red-400">${result.original_score}</p>
        </div>
        <div class="flex-1 text-center text-slate-600">${Icons.alertTriangle("w-4 h-4 mx-auto")}</div>
        <div class="text-center">
          <p class="text-xs text-slate-600">After</p>
          <p class="text-xl font-bold tabular-nums text-emerald-400">${result.residual_score}</p>
        </div>
        ${delta > 0 ? `<div class="ml-auto rounded-lg bg-emerald-500/20 px-3 py-1 text-sm font-bold text-emerald-300">−${delta} pts</div>` : ""}
      </div>

      ${result.output_path && !result.dry_run
        ? `<p class="mt-3 font-mono text-[11px] text-slate-600 break-all"><span class="text-slate-500">Saved → </span>${result.output_path}</p>`
        : ""}

      ${result.dry_run
        ? `<p class="mt-3 text-xs text-amber-500/80">Dry run — no file was written. Uncheck "Dry run" in the sidebar options to apply.</p>`
        : ""}
    </div>`;
}
