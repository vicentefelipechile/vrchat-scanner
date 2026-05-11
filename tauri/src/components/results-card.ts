/**
 * Results card component — matches web version.
 * Sharp badges with colored borders, flat surfaces, no glow, no rounded excess.
 */

import { Icons, formatBytes, formatDuration, basename } from "../icons.js";
import { mountFindingsList } from "./findings-list.js";
import type { ScanReport, RiskLevel } from "../types.js";

/** Border + text color per risk level — matches web badges exactly */
const RISK_BADGE: Record<RiskLevel, string> = {
  CLEAN:    "border border-green-500  text-green-400",
  LOW:      "border border-blue-500   text-blue-400",
  MEDIUM:   "border border-yellow-500 text-yellow-400",
  HIGH:     "border border-orange-500 text-orange-400",
  CRITICAL: "border border-red-500    text-red-400",
  ERROR:    "border border-slate-500  text-slate-400",
};

export interface ResultsCardCallbacks {
  onSave?: () => void;
  onSanitize?: () => void;
  onExport?: () => void;
}

export function mountResultsCard(
  container: HTMLElement,
  report: ScanReport,
  callbacks: ResultsCardCallbacks = {}
) {
  const level = report.risk.level as RiskLevel;
  const badgeCls = RISK_BADGE[level];
  const name = basename(report.file.path);

  const statItems = [
    { label: "Total",    value: report.assets_analyzed.total },
    { label: "DLLs",     value: report.assets_analyzed.dlls },
    { label: "Scripts",  value: report.assets_analyzed.scripts },
    { label: "Textures", value: report.assets_analyzed.textures },
    { label: "Prefabs",  value: report.assets_analyzed.prefabs },
    { label: "Audio",    value: report.assets_analyzed.audio },
  ];

  const statsHtml = statItems.map(s => `
    <div class="border border-white/[0.07] bg-white/[0.02] px-3 py-2 text-center">
      <p class="text-base font-bold tabular-nums text-slate-200">${s.value}</p>
      <p class="text-[10px] uppercase tracking-wider text-slate-500">${s.label}</p>
    </div>`).join("");

  const actionBtn = (id: string, label: string, icon: string, disabled = false) => {
    const cls = disabled
      ? "flex items-center gap-1.5 border border-white/[0.05] px-3 py-1.5 text-xs text-slate-600 cursor-not-allowed select-none"
      : "flex items-center gap-1.5 border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-slate-300 hover:bg-white/[0.06] hover:text-slate-100 transition-colors";
    const title = disabled ? `title="Nothing to sanitize — package is clean"` : "";
    return `<button id="rc-${id}" class="${cls}" ${disabled ? "disabled" : ""} ${title}>${icon}${label}</button>`;
  };

  container.innerHTML = `
    <div class="flex flex-col gap-4">

      <!-- Risk header -->
      <div class="border-b border-white/[0.06] pb-4">
        <div class="flex items-center gap-3 flex-wrap">
          <span class="px-2 py-0.5 text-xs font-bold uppercase tracking-widest ${badgeCls}">${level}</span>
          <span class="text-2xl font-bold tabular-nums text-slate-100">${report.risk.score}<span class="text-sm font-normal text-slate-500"> pts</span></span>
        </div>
        <p class="mt-2 text-sm text-slate-500">${report.risk.recommendation}</p>
        <div class="mt-3 flex flex-wrap gap-4 text-xs text-slate-500">
          <span class="flex items-center gap-1.5">${Icons.fileCode("w-3.5 h-3.5")}<span class="text-slate-400 truncate max-w-[240px]">${name}</span></span>
          <span class="flex items-center gap-1.5">${Icons.hardDrive("w-3.5 h-3.5")}${formatBytes(report.file.size_bytes)}</span>
          <span class="flex items-center gap-1.5">${Icons.clock("w-3.5 h-3.5")}${formatDuration(report.scan_duration_ms)}</span>
        </div>
      </div>

      <!-- SHA-256 -->
      <div class="border border-white/[0.05] bg-black/20 px-3 py-2">
        <p class="font-mono text-[11px] text-slate-400 break-all">
          <span class="text-slate-500">SHA-256 </span>${report.file.sha256}
        </p>
      </div>

      <!-- Asset stats -->
      <div class="grid grid-cols-3 gap-1.5 sm:grid-cols-6">${statsHtml}</div>

      <!-- Findings -->
      ${report.findings.length > 0
        ? `<div>
             <p class="mb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-500">Findings (${report.findings.length})</p>
             <div id="rc-findings"></div>
           </div>`
        : `<div class="flex items-center gap-2.5 border border-green-500/20 bg-green-500/[0.04] px-4 py-3">
             ${Icons.checkCircle("w-4 h-4 text-green-500")}
             <p class="text-sm text-green-400">No findings — package appears clean.</p>
           </div>`
      }

      <!-- Action buttons -->
      <div class="flex flex-wrap gap-2">
        ${callbacks.onSave     ? actionBtn("save",     "Save Report", Icons.save("w-3.5 h-3.5"))                               : ""}
        ${callbacks.onSanitize ? actionBtn("sanitize", "Sanitize",    Icons.shieldCheck("w-3.5 h-3.5"), report.risk.score === 0) : ""}
        ${callbacks.onExport   ? actionBtn("export",   "Export",      Icons.download("w-3.5 h-3.5"))                            : ""}
      </div>

    </div>`;

  const findingsContainer = container.querySelector<HTMLElement>("#rc-findings");
  if (findingsContainer && report.findings.length > 0) {
    mountFindingsList(findingsContainer, report.findings);
  }

  container.querySelector("#rc-save")?.addEventListener("click", () => callbacks.onSave?.());
  // Sanitize: only fire if not disabled (score > 0)
  const sanitizeBtn = container.querySelector<HTMLButtonElement>("#rc-sanitize");
  if (sanitizeBtn && !sanitizeBtn.disabled) {
    sanitizeBtn.addEventListener("click", () => callbacks.onSanitize?.());
  }
  container.querySelector("#rc-export")?.addEventListener("click", () => callbacks.onExport?.());
}
