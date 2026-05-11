/**
 * Settings view — persistent preferences via tauri-plugin-store.
 */

import { store } from "../store.js";
import type { AppSettings, Severity } from "../types.js";
import { DEFAULT_SETTINGS } from "../types.js";

const SETTINGS_KEY = "app_settings";
let pluginStore: Awaited<ReturnType<typeof loadStore>> | null = null;

async function loadStore() {
  const { load } = await import("@tauri-apps/plugin-store");
  return load("vrcstorage.bin", { defaults: {}, autoSave: true });
}

export async function initSettingsView() {
  const el = document.getElementById("view-settings")!;

  pluginStore = await loadStore();
  const saved = await pluginStore.get<AppSettings>(SETTINGS_KEY);
  if (saved) store.applySettings(saved);

  renderSettings(el);

  // Keep settings UI in sync if settings are mutated from another view (e.g. scan options)
  store.on("settings", () => renderSettings(el));
}

function renderSettings(el: HTMLElement) {
  const { settings } = store;

  // ── Design tokens — same language as History / results-card ─────────────
  const selectCls = "mt-1 w-full border border-white/10 bg-white/[0.05] px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-white/20";
  const labelCls  = "text-[11px] font-semibold uppercase tracking-wider text-slate-500";
  const checkCls  = "h-3.5 w-3.5 accent-white cursor-pointer";

  const sevOptions: Severity[] = ["Low", "Medium", "High", "Critical"];

  const sectionHeader = (title: string) =>
    `<p class="text-[10px] font-semibold uppercase tracking-widest text-slate-500 border-b border-white/[0.06] pb-2 mb-1">${title}</p>`;

  const field = (id: string, label: string, inner: string) => `
    <div class="flex flex-col gap-1">
      <label class="${labelCls}" for="${id}">${label}</label>
      ${inner}
    </div>`;

  const checkRow = (id: string, label: string, checked: boolean) => `
    <label class="flex items-center gap-2.5 px-2 py-1.5 cursor-pointer hover:bg-white/[0.03] transition-colors">
      <input type="checkbox" id="${id}" class="${checkCls}" ${checked ? "checked" : ""} />
      <span class="text-xs text-slate-300">${label}</span>
    </label>`;

  el.innerHTML = `
    <div class="w-full flex flex-col gap-6">
      <h2 class="text-base font-semibold uppercase tracking-widest text-slate-300">Settings</h2>

      <!-- Scan Defaults -->
      <div class="flex flex-col gap-3">
        ${sectionHeader("Scan Defaults")}

        ${field("st-min-sev", "Min Severity (sanitize)",
          `<select id="st-min-sev" class="${selectCls}">
            ${sevOptions.map(s => `<option value="${s}" ${settings.defaultMinSeverity === s ? "selected" : ""}>${s}</option>`).join("")}
          </select>`
        )}

        ${field("st-format", "Output Format",
          `<select id="st-format" class="${selectCls}">
            <option value="txt"  ${settings.defaultOutputFormat === "txt"  ? "selected" : ""}>TXT</option>
            <option value="json" ${settings.defaultOutputFormat === "json" ? "selected" : ""}>JSON</option>
          </select>`
        )}

        ${field("st-export-type", "Export Type",
          `<select id="st-export-type" class="${selectCls}">
            <option value="folder" ${settings.exportType === "folder" ? "selected" : ""}>Folder</option>
            <option value="zip"    ${settings.exportType === "zip"    ? "selected" : ""}>ZIP</option>
          </select>`
        )}
      </div>

      <!-- Toggles -->
      <div class="flex flex-col gap-0">
        ${checkRow("st-dry-run",   "Dry run mode (sanitize)",      settings.dryRunSanitize)}
        ${checkRow("st-skip-meta", "Skip .meta files (export)",    settings.skipMeta)}
        ${checkRow("st-verbose",   "Verbose findings",             settings.verboseFindings)}
        ${checkRow("st-auto-save", "Auto-save report after scan",  settings.autoSaveReport)}
      </div>

      <!-- Community Sharing -->
      <div class="flex flex-col gap-3">
        ${sectionHeader("Community Sharing")}

        ${field("st-share", "Share scan results",
          `<select id="st-share" class="${selectCls}">
            <option value="ask"    ${settings.shareResults === "ask"    ? "selected" : ""}>Ask each time</option>
            <option value="always" ${settings.shareResults === "always" ? "selected" : ""}>Always (automatic)</option>
            <option value="never"  ${settings.shareResults === "never"  ? "selected" : ""}>Never</option>
          </select>`
        )}
        <p class="text-[11px] text-slate-600">Shared results are anonymous. No file is uploaded — only the scan report JSON.</p>
      </div>

      <!-- Reset -->
      <div class="border-t border-white/[0.06] pt-4">
        <button id="st-reset" class="border border-white/10 px-3 py-1.5 text-xs text-slate-400 hover:text-red-400 hover:border-red-500/30 transition-colors">
          Reset to defaults
        </button>
      </div>
    </div>`;

  bindSettings(el);
}


function bindSettings(el: HTMLElement) {
  function save(patch: Partial<AppSettings>) {
    store.applySettings(patch);
    pluginStore?.set(SETTINGS_KEY, store.settings);
  }

  el.querySelector<HTMLSelectElement>("#st-min-sev")?.addEventListener("change", (e) =>
    save({ defaultMinSeverity: (e.target as HTMLSelectElement).value as Severity }));

  el.querySelector<HTMLSelectElement>("#st-format")?.addEventListener("change", (e) =>
    save({ defaultOutputFormat: (e.target as HTMLSelectElement).value as "txt" | "json" }));

  el.querySelector<HTMLSelectElement>("#st-export-type")?.addEventListener("change", (e) =>
    save({ exportType: (e.target as HTMLSelectElement).value as "folder" | "zip" }));

  el.querySelector<HTMLInputElement>("#st-dry-run")?.addEventListener("change", (e) =>
    save({ dryRunSanitize: (e.target as HTMLInputElement).checked }));

  el.querySelector<HTMLInputElement>("#st-skip-meta")?.addEventListener("change", (e) =>
    save({ skipMeta: (e.target as HTMLInputElement).checked }));

  el.querySelector<HTMLInputElement>("#st-verbose")?.addEventListener("change", (e) =>
    save({ verboseFindings: (e.target as HTMLInputElement).checked }));

  el.querySelector<HTMLInputElement>("#st-auto-save")?.addEventListener("change", (e) =>
    save({ autoSaveReport: (e.target as HTMLInputElement).checked }));

  el.querySelector<HTMLSelectElement>("#st-share")?.addEventListener("change", (e) =>
    save({ shareResults: (e.target as HTMLSelectElement).value as AppSettings["shareResults"] }));

  el.querySelector<HTMLButtonElement>("#st-reset")?.addEventListener("click", () => {
    store.applySettings(DEFAULT_SETTINGS);
    pluginStore?.set(SETTINGS_KEY, DEFAULT_SETTINGS);
    renderSettings(el);
  });
}
