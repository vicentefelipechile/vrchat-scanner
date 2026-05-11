/**
 * Drop zone component — minimal, matches the web version aesthetic.
 * Dashed border rectangle, no icon box, no gradients, no hover scale.
 */

import { Icons } from "../icons.js";

export interface DropZoneOptions {
  onDrop: (paths: string[]) => void;
  disabled?: boolean;
}

function html(state: "idle" | "dragging" | "scanning"): string {
  if (state === "scanning") {
    return `<div class="drop-zone flex flex-col items-center justify-center min-h-[200px] border border-dashed border-white/10 bg-transparent opacity-60 cursor-not-allowed">
      <div class="spinner text-slate-500">${Icons.spinner("w-6 h-6")}</div>
      <p class="mt-3 text-sm text-slate-500">Scanning…</p>
    </div>`;
  }

  const borderCls = state === "dragging"
    ? "border-white/40 bg-white/[0.03]"
    : "border-white/[0.12] bg-transparent hover:border-white/20";

  return `<div class="drop-zone flex flex-col items-center justify-center min-h-[200px] border border-dashed ${borderCls} cursor-pointer select-none" id="drop-zone-inner">
    ${Icons.upload("w-7 h-7 text-slate-500")}
    <p class="mt-3 text-sm font-medium text-slate-400">Drag &amp; drop a file here</p>
    <p class="mt-1 text-xs text-slate-500">or <button id="dz-browse" class="text-slate-400 underline underline-offset-2 hover:text-slate-200">Browse…</button></p>
    <p class="mt-4 text-[11px] text-slate-500">Only .unitypackage — single or multiple files</p>
  </div>`;
}

export function mountDropZone(container: HTMLElement, opts: DropZoneOptions): { setScanning(v: boolean): void } {
  let dragging = false;
  let scanning = false;
  let dragCounter = 0;

  function render() {
    const state = scanning ? "scanning" : dragging ? "dragging" : "idle";
    container.innerHTML = html(state);
    bindEvents();
  }

  async function openDialog() {
    if (opts.disabled || scanning) return;
    const { open } = await import("@tauri-apps/plugin-dialog");
    const result = await open({ multiple: true });
    if (!result) return;
    const paths = Array.isArray(result) ? result : [result];
    opts.onDrop(paths);
  }

  function bindEvents() {
    const zone = container.firstElementChild as HTMLElement | null;
    if (!zone) return;

    container.querySelector<HTMLButtonElement>("#dz-browse")?.addEventListener("click", (e) => {
      e.stopPropagation();
      openDialog();
    });

    zone.addEventListener("click", openDialog);

    zone.addEventListener("dragenter", (e) => {
      e.preventDefault();
      dragCounter++;
      if (!dragging) { dragging = true; render(); }
    });

    zone.addEventListener("dragleave", (e) => {
      e.preventDefault();
      dragCounter--;
      if (dragCounter <= 0) { dragCounter = 0; dragging = false; render(); }
    });

    zone.addEventListener("dragover", (e) => {
      e.preventDefault();
      (e as DragEvent).dataTransfer!.dropEffect = "copy";
    });

    zone.addEventListener("drop", (e) => {
      e.preventDefault();
      dragCounter = 0;
      dragging = false;

      const files = (e as DragEvent).dataTransfer?.files;
      if (!files || files.length === 0) { render(); return; }

      const paths: string[] = [];
      for (let i = 0; i < files.length; i++) {
        const f = files[i] as File & { path?: string };
        if (f.path) paths.push(f.path);
      }
      render();
      if (paths.length > 0) opts.onDrop(paths);
    });
  }

  render();

  return {
    setScanning(v: boolean) {
      scanning = v;
      dragging = false;
      dragCounter = 0;
      render();
    },
  };
}
