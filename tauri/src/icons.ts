/**
 * Icon set backed by Lucide (https://lucide.dev).
 * Each entry returns an SVG string ready for innerHTML injection.
 * Size is controlled by the Tailwind w/h class passed via `cls`.
 *
 * Imports are tree-shaken at build time — only the icons listed here
 * are bundled.
 */

import {
  Shield,
  ShieldCheck,
  ScanLine,
  History,
  Settings,
  Upload,
  Download,
  Folder,
  File,
  FileCode,
  Image,
  Music,
  Box,
  Layers,
  Cpu,
  TriangleAlert,
  CircleAlert,
  CircleCheck,
  Info,
  ChevronRight,
  ChevronDown,
  ChevronLeft,
  Save,
  Trash2,
  HardDrive,
  Clock,
  X,
  LoaderCircle,
} from "lucide";
import type { IconNode } from "lucide";

/** Renders a Lucide IconNode to an SVG innerHTML string.
 *
 * Lucide exports icons as a flat `[tag, attrs][]` array, e.g.:
 *   [["path", {d:"M20 13c0 5..."}], ["line", {x1:"0", ...}]]
 */
function toSvg(icon: IconNode, cls = "w-4 h-4"): string {
  const inner = (icon as Array<[string, Record<string, string | number>]>)
    .map(([tag, attrs]) => {
      const attrStr = Object.entries(attrs)
        .map(([k, v]) => `${k}="${v}"`)
        .join(" ");
      return `<${tag} ${attrStr}/>`;
    })
    .join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" class="${cls}" viewBox="0 0 24 24"
    fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
    aria-hidden="true">${inner}</svg>`;
}

export const Icons = {
  shield:        (cls?: string) => toSvg(Shield,        cls),
  shieldCheck:   (cls?: string) => toSvg(ShieldCheck,   cls),
  scan:          (cls?: string) => toSvg(ScanLine,       cls),
  history:       (cls?: string) => toSvg(History,        cls),
  settings:      (cls?: string) => toSvg(Settings,       cls),
  upload:        (cls?: string) => toSvg(Upload,         cls),
  download:      (cls?: string) => toSvg(Download,       cls),
  folder:        (cls?: string) => toSvg(Folder,         cls),
  file:          (cls?: string) => toSvg(File,           cls),
  fileCode:      (cls?: string) => toSvg(FileCode,       cls),
  image:         (cls?: string) => toSvg(Image,          cls),
  music:         (cls?: string) => toSvg(Music,          cls),
  box:           (cls?: string) => toSvg(Box,            cls),
  layers:        (cls?: string) => toSvg(Layers,         cls),
  cpu:           (cls?: string) => toSvg(Cpu,            cls),
  alertTriangle: (cls?: string) => toSvg(TriangleAlert,  cls),
  alertCircle:   (cls?: string) => toSvg(CircleAlert,    cls),
  checkCircle:   (cls?: string) => toSvg(CircleCheck,    cls),
  info:          (cls?: string) => toSvg(Info,           cls),
  chevronRight:  (cls?: string) => toSvg(ChevronRight,   cls),
  chevronDown:   (cls?: string) => toSvg(ChevronDown,    cls),
  chevronLeft:   (cls?: string) => toSvg(ChevronLeft,    cls),
  save:          (cls?: string) => toSvg(Save,           cls),
  trash:         (cls?: string) => toSvg(Trash2,         cls),
  hardDrive:     (cls?: string) => toSvg(HardDrive,      cls),
  clock:         (cls?: string) => toSvg(Clock,          cls),
  x:             (cls?: string) => toSvg(X,              cls),
  spinner:       (cls?: string) => toSvg(LoaderCircle,   cls),
} as const;

// ─── Convenience helpers (unchanged public API) ──────────────────────────────

/** Format bytes to a human-readable string. */
export function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(1)} MB`;
}

/** Format milliseconds to a human-readable string. */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

/** Extract the filename from a full path. */
export function basename(path: string): string {
  return path.split(/[\\\/]/).pop() ?? path;
}
