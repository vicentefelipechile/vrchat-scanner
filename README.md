# vrcstorage-scanner

> Static analysis scanner for Unity/VRChat packages — detects malicious scripts, dangerous DLLs, and suspicious assets **without executing any code**.

[![Rust](https://img.shields.io/badge/rust-1.76%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Release](https://github.com/vicentefelipechile/vrchat-scanner/actions/workflows/release.yml/badge.svg)](https://github.com/vicentefelipechile/vrchat-scanner/actions/workflows/release.yml)
[![CI](https://github.com/vicentefelipechile/vrchat-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/vicentefelipechile/vrchat-scanner/actions/workflows/ci.yml)

---

## Table of Contents

1. [What it does](#1-what-it-does)
2. [Quick Start](#2-quick-start)
3. [Desktop GUI (Tauri)](#3-desktop-gui-tauri)
4. [CLI Usage](#4-cli-usage)
5. [JSON Output](#5-json-output)
6. [Risk Levels](#6-risk-levels)
7. [Server Mode](#7-server-mode)
8. [Deploy on Cloudflare Containers](#8-deploy-on-cloudflare-containers)
9. [Building from Source](#9-building-from-source)
10. [Running Tests](#10-running-tests)
11. [License](#11-license)

---

## 1. What it does

`vrcstorage-scanner` performs **multi-stage static analysis** on Unity packages and related files to detect potentially malicious content before it is published or distributed.

**Supported input formats:**

| Format | Extension |
|---|---|
| Unity Package | `.unitypackage` |
| ZIP archive | `.zip` |
| C# script | `.cs` |
| DLL / PE binary | `.dll` |

**What it scans for:**

- 🔴 **Critical** — `Process.Start()`, `Assembly.Load(bytes)`, executable files embedded in packages, path traversal
- 🟠 **High** — Polyglot files (PE/ZIP inside textures or audio), unknown `[DllImport]`, hardcoded IPs, shell command strings, W+X PE sections
- 🟡 **Medium** — HTTP clients, `BinaryFormatter`, `unsafe` blocks, magic byte mismatches, high-entropy PE sections, future `.meta` timestamps, unknown RIFF chunks in audio files
- 🟢 **Low** — Missing `.meta` files, obfuscated identifiers, excessive DLL count, DLL referenced by many assets, unusual audio entropy, trailing data after RIFF/AIFF chunks, malformed WAV/AIFF headers

Each finding is assigned a **risk score**. The final score maps to one of five risk levels with a recommended action: auto-publish, audit note, manual review, or reject.

---

## 2. Quick Start

```bash
# Build
cargo build --release

# Scan a package (colored CLI output)
./target/release/vrcstorage-scanner scan my_avatar.unitypackage

# Scan and output JSON
./target/release/vrcstorage-scanner scan my_avatar.unitypackage --output json

# Save JSON report to a file
./target/release/vrcstorage-scanner scan my_avatar.unitypackage --output json --output-file report.json

# Start HTTP server on port 8080
./target/release/vrcstorage-scanner serve --port 8080
```

### Drag-and-drop (Windows / macOS)

Drop any supported file directly onto the `vrcstorage-scanner` executable.
The scanner runs automatically and **waits for you to press Enter** before closing
the terminal window so you have time to read the results.

---

## 3. Desktop GUI (Tauri)

`vrcstorage-scanner` ships an optional native desktop application built with **[Tauri v2](https://v2.tauri.app/)**. It wraps the same Rust analysis engine in a polished graphical interface, making the tool accessible to non-technical users.

### Features

- **Drag-and-drop scanning** — drop one or more `.unitypackage` files (or a whole folder) directly onto the window
- **Batch progress tracking** — each file shows its own status card with a progress indicator and final risk badge
- **Interactive file-tree viewer** — collapsible tree of every asset inside the package with type icons
- **Sanitize panel** — remove or neutralize dangerous assets in one click (dry-run preview supported)
- **Export panel** — extract the package to a folder or ZIP archive
- **Scan history** — all past results stored locally via `tauri-plugin-store`; searchable and re-openable
- **Settings panel** — configure default severity threshold, output format, theme, and more

### Architecture

```
tauri/
├── index.html               ← SPA shell (three view panels: scan, history, settings)
├── vite.config.ts           ← Vite + @tailwindcss/vite bundler config
├── package.json             ← Node deps: @tauri-apps/* plugins, lucide icons, tailwindcss, vite, typescript
├── tsconfig.json
│
├── src/                     ← Vanilla TypeScript frontend (no framework)
│   ├── main.ts              ← Entry point: mounts sidebar, bootstraps router + views
│   ├── router.ts            ← SPA panel router (scan | history | settings)
│   ├── store.ts             ← Module-level reactive state (EventTarget-based AppStore)
│   ├── types.ts             ← TypeScript mirrors of all Rust IPC structs
│   ├── tauri.ts             ← Typed invoke() wrappers for every backend command
│   ├── icons.ts             ← Asset-type → Lucide icon / color mapping
│   ├── app.css              ← Global styles (Tailwind CSS v4 + custom tokens)
│   ├── components/
│   │   ├── drop-zone.ts     ← Drag-and-drop target + file-browse button
│   │   ├── findings-list.ts ← Findings table with severity filter chips
│   │   ├── results-card.ts  ← Per-file scan result card (risk badge, stats, actions)
│   │   ├── sanitize-panel.ts← Sanitize options + result summary
│   │   ├── sidebar.ts       ← Navigation sidebar (mounts nav links + keyboard shortcuts)
│   │   └── tree-viewer.ts   ← Recursive file-tree renderer with collapsible nodes
│   └── views/
│       ├── scan.ts          ← Main scan view: drop-zone, progress, results, tree/sanitize/export tabs
│       ├── history.ts       ← History view: list + detail panel per entry
│       └── settings.ts      ← Settings view: form backed by tauri-plugin-store
│
└── src-tauri/               ← Tauri Rust backend (crate: vrcstorage-scanner-gui)
    ├── tauri.conf.json      ← App identity, window config (1200×660, min 900×600), bundle targets
    ├── build.rs
    ├── capabilities/        ← Tauri v2 permission scopes (dialog, fs, shell, store, opener)
    │
    └── src/
        ├── main.rs          ← Binary entry point (calls lib run())
        ├── lib.rs           ← Registers plugins + invoke_handler with all commands
        ├── state.rs         ← AppState (Tauri managed state)
        └── commands/
            ├── mod.rs       ← Re-exports sub-modules
            ├── scan.rs      ← scan_file (streaming Channel), collect_packages, save_report, generate_txt_report
            ├── sanitize.rs  ← sanitize_file → SanitizeResult
            ├── export.rs    ← export_file → ExportResult
            └── tree.rs      ← get_tree → SerTreeNode, export_tree → String
```

### IPC Commands

| Command | Direction | Description |
|---|---|---|
| `scan_file` | Frontend → Backend | Scan a single file; streams `ScanProgress` events via `Channel` |
| `collect_packages` | Frontend → Backend | Resolve dropped paths (files/folders) to a flat list of `.unitypackage` files |
| `save_report` | Frontend → Backend | Write a TXT/JSON report string to disk |
| `generate_txt_report` | Frontend → Backend | Render a `ScanReport` as plain text (uses `txt_reporter`) |
| `sanitize_file` | Frontend → Backend | Sanitize a package; returns `SanitizeResult` counts + output path |
| `export_file` | Frontend → Backend | Extract package to folder or ZIP; returns `ExportResult` |
| `get_tree` | Frontend → Backend | Parse package tree and return `SerTreeNode` hierarchy for rendering |
| `export_tree` | Frontend → Backend | Render tree as TXT / JSON / XML string for save-file dialog |

### Building the GUI

**Prerequisites:** Node.js ≥ 18, Rust stable, OS build tools (Visual Studio C++ Build Tools on Windows, Xcode CLT on macOS, `libwebkit2gtk-4.1-dev` + `patchelf` on Linux). See the [Tauri prerequisites guide](https://v2.tauri.app/start/prerequisites/).

```bash
cd tauri
npm install

# Development (hot-reload frontend + auto Rust recompile)
npm run tauri dev

# Production build (creates installers in src-tauri/target/release/bundle/)
npm run tauri build
```

**Output installers** (`src-tauri/target/release/bundle/`):

| OS | Formats |
|---|---|
| Windows | NSIS `.exe` installer, MSI `.msi` |
| Linux | AppImage, `.deb`, `.rpm` |
| macOS | `.app` bundle, `.dmg` |

### Cargo workspace

The repository is a Cargo **workspace** with two members:

```
[workspace]
members = [".", "tauri/src-tauri"]
```

- `.` → `vrcstorage-scanner` (CLI + library crate)
- `tauri/src-tauri` → `vrcstorage-scanner-gui` (Tauri binary; depends on the library via `path = "../.."`)

---

## 4. CLI Usage

```
vrcstorage-scanner [FILE]                    # Drag-and-drop shorthand (pauses on exit)
vrcstorage-scanner scan <FILE> [OPTIONS]     # Explicit scan (single or multiple files/folders)
vrcstorage-scanner sanitize <FILE> [OPTIONS] # Remove/neutralize malicious assets
vrcstorage-scanner export <FILE> [OPTIONS]   # Extract package to folder or ZIP
vrcstorage-scanner tree <FILE> [OPTIONS]     # Render internal file-tree
vrcstorage-scanner serve [OPTIONS]           # Start HTTP server (Cloudflare Containers)
vrcstorage-scanner credits                   # Show credits and project info

Arguments (scan):
  <PATH...>   One or more paths (.unitypackage, .dll, .cs, .zip, folder...)

Options (scan):
  -o, --output <FORMAT>        Output format: "cli" (default), "json", or "txt"
  -f, --output-file <PATH>     Write output to file instead of stdout
  -h, --help                   Print help
  -V, --version                Print version

Options (sanitize):
  -o, --output <PATH>          Output path [default: <input>-sanitized.unitypackage]
  -s, --min-severity <LEVEL>   Minimum severity to act on: low|medium|high|critical [default: high]
  -d, --dry-run                Show what would happen without writing output
      --json                   Also emit JSON scan report

Options (export):
  -o, --output <FORMAT>        Output format: "folder" (default) or "zip"
  -d, --out-dir <PATH>         Output directory or file
  -m, --skip-meta              Omit .meta files from export

Options (tree):
  -e, --export <FORMAT>        Output format: "txt" (default), "json", or "xml"
  -p, --pretty                 Use Unicode box-drawing (TXT only)
  -f, --output-file <PATH>     Write output to file instead of stdout

Options (serve):
  -p, --port <PORT>            Port to listen on (default: 8080)
```

### Example — CLI output

```
vrcstorage-scanner v0.9.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
File:    my_mod.unitypackage
SHA-256: a3f8c2...
Size:    1.2 MB
Type:    UnityPackage
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FINDINGS (2 found)
────────────────────────────────────────────

[CRITICAL +75] Process.Start() detected in C# script
  File:     Assets/Scripts/Loader.cs
  ID:       CS_PROCESS_START

[MEDIUM   +30] HTTP client detected in C# script
  File:     Assets/Scripts/Updater.cs
  ID:       CS_HTTP_CLIENT

────────────────────────────────────────────
Total score:   105
Risk level:    ■ HIGH
Action:        Retain — mandatory manual review
────────────────────────────────────────────
Duration:      38ms
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed — risk level Clean, Low, Medium, or High |
| `2` | Risk level **Critical** — package should be rejected |
| `1` | Fatal error (file not found, unreadable archive, etc.) |

---

## 5. JSON Output

```bash
vrcstorage-scanner scan my_avatar.unitypackage --output json
```

```json
{
  "file": {
    "path": "my_avatar.unitypackage",
    "sha256": "a3f8c2...",
    "md5": "5d41402...",
    "sha1": "da39a3...",
    "size_bytes": 1258291,
    "file_type": "UnityPackage",
    "timestamp": "2026-04-19T22:00:00Z"
  },
  "findings": [
    {
      "id": "CS_PROCESS_START",   // serialised from FindingId::CsProcessStart
      "severity": "Critical",
      "points": 75,
      "location": "Assets/Scripts/Loader.cs",
      "detail": "Process.Start() detected in C# script — executes arbitrary process",
      "context": null
    }
  ],
  "risk": {
    "score": 75,
    "level": "High",
    "recommendation": "Retain — mandatory manual review"
  },
  "asset_counts": {
    "total": 14,
    "dlls": 1,
    "scripts": 5,
    "textures": 4,
    "prefabs": 3,
    "audio": 1,
    "other": 0
  },
  "scan_duration_ms": 38
}
```

---

## 6. Risk Levels

| Score | Level | CLI Exit Code | Recommended Action |
|---|---|---|---|
| 0 – 30 | **Clean** | `0` | Auto-publish |
| 31 – 60 | **Low** | `0` | Publish with audit note |
| 61 – 100 | **Medium** | `0` | Manual review recommended |
| 101 – 150 | **High** | `0` | Retain — mandatory manual review |
| 151+ | **Critical** | `2` | Reject immediately |

> Context-aware reductions apply automatically: `UnityWebRequest` usage is penalised less when the VRChat SDK is detected; `Reflection.Emit` in an `Editor/` folder is treated as a legitimate editor tool.

---

## 7. Server Mode

The scanner ships a lightweight HTTP server designed to be called by a **Cloudflare Worker** or any backend service.

```bash
vrcstorage-scanner serve --port 8080
```

### Endpoints

#### `POST /scan`

Downloads a file from R2, scans it, and returns the full JSON report.

**Request body:**
```json
{
  "r2_url": "https://your-bucket.r2.cloudflarestorage.com/uploads/file-uuid.unitypackage",
  "file_id": "file-uuid",
  "expected_sha256": "a3f8c2..."
}
```

| Field | Required | Description |
|---|---|---|
| `r2_url` | ✅ | Pre-signed or public URL to the file in R2 |
| `file_id` | ✅ | Identifier used as the file label in the report |
| `expected_sha256` | ❌ | If provided, the download is rejected if the hash doesn't match |

**Response (200 OK):**
```json
{
  "file_id": "file-uuid",
  "ok": true,
  "scan_result": { ... }
}
```

**Error codes:**

| HTTP Code | Meaning |
|---|---|
| `200` | Scan completed (even if risk is Critical — the Worker decides what to do) |
| `400` | SHA-256 mismatch |
| `502` | Failed to download from R2 |
| `500` | Internal scan or serialization error |

#### `GET /health`

```json
{ "ok": true }
```

#### `POST /sanitize`

Neutralizes malicious entries and returns cleaned `.unitypackage` bytes. File metadata (content type, asset count) is returned in response headers.

---

## 8. Deploy on Cloudflare Containers

The server mode is designed to run as a **Cloudflare Container** — an on-demand, serverless container spawned by a [Worker](https://developers.cloudflare.com/workers/) through a [Durable Object](https://developers.cloudflare.com/durable-objects/) binding.

Everything is pre-configured in the repository:

```
vrchat-analyzer/
├── Dockerfile              ← multi-stage Rust build → minimal runtime image
├── .dockerignore           ← excludes target/, tests/, worker/ from build context
├── wrangler.jsonc          ← Container + Worker + Durable Object config
└── worker/
    ├── package.json        ← @cloudflare/containers + wrangler
    ├── tsconfig.json
    └── src/
        └── index.ts        ← ScannerContainer class + fetch handler
```

### Architecture

```
Client / API
      │
      ▼ HTTPS request
Cloudflare Worker (TypeScript)
      │  ScannerContainer extends Container
      │  └─ getContainer(env.SCANNER, id).fetch(request)
      ▼
Durable Object (runs ScannerContainer class)
      │  Manages container lifecycle (start, sleep, stop)
      ▼  HTTP on defaultPort 8080
vrcstorage-scanner Container (Rust / axum)
      │  Downloads file from R2 via reqwest
      │  Runs full analysis pipeline in memory
      │  Returns JSON / TXT / sanitized .unitypackage bytes
```

### How it works

1. The Worker receives a request and calls `getContainer(env.SCANNER, "singleton").fetch(request)`.
2. Under the hood, Cloudflare spins up a **Durable Object** instance for `ScannerContainer`.
3. The Durable Object starts the container image (cold start ~1–3 s, then warm).
4. Requests are forwarded to the container's **port 8080**, where the axum server listens.
5. The container downloads the file from R2 (via `reqwest`, requiring `enableInternet: true`), runs the scan fully in memory, and returns the result.
6. After the idle timeout (`sleepAfter: "10m"`), the container receives `SIGTERM` and shuts down gracefully.

### Step 1 — Install dependencies

```bash
npm install
```

### Step 2 — Deploy

```bash
# Build Docker image, push to Cloudflare Registry, and deploy Worker + Container
npx wrangler deploy
```

Wrangler automatically:
- Builds the Docker image using the `Dockerfile` at the repo root.
- Pushes it to Cloudflare's managed container registry (backed by R2).
- Deploys the Worker and configures the Durable Object binding.

> **Note:** The first deploy takes several minutes while the container is provisioned across Cloudflare's network. Subsequent deploys reuse cached image layers and are much faster.

### Check deployment status

```bash
npx wrangler containers list        # list deployed containers
npx wrangler containers images list # list images in registry
```

### Local testing

Run the axum server directly (no Docker, no Worker):

```bash
cargo run -- serve --port 8080
```

Then send a request directly:

```bash
curl -X POST http://localhost:8080/health
```

### Key configuration details

**`worker/src/index.ts`** — The `ScannerContainer` class:

```typescript
import { Container, getContainer } from "@cloudflare/containers";

export class ScannerContainer extends Container {
  defaultPort = 8080;        // axum listens here
  sleepAfter = "10m";        // keep alive 10 min after last request
  enableInternet = true;     // REQUIRED: container must download from R2
}
```

**`wrangler.jsonc`** — Container + Durable Object binding:

```jsonc
{
  "containers": [
    {
      "class_name": "ScannerContainer",
      "image": "registry.cloudflare.com/...",
      "max_instances": 2,
      "instance_type": "standard-1"
    }
  ],
  "durable_objects": {
    "bindings": [
      { "class_name": "ScannerContainer", "name": "SCANNER" }
    ]
  },
  "migrations": [
    { "new_sqlite_classes": ["ScannerContainer"], "tag": "v1" }
  ]
}
```

### Instance sizing

| Instance type | RAM | vCPU | Suitable for |
|---|---|---|---|
| `lite` | 256 MiB | 1/16 | Small C# files only |
| `standard-1` ★ | 4 GiB | 1/2 | Medium packages (< 100 MB) — **current default** |
| `standard-2` | 6 GiB | 1 | Large packages (up to 500 MB) |
| `standard-3` | 8 GiB | 2 | Heavy concurrent scanning |


### Limitations

- **Disk is ephemeral**: the container gets a fresh filesystem on every cold start. This project stores nothing on disk — all analysis runs in memory.
- **No inbound TCP/UDP from end users**: only HTTP requests proxied through the Worker reach the container.
- **`enableInternet` must be `true`**: otherwise `reqwest` cannot download files from R2.
- **Image must be `linux/amd64`**: the Rust binary is cross-compiled automatically in the Docker build.

---

## 9. Building from Source

**Prerequisites:**
- Rust 1.76 or later (`rustup update stable`)
- No system dependencies — all native libraries are vendored via Cargo

```bash
# Clone
git clone https://github.com/vicentefelipechile/vrchat-scanner.git
cd vrcstorage-scanner

# Debug build (faster compile)
cargo build

# Release build (optimized)
cargo build --release

# The binary will be at:
./target/release/vrcstorage-scanner
```

### Building only the GUI

```bash
cd tauri
npm install
npm run tauri build
# Installers appear in tauri/src-tauri/target/release/bundle/
```

---

## 10. Running Tests

```bash
# All tests (unit + integration)
cargo test

# Integration tests only
cargo test --test integration

# Integration tests with full output
cargo test --test integration -- --nocapture

# A specific test by name
cargo test process_start_detected_as_critical

# Lint
cargo clippy

# Benchmarks
cargo bench
```

The test suite covers **87 scenarios** (84 integration + 3 unit) including:

- Clean packages that produce no false positives
- Malicious DLL patterns (socket imports, W+X sections, high entropy)
- Obfuscated C# scripts (base64, short identifiers, XOR, unicode escapes)
- Polyglot asset detection (PE/ZIP embedded in PNG or audio files)
  — validated with full DOS+PE struct check, not just `MZ` bytes
- Compressed format exemptions (PNG, JPEG, OGG, MP3 don't trigger entropy)
- Metadata anomalies (future timestamps, external references, dependency fan-in)
- Scoring pipeline and context reductions (polyglot ↔ loader correlation,
  VRChat SDK HTTP reduction, Editor folder Reflection.Emit reduction)

---

## 11. License

[LICENSE](/LICENSE)

---

> For architecture notes, coding conventions, and contribution rules, see [AGENTS.md](AGENTS.md).
>
> For a non-technical guide to adjusting scanner sensitivity (score thresholds, domains, point values), see [CONFIG.md](CONFIG.md).
>
> For Tauri GUI build instructions, see [tauri/README.md](tauri/README.md).
