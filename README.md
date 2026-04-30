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
3. [CLI Usage](#3-cli-usage)
4. [JSON Output](#4-json-output)
5. [Risk Levels](#5-risk-levels)
6. [Server Mode](#6-server-mode)
7. [Deploy on Cloudflare Containers](#7-deploy-on-cloudflare-containers)
8. [Building from Source](#8-building-from-source)
9. [Running Tests](#9-running-tests)
10. [License](#10-license)

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
- 🟡 **Medium** — HTTP clients, `BinaryFormatter`, `unsafe` blocks, magic byte mismatches, high-entropy PE sections, future `.meta` timestamps
- 🟢 **Low** — Missing `.meta` files, obfuscated identifiers, excessive DLL count, DLL referenced by many assets

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

## 3. CLI Usage

```
vrcstorage-scanner [FILE]                    # Drag-and-drop shorthand (pauses on exit)
vrcstorage-scanner scan <FILE> [OPTIONS]     # Explicit scan subcommand
vrcstorage-scanner serve [OPTIONS]           # Start HTTP server

Arguments (scan):
  <FILE>   Path to file to scan (.unitypackage, .dll, .cs, .zip, ...)

Options (scan):
  -o, --output <FORMAT>        Output format: "cli" (default) or "json"
  -f, --output-file <PATH>     Write output to file instead of stdout
  -h, --help                   Print help
  -V, --version                Print version

Options (serve):
  -p, --port <PORT>            Port to listen on (default: 8080)
```

### Example — CLI output

```
vrcstorage-scanner v0.1.0
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

## 4. JSON Output

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

## 5. Risk Levels

| Score | Level | CLI Exit Code | Recommended Action |
|---|---|---|---|
| 0 – 30 | **Clean** | `0` | Auto-publish |
| 31 – 60 | **Low** | `0` | Publish with audit note |
| 61 – 100 | **Medium** | `0` | Manual review recommended |
| 101 – 150 | **High** | `0` | Retain — mandatory manual review |
| 151+ | **Critical** | `2` | Reject immediately |

> Context-aware reductions apply automatically: `UnityWebRequest` usage is penalised less when the VRChat SDK is detected; `Reflection.Emit` in an `Editor/` folder is treated as a legitimate editor tool.

---

## 6. Server Mode

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

---

## 7. Deploy on Cloudflare Containers

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

Then hit `http://localhost:8080/gui` for the interactive test console.

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
      "image": "./Dockerfile",
      "max_instances": 5,
      "instance_type": "standard-2"   // 6 GiB RAM, handles 500 MB packages in memory
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
| `standard-1` | 4 GiB | 1/2 | Medium packages (< 100 MB) |
| `standard-2` ★ | 6 GiB | 1 | Large packages (up to 500 MB) |
| `standard-3` | 8 GiB | 2 | Heavy concurrent scanning |

★ default for this project

### Limitations

- **Disk is ephemeral**: the container gets a fresh filesystem on every cold start. This project stores nothing on disk — all analysis runs in memory.
- **No inbound TCP/UDP from end users**: only HTTP requests proxied through the Worker reach the container.
- **`enableInternet` must be `true`**: otherwise `reqwest` cannot download files from R2.
- **Image must be `linux/amd64`**: the Rust binary is cross-compiled automatically in the Docker build.

---

## 8. Building from Source

**Prerequisites:**
- Rust 1.76 or later (`rustup update stable`)
- No system dependencies — all native libraries are vendored via Cargo

```bash
# Clone
git clone https://github.com/yourorg/vrcstorage-scanner.git
cd vrcstorage-scanner

# Debug build (faster compile)
cargo build

# Release build (optimized)
cargo build --release

# The binary will be at:
./target/release/vrcstorage-scanner
```

---

## 9. Running Tests

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

## 10. License

[LICENSE](/LICENSE)

---

> For architecture notes, coding conventions, and contribution rules, see [AGENTS.md](AGENTS.md).
>
> For a non-technical guide to adjusting scanner sensitivity (score thresholds, domains, point values), see [CONFIG.md](CONFIG.md).
