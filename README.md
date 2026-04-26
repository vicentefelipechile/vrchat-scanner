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

The server mode is designed to run as a **Cloudflare Container** triggered by a Worker via internal binding.

### Step 1 — Build the Docker image

```dockerfile
# Dockerfile
FROM rust:1.76-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/vrcstorage-scanner .
EXPOSE 8080
CMD ["./vrcstorage-scanner", "serve", "--port", "8080"]
```

```bash
docker build -t vrcstorage-scanner:latest .
```

### Step 2 — Configure `wrangler.toml`

Add a `containers` binding to your Worker's configuration:

```toml
# wrangler.toml (in your Cloudflare Worker project)
name = "vrcstorage-worker"
main = "src/index.ts"
compatibility_date = "2025-01-01"

[[containers]]
name = "scanner"
image = "vrcstorage-scanner:latest"
max_instances = 3

[containers.scaling]
min_instances = 0
max_instances = 3
```

### Step 3 — Call the scanner from your Worker

```typescript
// src/index.ts
export interface Env {
  scanner: Container;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { r2_url, file_id, expected_sha256 } = await request.json();

    // Route to the container's /scan endpoint
    const scanRes = await env.scanner.fetch("http://scanner/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ r2_url, file_id, expected_sha256 }),
    });

    const result = await scanRes.json();

    // Reject Critical packages at the Worker level
    if (result.scan_result?.risk?.level === "Critical") {
      return Response.json(
        { error: "Package rejected — critical risk detected", scan: result },
        { status: 422 }
      );
    }

    return Response.json(result);
  },
};
```

### Step 4 — Deploy

```bash
# Push the container image to Cloudflare's registry
wrangler containers push vrcstorage-scanner:latest

# Deploy the Worker + Container binding
wrangler deploy
```

### Architecture

```
Upload flow
───────────
Browser / API client
      │
      ▼ POST /upload
Cloudflare Worker
      │  (R2 pre-signed URL passed to scanner)
      ▼ POST http://scanner/scan
vrcstorage-scanner Container
      │  (downloads from R2, runs full pipeline)
      ▼ JSON ScanReport
Cloudflare Worker
      │  (decides publish / reject / hold for review)
      ▼
Response to client
```

> **Note:** The container never stores files to disk. All analysis runs fully in memory, making it safe and stateless for multi-instance scaling.

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
