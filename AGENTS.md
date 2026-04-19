# AGENTS.md — vrcstorage-scanner

Reference guide for AI agents (and human developers) working in this repository.
Read this guide **before modifying any file** to understand the conventions, design invariants,
and rules that must be respected at all times.

---

## Table of Contents

1. [Project Purpose](#1-project-purpose)
2. [Repository Structure](#2-repository-structure)
3. [Analysis Pipeline](#3-analysis-pipeline)
4. [Modules and Responsibilities](#4-modules-and-responsibilities)
5. [Code Conventions](#5-code-conventions)
6. [Finding System](#6-finding-system)
7. [Scoring System](#7-scoring-system)
8. [Centralized Regex Patterns](#8-centralized-regex-patterns)
9. [Testing Rules](#9-testing-rules)
10. [Common Mistakes and Pitfalls](#10-common-mistakes-and-pitfalls)
11. [Server Mode (Cloudflare Containers)](#11-server-mode-cloudflare-containers)
12. [Development Commands](#12-development-commands)

---

## 1. Project Purpose

`vrcstorage-scanner` is a **Rust** CLI tool for static analysis of Unity/VRChat packages
(`.unitypackage`, `.zip`, `.cs`, `.dll`). It detects potentially malicious behaviors without
executing the content.

**Operation modes:**

| Mode | Command | Use case |
|---|---|---|
| CLI scan | `vrcstorage-scanner scan <FILE>` | Local file analysis |
| CLI JSON | `vrcstorage-scanner scan <FILE> --output json` | CI / script integration |
| HTTP server | `vrcstorage-scanner serve --port 8080` | Cloudflare Containers (R2 download) |

**Server output:** `POST /scan` with body `{ "r2_url": "...", "file_id": "...", "expected_sha256": "..." }`.
The server downloads the file from R2, scans it, and returns the JSON report.

---

## 2. Repository Structure

```
vrcstorage-scanner/
├── Cargo.toml                  ← crate dependencies and configuration
├── Cargo.lock
├── AGENTS.md                   ← this file
├── vrcstorage-scanner-workflow.md  ← design specification (source of truth)
│
├── src/
│   ├── lib.rs                  ← re-exports all modules (used by tests and integrations)
│   ├── main.rs                 ← CLI with clap: `scan` and `serve` subcommands
│   ├── pipeline.rs             ← full flow orchestration (stages 0-7)
│   │
│   ├── ingestion/              ← Stages 0 and 1: ingestion and extraction
│   │   ├── mod.rs
│   │   ├── file_record.rs      ← FileRecord, FileType, SHA-256/MD5/SHA-1 hashes
│   │   ├── type_detection.rs   ← file type detection by magic bytes
│   │   └── extractor.rs        ← PackageTree, PackageEntry, AssetType; extracts .unitypackage/.zip
│   │
│   ├── analysis/               ← Stages 2-5: parallel analysis with rayon
│   │   ├── mod.rs              ← run_all_analyses() → (Vec<Finding>, AssetCounts, AnalysisContext)
│   │   ├── dll/
│   │   │   ├── mod.rs          ← analyze_dll(): orchestrates pe_parser → import_scanner → string_extractor → dotnet_scanner
│   │   │   ├── pe_parser.rs    ← PE header, sections, entropy, PEInfo
│   │   │   ├── import_scanner.rs   ← IAT: dangerous imports (kernel32, ws2_32, etc.)
│   │   │   ├── string_extractor.rs ← ASCII/UTF-16 strings + URLs + shell commands
│   │   │   └── dotnet_scanner.rs   ← CLI metadata, MemberRef (only if is_dotnet == true)
│   │   ├── scripts/
│   │   │   ├── mod.rs          ← analyze_script(): calls pattern_matcher + url_extractor + obfuscation
│   │   │   ├── pattern_matcher.rs  ← regex over C# code (dangerous APIs)
│   │   │   ├── url_extractor.rs    ← embedded URLs + safe domain whitelist
│   │   │   └── obfuscation.rs      ← base64 ratio, short identifiers, XOR, unicode escapes
│   │   ├── assets/
│   │   │   ├── mod.rs          ← analyze_asset(): dispatches by AssetType
│   │   │   ├── texture_scanner.rs  ← magic bytes, entropy, byte-by-byte polyglot scan
│   │   │   ├── audio_scanner.rs    ← entropy, byte-by-byte polyglot scan
│   │   │   └── prefab_scanner.rs   ← YAML parsing, externalObjects, inline Base64
│   │   └── metadata/
│   │       ├── mod.rs          ← analyze_metadata() + pub mod declarations
│   │       ├── meta_parser.rs  ← GUID, timestamps, externalObjects
│   │       └── dependency_graph.rs ← DLL_MANY_DEPENDENTS: flags DLLs with > 5 .meta references
│   │
│   ├── scoring/
│   │   ├── mod.rs              ← re-exports compute_score, apply_context_reductions, RiskLevel
│   │   ├── scorer.rs           ← compute_score() + classification (Clean/Low/Medium/High/Critical)
│   │   ├── context.rs          ← apply_context_reductions() + AnalysisContext
│   │   └── rules.rs            ← rule table (reference only; not used at runtime)
│   │
│   ├── report/
│   │   ├── mod.rs
│   │   ├── finding.rs          ← Finding, Severity (Low/Medium/High/Critical)
│   │   ├── json_reporter.rs    ← to_json(): serializes ScanReport to JSON
│   │   └── cli_reporter.rs     ← print_report(): colored ANSI output
│   │
│   ├── server/
│   │   └── mod.rs              ← axum server: POST /scan, GET /health
│   │
│   └── utils/
│       ├── mod.rs              ← re-exports shannon_entropy, ScannerError, Result
│       ├── entropy.rs          ← shannon_entropy(&[u8]) → f64
│       ├── error.rs            ← ScannerError (thiserror), Result alias
│       └── patterns.rs         ← lazy_static! centralized Regex + SAFE_DOMAINS + is_safe_domain()
│
├── tests/
│   ├── integration.rs          ← entry point (includes integration/ modules)
│   └── integration/
│       ├── clean_package.rs
│       ├── malicious_dll.rs
│       ├── obfuscated_script.rs
│       ├── url_detection.rs
│       ├── texture_analysis.rs
│       ├── metadata_analysis.rs
│       ├── scoring_pipeline.rs
│       └── edge_cases.rs
│
└── benches/
    └── scan_performance.rs     ← benchmarks with criterion
```

---

## 3. Analysis Pipeline

The full flow runs in `src/pipeline.rs` via `run_scan()` or `run_scan_bytes()`:

```
Input (path or bytes)
   │
   ▼ Stage 0 — FileRecord::from_path()
   │   Compute SHA-256, MD5, SHA-1 + file type detection by magic bytes
   ▼ Stage 1 — extractor::extract()
   │   Unpack .unitypackage (TAR+gzip) or .zip → PackageTree
   ▼ Stages 2-5 — run_all_analyses()  ← parallel with rayon
   │   For each PackageEntry:
   │   ├── Structural checks: PATH_TRAVERSAL, FORBIDDEN_EXTENSION, DOUBLE_EXTENSION, DLL_OUTSIDE_PLUGINS
   │   ├── AssetType::Dll     → analysis::dll::analyze_dll()
   │   ├── AssetType::Script  → analysis::scripts::analyze_script()
   │   ├── AssetType::Texture → analysis::assets::analyze_asset()
   │   ├── AssetType::Audio   → analysis::assets::analyze_asset()
   │   └── AssetType::Prefab/ScriptableObject → analysis::assets::analyze_asset()
   │   + metadata::analyze_metadata() if meta_content.is_some()
   │   + global checks: CS_NO_META, EXCESSIVE_DLLS
   │   + global post-pass: metadata::dependency_graph::analyze() — cross-references .meta files
   │     to flag DLLs referenced by an abnormally high number of assets (> 5)
   ▼ Stage 6 — apply_context_reductions()
   │   Reduce points based on AnalysisContext (VRChat SDK, Editor folder, managed DLL)
   ▼ Stage 6 (cont.) — compute_score()
   │   Sum points → RiskLevel (Clean/Low/Medium/High/Critical)
   ▼ Stage 7 — ScanReport::build()
   └── JSON (to_json) or CLI (print_report)
```

> **Parallelism rule:** Stages 2-5 use `rayon::par_iter()`. Do not introduce shared mutable state
> without protection. Each `entry` is analyzed independently.

---

## 4. Modules and Responsibilities

### `ingestion`

- `FileType` — top-level file type detected by magic bytes.
- `AssetType` — type of each asset within the package (classified by extension).
- `PackageEntry` — one entry in the extracted tree: `guid`, `original_path`, `bytes`, `meta_content`.
- `PackageTree` — collection of `PackageEntry` indexed by GUID.
- `extract()` — supports `.unitypackage` (gzip TAR or plain TAR) and `.zip`. Direct files are
  wrapped in a generic `PackageEntry`.

### `analysis`

- `run_all_analyses(tree)` — main entry point. Returns `(Vec<Finding>, AssetCounts, AnalysisContext)`.
- Parallel sub-modules: `dll`, `scripts`, `assets`, `metadata`.
- After the parallel pass, a sequential global post-pass runs:
  - `CS_NO_META` — scripts without an associated `.meta` file.
  - `EXCESSIVE_DLLS` — packages with more than 10 DLLs.
  - `DLL_MANY_DEPENDENTS` — via `metadata::dependency_graph::analyze()`, built from `.meta`
    cross-references already in memory.
- **Do not modify** `run_all_analyses` to add type-specific analysis logic; add it inside the
  corresponding sub-module instead.

### `metadata`

- `meta_parser::analyze(content, location)` — parses a single `.meta` YAML file. Returns
  `(MetaInfo, Vec<Finding>)`. Detects `META_EXTERNAL_REF` and `META_FUTURE_TIMESTAMP`.
- `dependency_graph::analyze(guid_to_path, dll_guid_count, location)` — global post-pass that
  counts how many `.meta` files reference each DLL GUID and flags those above the threshold
  with `DLL_MANY_DEPENDENTS` (threshold: 5, `Severity::Low`, 15 pts).

### `scoring`

- `compute_score(findings)` → `(u32, RiskLevel)` — sums `finding.points`.
- `apply_context_reductions(findings: &mut [Finding], context)` — mutates `finding.points`
  in-place based on context. Takes a slice, not a `Vec`, to avoid unnecessary ownership.
- `AnalysisContext` — three flags: `has_vrchat_sdk`, `is_managed_dotnet`, `in_editor_folder`.

### `report`

- `Finding` — atomic result unit: `id`, `severity`, `points`, `location`, `detail`, `context`.
- `Severity` — `Low | Medium | High | Critical` (impl `PartialOrd`).
- `ScanReport` — complete structure serializable to JSON.

### `utils`

- `shannon_entropy(data: &[u8]) -> f64` — Shannon entropy. Returns `0.0` for empty slices.
- `ScannerError` — domain error enum (uses `thiserror`).
- `patterns.rs` — **all `Regex` used in the project must live here** as `lazy_static!`.

---

## 5. Code Conventions

### Public analysis function signatures

Each analysis sub-module exposes a public function with a canonical signature:

```rust
// DLL
pub fn analyze(data: &[u8], location: &str) -> (PeInfo, Vec<Finding>)   // pe_parser
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding>             // import_scanner, string_extractor, dotnet_scanner

// Scripts
pub fn analyze(source: &str, location: &str) -> Vec<Finding>            // pattern_matcher, url_extractor, obfuscation

// Assets
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding>             // texture_scanner, audio_scanner, prefab_scanner

// Metadata — per-entry
pub fn analyze_metadata(entries: &[&PackageEntry]) -> Vec<Finding>      // metadata::mod

// Metadata — global post-pass
pub fn analyze(
    guid_to_path: &HashMap<String, String>,
    dll_guid_count: &HashMap<String, usize>,
    location: &str,
) -> Vec<Finding>                                                         // metadata::dependency_graph
```

The `location` parameter is always the internal asset path within the package
(e.g. `"Assets/Plugins/MyPlugin.dll"`). It is used as `finding.location`.

### Creating findings

Always use the `Finding::new()` constructor and optionally `.with_context()`:

```rust
Finding::new(
    "RULE_ID",          // &str — unique identifier in SCREAMING_SNAKE_CASE
    Severity::High,     // severity level
    50,                 // risk points
    location,           // &str — asset path
    "Clear description of the finding",
)
.with_context(format!("key=value"))   // optional
```

**Rule IDs** must be unique, descriptive, and in `SCREAMING_SNAKE_CASE`.
Conventional prefixes:

| Prefix | Area |
|---|---|
| `CS_` | C# script |
| `DLL_` / `PE_` | DLL/PE binary |
| `META_` | `.meta` files |
| `TEXTURE_` / `AUDIO_` | Binary assets |
| `POLYGLOT_` | Polyglot files |
| `MAGIC_` | Magic byte mismatch |
| `PATH_` | Suspicious paths |

### Entropy thresholds

| Context | Threshold | Finding |
|---|---|---|
| PE section | ≥ 7.2 | `PE_HIGH_ENTROPY_SECTION` |
| PE section (suspicious) | ≥ 6.8 and < 7.2 | `PE_HIGH_ENTROPY_SECTION` (Medium, 20 pts) |
| Texture | > 7.5 | `TEXTURE_HIGH_ENTROPY` |
| Audio | outside `5.0..=7.9` | `AUDIO_UNUSUAL_ENTROPY` |

---

## 6. Finding System

### Reference scoring table

| Signal | ID | Severity | Points |
|---|---|---|---|
| Executable (`.exe`, `.bat`, `.ps1`, `.sh`) inside the package | `FORBIDDEN_EXTENSION` | Critical | 90 |
| Path traversal (`../`) | `PATH_TRAVERSAL` | Critical | 85 |
| `Assembly.Load(bytes)` in C# | `CS_ASSEMBLY_LOAD_BYTES` | Critical | 80 |
| `Process.Start()` in C# | `CS_PROCESS_START` | Critical | 75 |
| Polyglot file detected | `POLYGLOT_FILE` | High | 70 |
| `[DllImport]` **unknown** DLL in C# | `CS_DLLIMPORT_UNKNOWN` | High | 60 |
| Direct socket import (`ws2_32`) | `DLL_IMPORT_SOCKET` | High | 60 |
| PE section entropy ≥ 7.2 | `PE_HIGH_ENTROPY_SECTION` | High | 55 |
| URL to unknown domain / hardcoded IP | `CS_URL_UNKNOWN_DOMAIN` / `CS_IP_HARDCODED` | High | 50 |
| Magic bytes don't match extension | `MAGIC_MISMATCH` | Medium | 50 |
| Double extension (e.g. `file.png.dll`) | `DOUBLE_EXTENSION` | High | 50 |
| `BinaryFormatter` in C# | `CS_BINARY_FORMATTER` | High | 45 |
| Shell command strings in DLL/C# | `CS_SHELL_STRINGS` | High | 45 |
| `[DllImport]` **known** system DLL in C# | `CS_DLLIMPORT_UNKNOWN` | Medium | 45 |
| File write/delete operations in C# | `CS_FILE_WRITE` | High | 40 |
| PE section W+X (writable + executable) | `PE_WRITE_EXECUTE_SECTION` | High | 40 |
| `System.Reflection.Emit` in C# | `CS_REFLECTION_EMIT` | Medium | 40 |
| DLL outside `Assets/Plugins/` | `DLL_OUTSIDE_PLUGINS` | Medium | 35 |
| Registry access in C# | `CS_REGISTRY_ACCESS` | Medium | 35 |
| HTTP/WebClient in C# | `CS_HTTP_CLIENT` | Medium | 30 |
| `unsafe` code in C# | `CS_UNSAFE_BLOCK` | Medium | 30 |
| Reference to external asset not included | `META_EXTERNAL_REF` | Medium | 25 |
| Long Base64 string in DLL/script | `CS_BASE64_HIGH_RATIO` | Medium | 25 |
| Marshal ops in C# | `CS_MARSHAL_OPS` | Medium | 25 |
| PE section entropy 6.8–7.2 (suspicious) | `PE_HIGH_ENTROPY_SECTION` | Medium | 20 |
| Future timestamp in `.meta` | `META_FUTURE_TIMESTAMP` | Medium | 20 |
| High entropy in texture | `TEXTURE_HIGH_ENTROPY` | Medium | 20 |
| PE section without a name | `PE_UNNAMED_SECTION` | Medium | 20 |
| PE virtual size >> raw size (inflated) | `PE_INFLATED_SECTION` | Medium | 20 |
| DLL referenced by > 5 other assets | `DLL_MANY_DEPENDENTS` | Low | 15 |
| More than 10 DLLs in the package | `EXCESSIVE_DLLS` | Low | 15 |
| Obfuscated identifiers (short names) | `CS_OBFUSCATED_IDENTIFIERS` | Low | 15 |
| Suspicious system path in DLL strings | `DLL_STRINGS_SUSPICIOUS_PATH` | Low | 12 |
| Windows registry path in DLL strings | `DLL_IMPORT_REGISTRY` | Medium | 25 |
| Environment variable access in C# | `CS_ENVIRONMENT_ACCESS` | Medium | 15 |
| C# script without `.meta` | `CS_NO_META` | Low | 10 |

### Final risk classification

| Score | Level | Action |
|---|---|---|
| 0–30 | `Clean` | Auto-publish |
| 31–60 | `Low` | Publish with audit note |
| 61–100 | `Medium` | Manual review recommended |
| 101–150 | `High` | Retain — mandatory manual review |
| 151+ | `Critical` | Reject; CLI exit code 2 |

---

## 7. Scoring System

### Context reductions (`apply_context_reductions`)

| Finding ID | Condition | Reduction |
|---|---|---|
| `CS_HTTP_CLIENT` | `has_vrchat_sdk == true` | 30 → 10 pts |
| `CS_REFLECTION_EMIT` | `in_editor_folder == true` | 40 → 15 pts |
| `DLL_OUTSIDE_PLUGINS` | `is_managed_dotnet == true` | N → 0 pts |

> **Critical rule:** Context reductions never affect findings with `Critical` severity.
> They only modify `finding.points`; they never change `finding.severity`.

### How to add a new context reduction

1. Add the required flag to `AnalysisContext` in `scoring/context.rs`.
2. Propagate the flag from `run_all_analyses()` in `analysis/mod.rs`.
3. Add the `match` arm in `apply_context_reductions()`.
4. Add a test in `tests/integration/scoring_pipeline.rs`.

---

## 8. Centralized Regex Patterns

**All `Regex` must be declared in `src/utils/patterns.rs`** as `lazy_static!`.
Do not declare `Regex` inline inside analysis modules.

Current patterns:

| Variable | Detects |
|---|---|
| `URL_PATTERN` | URLs (`http://`, `https://`, `ftp://`, `ws://`, `wss://`) |
| `IP_PATTERN` | Hardcoded IP addresses |
| `BASE64_LONG` | Base64 strings ≥ 50 chars |
| `HEX_PE_HEADER` | `4D5A...` hex-encoded PE header |
| `REGISTRY_KEY` | Windows Registry keys |
| `SYSTEM_PATH` | System paths (`%APPDATA%`, `C:\Windows\`, etc.) |
| `SHELL_CMD` | `cmd.exe`, `powershell`, `bash`, `wget`, `curl`, `ncat` |
| `PATH_TRAVERSAL` | `../` or `..\` |
| `CS_PROCESS_START` | `Process.Start(` |
| `CS_ASSEMBLY_LOAD` | `Assembly.Load/LoadFile/LoadFrom(` |
| `CS_REFLECTION_EMIT` | `System.Reflection.Emit`, `ILGenerator`, `TypeBuilder` |
| `CS_WEBCLIENT` | `WebClient`, `HttpClient`, `UnityWebRequest`, `TcpClient` |
| `CS_FILE_WRITE` | `File.WriteAll*`, `File.Delete`, `Directory.CreateDirectory` |
| `CS_BINARY_FORMATTER` | `BinaryFormatter` |
| `CS_DLLIMPORT` | `[DllImport("...")]` — captures the DLL name |
| `CS_UNSAFE` | `\bunsafe\b` — unsafe keyword in any position |
| `CS_REGISTRY` | `Registry.` or `Microsoft.Win32.Registry` |
| `CS_ENVIRONMENT` | `Environment.GetEnvironmentVariable/UserName/MachineName` |
| `CS_CRYPTO` | AES/RSA/BCrypt |
| `CS_MARSHAL` | `Marshal.Copy/AllocHGlobal/GetFunctionPointerForDelegate` |
| `VRCHAT_SDK` | `using VRC.SDK3`, `using UdonSharp`, `using VRC.Udon` |
| `SHORT_IDENTIFIER` | 1-2 char identifiers (obfuscation detection) |

### Domain whitelist (`SAFE_DOMAINS`)

```
vrchat.com, unity3d.com, unity.com, microsoft.com, github.com,
githubusercontent.com, nuget.org, visualstudio.com, windowsupdate.com
```

Use `is_safe_domain(url: &str) -> bool` to check URLs against the whitelist.

---

## 9. Testing Rules

### Structure

- **Unit tests:** inside the module itself in `#[cfg(test)]` (e.g. `utils/entropy.rs`).
- **Integration tests:** in `tests/integration/<module>.rs`, included from `tests/integration.rs`.
- **Benchmarks:** in `benches/scan_performance.rs` with `criterion`.

### How to add an integration test

1. Add the function to the appropriate file in `tests/integration/`.
2. If a new test file is needed, create `tests/integration/my_module.rs` and add
   `#[path = "integration/my_module.rs"] mod my_module;` to `tests/integration.rs`.
3. Always import from `vrcstorage_scanner::` (the lib crate), not from relative paths.

### Test conventions

- Analysis tests should build minimal input and verify concrete finding IDs:
  ```rust
  let findings = analyze_script(source, "Assets/Scripts/Test.cs");
  let has = findings.iter().any(|f| f.id == "CS_PROCESS_START");
  assert!(has, "CS_PROCESS_START not found; got: {:#?}", findings);
  ```
- For polyglot tests: embed the magic byte **inside the file body**, not at the start.
  Detection **skips the first 16 bytes** (legitimate format header area).
- For scoring tests: use `compute_score(&findings)` and verify `(score, level)`.
- "No false positive" tests must ensure that specific IDs do **not** appear:
  ```rust
  let suspicious: Vec<_> = findings.iter().filter(|f| f.id == "MAGIC_MISMATCH").collect();
  assert!(suspicious.is_empty(), "...");
  ```

### Running tests

```bash
cargo test                          # all tests
cargo test --test integration       # integration tests only
cargo test <test_name>              # specific test
cargo test 2>&1 | tail -30          # view final summary
```

---

## 10. Common Mistakes and Pitfalls

### ❌ Polyglot scan with a fixed stride

**Wrong:**
```rust
let mut offset = 512;
while offset + 4 <= data.len() {
    // Only checks at 512, 1024, 1536... — misses headers that fall between strides
    offset += 512;
}
```

**Correct (byte-by-byte from byte 16):**
```rust
for offset in 16..data.len().saturating_sub(3) {
    let window = &data[offset..offset + 4];
    // ...
}
```

### ❌ Overly restrictive `unsafe` regex

`\bunsafe\s*\{` only detects `unsafe { }` blocks, not the keyword used as a function or method
modifier (`unsafe fn foo()`, `unsafe void Write(...)`). Use `\bunsafe\b` instead.

### ❌ Declaring Regex outside `patterns.rs`

All `Regex` must live in `src/utils/patterns.rs` as `lazy_static!`. A `Regex::new()` inline in
the analysis hot-path recompiles on every call.

### ❌ Modifying `finding.severity` in context reductions

`apply_context_reductions` must only modify `finding.points`. The severity of a finding is
immutable once assigned. Tests in `scoring_pipeline.rs` verify this invariant.

### ❌ Identical branches in conditional logic

When a condition is meant to produce different behavior (e.g. known vs. unknown DLL), verify
that both branches of the `if`/`match` actually differ. A dead condition misleads readers and
may silently skip the intended logic:

```rust
// ❌ Wrong — both branches are identical; the condition is pointless
let severity = if is_known { Severity::High } else { Severity::High };

// ✓ Correct — known system DLLs are less suspicious
let severity = if is_known { Severity::Medium } else { Severity::High };
```

### ❌ `&mut Vec<T>` when a slice is sufficient

If a function only iterates and mutates existing elements (no `push`, `pop`, or capacity ops),
accept `&mut [T]` instead. `&mut Vec<T>` auto-derefs to `&mut [T]` at all call sites:

```rust
// ❌ Unnecessarily restrictive — prevents passing a plain slice
pub fn apply_context_reductions(findings: &mut Vec<Finding>, ...) { ... }

// ✓ More general — callers can pass Vec or any mutable slice
pub fn apply_context_reductions(findings: &mut [Finding], ...) { ... }
```

### ❌ Shared mutable state in `par_iter()`

`run_all_analyses` uses `rayon::par_iter()`. Do not introduce `Arc<Mutex<...>>` without
justification. Findings are accumulated per entry and then flattened (`flatten()`).

### ❌ `panic!` in untrusted data analysis paths

The scanner processes arbitrary files. Use `unwrap_or_default()`, `unwrap_or(0)`, `map_err()`,
and the crate's own `Result` type wherever possible. Do not use `.unwrap()` in production code.

---

## 11. Server Mode (Cloudflare Containers)

The HTTP server is started with `vrcstorage-scanner serve --port 8080`.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/scan` | Submit a scan job |
| `GET` | `/health` | Health check; returns `{"ok": true}` |

### `POST /scan` body

```json
{
  "r2_url": "https://...r2.cloudflarestorage.com/...",
  "file_id": "file-uuid",
  "expected_sha256": "abc123..."   // optional — validates integrity before scanning
}
```

### Server flow

1. Download the file from `r2_url` using `reqwest`.
2. If `expected_sha256` is present, verify SHA-256. Mismatch → `400 Bad Request`.
3. Call `run_scan_bytes(&bytes, &file_id)` (same pipeline as CLI).
4. Serialize `ScanReport` to JSON and return it in `scan_result`.

### Server status codes

| Code | Situation |
|---|---|
| `200` | Scan completed (even if risk is CRITICAL) |
| `400` | SHA-256 mismatch |
| `502` | Failed to download from R2 |
| `500` | Internal error during scan or serialization |

> The server **does not reject** the request when risk is CRITICAL — it simply returns the result.
> The decision to reject content is the responsibility of the Cloudflare Worker consuming this endpoint.

---

## 12. Development Commands

```bash
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Run all tests
cargo test

# Run only integration tests with verbose output
cargo test --test integration -- --nocapture

# Run a specific test
cargo test unsafe_block_flagged

# Apply clippy suggestions
cargo clippy --fix

# Remove unused imports suggested by the compiler
cargo fix --lib -p vrcstorage-scanner

# Benchmarks
cargo bench

# Scan a file locally (CLI output)
cargo run -- scan Assets/my_avatar.unitypackage

# Scan a file and produce JSON
cargo run -- scan Assets/my_avatar.unitypackage --output json

# Start local server on port 9000
cargo run -- serve --port 9000
```

---

_Last updated: 2026-04-19 | Scanner version: 0.1.0 | Cleanup: dependency\_graph integrated, DLL\_MANY\_DEPENDENTS added, CS\_DLLIMPORT severity split, apply\_context\_reductions uses &mut [Finding]_
