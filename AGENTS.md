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
| CLI scan (single) | `vrcstorage-scanner scan <FILE>` | Local file analysis |
| CLI scan (multi)  | `vrcstorage-scanner scan <FILE1> <FILE2> <DIR>` | Multiple files or folders |
| CLI JSON | `vrcstorage-scanner scan <FILE> --output json` | CI / script integration |
| CLI TXT | `vrcstorage-scanner scan <FILE> --output txt -f report.txt` | Plain-text report to file |
| CLI sanitize | `vrcstorage-scanner sanitize <FILE>` | Remove/neutralize malicious assets |
| Drag-and-drop (single) | `vrcstorage-scanner <FILE>` | Non-technical users |
| Drag-and-drop (multi) | `vrcstorage-scanner <FILE1> <FILE2> …` | Multiple files dropped at once |
| Drag-and-drop (folder) | `vrcstorage-scanner <FOLDER>` | Recursive scan of a directory |
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
├── README.md                   ← user-facing documentation
├── CONFIG.md                   ← non-technical guide to tuning src/config.rs
├── vrcstorage-scanner-workflow.md  ← design specification (source of truth)
│
├── src/
│   ├── lib.rs                  ← re-exports all modules (used by tests and integrations)
│   ├── main.rs                 ← CLI with clap: `scan`, `sanitize`, `serve`, `credits` subcommands
│   │                              also handles drag-and-drop (single file, multiple files, folders)
│   │                              IMPORTANT: must declare all modules that use crate::config
│   ├── config.rs               ← SINGLE SOURCE OF TRUTH for all tuneable constants
│   ├── pipeline.rs             ← full flow orchestration (stages 0-7)
│   ├── terminal.rs             ← TermCaps: ANSI + Unicode capability detection (Win10 VTP)
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
│   │   │   ├── obfuscation.rs      ← base64 ratio, short identifiers, XOR, unicode escapes
│   │   │   └── preprocessor.rs     ← blanks comments and inactive #if blocks before analysis
│   │   ├── assets/
│   │   │   ├── mod.rs          ← analyze_asset(): dispatches by AssetType
│   │   │   ├── texture_scanner.rs  ← magic bytes, entropy (skips PNG/JPEG/WebP/EXR/HDR/DDS), byte-by-byte polyglot scan with PE validation
│   │   │   ├── audio_scanner.rs    ← entropy (compressed formats exempt), byte-by-byte polyglot scan with PE validation
│   │   │   └── prefab_scanner.rs   ← YAML parsing, externalObjects, inline Base64
│   │   └── metadata/
│   │       ├── mod.rs          ← analyze_metadata() + pub mod declarations
│   │       ├── meta_parser.rs  ← GUID, timestamps, externalObjects
│   │       └── dependency_graph.rs ← FindingId::DllManyDependents: flags DLLs with > 5 .meta references
│   │
│   ├── sanitize/               ← `sanitize` subcommand implementation
│   │   └── mod.rs              ← run_sanitize(): applies decision matrix, rewrites .unitypackage
│   │
│   ├── scoring/
│   │   ├── mod.rs              ← re-exports compute_score, apply_context_reductions, RiskLevel
│   │   ├── scorer.rs           ← compute_score() + classification (Clean/Low/Medium/High/Critical)
│   │   ├── context.rs          ← apply_context_reductions() + AnalysisContext
│   │   └── rules.rs            ← rule table (reference only; not used at runtime)
│   │
│   ├── report/
│   │   ├── mod.rs
│   │   ├── finding.rs          ← FindingId enum, Finding struct, Severity (Low/Medium/High/Critical)
│   │   ├── json_reporter.rs    ← to_json(): serializes ScanReport to JSON
│   │   ├── cli_reporter.rs     ← print_report(): colored ANSI output
│   │   ├── txt_reporter.rs     ← render_batch_txt() / render_single_txt(): plain-text output for
│   │   │                          drag-and-drop report saving and --output txt CLI flag
│   │   └── sanitize_reporter.rs ← print_sanitize_report(): colored output for sanitize results
│   │
│   ├── server/
│   │   └── mod.rs              ← axum server: POST /scan, GET /health
│   │
│   ├── utils/
│       ├── mod.rs              ← re-exports shannon_entropy, ScannerError, Result
│       ├── entropy.rs          ← shannon_entropy(&[u8]) → f64
│       ├── error.rs            ← ScannerError (thiserror), Result alias
│       └── patterns.rs         ← lazy_static! centralized Regex + re-exports SAFE_DOMAINS from config
│
└── whitelist.rs            ← check(location, data, source) → WhitelistVerdict
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
   │   │     └── preprocessor::preprocess() → blanks comments + inactive #if blocks
   │   │         then pattern_matcher / url_extractor / obfuscation run on active_source
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
   └── JSON (to_json) or CLI (print_report) or TXT (render_batch_txt / render_single_txt)
```

> **Parallelism rule:** Stages 2-5 use `rayon::par_iter()`. Do not introduce shared mutable state
> without protection. Each `entry` is analyzed independently.

---

## 4. Modules and Responsibilities

### `config`

- **Single source of truth** for every tuneable constant: point values (`PTS_*`), entropy thresholds
  (`ENTROPY_*`), score band boundaries (`SCORE_*_MAX`), context reductions (`REDUCE_*`),
  package-level thresholds (`THRESHOLD_*`), obfuscation parameters (`OBFUSC_*`), forbidden
  extensions (`FORBIDDEN_EXTENSIONS`), the domain whitelist (`SAFE_DOMAINS`), and the known-file whitelist (`WHITELIST`).
- Declared as `pub mod config` in **both** `lib.rs` and `main.rs`. This is required because the
  project has two crate roots: `lib.rs` (used by tests) and `main.rs` (the binary). Omitting
  `mod config` from either root causes `E0432` import errors in that compilation context.
- See `CONFIG.md` for a non-technical guide to every tuneable value.

### `ingestion`

- `FileType` — top-level file type detected by magic bytes.
- `AssetType` — type of each asset within the package (classified by extension):
  `Script`, `Dll`, `Shader`, `Prefab`, `ScriptableObject`, `Texture`, `Audio`,
  `AnimationClip`, `Meta`, `Other(String)`.
- `PackageEntry` — one entry in the extracted tree: `original_path`, `asset_type`, `bytes`, `meta_content`.
- `PackageTree` — collection of `PackageEntry` indexed by GUID (keyed `String → PackageEntry`).
- `extract()` — supports `.unitypackage` (gzip TAR or plain TAR) and `.zip`. Direct files are
  wrapped in a generic `PackageEntry`. Also hydrates entries that have a `pathname` but no
  asset bytes, so orphan `.cs` files are detected for `CS_NO_META`.

### `analysis`

- `run_all_analyses(tree)` — main entry point. Returns `(Vec<Finding>, AssetCounts, AnalysisContext)`.
- Parallel sub-modules: `dll`, `scripts`, `assets`, `metadata`.
- After the parallel pass, a sequential global post-pass runs:
  - `CS_NO_META` — scripts without an associated `.meta` file.
  - `EXCESSIVE_DLLS` — packages with more than `THRESHOLD_EXCESSIVE_DLLS` DLLs.
  - `DLL_MANY_DEPENDENTS` — via `metadata::dependency_graph::analyze()`, built from `.meta`
    cross-references already in memory (GUID lines in `.meta` files).
- **Do not modify** `run_all_analyses` to add type-specific analysis logic; add it inside the
  corresponding sub-module instead.

### `preprocessor` (within `analysis::scripts`)

- `preprocess(source, extra_inactive) -> PreprocessedSource` — single-pass O(n) preprocessor
  that blanks comments and inactive `#if` blocks before any pattern-based analysis runs.
- **`active_source`** — the output field. Same byte length as input; newlines preserved so
  1-indexed line numbers remain valid. All blanked regions are replaced with spaces.
- **What is blanked:**
  - `//` line comments
  - `/* … */` block comments (including unterminated ones — blanked to EOF)
  - `#if <inactive>` … `#endif` blocks and the directive lines themselves
  - `#elif`, `#else`, `#endif` directive lines (the control lines, not their bodies unless inactive)
- **What is NOT blanked (preserved for analysis):**
  - String literals `"…"` and char literals `'…'` — content is skipped, not erased
  - Verbatim strings `@"…"` — content is skipped, not erased
  - Interpolated verbatim strings `$@"…"` and `@$"…"`
  - Active code blocks
- **Inactive define rules:**
  - `#if UNITY_EDITOR` → blanked (inactive define)
  - `#if !UNITY_EDITOR` → kept (negation of inactive = potentially active in player builds)
  - `#if UNITY_EDITOR && X` → blanked if ANY non-negated term is an inactive define
  - `#if UNITY_EDITOR || X` → kept (OR with unknown = conservatively assume active)
- **`if_stack` invariant:** starts as `vec![true]` (top-level is always active). Each `#if`
  pushes a frame; `#endif` pops one. Never pop the last frame — minimum depth is 1.
- **String literal invariant:** `skip_string_literal` and `skip_verbatim_string` always return
  an index `<= bytes.len()`. They never advance past EOF even on malformed input.
- **Verbatim string escape rule:** inside `@"…"`, the sequence `""` is an escaped quote.
  Backslash (`\`) has no special meaning. Do NOT use `skip_string_literal` for verbatim strings.
- **Obfuscation exception:** `obfuscation::analyze` runs on the **original** (non-preprocessed)
  source. Obfuscated identifiers and base64 blobs inside comments are still worth flagging.
  Only `pattern_matcher` and `url_extractor` operate on `active_source`.

### `metadata`

- `meta_parser::analyze(content, location)` — parses a single `.meta` YAML file. Returns
  `(MetaInfo, Vec<Finding>)`. Detects `META_EXTERNAL_REF` and `META_FUTURE_TIMESTAMP`.
- `dependency_graph::analyze(guid_to_path, dll_guid_count, location)` — global post-pass that
  counts how many `.meta` files reference each DLL GUID and flags those above the threshold
  with `DLL_MANY_DEPENDENTS` (threshold: `THRESHOLD_DLL_MANY_DEPENDENTS` = 5,
  `Severity::Low`, `PTS_DLL_MANY_DEPENDENTS` = 15 pts).

### `scoring`

- `compute_score(findings)` → `(u32, RiskLevel)` — sums `finding.points`.
- `apply_context_reductions(findings: &mut [Finding], context)` — mutates `finding.points`
  in-place based on context. Takes a slice, not a `Vec`, to avoid unnecessary ownership.
- `AnalysisContext` — four flags:
  - `has_vrchat_sdk` — any script uses `using VRC.SDK3`, `using UdonSharp`, or `using VRC.Udon`.
  - `is_managed_dotnet` — DLL has a CLR header (managed .NET assembly).
  - `in_editor_folder` — asset is inside an `Editor/` folder.
  - `has_loader_script` — set when `CsAssemblyLoadBytes`, `CsProcessStart`, or `CsFileWrite`
    findings are present. Used to reduce `PolyglotFile` score when no trigger exists.

### `report`

- `FindingId` — typed enum with one variant per rule (`PascalCase`). Every variant carries a
  `#[serde(rename = "SCREAMING_SNAKE_CASE")]` attribute so the JSON wire format is identical to
  the previous string representation. `FindingId` is `Copy + Hash + Eq + PartialEq`.
- `Finding` — atomic result unit: `id: FindingId`, `severity`, `points`, `location`, `detail`,
  `context`, `line_numbers`. The `line_numbers: Vec<u64>` field (1-indexed) is populated by
  `pattern_matcher` for C# findings and consumed by the sanitizer to know which exact lines to
  comment out. It is omitted from JSON when empty.
- `Severity` — `Low | Medium | High | Critical` (impl `PartialOrd`).
- `ScanReport` — complete structure serializable to JSON.
- `cli_reporter` — `print_report(&ScanReport, RiskLevel, verbose, TermCaps)`: colored ANSI output.
- `json_reporter` — `to_json(&ScanReport) -> Result<String>`: pretty-printed JSON serialization.
- `txt_reporter` — `render_batch_txt(&[BatchEntry]) -> String` and
  `render_single_txt(&ScanReport, RiskLevel, sanitized) -> String`: plain-text output with no
  ANSI escape codes, suitable for writing to `.txt` files. Used by the drag-and-drop report-save
  prompt and by `--output txt` in the `scan` subcommand.
- `sanitize_reporter` — `print_sanitize_report(&SanitizeReport, TermCaps)`: colored CLI output
  for the result of a `sanitize` run.

### `utils`

- `shannon_entropy(data: &[u8]) -> f64` — Shannon entropy. Returns `0.0` for empty slices.
- `ScannerError` — domain error enum (uses `thiserror`).
- `patterns.rs` — **all `Regex` used in the project must live here** as `lazy_static!`.
  Also re-exports `SAFE_DOMAINS` from `crate::config` so callers only need one import.

### `whitelist`

- `WhitelistVerdict` — typed enum (`FullyTrusted`, `Modified`, `NotWhitelisted`).
- `check(location, data, source)` — evaluates a C# script against `crate::config::WHITELIST`.
  If the location matches and the computed SHA-256 matches a known hash, returns `FullyTrusted` (skips all findings).
  If the location matches but the hash mismatches (or is not yet registered), returns `Modified` (runs obfuscation
  checks only and appends extra context).

---

## 5. Code Conventions

### Dual crate root — critical rule

The project compiles as **both a library** (`lib.rs`) and a **binary** (`main.rs`). Every module
that is needed in the binary must be declared with `mod <name>;` in **`main.rs`**. Currently
these are:

```rust
// src/main.rs
mod analysis;
mod config;   // ← REQUIRED — all modules use crate::config::* from the binary context
mod ingestion;
mod pipeline;
mod report;
mod sanitize; // ← sanitize subcommand
mod scoring;
mod server;
mod terminal; // ← TermCaps capability detection
mod utils;
mod whitelist; // ← Known-file whitelist evaluation
```

Omitting `mod config;` from `main.rs` produces 13 `E0432` errors because `crate::config` is
not resolvable in the binary compilation context even though `lib.rs` already declares it.

### `main.rs` — drag-and-drop multi-file/folder flow

The drag-and-drop branch handles one or more files and folders dropped onto the executable.
The execution order is fixed and **must not be changed**:

```
1. collect_unitypackages(paths)     → Vec<PathBuf>  ← recursive folder walk, dedup
2. prompt_continue_large_batch()    ← shown only when count > 6; cancels on N
3. For each file in targets:
   a. print_file_header()           ← visual separator [N/Total] (skipped for single file)
   b. run_scan_command()            → (RiskLevel, Vec<Finding>)
   c. prompt_sanitize()             ← shown only for .unitypackage with High/Critical level
   d. run_sanitize_command()        ← only if user answers Y
4. print_batch_summary()            ← shown only when targets.len() > 1
5. prompt_save_report()             ← always shown; user decides whether to save txt
6. wait_for_keypress()              ← keeps the window open
7. process::exit(2)                 ← only if any file was Critical, AFTER all of the above
```

> **Critical rule:** `process::exit(2)` must never be called inside `run_scan_command`
> when used from the drag-and-drop path. The exit is always the **last** statement.

### `main.rs` — `BatchResult` struct

`BatchResult` accumulates state for each scanned file across the drag-and-drop loop:

```rust
struct BatchResult {
    path: PathBuf,
    level: scoring::RiskLevel,
    findings: Vec<report::Finding>,  // kept for potential future use (e.g. aggregate dedup)
    sanitized: bool,
    report: Option<report::ScanReport>, // None during main pass; reserved for future optimization
                                        // that avoids the re-scan in build_txt_from_batch()
}
```

`findings` and `report` are currently unused at runtime but are intentionally kept:
- `findings` — placeholder for future aggregate analysis across the batch (e.g. cross-package dedup).
- `report` — if populated, `build_txt_from_batch` could skip re-scanning each file to build the
  txt output. Currently it always re-scans because storing full `ScanReport` structs for large
  batches would double memory usage.

> Do not remove these fields. Remove the `#[allow(dead_code)]` comment and populate them
> when implementing the optimization.

### `main.rs` — `collect_unitypackages` rules

- Regular files are passed through as-is regardless of extension (user explicitly selected them).
- Directories are walked recursively; only `.unitypackage` files are collected from directories.
- Paths are deduplicated by canonical path (resolves symlinks).
- Entries are sorted for deterministic order across platforms.
- Non-existent paths emit a warning and are skipped; they do not abort the run.

### `main.rs` — sanitize prompt helpers

Three private functions support the interactive sanitize prompt:

| Function | Signature | Purpose |
|---|---|---|
| `finding_api_label` | `(FindingId) -> &'static str` | Maps a FindingId to a short API name (e.g. `"Process.Start()"`) |
| `build_action_list` | `(&[Finding]) -> Vec<String>` | Builds a sorted per-asset action list from High/Critical findings |
| `prompt_sanitize` | `(&Path, &[Finding], TermCaps) -> bool` | Renders the prompt with `═══` separators; returns true if user answers `Y` |

`build_action_list` groups findings by `location`:
- `.cs` files → `"comment out <api1>, <api2>"`
- `.dll` / `.so` / other binary assets → `"will be removed from the package"`

The prompt uses `═══` separator lines (Unicode) or `===` (ASCII fallback) — **never box-drawing
characters**. The output filename is computed from the actual input path, not a template string.

### `preprocessor` — rules and invariants

All analysis of C# scripts goes through `preprocessor::preprocess()` before reaching
`pattern_matcher` and `url_extractor`. The following invariants must always hold:

**Must blank:**
- `//` line comments
- `/* … */` block comments (blank from `/*` to `*/` inclusive; unterminated = blank to EOF)
- `#if <inactive>` … `#endif` block bodies
- All `#if` / `#elif` / `#else` / `#endif` directive lines themselves

**Must NOT blank (skip over without erasing):**
- Contents of `"…"` string literals
- Contents of `'…'` char literals
- Contents of `@"…"` verbatim strings — escape is `""`, not `\"`
- Contents of `$@"…"` and `@$"…"` interpolated verbatim strings

**String literal dispatch order (critical — must match this order in code):**
1. `@"` → `skip_verbatim_string` — checked BEFORE plain `"`
2. `$@"` / `@$"` → `skip_verbatim_string`
3. `"` → `skip_string_literal`
4. `'` → `skip_string_literal`

> **Never** use `skip_string_literal` for verbatim strings. Verbatim strings use `""` as
> the escape sequence, not `\`. Mis-routing causes the scanner to consume code after the
> string as if it were part of the literal, silently dropping real findings.

**`skip_string_literal` safety rule:**
```rust
// CORRECT — bounds-check before advancing past the escape character
b'\\' => { i += if i + 1 < bytes.len() { 2 } else { 1 }; }

// WRONG — can advance i past bytes.len() on EOF, corrupting loop state
b'\\' => { i += 2; }
```

**`if_stack` management:**
- Minimum stack depth is always 1 (the implicit top-level active frame).
- `#endif` with `if_stack.len() == 1` is a no-op (malformed input guard).
- Pop THEN evaluate when processing `#elif` (pop old branch frame, push new one).

**`obfuscation::analyze` exception:**
Obfuscation checks run on the **raw original source**, not on `active_source`. This is
intentional: base64 blobs and short identifiers inside comments or inactive blocks are
still worth flagging at low severity since they may indicate the file was tampered with.

### `txt_reporter` — output contract

`render_batch_txt` and `render_single_txt` must:
- Produce **no ANSI escape codes** — output is written directly to `.txt` files.
- Include a timestamp (`chrono::Utc::now().to_rfc2822()`) in the header.
- Contain a summary table (score, risk level, sanitized flag, filename) followed by per-file
  detail sections, followed by aggregate totals.
- Use only plain ASCII box characters (`=`, `-`) for separators.

`render_single_txt(report, level, sanitized)` is a convenience wrapper that calls
`render_batch_txt` with a single-element slice.

### Public analysis function signatures

Each analysis sub-module exposes a public function with a canonical signature:

```rust
// DLL
pub fn analyze(data: &[u8], location: &str) -> (PeInfo, Vec<Finding>)   // pe_parser
pub fn analyze(data: &[u8], location: &str) -> Vec<Finding>             // import_scanner, string_extractor, dotnet_scanner

// Scripts
pub fn analyze_script(data: &[u8], source: &str, location: &str) -> Vec<Finding> // mod.rs
pub fn analyze(source: &str, location: &str) -> Vec<Finding>            // pattern_matcher, url_extractor, obfuscation
pub fn preprocess(source: &str, extra_inactive: &[&str]) -> PreprocessedSource   // preprocessor

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

Always use the `Finding::new()` constructor with a **`FindingId` enum variant** and optionally
`.with_context()`:

```rust
use crate::report::{Finding, FindingId, Severity};

Finding::new(
    FindingId::CsProcessStart,  // typed enum variant — NOT a raw string
    Severity::High,             // severity level
    50,                         // risk points (prefer config constants: PTS_*)
    location,                   // &str — asset path
    "Clear description of the finding",
)
.with_context(format!("key=value"))   // optional
```

**Never pass a raw `&str` as the first argument.**  All rule IDs are defined as variants in
`FindingId` (in `src/report/finding.rs`). The enum variant naming convention is `PascalCase`
and maps to the legacy `SCREAMING_SNAKE_CASE` string via `#[serde(rename)]`.

**Adding a new rule ID:**
1. Add a new variant to `FindingId` in `src/report/finding.rs`.
2. Add the matching `#[serde(rename = "MY_RULE_ID")]` attribute above the variant.
3. Add the variant to the `Display` `match` arm and to `cli_reporter::human_explanation()`.
4. Add the corresponding `PTS_*` constant to `src/config.rs`.
5. Use the new variant and constant in your analysis module.
6. Add an integration test.

Conventional variant prefixes (PascalCase → SCREAMING_SNAKE_CASE):

| Variant prefix | JSON prefix | Area |
|---|---|---|
| `Cs…` | `CS_` | C# script |
| `Dll…` / `Pe…` | `DLL_` / `PE_` | DLL/PE binary |
| `Meta…` | `META_` | `.meta` files |
| `Texture…` / `Audio…` | `TEXTURE_` / `AUDIO_` | Binary assets |
| `Polyglot…` | `POLYGLOT_` | Polyglot files |
| `Magic…` | `MAGIC_` | Magic byte mismatch |
| `Path…` | `PATH_` | Suspicious paths |
| `Prefab…` | `PREFAB_` | Prefabs / ScriptableObjects |

### Entropy thresholds

| Context | Threshold | Constant | Finding |
|---|---|---|---|
| PE section (High) | ≥ 7.2 | `ENTROPY_PE_HIGH` | `PE_HIGH_ENTROPY_SECTION` (High, 55 pts) |
| PE section (Medium) | ≥ 6.8 and < 7.2 | `ENTROPY_PE_SUSPICIOUS` | `PE_HIGH_ENTROPY_SECTION` (Medium, 20 pts) |
| Texture (uncompressed only) | > 7.5 | `ENTROPY_TEXTURE_HIGH` | `TEXTURE_HIGH_ENTROPY` |
| Audio uncompressed | outside `5.0..=7.9` | `ENTROPY_AUDIO_MIN/MAX` | `AUDIO_UNUSUAL_ENTROPY` |
| Audio compressed (mp3/ogg/aac/flac) | < 4.0 only | — | `AUDIO_UNUSUAL_ENTROPY` |

**Natively-compressed format exemptions (false-positive prevention):**
- **Textures**: PNG, JPEG, WebP, **EXR, HDR, DDS** are **exempt** from entropy checks.
  DEFLATE/lossy/ZIP/PIZ/DWAA/BCn compression naturally saturates entropy at ~7.8–8.0.
  Only BMP, TGA, and PSD (without inner compression) are checked.
- **Audio**: MP3, OGG, AAC, FLAC, Opus, M4A are **exempt** from the upper entropy bound
  (codec compression pushes entropy near 8.0 legitimately).

---

## 6. Finding System

### All FindingId variants (complete list)

The following is the definitive list of `FindingId` variants as they exist in
`src/report/finding.rs`, grouped by category.

**Structural / path**
- `PathTraversal` → `PATH_TRAVERSAL`
- `ForbiddenExtension` → `FORBIDDEN_EXTENSION`
- `DoubleExtension` → `DOUBLE_EXTENSION`

**DLL placement / package level**
- `DllOutsidePlugins` → `DLL_OUTSIDE_PLUGINS`
- `DllManyDependents` → `DLL_MANY_DEPENDENTS`
- `ExcessiveDlls` → `EXCESSIVE_DLLS`

**C# script — Critical**
- `CsProcessStart` → `CS_PROCESS_START`
- `CsAssemblyLoadBytes` → `CS_ASSEMBLY_LOAD_BYTES` *(also used for LoadFile/LoadFrom)*

**C# script — High**
- `CsFileWrite` → `CS_FILE_WRITE`
- `CsBinaryFormatter` → `CS_BINARY_FORMATTER`
- `CsDllimportUnknown` → `CS_DLLIMPORT_UNKNOWN` *(used for both known and unknown DLL imports)*
- `CsShellStrings` → `CS_SHELL_STRINGS`
- `CsUrlUnknownDomain` → `CS_URL_UNKNOWN_DOMAIN`
- `CsIpHardcoded` → `CS_IP_HARDCODED`
- `CsUnicodeEscapes` → `CS_UNICODE_ESCAPES`

**C# script — Medium**
- `CsReflectionEmit` → `CS_REFLECTION_EMIT`
- `CsHttpClient` → `CS_HTTP_CLIENT`
- `CsUnsafeBlock` → `CS_UNSAFE_BLOCK`
- `CsRegistryAccess` → `CS_REGISTRY_ACCESS`
- `CsEnvironmentAccess` → `CS_ENVIRONMENT_ACCESS`
- `CsMarshalOps` → `CS_MARSHAL_OPS`
- `CsBase64HighRatio` → `CS_BASE64_HIGH_RATIO`
- `CsXorDecryption` → `CS_XOR_DECRYPTION`

**C# script — Low**
- `CsObfuscatedIdentifiers` → `CS_OBFUSCATED_IDENTIFIERS`
- `CsNoMeta` → `CS_NO_META`

**PE/DLL binary**
- `PeInvalidHeader` → `PE_INVALID_HEADER`
- `PeParseError` → `PE_PARSE_ERROR`
- `PeHighEntropySection` → `PE_HIGH_ENTROPY_SECTION`
- `PeUnnamedSection` → `PE_UNNAMED_SECTION`
- `PeWriteExecuteSection` → `PE_WRITE_EXECUTE_SECTION`
- `PeInflatedSection` → `PE_INFLATED_SECTION`

**Import table (DLL IAT)**
- `DllImportCreateprocess` → `DLL_IMPORT_CREATEPROCESS`
- `DllImportCreateremotethread` → `DLL_IMPORT_CREATEREMOTETHREAD`
- `DllImportSockets` → `DLL_IMPORT_SOCKETS`
- `DllImportInternet` → `DLL_IMPORT_INTERNET`
- `DllImportWriteProcessMem` → `DLL_IMPORT_WRITE_PROCESS_MEM`
- `DllImportVirtualAlloc` → `DLL_IMPORT_VIRTUAL_ALLOC`
- `DllImportLoadlibrary` → `DLL_IMPORT_LOADLIBRARY`
- `DllImportGetprocaddress` → `DLL_IMPORT_GETPROCADDRESS`
- `DllImportFileOps` → `DLL_IMPORT_FILE_OPS`
- `DllImportRegistry` → `DLL_IMPORT_REGISTRY`
- `DllImportCrypto` → `DLL_IMPORT_CRYPTO`
- `DllImportSysinfo` → `DLL_IMPORT_SYSINFO`

**DLL string analysis**
- `DllStringsSuspiciousPath` → `DLL_STRINGS_SUSPICIOUS_PATH`

**Asset scanners**
- `MagicMismatch` → `MAGIC_MISMATCH`
- `MagicMismatchImage` → `MAGIC_MISMATCH_IMAGE`
- `TextureHighEntropy` → `TEXTURE_HIGH_ENTROPY`
- `AudioUnusualEntropy` → `AUDIO_UNUSUAL_ENTROPY`
- `PolyglotFile` → `POLYGLOT_FILE`

**Metadata**
- `MetaExternalRef` → `META_EXTERNAL_REF`
- `MetaFutureTimestamp` → `META_FUTURE_TIMESTAMP`

**Prefab / ScriptableObject**
- `PrefabExcessiveGuids` → `PREFAB_EXCESSIVE_GUIDS`
- `PrefabInlineB64` → `PREFAB_INLINE_B64`
- `PrefabManyScripts` → `PREFAB_MANY_SCRIPTS`

### `MagicMismatch` vs `MagicMismatchImage` — decision matrix

Both findings fire when a texture's actual binary format does not match its declared extension.
They are **mutually exclusive**: only one is emitted per file.

| Condition | Finding | Severity | Points |
|---|---|---|---|
| File is not any recognised image format | `MagicMismatch` | Medium | `PTS_MAGIC_MISMATCH` = 25 |
| File IS a recognised image but wrong format (e.g. `.png` that is actually a JPEG) | `MagicMismatchImage` | Low | `PTS_MAGIC_MISMATCH_IMAGE` = 2 |

**Decision logic in `texture_scanner::analyze`:**

```
magic_ok = declared extension matches actual magic bytes?
           │
           ├─ YES → no mismatch finding; proceed to entropy + polyglot checks
           │
           └─ NO  → is_any_image(data)?
                     │
                     ├─ YES → MagicMismatchImage  (Low, 2 pts)
                     │        mislabelled image — usually an export/rename mistake
                     │        entropy + polyglot checks still run (magic_ok = false)
                     │
                     └─ NO  → MagicMismatch       (Medium, 25 pts)
                              file is not a recognised image at all — suspicious disguise
                              entropy + polyglot checks still run
```

**`is_natively_compressed` flag interaction:**
- `is_natively_compressed` is `true` only when the magic bytes **confirm** the format (e.g. PNG
  magic for a `.png` file). A mislabelled file (`magic_ok = false`) always has
  `is_natively_compressed = false`, so entropy is checked even for compressed formats.
- This means a `.png` file that is actually a JPEG still goes through the entropy check, which
  may produce an additional `TextureHighEntropy` finding if the entropy is abnormal.

**`is_any_image` helper — recognised formats:**
PNG, JPEG, EXR, DDS, HDR (`#?RADIANCE` / `#?RGBE`), BMP, PSD, WebP (`RIFF…WEBP`).
TGA is **not** included because TGA has no universal magic bytes; it is identified by extension
only and is always treated as `magic_ok = true` to avoid false positives.

**When to add a new format to `is_any_image`:**
Add it when the format has a reliable, unique magic byte sequence AND it is commonly used
in Unity packages. Do not add formats that share magic bytes with executable formats.

### Reference scoring table

Points come from the `PTS_*` constants in `src/config.rs` — never hardcode them in analysis
modules.

| Signal | ID | Sev | Pts constant |
|---|---|---|---|
| Executable inside package | `FORBIDDEN_EXTENSION` | Critical | `PTS_FORBIDDEN_EXTENSION` = 90 |
| Path traversal (`../`) | `PATH_TRAVERSAL` | Critical | `PTS_PATH_TRAVERSAL` = 85 |
| `Assembly.Load(byte[])` in C# | `CS_ASSEMBLY_LOAD_BYTES` | Critical | `PTS_CS_ASSEMBLY_LOAD_BYTES` = 80 |
| CreateProcess / ShellExecute (IAT) | `DLL_IMPORT_CREATEPROCESS` | Critical | `PTS_DLL_IMPORT_CREATEPROCESS` = 80 |
| `Process.Start()` in C# | `CS_PROCESS_START` | Critical | `PTS_CS_PROCESS_START` = 75 |
| CreateRemoteThread (IAT) | `DLL_IMPORT_CREATEREMOTETHREAD` | Critical | `PTS_DLL_IMPORT_CREATEREMOTETHREAD` = 75 |
| Polyglot file detected | `POLYGLOT_FILE` | High | `PTS_POLYGLOT_FILE` = 70 |
| `Assembly.LoadFile/LoadFrom()` | `CS_ASSEMBLY_LOAD_BYTES` | Critical | `PTS_CS_ASSEMBLY_LOAD_FILE` = 60 |
| Unknown `[DllImport]` | `CS_DLLIMPORT_UNKNOWN` | High | `PTS_CS_DLLIMPORT_UNKNOWN` = 60 |
| Raw socket import (ws2_32) | `DLL_IMPORT_SOCKETS` | High | `PTS_DLL_IMPORT_SOCKETS` = 60 |
| URL to unknown domain / hardcoded IP | `CS_URL_UNKNOWN_DOMAIN` / `CS_IP_HARDCODED` | High | `PTS_CS_URL_UNKNOWN_DOMAIN` = 50, `PTS_CS_IP_HARDCODED` = 50 |
| Double extension | `DOUBLE_EXTENSION` | High | `PTS_DOUBLE_EXTENSION` = 50 |
| PE section entropy ≥ 7.2 | `PE_HIGH_ENTROPY_SECTION` | High | `PTS_PE_HIGH_ENTROPY_HIGH` = 55 |
| WinInet/WinHTTP import | `DLL_IMPORT_INTERNET` | High | `PTS_DLL_IMPORT_INTERNET` = 45 |
| WriteProcessMemory import | `DLL_IMPORT_WRITE_PROCESS_MEM` | High | `PTS_DLL_IMPORT_WRITE_PROCESS_MEM` = 45 |
| `BinaryFormatter` in C# | `CS_BINARY_FORMATTER` | High | `PTS_CS_BINARY_FORMATTER` = 45 |
| Shell command strings | `CS_SHELL_STRINGS` | High | `PTS_CS_SHELL_STRINGS` = 45 |
| Known system `[DllImport]` | `CS_DLLIMPORT_UNKNOWN` | Medium | `PTS_CS_DLLIMPORT_KNOWN` = 45 |
| File write/delete in C# | `CS_FILE_WRITE` | High | `PTS_CS_FILE_WRITE` = 40 |
| PE section W+X | `PE_WRITE_EXECUTE_SECTION` | High | `PTS_PE_WRITE_EXECUTE_SECTION` = 40 |
| `System.Reflection.Emit` | `CS_REFLECTION_EMIT` | Medium | `PTS_CS_REFLECTION_EMIT` = 40 |
| DLL outside `Assets/Plugins/` | `DLL_OUTSIDE_PLUGINS` | Medium | `PTS_DLL_OUTSIDE_PLUGINS` = 35 |
| Windows Registry access (C#) | `CS_REGISTRY_ACCESS` | Medium | `PTS_CS_REGISTRY_ACCESS` = 35 |
| VirtualAlloc import | `DLL_IMPORT_VIRTUAL_ALLOC` | High | `PTS_DLL_IMPORT_VIRTUAL_ALLOC` = 35 |
| Unicode escape obfuscation | `CS_UNICODE_ESCAPES` | High | `PTS_CS_UNICODE_ESCAPES` = 30 |
| HTTP/WebClient in C# | `CS_HTTP_CLIENT` | Medium | `PTS_CS_HTTP_CLIENT` = 30 |
| `unsafe` code in C# | `CS_UNSAFE_BLOCK` | Medium | `PTS_CS_UNSAFE_BLOCK` = 30 |
| Registry APIs (IAT) | `DLL_IMPORT_REGISTRY` | Medium | `PTS_DLL_IMPORT_REGISTRY` = 25 |
| External `.meta` reference | `META_EXTERNAL_REF` | Medium | `PTS_META_EXTERNAL_REF` = 25 |
| Long Base64 blob | `CS_BASE64_HIGH_RATIO` | Medium | `PTS_CS_BASE64_HIGH_RATIO` = 25 |
| Marshal ops in C# | `CS_MARSHAL_OPS` | Medium | `PTS_CS_MARSHAL_OPS` = 25 |
| Magic bytes mismatch (non-image) | `MAGIC_MISMATCH` | Medium | `PTS_MAGIC_MISMATCH` = 25 |
| XOR decryption pattern | `CS_XOR_DECRYPTION` | Medium | `PTS_CS_XOR_DECRYPTION` = 20 |
| PE section entropy 6.8–7.2 | `PE_HIGH_ENTROPY_SECTION` | Medium | `PTS_PE_HIGH_ENTROPY_MEDIUM` = 20 |
| Future timestamp in `.meta` | `META_FUTURE_TIMESTAMP` | Medium | `PTS_META_FUTURE_TIMESTAMP` = 20 |
| High entropy in texture | `TEXTURE_HIGH_ENTROPY` | Medium | `PTS_TEXTURE_HIGH_ENTROPY` = 20 |
| PE unnamed section | `PE_UNNAMED_SECTION` | Medium | `PTS_PE_UNNAMED_SECTION` = 20 |
| PE inflated section | `PE_INFLATED_SECTION` | Medium | `PTS_PE_INFLATED_SECTION` = 20 |
| LoadLibrary import | `DLL_IMPORT_LOADLIBRARY` | Low | `PTS_DLL_IMPORT_LOADLIBRARY` = 25 |
| GetProcAddress import | `DLL_IMPORT_GETPROCADDRESS` | Low | `PTS_DLL_IMPORT_GETPROCADDRESS` = 20 |
| File ops import (DeleteFile) | `DLL_IMPORT_FILE_OPS` | Low | `PTS_DLL_IMPORT_FILE_OPS` = 20 |
| Crypto import | `DLL_IMPORT_CRYPTO` | Low | `PTS_DLL_IMPORT_CRYPTO` = 20 |
| PE invalid header | `PE_INVALID_HEADER` | Low | `PTS_PE_INVALID_HEADER` = 15 |
| DLL referenced by > 5 assets | `DLL_MANY_DEPENDENTS` | Low | `PTS_DLL_MANY_DEPENDENTS` = 15 |
| More than 10 DLLs | `EXCESSIVE_DLLS` | Low | `PTS_EXCESSIVE_DLLS` = 15 |
| Obfuscated identifiers | `CS_OBFUSCATED_IDENTIFIERS` | Low | `PTS_CS_OBFUSCATED_IDENTIFIERS` = 15 |
| Environment variable access (C#) | `CS_ENVIRONMENT_ACCESS` | Medium | `PTS_CS_ENVIRONMENT_ACCESS` = 15 |
| Suspicious path in DLL strings | `DLL_STRINGS_SUSPICIOUS_PATH` | Low | `PTS_DLL_STRINGS_SUSPICIOUS_PATH` = 12 |
| Sysinfo import (GetComputerName) | `DLL_IMPORT_SYSINFO` | Low | `PTS_DLL_IMPORT_SYSINFO` = 8 |
| Audio unusual entropy | `AUDIO_UNUSUAL_ENTROPY` | Low | `PTS_AUDIO_UNUSUAL_ENTROPY` = 8 |
| Inline Base64 in prefab | `PREFAB_INLINE_B64` | Low | `PTS_PREFAB_INLINE_B64` = 8 |
| C# script without `.meta` | `CS_NO_META` | Low | `PTS_CS_NO_META` = 10 |
| PE parse error | `PE_PARSE_ERROR` | Low | `PTS_PE_PARSE_ERROR` = 5 |
| Prefab excessive GUIDs | `PREFAB_EXCESSIVE_GUIDS` | Low | `PTS_PREFAB_EXCESSIVE_GUIDS` = 5 |
| Prefab many scripts | `PREFAB_MANY_SCRIPTS` | Low | `PTS_PREFAB_MANY_SCRIPTS` = 5 |
| Image in wrong format (mislabelled) | `MAGIC_MISMATCH_IMAGE` | Low | `PTS_MAGIC_MISMATCH_IMAGE` = 2 |

### Final risk classification

| Score | Level | Action |
|---|---|---|
| 0 – `SCORE_CLEAN_MAX` (30) | `Clean` | Auto-publish |
| 31 – `SCORE_LOW_MAX` (60) | `Low` | Publish with audit note |
| 61 – `SCORE_MEDIUM_MAX` (100) | `Medium` | Manual review recommended |
| 101 – `SCORE_HIGH_MAX` (150) | `High` | Retain — mandatory manual review |
| 151+ | `Critical` | Reject; CLI exit code 2 |

---

## 7. Scoring System

### Context reductions (`apply_context_reductions`)

| `FindingId` variant | Condition | Reduction |
|---|---|---|
| `FindingId::CsHttpClient` | `has_vrchat_sdk == true` | `PTS_CS_HTTP_CLIENT` → `REDUCE_HTTP_VRC` (10 pts) |
| `FindingId::CsReflectionEmit` | `in_editor_folder == true` | `PTS_CS_REFLECTION_EMIT` → `REDUCE_REFLECT_EDITOR` (15 pts) |
| `FindingId::DllOutsidePlugins` | `is_managed_dotnet == true` | → 0 pts |
| `FindingId::PolyglotFile` | `has_loader_script == false` | `PTS_POLYGLOT_FILE` → `REDUCE_POLYGLOT_NO_LOADER` (15 pts) |

> **Critical rule:** Context reductions never affect findings with `Critical` severity.
> They only modify `finding.points`; they never change `finding.severity`.

### `has_loader_script` detection

A package is considered to have a loader script if any of these `FindingId` variants are present
in the findings list **before** `apply_context_reductions` runs:

```rust
FindingId::CsAssemblyLoadBytes | FindingId::CsProcessStart | FindingId::CsFileWrite
```

This is evaluated in `analysis::mod::run_all_analyses()` after the parallel pass completes.

### How to add a new context reduction

1. Add the required flag to `AnalysisContext` in `scoring/context.rs`.
2. Propagate the flag from `run_all_analyses()` in `analysis/mod.rs`.
3. Add the `match` arm in `apply_context_reductions()`.
4. Add the corresponding `REDUCE_*` constant to `src/config.rs`.
5. Add a test in `tests/integration/scoring_pipeline.rs`.

---

## 8. Centralized Regex Patterns

**All `Regex` must be declared in `src/utils/patterns.rs`** as `lazy_static!`.
Do not declare `Regex` inline inside analysis modules.

`SAFE_DOMAINS` is defined in `src/config.rs` and re-exported from `patterns.rs` via
`pub use crate::config::SAFE_DOMAINS;` so callers only need `use crate::utils::patterns::*`.

Current patterns:

| Variable | Detects |
|---|---|
| `URL_PATTERN` | URLs (`http://`, `https://`, `ftp://`, `ws://`, `wss://`) |
| `IP_PATTERN` | Hardcoded IP addresses |
| `BASE64_LONG` | Base64 strings ≥ 50 chars |
| `HEX_PE_HEADER` | `4D5A...` hex-encoded PE header |
| `REGISTRY_KEY` | `HKEY_`, `SOFTWARE\`, `SYSTEM\CurrentControlSet` |
| `SYSTEM_PATH` | `%APPDATA%`, `%TEMP%`, `C:\Windows\`, `C:\Users\`, `/etc/`, `/tmp/` |
| `SHELL_CMD` | `cmd.exe`, `powershell`, `bash`, `/bin/sh`, `wget`, `curl`, `ncat`, `nc.exe` |
| `PATH_TRAVERSAL` | `../` or `..\` |
| `CS_PROCESS_START` | `Process.Start(` |
| `CS_ASSEMBLY_LOAD` | `Assembly.Load/LoadFile/LoadFrom(` |
| `CS_REFLECTION_EMIT` | `System.Reflection.Emit`, `ILGenerator`, `TypeBuilder`, `MethodBuilder` |
| `CS_WEBCLIENT` | `WebClient`, `HttpClient`, `UnityWebRequest`, `TcpClient`, `UdpClient` |
| `CS_FILE_WRITE` | `File.WriteAll*`, `File.Delete`, `Directory.CreateDirectory`, `File.Move`, `File.Copy` |
| `CS_BINARY_FORMATTER` | `BinaryFormatter`, `System.Runtime.Serialization.Formatters.Binary` |
| `CS_DLLIMPORT` | `[DllImport("...")]` — captures the DLL name |
| `CS_UNSAFE` | `\bunsafe\b` — unsafe keyword in any position |
| `CS_REGISTRY` | `Microsoft.Win32.Registry` or `Registry.<Hive>` or `RegistryKey` or `HKEY_*` |
| `CS_ENVIRONMENT` | `Environment.GetEnvironmentVariable/UserName/MachineName` |
| `CS_CRYPTO` | `AesCryptoServiceProvider`, `RSACryptoServiceProvider`, `BCryptEncrypt`, `CryptEncrypt` |
| `CS_MARSHAL` | `Marshal.Copy/AllocHGlobal/GetFunctionPointerForDelegate` |
| `VRCHAT_SDK` | `using VRC.SDK3`, `using UdonSharp`, `using VRC.Udon` |
| `SHORT_IDENTIFIER` | 1-2 char identifiers (obfuscation detection) |

### Domain whitelist (`SAFE_DOMAINS`) — defined in `config.rs`

```
vrchat.com, unity3d.com, unity.com, microsoft.com, github.com,
githubusercontent.com, nuget.org, visualstudio.com, windowsupdate.com
```

Use `is_safe_domain(url: &str) -> bool` (from `utils::patterns`) to check URLs against the list.

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

- Analysis tests should build minimal input and verify concrete `FindingId` variants:
  ```rust
  use vrcstorage_scanner::report::FindingId;

  let findings = analyze_script(source, "Assets/Scripts/Test.cs");
  let has = findings.iter().any(|f| f.id == FindingId::CsProcessStart);
  assert!(has, "CsProcessStart not found; got: {:#?}", findings);
  ```
- For polyglot tests: embed the magic byte **inside the file body**, not at the start.
  Detection **skips the first 16 bytes** (legitimate format header area).
  For PE polyglots the validator requires a full DOS+PE structure (MZ → e_lfanew → `PE\0\0`).
- For scoring tests: use `compute_score(&findings)` and verify `(score, level)`.
- "No false positive" tests must ensure that specific variants do **not** appear:
  ```rust
  let suspicious: Vec<_> = findings.iter()
      .filter(|f| f.id == FindingId::MagicMismatch)
      .collect();
  assert!(suspicious.is_empty(), "...");
  ```
- When constructing `Finding` directly in tests, always use a real `FindingId` variant:
  ```rust
  Finding::new(FindingId::PeHighEntropySection, Severity::High, 50, "path", "detail")
  ```

### Preprocessor test conventions

The preprocessor has its own `#[cfg(test)]` suite in `src/analysis/scripts/preprocessor.rs`.
When adding preprocessor tests:

- Always verify that `active_source.len() == source.len()` — blanking must not change byte length.
- Test **both sides** of every condition: the blanked case and the kept case.
- Cover all string literal types: `"…"`, `'…'`, `@"…"`, `$@"…"`.
- Always include an EOF edge-case test for any new string-skipping logic (backslash at EOF,
  unterminated string at EOF, unterminated block comment).
- Preprocessor tests must never assert on the exact content of blanked regions (spaces) —
  only assert on what is present or absent by name (e.g. `contains("Process.Start")`).

### Running tests

```bash
cargo test                          # all tests (84 integration + 3 unit)
cargo test --test integration       # integration tests only
cargo test <test_name>              # specific test
cargo test 2>&1 | tail -30          # view final summary
```

---

## 10. Common Mistakes and Pitfalls

### ❌ Missing `mod config;` in `main.rs`

The project has two crate roots: `lib.rs` (library, used by tests) and `main.rs` (binary).
`lib.rs` already declares `pub mod config`, but `main.rs` **must also declare `mod config;`**
independently. Without it, every `use crate::config::*` in an analysis module will fail with
`E0432: unresolved import` when compiling the binary.

```rust
// ❌ Causes 13 E0432 errors during binary compilation
mod analysis;
mod ingestion;
// ... config missing

// ✓ Correct
mod analysis;
mod config;  // ← required in main.rs even though lib.rs already has it
mod ingestion;
```

### ❌ Polyglot scan with a fixed stride

**Wrong:**
```rust
let mut offset = 512;
while offset + 4 <= data.len() {
    offset += 512;
}
```

**Correct (byte-by-byte from byte 16):**
```rust
for offset in 16..data.len().saturating_sub(3) {
    let window = &data[offset..offset + 4];
}
```

### ❌ Checking only `MZ` for PE polyglots (false positives)

Checking only the 2-byte `MZ` sequence produces massive false positives on compressed or
encrypted data. **Always validate the full DOS+PE header structure** using `is_valid_pe_header`:

1. `MZ` at `offset`.
2. Little-endian u32 at `offset + 0x3C` (`e_lfanew`) ≥ `0x40` and fits in the buffer.
3. The bytes at `base + e_lfanew` are exactly `PE\0\0`.

Both `texture_scanner.rs` and `audio_scanner.rs` implement this locally as `is_valid_pe_header`.

### ❌ Entropy check on compressed texture/audio formats

PNG, JPEG, WebP, EXR, HDR, DDS textures and MP3, OGG, AAC, FLAC, Opus audio files are
natively compressed. Their entropy is naturally near 8.0. **Never run entropy checks on
these formats** — doing so would flag virtually every legitimate asset.

Use the `is_natively_compressed` / `is_compressed_audio` guard before calling `shannon_entropy`.

### ❌ Overly restrictive `unsafe` regex

`\bunsafe\s*\{` only detects `unsafe { }` blocks, not the keyword used as a function or method
modifier (`unsafe fn foo()`, `unsafe void Write(...)`). Use `\bunsafe\b` instead.

### ❌ Using a raw `&str` as a finding ID

```rust
// ❌ Wrong — does not compile
Finding::new("CS_PROCESS_START", Severity::Critical, 75, loc, "...");

// ✓ Correct — use the enum variant
Finding::new(FindingId::CsProcessStart, Severity::Critical, 75, loc, "...");
```

### ❌ Declaring Regex outside `patterns.rs`

All `Regex` must live in `src/utils/patterns.rs` as `lazy_static!`. A `Regex::new()` inline in
the analysis hot-path recompiles on every call.

### ❌ Modifying `finding.severity` in context reductions

`apply_context_reductions` must only modify `finding.points`. The severity of a finding is
immutable once assigned. Tests in `scoring_pipeline.rs` verify this invariant.

### ❌ Hardcoding point values in analysis modules

Use the `PTS_*` constants from `src/config.rs` rather than literal numbers in `Finding::new()`.
This ensures all values are tuneable from a single location.

### ❌ Calling `process::exit` inside `run_scan_command` in drag-and-drop mode

In the drag-and-drop path, `run_scan_command` **must not** call `process::exit(2)` directly.
Doing so closes the terminal window before `wait_for_keypress()` is reached.

```rust
// ❌ Wrong — closes window before prompts
run_scan_command(&file, "cli", None, true, caps);
wait_for_keypress(caps); // ← never reached for Critical packages

// ✓ Correct — caller defers exit until after all prompts
let (level, _findings) = run_scan_command(&file, "cli", None, true, caps);
// ... prompt_sanitize, print_batch_summary, prompt_save_report, wait_for_keypress ...
if any_critical { std::process::exit(2); } // last statement
```

### ❌ Re-scanning the file a second time in the sanitize prompt

The sanitize prompt must **not** call `pipeline::run_scan()` again. The drag-and-drop branch
already has the full findings from the first scan. Pass them directly to `prompt_sanitize`.

### ❌ Using box-drawing characters in interactive prompts

All interactive prompts must use `═══` separator lines (Unicode) or `===` (ASCII fallback).

```
// ❌ Wrong
┌──────────────────────────────────────┐
│  Threats detected.                   │
└──────────────────────────────────────┘

// ✓ Correct
════════════════════════════════════════
  Section Title
════════════════════════════════════════
```

### ❌ Adding ANSI escape codes to `txt_reporter`

`txt_reporter` output is written to `.txt` files. Never import `colored` or write `\x1b[` escape
sequences in `txt_reporter.rs`. Use only plain ASCII text and the separators defined by its
output contract (see Section 5).

### ❌ Walking all file types when scanning a folder

`collect_from_dir` must only collect `.unitypackage` files from directories. Walking other
extensions from a folder would silently scan files the user did not intend to submit. Files
passed as explicit arguments are always scanned regardless of extension.

### ❌ Using `skip_string_literal` for verbatim strings (`@"…"`)

Verbatim strings use `""` as the escape sequence, not `\`. Routing `@"…"` through
`skip_string_literal` causes it to mis-parse the string: it interprets `\"` as an escape
inside a verbatim string (which it is not), and may consume code following the string as
if it were part of the literal.

```rust
// ❌ Wrong — verbatim string mis-parsed, real findings get dropped
if bytes[i] == b'"' {
    i = skip_string_literal(bytes, i + 1, b'"');
    continue;
}

// ✓ Correct — check for @ prefix BEFORE the plain " handler
if i + 1 < len && bytes[i] == b'@' && bytes[i + 1] == b'"' {
    i = skip_verbatim_string(bytes, i + 2);
    continue;
}
if bytes[i] == b'"' {
    i = skip_string_literal(bytes, i + 1, b'"');
    continue;
}
```

### ❌ Advancing `i` past EOF in `skip_string_literal`

```rust
// ❌ Wrong — if i == len-1, i becomes len+1 (wraps or goes OOB)
b'\\' => { i += 2; }

// ✓ Correct — bound the advance
b'\\' => { i += if i + 1 < bytes.len() { 2 } else { 1 }; }
```

### ❌ Emitting `MagicMismatch` for mislabelled images

When a texture's actual binary format is a recognised image format (just a different one than
declared), use `MagicMismatchImage` (Low, 2 pts), not `MagicMismatch` (Medium, 25 pts).
The distinction matters: a `.png` that is actually a JPEG is almost certainly an accidental
rename, not an attack. Only emit `MagicMismatch` when the file is not any recognised image.

```rust
// ❌ Wrong — penalises innocent format mismatches too heavily
if !magic_ok {
    findings.push(Finding::new(FindingId::MagicMismatch, ...));
}

// ✓ Correct — distinguish disguised executables from mislabelled images
if !magic_ok {
    if is_any_image(data) {
        findings.push(Finding::new(FindingId::MagicMismatchImage, Severity::Low, PTS_MAGIC_MISMATCH_IMAGE, ...));
    } else {
        findings.push(Finding::new(FindingId::MagicMismatch, Severity::Medium, PTS_MAGIC_MISMATCH, ...));
    }
}
```

---

## 11. Server Mode (Cloudflare Containers)

The scanner ships an **axum** HTTP server designed to run inside a Cloudflare Container, called
by a Worker when a new upload arrives.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/scan` | Download from R2, scan, return JSON report |
| `GET` | `/health` | Returns `{"ok": true}` |

### `POST /scan` request body

```json
{
  "r2_url": "https://bucket.r2.cloudflarestorage.com/…",
  "file_id": "some-uuid",
  "expected_sha256": "optional-hex-hash"
}
```

If `expected_sha256` is provided and the downloaded file's hash does not match, the server
returns HTTP 400.

### HTTP error codes

| Code | Meaning |
|---|---|
| `200` | Scan completed (even Critical — the Worker enforces rejection) |
| `400` | SHA-256 mismatch |
| `502` | R2 download failed |
| `500` | Internal scan or serialization error |

### Memory model

The container **never writes files to disk**. All data — download buffer, extracted tree,
findings — lives fully in memory. This makes it safe to run multiple instances concurrently.

---

## 12. Development Commands

```bash
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Run all tests (unit + integration)
cargo test

# Integration tests only
cargo test --test integration

# A specific test by name
cargo test process_start_detected_as_critical

# Lint
cargo clippy

# Benchmarks
cargo bench

# Start server locally
cargo run -- serve --port 8080

# Scan a single file (CLI)
cargo run -- scan path/to/file.unitypackage

# Scan multiple files at once
cargo run -- scan file1.unitypackage file2.unitypackage file3.unitypackage

# Scan an entire folder recursively (collects all .unitypackage files inside)
cargo run -- scan path/to/folder/

# Scan a mix of files and folders
cargo run -- scan file1.unitypackage path/to/folder/ file2.unitypackage

# Scan and emit JSON
cargo run -- scan path/to/file.unitypackage --output json

# Scan and save a plain-text report
cargo run -- scan path/to/file.unitypackage --output txt -f report.txt

# Scan multiple files and save a combined plain-text report
cargo run -- scan file1.unitypackage file2.unitypackage --output txt -f report.txt

# Sanitize a package (removes/neutralizes High+ findings)
cargo run -- sanitize path/to/file.unitypackage

# Sanitize with custom output path and dry-run
cargo run -- sanitize path/to/file.unitypackage --output out.unitypackage --dry-run

# Sanitize acting on Medium+ findings
cargo run -- sanitize path/to/file.unitypackage --min-severity medium

# Drag-and-drop (single file) — triggers interactive pause + sanitize prompt
cargo run -- path/to/file.unitypackage

# Drag-and-drop (multiple files) — scans each, per-file sanitize prompt, batch summary,
# offer to save txt report
cargo run -- file1.unitypackage file2.unitypackage file3.unitypackage

# Drag-and-drop (folder) — recursively finds all .unitypackage files, same flow as above
cargo run -- path/to/folder/

# Drag-and-drop (mix of files and folders)
cargo run -- file1.unitypackage path/to/folder/
```