//! # vrcstorage-scanner — Centralized Configuration
//!
//! This is the **single source of truth** for every tuneable value in the scanner.
//! Non-technical contributors only need to read and edit **this one file**.
//!
//! ## How to apply a change
//!
//! 1. Edit the constant(s) you want to adjust below.
//! 2. Save the file.
//! 3. Run `cargo test` — all 84 integration tests must still pass.
//! 4. Open a pull request with your rationale.
//!
//! No other source files need to change when you tune values here.
//!
//! ## Sections
//!
//! | Section | Constants |
//! |---|---|
//! | Risk score bands | `SCORE_*_MAX` |
//! | Per-finding points | `PTS_*` |
//! | Context score reductions | `REDUCE_*` |
//! | Entropy thresholds | `ENTROPY_*` |
//! | Package-level thresholds | `THRESHOLD_*` |
//! | Obfuscation detection | `OBFUSC_*` |
//! | Forbidden extensions | `FORBIDDEN_EXTENSIONS` |
//! | Domain whitelist | `SAFE_DOMAINS` |
//! | Known-file whitelist | `WHITELIST` / `WhitelistEntry` |

// =============================================================================
// 1. RISK SCORE BANDS
//
// These four boundaries define the five risk levels.  Every scanned package
// gets a total score (sum of all finding points) which is mapped to a level:
//
//   0  …  CLEAN_MAX  →  Clean    (auto-publish)
//   …  →  LOW_MAX    →  Low      (publish with audit note)
//   …  →  MEDIUM_MAX →  Medium   (manual review recommended)
//   …  →  HIGH_MAX   →  High     (retain — mandatory manual review)
//   HIGH_MAX+1  …   →  Critical  (reject; CLI exits with code 2)
//
// Raise a boundary to make the scanner more permissive at that level.
// Lower it to be stricter.
// =============================================================================

/// Upper bound (inclusive) for the **Clean** risk band.
/// Packages at or below this score are considered safe and can be auto-published.
pub const SCORE_CLEAN_MAX: u32 = 30;

/// Upper bound (inclusive) for the **Low** risk band.
/// Packages in this range are published with an audit note for the moderator.
pub const SCORE_LOW_MAX: u32 = 60;

/// Upper bound (inclusive) for the **Medium** risk band.
/// Manual review is recommended but the package is not automatically held.
pub const SCORE_MEDIUM_MAX: u32 = 100;

/// Upper bound (inclusive) for the **High** risk band.
/// The package is retained and requires mandatory manual review before release.
pub const SCORE_HIGH_MAX: u32 = 150;

// Scores above SCORE_HIGH_MAX → Critical (reject).

// =============================================================================
// 2. PER-FINDING RISK POINTS
//
// Each constant is the number of risk points added when the corresponding
// signal is detected.  The `FindingId` variant name follows each constant for
// cross-reference.  Severity labels are informational — they are set in the
// analysis modules, not here.
//
// Guidelines for choosing a value:
//   Critical findings  → 75–100 pts  (very few legitimate packages trigger these)
//   High findings      → 40– 75 pts  (strong signals, but some false positives)
//   Medium findings    → 20– 40 pts  (notable but context-dependent)
//   Low findings       →  5– 20 pts  (worth noting; rarely decisive on their own)
//
// If you raise a value, add a comment explaining why you believe the signal is
// more dangerous than previously thought.
// =============================================================================

// =============================================================================
// Structural / path
// =============================================================================

/// `ForbiddenExtension` — Executable file type (.exe, .bat, .ps1, …) inside
/// the package.  No legitimate Unity content should ever ship a standalone
/// runnable file.  Highest single-finding score in the system.
pub const PTS_FORBIDDEN_EXTENSION: u32 = 250;

/// `PathTraversal` — A `../` or `..\` sequence in an asset path.
/// Can be exploited to write files outside the Unity project directory.
pub const PTS_PATH_TRAVERSAL: u32 = 85;

/// `DoubleExtension` — File uses two extensions (e.g. `texture.png.dll`),
/// a classic disguise technique.
pub const PTS_DOUBLE_EXTENSION: u32 = 50;

// =============================================================================
// C# script — critical
// =============================================================================

/// `CsAssemblyLoadBytes` — `Assembly.Load(bytes)` call detected.
/// Loading a .NET assembly from raw bytes hides the payload from file scanners.
pub const PTS_CS_ASSEMBLY_LOAD_BYTES: u32 = 80;

/// `CsAssemblyLoadFile` — `Assembly.LoadFile/LoadFrom()` variant (less severe
/// than loading from bytes because the source file is at least visible on disk).
pub const PTS_CS_ASSEMBLY_LOAD_FILE: u32 = 60;

/// `CsProcessStart` — `Process.Start()` call detected.
/// No legitimate VRChat/Unity content ever needs to launch an external process.
pub const PTS_CS_PROCESS_START: u32 = 75;

// =============================================================================
// C# script — high
// =============================================================================

/// `CsFileWrite` — File write, move, copy, or delete operations in C#.
/// Legitimate VRChat content has no reason to touch the host filesystem.
pub const PTS_CS_FILE_WRITE: u32 = 40;

/// `CsBinaryFormatter` — `BinaryFormatter` detected.
/// Insecure deserializer; a crafted payload can execute arbitrary .NET code.
pub const PTS_CS_BINARY_FORMATTER: u32 = 45;

/// `CsDllimportUnknown` — `[DllImport]` referencing an **unknown** native DLL.
/// Bypasses .NET's safety sandbox; high risk if the DLL origin is unknown.
pub const PTS_CS_DLLIMPORT_UNKNOWN: u32 = 60;

/// `CsDllimportKnown` — `[DllImport]` referencing a **known** Windows system DLL
/// (kernel32, user32, ntdll, …).  Still suspicious in game content but less so.
pub const PTS_CS_DLLIMPORT_KNOWN: u32 = 45;

/// `CsShellStrings` — Shell command strings (cmd.exe, powershell, curl, …)
/// embedded in C# source or DLL string constants.
pub const PTS_CS_SHELL_STRINGS: u32 = 45;

/// `CsUrlUnknownDomain` — URL pointing to a domain not on the whitelist.
/// Could be used to download additional payloads or exfiltrate data.
pub const PTS_CS_URL_UNKNOWN_DOMAIN: u32 = 50;

/// `CsIpHardcoded` — Hardcoded IP address used as a URL.
/// Classic C2 (command-and-control) indicator.
pub const PTS_CS_IP_HARDCODED: u32 = 50;

/// `CsUnicodeEscapes` — Unicode escape sequences (`\u0063md`) in C# source.
/// Used by obfuscators to disguise API calls and keywords.
pub const PTS_CS_UNICODE_ESCAPES: u32 = 30;

// =============================================================================
// C# script — medium
// =============================================================================

/// `CsReflectionEmit` — `System.Reflection.Emit` / `ILGenerator` detected.
/// Used to compile and run code at runtime; the real logic may never be on disk.
pub const PTS_CS_REFLECTION_EMIT: u32 = 40;

/// `CsHttpClient` — HTTP/WebClient/UnityWebRequest usage detected.
/// Normal in VRChat SDK tools; score is reduced by context when SDK is present.
/// See `REDUCE_HTTP_VRC` for the context-aware reduction.
pub const PTS_CS_HTTP_CLIENT: u32 = 30;

/// `CsUnsafeBlock` — `unsafe` keyword detected.
/// Disables .NET memory safety; legitimate uses exist (high-perf math) but risk
/// is real if combined with other signals.
pub const PTS_CS_UNSAFE_BLOCK: u32 = 30;

/// `CsRegistryAccess` — Windows Registry read/write detected.
/// Game content running inside Unity has no legitimate reason to touch the registry.
pub const PTS_CS_REGISTRY_ACCESS: u32 = 35;

/// `CsEnvironmentAccess` — `Environment.UserName` / `MachineName` etc. detected.
/// Used to fingerprint or specifically target victims.
pub const PTS_CS_ENVIRONMENT_ACCESS: u32 = 15;

/// `CsMarshalOps` — `Marshal.Copy/AllocHGlobal/GetFunctionPointerForDelegate`.
/// Advanced native memory ops; can be used to inject shellcode.
pub const PTS_CS_MARSHAL_OPS: u32 = 25;

/// `CsBase64HighRatio` — Large concentrated Base64 blob in script or DLL strings.
/// Used to smuggle binary payloads that are decoded at runtime.
pub const PTS_CS_BASE64_HIGH_RATIO: u32 = 25;

/// `CsXorDecryption` — Byte-array XOR loop detected.
/// Classic string or shellcode decryption technique.
pub const PTS_CS_XOR_DECRYPTION: u32 = 20;

// =============================================================================
// C# script — low
// =============================================================================

/// `CsObfuscatedIdentifiers` — Very high density of 1-2 character identifiers.
/// Obfuscation tools rename all symbols to meaningless short names.
pub const PTS_CS_OBFUSCATED_IDENTIFIERS: u32 = 15;

/// `CsNoMeta` — C# script without an associated `.meta` file.
/// Unity generates .meta files automatically; their absence suggests the script
/// was injected outside Unity's normal workflow.
pub const PTS_CS_NO_META: u32 = 10;

// =============================================================================
// PE / DLL binary
// =============================================================================

/// `PeHighEntropySection` (High variant, entropy ≥ `ENTROPY_PE_HIGH`).
/// Very high section entropy almost always means the section is packed or encrypted.
pub const PTS_PE_HIGH_ENTROPY_HIGH: u32 = 55;

/// `PeHighEntropySection` (Medium variant, entropy in `ENTROPY_PE_SUSPICIOUS..ENTROPY_PE_HIGH`).
/// Elevated entropy — suspicious but not conclusive on its own.
pub const PTS_PE_HIGH_ENTROPY_MEDIUM: u32 = 20;

/// `PeWriteExecuteSection` — Section is both writable and executable (W+X).
/// Classic shellcode injection technique.
pub const PTS_PE_WRITE_EXECUTE_SECTION: u32 = 40;

/// `PeUnnamedSection` — PE section has no name.
/// Legitimate compilers always name sections (.text, .data, etc.).
pub const PTS_PE_UNNAMED_SECTION: u32 = 20;

/// `PeInflatedSection` — Virtual size >> raw size (>= `PE_INFLATED_RATIO`× larger).
/// Hidden data fills the gap only in RAM, invisible in the file.
pub const PTS_PE_INFLATED_SECTION: u32 = 20;

/// `PeInvalidHeader` — File doesn't start with MZ magic bytes.
pub const PTS_PE_INVALID_HEADER: u32 = 15;

/// `PeParseError` — PE file could not be parsed.
pub const PTS_PE_PARSE_ERROR: u32 = 5;

// =============================================================================
// Import table (DLL)
// =============================================================================

/// `DllImportCreateprocess` — CreateProcess / ShellExecute / WinExec imported.
/// Enables launching arbitrary executables.  Treated as Critical in PE analysis.
pub const PTS_DLL_IMPORT_CREATEPROCESS: u32 = 80;

/// `DllImportCreateremotethread` — CreateRemoteThread / RtlCreateUserThread.
/// Classic code injection into other processes.
pub const PTS_DLL_IMPORT_CREATEREMOTETHREAD: u32 = 75;

/// `DllImportSockets` — ws2_32 connect / send / recv imported.
/// Enables raw network connections without going through Unity's abstractions.
pub const PTS_DLL_IMPORT_SOCKETS: u32 = 60;

/// `DllImportInternet` — WinInet / WinHTTP APIs imported.
/// Can be used to download payloads or exfiltrate data.
pub const PTS_DLL_IMPORT_INTERNET: u32 = 45;

/// `DllImportWriteProcessMem` — WriteProcessMemory imported.
/// Core API for code injection into running processes.
pub const PTS_DLL_IMPORT_WRITE_PROCESS_MEM: u32 = 45;

/// `DllImportVirtualAlloc` — VirtualAlloc imported.
/// Key step for allocating executable memory regions (shellcode staging).
pub const PTS_DLL_IMPORT_VIRTUAL_ALLOC: u32 = 35;

/// `DllImportLoadlibrary` — LoadLibrary imported.
/// Allows dynamic loading of additional DLLs invisible at import time.
pub const PTS_DLL_IMPORT_LOADLIBRARY: u32 = 25;

/// `DllImportGetprocaddress` — GetProcAddress imported.
/// Resolves function pointers at runtime, hiding what APIs are actually called.
pub const PTS_DLL_IMPORT_GETPROCADDRESS: u32 = 20;

/// `DllImportFileOps` — DeleteFile / MoveFile imported.
/// Can be used to destroy evidence or user data.
pub const PTS_DLL_IMPORT_FILE_OPS: u32 = 20;

/// `DllImportRegistry` — Registry APIs imported (advapi32).
pub const PTS_DLL_IMPORT_REGISTRY: u32 = 25;

/// `DllImportCrypto` — CryptEncrypt / BCryptEncrypt imported.
/// Ransomware and legitimate software both use these; score accordingly.
pub const PTS_DLL_IMPORT_CRYPTO: u32 = 20;

/// `DllImportSysinfo` — GetComputerName / GetUserName imported.
/// Often used for victim fingerprinting.
pub const PTS_DLL_IMPORT_SYSINFO: u32 = 8;

// =============================================================================
// DLL string analysis
// =============================================================================

/// `DllStringsSuspiciousPath` — System paths embedded in DLL string constants.
pub const PTS_DLL_STRINGS_SUSPICIOUS_PATH: u32 = 12;

/// URL to unknown domain found in DLL string constants (same weight as in scripts).
pub const PTS_DLL_URL_UNKNOWN_DOMAIN: u32 = 50;

/// Hardcoded IP address found in DLL string constants.
pub const PTS_DLL_IP_HARDCODED: u32 = 50;

// =============================================================================
// Asset scanners
// =============================================================================

/// `MagicMismatch` — File's actual format does not match its declared extension.
pub const PTS_MAGIC_MISMATCH: u32 = 25;

/// `MagicMismatchImage` — declared image extension does not match actual format,
/// but the file IS a recognised image format (e.g. a .png that is actually a JPEG).
/// Low severity — mislabelled but not inherently malicious.
pub const PTS_MAGIC_MISMATCH_IMAGE: u32 = 2;

/// `TextureHighEntropy` — Texture entropy above `ENTROPY_TEXTURE_HIGH`.
/// Only fires for uncompressed formats (PNG/JPEG/WebP are exempt).
pub const PTS_TEXTURE_HIGH_ENTROPY: u32 = 20;

/// `AudioUnusualEntropy` — Audio entropy outside the expected range.
pub const PTS_AUDIO_UNUSUAL_ENTROPY: u32 = 8;

/// `PolyglotFile` — A valid PE or ZIP header found inside a texture or audio file.
/// Score may be reduced to `REDUCE_POLYGLOT_NO_LOADER` when no loader script exists.
pub const PTS_POLYGLOT_FILE: u32 = 70;

// =============================================================================
// Metadata
// =============================================================================

/// `MetaExternalRef` — .meta file references assets not included in the package.
pub const PTS_META_EXTERNAL_REF: u32 = 5;

/// `MetaFutureTimestamp` — Creation timestamp in the .meta file is in the future.
/// Possible tampering or crafting outside Unity.
pub const PTS_META_FUTURE_TIMESTAMP: u32 = 20;

// =============================================================================
// Prefab / ScriptableObject
// =============================================================================

/// `PrefabInlineB64` — Long inline Base64 field inside a YAML prefab.
pub const PTS_PREFAB_INLINE_B64: u32 = 3;

/// `PrefabExcessiveGuids` — Binary prefab with an abnormal number of GUID refs.
pub const PTS_PREFAB_EXCESSIVE_GUIDS: u32 = 5;

/// `PrefabManyScripts` — Prefab references an unusually large number of scripts.
pub const PTS_PREFAB_MANY_SCRIPTS: u32 = 5;

// =============================================================================
// Package-level
// =============================================================================

/// `DllOutsidePlugins` — DLL found outside `Assets/Plugins/`.
/// Score is zeroed if the DLL is a managed .NET assembly (see `REDUCE_DLL_MANAGED`).
pub const PTS_DLL_OUTSIDE_PLUGINS: u32 = 35;

/// `DllManyDependents` — A single DLL is referenced by more than
/// `THRESHOLD_DLL_MANY_DEPENDENTS` other assets.
pub const PTS_DLL_MANY_DEPENDENTS: u32 = 15;

/// `ExcessiveDlls` — Package ships more than `THRESHOLD_EXCESSIVE_DLLS` DLLs.
pub const PTS_EXCESSIVE_DLLS: u32 = 15;

// =============================================================================
// 3. CONTEXT SCORE REDUCTIONS
//
// When context makes a finding less dangerous, its points are *reduced* (not
// zeroed, unless explicitly intended) to reflect the lower real-world risk.
//
// Rules enforced by AGENTS.md:
//   • Reductions never apply to findings with `Severity::Critical`.
//   • They only mutate `finding.points`; `finding.severity` is immutable.
// =============================================================================

/// `CsHttpClient` when `has_vrchat_sdk == true`.
/// `UnityWebRequest` is normal in VRChat SDK scripts (avatar upload, world data).
/// Score is reduced from `PTS_CS_HTTP_CLIENT` to this value.
pub const REDUCE_HTTP_VRC: u32 = 10;

/// `CsReflectionEmit` when `in_editor_folder == true`.
/// `System.Reflection.Emit` in an `Editor/` script is a legitimate pattern for
/// build-time code generation tools.
/// Score is reduced from `PTS_CS_REFLECTION_EMIT` to this value.
pub const REDUCE_REFLECT_EDITOR: u32 = 15;

/// `PolyglotFile` when `has_loader_script == false`.
/// An embedded PE/ZIP payload inside a texture or audio file is only exploitable
/// if a companion loader script reads it into memory.  Without such a script the
/// payload is inert.
/// Score is reduced from `PTS_POLYGLOT_FILE` to this value.
pub const REDUCE_POLYGLOT_NO_LOADER: u32 = 15;

// Note: DLL_OUTSIDE_PLUGINS is reduced to 0 when is_managed_dotnet == true.
// Zero is the hard-coded intent (the finding becomes irrelevant) so no named
// constant is needed.

// =============================================================================
// 4. ENTROPY THRESHOLDS
//
// Shannon entropy is a measure of data randomness on a scale of 0.0 (all bytes
// identical) to 8.0 (all 256 byte values appear with equal probability).
//
// Legitimate compiled code has structured patterns → typical entropy 5.5–6.5.
// Packed / encrypted sections have near-random data → entropy > 7.0.
//
// Natively compressed formats (PNG, JPEG, OGG, MP3, …) also have high entropy
// because their compression algorithms push data towards randomness.  The
// scanners explicitly skip those formats for the entropy check.
// =============================================================================

/// PE section entropy at or above this value triggers a **High** finding.
/// Values >= 7.2 are almost always the result of packing or encryption.
pub const ENTROPY_PE_HIGH: f64 = 7.2;

/// PE section entropy at or above this value (but below `ENTROPY_PE_HIGH`)
/// triggers a **Medium** finding ("suspicious but not conclusive").
pub const ENTROPY_PE_SUSPICIOUS: f64 = 6.8;

/// Texture entropy above this value triggers `TextureHighEntropy`.
/// Only applied to uncompressed texture formats (TGA, BMP, PSD, EXR, HDR, DDS).
/// PNG/JPEG/WebP are excluded because their compression naturally hits ~7.8+.
pub const ENTROPY_TEXTURE_HIGH: f64 = 7.5;

/// Audio entropy below this value triggers `AudioUnusualEntropy` for
/// uncompressed formats (WAV, AIFF).  A legitimate audio file at ~0.0 entropy
/// means it is essentially silence or a non-audio file.
pub const ENTROPY_AUDIO_MIN: f64 = 5.0;

/// Audio entropy above this value triggers `AudioUnusualEntropy` for
/// uncompressed formats.  Compressed audio (MP3, OGG, FLAC) is exempt because
/// their compression codec raises entropy naturally above 7.5.
pub const ENTROPY_AUDIO_MAX: f64 = 7.9;

// =============================================================================
// 5. PACKAGE-LEVEL THRESHOLDS
// =============================================================================

/// A package containing more DLLs than this triggers `ExcessiveDlls`.
/// More DLLs mean more attack surface and more code the scanner must review.
pub const THRESHOLD_EXCESSIVE_DLLS: usize = 10;

/// A DLL referenced by more than this many `.meta` files triggers
/// `DllManyDependents`.  High fan-in means a single compromised DLL can affect
/// many assets.
pub const THRESHOLD_DLL_MANY_DEPENDENTS: usize = 5;

/// A prefab with more than this many `m_Script:` entries triggers
/// `PrefabManyScripts`.
pub const THRESHOLD_PREFAB_MANY_SCRIPTS: usize = 20;

/// A binary prefab with more than this many inline GUID references triggers
/// `PrefabExcessiveGuids`.
pub const THRESHOLD_PREFAB_EXCESSIVE_GUIDS: usize = 100;

/// PE section inflation ratio: if virtual_size > raw_size × this value **and**
/// raw_size > 0, the section is flagged as `PeInflatedSection`.
/// A ratio of 4× means the section expands to at least 4 times its on-disk size
/// in RAM, which is unusual outside of intentional runtime decompression or
/// injection staging.
pub const PE_INFLATED_RATIO: u64 = 4;

/// Minimum ASCII string length (inclusive) extracted from DLL binaries for
/// string analysis.  Shorter strings produce too many false positives.
pub const DLL_MIN_STRING_LEN: usize = 6;

// =============================================================================
// 6. OBFUSCATION DETECTION
// =============================================================================

/// Base64 character ratio above which `CsBase64HighRatio` fires.
/// If more than this fraction of the script's total characters belong to
/// Base64 matches, the script is flagged.
/// Value: 0.15 = 15 % of the file is Base64 data.
pub const OBFUSC_BASE64_RATIO: f64 = 0.15;

/// Individual Base64 string length (characters) above which the string is
/// flagged as suspicious even if the file-level ratio is below
/// `OBFUSC_BASE64_RATIO`.
pub const OBFUSC_BASE64_LONG_LEN: usize = 200;

/// Minimum number of tokens in the script before the short-identifier check is
/// applied.  Very short scripts (test stubs, data files) would almost always
/// trigger this check otherwise.
pub const OBFUSC_MIN_TOKENS: usize = 50;

/// Maximum fraction of tokens that may be 1-2 character identifiers before
/// `CsObfuscatedIdentifiers` fires.
/// Value: 0.4 = 40 % of all alphanumeric tokens are very short.
pub const OBFUSC_SHORT_IDENT_RATIO: f64 = 0.4;

// =============================================================================
// 7. FORBIDDEN EXTENSIONS
//
// Files with any of these extensions inside a Unity package are **always**
// flagged as `ForbiddenExtension` with Critical severity, regardless of content.
//
// To add a new extension, append it to the slice (lowercase, without the dot).
// To remove a false-positive trigger for a specific extension, delete it here
// and describe the rationale in your PR.
// =============================================================================

/// File extensions that are never legitimate inside a Unity/VRChat package.
/// Matched case-insensitively against the asset's on-disk extension.
pub const FORBIDDEN_EXTENSIONS: &[&str] = &[
    "exe", // Windows executable
    "bat", // Windows batch script
    "cmd", // Windows command file
    "ps1", // PowerShell script
    "sh",  // Unix shell script
    "vbs", // VBScript
    "jar", // Java archive (can contain runnable code)
    "msi", // Windows installer
    // "com", // DOS/Windows legacy executable but also used for websites so idk
    "scr", // Windows screensaver (executable)
    "hta", // HTML Application (runs with system privileges)
    "pif", // Program Information File (executable shortcut)
];

// =============================================================================
// 8. DOMAIN WHITELIST
//
// URLs pointing to domains on this list do NOT produce a `CsUrlUnknownDomain`
// or `CsIpHardcoded` finding.  Only add domains here if:
//
//   a) They belong to a platform or tool that VRChat/Unity content legitimately
//      contacts (e.g. the VRChat API, Unity package registry).
//   b) You are confident the domain cannot be purchased and repurposed by an
//      attacker (typo-squatting risk).
//
// Matching is substring-based: "github.com" also matches "api.github.com" and
// "raw.githubusercontent.com".
//
// To add a domain, append it to the slice and explain in your PR why it is safe.
// To remove a domain, delete it and describe what changed.
// =============================================================================

/// Domains whose URLs are treated as safe (no URL finding emitted).
pub const SAFE_DOMAINS: &[&str] = &[
    // Developer pages
    "vrchat.com",               // VRChat official platform & API
    "unity3d.com",              // Unity legacy CDN and asset store
    "unity.com",                // Unity website, package registry
    "microsoft.com",            // NuGet feed, authentication endpoints
    "github.com",               // Source repos, releases
    "githubusercontent.com",    // GitHub raw file hosting
    "nuget.org",                // .NET package registry
    "visualstudio.com",         // Azure DevOps, VS Marketplace
    "windowsupdate.com",        // Windows Update (rare but legitimate in managed DLLs)
    "thryrallo.de",             // Framework that powers the User Interface of poiyomi.
    "stackexchange.com",        // Stack Exchange websites
    "youtube.com",              // Youtube videos
    "poiyomi.com",              // PoiYomi's website
    "translate.googleapis.com", // Google Translate API
    "cloud.google.com",         // Google Cloud Storage
    // Credits pages
    "gumroad.com", // Gumroad
    "ko-fi.com",   // Ko-fi
    "linktr.ee",   // Linktree
    "twitter.com", // Twitter
    "x.com",       // X
    "discord.gg",  // Discord invites
    "patreon.com", // Patreon
];

// =============================================================================
// 9. KNOWN-FILE WHITELIST
//
// C# files listed here are treated differently depending on whether their
// SHA-256 matches a known-good hash:
//
//   • Hash match  → FullyTrusted : no findings emitted at all.
//   • Hash mismatch / no hashes registered
//                 → Modified     : only obfuscation checks run, and every
//                                  finding gets extra context attached.
//
// To add a new trusted file:
//   1. Append a WhitelistEntry to WHITELIST below.
//   2. Set path_patterns to uniquely identify the file's internal Unity path.
//   3. Add SHA-256 hashes of known-good versions to sha256_hashes.
//   4. Optionally set expected_line_range to the normal line-count range.
//
// To register a new hash for an existing entry, append it to sha256_hashes.
// =============================================================================

/// A single entry in the known-file whitelist.
/// See `src/whitelist.rs` for the verification logic that consumes this type.
pub struct WhitelistEntry {
    /// Human-readable name of the file/package (used in finding context messages).
    pub name: &'static str,
    /// All substrings must appear in the asset path for this entry to match
    /// (case-sensitive, AND logic).
    pub path_patterns: &'static [&'static str],
    /// SHA-256 hex strings (lowercase) for each known-good version.
    /// Leave empty while no hashes have been registered — the file will be
    /// treated as Modified (obfuscation-only analysis) until hashes are added.
    pub sha256_hashes: &'static [&'static str],
    /// Acceptable line-count range (inclusive both ends).
    /// `None` means no line-count check is performed.
    pub expected_line_range: Option<(usize, usize)>,
}

/// The list of known standard C# files that should not be flagged as malicious.
/// **Edit only this slice** to manage the whitelist.
pub static WHITELIST: &[WhitelistEntry] = &[
    // == Poiyomi Toon Shader ===================================================
    WhitelistEntry {
        name: "Poiyomi Toon - Localization",
        path_patterns: &["_PoiyomiShaders", "Scripts", "ThryEditor", "Editor", "Localization"],
        sha256_hashes: &[
            "0d5c54207ec13e6583eba4d79628539658e9d46842a17175502df9a0fdf14694",
        ],
        expected_line_range: Some((673, 674)),
    },
    WhitelistEntry {
        name: "Poiyomi Toon - PoiOutlineUtil",
        path_patterns: &["_PoiyomiShaders", "Scripts", "poi-tools", "Editor", "Tools and Editors", "PoiOutlineUtil"],
        sha256_hashes: &[
            "033d5681c9cda2c80b4e7af794bcb3f3f3fa06d6eb2283d97dbf413ca64cfd50",
        ],
        expected_line_range: Some((686, 687)),
    },
    WhitelistEntry {
        name: "Poiyomi Toon - ThirdPartyIncluder",
        path_patterns: &["_PoiyomiShaders", "Scripts", "poi-tools", "Editor", "Export Stuff", "ThirdPartyIncluder"],
        sha256_hashes: &[
            "7505b4bf8700f1119ed0960b5a1ed26433f7e0793763ff4b34ced1332f1182d6",
        ],
        expected_line_range: Some((219, 220)),
    },
    WhitelistEntry {
        name: "Poiyomi Toon - PoiHelpers",
        path_patterns: &["_PoiyomiShaders", "Scripts", "poi-tools", "Editor", "Helpers and Extensions", "PoiHelpers"],
        sha256_hashes: &[
            "8845fe7e02a2ff316477dd3675d7be3a6d0175d56f5ff13acefaa40e27f7620b",
        ],
        expected_line_range: Some((279, 280)),
    },
    WhitelistEntry {
        name: "Poiyomi Toon - PoiSettingsUtility",
        path_patterns: &["_PoiyomiShaders", "Scripts", "poi-tools", "Editor", "PoiSettingsUtility"],
        sha256_hashes: &[
            "6678e7ff492fc71ec825e34106e0986224c2f3b211cabc8433099b494e7ba08d",
        ],
        expected_line_range: Some((102, 103)),
    },
    WhitelistEntry {
        name: "Poiyomi Toon - Presets",
        path_patterns: &["_PoiyomiShaders", "Scripts", "ThryEditor", "Editor", "Presets"],
        sha256_hashes: &[
            "eaf18df7c3faaf699877068f0465dc850d8490622ba4668cce427cc8af5cc272",
        ],
        expected_line_range: Some((974, 975)),
    },
    WhitelistEntry {
        name: "Poiyomi Toon - InspectorCapture",
        path_patterns: &["_PoiyomiShaders", "Scripts", "ThryEditor", "Editor", "Debug", "InspectorCapture"],
        sha256_hashes: &[
            "45959564f26da89f04992fe2a7250b5a5135b7ca072ce86c0f5c2ece4eadf3d1",
        ],
        expected_line_range: Some((185, 186)),
    },
    WhitelistEntry {
        name: "Poiyomi Toon - FileHelper",
        path_patterns: &["_PoiyomiShaders", "Scripts", "ThryEditor", "Editor", "Helpers", "FileHelper"],
        sha256_hashes: &[
            "b7eb17fc7ca403caf4da4c0a559b4a81a81ec557a469698599b67c9af59b695f",
        ],
        expected_line_range: Some((137, 138)),
    },
    WhitelistEntry {
        name: "Poiyomi Toon - TrashHandler",
        path_patterns: &["_PoiyomiShaders", "Scripts", "ThryEditor", "Editor", "Helpers", "TrashHandler"],
        sha256_hashes: &[
            "7492e934475d95d8cf086bed99b072f38fe0f25ec11c9cf3b3cb0180df6c5667",
        ],
        expected_line_range: Some((50, 51)),
    },
    WhitelistEntry {
        name: "Poiyomi Toon - Helper",
        path_patterns: &["_PoiyomiShaders", "Scripts", "ThryEditor", "Editor", "Helpers", "Helper"],
        sha256_hashes: &[
            "64251b638c73a5f80ccebf2f07b8d22c9662067d8f6d0d60921423f64f35e81d",
        ],
        expected_line_range: Some((323, 324)),
    },
];