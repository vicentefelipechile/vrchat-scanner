use serde::{Deserialize, Serialize};

/// Severity level of a finding
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low      => write!(f, "LOW"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Every distinct rule ID the scanner can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingId {
    // ── Structural / path ──────────────────────────────────────────────────
    #[serde(rename = "PATH_TRAVERSAL")]
    PathTraversal,
    #[serde(rename = "FORBIDDEN_EXTENSION")]
    ForbiddenExtension,
    #[serde(rename = "DOUBLE_EXTENSION")]
    DoubleExtension,

    // ── DLL placement ──────────────────────────────────────────────────────
    #[serde(rename = "DLL_OUTSIDE_PLUGINS")]
    DllOutsidePlugins,
    #[serde(rename = "DLL_MANY_DEPENDENTS")]
    DllManyDependents,

    // ── C# script — critical ───────────────────────────────────────────────
    #[serde(rename = "CS_PROCESS_START")]
    CsProcessStart,
    #[serde(rename = "CS_ASSEMBLY_LOAD_BYTES")]
    CsAssemblyLoadBytes,

    // ── C# script — high ──────────────────────────────────────────────────
    #[serde(rename = "CS_FILE_WRITE")]
    CsFileWrite,
    #[serde(rename = "CS_BINARY_FORMATTER")]
    CsBinaryFormatter,
    #[serde(rename = "CS_DLLIMPORT_UNKNOWN")]
    CsDllimportUnknown,
    #[serde(rename = "CS_SHELL_STRINGS")]
    CsShellStrings,
    #[serde(rename = "CS_URL_UNKNOWN_DOMAIN")]
    CsUrlUnknownDomain,
    #[serde(rename = "CS_IP_HARDCODED")]
    CsIpHardcoded,
    #[serde(rename = "CS_UNICODE_ESCAPES")]
    CsUnicodeEscapes,

    // ── C# script — medium ────────────────────────────────────────────────
    #[serde(rename = "CS_REFLECTION_EMIT")]
    CsReflectionEmit,
    #[serde(rename = "CS_HTTP_CLIENT")]
    CsHttpClient,
    #[serde(rename = "CS_UNSAFE_BLOCK")]
    CsUnsafeBlock,
    #[serde(rename = "CS_REGISTRY_ACCESS")]
    CsRegistryAccess,
    #[serde(rename = "CS_ENVIRONMENT_ACCESS")]
    CsEnvironmentAccess,
    #[serde(rename = "CS_MARSHAL_OPS")]
    CsMarshalOps,
    #[serde(rename = "CS_BASE64_HIGH_RATIO")]
    CsBase64HighRatio,
    #[serde(rename = "CS_XOR_DECRYPTION")]
    CsXorDecryption,

    // ── C# script — low ───────────────────────────────────────────────────
    #[serde(rename = "CS_OBFUSCATED_IDENTIFIERS")]
    CsObfuscatedIdentifiers,
    #[serde(rename = "CS_NO_META")]
    CsNoMeta,

    // ── PE / DLL binary ───────────────────────────────────────────────────
    #[serde(rename = "PE_INVALID_HEADER")]
    PeInvalidHeader,
    #[serde(rename = "PE_PARSE_ERROR")]
    PeParseError,
    #[serde(rename = "PE_HIGH_ENTROPY_SECTION")]
    PeHighEntropySection,
    #[serde(rename = "PE_UNNAMED_SECTION")]
    PeUnnamedSection,
    #[serde(rename = "PE_WRITE_EXECUTE_SECTION")]
    PeWriteExecuteSection,
    #[serde(rename = "PE_INFLATED_SECTION")]
    PeInflatedSection,

    // ── Import table ──────────────────────────────────────────────────────
    #[serde(rename = "DLL_IMPORT_CREATEPROCESS")]
    DllImportCreateprocess,
    #[serde(rename = "DLL_IMPORT_CREATEREMOTETHREAD")]
    DllImportCreateremotethread,
    #[serde(rename = "DLL_IMPORT_SOCKETS")]
    DllImportSockets,
    #[serde(rename = "DLL_IMPORT_INTERNET")]
    DllImportInternet,
    #[serde(rename = "DLL_IMPORT_WRITE_PROCESS_MEM")]
    DllImportWriteProcessMem,
    #[serde(rename = "DLL_IMPORT_VIRTUAL_ALLOC")]
    DllImportVirtualAlloc,
    #[serde(rename = "DLL_IMPORT_LOADLIBRARY")]
    DllImportLoadlibrary,
    #[serde(rename = "DLL_IMPORT_GETPROCADDRESS")]
    DllImportGetprocaddress,
    #[serde(rename = "DLL_IMPORT_FILE_OPS")]
    DllImportFileOps,
    #[serde(rename = "DLL_IMPORT_REGISTRY")]
    DllImportRegistry,
    #[serde(rename = "DLL_IMPORT_CRYPTO")]
    DllImportCrypto,
    #[serde(rename = "DLL_IMPORT_SYSINFO")]
    DllImportSysinfo,

    // ── DLL string analysis ───────────────────────────────────────────────
    #[serde(rename = "DLL_STRINGS_SUSPICIOUS_PATH")]
    DllStringsSuspiciousPath,

    // ── Assets ────────────────────────────────────────────────────────────
    #[serde(rename = "MAGIC_MISMATCH")]
    MagicMismatch,
    /// The file is a valid image but in a different format than its extension.
    /// E.g. a file named `.png` that is actually a JPEG.
    /// Lower severity than `MagicMismatch` — mislabelled but not inherently malicious.
    #[serde(rename = "MAGIC_MISMATCH_IMAGE")]
    MagicMismatchImage,
    #[serde(rename = "TEXTURE_HIGH_ENTROPY")]
    TextureHighEntropy,
    #[serde(rename = "AUDIO_UNUSUAL_ENTROPY")]
    AudioUnusualEntropy,
    #[serde(rename = "POLYGLOT_FILE")]
    PolyglotFile,

    // ── Metadata ──────────────────────────────────────────────────────────
    #[serde(rename = "META_EXTERNAL_REF")]
    MetaExternalRef,
    #[serde(rename = "META_FUTURE_TIMESTAMP")]
    MetaFutureTimestamp,

    // ── Prefab / ScriptableObject ─────────────────────────────────────────
    #[serde(rename = "PREFAB_EXCESSIVE_GUIDS")]
    PrefabExcessiveGuids,
    #[serde(rename = "PREFAB_INLINE_B64")]
    PrefabInlineB64,
    #[serde(rename = "PREFAB_MANY_SCRIPTS")]
    PrefabManyScripts,

    // ── Package-level ─────────────────────────────────────────────────────
    #[serde(rename = "EXCESSIVE_DLLS")]
    ExcessiveDlls,
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FindingId::PathTraversal               => "PATH_TRAVERSAL",
            FindingId::ForbiddenExtension          => "FORBIDDEN_EXTENSION",
            FindingId::DoubleExtension             => "DOUBLE_EXTENSION",
            FindingId::DllOutsidePlugins           => "DLL_OUTSIDE_PLUGINS",
            FindingId::DllManyDependents           => "DLL_MANY_DEPENDENTS",
            FindingId::CsProcessStart              => "CS_PROCESS_START",
            FindingId::CsAssemblyLoadBytes         => "CS_ASSEMBLY_LOAD_BYTES",
            FindingId::CsFileWrite                 => "CS_FILE_WRITE",
            FindingId::CsBinaryFormatter           => "CS_BINARY_FORMATTER",
            FindingId::CsDllimportUnknown          => "CS_DLLIMPORT_UNKNOWN",
            FindingId::CsShellStrings              => "CS_SHELL_STRINGS",
            FindingId::CsUrlUnknownDomain          => "CS_URL_UNKNOWN_DOMAIN",
            FindingId::CsIpHardcoded               => "CS_IP_HARDCODED",
            FindingId::CsUnicodeEscapes            => "CS_UNICODE_ESCAPES",
            FindingId::CsReflectionEmit            => "CS_REFLECTION_EMIT",
            FindingId::CsHttpClient                => "CS_HTTP_CLIENT",
            FindingId::CsUnsafeBlock               => "CS_UNSAFE_BLOCK",
            FindingId::CsRegistryAccess            => "CS_REGISTRY_ACCESS",
            FindingId::CsEnvironmentAccess         => "CS_ENVIRONMENT_ACCESS",
            FindingId::CsMarshalOps                => "CS_MARSHAL_OPS",
            FindingId::CsBase64HighRatio           => "CS_BASE64_HIGH_RATIO",
            FindingId::CsXorDecryption             => "CS_XOR_DECRYPTION",
            FindingId::CsObfuscatedIdentifiers     => "CS_OBFUSCATED_IDENTIFIERS",
            FindingId::CsNoMeta                    => "CS_NO_META",
            FindingId::PeInvalidHeader             => "PE_INVALID_HEADER",
            FindingId::PeParseError                => "PE_PARSE_ERROR",
            FindingId::PeHighEntropySection        => "PE_HIGH_ENTROPY_SECTION",
            FindingId::PeUnnamedSection            => "PE_UNNAMED_SECTION",
            FindingId::PeWriteExecuteSection       => "PE_WRITE_EXECUTE_SECTION",
            FindingId::PeInflatedSection           => "PE_INFLATED_SECTION",
            FindingId::DllImportCreateprocess      => "DLL_IMPORT_CREATEPROCESS",
            FindingId::DllImportCreateremotethread => "DLL_IMPORT_CREATEREMOTETHREAD",
            FindingId::DllImportSockets            => "DLL_IMPORT_SOCKETS",
            FindingId::DllImportInternet           => "DLL_IMPORT_INTERNET",
            FindingId::DllImportWriteProcessMem    => "DLL_IMPORT_WRITE_PROCESS_MEM",
            FindingId::DllImportVirtualAlloc       => "DLL_IMPORT_VIRTUAL_ALLOC",
            FindingId::DllImportLoadlibrary        => "DLL_IMPORT_LOADLIBRARY",
            FindingId::DllImportGetprocaddress     => "DLL_IMPORT_GETPROCADDRESS",
            FindingId::DllImportFileOps            => "DLL_IMPORT_FILE_OPS",
            FindingId::DllImportRegistry           => "DLL_IMPORT_REGISTRY",
            FindingId::DllImportCrypto             => "DLL_IMPORT_CRYPTO",
            FindingId::DllImportSysinfo            => "DLL_IMPORT_SYSINFO",
            FindingId::DllStringsSuspiciousPath    => "DLL_STRINGS_SUSPICIOUS_PATH",
            FindingId::MagicMismatch               => "MAGIC_MISMATCH",
            FindingId::MagicMismatchImage          => "MAGIC_MISMATCH_IMAGE",
            FindingId::TextureHighEntropy          => "TEXTURE_HIGH_ENTROPY",
            FindingId::AudioUnusualEntropy         => "AUDIO_UNUSUAL_ENTROPY",
            FindingId::PolyglotFile                => "POLYGLOT_FILE",
            FindingId::MetaExternalRef             => "META_EXTERNAL_REF",
            FindingId::MetaFutureTimestamp         => "META_FUTURE_TIMESTAMP",
            FindingId::PrefabExcessiveGuids        => "PREFAB_EXCESSIVE_GUIDS",
            FindingId::PrefabInlineB64             => "PREFAB_INLINE_B64",
            FindingId::PrefabManyScripts           => "PREFAB_MANY_SCRIPTS",
            FindingId::ExcessiveDlls               => "EXCESSIVE_DLLS",
        };
        write!(f, "{s}")
    }
}

/// A single detected finding from any analysis stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub severity: Severity,
    pub points: u32,
    pub location: String,
    pub detail: String,
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub line_numbers: Vec<u64>,
}

impl Finding {
    pub fn new(
        id: FindingId,
        severity: Severity,
        points: u32,
        location: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            severity,
            points,
            location: location.into(),
            detail: detail.into(),
            context: None,
            line_numbers: Vec::new(),
        }
    }

    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = Some(ctx.into());
        self
    }

    pub fn with_line_numbers(mut self, lines: Vec<u64>) -> Self {
        self.line_numbers = lines;
        self
    }
}