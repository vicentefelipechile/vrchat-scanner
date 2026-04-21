use lazy_static::lazy_static;
use regex::Regex;
// Domain whitelist is defined centrally in config.rs
pub use crate::config::SAFE_DOMAINS;

lazy_static! {
    // URLs in source code
    pub static ref URL_PATTERN: Regex =
        Regex::new(r#"(?i)(https?|ftp|ws|wss)://[^\s"';)]+"#).unwrap();

    // IP addresses (rough match)
    pub static ref IP_PATTERN: Regex =
        Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();

    // Long Base64 strings (>= 50 chars)
    pub static ref BASE64_LONG: Regex =
        Regex::new(r"[A-Za-z0-9+/]{50,}={0,2}").unwrap();

    // Hex-encoded PE header (starts with MZ = 4D5A)
    pub static ref HEX_PE_HEADER: Regex =
        Regex::new(r"(?i)4[Dd]5[Aa][0-9A-Fa-f]{10,}").unwrap();

    // Registry key patterns
    pub static ref REGISTRY_KEY: Regex =
        Regex::new(r"(?i)(HKEY_|SOFTWARE\\|SYSTEM\\CurrentControlSet)").unwrap();

    // System paths
    pub static ref SYSTEM_PATH: Regex =
        Regex::new(r"(?i)(%APPDATA%|%TEMP%|C:\\Windows\\|C:\\Users\\|/etc/|/tmp/)").unwrap();

    // Shell commands embedded in strings
    pub static ref SHELL_CMD: Regex =
        Regex::new(r"(?i)\b(cmd\.exe|powershell|powershell\.exe|bash|/bin/sh|wget|curl\b|ncat|nc\.exe)\b").unwrap();

    // Path traversal
    pub static ref PATH_TRAVERSAL: Regex =
        Regex::new(r"(\.\.\/|\.\.\\)").unwrap();

    // C# dangerous API patterns
    pub static ref CS_PROCESS_START: Regex =
        Regex::new(r"Process\.Start\s*\(").unwrap();

    pub static ref CS_ASSEMBLY_LOAD: Regex =
        Regex::new(r"Assembly\.Load(File|From)?\s*\(").unwrap();

    pub static ref CS_REFLECTION_EMIT: Regex =
        Regex::new(r"System\.Reflection\.Emit|ILGenerator|TypeBuilder|MethodBuilder").unwrap();

    pub static ref CS_WEBCLIENT: Regex =
        Regex::new(r"(System\.Net\.WebClient|System\.Net\.Http\.HttpClient|UnityWebRequest|TcpClient|UdpClient)").unwrap();

    pub static ref CS_FILE_WRITE: Regex =
        Regex::new(r"(File\.WriteAll(Bytes|Text|Lines)|File\.Delete|Directory\.CreateDirectory|File\.Move|File\.Copy)\s*\(").unwrap();

    pub static ref CS_BINARY_FORMATTER: Regex =
        Regex::new(r"BinaryFormatter|System\.Runtime\.Serialization\.Formatters\.Binary").unwrap();

    pub static ref CS_DLLIMPORT: Regex =
        Regex::new(r#"\[DllImport\s*\(\s*"([^"]+)""#).unwrap();

    pub static ref CS_UNSAFE: Regex =
        Regex::new(r"\bunsafe\b").unwrap();

    // Matches real Windows Registry API usage only.
    // Avoids false positives from custom classes like PoiExternalToolRegistry:
    //   - Microsoft.Win32.Registry  — fully-qualified namespace
    //   - Registry.<Hive>           — direct access to a known hive (LocalMachine, CurrentUser, etc.)
    //   - RegistryKey               — use of the RegistryKey type (.OpenSubKey, .SetValue, etc.)
    //   - HKEY_*                    — string literals containing Win32 registry root paths
    pub static ref CS_REGISTRY: Regex =
        Regex::new(r"Microsoft\.Win32\.Registry|\bRegistry\.(LocalMachine|CurrentUser|ClassesRoot|Users|CurrentConfig|PerformanceData)\b|\bRegistryKey\b|HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)").unwrap();

    pub static ref CS_ENVIRONMENT: Regex =
        Regex::new(r"Environment\.(GetEnvironmentVariable|UserName|MachineName)").unwrap();

    pub static ref CS_CRYPTO: Regex =
        Regex::new(r"(AesCryptoServiceProvider|RSACryptoServiceProvider|BCryptEncrypt|CryptEncrypt)").unwrap();

    pub static ref CS_MARSHAL: Regex =
        Regex::new(r"(Marshal\.(Copy|AllocHGlobal|GetFunctionPointerForDelegate))").unwrap();

    // VRChat context
    pub static ref VRCHAT_SDK: Regex =
        Regex::new(r"using\s+(VRC\.SDK3|UdonSharp|VRC\.Udon)").unwrap();

    // Obfuscated identifiers (very short names, high density)
    pub static ref SHORT_IDENTIFIER: Regex =
        Regex::new(r"\b[a-zA-Z_][a-zA-Z0-9_]{0,1}\b").unwrap();
}

/// Check if a URL's host is in the whitelist defined in `config::SAFE_DOMAINS`.
pub fn is_safe_domain(url: &str) -> bool {
    SAFE_DOMAINS.iter().any(|d| url.contains(d))
}
