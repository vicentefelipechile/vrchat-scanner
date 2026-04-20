use crate::config::{REDUCE_HTTP_VRC, REDUCE_REFLECT_EDITOR, REDUCE_POLYGLOT_NO_LOADER};
use crate::report::{Finding, FindingId, Severity};

/// Apply context-aware score reductions to findings.
///
/// This mutates the points of relevant findings when context
/// (e.g. VRChat SDK usage, Editor folder placement) justifies it.
///
/// Reduction amounts are defined in `src/config.rs`.
pub fn apply_context_reductions(findings: &mut [Finding], source_context: &AnalysisContext) {
    for finding in findings.iter_mut() {
        // Critical-severity findings are never reduced (invariant from AGENTS.md)
        if finding.severity == Severity::Critical {
            continue;
        }

        match finding.id {
            // HTTP in VRChat scripts is expected — reduce to REDUCE_HTTP_VRC
            FindingId::CsHttpClient if source_context.has_vrchat_sdk => {
                finding.points = finding.points.min(REDUCE_HTTP_VRC);
                finding.context = Some(
                    "Reduced: UnityWebRequest expected in VRChat SDK context".to_string(),
                );
            }
            // Reflection.Emit in Editor folder is legitimate
            FindingId::CsReflectionEmit if source_context.in_editor_folder => {
                finding.points = finding.points.min(REDUCE_REFLECT_EDITOR);
                finding.context = Some(
                    "Reduced: Reflection.Emit in Editor/ folder (legitimate editor tool)".to_string(),
                );
            }
            // Managed DLL in Plugins/ without dangerous imports → no penalty
            FindingId::DllOutsidePlugins if source_context.is_managed_dotnet => {
                finding.points = 0;
                finding.context = Some(
                    "Reduced: managed .NET DLL in Plugins/ without dangerous imports".to_string(),
                );
            }
            // Polyglot payload without a loader script is inert — reduce to REDUCE_POLYGLOT_NO_LOADER
            FindingId::PolyglotFile if !source_context.has_loader_script => {
                finding.points = REDUCE_POLYGLOT_NO_LOADER;
                finding.context = Some(
                    "Reduced: no loader script (Assembly.Load / Process.Start / File.Write) \
                     found in this package — embedded payload cannot self-execute"
                        .to_string(),
                );
            }
            _ => {}
        }
    }
}

/// Context gathered from the analysis phases
#[derive(Debug, Default, Clone)]
pub struct AnalysisContext {
    /// Script includes `using VRC.SDK3` or `using UdonSharp`
    pub has_vrchat_sdk: bool,
    /// DLL is .NET managed (has CLR header)
    pub is_managed_dotnet: bool,
    /// File is located inside an Editor/ folder
    pub in_editor_folder: bool,
    /// Package contains a script capable of loading or executing byte arrays
    /// (CsAssemblyLoadBytes, CsProcessStart, or CsFileWrite findings).
    /// When false, PolyglotFile findings are considered inert and their score
    /// is reduced to `config::REDUCE_POLYGLOT_NO_LOADER`.
    pub has_loader_script: bool,
}
