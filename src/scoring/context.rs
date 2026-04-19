use crate::report::Finding;
use crate::report::Severity;

/// Apply context-aware score reductions to findings.
///
/// This mutates the points of relevant findings when context
/// (e.g. VRChat SDK usage, Editor folder placement) justifies it.
pub fn apply_context_reductions(findings: &mut [Finding], source_context: &AnalysisContext) {
    for finding in findings.iter_mut() {
        // Critical-severity findings are never reduced (invariant from AGENTS.md)
        if finding.severity == Severity::Critical {
            continue;
        }

        match finding.id.as_str() {
            // HTTP in VRChat scripts is expected — reduce from 30 to 10
            "CS_HTTP_CLIENT" if source_context.has_vrchat_sdk => {
                finding.points = finding.points.min(10);
                finding.context = Some(
                    "Reduced: UnityWebRequest expected in VRChat SDK context".to_string(),
                );
            }
            // Reflection.Emit in Editor folder is legitimate
            "CS_REFLECTION_EMIT" if source_context.in_editor_folder => {
                finding.points = finding.points.min(15);
                finding.context = Some(
                    "Reduced: Reflection.Emit in Editor/ folder (legitimate editor tool)".to_string(),
                );
            }
            // Managed DLL in Plugins/ without dangerous imports → no penalty
            "DLL_OUTSIDE_PLUGINS" if source_context.is_managed_dotnet => {
                finding.points = 0;
                finding.context = Some(
                    "Reduced: managed .NET DLL in Plugins/ without dangerous imports".to_string(),
                );
            }
            // Polyglot file without a script that can load/execute byte arrays.
            //
            // A texture or audio file embedding a PE payload is only exploitable
            // if a C# loader script reads its raw bytes and calls Assembly.Load,
            // File.WriteAllBytes + Process.Start, or similar.  Without such a
            // script in the same package the payload is inert — analogous to
            // having a payload but no trigger.  Reduce from 70 → 15 pts
            // (kept above zero because the anomaly is still worth noting).
            "POLYGLOT_FILE" if !source_context.has_loader_script => {
                finding.points = 15;
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
    /// (CS_ASSEMBLY_LOAD_BYTES, CS_PROCESS_START, or CS_FILE_WRITE findings).
    /// When false, POLYGLOT_FILE findings are considered inert and their score
    /// is reduced significantly.
    pub has_loader_script: bool,
}
