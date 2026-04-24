/// Output of the C# source preprocessor.
///
/// All analysis modules should operate on `active_source` rather than the
/// raw source string so that:
///   - Comments (`//` and `/* */`) are blanked out.
///   - Code inside inactive `#if` blocks (editor-only, SDK-specific, etc.)
///     is blanked out.
///
/// "Blanked out" means replaced with whitespace of equal length so that
/// 1-indexed line numbers remain valid for the original file.
pub struct PreprocessedSource {
    /// Source with comments and inactive blocks replaced by spaces.
    /// Same byte length as the original — line numbers are preserved.
    pub active_source: String,
    // Original source, untouched. Used only for line-count and whitelist checks.
    // pub original: String,
}

/// Symbols whose `#if` / `#elif` blocks are considered inactive for security
/// analysis purposes.  Code inside these guards is unlikely to run in a
/// standard VRChat/Unity player build.
///
/// All comparisons are case-insensitive.
///
/// Extend this list in `config.rs` via `INACTIVE_DEFINES` (see below).
/// The list here is the hard-coded fallback used when the config constant
/// is not yet present.
const BUILTIN_INACTIVE_DEFINES: &[&str] = &[
    // Unity editor-only — never runs in a player build
    "UNITY_EDITOR",
    "UNITY_EDITOR_WIN",
    "UNITY_EDITOR_OSX",
    "UNITY_EDITOR_LINUX",
    // Platform stubs that only exist when a specific SDK is installed
    "CVR_CCK_EXISTS",       // ChilloutVR Creator Kit
    "VRC_SDK_VRCSDK2",      // VRChat SDK2 (legacy)
    "VRC_SDK_VRCSDK3",      // VRChat SDK3
    "UDON",                 // UdonSharp
    "RESONITE",             // Resonite / NeosVR
    "MELONLOADER",          // MelonLoader mod environment
    // Debug / development guards
    "DEBUG",
    "DEVELOPMENT_BUILD",
];

/// Preprocess a C# source string.
///
/// Pass `inactive_defines` from `crate::config::INACTIVE_DEFINES` when
/// available; otherwise pass an empty slice to use only the built-in list.
pub fn preprocess(source: &str, extra_inactive: &[&str]) -> PreprocessedSource {
    let combined: Vec<&str> = BUILTIN_INACTIVE_DEFINES
        .iter()
        .copied()
        .chain(extra_inactive.iter().copied())
        .collect();

    let active_source = blank_inactive(source, &combined);

    PreprocessedSource {
        active_source,
        // original: source.to_string(),
    }
}

/// Blank out comments and inactive `#if` blocks, preserving byte positions.
fn blank_inactive(source: &str, inactive_defines: &[&str]) -> String {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut out: Vec<u8> = bytes.to_vec();

    let mut i = 0;

    // Stack of (is_active: bool) — one entry per nested #if level.
    // We start with one implicit "active" frame representing the top level.
    let mut if_stack: Vec<bool> = vec![true];

    /// True when all frames on the stack are active.
    fn all_active(stack: &[bool]) -> bool {
        stack.iter().all(|&b| b)
    }

    while i < len {
        // ── Line-level directives (#if / #elif / #else / #endif) ──────────
        // Only process when we are at the start of a (possibly indented) line.
        if is_line_start(&out, i) {
            // Skip leading whitespace to find the '#'
            let mut j = i;
            while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < len && bytes[j] == b'#' {
                let line_end = next_line_end(bytes, j);
                let directive_bytes = &bytes[j..line_end];
                let directive = std::str::from_utf8(directive_bytes)
                    .unwrap_or("")
                    .trim();

                if let Some(rest) = directive.strip_prefix("#if") {
                    // #if or #ifdef — push a new frame
                    let condition = rest.trim();
                    let active = all_active(&if_stack)
                        && !is_inactive_condition(condition, inactive_defines);
                    if_stack.push(active);
                    // Blank the directive line itself — it's not executable code
                    blank_range(&mut out, i, line_end);
                    i = line_end;
                    continue;
                } else if directive.starts_with("#elif") {
                    // Pop the last frame and replace it
                    if if_stack.len() > 1 {
                        if_stack.pop();
                        let condition = directive["#elif".len()..].trim();
                        let active = all_active(&if_stack)
                            && !is_inactive_condition(condition, inactive_defines);
                        if_stack.push(active);
                    }
                    blank_range(&mut out, i, line_end);
                    i = line_end;
                    continue;
                } else if directive.starts_with("#else") {
                    // Flip the top frame
                    if if_stack.len() > 1 {
                        let top = if_stack.pop().unwrap();
                        // Active only when parent is active AND previous branch was inactive
                        let parent_active = all_active(&if_stack);
                        if_stack.push(parent_active && !top);
                    }
                    blank_range(&mut out, i, line_end);
                    i = line_end;
                    continue;
                } else if directive.starts_with("#endif") {
                    if if_stack.len() > 1 {
                        if_stack.pop();
                    }
                    blank_range(&mut out, i, line_end);
                    i = line_end;
                    continue;
                }
            }
        }

        // ── If current position is inside an inactive block, blank it ─────
        if !all_active(&if_stack) {
            // Blank everything until end of line (newline is kept so line
            // numbers remain intact)
            let line_end = next_line_end(bytes, i);
            blank_range(&mut out, i, line_end);
            i = line_end;
            continue;
        }

        // ── Line comment: // ──────────────────────────────────────────────
        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            let line_end = next_line_end(bytes, i);
            blank_range(&mut out, i, line_end);
            i = line_end;
            continue;
        }

        // ── Block comment: /* … */ ────────────────────────────────────────
        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            let end = find_block_comment_end(bytes, i + 2);
            blank_range(&mut out, i, end);
            i = end;
            continue;
        }

        // ── String literal: skip so we don't blank contents of strings ────
        // This prevents `// fake comment inside string` from being blanked.
        if bytes[i] == b'"' {
            i = skip_string_literal(bytes, i + 1, b'"');
            continue;
        }
        if bytes[i] == b'\'' {
            i = skip_string_literal(bytes, i + 1, b'\'');
            continue;
        }

        i += 1;
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// Returns true when `condition` (the text after `#if`) references one of the
/// inactive defines — meaning the block should be treated as dead code.
///
/// Handles:
///   `#if UNITY_EDITOR`
///   `#if !UNITY_EDITOR`       → active (negation of inactive = active, keep scanning)
///   `#if UNITY_EDITOR && X`   → inactive if any term is inactive
///   `#if UNITY_EDITOR || X`   → active (OR with unknown = assume active)
fn is_inactive_condition(condition: &str, inactive: &[&str]) -> bool {
    // Split on || first — if any OR branch might be active, keep the block.
    // We only blank when ALL branches are inactive, which we approximate as:
    // no `||` present and at least one term matches an inactive define.
    if condition.contains("||") {
        return false;
    }

    // Split on && — if ANY term is an inactive define (without negation), blank.
    let terms: Vec<&str> = condition
        .split("&&")
        .map(|t| t.trim())
        .collect();

    terms.iter().any(|term| {
        // Ignore negated terms: `!UNITY_EDITOR` means "if editor is NOT present"
        // which could be active in a non-editor build — don't blank.
        if term.starts_with('!') {
            return false;
        }
        let term_clean = term.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
        inactive
            .iter()
            .any(|d| d.eq_ignore_ascii_case(term_clean))
    })
}

// ─── Byte-level helpers ───────────────────────────────────────────────────────

/// True when position `i` is at the start of a new line (i == 0 or preceded
/// by `\n`).
fn is_line_start(buf: &[u8], i: usize) -> bool {
    i == 0 || buf[i - 1] == b'\n'
}

/// Index of the first byte past the end of the current line (i.e. just after
/// `\n`, or `len` if no newline follows).  The newline byte itself is NOT
/// blanked — it is kept so line numbers remain accurate.
fn next_line_end(bytes: &[u8], from: usize) -> usize {
    let mut j = from;
    while j < bytes.len() && bytes[j] != b'\n' {
        j += 1;
    }
    // Include the newline in the "line" but we blank only up to it, not the
    // newline itself (blank_range excludes the newline).
    j
}

/// Index just past the closing `*/`, or `len` if unterminated.
fn find_block_comment_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            return i + 2;
        }
        i += 1;
    }
    bytes.len()
}

/// Skip past a string/char literal, returning the index after the closing
/// delimiter. Handles `\"` escapes.
fn skip_string_literal(bytes: &[u8], from: usize, delim: u8) -> usize {
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped character
            continue;
        }
        if bytes[i] == delim {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

/// Replace bytes in `buf[start..end]` with spaces, except newlines which are
/// kept intact so line numbers remain valid.
fn blank_range(buf: &mut [u8], start: usize, end: usize) {
    let end = end.min(buf.len());
    for b in &mut buf[start..end] {
        if *b != b'\n' {
            *b = b' ';
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_comment_blanked() {
        let src = "int x = 1;\n// Process.Start(\"cmd\");\nint y = 2;\n";
        let out = preprocess(src, &[]);
        assert!(!out.active_source.contains("Process.Start"));
        assert!(out.active_source.contains("int x = 1;"));
        assert!(out.active_source.contains("int y = 2;"));
    }

    #[test]
    fn block_comment_blanked() {
        let src = "int x;\n/* Assembly.Load(bytes); */\nint y;\n";
        let out = preprocess(src, &[]);
        assert!(!out.active_source.contains("Assembly.Load"));
    }

    #[test]
    fn sanitized_comment_blanked() {
        let src = "/* SANITIZED */ // Process.Start(\"evil\");\nint y;\n";
        let out = preprocess(src, &[]);
        assert!(!out.active_source.contains("Process.Start"));
    }

    #[test]
    fn unity_editor_block_blanked() {
        let src = "#if UNITY_EDITOR\nProcess.Start(\"cmd\");\n#endif\nint safe;\n";
        let out = preprocess(src, &[]);
        assert!(!out.active_source.contains("Process.Start"));
        assert!(out.active_source.contains("int safe;"));
    }

    #[test]
    fn negated_unity_editor_kept() {
        let src = "#if !UNITY_EDITOR\nProcess.Start(\"cmd\");\n#endif\n";
        let out = preprocess(src, &[]);
        // !UNITY_EDITOR means "runs in player" — should NOT be blanked
        assert!(out.active_source.contains("Process.Start"));
    }

    #[test]
    fn cvr_cck_block_blanked() {
        let src = "#if CVR_CCK_EXISTS\nAssembly.Load(data);\n#endif\nint ok;\n";
        let out = preprocess(src, &[]);
        assert!(!out.active_source.contains("Assembly.Load"));
        assert!(out.active_source.contains("int ok;"));
    }

    #[test]
    fn line_numbers_preserved() {
        let src = "line1\n// comment\nline3\n";
        let out = preprocess(src, &[]);
        let lines: Vec<&str> = out.active_source.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line1");
        assert_eq!(lines[2], "line3");
    }

    #[test]
    fn string_literal_not_blanked() {
        let src = "string s = \"// not a comment\";\n";
        let out = preprocess(src, &[]);
        assert!(out.active_source.contains("// not a comment"));
    }

    #[test]
    fn or_condition_not_blanked() {
        // UNITY_EDITOR || SOMETHING_ELSE — we cannot be sure it's inactive
        let src = "#if UNITY_EDITOR || SOMETHING_ELSE\nProcess.Start(\"x\");\n#endif\n";
        let out = preprocess(src, &[]);
        assert!(out.active_source.contains("Process.Start"));
    }
}