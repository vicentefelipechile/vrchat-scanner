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
}

/// Symbols whose `#if` / `#elif` blocks are considered inactive for security
/// analysis purposes.  Code inside these guards is unlikely to run in a
/// standard VRChat/Unity player build.
const BUILTIN_INACTIVE_DEFINES: &[&str] = &[
    "UNITY_EDITOR",
    "UNITY_EDITOR_WIN",
    "UNITY_EDITOR_OSX",
    "UNITY_EDITOR_LINUX",
    "CVR_CCK_EXISTS",
    "VRC_SDK_VRCSDK2",
    "VRC_SDK_VRCSDK3",
    "UDON",
    "RESONITE",
    "MELONLOADER",
    "DEBUG",
    "DEVELOPMENT_BUILD",
];

/// Preprocess a C# source string.
pub fn preprocess(source: &str, extra_inactive: &[&str]) -> PreprocessedSource {
    let combined: Vec<&str> = BUILTIN_INACTIVE_DEFINES
        .iter()
        .copied()
        .chain(extra_inactive.iter().copied())
        .collect();

    let active_source = blank_inactive(source, &combined);

    PreprocessedSource { active_source }
}

/// Blank out comments and inactive `#if` blocks, preserving byte positions.
///
/// # Algorithm
/// Single-pass, O(n). Each byte is visited at most twice (once by the main
/// loop, once inside a helper that also advances `i`).  No quadratic patterns.
fn blank_inactive(source: &str, inactive_defines: &[&str]) -> String {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut out: Vec<u8> = bytes.to_vec();

    // Stack of `is_active` booleans — one entry per nested #if level.
    // The implicit top-level frame is always active.
    let mut if_stack: Vec<bool> = vec![true];

    let mut i = 0;

    while i < len {
        // ── Detect line-level directives (#if / #elif / #else / #endif) ──
        // Only when we are at the logical start of a line.
        if is_line_start(&out, i) {
            // Skip leading whitespace to find '#'
            let mut j = i;
            while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }

            if j < len && bytes[j] == b'#' {
                let line_end = next_line_end(bytes, j);
                // Parse from the original bytes so blanking doesn't affect parsing.
                let directive = std::str::from_utf8(&bytes[j..line_end])
                    .unwrap_or("")
                    .trim();

                if let Some(rest) = directive.strip_prefix("#if") {
                    let condition = rest.trim();
                    let active = all_active(&if_stack)
                        && !is_inactive_condition(condition, inactive_defines);
                    if_stack.push(active);
                    blank_range(&mut out, i, line_end);
                    i = line_end;
                    continue;
                } else if let Some(rest) = directive.strip_prefix("#elif") {
                    if if_stack.len() > 1 {
                        if_stack.pop();
                        let condition = rest.trim();
                        let active = all_active(&if_stack)
                            && !is_inactive_condition(condition, inactive_defines);
                        if_stack.push(active);
                    }
                    blank_range(&mut out, i, line_end);
                    i = line_end;
                    continue;
                } else if directive.starts_with("#else") {
                    if if_stack.len() > 1 {
                        let top = if_stack.pop().unwrap();
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
                // Other directives (#pragma, #region, …): fall through to normal
                // processing so their content isn't accidentally flagged.
            }
        }

        // ── If inside an inactive block, blank the rest of this line ──────
        if !all_active(&if_stack) {
            let line_end = next_line_end(bytes, i);
            blank_range(&mut out, i, line_end);
            i = line_end;
            continue;
        }

        // ── Active code from here on ──────────────────────────────────────

        // Line comment: //
        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            let line_end = next_line_end(bytes, i);
            blank_range(&mut out, i, line_end);
            i = line_end;
            continue;
        }

        // Block comment: /* … */
        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            let end = find_block_comment_end(bytes, i + 2);
            blank_range(&mut out, i, end);
            i = end;
            continue;
        }

        // Verbatim string: @"…" — no escape sequences, only "" to escape a quote.
        // FIX: Must be handled BEFORE regular strings so @" isn't mis-parsed.
        if i + 1 < len && bytes[i] == b'@' && bytes[i + 1] == b'"' {
            // Skip the @" opener, then find the closing " (doubled "" = escaped quote).
            let end = skip_verbatim_string(bytes, i + 2);
            // Do NOT blank verbatim strings — they may contain URLs we need to scan.
            i = end;
            continue;
        }

        // Interpolated verbatim string: $@"…" or @$"…"
        if i + 2 < len
            && ((bytes[i] == b'$' && bytes[i + 1] == b'@' && bytes[i + 2] == b'"')
                || (bytes[i] == b'@' && bytes[i + 1] == b'$' && bytes[i + 2] == b'"'))
        {
            let end = skip_verbatim_string(bytes, i + 3);
            i = end;
            continue;
        }

        // Regular string literal: "…"
        // FIX: guard against `i + 1 >= len` and handle escape at EOF.
        if bytes[i] == b'"' {
            let end = skip_string_literal(bytes, i + 1, b'"');
            i = end;
            continue;
        }

        // Char literal: '…'
        if bytes[i] == b'\'' {
            let end = skip_string_literal(bytes, i + 1, b'\'');
            i = end;
            continue;
        }

        i += 1;
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

// ─── Condition helpers ────────────────────────────────────────────────────────

#[inline]
fn all_active(stack: &[bool]) -> bool {
    // Stack is usually very short (< 5 frames); linear scan is fine.
    stack.iter().all(|&b| b)
}

/// Returns true when `condition` references one of the inactive defines.
///
/// Rules:
/// - `||` present → assume potentially active, do NOT blank.
/// - `&&` terms → blank if ANY non-negated term is an inactive define.
fn is_inactive_condition(condition: &str, inactive: &[&str]) -> bool {
    if condition.contains("||") {
        return false;
    }

    condition.split("&&").any(|term| {
        let term = term.trim();
        if term.starts_with('!') {
            return false;
        }
        // Strip parentheses and other non-identifier chars.
        let term_clean: &str = term.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
        inactive
            .iter()
            .any(|d| d.eq_ignore_ascii_case(term_clean))
    })
}

// ─── Byte-level helpers ───────────────────────────────────────────────────────

/// True when position `i` is at the start of a new line.
#[inline]
fn is_line_start(buf: &[u8], i: usize) -> bool {
    i == 0 || buf[i - 1] == b'\n'
}

/// Index of the first byte past the end of the current line.
/// The newline byte itself is NOT included in the returned range.
#[inline]
fn next_line_end(bytes: &[u8], from: usize) -> usize {
    match memchr_newline(bytes, from) {
        Some(pos) => pos,  // points AT the '\n'; callers blank [from..pos)
        None => bytes.len(),
    }
}

/// Fast newline search. Equivalent to `bytes[from..].iter().position(|&b| b == b'\n')`.
#[inline]
fn memchr_newline(bytes: &[u8], from: usize) -> Option<usize> {
    bytes[from..].iter().position(|&b| b == b'\n').map(|p| from + p)
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

/// Skip past a regular string/char literal, returning the index after the
/// closing delimiter.
///
/// FIX (vs original): bounds-check before `i += 2` on escape so we never
/// advance past `bytes.len()` and the outer loop terminates.
fn skip_string_literal(bytes: &[u8], from: usize, delim: u8) -> usize {
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Escape sequence: skip one extra byte, but only if it exists.
                i += if i + 1 < bytes.len() { 2 } else { 1 };
            }
            b if b == delim => {
                return i + 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    bytes.len() // unterminated — return end of file
}

/// Skip past a verbatim string (`@"…"`), starting AFTER the opening `"`.
///
/// In verbatim strings `""` is an escaped quote; `\"` is NOT.
/// Returns the index after the closing `"`.
fn skip_verbatim_string(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            // Peek ahead: `""` is an escaped quote, not the end.
            if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                i += 2; // skip both quote chars
            } else {
                return i + 1; // closing quote
            }
        } else {
            i += 1;
        }
    }
    bytes.len()
}

/// Replace bytes in `buf[start..end]` with spaces, preserving newlines.
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
        let src = "#if UNITY_EDITOR || SOMETHING_ELSE\nProcess.Start(\"x\");\n#endif\n";
        let out = preprocess(src, &[]);
        assert!(out.active_source.contains("Process.Start"));
    }

    // ── New regression tests for the fixed cases ──────────────────────────

    #[test]
    fn verbatim_string_not_blanked() {
        // @"..." must not cause the preprocessor to consume the rest of the file.
        let src = "string path = @\"C:\\Windows\\System32\";\nint x = 1;\n";
        let out = preprocess(src, &[]);
        assert!(out.active_source.contains("int x = 1;"));
    }

    #[test]
    fn verbatim_string_with_escaped_quote() {
        // @"say ""hello""" — the "" inside is an escaped quote, not end of string.
        let src = "string s = @\"say \"\"hello\"\"\";\nint ok;\n";
        let out = preprocess(src, &[]);
        assert!(out.active_source.contains("int ok;"));
    }

    #[test]
    fn escape_at_eof_no_panic() {
        // A backslash at the very end of file must not panic or loop infinitely.
        let src = "string s = \"\\\n";
        let out = preprocess(src, &[]);
        // Just assert it returns something with the same number of lines.
        assert_eq!(out.active_source.lines().count(), src.lines().count());
    }

    #[test]
    fn elif_directive_handled() {
        let src =
            "#if UNITY_EDITOR\nProcess.Start(\"a\");\n#elif !UNITY_EDITOR\nProcess.Start(\"b\");\n#endif\n";
        let out = preprocess(src, &[]);
        // UNITY_EDITOR branch → blanked; !UNITY_EDITOR branch → active (negated)
        let starts: Vec<&str> = out
            .active_source
            .lines()
            .filter(|l| l.contains("Process.Start"))
            .collect();
        // Only the #elif branch (b) should survive.
        assert_eq!(starts.len(), 1);
        assert!(starts[0].contains("\"b\""));
    }

    #[test]
    fn deeply_nested_if_stack() {
        let src = "#if UNITY_EDITOR\n#if DEBUG\nProcess.Start(\"x\");\n#endif\n#endif\nint ok;\n";
        let out = preprocess(src, &[]);
        assert!(!out.active_source.contains("Process.Start"));
        assert!(out.active_source.contains("int ok;"));
    }

    #[test]
    fn unterminated_block_comment_no_infinite_loop() {
        // Must terminate, not loop forever.
        let src = "int x;\n/* unclosed comment\nint y;\n";
        let out = preprocess(src, &[]);
        // The whole rest of the file gets blanked — just verify it terminates
        // and produces a string of the same byte length.
        assert_eq!(out.active_source.len(), src.len());
    }
}