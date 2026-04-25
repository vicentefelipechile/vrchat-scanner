/// Output of the C# source preprocessor.
///
/// All analysis modules should operate on `active_source` rather than the
/// raw source string so that:
///   - Comments (`//` and `/* */`) are blanked out.
///   - Code inside inactive `#if` blocks (editor-only, SDK-specific, etc.)
///     is blanked out.
///
/// "Blanked out" means replaced with spaces of equal length so that
/// 1-indexed line numbers remain valid for the original file.
pub struct PreprocessedSource {
    /// Source with comments and inactive blocks replaced by spaces.
    /// Same byte length as the original — line numbers are preserved.
    pub active_source: String,
}

/// Symbols whose `#if` / `#elif` blocks are considered inactive for security
/// analysis purposes. Code inside these guards is unlikely to run in a
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
    let inactive: Vec<&str> = BUILTIN_INACTIVE_DEFINES
        .iter()
        .copied()
        .chain(extra_inactive.iter().copied())
        .collect();

    let active_source = process_lines(source, &inactive);
    PreprocessedSource { active_source }
}

// ─── Line-by-line processor ───────────────────────────────────────────────────

fn process_lines(source: &str, inactive: &[&str]) -> String {
    let mut out = source.as_bytes().to_vec();

    // Stack of `is_active` booleans — one entry per nesting level.
    // The implicit top-level frame is always active.
    let mut if_stack: Vec<bool> = vec![true];

    // Tracks whether we are inside a `/* … */` block comment spanning lines.
    let mut in_block_comment = false;

    let mut line_start = 0usize;

    for line_raw in source.split_inclusive('\n') {
        let line_end = line_start + line_raw.len();

        // Strip UTF-8 BOM (U+FEFF → 0xEF 0xBB 0xBF) that some editors add to
        // the very first line. Without this, `#if UNITY_EDITOR` at byte 3 is
        // not recognized as a directive and the whole file gets analyzed.
        let line_no_bom = line_raw.trim_start_matches('\u{FEFF}');

        // Strip trailing CR/LF — we never blank those bytes.
        let line_content = line_no_bom
            .trim_end_matches('\n')
            .trim_end_matches('\r');

        // ── Preprocessor directive? ───────────────────────────────────────
        let trimmed = line_content.trim_start();

        if trimmed.starts_with('#') {
            // Always blank the directive line itself.
            blank_line(&mut out, line_start, line_end);

            if let Some(rest) = trimmed.strip_prefix("#if") {
                let condition = rest.trim();
                let active = all_active(&if_stack)
                    && !is_inactive_condition(condition, inactive);
                if_stack.push(active);
            } else if let Some(rest) = trimmed.strip_prefix("#elif") {
                if if_stack.len() > 1 {
                    if_stack.pop();
                    let condition = rest.trim();
                    let active = all_active(&if_stack)
                        && !is_inactive_condition(condition, inactive);
                    if_stack.push(active);
                }
            } else if trimmed.starts_with("#else") {
                if if_stack.len() > 1 {
                    let top = if_stack.pop().unwrap();
                    let parent_active = all_active(&if_stack);
                    if_stack.push(parent_active && !top);
                }
            } else if trimmed.starts_with("#endif") && if_stack.len() > 1 {
				if_stack.pop();
			}

            // Preprocessor directives cannot legally appear inside a block
            // comment in C#, so reset the flag to avoid spill-over.
            in_block_comment = false;

            line_start = line_end;
            continue;
        }

        // ── Inside an inactive block — blank the whole line ────────────────
        if !all_active(&if_stack) {
            blank_line(&mut out, line_start, line_end);
            // Don't carry block-comment state through inactive blocks.
            in_block_comment = false;
            line_start = line_end;
            continue;
        }

        // ── Active line — blank inline comments only ───────────────────────
        blank_comments_in_line(&mut out, line_start, line_content, &mut in_block_comment);

        line_start = line_end;
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

// ─── Comment blanking within a single active line ────────────────────────────

fn blank_comments_in_line(
    out: &mut [u8],
    line_offset: usize,
    line: &str,
    in_block_comment: &mut bool,
) {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        let abs = line_offset + i;

        // ── Inside a block comment ─────────────────────────────────────────
        if *in_block_comment {
            if i + 1 < len && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                out[abs] = b' ';
                out[abs + 1] = b' ';
                *in_block_comment = false;
                i += 2;
            } else {
                out[abs] = b' ';
                i += 1;
            }
            continue;
        }

        // ── Line comment `//` — blank to end of line ──────────────────────
        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            for j in i..len {
                out[line_offset + j] = b' ';
            }
            return;
        }

        // ── Block comment open `/*` ────────────────────────────────────────
        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            out[abs] = b' ';
            out[abs + 1] = b' ';
            *in_block_comment = true;
            i += 2;
            continue;
        }

        // ── Interpolated verbatim string `$@"` or `@$"` ───────────────────
        if i + 2 < len
            && ((bytes[i] == b'$' && bytes[i + 1] == b'@' && bytes[i + 2] == b'"')
                || (bytes[i] == b'@' && bytes[i + 1] == b'$' && bytes[i + 2] == b'"'))
        {
            i = skip_verbatim_string(bytes, i + 3);
            continue;
        }

        // ── Verbatim string `@"` (must precede plain `"`) ─────────────────
        if i + 1 < len && bytes[i] == b'@' && bytes[i + 1] == b'"' {
            i = skip_verbatim_string(bytes, i + 2);
            continue;
        }

        // ── Regular string literal `"…"` ──────────────────────────────────
        if bytes[i] == b'"' {
            i = skip_string_literal(bytes, i + 1, b'"');
            continue;
        }

        // ── Char literal `'…'` ────────────────────────────────────────────
        if bytes[i] == b'\'' {
            i = skip_string_literal(bytes, i + 1, b'\'');
            continue;
        }

        i += 1;
    }
}

// ─── Condition evaluation ─────────────────────────────────────────────────────

#[inline]
fn all_active(stack: &[bool]) -> bool {
    stack.iter().all(|&b| b)
}

fn is_inactive_condition(condition: &str, inactive: &[&str]) -> bool {
    if condition.contains("||") {
        return false;
    }
    condition.split("&&").any(|term| {
        let term = term.trim();
        if term.starts_with('!') {
            return false;
        }
        let term_clean: &str = term.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
        inactive.iter().any(|d| d.eq_ignore_ascii_case(term_clean))
    })
}

// ─── String-skipping helpers ──────────────────────────────────────────────────

fn skip_string_literal(bytes: &[u8], from: usize, delim: u8) -> usize {
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += if i + 1 < bytes.len() { 2 } else { 1 };
            }
            b if b == delim => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn skip_verbatim_string(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                i += 2;
            } else {
                return i + 1;
            }
        } else {
            i += 1;
        }
    }
    bytes.len()
}

// ─── Blanking helper ──────────────────────────────────────────────────────────

#[inline]
fn blank_line(out: &mut [u8], start: usize, end: usize) {
    let end = end.min(out.len());
    for b in &mut out[start..end] {
        if *b != b'\n' && *b != b'\r' {
            *b = b' ';
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn check(src: &str, extra: &[&str]) -> String {
        let out = preprocess(src, extra);
        assert_eq!(
            out.active_source.len(),
            src.len(),
            "byte length changed!\noriginal: {src:?}\nprocessed: {:?}",
            out.active_source
        );
        out.active_source
    }

    #[test]
    fn line_comment_blanked() {
        let src = "int x = 1;\n// Process.Start(\"cmd\");\nint y = 2;\n";
        let out = check(src, &[]);
        assert!(!out.contains("Process.Start"));
        assert!(out.contains("int x = 1;"));
        assert!(out.contains("int y = 2;"));
    }

    #[test]
    fn block_comment_blanked() {
        let src = "int x;\n/* Assembly.Load(bytes); */\nint y;\n";
        let out = check(src, &[]);
        assert!(!out.contains("Assembly.Load"));
        assert!(out.contains("int y;"));
    }

    #[test]
    fn multiline_block_comment_blanked() {
        let src = "int x;\n/* start\nAssembly.Load(bytes);\nend */\nint y;\n";
        let out = check(src, &[]);
        assert!(!out.contains("Assembly.Load"));
        assert!(out.contains("int y;"));
    }

    #[test]
    fn sanitized_comment_blanked() {
        let src = "/* SANITIZED */ // Process.Start(\"evil\");\nint y;\n";
        let out = check(src, &[]);
        assert!(!out.contains("Process.Start"));
    }

    #[test]
    fn unity_editor_block_blanked() {
        let src = "#if UNITY_EDITOR\nProcess.Start(\"cmd\");\n#endif\nint safe;\n";
        let out = check(src, &[]);
        assert!(!out.contains("Process.Start"));
        assert!(out.contains("int safe;"));
    }

    /// Simulates lilToonEditorUtils.cs: whole file wrapped in #if UNITY_EDITOR.
    #[test]
    fn whole_file_in_unity_editor_block() {
        let src = "#if UNITY_EDITOR\nusing UnityEditor;\nProcess.Start(\"cmd\");\nFile.Delete(\"x\");\n#endif\n";
        let out = check(src, &[]);
        assert!(!out.contains("Process.Start"));
        assert!(!out.contains("File.Delete"));
    }

    /// UTF-8 BOM at the start of the file must not prevent #if from being recognized.
    #[test]
    fn bom_at_start_of_file() {
        let src = "\u{FEFF}#if UNITY_EDITOR\nProcess.Start(\"cmd\");\n#endif\nint ok;\n";
        let out = preprocess(src, &[]);
        assert!(
            !out.active_source.contains("Process.Start"),
            "BOM prevented #if UNITY_EDITOR from being recognized"
        );
        assert!(out.active_source.contains("int ok;"));
    }

    #[test]
    fn negated_unity_editor_kept() {
        let src = "#if !UNITY_EDITOR\nProcess.Start(\"cmd\");\n#endif\n";
        let out = check(src, &[]);
        assert!(out.contains("Process.Start"));
    }

    #[test]
    fn cvr_cck_block_blanked() {
        let src = "#if CVR_CCK_EXISTS\nAssembly.Load(data);\n#endif\nint ok;\n";
        let out = check(src, &[]);
        assert!(!out.contains("Assembly.Load"));
        assert!(out.contains("int ok;"));
    }

    #[test]
    fn line_numbers_preserved() {
        let src = "line1\n// comment\nline3\n";
        let out = check(src, &[]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line1");
        assert_eq!(lines[2], "line3");
    }

    #[test]
    fn string_literal_not_blanked() {
        let src = "string s = \"// not a comment\";\n";
        let out = check(src, &[]);
        assert!(out.contains("// not a comment"));
    }

    #[test]
    fn or_condition_not_blanked() {
        let src = "#if UNITY_EDITOR || SOMETHING_ELSE\nProcess.Start(\"x\");\n#endif\n";
        let out = check(src, &[]);
        assert!(out.contains("Process.Start"));
    }

    #[test]
    fn verbatim_string_not_blanked() {
        let src = "string path = @\"C:\\Windows\\System32\";\nint x = 1;\n";
        let out = check(src, &[]);
        assert!(out.contains("int x = 1;"));
    }

    #[test]
    fn verbatim_string_with_escaped_quote() {
        let src = "string s = @\"say \"\"hello\"\"\";\nint ok;\n";
        let out = check(src, &[]);
        assert!(out.contains("int ok;"));
    }

    #[test]
    fn escape_at_eof_no_panic() {
        let src = "string s = \"\\\n";
        let out = preprocess(src, &[]);
        assert_eq!(out.active_source.len(), src.len());
    }

    #[test]
    fn elif_directive_handled() {
        let src =
            "#if UNITY_EDITOR\nProcess.Start(\"a\");\n#elif !UNITY_EDITOR\nProcess.Start(\"b\");\n#endif\n";
        let out = check(src, &[]);
        let active_starts: Vec<&str> = out
            .lines()
            .filter(|l| l.contains("Process.Start"))
            .collect();
        assert_eq!(active_starts.len(), 1);
        assert!(active_starts[0].contains("\"b\""));
    }

    #[test]
    fn deeply_nested_if_stack() {
        let src = "#if UNITY_EDITOR\n#if DEBUG\nProcess.Start(\"x\");\n#endif\n#endif\nint ok;\n";
        let out = check(src, &[]);
        assert!(!out.contains("Process.Start"));
        assert!(out.contains("int ok;"));
    }

    /// Unknown define nested inside an inactive block: inner #endif must not
    /// pop the outer frame and accidentally re-activate the stack.
    #[test]
    fn nested_unknown_if_inside_inactive() {
        let src = "#if UNITY_EDITOR\n#if SOME_UNKNOWN\nProcess.Start(\"x\");\n#endif\n#endif\nint ok;\n";
        let out = check(src, &[]);
        assert!(!out.contains("Process.Start"));
        assert!(out.contains("int ok;"));
    }

    #[test]
    fn unterminated_block_comment_no_infinite_loop() {
        let src = "int x;\n/* unclosed comment\nint y;\n";
        let out = preprocess(src, &[]);
        assert_eq!(out.active_source.len(), src.len());
        assert!(!out.active_source.contains("unclosed comment"));
        assert!(!out.active_source.contains("int y;"));
    }

    #[test]
    fn block_comment_inline_with_code_after() {
        let src = "int x = /* evil */ 1;\n";
        let out = check(src, &[]);
        assert!(!out.contains("evil"));
        assert!(out.contains("1;"));
    }

    #[test]
    fn block_comment_spanning_three_lines() {
        let src = "int a;\n/*\nAssembly.Load();\n*/\nint b;\n";
        let out = check(src, &[]);
        assert!(!out.contains("Assembly.Load"));
        assert!(out.contains("int a;"));
        assert!(out.contains("int b;"));
    }

    #[test]
    fn extra_inactive_defines_respected() {
        let src = "#if MY_DEFINE\nProcess.Start(\"x\");\n#endif\nint ok;\n";
        let out = check(src, &["MY_DEFINE"]);
        assert!(!out.contains("Process.Start"));
        assert!(out.contains("int ok;"));
    }

    #[test]
    fn byte_length_preserved_crlf() {
        let src = "#if UNITY_EDITOR\r\nint x;\r\n#endif\r\nint y;\r\n";
        let out = preprocess(src, &[]);
        assert_eq!(out.active_source.len(), src.len());
        assert!(out.active_source.contains("int y;"));
        assert!(!out.active_source.contains("int x;"));
    }

    /// Version-specific defines (e.g. UNITY_2021_2_OR_NEWER) are unknown →
    /// treated as active conservatively (no blanking).
    #[test]
    fn version_define_treated_as_active() {
        let src = "#if UNITY_2021_2_OR_NEWER\nint x = 1;\n#else\nint x = 0;\n#endif\n";
        let out = check(src, &[]);
        assert!(out.contains("int x = 1;"));
        assert!(!out.contains("int x = 0;"));
    }
}