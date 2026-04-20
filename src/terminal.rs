//! Terminal capability detection.
//!
//! Windows 10's legacy console host (conhost.exe) does not process ANSI escape
//! sequences or render Unicode box-drawing characters unless Virtual Terminal
//! Processing (VTP) is explicitly enabled via SetConsoleMode.  Windows Terminal
//! (WT_SESSION) and modern terminal emulators enable it automatically.
//!
//! This module checks the environment and, on Windows, attempts to enable VTP.
//! If VTP is unavailable the caller should disable colored output and fall back
//! to plain ASCII separators.

/// The set of capabilities we detected at startup.
#[derive(Debug, Clone, Copy)]
pub struct TermCaps {
    /// True when ANSI escape codes (colors, bold, etc.) render correctly.
    pub ansi: bool,
    /// True when Unicode box-drawing characters render correctly.
    /// On legacy conhost this is usually false even when some ANSI works.
    pub unicode: bool,
}

impl TermCaps {
    /// Detect capabilities of the current terminal.
    pub fn detect() -> Self {
        let ansi = detect_ansi();
        // If ANSI works the terminal is modern enough for Unicode box chars.
        // If ANSI doesn't work (legacy conhost) Unicode box chars will also
        // appear as garbage, so tie them together.
        TermCaps { ansi, unicode: ansi }
    }
}

fn detect_ansi() -> bool {
    // --- Environment hints (fastest, no syscalls) ---

    // Windows Terminal always sets WT_SESSION.
    if std::env::var("WT_SESSION").is_ok() {
        return true;
    }
    // ConEmu with ANSI enabled.
    if std::env::var("ConEmuANSI").ok().as_deref() == Some("ON") {
        return true;
    }
    // ANSICON wrapper.
    if std::env::var("ANSICON").is_ok() {
        return true;
    }
    // Any TERM variable usually means a capable terminal (Unix, MSYS2, Git Bash…).
    if std::env::var("TERM").is_ok() {
        return true;
    }
    // COLORTERM is set by many modern terminals.
    if std::env::var("COLORTERM").is_ok() {
        return true;
    }

    // --- Windows: try to enable Virtual Terminal Processing via SetConsoleMode ---
    #[cfg(target_os = "windows")]
    {
        return try_enable_vtp_windows();
    }

    // --- Non-Windows fallback: assume support ---
    #[cfg(not(target_os = "windows"))]
    true
}

/// Try to enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004) on the stdout
/// console handle.  Returns true if the flag was already set or was
/// successfully enabled.
#[cfg(target_os = "windows")]
fn try_enable_vtp_windows() -> bool {
    // SAFETY: We call only well-documented Win32 console APIs with correct
    // argument types.  No memory is allocated or freed.
    unsafe {
        let handle = windows_sys::Win32::System::Console::GetStdHandle(
            windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE,
        );
        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return false;
        }

        let mut mode: u32 = 0;
        if windows_sys::Win32::System::Console::GetConsoleMode(handle, &mut mode) == 0 {
            return false; // Not a real console (e.g. piped to a file)
        }

        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true; // Already enabled
        }

        // Try to enable it
        windows_sys::Win32::System::Console::SetConsoleMode(
            handle,
            mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        ) != 0
    }
}
