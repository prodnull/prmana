//! Terminal UI for device flow prompts.
//!
//! This module provides terminal-based UI components for displaying
//! device flow authentication prompts to users.

pub mod terminal;

pub use terminal::{PamDisplay, TerminalDisplay};

/// Strip control characters from strings before terminal display.
///
/// IdP-supplied values (verification_uri, user_code, error messages) are
/// rendered directly on the user's terminal. A compromised or malicious IdP
/// could embed ANSI escape sequences to spoof output, remap keys, or (on
/// vulnerable terminals) inject commands.
///
/// This function replaces all C0/C1 control characters (U+0000–U+001F,
/// U+007F–U+009F) except common whitespace (tab, newline, carriage return)
/// with the Unicode replacement character.
pub fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            // Allow printable ASCII and all non-control Unicode
            _ if !c.is_control() => c,
            // Allow common whitespace
            '\t' | '\n' | '\r' => c,
            // Replace everything else (ESC, BEL, BS, C1 controls, etc.)
            _ => '\u{FFFD}',
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_passes_normal_url() {
        let url = "https://login.microsoftonline.com/device?code=ABCD-1234";
        assert_eq!(sanitize_for_terminal(url), url);
    }

    #[test]
    fn test_sanitize_strips_ansi_escape() {
        let malicious = "https://legit.com\x1b[31m FAKE SUCCESS \x1b[0m";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains('\u{FFFD}'));
        assert!(sanitized.contains("https://legit.com"));
    }

    #[test]
    fn test_sanitize_strips_bell() {
        let noisy = "Visit: https://example.com\x07\x07\x07";
        let sanitized = sanitize_for_terminal(noisy);
        assert!(!sanitized.contains('\x07'));
    }

    #[test]
    fn test_sanitize_strips_backspace() {
        // Backspace attack: display "https://legit.com" then backspace over it
        // and write "http://evil.com"
        let sneaky = "https://legit.com\x08\x08\x08\x08\x08\x08\x08\x08\x08evil.com";
        let sanitized = sanitize_for_terminal(sneaky);
        assert!(!sanitized.contains('\x08'));
        // Both URLs should be visible since backspaces are stripped
        assert!(sanitized.contains("legit.com"));
        assert!(sanitized.contains("evil.com"));
    }

    #[test]
    fn test_sanitize_preserves_tab_newline() {
        let with_ws = "line1\n\tindented\r\nline3";
        assert_eq!(sanitize_for_terminal(with_ws), with_ws);
    }

    #[test]
    fn test_sanitize_strips_c1_controls() {
        // C1 control range U+0080–U+009F (e.g., CSI = U+009B)
        let c1 = "hello\u{009B}31mworld";
        let sanitized = sanitize_for_terminal(c1);
        assert!(!sanitized.contains('\u{009B}'));
    }

    #[test]
    fn test_sanitize_preserves_unicode() {
        let unicode = "Přihlášení: https://example.com/zařízení";
        assert_eq!(sanitize_for_terminal(unicode), unicode);
    }
}
