//! Terminal escape sequence sanitization for IdP-supplied URIs.
//!
//! Malicious or compromised identity providers could inject ANSI escape sequences
//! into `verification_uri` values, enabling terminal injection attacks (e.g.,
//! clearing the screen, setting the window title, or injecting invisible text).
//!
//! This module strips all control characters and escape sequences while preserving
//! valid Unicode (including internationalized domain names with non-ASCII characters).
//!
//! # Security rationale
//!
//! ANSI escape sequences can:
//! - Clear the screen (`CSI 2J`) hiding legitimate output
//! - Set the terminal title (`OSC 0;...ST`) for social engineering
//! - Inject invisible text via cursor repositioning
//! - Execute arbitrary commands in some terminal emulators via DCS/APC sequences
//!
//! Stripping these sequences is defense-in-depth: even if an IdP is compromised,
//! the agent will not relay terminal attacks to the user.

/// Sanitize a string by stripping terminal escape sequences and control characters.
///
/// Returns a tuple of `(sanitized_string, was_modified)` where `was_modified` is
/// `true` if any characters were removed during sanitization.
///
/// # What is stripped
///
/// - C0 control characters (U+0000..U+001F) — includes ESC, NUL, BEL, etc.
/// - C1 control characters (U+0080..U+009F) — includes 8-bit CSI (0x9B), OSC (0x9D), etc.
/// - 7-bit ANSI escape sequences: CSI (`ESC [`), OSC (`ESC ]`), DCS (`ESC P`),
///   APC (`ESC _`), PM (`ESC ^`), SOS (`ESC X`), and their payloads up to the
///   sequence terminator.
///
/// # What is preserved
///
/// - All printable ASCII (U+0020..U+007E)
/// - DEL (U+007F) is stripped (control character)
/// - All valid Unicode >= U+00A0 (internationalized domain names, percent-encoded URLs)
pub fn sanitize_terminal_output(input: &str) -> (String, bool) {
    if input.is_empty() {
        return (String::new(), false);
    }

    let mut output = String::with_capacity(input.len());
    let mut modified = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            // ESC (0x1B) — start of 7-bit escape sequence
            '\x1b' => {
                modified = true;
                consume_escape_sequence(&mut chars);
            }
            // 8-bit C1 control characters (U+0080..U+009F)
            // These include 8-bit CSI (0x9B), OSC (0x9D), DCS (0x90), etc.
            '\u{0080}'..='\u{009F}' => {
                modified = true;
                // 8-bit CSI (0x9B) has parameters + final byte like 7-bit CSI
                if ch == '\u{009B}' {
                    consume_csi_params(&mut chars);
                }
                // 8-bit OSC (0x9D), DCS (0x90), APC (0x9F), PM (0x9E), SOS (0x98)
                // all consume until ST (0x9C or ESC \)
                else if matches!(
                    ch,
                    '\u{009D}' | '\u{0090}' | '\u{009F}' | '\u{009E}' | '\u{0098}'
                ) {
                    consume_until_st(&mut chars);
                }
                // Other C1 controls: just skip the character
            }
            // C0 control characters (0x00..0x1F, excluding ESC handled above)
            '\x00'..='\x1a' | '\x1c'..='\x1f' => {
                modified = true;
            }
            // DEL
            '\x7f' => {
                modified = true;
            }
            // Everything else: printable ASCII and Unicode >= U+00A0
            _ => {
                output.push(ch);
            }
        }
    }

    (output, modified)
}

/// Consume the body of a 7-bit escape sequence after the initial ESC character.
fn consume_escape_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.peek() {
        // CSI: ESC [ ... (parameters) ... (final byte 0x40-0x7E)
        Some('[') => {
            chars.next(); // consume '['
            consume_csi_params(chars);
        }
        // OSC: ESC ] ... ST
        Some(']') => {
            chars.next();
            consume_until_st(chars);
        }
        // DCS: ESC P ... ST
        Some('P') => {
            chars.next();
            consume_until_st(chars);
        }
        // APC: ESC _ ... ST
        Some('_') => {
            chars.next();
            consume_until_st(chars);
        }
        // PM: ESC ^ ... ST
        Some('^') => {
            chars.next();
            consume_until_st(chars);
        }
        // SOS: ESC X ... ST
        Some('X') => {
            chars.next();
            consume_until_st(chars);
        }
        // Other escape sequences (e.g., ESC c for RIS): consume just the next char
        Some(_) => {
            chars.next();
        }
        // Bare ESC at end of string: already consumed
        None => {}
    }
}

/// Consume CSI parameters and intermediate bytes until the final byte (0x40..0x7E).
fn consume_csi_params(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    // CSI sequences: parameter bytes (0x30-0x3F), intermediate bytes (0x20-0x2F),
    // then a final byte (0x40-0x7E).
    while let Some(&ch) = chars.peek() {
        if ('\x40'..='\x7e').contains(&ch) {
            chars.next(); // consume final byte
            return;
        }
        chars.next(); // consume parameter/intermediate byte
    }
}

/// Consume characters until String Terminator (ST).
///
/// ST can be either:
/// - ESC \ (7-bit ST)
/// - U+009C (8-bit ST)
/// - BEL (0x07) for OSC sequences (xterm extension, widely supported)
fn consume_until_st(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(ch) = chars.next() {
        match ch {
            // 8-bit ST
            '\u{009C}' => return,
            // BEL — common OSC terminator (xterm extension)
            '\x07' => return,
            // ESC \ — 7-bit ST terminator
            '\x1b' if chars.peek() == Some(&'\\') => {
                chars.next(); // consume '\'
                return;
            }
            // Bare ESC inside the sequence — continue consuming
            '\x1b' => {}
            _ => {} // consume payload
        }
    }
}

/// Format removed bytes as a hex string for audit logging.
///
/// Compares the original input with the sanitized output to identify removed bytes.
pub fn format_removed_bytes(original: &str, sanitized: &str) -> String {
    let orig_bytes: std::collections::HashSet<u8> = original.bytes().collect();
    let sanitized_bytes: std::collections::HashSet<u8> = sanitized.bytes().collect();

    let mut removed: Vec<u8> = orig_bytes.difference(&sanitized_bytes).copied().collect();
    removed.sort();

    removed
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_clean_url_unchanged() {
        let (result, modified) = sanitize_terminal_output("https://login.example.com");
        assert_eq!(result, "https://login.example.com");
        assert!(!modified);
    }

    #[test]
    fn sanitize_strips_csi_clear_screen_and_cursor_home() {
        // ESC[2J = clear screen, ESC[H = cursor home
        let (result, modified) = sanitize_terminal_output("https://evil.com\x1b[2J\x1b[H");
        assert_eq!(result, "https://evil.com");
        assert!(modified);
    }

    #[test]
    fn sanitize_strips_osc_title_set() {
        // ESC]0;pwned BEL
        let (result, modified) = sanitize_terminal_output("https://evil.com\x1b]0;pwned\x07");
        assert_eq!(result, "https://evil.com");
        assert!(modified);
    }

    #[test]
    fn sanitize_strips_dcs_sequence() {
        // ESC P malicious ESC \
        let (result, modified) = sanitize_terminal_output("https://evil.com\x1bPmalicious\x1b\\");
        assert_eq!(result, "https://evil.com");
        assert!(modified);
    }

    #[test]
    fn sanitize_strips_apc_sequence() {
        // ESC _ malicious ESC \
        let (result, modified) = sanitize_terminal_output("https://evil.com\x1b_malicious\x1b\\");
        assert_eq!(result, "https://evil.com");
        assert!(modified);
    }

    #[test]
    fn sanitize_strips_control_characters() {
        let (result, modified) = sanitize_terminal_output("https://evil.com\x00\x01\x02");
        assert_eq!(result, "https://evil.com");
        assert!(modified);
    }

    #[test]
    fn sanitize_preserves_percent_encoded_urls() {
        let (result, modified) =
            sanitize_terminal_output("https://login.example.com/path?q=hello%20world");
        assert_eq!(result, "https://login.example.com/path?q=hello%20world");
        assert!(!modified);
    }

    #[test]
    fn sanitize_preserves_valid_unicode() {
        // U+00E9 (e-acute) is valid Unicode >= U+00A0
        let (result, modified) = sanitize_terminal_output("https://login.example.com/idp/\u{00E9}");
        assert_eq!(result, "https://login.example.com/idp/\u{00E9}");
        assert!(!modified);
    }

    #[test]
    fn sanitize_empty_string() {
        let (result, modified) = sanitize_terminal_output("");
        assert_eq!(result, "");
        assert!(!modified);
    }

    #[test]
    fn sanitize_returns_was_modified_flag() {
        // Clean input
        let (_, modified) = sanitize_terminal_output("clean");
        assert!(!modified, "clean input should not be marked as modified");

        // Dirty input
        let (_, modified) = sanitize_terminal_output("dirty\x1b[31m");
        assert!(modified, "input with escape should be marked as modified");
    }

    #[test]
    fn sanitize_strips_8bit_csi() {
        // 0x9B is the 8-bit CSI introducer (equivalent to ESC [)
        // 0x9B followed by "31m" (SGR color) should be stripped
        let input = format!("https://evil.com{}31m", '\u{009B}');
        let (result, modified) = sanitize_terminal_output(&input);
        assert_eq!(result, "https://evil.com");
        assert!(modified);
    }

    #[test]
    fn sanitize_strips_pm_sequence() {
        // ESC ^ ... ESC \ (Privacy Message)
        let (result, modified) = sanitize_terminal_output("https://evil.com\x1b^secret\x1b\\");
        assert_eq!(result, "https://evil.com");
        assert!(modified);
    }

    #[test]
    fn sanitize_strips_sos_sequence() {
        // ESC X ... ESC \ (Start of String)
        let (result, modified) = sanitize_terminal_output("https://evil.com\x1bXdata\x1b\\");
        assert_eq!(result, "https://evil.com");
        assert!(modified);
    }

    #[test]
    fn sanitize_handles_multiple_escape_sequences() {
        let (result, modified) =
            sanitize_terminal_output("\x1b[2Jhttps://evil.com\x1b]0;pwned\x07\x1bPdcs\x1b\\\x00");
        assert_eq!(result, "https://evil.com");
        assert!(modified);
    }

    #[test]
    fn sanitize_strips_bare_esc_at_end() {
        let (result, modified) = sanitize_terminal_output("url\x1b");
        assert_eq!(result, "url");
        assert!(modified);
    }
}
