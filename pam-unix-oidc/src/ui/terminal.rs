//! Terminal display for device flow prompts.

use crate::sudo::StepUpDisplay;

/// Terminal-based display for step-up prompts.
///
/// This implementation outputs to stderr, which is typically
/// visible to the user during PAM authentication.
pub struct TerminalDisplay;

impl TerminalDisplay {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerminalDisplay {
    fn default() -> Self {
        Self::new()
    }
}

impl StepUpDisplay for TerminalDisplay {
    fn show_device_flow_prompt(&self, verification_uri: &str, user_code: &str) {
        eprintln!();
        eprintln!("═══════════════════════════════════════════════════════════");
        eprintln!("  Sudo requires step-up authentication");
        eprintln!();
        eprintln!("  Visit: {}", verification_uri);
        eprintln!("  Enter code: {}", user_code);
        eprintln!();
        eprintln!("  Waiting for authentication...");
        eprintln!("═══════════════════════════════════════════════════════════");
    }

    fn show_waiting(&self, elapsed_seconds: u64, timeout_seconds: u64) {
        let remaining = timeout_seconds.saturating_sub(elapsed_seconds);
        eprint!(
            "\r  Waiting for authentication... ({}s remaining)   ",
            remaining
        );
    }

    fn show_success(&self) {
        eprintln!();
        eprintln!("  Authentication successful!");
        eprintln!("═══════════════════════════════════════════════════════════");
        eprintln!();
    }

    fn show_failure(&self, reason: &str) {
        eprintln!();
        eprintln!("  Authentication failed: {}", reason);
        eprintln!("═══════════════════════════════════════════════════════════");
        eprintln!();
    }
}

/// PAM-based display using PAM conversation.
///
/// This implementation uses PAM conversation to communicate
/// with the user, which works better in some PAM contexts.
pub struct PamDisplay<'a> {
    pamh: &'a pamsm::Pam,
}

impl<'a> PamDisplay<'a> {
    pub fn new(pamh: &'a pamsm::Pam) -> Self {
        Self { pamh }
    }
}

impl<'a> StepUpDisplay for PamDisplay<'a> {
    fn show_device_flow_prompt(&self, verification_uri: &str, user_code: &str) {
        use pamsm::PamLibExt;

        let message = format!(
            "\n\
            ═══════════════════════════════════════════════════════════\n\
              Sudo requires step-up authentication\n\
            \n\
              Visit: {}\n\
              Enter code: {}\n\
            \n\
              Waiting for authentication...\n\
            ═══════════════════════════════════════════════════════════",
            verification_uri, user_code
        );

        // Use PAM conversation to show the message
        let _ = self
            .pamh
            .conv(Some(&message), pamsm::PamMsgStyle::TEXT_INFO);
    }

    fn show_waiting(&self, elapsed_seconds: u64, timeout_seconds: u64) {
        use pamsm::PamLibExt;

        let remaining = timeout_seconds.saturating_sub(elapsed_seconds);
        let message = format!("Waiting for authentication... ({}s remaining)", remaining);
        let _ = self
            .pamh
            .conv(Some(&message), pamsm::PamMsgStyle::TEXT_INFO);
    }

    fn show_success(&self) {
        use pamsm::PamLibExt;

        let message = "\n  Authentication successful!\n\
            ═══════════════════════════════════════════════════════════\n";
        let _ = self.pamh.conv(Some(message), pamsm::PamMsgStyle::TEXT_INFO);
    }

    fn show_failure(&self, reason: &str) {
        use pamsm::PamLibExt;

        let message = format!(
            "\n  Authentication failed: {}\n\
            ═══════════════════════════════════════════════════════════\n",
            reason
        );
        let _ = self
            .pamh
            .conv(Some(&message), pamsm::PamMsgStyle::ERROR_MSG);
    }
}

/// Quiet display that doesn't output anything (for testing).
pub struct QuietDisplay;

impl QuietDisplay {
    pub fn new() -> Self {
        Self
    }
}

impl Default for QuietDisplay {
    fn default() -> Self {
        Self::new()
    }
}

impl StepUpDisplay for QuietDisplay {
    fn show_device_flow_prompt(&self, _verification_uri: &str, _user_code: &str) {}
    fn show_waiting(&self, _elapsed_seconds: u64, _timeout_seconds: u64) {}
    fn show_success(&self) {}
    fn show_failure(&self, _reason: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_display_creation() {
        let display = TerminalDisplay::new();
        // Just verify it compiles and can be created
        display.show_success();
    }

    #[test]
    fn test_quiet_display() {
        let display = QuietDisplay::new();
        // Verify quiet display doesn't panic
        display.show_device_flow_prompt("https://example.com/device", "ABCD-1234");
        display.show_waiting(10, 60);
        display.show_success();
        display.show_failure("test failure");
    }
}
