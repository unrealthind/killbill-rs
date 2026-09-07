//! The logger responder: an independent record that a kill fired.
//!
//! It is "just another responder, not a prerequisite" (charter §6). It only
//! emits a `tracing` event — no file handling, no flushing, no blocking. Where
//! those records go (journald, a file layer) is a daemon-startup decision made
//! once in `main.rs`, never in the kill path, and that sink must be
//! non-blocking (see the module docs).
//!
//! [`message`] is a pure function so the wording of the log line is a tested
//! contract; `respond` only picks the level and attaches the structured fields.

use killbill_proto::Action;

use super::Responder;

/// Writes one structured line per kill decision.
pub(crate) struct LoggerResponder;

/// The human-readable line this responder logs for `action`. Pure.
///
/// A dry run says so explicitly; a real kill never contains the words
/// "DRY RUN". Both name the reason.
fn message(action: &Action) -> String {
    if action.dry_run {
        format!(
            "DRY RUN — a kill decision fired; no action was taken: {}",
            action.reason
        )
    } else {
        format!("KILL — responding to: {}", action.reason)
    }
}

impl Responder for LoggerResponder {
    fn name(&self) -> &'static str {
        "logger"
    }

    fn respond(&self, action: &Action) {
        let message = message(action);
        if action.dry_run {
            tracing::warn!(
                power = %action.power,
                luks_destroy = action.luks_destroy,
                dry_run = true,
                "{message}"
            );
        } else {
            // A real kill is the single most important non-error event this
            // daemon produces — log it at ERROR so it survives aggressive
            // journald filtering.
            tracing::error!(
                power = %action.power,
                luks_destroy = action.luks_destroy,
                dry_run = false,
                "{message}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use killbill_proto::{KillReason, PowerAction, UsbId};

    fn action(dry_run: bool) -> Action {
        Action {
            reason: KillReason::WhitelistedDeviceRemoved {
                id: UsbId::new(0x1050, 0x0407),
            },
            power: PowerAction::PowerOff,
            luks_destroy: false,
            dry_run,
        }
    }

    #[test]
    fn dry_run_line_is_marked_and_names_the_reason() {
        let m = message(&action(true));
        assert!(m.contains("DRY RUN"), "got: {m}");
        assert!(m.contains("1050:0407"), "got: {m}");
    }

    #[test]
    fn real_kill_line_never_says_dry_run() {
        let m = message(&action(false));
        assert!(!m.contains("DRY RUN"), "got: {m}");
        assert!(m.contains("KILL"), "got: {m}");
        assert!(m.contains("1050:0407"), "got: {m}");
    }

    #[test]
    fn respond_is_infallible_and_non_blocking() {
        LoggerResponder.respond(&action(false));
        LoggerResponder.respond(&action(true));
    }
}
