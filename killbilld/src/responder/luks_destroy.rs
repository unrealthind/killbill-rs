//! The LUKS-header-destruction responder — **a stub in v1 (invariant 3).**
//!
//! The config schema, its fenced acknowledgment key
//! (`i_understand_this_is_irreversible`), validation, and this responder's
//! dry-run/log wiring are all real. The header wipe itself is **deliberately
//! unimplemented**. There is no code path in this file that writes to a device,
//! and none may be added — not behind a flag, not behind `#[cfg]`. See charter
//! §6 "Option B".
//!
//! On any kill where `luks_destroy` is set, this responder logs one line: a
//! static message plus the target as a **structured field** (never spliced into
//! the message text — the target is a config-controlled string and the log is
//! the operator's only account of what happened). Dry run and real run behave
//! identically here — that is the point of the stub.

use std::path::{Path, PathBuf};

use killbill_proto::Action;

use super::{Responder, ResponderNotReady};

/// The one line this responder emits for a LUKS-destroy "response". Static text
/// only; the target travels as a separate field.
const STUB_MESSAGE: &str = "luks_destroy STUB: would destroy the configured LUKS header — \
     not implemented in v1, NOTHING was written";

/// Logs what a real implementation *would* wipe. Writes nothing, ever.
pub(crate) struct LuksDestroyResponder {
    /// The validated `[response.luks_destroy] target_header`. Used only to name
    /// the target in the log line. `config::validate` guarantees this is an
    /// absolute, control-char-free path under `/dev/`; it is present here only
    /// because `build_responders` constructs this responder solely when the
    /// config produced a `Some(LuksDestroy)`.
    target: PathBuf,
}

impl LuksDestroyResponder {
    pub(crate) fn new(target: PathBuf) -> Self {
        Self { target }
    }
}

impl Responder for LuksDestroyResponder {
    fn name(&self) -> &'static str {
        "luks-destroy"
    }

    fn respond(&self, action: &Action) {
        if !action.luks_destroy {
            return;
        }
        // Field name is `target_header` (matches the config key, and avoids
        // colliding with `tracing`'s own metadata `target`).
        tracing::warn!(
            target_header = %self.target.display(),
            dry_run = action.dry_run,
            "{STUB_MESSAGE}"
        );
    }

    fn preflight(&self) -> Result<(), ResponderNotReady> {
        preflight_target(&self.target).map_err(|reason| ResponderNotReady {
            responder: self.name(),
            reason,
        })
    }
}

/// Arm-time check (invariant 2, charter §5): the configured target must exist
/// and be a block device. This is **not** a real LUKS-header probe — that lands
/// in Phase 3 with the actual wipe — but it is the fail-closed gate that
/// `config.rs` and the charter promise, so a typo'd or unplugged target refuses
/// the arm rather than surfacing at kill time.
#[cfg(unix)]
fn preflight_target(target: &Path) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;

    let meta = std::fs::metadata(target).map_err(|e| {
        let mut msg = format!("luks_destroy target {} cannot be read: {e}", target.display());
        // The shipped systemd unit sets `PrivateDevices=yes`, which gives the
        // daemon an empty private `/dev`. A real target under `/dev/` then looks
        // like it is missing. Point the operator at the fix rather than at their
        // disk layout.
        if e.kind() == std::io::ErrorKind::NotFound && target.starts_with("/dev/") {
            msg.push_str(
                " — if killbilld runs under systemd, PrivateDevices=yes hides /dev; \
                 install the killbilld.service.d/luks-destroy.conf drop-in \
                 (see /usr/share/killbill-rs/) and run `systemctl daemon-reload`",
            );
        }
        msg
    })?;
    if !meta.file_type().is_block_device() {
        return Err(format!(
            "luks_destroy target {} is not a block device",
            target.display()
        ));
    }
    // TODO(phase 3): read the LUKS2 magic from the header and refuse to arm if
    // the target is not actually a LUKS container.
    Ok(())
}

#[cfg(not(unix))]
fn preflight_target(_target: &Path) -> Result<(), String> {
    Err("luks_destroy is only supported on Unix".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use killbill_proto::{KillReason, PowerAction, UsbId};

    fn action(luks_destroy: bool, dry_run: bool) -> Action {
        Action {
            reason: KillReason::UnknownDevice {
                id: UsbId::new(0x0781, 0x5567),
            },
            power: PowerAction::PowerOff,
            luks_destroy,
            dry_run,
        }
    }

    #[test]
    fn the_stub_message_can_never_read_as_though_a_wipe_happened() {
        assert!(STUB_MESSAGE.contains("STUB"));
        assert!(STUB_MESSAGE.contains("NOTHING was written"));
        assert!(STUB_MESSAGE.contains("not implemented in v1"));
    }

    #[test]
    fn respond_is_silent_when_the_action_does_not_request_destruction() {
        // Only observable effect would be a log line; with no subscriber the
        // assertion is that both calls return cleanly and write nothing.
        let r = LuksDestroyResponder::new(PathBuf::from("/dev/nvme0n1p3"));
        r.respond(&action(false, false));
        r.respond(&action(false, true));
    }

    #[test]
    fn respond_runs_the_same_for_dry_and_real() {
        // Identical code path; the only difference is the `dry_run` field value
        // on the log record. Neither touches the device (stub).
        let r = LuksDestroyResponder::new(PathBuf::from("/dev/sda2"));
        r.respond(&action(true, true));
        r.respond(&action(true, false));
    }

    #[test]
    #[cfg(unix)]
    fn preflight_refuses_a_target_that_is_not_a_block_device() {
        // A path that does not exist. A missing `/dev/` target also carries the
        // PrivateDevices hint so a packaged install is not left guessing.
        let missing = LuksDestroyResponder::new(PathBuf::from("/dev/killbill-does-not-exist"));
        let err = missing.preflight().unwrap_err();
        assert!(err.reason.contains("PrivateDevices"), "{}", err.reason);

        // A regular file is not a block device.
        let dir = std::env::temp_dir().join(format!("killbilld-luks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let regular = dir.join("not-a-device");
        std::fs::write(&regular, b"x").unwrap();
        let r = LuksDestroyResponder::new(regular);
        assert!(r.preflight().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
