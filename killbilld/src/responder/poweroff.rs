//! The poweroff responder: the reason the tool exists.
//!
//! On a real kill it calls `reboot(2)` directly (via `nix`) — a typed syscall,
//! never a shelled-out command (invariant 6). `RB_POWER_OFF` is the hard stop:
//! the kernel cuts power without running any userspace, syncing, or unmounting.
//! That is deliberate. Any "tidy up first" step is a delay, and invariant 1
//! forbids delaying the poweroff; a LUKS disk that re-locks with a dirty
//! filesystem is the whole point of the trade.
//!
//! The real-kill branch of `respond` does **no logging** — not even "killing
//! now" — because a blocked log sink would sit between the decision and the
//! syscall (invariant 1). The record of the decision is the core's job and the
//! `logger` responder's job, both on other threads, both allowed to lose the
//! race.
//!
//! `lock_screen_first` (charter §9) is **not** wired here, and `config::validate`
//! rejects `= true` outright: a pre-poweroff wait would contend with invariant 1
//! and a fire-and-forget lock never wins the race against power being cut. See
//! `PROJECT_CHARTER.md` §13.
//!
//! Testability: [`plan`] is a pure function that decides *what* to do;
//! [`PoweroffResponder::respond`] is the thin part that performs the syscall.

use killbill_proto::{Action, PowerAction};

use super::{Responder, ResponderNotReady};

/// Performs the power action on a real kill.
pub(crate) struct PoweroffResponder;

/// What [`PoweroffResponder`] should do for a given [`Action`]. Pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoweroffPlan {
    /// `power_action = "none"` — the decision fired, but no power action is
    /// wanted. Logged; machine stays up.
    Skip,
    /// Dry run — say what would happen, touch nothing.
    Would(PowerAction),
    /// A real kill — invoke the syscall now.
    Now(PowerAction),
}

/// Decide what the poweroff responder does for `action`. No I/O.
fn plan(action: &Action) -> PoweroffPlan {
    match action.power {
        PowerAction::None => PoweroffPlan::Skip,
        power if action.dry_run => PoweroffPlan::Would(power),
        power => PoweroffPlan::Now(power),
    }
}

impl Responder for PoweroffResponder {
    fn name(&self) -> &'static str {
        "poweroff"
    }

    fn respond(&self, action: &Action) {
        match plan(action) {
            PoweroffPlan::Skip => tracing::warn!(
                reason = %action.reason,
                "kill decision fired but power_action = none; machine stays up"
            ),
            PoweroffPlan::Would(power) => tracing::warn!(
                reason = %action.reason,
                %power,
                "DRY RUN — would {power} the machine now"
            ),
            // Real kill: no logging here — straight to the syscall.
            PoweroffPlan::Now(power) => invoke(power),
        }
    }

    fn preflight(&self) -> Result<(), ResponderNotReady> {
        preflight_impl().map_err(|reason| ResponderNotReady {
            responder: self.name(),
            reason,
        })
    }
}

/// `CAP_SYS_BOOT` is capability number 22.
#[cfg(target_os = "linux")]
const CAP_SYS_BOOT_MASK: u64 = 1 << 22;

/// Arm-time check: can this host actually be powered off by us? Not the kill
/// path — file/syscall probes are fine.
///
/// Checks the *effective* capability set, not euid: under Phase 3's planned
/// `CapabilityBoundingSet` a root-euid daemon can still lack `CAP_SYS_BOOT`,
/// and that must fail the arm (invariant 2), not surface as an `EPERM` at kill
/// time.
#[cfg(target_os = "linux")]
fn preflight_impl() -> Result<(), String> {
    match effective_capabilities() {
        Some(caps) if (caps & CAP_SYS_BOOT_MASK) != 0 => Ok(()),
        Some(_) => Err(
            "CAP_SYS_BOOT is not in this process's effective capability set; \
                        reboot(2) would fail — check the unit's CapabilityBoundingSet"
                .to_owned(),
        ),
        None => Err(
            "could not read /proc/self/status to confirm CAP_SYS_BOOT; refusing to \
                     arm rather than assume the kill path works"
                .to_owned(),
        ),
    }
}

/// The effective-capability bitmask from `/proc/self/status` (`CapEff:`), or
/// `None` if it cannot be read or parsed.
#[cfg(target_os = "linux")]
fn effective_capabilities() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(not(target_os = "linux"))]
fn preflight_impl() -> Result<(), String> {
    Err(
        "the poweroff responder is not implemented on this platform; this host \
         cannot be protected"
            .to_owned(),
    )
}

/// Perform the power action. Does not return on success.
#[cfg(target_os = "linux")]
fn invoke(power: PowerAction) {
    use nix::sys::reboot::{reboot, RebootMode};

    let mode = match power {
        PowerAction::PowerOff => RebootMode::RB_POWER_OFF,
        PowerAction::Halt => RebootMode::RB_HALT_SYSTEM,
        PowerAction::None => {
            // `plan` never yields `Now(None)`; defensive only.
            tracing::error!("poweroff invoked with power_action = none; nothing to do");
            return;
        }
        other => {
            // A `PowerAction` variant added later must fail *toward* the kill.
            tracing::error!(?other, "unrecognized power_action; defaulting to power-off");
            RebootMode::RB_POWER_OFF
        }
    };

    // `nix`'s `reboot` returns `Result<Infallible, Errno>` on Linux: it does not
    // return on success, so `Err` is the only inhabited variant and these `let`
    // bindings are irrefutable. Binding one at all means the syscall failed and
    // the machine is still up — the worst outcome this daemon has. (If a future
    // `nix` changes the signature this stops compiling, which is the right kind
    // of loud.)
    //
    // Every fallback runs BEFORE any logging: `reboot(2)` may have failed
    // because the system is sick, and a wedged log sink must not stop the
    // SysRq write or the halt from being attempted (the C1 reasoning, carried
    // through). SysRq (`/proc/sysrq-trigger` <- 'o') is a typed constant write,
    // not a shelled command (invariant 6); it needs `kernel.sysrq` to permit
    // it and Phase 3's `ProtectKernelTunables=` will remount it read-only —
    // both tracked in the packaging work. When `power` was `Halt`, the halt
    // retry below repeats the call that just failed; harmless, and there is no
    // SysRq halt to escalate to.
    let Err(reboot_errno) = reboot(mode);
    let sysrq = std::fs::write("/proc/sysrq-trigger", b"o");
    let Err(halt_errno) = reboot(RebootMode::RB_HALT_SYSTEM);

    // Every path failed and the machine is still up. Record it so the daemon's
    // park-forever shutdown lets the process exit for a supervisor restart
    // instead of becoming a signal-immune zombie (set before logging — a wedged
    // sink must not gate this).
    super::mark_kill_failed();

    tracing::error!(
        %reboot_errno,
        sysrq = ?sysrq,
        %halt_errno,
        "reboot(2) FAILED and every last-resort poweroff path FAILED — the machine is \
         still up (missing CAP_SYS_BOOT?)"
    );
}

/// Non-Linux builds have no poweroff path. Arm-time [`preflight`](Responder::preflight)
/// refuses to arm here, so this should be unreachable in practice; it exists so
/// the daemon binary links and the pure code is testable anywhere.
#[cfg(not(target_os = "linux"))]
fn invoke(power: PowerAction) {
    super::mark_kill_failed();
    tracing::error!(
        ?power,
        "poweroff is unimplemented on this platform; NO power action taken"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use killbill_proto::{KillReason, UsbId};

    fn action(power: PowerAction, dry_run: bool) -> Action {
        Action {
            reason: KillReason::UnknownDevice {
                id: UsbId::new(0x0781, 0x5567),
            },
            power,
            luks_destroy: false,
            dry_run,
        }
    }

    #[test]
    fn none_is_always_skipped_even_when_not_a_dry_run() {
        assert_eq!(plan(&action(PowerAction::None, false)), PoweroffPlan::Skip);
        assert_eq!(plan(&action(PowerAction::None, true)), PoweroffPlan::Skip);
    }

    #[test]
    fn dry_run_never_reaches_the_syscall() {
        assert_eq!(
            plan(&action(PowerAction::PowerOff, true)),
            PoweroffPlan::Would(PowerAction::PowerOff)
        );
        assert_eq!(
            plan(&action(PowerAction::Halt, true)),
            PoweroffPlan::Would(PowerAction::Halt)
        );
    }

    #[test]
    fn a_real_kill_powers_off_now() {
        assert_eq!(
            plan(&action(PowerAction::PowerOff, false)),
            PoweroffPlan::Now(PowerAction::PowerOff)
        );
        assert_eq!(
            plan(&action(PowerAction::Halt, false)),
            PoweroffPlan::Now(PowerAction::Halt)
        );
    }

    #[test]
    fn respond_touches_no_power_for_none_or_dry_run() {
        // These branches never call `invoke`; if they did, the test runner
        // would go down. Reaching the assert means they returned cleanly.
        PoweroffResponder.respond(&action(PowerAction::None, false));
        PoweroffResponder.respond(&action(PowerAction::PowerOff, true));
        PoweroffResponder.respond(&action(PowerAction::Halt, true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preflight_tracks_cap_sys_boot() {
        let has_cap = effective_capabilities().is_some_and(|c| (c & CAP_SYS_BOOT_MASK) != 0);
        assert_eq!(PoweroffResponder.preflight().is_ok(), has_cap);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn effective_capabilities_parses_a_hex_bitmask() {
        // The running test process always has /proc/self/status.
        assert!(effective_capabilities().is_some());
    }
}
