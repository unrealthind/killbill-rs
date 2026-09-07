//! Responders: what a kill decision *does* (charter §6, build step 4).
//!
//! The policy engine produces an [`Action`]; a responder consumes it and acts.
//! The rule that governs this module is **invariant 1 — the kill path is
//! sacred**:
//!
//! * Responders are **independent subscribers, never a chain.** [`dispatch`]
//!   hands each responder its own owned copy of the [`Action`] on its own
//!   thread. No responder can see, wait on, or fail another.
//! * A responder **never returns an error and never blocks the caller.**
//!   [`Responder::respond`] returns `()`; a responder that fails logs and moves
//!   on. A slow or panicking responder cannot delay or abort the poweroff.
//! * [`dispatch`] does no blocking I/O and no logging *before* it has launched
//!   every responder. `PoweroffResponder` is launched first (see
//!   [`build_responders`]); if its thread cannot be spawned it runs inline,
//!   panic-caught, so the machine still powers off under thread-resource
//!   exhaustion.
//!
//! Because responders are trivial and rare-fired, they are plain synchronous
//! code on `std::thread`, not async tasks: nothing here depends on the Tokio
//! runtime being healthy, which is exactly the property the kill path wants.
//!
//! **Contracts the daemon wiring (steps 5–6) must honour:**
//!
//! * The decision site calls [`dispatch`] **synchronously, on the thread that
//!   made the decision.** The [`Action`] is never queued, buffered, or sent
//!   across a channel on its way to the responders — a bounded channel would
//!   add back-pressure to the kill path and an unbounded one a memory/deadlock
//!   risk (invariant 1). The control-socket event fan-out to UI subscribers is
//!   a separate, lossy, drop-on-full path.
//! * The `tracing` subscriber installed at startup must be non-blocking /
//!   drop-on-full, so no responder thread can be parked behind a log sink.
//! * The authoritative "what was decided" log line is written by the core
//!   **after** (or concurrently with) [`dispatch`], never before — `dispatch`
//!   returns in microseconds without joining, so the decision log then races
//!   the poweroff instead of gating it.
//! * The signal/shutdown path must check [`kill_in_flight`] and refuse to exit
//!   while it is set: a `SIGTERM` in the same millisecond as a real kill must
//!   not be able to tear down the poweroff thread (invariant 5 — a signal must
//!   never skip a pending kill). The latch is only set for an action that
//!   actually attempts a power action, so a healthy daemon after a dry run
//!   shuts down normally.
//! * Arming must call [`preflight`] and refuse to arm (loudly) if it reports
//!   any responder cannot act — e.g. no `CAP_SYS_BOOT`, or a non-Linux host
//!   (invariant 2).
//! * A `ReloadConfig` that produces an invalid config must be refused with the
//!   prior armed state and config kept — never silently disarmed or armed on a
//!   half-understood file (invariant 2).

mod logger;
mod luks_destroy;
mod poweroff;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use killbill_proto::{Action, PowerAction};

use crate::config::Config;

pub(crate) use logger::LoggerResponder;
pub(crate) use luks_destroy::LuksDestroyResponder;
pub(crate) use poweroff::PoweroffResponder;

/// Set by [`dispatch`] when it fans out an action that will actually attempt a
/// power action (not a dry run, not `power_action = "none"`), and never cleared.
static KILL_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// `true` once a real kill has been dispatched. The signal-driven shutdown path
/// must not let the process exit while this holds — doing so would destroy the
/// detached poweroff thread before it reaches `reboot(2)` (invariant 5). Since
/// `reboot(2)` does not return, "block forever" is the correct behaviour there:
/// the machine dies, not the daemon. A dry run or `power_action = "none"` never
/// sets it, so an ordinary shutdown after those is unaffected.
#[must_use]
pub fn kill_in_flight() -> bool {
    KILL_IN_FLIGHT.load(Ordering::SeqCst)
}

/// A single, independent reaction to a kill [`Action`].
///
/// Implementors must not block indefinitely, must not panic on a recoverable
/// error (log and return instead), and must assume nothing about any other
/// responder. `respond` takes `&self`: a responder holds only config-time state
/// and never mutates anything shared.
pub trait Responder: Send + Sync + 'static {
    /// Stable identifier for logs. One word, kebab-case.
    fn name(&self) -> &'static str;

    /// React to `action`. Called on a dedicated thread (or inline as a
    /// spawn-failure fallback); the return is ignored.
    fn respond(&self, action: &Action);

    /// Checked once, from the **arm path only** — never from [`dispatch`]. A
    /// responder that cannot possibly act (missing capability, unsupported
    /// platform) returns `Err` so the daemon refuses to arm instead of
    /// reporting itself armed and failing at kill time (invariant 2). File I/O
    /// and slow checks are fine here; this is not the kill path.
    fn preflight(&self) -> Result<(), ResponderNotReady> {
        Ok(())
    }
}

/// A responder reported, at arm time, that it cannot act. The daemon refuses to
/// arm and surfaces every one of these.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("responder {responder:?} is not ready: {reason}")]
pub struct ResponderNotReady {
    pub responder: &'static str,
    pub reason: String,
}

/// Fan `action` out to every responder and return immediately.
///
/// This is the kill path's fan-out point. It deliberately does **not** join the
/// threads, collect results, or let one responder's spawn failure drop it.
/// `PoweroffResponder` is listed first (see [`build_responders`]); if its
/// thread cannot be spawned it is run inline here — panic-caught — so a
/// `reboot(2)` still happens under thread-resource exhaustion. No `format!`, no
/// logging, and nothing that can block precedes the poweroff launch.
///
/// The poweroff runs on its own thread (spawned first) rather than inline-last
/// so that `dispatch` returns without blocking — the decision log then races
/// the poweroff instead of gating it (the contract above). A kill is a
/// once-per-lifetime event; scheduler starvation of a fresh thread on a machine
/// that is not already wedged is not a real risk, and the inline fallback
/// covers the case where the thread cannot be created at all.
pub fn dispatch(action: &Action, responders: &[Arc<dyn Responder>]) {
    if attempts_power(action) {
        KILL_IN_FLIGHT.store(true, Ordering::SeqCst);
    }

    let mut spawn_failures: usize = 0;

    for responder in responders {
        let responder_owned = Arc::clone(responder);
        let action_owned = action.clone();
        let launched = std::thread::Builder::new()
            .spawn(move || responder_owned.respond(&action_owned))
            .is_ok();

        if !launched {
            // No thread available (RLIMIT_NPROC, a PID cgroup, memory
            // pressure). Dropping this responder is not an option — for
            // poweroff it is the whole point of the daemon — so run it on this
            // thread, isolated so a panic here cannot unwind into the caller.
            // poweroff is first and `reboot(2)` does not return, so it never
            // reaches a later responder; a later responder that blocks here is
            // acceptable because poweroff already ran.
            spawn_failures += 1;
            run_isolated(responder.as_ref(), action);
        }
    }

    // Safe to log now: every responder has been launched (or run). A blocked
    // sink here can no longer gate the poweroff.
    tracing::debug!(
        count = responders.len(),
        spawn_failures,
        "kill action dispatched to responders"
    );
}

/// Whether `action` will actually try to power the machine down.
fn attempts_power(action: &Action) -> bool {
    !action.dry_run && action.power != PowerAction::None
}

/// Run one responder, swallowing a panic so it cannot unwind into the caller.
/// Used only for the inline spawn-failure fallback — a spawned responder is
/// already isolated by its thread boundary.
fn run_isolated(responder: &dyn Responder, action: &Action) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| responder.respond(action)));
}

/// Run every responder's [`Responder::preflight`]. Returns all failures; the
/// daemon calls this on the arm path and refuses to arm if it is non-empty.
#[must_use]
pub fn preflight(responders: &[Arc<dyn Responder>]) -> Vec<ResponderNotReady> {
    responders
        .iter()
        .filter_map(|r| r.preflight().err())
        .collect()
}

/// Assemble the responder set for a validated config.
///
/// `PoweroffResponder` is first on purpose (see [`dispatch`]).
/// `LuksDestroyResponder` is present only when `[response.luks_destroy]` was
/// configured and validated — and even then it is a stub that writes nothing
/// (invariant 3).
pub fn build_responders(cfg: &Config) -> Vec<Arc<dyn Responder>> {
    let mut responders: Vec<Arc<dyn Responder>> =
        vec![Arc::new(PoweroffResponder), Arc::new(LoggerResponder)];

    if let Some(luks) = &cfg.luks_destroy {
        responders.push(Arc::new(LuksDestroyResponder::new(
            luks.target_header.clone(),
        )));
    }

    responders
}

#[cfg(test)]
mod tests {
    use super::*;
    use killbill_proto::{KillReason, UsbId};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// An action that does not attempt a power action (so it never touches the
    /// process-global `KILL_IN_FLIGHT` latch).
    fn act() -> Action {
        Action {
            reason: KillReason::UnknownDevice {
                id: UsbId::new(0x0781, 0x5567),
            },
            power: PowerAction::None,
            luks_destroy: false,
            dry_run: false,
        }
    }

    /// Records its name down a channel when it runs, after an optional delay.
    struct Recorder {
        name: &'static str,
        delay: Duration,
        tx: mpsc::Sender<&'static str>,
    }

    impl Responder for Recorder {
        fn name(&self) -> &'static str {
            self.name
        }
        fn respond(&self, _action: &Action) {
            std::thread::sleep(self.delay);
            let _ = self.tx.send(self.name);
        }
    }

    struct Panicker;
    impl Responder for Panicker {
        fn name(&self) -> &'static str {
            "panicker"
        }
        fn respond(&self, _action: &Action) {
            panic!("responder blew up");
        }
    }

    #[test]
    fn attempts_power_only_for_a_real_power_action() {
        let real = Action {
            power: PowerAction::PowerOff,
            dry_run: false,
            ..act()
        };
        let dry = Action {
            dry_run: true,
            ..real.clone()
        };
        let none = Action {
            power: PowerAction::None,
            ..real.clone()
        };
        assert!(attempts_power(&real));
        assert!(!attempts_power(&dry));
        assert!(!attempts_power(&none));
    }

    #[test]
    fn run_isolated_swallows_a_panicking_responder() {
        // Returns normally rather than unwinding into the caller.
        run_isolated(&Panicker, &act());
    }

    #[test]
    fn dispatch_fans_out_to_every_responder() {
        let (tx, rx) = mpsc::channel();
        let responders: Vec<Arc<dyn Responder>> = vec![
            Arc::new(Recorder {
                name: "a",
                delay: Duration::ZERO,
                tx: tx.clone(),
            }),
            Arc::new(Recorder {
                name: "b",
                delay: Duration::ZERO,
                tx: tx.clone(),
            }),
            Arc::new(Recorder {
                name: "c",
                delay: Duration::ZERO,
                tx,
            }),
        ];

        dispatch(&act(), &responders);

        let mut seen = vec![
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        ];
        seen.sort_unstable();
        assert_eq!(seen, ["a", "b", "c"]);
    }

    #[test]
    fn dispatch_latches_kill_in_flight_for_a_real_kill() {
        // The latch is a process-global that is never cleared, so this only
        // asserts the monotonic transition to `true`.
        dispatch(
            &Action {
                power: PowerAction::PowerOff,
                dry_run: false,
                ..act()
            },
            &[],
        );
        assert!(kill_in_flight());
    }

    #[test]
    fn a_slow_responder_does_not_delay_a_fast_one() {
        let (tx, rx) = mpsc::channel();
        let responders: Vec<Arc<dyn Responder>> = vec![
            Arc::new(Recorder {
                name: "slow",
                delay: Duration::from_secs(3),
                tx: tx.clone(),
            }),
            Arc::new(Recorder {
                name: "fast",
                delay: Duration::ZERO,
                tx,
            }),
        ];

        let start = Instant::now();
        dispatch(&act(), &responders);

        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), "fast");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "fast responder was gated by the slow one"
        );
    }

    #[test]
    fn a_panicking_responder_does_not_stop_the_others() {
        let (tx, rx) = mpsc::channel();
        let responders: Vec<Arc<dyn Responder>> = vec![
            Arc::new(Panicker),
            Arc::new(Recorder {
                name: "survivor",
                delay: Duration::ZERO,
                tx,
            }),
        ];

        dispatch(&act(), &responders);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), "survivor");
    }

    #[test]
    fn build_responders_omits_luks_destroy_unless_configured() {
        let cfg = crate::config::validate(crate::config::RawConfig::default()).unwrap();
        let names: Vec<_> = build_responders(&cfg).iter().map(|r| r.name()).collect();
        assert_eq!(names, ["poweroff", "logger"]);
    }

    #[test]
    fn build_responders_puts_poweroff_first_and_adds_luks_when_configured() {
        let cfg = crate::config::validate(
            toml::from_str(
                r#"
                [response.luks_destroy]
                i_understand_this_is_irreversible = true
                target_header = "/dev/nvme0n1p3"
                "#,
            )
            .unwrap(),
        )
        .unwrap();

        let names: Vec<_> = build_responders(&cfg).iter().map(|r| r.name()).collect();
        assert_eq!(names, ["poweroff", "logger", "luks-destroy"]);
    }

    #[test]
    fn preflight_collects_every_not_ready_responder() {
        struct NotReady(&'static str);
        impl Responder for NotReady {
            fn name(&self) -> &'static str {
                self.0
            }
            fn respond(&self, _action: &Action) {}
            fn preflight(&self) -> Result<(), ResponderNotReady> {
                Err(ResponderNotReady {
                    responder: self.0,
                    reason: "test".to_owned(),
                })
            }
        }

        let responders: Vec<Arc<dyn Responder>> = vec![
            Arc::new(NotReady("one")),
            Arc::new(Recorder {
                name: "ok",
                delay: Duration::ZERO,
                tx: mpsc::channel().0,
            }),
            Arc::new(NotReady("two")),
        ];
        let failures: Vec<_> = preflight(&responders).iter().map(|f| f.responder).collect();
        assert_eq!(failures, ["one", "two"]);
    }
}
