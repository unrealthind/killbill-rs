//! The daemon runtime: wire the sensor, the policy engine, the responders, and
//! the control server into one running process (charter §7.1).
//!
//! ## One authority thread
//!
//! Every piece of mutable daemon state — config, armed-state, the connected-
//! device set, the responder set, the subscriber list — lives in [`Core`], and
//! `Core` is touched by exactly **one thread**: the loop in [`run`]. Sensor
//! messages and control requests arrive on a single channel and are handled one
//! at a time. There are no locks, and "the decision site calls `dispatch`
//! synchronously on the thread that made the decision" ([`crate::responder`]) is
//! trivially true — that thread is this one.
//!
//! **The core thread never blocks on unbounded I/O.** Config *writes* — the
//! `fsync` in particular — move to a dedicated [`config_writer`] thread so they
//! can never sit in front of a pending USB event (invariant 1); the core
//! validates and does the in-memory swap only. The arm and reload paths *do*
//! run a bounded preflight on the core thread (a `/proc/self/status` read for
//! `CAP_SYS_BOOT`, opening a throwaway netlink socket) — these are
//! microsecond-scale, arming is not latency-sensitive, and a sensor event that
//! lands mid-arm is simply decided against the pre-arm state, which is the
//! correct fail-closed answer. Moving preflight onto the writer thread too is a
//! noted follow-up, not a correctness gap.
//!
//! Supporting threads do no policy: the sensor supervisor ([`sensor_supervisor`]
//! wrapping [`crate::sensor`]), the control acceptor and its per-connection
//! threads ([`crate::control`]), a signal thread, the config writer, and one
//! forwarder onto the core channel.
//!
//! ## Failure posture
//!
//! * Invalid config → the daemon runs but refuses to arm, and says why in
//!   `status` (invariant 2). `reload` fixes it without a restart. A whitelist
//!   change is refused while the config is invalid — the daemon never writes a
//!   config it could not read.
//! * The USB sensor thread dying → logged loudly, an `Event::SensorStopped`, and
//!   the daemon **exits non-zero** so its supervisor restarts a working
//!   instance (invariant 7). Armed state is not touched on the way out.
//! * The sensor losing events (buffer overflow) → sticky `events_lost` in
//!   `status`; with `on_sensor_gap = "kill"` a kill fires instead.
//! * A kill in flight at shutdown → the process parks and never exits; the
//!   machine is going down (invariant 5, [`kill_in_flight`]).

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use killbill_proto::{
    rfc3339_now, Action, Command, ConfigChange, ConfigPayload, DeviceIdentity, DeviceInfo, Event,
    EventKind, KillReason, LuksDestroyInfo, OnSensorGap, PowerAction, Reply, SensorEvent,
    SensorSource, StatusPayload, StreamEvent, UsbId, WhitelistEntry,
};

use crate::config::{self, Config, RawConfig, RawWhitelistEntry, SensorGapAction, SensorName};
use crate::config_store;
use crate::control::{self, ControlRequest, PeerCred, SubscribeOutcome};
use crate::device_table::DeviceTable;
use crate::policy::{self, Decision};
use crate::responder::{self, build_responders, dispatch, kill_failed, kill_in_flight, Responder};
use crate::sensor::{self, Sensor, SensorMessage, UsbNetlinkSensor};
use crate::StopFlag;

/// Where the daemon reads/writes config and binds its control socket.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub config_path: PathBuf,
    pub socket_path: PathBuf,
}

/// During startup, how long the inbox must be quiet of sensor traffic — with
/// the sensor already watching — before `armed_at_boot` arms. Lets a device
/// present at boot (or a `udevadm trigger` re-broadcast) be recorded as an
/// observation, not judged under protection, without keying off wall-clock.
const STARTUP_QUIET: Duration = Duration::from_millis(250);

/// Hard ceiling on the startup settling wait, so a sensor that never starts
/// does not hold `run` in the settling loop forever.
const STARTUP_CEILING: Duration = Duration::from_secs(5);

/// What ends the core loop.
enum Outcome {
    /// A termination signal: stop cleanly, exit zero.
    Shutdown,
    /// An unrecoverable condition: exit non-zero for a supervisor restart.
    Failed(String),
}

/// The `armed_at_boot` decision once the startup burst has settled.
#[derive(Debug, PartialEq, Eq)]
enum BootArm {
    /// `armed_at_boot` is not set.
    NotRequested,
    /// Arm now — the sensor is watching and no gap occurred.
    Now,
    /// The sensor is not up yet; leave the arm pending for a later
    /// `SensorStarted`.
    WhenSensorStarts,
    /// A gap occurred during startup (a sensor restart or overflow) — refuse,
    /// fail closed. Only an operator restart clears it.
    RefuseGap,
}

/// Pure decision for [`BootArm`], split out so it can be unit-tested (`run` has
/// no harness).
fn boot_arm_after_settle(armed_at_boot: bool, events_lost: bool, sensor_ok: bool) -> BootArm {
    if !armed_at_boot {
        BootArm::NotRequested
    } else if events_lost {
        BootArm::RefuseGap
    } else if sensor_ok {
        BootArm::Now
    } else {
        BootArm::WhenSensorStarts
    }
}

/// One message on the core thread's single inbox.
enum Msg {
    /// The sensor opened its socket and is now watching (sent on every
    /// (re)start of the sensor loop).
    SensorStarted,
    /// A normalized device add/remove.
    Sensor(SensorEvent),
    /// The sensor lost events (buffer overflow or an unparseable datagram).
    SensorLost,
    /// The sensor thread exited unexpectedly and the supervisor is respawning
    /// it. Armed state is unchanged; `sensor_ok` goes false until it is back.
    SensorRestarting,
    /// The sensor could not be kept running (repeated rapid failures). The
    /// daemon exits non-zero for a supervisor restart.
    SensorEnded,
    /// A request from a control connection.
    Control(ControlRequest),
    /// The config writer finished persisting a change.
    ConfigWritten {
        raw: RawConfig,
        config: Config,
        label: &'static str,
        result: Result<(), String>,
        reply: SyncSender<Reply>,
    },
    /// The config writer finished re-reading the file for a reload.
    ConfigReloaded {
        raw: Result<RawConfig, String>,
        reply: SyncSender<Reply>,
    },
    /// A termination signal was received.
    Shutdown,
}

/// A filesystem job for the [`config_writer`] thread — kept off the core thread.
enum WriteJob {
    Persist {
        path: PathBuf,
        // Boxed: `RawConfig` + `Config` dwarf the `Reload` variant, and this
        // job only ever travels down a channel — one allocation, no hot path.
        raw: Box<RawConfig>,
        config: Box<Config>,
        label: &'static str,
        reply: SyncSender<Reply>,
    },
    Reload {
        path: PathBuf,
        reply: SyncSender<Reply>,
    },
}

/// Run the daemon until a termination signal or the sensor dies. Blocks the
/// calling thread; the core loop runs on it.
pub fn run(opts: RunOptions) -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        tracing::warn!(
            "killbilld is not running as root — it will not be able to bind the control socket \
             root-owned, read netlink, or power the machine off. This is only useful for \
             development."
        );
    }

    let (msg_tx, msg_rx) = mpsc::channel::<Msg>();

    // --- USB sensor supervisor ------------------------------------------
    // One thread owns the sensor lifecycle: it spawns the sensor loop,
    // forwards its messages onto the core inbox, and on an unexpected exit
    // backs off and respawns rather than taking the daemon — and a manual arm
    // — down with it. It gives up (Msg::SensorEnded, non-zero exit) only after
    // repeated rapid failures.
    let sensor_stop = StopFlag::new();
    {
        let msg_tx = msg_tx.clone();
        let stop = sensor_stop.clone();
        spawn_named("sensor-supervisor", move || {
            let make = || -> Box<dyn Sensor> { Box::new(UsbNetlinkSensor::new()) };
            sensor_supervisor(make, &msg_tx, &stop);
        })?;
    }

    // --- config writer ---------------------------------------------------
    let (write_tx, write_rx) = mpsc::channel::<WriteJob>();
    {
        let msg_tx = msg_tx.clone();
        spawn_named("config-writer", move || config_writer(write_rx, msg_tx))?;
    }

    // --- control server + forwarder --------------------------------------
    let control_stop = StopFlag::new();
    let (creq_tx, creq_rx) = mpsc::channel::<ControlRequest>();
    {
        let msg_tx = msg_tx.clone();
        spawn_named("control-forward", move || {
            for request in creq_rx {
                if msg_tx.send(Msg::Control(request)).is_err() {
                    return;
                }
            }
        })?;
    }
    {
        let socket_path = opts.socket_path.clone();
        let stop = control_stop.clone();
        // Bind before spawning, and make failure fatal: a control socket we
        // cannot open (another daemon owns it, a stale non-socket file, a socket
        // the probe cannot classify) must stop startup. A daemon left running
        // with no control socket can never be disarmed (invariant 5), so a
        // degraded run is not an option.
        let listener = control::bind_listener(&socket_path)
            .with_context(|| format!("binding the control socket at {}", socket_path.display()))?;
        spawn_named("control-accept", move || {
            if let Err(e) = control::serve(listener, &socket_path, creq_tx, stop) {
                tracing::error!(error = %e, "control server stopped with an error");
            }
        })?;
    }

    // --- signals -------------------------------------------------------
    spawn_signal_thread(msg_tx.clone())?;

    // --- core state ----------------------------------------------------
    let mut core = Core::load(&opts.config_path, write_tx);
    match &core.config_error {
        Some(err) => tracing::error!(
            "configuration is INVALID — the daemon is running but WILL NOT ARM until it is \
             fixed and reloaded (invariant 2):\n{err}"
        ),
        None => tracing::info!(
            whitelist = core.config.whitelist.len(),
            dry_run = core.config.dry_run,
            power_action = %core.config.power_action,
            "configuration loaded"
        ),
    }

    // --- startup settling ---------------------------------------------------
    // Handle messages as they arrive, with `armed` still false and
    // `boot_arm_pending` not yet set, until the sensor is watching AND its
    // startup burst has gone quiet (or a ceiling elapses). Keys off "no sensor
    // traffic for STARTUP_QUIET", never wall-clock, so a slow hub or a
    // `udevadm trigger` re-broadcast cannot be judged under protection.
    let mut exit_error: Option<String> = None;
    let mut shutting_down = false;
    let settle_start = Instant::now();
    let mut last_sensor_traffic = settle_start;
    loop {
        let now = Instant::now();
        if now.duration_since(settle_start) >= STARTUP_CEILING {
            break;
        }
        if core.sensor_ok && now.duration_since(last_sensor_traffic) >= STARTUP_QUIET {
            break;
        }
        match msg_rx.recv_timeout(STARTUP_QUIET) {
            Ok(msg) => {
                let sensor_traffic = matches!(
                    msg,
                    Msg::Sensor(_) | Msg::SensorLost | Msg::SensorStarted | Msg::SensorRestarting
                );
                match handle_msg(&mut core, msg) {
                    ControlFlow::Continue(()) => {}
                    ControlFlow::Break(Outcome::Shutdown) => {
                        shutting_down = true;
                        break;
                    }
                    ControlFlow::Break(Outcome::Failed(reason)) => {
                        exit_error = Some(reason);
                        break;
                    }
                }
                if sensor_traffic {
                    last_sensor_traffic = Instant::now();
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // The startup burst has settled. Now honour `armed_at_boot`.
    if !shutting_down && exit_error.is_none() {
        match boot_arm_after_settle(core.config.armed_at_boot, core.events_lost, core.sensor_ok) {
            BootArm::NotRequested => {}
            BootArm::RefuseGap => tracing::error!(
                "armed_at_boot is set but the USB sensor reported a gap during startup — staying \
                 DISARMED (fail closed); restart killbilld once the sensor is healthy"
            ),
            BootArm::Now => {
                core.boot_arm_pending = true;
                core.try_boot_arm();
            }
            // Leave `boot_arm_pending` set so the next `SensorStarted` completes
            // it (B5b — a slow sensor must not silently become disarmed forever).
            BootArm::WhenSensorStarts => {
                core.boot_arm_pending = true;
                tracing::warn!(
                    ceiling_secs = STARTUP_CEILING.as_secs(),
                    "armed_at_boot is set but the USB sensor has not started yet — staying \
                     DISARMED; the daemon will arm as soon as the sensor is watching"
                );
            }
        }
    }

    tracing::info!(socket = %opts.socket_path.display(), "killbilld ready");

    // --- the one authority loop -------------------------------------------
    if !shutting_down && exit_error.is_none() {
        while let Ok(msg) = msg_rx.recv() {
            match handle_msg(&mut core, msg) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(Outcome::Shutdown) => {
                    tracing::info!("shutting down");
                    // Invariant 5: a signal must not skip a decision already in
                    // the queue. Evaluate every queued sensor observation first.
                    drain_pending_sensor_events(&mut core, &msg_rx);
                    break;
                }
                ControlFlow::Break(Outcome::Failed(reason)) => {
                    exit_error = Some(reason);
                    break;
                }
            }
        }
    }

    // Never exit — teardown included — while a kill is in flight (invariant 5),
    // unless every poweroff path has failed and parking would just wedge a
    // daemon that protects nothing.
    if kill_in_flight() {
        tracing::warn!(
            "a kill is in flight — killbilld will NOT exit; the machine is powering off now"
        );
        while kill_in_flight() && !kill_failed() {
            thread::park_timeout(Duration::from_secs(1));
        }
        if kill_failed() {
            control::remove_socket(&opts.socket_path);
            return Err(anyhow::anyhow!(
                "the poweroff and every fallback failed; exiting non-zero so a supervisor can \
                 restart a daemon that can be re-armed"
            ));
        }
    }

    control_stop.stop();
    sensor_stop.stop();
    control::remove_socket(&opts.socket_path);

    match exit_error {
        Some(reason) => Err(anyhow::anyhow!(reason)),
        None => Ok(()),
    }
}

/// Evaluate every sensor observation still queued on the inbox, then return.
/// Called on the shutdown path so a `SIGTERM` that raced an unplug still gets
/// that unplug decided (invariant 5).
///
/// **Every message that can dispatch a kill must be routed here.** That is all
/// four sensor variants, not just the device events: a queued `SensorRestarting`
/// or `SensorEnded` is a gap, and under `on_sensor_gap = "kill"` a gap fires.
/// Dropping one would make a signal a way to skip a pending kill — exactly what
/// invariant 5 forbids. The handlers are safe to re-enter here: `events_lost` is
/// sticky and [`Core::maybe_dispatch_gap_kill`] is latched.
///
/// Control requests and config-writer replies *are* dropped — we are stopping,
/// and neither can fire an `Action`.
fn drain_pending_sensor_events(core: &mut Core, rx: &Receiver<Msg>) {
    let mut drained = 0usize;
    while let Ok(msg) = rx.try_recv() {
        match msg {
            Msg::Sensor(event) => {
                core.on_sensor_event(event);
                drained += 1;
            }
            Msg::SensorLost => core.on_sensor_lost(),
            Msg::SensorRestarting => core.on_sensor_restarting(),
            Msg::SensorEnded => core.on_sensor_ended(),
            Msg::SensorStarted | Msg::Control(_) | Msg::Shutdown => {}
            Msg::ConfigWritten { .. } | Msg::ConfigReloaded { .. } => {}
        }
    }
    if drained > 0 {
        tracing::info!(drained, "evaluated queued device events before shutdown");
    }
}

/// Own the sensor's lifecycle: spawn it, forward its messages to the core, and
/// respawn with backoff if it exits unexpectedly. Gives up after repeated rapid
/// failures.
fn sensor_supervisor(make: impl Fn() -> Box<dyn Sensor>, core: &Sender<Msg>, stop: &StopFlag) {
    /// Backoff before respawn, indexed by consecutive-failure count.
    const BACKOFF: [Duration; 5] = [
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(15),
        Duration::from_secs(30),
    ];
    /// A sensor that ran at least this long before dying is treated as having
    /// recovered; the consecutive-failure count resets.
    const HEALTHY_RUN: Duration = Duration::from_secs(60);

    let mut failures = 0usize;
    loop {
        if stop.should_stop() {
            return;
        }

        let (sensor_tx, sensor_rx) = mpsc::channel::<SensorMessage>();
        let handle = match sensor::spawn(make(), sensor_tx) {
            Ok(handle) => handle,
            Err(e) => {
                tracing::error!(error = %e, "could not spawn the USB sensor thread — giving up");
                let _ = core.send(Msg::SensorEnded);
                return;
            }
        };
        let started_at = Instant::now();

        // `recv_timeout`, not `for message in sensor_rx`, so a `stop` set during
        // daemon shutdown is noticed promptly even when the sensor is idle —
        // otherwise this loop only ends when the sensor next emits or its
        // thread exits, and `run`'s `sensor_stop.stop()` would not be honoured
        // (harmless at process exit, but it hangs an in-process test harness).
        loop {
            match sensor_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(message) => {
                    let msg = match message {
                        SensorMessage::Started => Msg::SensorStarted,
                        SensorMessage::Event(ev) => Msg::Sensor(ev),
                        SensorMessage::EventsLost => Msg::SensorLost,
                    };
                    if core.send(msg).is_err() {
                        let _ = handle.shutdown();
                        return; // core is gone: daemon shutting down
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if stop.should_stop() {
                        let _ = handle.shutdown();
                        return;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        // The sensor channel closed: the sensor thread exited.
        let outcome = handle.shutdown();
        if stop.should_stop() {
            return;
        }

        if started_at.elapsed() >= HEALTHY_RUN {
            failures = 0;
        }
        failures += 1;

        // `>` not `>=`: every entry in BACKOFF is one respawn attempt, so the
        // daemon gets BACKOFF.len() of them (1+2+5+15+30 = 53s of backoff) and
        // gives up on the failure *after* the last one. Tolerating the full
        // table matters because giving up exits the process, and a restarted
        // daemon comes back DISARMED unless `armed_at_boot` is set — staying up
        // through a transient sensor fault keeps protection on.
        if failures > BACKOFF.len() {
            tracing::error!(
                ?outcome,
                failures,
                "the USB sensor has failed repeatedly — giving up; killbilld will exit non-zero \
                 for a supervisor (systemd Restart=on-failure) to restart it"
            );
            let _ = core.send(Msg::SensorEnded);
            return;
        }

        // In bounds by the check above; `get` keeps that a fact rather than a
        // proof obligation on the reader, in code that runs while armed.
        let backoff = BACKOFF
            .get(failures - 1)
            .copied()
            .unwrap_or(Duration::from_secs(30));
        tracing::error!(
            ?outcome,
            failures,
            backoff_secs = backoff.as_secs(),
            "the USB sensor thread stopped unexpectedly — respawning it; armed state is unchanged, \
             but device changes are not being seen until it is back"
        );
        if core.send(Msg::SensorRestarting).is_err() {
            return;
        }

        let deadline = Instant::now() + backoff;
        while Instant::now() < deadline {
            if stop.should_stop() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Handle one core message. `Break` ends the loop — [`Outcome::Failed`] makes
/// [`run`] return an error (for a supervisor restart).
fn handle_msg(core: &mut Core, msg: Msg) -> ControlFlow<Outcome> {
    match msg {
        Msg::SensorStarted => core.on_sensor_started(),
        Msg::Sensor(event) => core.on_sensor_event(event),
        Msg::SensorLost => core.on_sensor_lost(),
        Msg::SensorRestarting => core.on_sensor_restarting(),
        Msg::SensorEnded => {
            core.on_sensor_ended();
            return ControlFlow::Break(Outcome::Failed(
                "the USB sensor could not be kept running".to_owned(),
            ));
        }
        Msg::Control(ControlRequest::Command { cmd, reply, peer }) => {
            core.on_command(cmd, peer, reply);
        }
        Msg::Control(ControlRequest::Subscribe { peer, events, ack }) => {
            core.subscribe(peer, events, ack);
        }
        Msg::ConfigWritten {
            raw,
            config,
            label,
            result,
            reply,
        } => core.on_config_written(raw, config, label, result, reply),
        Msg::ConfigReloaded { raw, reply } => core.on_config_reloaded(raw, reply),
        Msg::Shutdown => return ControlFlow::Break(Outcome::Shutdown),
    }
    ControlFlow::Continue(())
}

fn config_writer(jobs: Receiver<WriteJob>, done: Sender<Msg>) {
    for job in jobs {
        let sent = match job {
            WriteJob::Persist {
                path,
                raw,
                config,
                label,
                reply,
            } => {
                let result = config_store::write_atomic(&path, &raw).map_err(|e| e.to_string());
                done.send(Msg::ConfigWritten {
                    raw: *raw,
                    config: *config,
                    label,
                    result,
                    reply,
                })
            }
            WriteJob::Reload { path, reply } => {
                let raw = config::load(&path).map_err(|e| e.to_string());
                done.send(Msg::ConfigReloaded { raw, reply })
            }
        };
        if sent.is_err() {
            return; // core is gone
        }
    }
}

fn spawn_named<F>(name: &str, f: F) -> anyhow::Result<()>
where
    F: FnOnce() + Send + 'static,
{
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(f)
        .map(drop)
        .with_context(|| format!("starting the {name} thread"))
}

fn spawn_signal_thread(msg_tx: Sender<Msg>) -> anyhow::Result<()> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let signals = Signals::new([SIGTERM, SIGINT]).context("installing signal handlers")?;
    spawn_named("signals", move || {
        let mut signals = signals;
        for signal in signals.forever() {
            if kill_in_flight() {
                tracing::warn!(
                    signal,
                    "signal received while a kill is in flight — IGNORED; a signal must never \
                     abort a pending kill (invariant 5)"
                );
                continue;
            }
            tracing::info!(signal, "termination signal received");
            let _ = msg_tx.send(Msg::Shutdown);
            // Keep handling signals — do NOT return here: dropping `Signals`
            // would restore the default disposition, and a second SIGTERM
            // during teardown would then kill a detached poweroff thread.
        }
    })
}

/// A subscribed control connection's event channel, plus a miss counter so a
/// client that stops reading is eventually dropped rather than leaking a thread.
struct Subscriber {
    tx: SyncSender<StreamEvent>,
    consecutive_misses: u32,
}

/// Cap on the event backlog replayed to a new subscriber. Generous for a UI
/// that reconnects promptly; a long-disconnected client just starts from
/// "now" like it always could.
const EVENT_BACKLOG_CAP: usize = 200;

/// All the daemon's mutable state. Touched only by the core loop.
struct Core {
    config_path: PathBuf,
    raw: RawConfig,
    config: Config,
    /// `Some` when the config is invalid: the daemon refuses to arm and refuses
    /// to write the file.
    config_error: Option<String>,
    armed: bool,
    devices: DeviceTracker,
    responders: Vec<Arc<dyn Responder>>,
    subscribers: Vec<Subscriber>,
    /// The last [`EVENT_BACKLOG_CAP`] broadcast events, oldest first — replayed
    /// to a new subscriber by the connection thread (see
    /// [`crate::control::serve_subscription`]), never by this one.
    event_backlog: VecDeque<StreamEvent>,
    sensor_ok: bool,
    events_lost: bool,
    /// The runtime twin of `config.luks_destroy`'s config-time acknowledgment
    /// (invariant 4: two distinctly-named opt-ins, neither sufficient alone —
    /// see `policy::act`). Set only by `Command::SetLuksDestroyEngaged`, and
    /// **never persisted**: every daemon start begins `false`, and any config
    /// swap that drops or de-acknowledges `luks_destroy` clears it too (see
    /// `swap_config`) — an engaged flag must not silently outlive the target
    /// it was engaged for.
    luks_destroy_engaged: bool,
    /// A sensor-gap kill has been dispatched under `on_sensor_gap = "kill"`.
    /// Latches [`Core::maybe_dispatch_gap_kill`] against a gap-notification
    /// burst; cleared on any config swap so a post-gap `reload` re-enables it.
    gap_kill_dispatched: bool,
    /// The running config differs from what is on disk because a `reload` was
    /// rejected (invariant 2 kept the last-good config). Surfaced in `status`.
    config_stale: bool,
    /// `armed_at_boot` is set but arming has not yet succeeded — retried on the
    /// next `SensorStarted`. Cleared on the first successful arm.
    boot_arm_pending: bool,
    /// A config read/write is in flight on the writer thread; reject a second.
    config_op_pending: bool,
    writer_tx: Sender<WriteJob>,
}

impl Core {
    const MAX_SUBSCRIBERS: usize = 16;
    /// Drop a subscriber after this many events in a row could not be delivered.
    const MAX_MISSES: u32 = 64;

    fn load(config_path: &Path, writer_tx: Sender<WriteJob>) -> Self {
        let (raw, config, config_error) = match config::load(config_path) {
            Ok(raw) => match config::validate(raw.clone()) {
                Ok(config) => (raw, config, None),
                Err(report) => (
                    RawConfig::default(),
                    default_config(),
                    Some(report.to_string()),
                ),
            },
            Err(err) => (
                RawConfig::default(),
                default_config(),
                Some(err.to_string()),
            ),
        };
        let responders = build_responders(&config);
        Self {
            config_path: config_path.to_path_buf(),
            raw,
            config,
            config_error,
            armed: false,
            devices: DeviceTracker::default(),
            responders,
            subscribers: Vec::new(),
            event_backlog: VecDeque::with_capacity(EVENT_BACKLOG_CAP),
            // Optimism is not allowed here (invariant 2): the sensor is "not ok"
            // until it has told us its socket opened (`Msg::SensorStarted`).
            sensor_ok: false,
            events_lost: false,
            // Never persisted, never inherited from a prior run — see the
            // field's doc comment.
            luks_destroy_engaged: false,
            gap_kill_dispatched: false,
            config_stale: false,
            boot_arm_pending: false,
            config_op_pending: false,
            writer_tx,
        }
    }

    // --- sensor events ---------------------------------------------------

    fn on_sensor_started(&mut self) {
        self.sensor_ok = true;
        tracing::info!("USB sensor is watching");
        if self.boot_arm_pending && !self.armed {
            self.try_boot_arm();
        }
    }

    fn on_sensor_event(&mut self, event: SensorEvent) {
        // A kernel-synthesized uevent (`udevadm trigger`, a sysfs `uevent`
        // write) carries SYNTH_UUID. A synthetic *add* re-announces a device
        // that is *already* present; with no coldplug enumeration in v1 a device
        // connected before the daemon started would otherwise read as "unknown"
        // here and fire — so record its identity and do not act on it.
        //
        // A synthetic *remove* has no such justification: nothing re-announces a
        // device that is gone, and an unplug is the event this tool exists to
        // catch. So the suppression is scoped to additions only.
        let synthetic = event.kind == EventKind::Added && event.raw.contains_key("SYNTH_UUID");

        // Decide against the table as it was *before* this event (the policy.rs
        // contract).
        let decision = policy::decide(
            &event,
            &self.config,
            &self.devices.table,
            self.luks_destroy_engaged,
        );

        // KILL PATH: if armed, the decision is to act, and this is a real
        // (non-synthetic) event, dispatch *now*. The Action is never queued.
        //
        // Nothing runs between the decision and this dispatch — the device-table
        // update below deliberately comes *after*, because it allocates (a
        // `DeviceIdentity` clone, a `HashMap` insert, a `Vec` push that may
        // reallocate) and allocation under memory pressure is the one thing on
        // this path that can stall. `dispatch` needs none of it. Everything else
        // (bookkeeping, subscriber fan-out, the decision log) is likewise after,
        // so none of it can gate the poweroff (invariant 1).
        let acting = self.armed && !synthetic && matches!(decision, Decision::Act(_));
        if let Decision::Act(action) = &decision {
            if acting {
                dispatch(action, &self.responders);
            }
        }

        match event.kind {
            EventKind::Added => self.devices.add(event.identity.clone()),
            EventKind::Removed => self.devices.remove(&event.identity),
        }

        let info = self.device_info(&event.identity);
        match event.kind {
            EventKind::Added => self.broadcast(Event::DeviceAdded(info)),
            EventKind::Removed => self.broadcast(Event::DeviceRemoved(info)),
        }
        match &decision {
            Decision::Ignore => tracing::debug!(
                kind = ?event.kind,
                id = ?event.identity.usb_id,
                "device event — allowed"
            ),
            Decision::Act(action) if acting => {
                // The responders run for real here, but two of them are
                // effectively silent to a subscriber: `dry_run` makes every
                // responder log-only (invariant 1's "dry_run" contract), and
                // `power_action = "none"` makes the poweroff responder itself
                // a no-op even outside dry-run — both are documented safety
                // belts (the hardware-gate protocol tests every substep with
                // both engaged) and both leave nothing for the machine to
                // visibly do. Without this, a client watching either belt
                // sees the device appear and then silence. `run_dry_run`'s
                // manual `WouldKill` broadcast is the other half of this;
                // this is the automatic-on-every-event half.
                //
                // `power = "none"` only counts as "hypothetical" when nothing
                // else on the Action actually acts: with `luks_destroy` engaged
                // the LUKS responder still receives a real `luks_destroy: true`
                // (a stub today, invariant 3 — but this broadcast must not grow
                // into announcing "would kill" while a real header wipe runs).
                let would_only_log =
                    action.dry_run || (action.power == PowerAction::None && !action.luks_destroy);
                if would_only_log {
                    self.broadcast(Event::WouldKill(action.reason.clone()));
                }
                tracing::warn!(
                    reason = %action.reason,
                    power = %action.power,
                    dry_run = action.dry_run,
                    luks_destroy = action.luks_destroy,
                    // A synthetic `remove` (e.g. `udevadm trigger --action=remove`)
                    // fires like a real unplug — the log must let them be told
                    // apart after the fact.
                    synthetic_uevent = event.raw.contains_key("SYNTH_UUID"),
                    "UNAUTHORIZED USB EVENT — kill action dispatched to all responders"
                );
            }
            Decision::Act(action) if synthetic => tracing::info!(
                reason = %action.reason,
                "policy would fire for a device announced by a synthetic uevent (already \
                 present at startup) — NOT acting; whitelist it or restart with it connected"
            ),
            Decision::Act(action) => tracing::info!(
                reason = %action.reason,
                "unauthorized USB event while DISARMED — recorded, not acted on"
            ),
        }
    }

    /// Build and dispatch the kill for a sensor gap (`on_sensor_gap = "kill"`).
    /// B1: a gap fires `power_action` only — header destruction is reserved for
    /// an actual identified device event and needs its own acknowledgment (see
    /// `PROJECT_CHARTER` §9).
    fn dispatch_gap_kill(&self) {
        let action = Action {
            reason: KillReason::SensorGap,
            power: self.config.power_action,
            luks_destroy: false,
            dry_run: self.config.dry_run,
        };
        dispatch(&action, &self.responders);
    }

    /// Dispatch a sensor-gap kill iff `on_sensor_gap = "kill"` and armed —
    /// called by every gap handler, KILL PATH FIRST (invariant 1), and *before*
    /// the sticky `events_lost` early-return, so a gap under `kill` still fires
    /// even when an earlier gap (a sensor restart, or one seen under a `warn`
    /// config since changed by `reload`) already latched the flag.
    ///
    /// Latched by `gap_kill_dispatched` so a burst of gap notifications — an
    /// unparseable-datagram flood, the supervisor's up-to-four respawns —
    /// cannot spawn a responder fan-out per notification. The latch is cleared
    /// on any config swap ([`Core::swap_config`]), so an operator who reloads
    /// after a gap (turning off `dry_run`, or `warn` → `kill`) gets a fresh
    /// decision on the next gap. Logs the dispatch itself, since the callers'
    /// own logging is skipped on a repeat gap.
    fn maybe_dispatch_gap_kill(&mut self) {
        if self.gap_kill_dispatched {
            return;
        }
        if !(matches!(self.config.on_sensor_gap, SensorGapAction::Kill) && self.armed) {
            return;
        }
        self.gap_kill_dispatched = true;
        self.dispatch_gap_kill();
        tracing::error!(
            dry_run = self.config.dry_run,
            power_action = %self.config.power_action,
            "USB sensor gap while ARMED and on_sensor_gap = kill — gap kill dispatched to all \
             responders"
        );
    }

    fn on_sensor_lost(&mut self) {
        self.maybe_dispatch_gap_kill();

        if self.events_lost {
            return; // reporting + bookkeeping are once-only
        }
        self.events_lost = true;
        self.broadcast(Event::EventsLost);

        match self.config.on_sensor_gap {
            // `maybe_dispatch_gap_kill` already logged if it dispatched.
            SensorGapAction::Kill if self.armed => {}
            SensorGapAction::Kill => tracing::error!(
                "the USB sensor lost events — on_sensor_gap = kill but DISARMED; not acting"
            ),
            SensorGapAction::Warn => tracing::error!(
                "the USB sensor lost events (buffer overflow or an unparseable datagram) — some \
                 device changes were MISSED. `status` now reports events_lost and the daemon \
                 will not (re)arm until restarted. (set response.on_sensor_gap = \"kill\" to \
                 power off on this instead.)"
            ),
        }
    }

    /// The sensor thread exited and the supervisor is respawning it (B6). Armed
    /// state is untouched; the daemon keeps running.
    ///
    /// A respawn window is a stretch of time the daemon could not see USB
    /// events — the exact shape invariant 7 exists to make loud. It is recorded
    /// on the same sticky `events_lost` flag a buffer overflow uses: `arm()`
    /// already refuses while it is set, `status` already reports it, and the
    /// clients already render it. The daemon will therefore not silently re-arm
    /// (or finish an `armed_at_boot` arm) across a sensor restart without an
    /// operator restarting it — the fail-closed answer, and the same one an
    /// `ENOBUFS` gap already gets.
    fn on_sensor_restarting(&mut self) {
        self.sensor_ok = false;

        // KILL PATH FIRST (invariant 1): before any bookkeeping or fan-out.
        self.maybe_dispatch_gap_kill();

        let first_gap = !self.events_lost;
        self.events_lost = true;

        // A pending boot arm must not survive the gap: clear it so it is not
        // retried — and refused, logging each time — on every later
        // `SensorStarted`. Arming now requires an operator restart anyway.
        if self.boot_arm_pending {
            self.boot_arm_pending = false;
            tracing::warn!(
                "clearing the pending armed_at_boot arm — the USB sensor restarted before it \
                 completed; the device set can no longer be accounted for. Restart killbilld \
                 once it is trustworthy, or arm manually."
            );
        }

        self.broadcast(Event::SensorStopped);
        if first_gap {
            self.broadcast(Event::EventsLost);
        }

        match self.config.on_sensor_gap {
            // `maybe_dispatch_gap_kill` already logged if it dispatched.
            SensorGapAction::Kill if self.armed => {}
            SensorGapAction::Kill => tracing::error!(
                "the USB sensor thread stopped — on_sensor_gap = kill but DISARMED; not acting"
            ),
            SensorGapAction::Warn => tracing::error!(
                "the USB sensor thread stopped and is being respawned — device changes are NOT \
                 being seen until it is back. Armed state is unchanged, but `status` now reports \
                 events_lost and the daemon will not (re)arm until it is restarted."
            ),
        }
    }

    /// The supervisor gave up: the sensor cannot be kept running and the daemon
    /// is about to exit non-zero for a supervisor restart. Treated as a gap too
    /// — `events_lost` set, gap kill dispatched under `kill` — so this terminal
    /// case cannot become a fail-open if the supervisor's retry counting is ever
    /// retuned (today it is only reachable before the daemon could have armed).
    fn on_sensor_ended(&mut self) {
        self.sensor_ok = false;
        self.maybe_dispatch_gap_kill();
        if !self.events_lost {
            self.events_lost = true;
            self.broadcast(Event::EventsLost);
        }
        self.broadcast(Event::SensorStopped);
        tracing::error!(
            "the USB sensor could not be kept running — device changes are no longer being \
             seen. killbilld is exiting non-zero so its supervisor (systemd Restart=on-failure) \
             starts a fresh instance. Armed state is not changed here (invariant 5)."
        );
    }

    // --- commands ------------------------------------------------------------

    fn on_command(&mut self, cmd: Command, peer: PeerCred, reply: SyncSender<Reply>) {
        // Charter §12: state-changing and expensive commands are "authenticated".
        // The connection thread already rejects a non-root peer for these
        // ([`Command::requires_root`]); this is defence in depth on the one
        // authz gate, and it also covers the in-process `PeerCred::SYSTEM` path.
        if cmd.requires_root() && !peer.is_root() {
            tracing::warn!(
                peer_uid = peer.uid,
                peer_pid = peer.pid,
                command = command_name(&cmd),
                "denied a privileged control command from a non-root peer"
            );
            answer(
                reply,
                Reply::Error(format!(
                    "permission denied: {} requires uid 0 (peer uid {})",
                    command_name(&cmd),
                    peer.uid
                )),
            );
            return;
        }

        match cmd {
            Command::GetStatus => answer(reply, Reply::Status(self.status())),
            Command::ListDevices => answer(reply, Reply::Devices(self.device_list())),
            Command::WhitelistList => answer(reply, Reply::Whitelist(self.whitelist_entries())),
            Command::Arm => {
                let result = self.arm(peer);
                if let Err(reason) = &result {
                    tracing::warn!(
                        peer_uid = peer.uid,
                        peer_pid = peer.pid,
                        %reason,
                        "arm request REFUSED"
                    );
                }
                answer(
                    reply,
                    match result {
                        Ok(()) => Reply::Ok,
                        Err(reason) => Reply::Error(reason),
                    },
                );
            }
            Command::Disarm => {
                self.disarm(peer);
                answer(reply, Reply::Ok);
            }
            Command::RunDryRun => answer(reply, self.run_dry_run()),
            Command::WhitelistAdd(entry) => self.whitelist_add(entry, reply),
            Command::WhitelistRemove(id) => self.whitelist_remove(id, reply),
            Command::ReloadConfig => self.reload(reply),
            Command::GetConfig => answer(reply, Reply::Config(self.config_payload())),
            Command::ConfigSet(change) => self.config_set(change, peer, reply),
            Command::SetLuksDestroyEngaged(want) => {
                self.set_luks_destroy_engaged(want, peer, reply)
            }
            Command::Subscribe => answer(
                reply,
                Reply::Error(
                    "Subscribe is a streaming command handled by the connection layer".to_owned(),
                ),
            ),
            _ => answer(reply, Reply::Error("unrecognized command".to_owned())),
        }
    }

    fn subscribe(
        &mut self,
        peer: PeerCred,
        tx: SyncSender<StreamEvent>,
        ack: SyncSender<SubscribeOutcome>,
    ) {
        // The event stream carries device ids, serials, and arm/disarm/would-kill
        // transitions — more than `status`. Require uid 0, like the state-
        // changing commands (the connection thread checks this too).
        if !peer.is_root() {
            tracing::warn!(
                peer_uid = peer.uid,
                peer_pid = peer.pid,
                "denied an event subscription from a non-root peer"
            );
            answer_subscribe(
                ack,
                Reply::Error(format!(
                    "permission denied: the event stream requires uid 0 (peer uid {})",
                    peer.uid
                )),
            );
            return;
        }
        if self.subscribers.len() >= Self::MAX_SUBSCRIBERS {
            tracing::warn!(
                limit = Self::MAX_SUBSCRIBERS,
                "refusing an event subscriber — already at the limit"
            );
            answer_subscribe(
                ack,
                Reply::Error("too many event subscribers; try again shortly".to_owned()),
            );
            return;
        }
        // Snapshot the backlog before pushing the new subscriber — not that
        // ordering matters on a single-threaded core, but it reads as the
        // obviously-correct order: "what happened before you joined".
        let backlog: Vec<StreamEvent> = self.event_backlog.iter().cloned().collect();
        self.subscribers.push(Subscriber {
            tx,
            consecutive_misses: 0,
        });
        let _ = ack.try_send(SubscribeOutcome {
            reply: Reply::Ok,
            backlog,
        });
    }

    fn status(&self) -> StatusPayload {
        StatusPayload {
            armed: self.armed,
            dry_run: self.config.dry_run,
            power_action: self.config.power_action,
            whitelist_len: self.config.whitelist.len(),
            device_count: self.devices.connected.len(),
            config_error: self.config_error.clone(),
            sensor_ok: self.sensor_ok,
            events_lost: self.events_lost,
            config_stale: self.config_stale,
        }
    }

    /// A snapshot of the **running** (validated) config, answering
    /// `Command::GetConfig`. See [`ConfigPayload`]'s doc comment for why this
    /// is the last-good config rather than a reflection of a broken file.
    fn config_payload(&self) -> ConfigPayload {
        ConfigPayload {
            armed_at_boot: self.config.armed_at_boot,
            sensors: self
                .config
                .sensors
                .iter()
                .map(|s| match s {
                    SensorName::Usb => "usb".to_owned(),
                })
                .collect(),
            dry_run: self.config.dry_run,
            power_action: self.config.power_action,
            on_sensor_gap: match self.config.on_sensor_gap {
                SensorGapAction::Warn => OnSensorGap::Warn,
                SensorGapAction::Kill => OnSensorGap::Kill,
            },
            luks_destroy: self.config.luks_destroy.as_ref().map(|l| LuksDestroyInfo {
                // Always true here — see `LuksDestroyInfo::acknowledged`'s doc
                // comment for why `validate` guarantees it.
                acknowledged: true,
                target_header: l.target_header.display().to_string(),
                engaged: self.luks_destroy_engaged,
            }),
            validation_error: self.config_error.clone(),
        }
    }

    /// Retry the `armed_at_boot` arm. Called from the startup settle and on
    /// every later `SensorStarted` while `boot_arm_pending`. Clears the flag
    /// only on success, so a transient failure is retried when the sensor next
    /// (re)starts; a genuine config problem just re-logs (rare — sensor
    /// restarts are rare).
    fn try_boot_arm(&mut self) {
        match self.arm(PeerCred::SYSTEM) {
            Ok(()) => self.boot_arm_pending = false,
            Err(reason) => tracing::error!(
                "armed_at_boot is set but arming failed — staying DISARMED (fail closed); will \
                 retry if the sensor restarts:\n{reason}"
            ),
        }
    }

    fn arm(&mut self, peer: PeerCred) -> Result<(), String> {
        if self.armed {
            return Ok(());
        }
        if let Some(err) = &self.config_error {
            return Err(format!(
                "refusing to arm — the configuration is invalid:\n{err}"
            ));
        }
        if !self.sensor_ok {
            return Err(
                "refusing to arm — the USB sensor is not running, so device changes \
                        would go unseen (invariant 7)"
                    .to_owned(),
            );
        }
        if self.events_lost {
            return Err(
                "refusing to arm — the USB sensor has lost events and can no longer \
                        account for the device set; restart killbilld"
                    .to_owned(),
            );
        }

        // Sensor preflight (invariant 2). Exhaustive on `SensorName` on purpose:
        // a new sensor must not silently skip its arm-time check.
        for name in &self.config.sensors {
            match name {
                SensorName::Usb => {
                    let sensor = UsbNetlinkSensor::new();
                    sensor
                        .preflight()
                        .map_err(|e| format!("refusing to arm — sensor {}: {e}", sensor.name()))?;
                }
            }
        }

        // Responder preflight (invariant 2).
        let failures = responder::preflight(&self.responders);
        if !failures.is_empty() {
            return Err(format!("refusing to arm — {}", join_failures(&failures)));
        }

        self.armed = true;
        tracing::warn!(
            peer_uid = peer.uid,
            peer_pid = peer.pid,
            dry_run = self.config.dry_run,
            power_action = %self.config.power_action,
            "ARMED"
        );
        self.broadcast(Event::Armed);
        Ok(())
    }

    fn disarm(&mut self, peer: PeerCred) {
        if self.armed {
            self.armed = false;
            tracing::warn!(peer_uid = peer.uid, peer_pid = peer.pid, "DISARMED");
            self.broadcast(Event::Disarmed);
            // The destructive opt-in is scoped to a single armed session
            // (decision recorded in CLAUDE.md, 2026-09-08): a disarm clears the
            // runtime engage toggle, so re-engaging always means the operator
            // walks the typed-`DESTROY` fence again. Already cleared on daemon
            // restart and on a config target change — this adds disarm.
            if self.luks_destroy_engaged {
                self.luks_destroy_engaged = false;
                tracing::warn!(
                    peer_uid = peer.uid,
                    peer_pid = peer.pid,
                    "cleared LUKS header destruction engage toggle on disarm"
                );
                self.broadcast(Event::ConfigChanged);
            }
        } else {
            tracing::info!(
                peer_uid = peer.uid,
                peer_pid = peer.pid,
                "disarm command received while already disarmed"
            );
        }
    }

    fn whitelist_add(&mut self, entry: WhitelistEntry, reply: SyncSender<Reply>) {
        if let Some(guard) = self.config_change_refusal("whitelist add") {
            answer(reply, guard);
            return;
        }
        let id = entry.id.to_string();
        let mut raw = self.raw.clone();
        raw.whitelist.retain(|w| w.id != id); // upsert by id
        raw.whitelist.push(RawWhitelistEntry {
            id,
            label: entry.label,
            max_count: entry.max_count,
        });
        self.begin_apply(raw, "whitelist add", reply);
    }

    fn whitelist_remove(&mut self, id: UsbId, reply: SyncSender<Reply>) {
        if let Some(guard) = self.config_change_refusal("whitelist remove") {
            answer(reply, guard);
            return;
        }
        let id = id.to_string();
        if !self.raw.whitelist.iter().any(|w| w.id == id) {
            answer(reply, Reply::Error(format!("no whitelist entry for {id}")));
            return;
        }
        let mut raw = self.raw.clone();
        raw.whitelist.retain(|w| w.id != id);
        self.begin_apply(raw, "whitelist remove", reply);
    }

    /// Apply one [`ConfigChange`] to a clone of the raw config and validate the
    /// whole thing (invariant 2) — exactly [`Core::whitelist_add`]'s shape,
    /// just touching a different field. `label` is used only for logging and
    /// to pick the right broadcast event in [`Core::swap_config`].
    fn config_set(&mut self, change: ConfigChange, peer: PeerCred, reply: SyncSender<Reply>) {
        if let Some(guard) = self.config_change_refusal("config set") {
            answer(reply, guard);
            return;
        }
        // Audit trail: a config change alters how the daemon responds to a kill;
        // record who asked, the same as `arm`/`disarm` do.
        tracing::info!(
            peer_uid = peer.uid,
            peer_pid = peer.pid,
            change = ?change,
            "config set requested"
        );
        let mut raw = self.raw.clone();
        let label: &'static str = match change {
            ConfigChange::DryRun(v) => {
                raw.response.dry_run = v;
                "config set dry_run"
            }
            ConfigChange::PowerAction(pa) => {
                raw.response.power_action = Some(pa.to_string());
                "config set power_action"
            }
            ConfigChange::ArmedAtBoot(v) => {
                raw.general.armed_at_boot = v;
                "config set armed_at_boot"
            }
            ConfigChange::Sensors(names) => {
                raw.detection.sensors = names;
                "config set sensors"
            }
            ConfigChange::OnSensorGap(gap) => {
                raw.response.on_sensor_gap = Some(gap.to_string());
                "config set on_sensor_gap"
            }
            // `ConfigChange` is `#[non_exhaustive]` from this crate's side —
            // a future variant added to `killbill-proto` without a matching
            // arm here must fail closed (invariant 2), not panic on the
            // authority thread. Same shape as `on_command`'s catch-all.
            _ => {
                answer(reply, Reply::Error("unrecognized config field".to_owned()));
                return;
            }
        };
        self.begin_apply(raw, label, reply);
    }

    /// `Command::SetLuksDestroyEngaged` — the runtime half of invariant 4's
    /// two-opt-in requirement (see `policy::act` and the `luks_destroy_engaged`
    /// field doc comment). Never touches the config file: this is `Core`
    /// state, not persisted, so it never goes through `begin_apply`/the
    /// writer thread.
    fn set_luks_destroy_engaged(&mut self, want: bool, peer: PeerCred, reply: SyncSender<Reply>) {
        if want && self.config.luks_destroy.is_none() {
            answer(
                reply,
                Reply::Error(
                    "refusing to engage LUKS header destruction: [response.luks_destroy] is not \
                     configured and acknowledged in the running config"
                        .to_owned(),
                ),
            );
            return;
        }
        // Log every accepted request, not just ones that actually flip the
        // value: a repeated `SetLuksDestroyEngaged(true)` is an operator
        // re-confirming a dangerous state, and the audit trail for a
        // destructive opt-in (invariant 4) should show every confirmation,
        // not only the first.
        let changed = self.luks_destroy_engaged != want;
        self.luks_destroy_engaged = want;
        tracing::warn!(
            engaged = want,
            changed,
            peer_uid = peer.uid,
            peer_pid = peer.pid,
            "LUKS header destruction runtime engage toggle set"
        );
        // Tell every other subscriber (a second TUI, `killbillctl events
        // --follow`) that a dangerous runtime state changed — it is surfaced
        // through `ConfigPayload::luks_destroy.engaged`, so `ConfigChanged` is
        // the "re-fetch GetConfig" signal for it (invariant 4: the engaged
        // state must be visible everywhere, not only to the client that set it).
        if changed {
            self.broadcast(Event::ConfigChanged);
        }
        answer(reply, Reply::Ok);
    }

    /// `Some(reason)` if a config-mutating command must be refused right now.
    fn config_change_refusal(&self, what: &str) -> Option<Reply> {
        if let Some(err) = &self.config_error {
            return Some(Reply::Error(format!(
                "refusing to {what}: the running configuration is invalid. Fix {} on disk and \
                 run `reload` first.\n{err}",
                self.config_path.display()
            )));
        }
        if self.config_op_pending {
            return Some(Reply::Error(
                "a configuration change is already being written; retry shortly".to_owned(),
            ));
        }
        None
    }

    /// Validate `raw`; if it passes (and, while armed, keeps every responder
    /// able to act), hand the persist to the writer thread. The in-memory swap
    /// and the client reply happen later, on [`Core::on_config_written`].
    fn begin_apply(&mut self, raw: RawConfig, label: &'static str, reply: SyncSender<Reply>) {
        let config = match config::validate(raw.clone()) {
            Ok(config) => config,
            Err(report) => {
                tracing::warn!(change = label, %report, "config change REJECTED — file untouched");
                answer(reply, Reply::Error(format!("{label} rejected:\n{report}")));
                return;
            }
        };
        if self.armed {
            let failures = responder::preflight(&build_responders(&config));
            if !failures.is_empty() {
                let detail = join_failures(&failures);
                tracing::warn!(
                    change = label,
                    failures = %detail,
                    "config change REJECTED while armed — a responder would no longer be able to act"
                );
                answer(
                    reply,
                    Reply::Error(format!(
                        "{label} rejected — while armed, a responder would no longer be able to \
                         act: {detail}"
                    )),
                );
                return;
            }
        }

        self.config_op_pending = true;
        let job = WriteJob::Persist {
            path: self.config_path.clone(),
            raw: Box::new(raw),
            config: Box::new(config),
            label,
            reply,
        };
        if let Err(mpsc::SendError(job)) = self.writer_tx.send(job) {
            self.config_op_pending = false;
            if let WriteJob::Persist { reply, .. } = job {
                answer(reply, Reply::Error("daemon is shutting down".to_owned()));
            }
        }
    }

    fn on_config_written(
        &mut self,
        raw: RawConfig,
        config: Config,
        label: &'static str,
        result: Result<(), String>,
        reply: SyncSender<Reply>,
    ) {
        self.config_op_pending = false;
        match result {
            Ok(()) => {
                self.swap_config(raw, config, label);
                answer(reply, Reply::Ok);
            }
            Err(e) => {
                tracing::error!(
                    change = label,
                    error = %e,
                    "config change validated but could NOT be persisted; running config unchanged"
                );
                answer(
                    reply,
                    Reply::Error(format!("{label}: could not write the config file: {e}")),
                );
            }
        }
    }

    fn reload(&mut self, reply: SyncSender<Reply>) {
        if self.config_op_pending {
            answer(
                reply,
                Reply::Error("a configuration change is already being processed; retry".to_owned()),
            );
            return;
        }
        self.config_op_pending = true;
        let job = WriteJob::Reload {
            path: self.config_path.clone(),
            reply,
        };
        if let Err(mpsc::SendError(job)) = self.writer_tx.send(job) {
            self.config_op_pending = false;
            if let WriteJob::Reload { reply, .. } = job {
                answer(reply, Reply::Error("daemon is shutting down".to_owned()));
            }
        }
    }

    fn on_config_reloaded(&mut self, raw: Result<RawConfig, String>, reply: SyncSender<Reply>) {
        self.config_op_pending = false;
        let raw = match raw {
            Ok(raw) => raw,
            Err(e) => {
                self.config_stale = true;
                tracing::error!(
                    error = %e,
                    "reload REJECTED — the config file could not be read; running config and \
                     armed state kept (invariant 2), on-disk file differs and needs fixing"
                );
                let reason = format!("reload failed — the config file could not be read: {e}");
                self.broadcast(Event::ReloadFailed(truncate_for_broadcast(&reason)));
                answer(reply, Reply::Error(reason));
                return;
            }
        };
        let config = match config::validate(raw.clone()) {
            Ok(config) => config,
            Err(report) => {
                self.config_stale = true;
                tracing::error!(
                    %report,
                    "reload REJECTED — the config on disk is invalid; running config and armed \
                     state kept (invariant 2), on-disk file differs and needs fixing"
                );
                let reason = format!(
                    "reload failed — the config on disk is invalid; keeping the running config \
                     and armed state (invariant 2):\n{report}"
                );
                self.broadcast(Event::ReloadFailed(truncate_for_broadcast(&reason)));
                answer(reply, Reply::Error(reason));
                return;
            }
        };
        if self.armed {
            let failures = responder::preflight(&build_responders(&config));
            if !failures.is_empty() {
                self.config_stale = true;
                let detail = join_failures(&failures);
                tracing::error!(
                    failures = %detail,
                    "reload REJECTED while armed — a responder would no longer be able to act; \
                     running config kept, on-disk file differs"
                );
                let reason = format!(
                    "reload rejected — while armed, a responder would no longer be able to act: \
                     {detail}"
                );
                self.broadcast(Event::ReloadFailed(truncate_for_broadcast(&reason)));
                answer(reply, Reply::Error(reason));
                return;
            }
        }
        self.swap_config(raw, config, "reload");
        answer(reply, Reply::Ok);
    }

    /// Swap in a validated config and rebuild the responder set. Warns loudly if
    /// the change weakens the response while armed.
    fn swap_config(&mut self, raw: RawConfig, config: Config, label: &'static str) {
        let was_armed = self.armed;
        let prev_dry_run = self.config.dry_run;
        let prev_power = self.config.power_action;
        // Captured *before* the swap below overwrites `self.config` — see the
        // engage-toggle clearing logic just after it.
        let prev_target = self
            .config
            .luks_destroy
            .as_ref()
            .map(|l| l.target_header.clone());

        self.raw = raw;
        self.config = config;
        self.config_error = None;
        self.config_stale = false;
        // An operator config change is a fresh look at the situation: re-enable
        // the sensor-gap kill so the next gap is judged against the new config
        // (e.g. `dry_run` just turned off, or `warn` → `kill`). `events_lost`
        // stays sticky — this does not let the daemon re-arm.
        self.gap_kill_dispatched = false;
        // The runtime engage toggle must not silently outlive the target it
        // was engaged for (see the field's doc comment). Clearing only when
        // `luks_destroy` disappears entirely is not enough: a config change
        // that keeps `luks_destroy` present but repoints `target_header` at a
        // *different* device is functionally a brand-new, unconfirmed
        // destructive target, and an old engagement must not carry over to
        // it — the operator confirmed the old header, not this one. So the
        // toggle survives a swap only if the target is unchanged.
        let same_target = matches!(
            (&prev_target, self.config.luks_destroy.as_ref()),
            (Some(prev), Some(new)) if *prev == new.target_header
        );
        if !same_target {
            // Log the automatic clear so the audit trail is symmetric with the
            // explicit engage (which always logs) — a destructive opt-in going
            // away silently is the asymmetry the review gate flagged.
            if self.luks_destroy_engaged {
                tracing::warn!(
                    change = label,
                    prev_target = ?prev_target,
                    "cleared LUKS header destruction engage toggle — target changed"
                );
            }
            self.luks_destroy_engaged = false;
        }
        self.responders = build_responders(&self.config);

        tracing::info!(change = label, "configuration updated");

        // `label` is one of a handful of `&'static str`s this module itself
        // hands `swap_config` — never client-supplied — so matching on its
        // text to pick the event is safe and simpler than threading a
        // dedicated enum through `WriteJob`/`Msg` for the same information.
        if label.starts_with("whitelist") {
            self.broadcast(Event::WhitelistChanged);
        } else {
            self.broadcast(Event::ConfigChanged);
        }

        if was_armed {
            if self.config.dry_run && !prev_dry_run {
                tracing::warn!(
                    change = label,
                    "this change set dry_run = true while ARMED — a kill would now only be logged"
                );
            }
            if self.config.power_action != prev_power {
                tracing::warn!(
                    change = label,
                    from = %prev_power,
                    to = %self.config.power_action,
                    "this change altered power_action while ARMED"
                );
            }
        }
    }

    fn run_dry_run(&mut self) -> Reply {
        let mut reasons = Vec::new();
        for (i, identity) in self.devices.connected.iter().enumerate() {
            // Evaluate this device as if it were the one just added: the
            // "already connected" count is every *other* tracked device.
            let others: DeviceTable = self
                .devices
                .connected
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .filter_map(|(_, d)| d.usb_id)
                .collect();
            let synthetic = SensorEvent {
                source: SensorSource::Usb,
                kind: EventKind::Added,
                identity: identity.clone(),
                raw: Default::default(),
            };
            let decision =
                policy::decide(&synthetic, &self.config, &others, self.luks_destroy_engaged);
            if let Decision::Act(action) = decision {
                reasons.push(action.reason);
            }
        }
        for reason in &reasons {
            self.broadcast(Event::WouldKill(reason.clone()));
        }
        tracing::info!(
            hits = reasons.len(),
            "dry run evaluated the connected device set"
        );
        Reply::DryRun(reasons)
    }

    // --- helpers ------------------------------------------------------------

    fn device_list(&self) -> Vec<DeviceInfo> {
        self.devices
            .connected
            .iter()
            .map(|d| self.device_info(d))
            .collect()
    }

    fn device_info(&self, identity: &DeviceIdentity) -> DeviceInfo {
        DeviceInfo {
            source: SensorSource::Usb,
            id: identity.usb_id,
            serial: identity.serial.clone(),
            label: identity.label.clone(),
            whitelisted: identity
                .usb_id
                .is_some_and(|id| self.config.whitelist.iter().any(|w| w.id == id)),
        }
    }

    fn whitelist_entries(&self) -> Vec<WhitelistEntry> {
        self.config
            .whitelist
            .iter()
            .map(|w| WhitelistEntry {
                id: w.id,
                label: w.label.clone(),
                max_count: Some(w.max_count),
            })
            .collect()
    }

    /// Stamp `event` as a [`StreamEvent`], append it to the backlog (capped at
    /// [`EVENT_BACKLOG_CAP`]), and push it to every live subscriber. The
    /// timestamp is generated exactly once here, so the copy a new subscriber
    /// gets from the backlog and the copy an already-subscribed client got
    /// live are identical — never two different stamps for the same event.
    fn broadcast(&mut self, event: Event) {
        let stream_event = StreamEvent {
            at: rfc3339_now(),
            event,
        };

        if self.event_backlog.len() >= EVENT_BACKLOG_CAP {
            self.event_backlog.pop_front();
        }
        self.event_backlog.push_back(stream_event.clone());

        self.subscribers
            .retain_mut(|sub| match sub.tx.try_send(stream_event.clone()) {
                Ok(()) => {
                    sub.consecutive_misses = 0;
                    true
                }
                Err(mpsc::TrySendError::Full(_)) => {
                    sub.consecutive_misses += 1;
                    if sub.consecutive_misses >= Self::MAX_MISSES {
                        tracing::debug!("dropping a subscriber that stopped reading");
                        false
                    } else {
                        true // lossy by design (charter §6) — this event is skipped
                    }
                }
                Err(mpsc::TrySendError::Disconnected(_)) => false,
            });
    }
}

fn answer(reply: SyncSender<Reply>, r: Reply) {
    let _ = reply.try_send(r);
}

/// Like [`answer`], for a refused subscription — the backlog is always empty
/// on refusal (nothing is ever handed to a caller that was denied it).
fn answer_subscribe(ack: SyncSender<SubscribeOutcome>, reply: Reply) {
    let _ = ack.try_send(SubscribeOutcome {
        reply,
        backlog: Vec::new(),
    });
}

fn command_name(cmd: &Command) -> &'static str {
    match cmd {
        Command::GetStatus => "status",
        Command::ListDevices => "list-devices",
        Command::Arm => "arm",
        Command::Disarm => "disarm",
        Command::WhitelistAdd(_) => "whitelist-add",
        Command::WhitelistRemove(_) => "whitelist-remove",
        Command::WhitelistList => "whitelist-list",
        Command::RunDryRun => "dry-run",
        Command::ReloadConfig => "reload",
        Command::GetConfig => "get-config",
        Command::ConfigSet(_) => "config-set",
        Command::SetLuksDestroyEngaged(_) => "set-luks-destroy-engaged",
        Command::Subscribe => "subscribe",
        _ => "unknown",
    }
}

fn join_failures(failures: &[responder::ResponderNotReady]) -> String {
    failures
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Cap on a `String` this module puts into a broadcast [`Event`] (currently
/// just `Event::ReloadFailed`'s reason). A [`config::ValidationReport`]
/// collects *every* problem in the file — unbounded in principle, e.g. a
/// config with hundreds of malformed whitelist entries — so without this a
/// single broadcast can exceed `MAX_CONTROL_FRAME` on its own. `encode`
/// rejects an oversized frame with `ProtocolError::FrameTooLarge`, and unlike
/// a direct command reply (which `control::serve_connection` already turns
/// into a small "too large" error) an unsendable *broadcast* event has
/// nowhere else to go: it would sit in `event_backlog` and break replay for
/// every subscriber after it, not just this one. So truncate at the source
/// instead of relying on every write site downstream. The caller who asked
/// for the reload directly still gets the full, untruncated report in their
/// own `Reply::Error`; the daemon's log always has the full report too — only
/// the broadcast copy is capped.
const MAX_BROADCAST_REASON_LEN: usize = 4096;

fn truncate_for_broadcast(reason: &str) -> String {
    // Scrub C0/C1 control characters (keeping `\n` and `\t`) before this reaches
    // every subscriber's terminal. A `ValidationReport` is already escape-safe —
    // every `ConfigError` field is formatted with `{:?}` — but a TOML parse
    // error echoes a raw source line, and that is the one broadcast string that
    // could carry a stray control byte from the root-owned config file.
    let scrubbed: String = reason
        .chars()
        .map(|c| match c {
            '\n' | '\t' => c,
            c if c.is_control() => '\u{fffd}',
            c => c,
        })
        .collect();
    if scrubbed.len() <= MAX_BROADCAST_REASON_LEN {
        return scrubbed;
    }
    let mut cut = MAX_BROADCAST_REASON_LEN;
    while !scrubbed.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{}… (truncated; see the daemon log or run `reload` directly for the full report)",
        &scrubbed[..cut]
    )
}

fn default_config() -> Config {
    // Startup only: `RawConfig::default()` is always valid (there is a test).
    config::validate(RawConfig::default()).expect("the empty configuration is always valid")
}

/// The connected-device set: counts (for the policy engine) and a list (for
/// `ListDevices` and events).
#[derive(Default)]
struct DeviceTracker {
    table: DeviceTable,
    connected: Vec<DeviceIdentity>,
}

impl DeviceTracker {
    fn add(&mut self, identity: DeviceIdentity) {
        if let Some(id) = identity.usb_id {
            self.table.insert(id);
        }
        self.connected.push(identity);
    }

    fn remove(&mut self, identity: &DeviceIdentity) {
        if let Some(id) = identity.usb_id {
            self.table.remove(id);
        }
        if let Some(pos) = self
            .connected
            .iter()
            .position(|d| d.usb_id == identity.usb_id && d.serial == identity.serial)
        {
            self.connected.remove(pos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::sync_channel;
    use std::sync::Mutex;

    /// A minimal owned temp directory (the workspace has no tempfile dep).
    struct TempDir(PathBuf);

    impl TempDir {
        fn create() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let base = std::env::temp_dir().join(format!(
                "killbilld-daemon-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&base).unwrap();
            Self(base)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A `Core` wired to an in-test config writer we pump by hand.
    struct Harness {
        _dir: TempDir,
        path: PathBuf,
        core: Core,
        jobs: Receiver<WriteJob>,
    }

    impl Harness {
        fn new(config_body: &str) -> Self {
            let dir = TempDir::create();
            let path = dir.0.join("config.toml");
            std::fs::write(&path, config_body).unwrap();
            let (write_tx, jobs) = mpsc::channel::<WriteJob>();
            let core = Core::load(&path, write_tx);
            Self {
                _dir: dir,
                path,
                core,
                jobs,
            }
        }

        /// Subscribe on behalf of `peer`, returning the synchronous ack (the
        /// backlog, if accepted, is discarded — see [`Self::subscribe_full`]
        /// for the tests that care about it).
        fn subscribe(&mut self, peer: PeerCred, tx: SyncSender<StreamEvent>) -> Reply {
            self.subscribe_full(peer, tx).0
        }

        /// Subscribe on behalf of `peer`, returning both the ack and the
        /// backlog it was handed.
        fn subscribe_full(
            &mut self,
            peer: PeerCred,
            tx: SyncSender<StreamEvent>,
        ) -> (Reply, Vec<StreamEvent>) {
            let (ack, ack_rx) = sync_channel::<SubscribeOutcome>(1);
            self.core.subscribe(peer, tx, ack);
            let outcome = ack_rx.try_recv().expect("subscribe answers synchronously");
            (outcome.reply, outcome.backlog)
        }

        /// Run one pending writer job synchronously, as the writer thread would,
        /// then feed the result back into the core.
        fn pump_writer(&mut self) {
            match self.jobs.try_recv().expect("a write job was queued") {
                WriteJob::Persist {
                    path,
                    raw,
                    config,
                    label,
                    reply,
                } => {
                    let result = config_store::write_atomic(&path, &raw).map_err(|e| e.to_string());
                    self.core
                        .on_config_written(*raw, *config, label, result, reply);
                }
                WriteJob::Reload { path, reply } => {
                    let raw = config::load(&path).map_err(|e| e.to_string());
                    self.core.on_config_reloaded(raw, reply);
                }
            }
        }
    }

    /// Records every Action it is handed.
    struct Recorder(Arc<Mutex<Vec<Action>>>);
    impl Responder for Recorder {
        fn name(&self) -> &'static str {
            "recorder"
        }
        fn respond(&self, action: &Action) {
            self.0.lock().unwrap().push(action.clone());
        }
    }

    fn added(id: Option<UsbId>) -> SensorEvent {
        SensorEvent {
            source: SensorSource::Usb,
            kind: EventKind::Added,
            identity: DeviceIdentity {
                usb_id: id,
                serial: None,
                label: None,
            },
            raw: Default::default(),
        }
    }

    fn removed(id: Option<UsbId>) -> SensorEvent {
        SensorEvent {
            kind: EventKind::Removed,
            ..added(id)
        }
    }

    /// An `add` carrying SYNTH_UUID — a `udevadm trigger` re-broadcast.
    fn synthetic_added(id: Option<UsbId>) -> SensorEvent {
        let mut ev = added(id);
        ev.raw.insert("SYNTH_UUID".to_owned(), "0".to_owned());
        ev
    }

    /// A `remove` carrying SYNTH_UUID. Unlike a synthetic add, this is never a
    /// re-announcement of a present device and must still fire.
    fn synthetic_removed(id: Option<UsbId>) -> SensorEvent {
        let mut ev = removed(id);
        ev.raw.insert("SYNTH_UUID".to_owned(), "0".to_owned());
        ev
    }

    fn root() -> PeerCred {
        PeerCred {
            uid: 0,
            pid: 1,
            gid: 0,
        }
    }

    fn mallory() -> PeerCred {
        PeerCred {
            uid: 1000,
            pid: 42,
            gid: 1000,
        }
    }

    #[test]
    fn arm_is_refused_while_the_config_is_invalid() {
        let mut h = Harness::new("[detection]\nsensors = []\n");
        h.core.sensor_ok = true;
        assert!(h.core.config_error.is_some());
        assert!(h.core.arm(root()).unwrap_err().contains("refusing to arm"));
        assert!(!h.core.armed);
    }

    #[test]
    fn arm_is_refused_until_the_sensor_has_started() {
        let mut h = Harness::new("");
        // sensor_ok starts false (invariant 2 — no optimistic guess).
        assert!(h
            .core
            .arm(root())
            .unwrap_err()
            .contains("sensor is not running"));
        h.core.sensor_ok = true;
        // Now it gets past the sensor gate (a bind may still fail without perms;
        // either way it is no longer the sensor-not-running message).
        let err = h.core.arm(root()).err();
        assert!(err.as_deref().is_none_or(|e| !e.contains("not running")));
    }

    #[test]
    fn a_successful_arm_flips_state_and_broadcasts() {
        let mut h = Harness::new("[response]\npower_action = \"none\"\n");
        h.core.sensor_ok = true;
        // Skip the real UsbNetlinkSensor preflight (needs a live netlink socket)
        // and the poweroff preflight (needs CAP_SYS_BOOT) by driving the state
        // machine past them: no sensors configured, no responders.
        h.core.config.sensors.clear();
        h.core.responders.clear();

        let (tx, rx) = sync_channel::<StreamEvent>(4);
        assert!(matches!(h.subscribe(root(), tx), Reply::Ok));

        assert!(h.core.arm(root()).is_ok());
        assert!(h.core.armed);
        assert!(matches!(rx.try_recv().unwrap().event, Event::Armed));

        h.core.disarm(root());
        assert!(!h.core.armed);
        assert!(matches!(rx.try_recv().unwrap().event, Event::Disarmed));
    }

    #[test]
    fn sensor_ended_marks_not_ok_without_touching_armed() {
        let mut h = Harness::new("[response]\npower_action = \"none\"\n");
        h.core.sensor_ok = true;
        h.core.config.sensors.clear();
        h.core.responders.clear();
        h.core.arm(root()).unwrap();

        h.core.on_sensor_ended();
        assert!(!h.core.sensor_ok);
        assert!(h.core.armed, "sensor death must not disarm (invariant 5)");

        // A fresh arm after the sensor is gone must be refused.
        h.core.disarm(root());
        assert!(h
            .core
            .arm(root())
            .unwrap_err()
            .contains("sensor is not running"));
    }

    #[test]
    fn a_non_root_peer_cannot_change_state_but_can_read_status() {
        let mut h = Harness::new("");
        h.core.sensor_ok = true;

        for cmd in [
            Command::Arm,
            Command::Disarm,
            Command::ReloadConfig,
            Command::RunDryRun,
            Command::WhitelistRemove(UsbId::new(0x1050, 0x0407)),
        ] {
            let (tx, rx) = sync_channel::<Reply>(1);
            h.core.on_command(cmd, mallory(), tx);
            assert!(
                matches!(rx.try_recv(), Ok(Reply::Error(e)) if e.contains("permission denied")),
                "a non-root peer must be denied"
            );
        }
        assert!(!h.core.armed);
        assert!(h.jobs.try_recv().is_err(), "nothing was written");

        // Read-only status is allowed for a non-root peer.
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.on_command(Command::GetStatus, mallory(), tx);
        assert!(matches!(rx.try_recv(), Ok(Reply::Status(_))));
    }

    #[test]
    fn a_non_root_peer_cannot_subscribe() {
        let mut h = Harness::new("");
        let (tx, _rx) = sync_channel::<StreamEvent>(4);
        assert!(matches!(h.subscribe(mallory(), tx), Reply::Error(_)));
        assert!(h.core.subscribers.is_empty());
    }

    #[test]
    fn whitelist_add_is_refused_while_the_config_is_invalid_and_the_file_is_untouched() {
        let mut h = Harness::new("[detection]\nsensors = []\n");
        let original = std::fs::read_to_string(&h.path).unwrap();

        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.whitelist_add(
            WhitelistEntry {
                id: UsbId::new(0x1050, 0x0407),
                label: None,
                max_count: None,
            },
            tx,
        );
        assert!(matches!(rx.try_recv().unwrap(), Reply::Error(_)));
        assert!(h.jobs.try_recv().is_err(), "no write job was queued");
        assert_eq!(std::fs::read_to_string(&h.path).unwrap(), original);
    }

    #[test]
    fn whitelist_add_persists_and_takes_effect() {
        let mut h = Harness::new("");
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.whitelist_add(
            WhitelistEntry {
                id: UsbId::new(0x1050, 0x0407),
                label: Some("YubiKey".to_owned()),
                max_count: Some(1),
            },
            tx,
        );
        h.pump_writer();

        assert!(matches!(rx.try_recv().unwrap(), Reply::Ok));
        assert_eq!(h.core.config.whitelist.len(), 1);

        let (wt, _) = mpsc::channel();
        let reloaded = Core::load(&h.path, wt);
        assert_eq!(reloaded.config.whitelist.len(), 1);
    }

    #[test]
    fn get_config_reflects_the_running_config() {
        let h = Harness::new(
            "[general]\narmed_at_boot = true\n[response]\ndry_run = true\n\
             power_action = \"halt\"\non_sensor_gap = \"kill\"\n",
        );
        let payload = h.core.config_payload();
        assert!(payload.armed_at_boot);
        assert_eq!(payload.sensors, vec!["usb".to_owned()]);
        assert!(payload.dry_run);
        assert_eq!(payload.power_action, PowerAction::Halt);
        assert_eq!(payload.on_sensor_gap, killbill_proto::OnSensorGap::Kill);
        assert!(payload.luks_destroy.is_none());
        assert!(payload.validation_error.is_none());
    }

    #[test]
    fn get_config_surfaces_the_validation_error_and_falls_back_to_defaults() {
        let h = Harness::new("[response]\npower_action = \"explode\"\n");
        assert!(h.core.config_error.is_some());
        let payload = h.core.config_payload();
        assert!(payload.validation_error.is_some());
        // Falls back to the always-valid default, not a half-parsed guess
        // (invariant 2) — never a reflection of the broken file.
        assert_eq!(payload.power_action, PowerAction::PowerOff);
    }

    #[test]
    fn whitelist_add_broadcasts_whitelist_changed_not_config_changed() {
        let mut h = Harness::new("");
        let (etx, erx) = sync_channel::<StreamEvent>(4);
        assert!(matches!(h.subscribe(root(), etx), Reply::Ok));

        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.whitelist_add(
            WhitelistEntry {
                id: UsbId::new(0x1050, 0x0407),
                label: None,
                max_count: None,
            },
            tx,
        );
        h.pump_writer();
        assert!(matches!(rx.try_recv().unwrap(), Reply::Ok));

        assert!(matches!(
            erx.try_recv().unwrap().event,
            Event::WhitelistChanged
        ));
    }

    #[test]
    fn config_set_dry_run_persists_and_broadcasts_config_changed() {
        let mut h = Harness::new("");
        let (etx, erx) = sync_channel::<StreamEvent>(4);
        assert!(matches!(h.subscribe(root(), etx), Reply::Ok));

        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.config_set(ConfigChange::DryRun(true), root(), tx);
        h.pump_writer();

        assert!(matches!(rx.try_recv().unwrap(), Reply::Ok));
        assert!(h.core.config.dry_run);

        let (wt, _) = mpsc::channel();
        let reloaded = Core::load(&h.path, wt);
        assert!(reloaded.config.dry_run, "the change was persisted to disk");

        assert!(matches!(
            erx.try_recv().unwrap().event,
            Event::ConfigChanged
        ));
    }

    #[test]
    fn config_set_rejecting_an_invalid_change_touches_neither_file_nor_running_config() {
        let mut h = Harness::new("");
        let (tx, rx) = sync_channel::<Reply>(1);
        // "bogus" is not a real sensor name -> the whole config fails validation.
        h.core
            .config_set(ConfigChange::Sensors(vec!["bogus".to_owned()]), root(), tx);

        assert!(matches!(rx.try_recv().unwrap(), Reply::Error(_)));
        assert!(h.jobs.try_recv().is_err(), "nothing was written");
        assert_eq!(h.core.config.sensors, vec![SensorName::Usb]);
    }

    #[test]
    fn set_luks_destroy_engaged_is_refused_without_an_acknowledged_target() {
        let mut h = Harness::new("");
        assert!(h.core.config.luks_destroy.is_none());
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.set_luks_destroy_engaged(true, root(), tx);
        assert!(matches!(rx.try_recv().unwrap(), Reply::Error(_)));
        assert!(!h.core.luks_destroy_engaged);
    }

    #[test]
    fn set_luks_destroy_engaged_succeeds_with_an_acknowledged_target_and_reflects_in_get_config() {
        let mut h = Harness::new(
            "[response.luks_destroy]\ni_understand_this_is_irreversible = true\n\
             target_header = \"/dev/nvme0n1p3\"\n",
        );
        assert!(h.core.config.luks_destroy.is_some());

        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.set_luks_destroy_engaged(true, root(), tx);
        assert!(matches!(rx.try_recv().unwrap(), Reply::Ok));
        assert!(h.core.luks_destroy_engaged);
        assert!(h.core.config_payload().luks_destroy.unwrap().engaged);

        let (tx2, rx2) = sync_channel::<Reply>(1);
        h.core.set_luks_destroy_engaged(false, root(), tx2);
        assert!(matches!(rx2.try_recv().unwrap(), Reply::Ok));
        assert!(!h.core.luks_destroy_engaged);
    }

    #[test]
    fn engaged_flag_is_cleared_when_a_config_change_drops_luks_destroy() {
        let mut h = Harness::new(
            "[response.luks_destroy]\ni_understand_this_is_irreversible = true\n\
             target_header = \"/dev/nvme0n1p3\"\n",
        );
        let (tx, _rx) = sync_channel::<Reply>(1);
        h.core.set_luks_destroy_engaged(true, root(), tx);
        assert!(h.core.luks_destroy_engaged);

        // Reload onto a file with no [response.luks_destroy] at all.
        std::fs::write(&h.path, "").unwrap();
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.reload(tx);
        h.pump_writer();
        assert!(matches!(rx.try_recv().unwrap(), Reply::Ok));

        assert!(h.core.config.luks_destroy.is_none());
        assert!(
            !h.core.luks_destroy_engaged,
            "an engaged flag must not survive its target leaving the config"
        );
    }

    #[test]
    fn engaged_flag_is_cleared_when_the_config_change_retargets_luks_destroy() {
        // The other half of the drop case above: `luks_destroy` stays
        // configured, but a *different* target replaces it. The operator
        // confirmed the old header, not this one — the engagement must not
        // carry over.
        let mut h = Harness::new(
            "[response.luks_destroy]\ni_understand_this_is_irreversible = true\n\
             target_header = \"/dev/nvme0n1p3\"\n",
        );
        let (tx, _rx) = sync_channel::<Reply>(1);
        h.core.set_luks_destroy_engaged(true, root(), tx);
        assert!(h.core.luks_destroy_engaged);

        std::fs::write(
            &h.path,
            "[response.luks_destroy]\ni_understand_this_is_irreversible = true\n\
             target_header = \"/dev/sda\"\n",
        )
        .unwrap();
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.reload(tx);
        h.pump_writer();
        assert!(matches!(rx.try_recv().unwrap(), Reply::Ok));

        assert!(
            h.core.config.luks_destroy.is_some(),
            "luks_destroy is still configured, just retargeted"
        );
        assert!(
            !h.core.luks_destroy_engaged,
            "an engaged flag must not carry over to a target the operator never confirmed"
        );
    }

    #[test]
    fn engaged_flag_survives_an_unrelated_config_change_to_the_same_target() {
        let mut h = Harness::new(
            "[response.luks_destroy]\ni_understand_this_is_irreversible = true\n\
             target_header = \"/dev/nvme0n1p3\"\n",
        );
        let (tx, _rx) = sync_channel::<Reply>(1);
        h.core.set_luks_destroy_engaged(true, root(), tx);
        assert!(h.core.luks_destroy_engaged);

        // config_set touches dry_run only — the luks_destroy target is untouched.
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.config_set(ConfigChange::DryRun(true), root(), tx);
        h.pump_writer();
        assert!(matches!(rx.try_recv().unwrap(), Reply::Ok));

        assert!(
            h.core.luks_destroy_engaged,
            "an unrelated config change must not disengage a still-valid target"
        );
    }

    #[test]
    fn disarm_clears_the_luks_destroy_engage_toggle() {
        // Decision recorded in CLAUDE.md (2026-09-08): the destructive opt-in is
        // scoped to one armed session — a disarm clears it, so re-engaging
        // always walks the typed-`DESTROY` fence again.
        let mut h = Harness::new(
            "[response.luks_destroy]\ni_understand_this_is_irreversible = true\n\
             target_header = \"/dev/nvme0n1p3\"\n",
        );
        h.core.sensor_ok = true;
        h.core.config.sensors.clear();
        h.core.responders.clear();
        h.core.arm(root()).unwrap();

        let (tx, _rx) = sync_channel::<Reply>(1);
        h.core.set_luks_destroy_engaged(true, root(), tx);
        assert!(h.core.luks_destroy_engaged);

        let (etx, erx) = sync_channel::<StreamEvent>(8);
        assert!(matches!(h.subscribe(root(), etx), Reply::Ok));

        h.core.disarm(root());
        assert!(!h.core.armed);
        assert!(
            !h.core.luks_destroy_engaged,
            "a disarm must clear the runtime engage toggle"
        );

        // Other clients learn the engaged state changed (via ConfigChanged, the
        // "re-fetch GetConfig" signal), alongside the Disarmed event.
        let mut events = Vec::new();
        while let Ok(se) = erx.try_recv() {
            events.push(se.event);
        }
        assert!(events.iter().any(|e| matches!(e, Event::Disarmed)));
        assert!(events.iter().any(|e| matches!(e, Event::ConfigChanged)));
    }

    #[test]
    fn a_new_subscriber_receives_the_event_backlog_before_anything_live() {
        let mut h = Harness::new("");
        h.core.broadcast(Event::Armed);
        h.core.broadcast(Event::Disarmed);

        let (tx, _rx) = sync_channel::<StreamEvent>(4);
        let (reply, backlog) = h.subscribe_full(root(), tx);
        assert!(matches!(reply, Reply::Ok));
        assert_eq!(backlog.len(), 2);
        assert!(matches!(backlog[0].event, Event::Armed));
        assert!(matches!(backlog[1].event, Event::Disarmed));
    }

    #[test]
    fn event_backlog_is_capped() {
        let mut h = Harness::new("");
        for _ in 0..(EVENT_BACKLOG_CAP + 10) {
            h.core.broadcast(Event::Disarmed);
        }
        assert_eq!(h.core.event_backlog.len(), EVENT_BACKLOG_CAP);
    }

    #[test]
    fn reload_failure_broadcasts_reload_failed() {
        let mut h = Harness::new("");
        let (etx, erx) = sync_channel::<StreamEvent>(4);
        assert!(matches!(h.subscribe(root(), etx), Reply::Ok));

        std::fs::write(&h.path, "not = = valid toml").unwrap();
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.reload(tx);
        h.pump_writer();
        assert!(matches!(rx.try_recv().unwrap(), Reply::Error(_)));
        assert!(h.core.config_stale);

        assert!(matches!(
            erx.try_recv().unwrap().event,
            Event::ReloadFailed(_)
        ));
    }

    #[test]
    fn armed_dry_run_kill_dispatches_and_broadcasts_would_kill() {
        let mut h = Harness::new("[response]\ndry_run = true\npower_action = \"none\"\n");
        h.core.armed = true;
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];

        let (tx, rx) = sync_channel::<StreamEvent>(4);
        assert!(matches!(h.subscribe(root(), tx), Reply::Ok));

        h.core
            .on_sensor_event(added(Some(UsbId::new(0x0781, 0x5567))));

        for _ in 0..50 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "the kill was actually dispatched to the responder, not skipped"
        );

        let mut saw_would_kill = false;
        while let Ok(se) = rx.try_recv() {
            if matches!(se.event, Event::WouldKill(_)) {
                saw_would_kill = true;
            }
        }
        assert!(
            saw_would_kill,
            "an armed dry-run kill must broadcast WouldKill, not go silent"
        );
    }

    #[test]
    fn armed_kill_with_power_action_none_also_broadcasts_would_kill() {
        // Not dry_run — power_action = "none" is the *other* documented safety
        // belt (the hardware-gate protocol, step 0.0, treats them as two
        // independent belts), and it is just as silent to a subscriber: the
        // kill dispatches for real, but the poweroff responder's plan is
        // Skip, so nothing visibly happens on the machine either.
        let mut h = Harness::new("[response]\ndry_run = false\npower_action = \"none\"\n");
        h.core.armed = true;
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];

        let (tx, rx) = sync_channel::<StreamEvent>(4);
        assert!(matches!(h.subscribe(root(), tx), Reply::Ok));

        h.core
            .on_sensor_event(added(Some(UsbId::new(0x0781, 0x5567))));

        for _ in 0..50 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(!seen.lock().unwrap()[0].dry_run);

        let mut saw_would_kill = false;
        while let Ok(se) = rx.try_recv() {
            if matches!(se.event, Event::WouldKill(_)) {
                saw_would_kill = true;
            }
        }
        assert!(
            saw_would_kill,
            "power_action = none must also broadcast WouldKill, not go silent"
        );
    }

    #[test]
    fn armed_real_kill_does_not_broadcast_would_kill() {
        // The mirror case: dry_run = false AND power_action != none is a
        // genuine kill, not a silent belt, and must NOT also be reported as a
        // would-kill — that would misdescribe a real dispatch as hypothetical.
        let mut h = Harness::new("[response]\ndry_run = false\npower_action = \"poweroff\"\n");
        h.core.armed = true;
        h.core.responders.clear(); // don't actually attempt a poweroff in a test

        let (tx, rx) = sync_channel::<StreamEvent>(4);
        assert!(matches!(h.subscribe(root(), tx), Reply::Ok));

        h.core
            .on_sensor_event(added(Some(UsbId::new(0x0781, 0x5567))));

        let mut saw_would_kill = false;
        while let Ok(se) = rx.try_recv() {
            if matches!(se.event, Event::WouldKill(_)) {
                saw_would_kill = true;
            }
        }
        assert!(
            !saw_would_kill,
            "a real kill must not also be reported as a would-kill"
        );
    }

    #[test]
    fn armed_kill_with_power_none_but_luks_destroy_engaged_does_not_broadcast_would_kill() {
        // `power = "none"` alone is a silent belt (test above). But with LUKS
        // destruction engaged the Action carries `luks_destroy: true` and the
        // LUKS responder acts on it for real — the kill is no longer
        // hypothetical, so it must NOT be announced as a would-kill (a latent
        // trap once the wipe stops being a stub — invariant 3).
        let mut h = Harness::new(
            "[response]\ndry_run = false\npower_action = \"none\"\n\
             [response.luks_destroy]\ni_understand_this_is_irreversible = true\n\
             target_header = \"/dev/nvme0n1p3\"\n",
        );
        h.core.armed = true;
        h.core.responders.clear();
        let (tx, _rx0) = sync_channel::<Reply>(1);
        h.core.set_luks_destroy_engaged(true, root(), tx);
        assert!(h.core.luks_destroy_engaged);

        let (tx, rx) = sync_channel::<StreamEvent>(8);
        assert!(matches!(h.subscribe(root(), tx), Reply::Ok));

        h.core
            .on_sensor_event(added(Some(UsbId::new(0x0781, 0x5567))));

        let mut saw_would_kill = false;
        while let Ok(se) = rx.try_recv() {
            if matches!(se.event, Event::WouldKill(_)) {
                saw_would_kill = true;
            }
        }
        assert!(
            !saw_would_kill,
            "a kill that runs the LUKS responder for real is not a would-kill"
        );
    }

    #[test]
    fn reload_of_an_invalid_file_keeps_the_running_config_and_armed_state() {
        let mut h = Harness::new("");
        h.core.sensor_ok = true;
        h.core.armed = true;

        std::fs::write(&h.path, "[detection]\nsensors = []\n").unwrap();
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.reload(tx);
        h.pump_writer();

        assert!(matches!(rx.try_recv().unwrap(), Reply::Error(_)));
        assert!(
            h.core.armed,
            "an invalid reload must not disarm (invariant 5)"
        );
        assert!(h.core.config_error.is_none(), "old valid config kept");
    }

    #[test]
    fn dry_run_reports_unknown_connected_devices() {
        let mut h = Harness::new("[[whitelist]]\nid = \"1050:0407\"\n");
        h.core
            .on_sensor_event(added(Some(UsbId::new(0x1050, 0x0407)))); // whitelisted
        h.core
            .on_sensor_event(added(Some(UsbId::new(0x0781, 0x5567)))); // stranger
        h.core.on_sensor_event(added(None)); // unidentified

        match h.core.run_dry_run() {
            Reply::DryRun(reasons) => {
                assert_eq!(reasons.len(), 2);
                assert!(reasons
                    .iter()
                    .any(|r| matches!(r, KillReason::UnknownDevice { .. })));
                assert!(reasons
                    .iter()
                    .any(|r| matches!(r, KillReason::UnidentifiedDevice)));
            }
            other => panic!("expected DryRun, got {other:?}"),
        }
    }

    #[test]
    fn an_unauthorized_event_dispatches_only_while_armed() {
        // power_action = none: the decision fires but attempts_power() is false,
        // so KILL_IN_FLIGHT is never set and no poweroff syscall is attempted.
        let mut h = Harness::new("[response]\npower_action = \"none\"\n");
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];

        h.core
            .on_sensor_event(added(Some(UsbId::new(0x0781, 0x5567))));
        assert!(seen.lock().unwrap().is_empty(), "disarmed: no dispatch");

        h.core.armed = true;
        h.core
            .on_sensor_event(added(Some(UsbId::new(0x0781, 0x5567))));
        for _ in 0..50 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen.lock().unwrap().len(), 1, "armed: dispatched once");
        assert_eq!(seen.lock().unwrap()[0].power, PowerAction::None);
    }

    #[test]
    fn on_sensor_gap_kill_dispatches_when_armed() {
        let mut h = Harness::new("[response]\npower_action = \"none\"\non_sensor_gap = \"kill\"\n");
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];
        h.core.armed = true;

        h.core.on_sensor_lost();
        for _ in 0..50 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(seen.lock().unwrap()[0].reason, KillReason::SensorGap);
        assert!(h.core.events_lost);

        // Sticky: a second gap does not dispatch again.
        h.core.on_sensor_lost();
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn on_sensor_gap_warn_only_marks_status() {
        let mut h = Harness::new(""); // default on_sensor_gap = warn
        h.core.on_sensor_lost();
        assert!(h.core.events_lost);
        assert!(h.core.status().events_lost);
        // and it blocks arming
        h.core.sensor_ok = true;
        assert!(h.core.arm(root()).unwrap_err().contains("lost events"));
    }

    #[test]
    fn a_gap_under_kill_does_not_dispatch_while_disarmed() {
        // Rejection case: on_sensor_gap = kill but disarmed → no kill, for both
        // gap handlers.
        for drive in ["lost", "restart"] {
            let mut h =
                Harness::new("[response]\npower_action = \"none\"\non_sensor_gap = \"kill\"\n");
            let seen = Arc::new(Mutex::new(Vec::new()));
            h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];
            // h.core.armed stays false

            match drive {
                "lost" => h.core.on_sensor_lost(),
                _ => h.core.on_sensor_restarting(),
            }
            std::thread::sleep(Duration::from_millis(30));
            assert!(
                seen.lock().unwrap().is_empty(),
                "{drive}: disarmed must not dispatch"
            );
            assert!(!h.core.gap_kill_dispatched);
        }
    }

    #[test]
    fn a_gap_that_did_not_dispatch_still_kills_on_a_later_gap() {
        // M-A: an early gap that recorded `events_lost` without dispatching (it
        // was disarmed, or `warn`) must not let the sticky flag swallow a later
        // gap that does warrant a kill.
        let mut h = Harness::new("[response]\npower_action = \"none\"\non_sensor_gap = \"kill\"\n");
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];

        h.core.on_sensor_lost(); // disarmed: records events_lost, dispatches nothing
        assert!(h.core.events_lost);
        assert!(seen.lock().unwrap().is_empty());
        assert!(!h.core.gap_kill_dispatched);

        h.core.armed = true;
        h.core.on_sensor_lost(); // events_lost already set — must still fire
        for _ in 0..50 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen.lock().unwrap().len(), 1, "the later gap must fire");
        assert!(h.core.gap_kill_dispatched);
    }

    #[test]
    fn a_config_swap_re_enables_the_gap_kill() {
        // After a gap kill, an operator config change re-arms the latch so the
        // next gap (e.g. now that dry_run is off) fires again.
        let mut h = Harness::new("[response]\npower_action = \"none\"\non_sensor_gap = \"kill\"\n");
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];
        h.core.armed = true;

        h.core.on_sensor_lost();
        for _ in 0..50 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(h.core.gap_kill_dispatched);

        let raw = h.core.raw.clone();
        let cfg = config::validate(raw.clone()).unwrap();
        h.core.swap_config(raw, cfg, "test");
        assert!(
            !h.core.gap_kill_dispatched,
            "a config swap clears the latch"
        );
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];

        h.core.on_sensor_lost();
        for _ in 0..50 {
            if seen.lock().unwrap().len() == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            seen.lock().unwrap().len(),
            2,
            "the post-swap gap fires again"
        );
    }

    #[test]
    fn subscribers_get_device_events_and_dead_ones_are_pruned() {
        let mut h = Harness::new("");
        let (tx, rx) = sync_channel::<StreamEvent>(8);
        assert!(matches!(h.subscribe(root(), tx), Reply::Ok));
        h.core
            .on_sensor_event(added(Some(UsbId::new(0x1050, 0x0407))));
        assert!(matches!(rx.recv().unwrap().event, Event::DeviceAdded(_)));

        drop(rx);
        h.core
            .on_sensor_event(added(Some(UsbId::new(0x1050, 0x0407))));
        assert!(h.core.subscribers.is_empty(), "dropped subscriber pruned");
    }

    #[test]
    fn status_reflects_core_state() {
        let mut h = Harness::new("[[whitelist]]\nid = \"1050:0407\"\n");
        h.core.sensor_ok = true;
        h.core
            .on_sensor_event(added(Some(UsbId::new(0x1050, 0x0407))));

        let s = h.core.status();
        assert!(!s.armed);
        assert!(s.sensor_ok);
        assert!(!s.events_lost);
        assert!(!s.config_stale);
        assert_eq!(s.whitelist_len, 1);
        assert_eq!(s.device_count, 1);
        assert!(s.config_error.is_none());
    }

    #[test]
    fn a_synthetic_uevent_never_fires_but_is_recorded() {
        let mut h = Harness::new("[response]\npower_action = \"none\"\n");
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];
        h.core.armed = true;

        // A `udevadm trigger` re-broadcast of an unknown device: no dispatch...
        h.core
            .on_sensor_event(synthetic_added(Some(UsbId::new(0x0781, 0x5567))));
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            seen.lock().unwrap().is_empty(),
            "synthetic event must not fire"
        );
        // ...but its identity is tracked.
        assert_eq!(h.core.devices.connected.len(), 1);

        // A real event for the same stranger still fires.
        h.core
            .on_sensor_event(added(Some(UsbId::new(0x0781, 0x5567))));
        for _ in 0..50 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_synthetic_remove_still_fires() {
        // The SYNTH_UUID suppression is for re-announced *present* devices; a
        // synthetic removal has no such cover and unplugging must still fire.
        let mut h = Harness::new(
            "[[whitelist]]\nid = \"1050:0407\"\n[response]\npower_action = \"none\"\n",
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];
        h.core.armed = true;
        // Whitelisted add: recorded, no dispatch.
        h.core
            .on_sensor_event(added(Some(UsbId::new(0x1050, 0x0407))));
        assert!(
            seen.lock().unwrap().is_empty(),
            "whitelisted add must not fire"
        );

        h.core
            .on_sensor_event(synthetic_removed(Some(UsbId::new(0x1050, 0x0407))));
        for _ in 0..50 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "a synthetic remove must fire"
        );
    }

    #[test]
    fn sensor_restarting_marks_not_ok_and_keeps_armed_under_warn() {
        let mut h = Harness::new("[response]\npower_action = \"none\"\n");
        h.core.sensor_ok = true;
        h.core.config.sensors.clear();
        h.core.responders.clear();
        h.core.arm(root()).unwrap();

        h.core.on_sensor_restarting();
        assert!(!h.core.sensor_ok);
        assert!(
            h.core.armed,
            "a sensor restart must not disarm (invariant 5)"
        );
        assert!(
            h.core.events_lost,
            "a restart is a gap and must be recorded (invariant 7)"
        );

        // The replacement announces itself: the socket is back, but the gap is
        // sticky — sensor_ok recovers, events_lost does not.
        h.core.on_sensor_started();
        assert!(h.core.sensor_ok);
        assert!(h.core.events_lost, "the gap does not heal itself");
    }

    #[test]
    fn a_sensor_restart_blocks_re_arming_until_the_daemon_restarts() {
        let mut h = Harness::new("[response]\npower_action = \"none\"\n");
        h.core.sensor_ok = true;
        h.core.config.sensors.clear();
        h.core.responders.clear();

        h.core.on_sensor_restarting();
        h.core.on_sensor_started(); // socket back
        assert!(h.core.sensor_ok);

        // arm() gates on events_lost, so a restart is enough to refuse it.
        assert!(h.core.arm(root()).unwrap_err().contains("lost events"));
        assert!(h.core.status().events_lost);
    }

    #[test]
    fn a_sensor_restart_clears_a_pending_boot_arm() {
        let mut h = Harness::new("[general]\narmed_at_boot = true\n");
        h.core.config.sensors.clear();
        h.core.responders.clear();
        h.core.boot_arm_pending = true;

        h.core.on_sensor_restarting();
        assert!(
            !h.core.boot_arm_pending,
            "the boot arm must not survive a gap"
        );

        // A late SensorStarted must NOT complete it now.
        h.core.on_sensor_started();
        assert!(!h.core.armed, "no auto-arm after a gap");
    }

    #[test]
    fn a_sensor_restart_reaches_subscribers() {
        let mut h = Harness::new("");
        let (tx, rx) = sync_channel::<StreamEvent>(8);
        assert!(matches!(h.subscribe(root(), tx), Reply::Ok));

        h.core.on_sensor_restarting();

        let mut got = Vec::new();
        while let Ok(se) = rx.try_recv() {
            got.push(se.event);
        }
        assert!(got.iter().any(|e| matches!(e, Event::SensorStopped)));
        assert!(got.iter().any(|e| matches!(e, Event::EventsLost)));
    }

    #[test]
    fn boot_arm_after_settle_decision_table() {
        use BootArm::*;
        assert_eq!(boot_arm_after_settle(false, false, false), NotRequested);
        assert_eq!(boot_arm_after_settle(false, true, true), NotRequested);
        assert_eq!(boot_arm_after_settle(true, false, true), Now);
        assert_eq!(boot_arm_after_settle(true, false, false), WhenSensorStarts);
        assert_eq!(boot_arm_after_settle(true, true, true), RefuseGap);
        assert_eq!(boot_arm_after_settle(true, true, false), RefuseGap);
    }

    #[test]
    fn sensor_restarting_dispatches_under_kill_when_armed() {
        let mut h = Harness::new("[response]\npower_action = \"none\"\non_sensor_gap = \"kill\"\n");
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.core.responders = vec![Arc::new(Recorder(Arc::clone(&seen))) as Arc<dyn Responder>];
        h.core.armed = true;

        h.core.on_sensor_restarting();
        for _ in 0..50 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(seen.lock().unwrap()[0].reason, KillReason::SensorGap);
        assert!(
            !seen.lock().unwrap()[0].luks_destroy,
            "a gap never asserts luks_destroy"
        );
    }

    #[test]
    fn a_rejected_reload_marks_config_stale_and_a_good_one_clears_it() {
        let mut h = Harness::new("");

        std::fs::write(&h.path, "[detection]\nsensors = []\n").unwrap();
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.reload(tx);
        h.pump_writer();
        assert!(matches!(rx.try_recv().unwrap(), Reply::Error(_)));
        assert!(h.core.config_stale, "a rejected reload is surfaced");
        assert!(h.core.status().config_stale);

        std::fs::write(&h.path, "[[whitelist]]\nid = \"1050:0407\"\n").unwrap();
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.reload(tx);
        h.pump_writer();
        assert!(matches!(rx.try_recv().unwrap(), Reply::Ok));
        assert!(!h.core.config_stale, "a good reload clears the flag");
    }

    #[test]
    fn whitelist_remove_of_an_absent_id_is_an_error_and_writes_nothing() {
        let mut h = Harness::new("");
        let (tx, rx) = sync_channel::<Reply>(1);
        h.core.whitelist_remove(UsbId::new(0x1050, 0x0407), tx);
        assert!(matches!(rx.try_recv().unwrap(), Reply::Error(_)));
        assert!(h.jobs.try_recv().is_err(), "no write job was queued");
    }

    #[test]
    fn a_boot_arm_is_retried_when_the_sensor_starts_late() {
        let mut h = Harness::new("[general]\narmed_at_boot = true\n");
        h.core.config.sensors.clear();
        h.core.responders.clear();
        h.core.boot_arm_pending = true;

        // Sensor not up yet: no arm.
        assert!(!h.core.armed);

        // The sensor announces itself after the settle window would have passed.
        h.core.on_sensor_started();
        assert!(
            h.core.armed,
            "a late sensor start still completes the boot arm"
        );
        assert!(!h.core.boot_arm_pending);
    }
}
