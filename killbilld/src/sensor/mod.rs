//! Seam 1 — sensors (charter §6, build step 5).
//!
//! A sensor watches the outside world and emits normalized [`SensorEvent`]s on
//! a channel. It knows nothing about policy or responders. v1 has exactly one,
//! [`UsbNetlinkSensor`], which reads USB add/remove uevents from the kernel's
//! netlink broadcast socket; the pure byte parser behind it lives in
//! [`uevent`](self::uevent).
//!
//! ## Shape: one thread, not an async task
//!
//! Like the responders ([`crate::responder`]), the sensor is plain synchronous
//! code on a dedicated [`std::thread`]. The whole sensor *is* one blocking
//! `recv` loop, and a thread with a receive timeout expresses that directly
//! without adding an async runtime for a single loop. It also keeps the daemon
//! on one concurrency model — `std::thread` + channels — end to end. Charter
//! §13.1 leaves this choice open and explicitly permits the no-async route.
//!
//! ## Failing loud (invariant 7)
//!
//! A sensor must never let a parse failure or a dead socket quietly become "no
//! devices seen" — which reads as "nothing is plugged in", which reads as "no
//! threat". Concretely:
//!
//! * [`uevent::parse_uevent`] returns `Err` for bytes it cannot understand; the
//!   run loop logs every one at `error!` and keeps listening.
//! * A datagram that *is* a USB device add/remove but carries no readable id
//!   becomes a [`SensorEvent`] with `usb_id: None`. The policy engine turns
//!   that into a kill (`KillReason::UnidentifiedDevice`) — it is never dropped.
//! * An unrecoverable socket error ends [`Sensor::run`] with `Err`. [`spawn`]
//!   logs it; the daemon surfaces it rather than spinning on a broken fd.
//! * [`Sensor::preflight`] actually opens the socket, so arming fails loudly
//!   (invariant 2) on a host where the daemon cannot watch USB at all.

mod netlink;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod uevent;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;

use killbill_proto::SensorEvent;

pub use netlink::UsbNetlinkSensor;

/// What a running sensor sends to the daemon core.
///
/// A plain [`SensorEvent`] channel would not be enough: the daemon has to know
/// when the sensor is actually watching (so it does not arm blind, invariant 2)
/// and when the kernel has dropped events (so it does not stay armed pretending
/// it can still see everything, invariant 7).
pub enum SensorMessage {
    /// The sensor opened its source and is now watching. Sent exactly once,
    /// before any [`Event`](Self::Event).
    Started,
    /// A normalized device add/remove.
    Event(SensorEvent),
    /// The kernel dropped one or more events (receive-buffer overflow). The
    /// daemon can no longer fully account for the device set.
    EventsLost,
}

/// A pluggable event source (charter glossary: "Sensor").
///
/// Implementors run one blocking loop on their own thread (see [`spawn`]) and
/// must obey invariant 7: never return `Ok` while silently seeing nothing on a
/// source they cannot actually read.
pub trait Sensor: Send + 'static {
    /// Stable identifier for logs and thread names. One word, kebab-case.
    fn name(&self) -> &'static str;

    /// Arm-path check (invariant 2): can this sensor actually observe events on
    /// this host right now? Open sockets and probe files freely — this is not
    /// the hot loop. Returning `Err` makes the daemon refuse to arm.
    fn preflight(&self) -> Result<(), SensorError>;

    /// Run the event loop, sending [`SensorMessage`]s on `out`, until `stop` is
    /// set or an unrecoverable error occurs.
    ///
    /// Must send [`SensorMessage::Started`] once the source is open, before any
    /// event. Blocks the calling thread. Returns `Ok(())` only on a clean stop
    /// (or once the receiver has hung up); any broken-source condition must come
    /// back as `Err`, never as a quiet `Ok`.
    fn run(&self, out: &Sender<SensorMessage>, stop: &StopFlag) -> Result<(), SensorError>;
}

/// A shared "please stop" flag handed to [`Sensor::run`]. Cloneable; every
/// clone observes the same bit.
#[derive(Clone, Default)]
pub struct StopFlag(Arc<AtomicBool>);

impl StopFlag {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the sensor loop to stop. Idempotent.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether [`stop`](Self::stop) has been called.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Something a sensor could not do. `thiserror` (library error); the sensor
/// loop's per-datagram parse failures are a separate, crate-private type in
/// [`uevent`](self::uevent) and never reach here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SensorError {
    /// The netlink uevent socket could not be created.
    #[error("could not open the netlink uevent socket: {0}")]
    OpenSocket(#[source] std::io::Error),
    /// The socket could not be bound to the kernel's uevent group (often a
    /// missing capability under a restrictive `CapabilityBoundingSet`).
    #[error("could not bind the netlink uevent socket to the kernel group: {0}")]
    BindSocket(#[source] std::io::Error),
    /// The receive timeout could not be set on the socket.
    #[error("could not configure the netlink uevent socket: {0}")]
    ConfigureSocket(#[source] std::io::Error),
    /// A `recv` on the socket failed with an error the loop cannot recover from.
    #[error("reading from the netlink uevent socket failed: {0}")]
    Recv(#[source] std::io::Error),
    /// The sensor thread panicked.
    #[error("the sensor thread panicked")]
    Panicked,
    /// This build has no USB sensor (non-Linux target).
    #[error("the USB sensor is only available on Linux")]
    UnsupportedPlatform,
}

/// Start `sensor` on its own thread.
///
/// Returns as soon as the thread is spawned. [`SensorMessage`]s flow on `out`
/// (an unbounded channel — a sensor event must never be dropped for
/// back-pressure, invariant 7); the returned [`SensorHandle`] stops the thread
/// on [`shutdown`](SensorHandle::shutdown) or drop.
///
/// This does **not** call [`Sensor::preflight`] — the sensor runs whether or
/// not the daemon is armed, so control clients can always see the device
/// stream. The arm path calls `preflight` separately.
pub fn spawn(sensor: Box<dyn Sensor>, out: Sender<SensorMessage>) -> std::io::Result<SensorHandle> {
    let stop = StopFlag::new();
    let stop_for_thread = stop.clone();
    let name = sensor.name();

    let join = std::thread::Builder::new()
        .name(format!("sensor:{name}"))
        .spawn(move || {
            let outcome = sensor.run(&out, &stop_for_thread);
            match &outcome {
                Ok(()) => tracing::debug!(sensor = name, "sensor stopped"),
                Err(err) => tracing::error!(sensor = name, %err, "sensor stopped with an error"),
            }
            outcome
        })?;

    Ok(SensorHandle {
        stop,
        join: Some(join),
    })
}

/// Handle to a running sensor thread. Dropping it stops and joins the thread.
pub struct SensorHandle {
    stop: StopFlag,
    join: Option<JoinHandle<Result<(), SensorError>>>,
}

impl SensorHandle {
    /// Signal the sensor to stop and block until its thread has finished,
    /// returning whatever [`Sensor::run`] returned — an `Err` means the sensor
    /// had already failed before the stop.
    pub fn shutdown(mut self) -> Result<(), SensorError> {
        self.stop.stop();
        join_thread(self.join.take())
    }

    /// Whether the sensor thread has exited already. While the daemon is
    /// running this should be `false`; `true` means the sensor hit a fatal
    /// error and the daemon should treat itself as no longer protecting.
    #[must_use]
    pub fn has_stopped(&self) -> bool {
        self.join.as_ref().is_some_and(JoinHandle::is_finished)
    }
}

impl Drop for SensorHandle {
    fn drop(&mut self) {
        self.stop.stop();
        let _ = join_thread(self.join.take());
    }
}

fn join_thread(join: Option<JoinHandle<Result<(), SensorError>>>) -> Result<(), SensorError> {
    match join {
        // A panicked sensor thread: the join payload is the panic value, which
        // we do not need — the loud record is the default panic hook's.
        Some(handle) => handle.join().unwrap_or(Err(SensorError::Panicked)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use killbill_proto::{DeviceIdentity, EventKind, SensorSource};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn an_event() -> SensorEvent {
        SensorEvent {
            source: SensorSource::Usb,
            kind: EventKind::Added,
            identity: DeviceIdentity::default(),
            raw: Default::default(),
        }
    }

    /// A sensor that announces `Started`, emits `count` events, then waits to
    /// be stopped.
    struct Fake {
        count: usize,
    }

    impl Sensor for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn preflight(&self) -> Result<(), SensorError> {
            Ok(())
        }
        fn run(&self, out: &Sender<SensorMessage>, stop: &StopFlag) -> Result<(), SensorError> {
            if out.send(SensorMessage::Started).is_err() {
                return Ok(());
            }
            for _ in 0..self.count {
                if out.send(SensorMessage::Event(an_event())).is_err() {
                    return Ok(());
                }
            }
            while !stop.should_stop() {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        }
    }

    /// A sensor that emits events as fast as it can until the send fails or it
    /// is stopped.
    struct Flood;
    impl Sensor for Flood {
        fn name(&self) -> &'static str {
            "flood"
        }
        fn preflight(&self) -> Result<(), SensorError> {
            Ok(())
        }
        fn run(&self, out: &Sender<SensorMessage>, stop: &StopFlag) -> Result<(), SensorError> {
            while !stop.should_stop() {
                if out.send(SensorMessage::Event(an_event())).is_err() {
                    return Ok(());
                }
            }
            Ok(())
        }
    }

    /// A sensor whose loop fails.
    struct Broken;
    impl Sensor for Broken {
        fn name(&self) -> &'static str {
            "broken"
        }
        fn preflight(&self) -> Result<(), SensorError> {
            Ok(())
        }
        fn run(&self, _out: &Sender<SensorMessage>, _stop: &StopFlag) -> Result<(), SensorError> {
            Err(SensorError::Recv(std::io::Error::other("socket died")))
        }
    }

    #[test]
    fn spawn_announces_started_then_delivers_events_then_stops_on_shutdown() {
        let (tx, rx) = mpsc::channel();
        let handle = spawn(Box::new(Fake { count: 3 }), tx).unwrap();

        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            SensorMessage::Started
        ));
        for _ in 0..3 {
            assert!(matches!(
                rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                SensorMessage::Event(_)
            ));
        }

        let start = Instant::now();
        handle.shutdown().unwrap();
        assert!(start.elapsed() < Duration::from_secs(2), "shutdown hung");
    }

    #[test]
    fn shutdown_surfaces_a_sensor_that_failed() {
        let (tx, _rx) = mpsc::channel();
        let handle = spawn(Box::new(Broken), tx).unwrap();

        let start = Instant::now();
        while !handle.has_stopped() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            handle.has_stopped(),
            "the failing sensor thread never exited"
        );
        assert!(matches!(handle.shutdown(), Err(SensorError::Recv(_))));
    }

    #[test]
    fn dropping_the_handle_stops_the_thread() {
        let (tx, rx) = mpsc::channel();
        let handle = spawn(Box::new(Fake { count: 0 }), tx).unwrap();
        drop(handle); // must not hang
        assert!(matches!(rx.recv(), Ok(SensorMessage::Started)));
        // The sender was moved into the thread; once it exits, the channel closes.
        assert!(rx.recv().is_err());
    }

    #[test]
    fn a_dead_receiver_ends_the_loop_cleanly() {
        let (tx, rx) = mpsc::channel();
        let handle = spawn(Box::new(Flood), tx).unwrap();
        drop(rx);
        // With the receiver gone, `run` returns Ok on the failed send — the
        // sensor stops on its own without needing the stop flag.
        assert!(handle.shutdown().is_ok());
    }
}
