//! [`UsbNetlinkSensor`] — the one v1 sensor: USB add/remove straight from the
//! kernel.
//!
//! It opens an `AF_NETLINK` / `NETLINK_KOBJECT_UEVENT` datagram socket, binds
//! the kernel's uevent multicast group, and loops: receive a datagram, check it
//! actually came from the kernel, hand the bytes to [`uevent::parse_uevent`],
//! send any resulting event on the channel. That is the whole sensor.
//!
//! **Why straight from the kernel, not libudev:** the kernel broadcasts uevents
//! on group 1 the instant a device changes. udev re-broadcasts an annotated
//! copy on group 2. Reading group 1 means the daemon sees device changes even
//! if `udevd` is stopped, slow, or has been tampered with — one less moving
//! part between a seizure and the kill decision.
//!
//! **Anti-forgery:** binding group 1 to *receive* kernel uevents needs no
//! capability (the group carries `NL_CFG_F_NONROOT_RECV`), which is good — it
//! means the daemon does not need `CAP_NET_ADMIN`, and *not* holding it is what
//! stops the daemon (or anything sharing its user) from *sending* on a
//! multicast group. Two further layers stop a local process forging a uevent by
//! unicasting it to our port:
//!
//! 1. After `bind`, we `connect` the socket to the kernel (port id 0). The
//!    socket is then `NETLINK_CONNECTED` with `dst_portid == 0`, so the kernel
//!    returns `ECONNREFUSED` to any other userspace process that tries to
//!    `sendto` our port. Multicast delivery from the kernel is unaffected.
//! 2. As defence in depth we still `recvfrom` and drop any datagram whose
//!    source port id is not 0 — the same check `systemd`'s device monitor
//!    makes — rate-limiting the log so the drop path cannot be used to flood
//!    the journal.
//!
//! **No `unsafe`:** every syscall here goes through `nix`'s safe wrappers, so
//! the crate keeps `#![deny(unsafe_code)]` with no local exception.

use std::sync::mpsc::Sender;

#[cfg(target_os = "linux")]
use super::uevent;
use super::{Sensor, SensorError, SensorMessage, StopFlag};

/// Reads USB add/remove uevents from the kernel netlink socket.
///
/// Holds no state: the socket is opened inside [`Sensor::run`] so it lives on
/// exactly the thread that reads it, and [`Sensor::preflight`] opens its own
/// throwaway socket to check the daemon can watch USB at all.
pub struct UsbNetlinkSensor;

impl UsbNetlinkSensor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for UsbNetlinkSensor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Linux: the real implementation.
// ---------------------------------------------------------------------------

/// Largest datagram we accept. A kernel uevent is assembled in a buffer of
/// `UEVENT_BUFFER_SIZE` (2048) plus a short summary line; 16 KiB is far more
/// than one can be, and small enough to sit on the stack.
#[cfg(target_os = "linux")]
const MAX_UEVENT_LEN: usize = 16 * 1024;

/// How long a blocking receive waits with no traffic before returning so the
/// loop can re-check the stop flag. Shutdown latency, nothing else.
#[cfg(target_os = "linux")]
const RECV_TIMEOUT_MS: i64 = 500;

/// Requested socket receive buffer. The kernel clamps this to
/// `net.core.rmem_max`; a large request makes a uevent flood far harder to use
/// to overflow the buffer and bury a real add/remove (see `on_sensor_gap`).
/// Plain `SO_RCVBUF` — `SO_RCVBUFFORCE` would need `CAP_NET_ADMIN`, which this
/// daemon deliberately does not hold.
#[cfg(target_os = "linux")]
const REQUESTED_RCVBUF: usize = 8 * 1024 * 1024;

/// The outcome of one receive.
#[cfg(target_os = "linux")]
enum Recv<'b> {
    /// A datagram from the kernel.
    Datagram(&'b [u8]),
    /// Timed out or interrupted. Try again.
    Idle,
    /// A datagram from a non-kernel source was dropped. Try again; `run`
    /// rate-limits the log so it cannot be used to flood the journal.
    Forged,
    /// The kernel's receive buffer overflowed — one or more events were lost.
    Lost,
}

/// How often at most `run` logs about dropped non-kernel datagrams.
#[cfg(target_os = "linux")]
const FORGED_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(target_os = "linux")]
struct NetlinkSocket {
    fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl NetlinkSocket {
    /// Open, bind the kernel uevent group, set the receive timeout, enlarge the
    /// receive buffer.
    fn open() -> Result<Self, SensorError> {
        use nix::sys::socket::{
            bind, connect, getsockopt, setsockopt, socket, sockopt, AddressFamily, NetlinkAddr,
            SockFlag, SockProtocol, SockType,
        };
        use nix::sys::time::{TimeVal, TimeValLike};
        use std::os::fd::AsRawFd;

        let fd = socket(
            AddressFamily::Netlink,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkKObjectUEvent,
        )
        .map_err(|e| SensorError::OpenSocket(e.into()))?;

        // nl_groups is a bitmask. Bit 0 (value 1) is the kernel's own uevent
        // group; bit 1 (value 2) is udev's libudev-framed re-broadcast, which
        // we deliberately do not join (see the module docs). pid 0 lets the
        // kernel assign the port id.
        let addr = NetlinkAddr::new(0, 1);
        bind(fd.as_raw_fd(), &addr).map_err(|e| SensorError::BindSocket(e.into()))?;

        // Connect to the kernel (port id 0). This puts the socket in
        // NETLINK_CONNECTED with dst_portid 0, so the kernel refuses unicast
        // datagrams sent to our port from any *other* userspace process
        // (`netlink_getsockbyportid` returns ECONNREFUSED to them). Without it,
        // a local unprivileged process can read our port id from
        // /proc/net/netlink and flood us with forged datagrams to bury a real
        // add/remove under an ENOBUFS gap. Multicast group-1 delivery from the
        // kernel is unaffected by connect. The `recvfrom` source check below is
        // kept as defence in depth.
        connect(fd.as_raw_fd(), &NetlinkAddr::new(0, 0))
            .map_err(|e| SensorError::ConfigureSocket(e.into()))?;

        // SO_RCVTIMEO: with no traffic, a blocking receive returns EAGAIN after
        // this long, which is how `run`'s loop gets back to its stop check.
        setsockopt(
            &fd,
            sockopt::ReceiveTimeout,
            &TimeVal::milliseconds(RECV_TIMEOUT_MS),
        )
        .map_err(|e| SensorError::ConfigureSocket(e.into()))?;

        // Best effort: a bigger receive buffer. Failure is not fatal — the
        // socket still works at the default size — but it is worth a warning.
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &REQUESTED_RCVBUF) {
            tracing::warn!(error = %e, "could not enlarge the netlink receive buffer");
        }
        // Report the size we actually got. `SO_RCVBUF` is clamped to
        // `net.core.rmem_max` (often ~208 KiB on a stock kernel), far below the
        // request; the `on_sensor_gap` machinery exists because of this buffer,
        // so the effective size is worth knowing. The kernel returns double the
        // real value (accounting overhead).
        match getsockopt(&fd, sockopt::RcvBuf) {
            Ok(bytes) if bytes / 2 < REQUESTED_RCVBUF => tracing::info!(
                effective_bytes = bytes / 2,
                requested_bytes = REQUESTED_RCVBUF,
                "netlink receive buffer is smaller than requested — raise net.core.rmem_max to \
                 harden against a uevent flood"
            ),
            Ok(bytes) => tracing::info!(effective_bytes = bytes / 2, "netlink receive buffer"),
            Err(e) => {
                tracing::warn!(error = %e, "could not read back the netlink receive buffer size")
            }
        }

        Ok(Self { fd })
    }

    /// Receive one datagram, or an [`Recv`] outcome the loop handles. A lost
    /// event ([`Recv::Lost`]) or an unparseable one is surfaced by `run` as
    /// `EventsLost` (invariant 7 — never a silent loss).
    fn recv_one<'b>(&self, buf: &'b mut [u8]) -> Result<Recv<'b>, SensorError> {
        use nix::errno::Errno;
        use nix::sys::socket::{recvfrom, NetlinkAddr};
        use std::os::fd::AsRawFd;

        match recvfrom::<NetlinkAddr>(self.fd.as_raw_fd(), buf) {
            Ok((len, from)) => {
                // Only the kernel (port id 0) may originate a uevent here. A
                // datagram from any userspace peer is forged. `connect()` in
                // `open` should already stop these arriving; this is the
                // belt-and-suspenders drop, rate-limited in `run`.
                match from {
                    Some(addr) if addr.pid() == 0 => {}
                    _ => return Ok(Recv::Forged),
                }
                if len > buf.len() {
                    // recvfrom cannot pass MSG_TRUNC, so `len` is already
                    // clamped; this branch is unreachable in practice but keeps
                    // the intent explicit.
                    tracing::error!(
                        len,
                        capacity = buf.len(),
                        "oversized uevent datagram; ignored"
                    );
                    return Ok(Recv::Idle);
                }
                Ok(Recv::Datagram(&buf[..len]))
            }
            Err(Errno::EAGAIN | Errno::EINTR) => Ok(Recv::Idle),
            Err(Errno::ENOBUFS) => {
                tracing::error!(
                    "netlink receive buffer overflowed — one or more USB events were lost"
                );
                Ok(Recv::Lost)
            }
            Err(e) => Err(SensorError::Recv(e.into())),
        }
    }
}

#[cfg(target_os = "linux")]
impl Sensor for UsbNetlinkSensor {
    fn name(&self) -> &'static str {
        "usb-netlink"
    }

    fn preflight(&self) -> Result<(), SensorError> {
        // Actually open and bind. This catches a seccomp filter, a network
        // namespace with no netlink, or a kernel without `CONFIG_NET` — any of
        // which must fail the arm (invariant 2), not first surface as silence
        // when a device is plugged in.
        NetlinkSocket::open().map(drop)
    }

    fn run(&self, out: &Sender<SensorMessage>, stop: &StopFlag) -> Result<(), SensorError> {
        use std::time::Instant;

        let socket = NetlinkSocket::open()?;
        if out.send(SensorMessage::Started).is_err() {
            return Ok(());
        }

        let mut buf = [0u8; MAX_UEVENT_LEN];
        let mut forged_seen: u64 = 0;
        let mut forged_reported: Option<Instant> = None;

        while !stop.should_stop() {
            let payload = match socket.recv_one(&mut buf)? {
                Recv::Datagram(payload) => payload,
                Recv::Idle => continue,
                Recv::Forged => {
                    forged_seen += 1;
                    if forged_reported.is_none_or(|t| t.elapsed() >= FORGED_LOG_INTERVAL) {
                        tracing::error!(
                            total = forged_seen,
                            "dropping non-kernel datagrams on the uevent socket — a local process \
                             is writing to it (ignored: connect() and the source check reject them)"
                        );
                        forged_reported = Some(Instant::now());
                    }
                    continue;
                }
                Recv::Lost => {
                    if out.send(SensorMessage::EventsLost).is_err() {
                        return Ok(());
                    }
                    continue;
                }
            };
            match uevent::parse_uevent(payload) {
                Ok(Some(event)) => {
                    if out.send(SensorMessage::Event(event)).is_err() {
                        // The core dropped its receiver: the daemon is shutting
                        // down. Not an error.
                        return Ok(());
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    // Invariant 7: a datagram we cannot parse might have *been*
                    // a device add/remove. Same epistemic state as a receive
                    // buffer overflow — surface it as lost events, not a silent
                    // drop. `on_sensor_lost` is sticky, so a stream of garbage
                    // reports once.
                    tracing::error!(%err, "could not parse a uevent — reporting lost events");
                    if out.send(SensorMessage::EventsLost).is_err() {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Everything else: a stub that refuses, so the crate builds and tests anywhere.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
impl Sensor for UsbNetlinkSensor {
    fn name(&self) -> &'static str {
        "usb-netlink"
    }

    fn preflight(&self) -> Result<(), SensorError> {
        Err(SensorError::UnsupportedPlatform)
    }

    fn run(&self, _out: &Sender<SensorMessage>, _stop: &StopFlag) -> Result<(), SensorError> {
        Err(SensorError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_stable() {
        assert_eq!(UsbNetlinkSensor::new().name(), "usb-netlink");
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn non_linux_refuses_to_arm_and_refuses_to_run() {
        let sensor = UsbNetlinkSensor::new();
        assert!(matches!(
            sensor.preflight(),
            Err(SensorError::UnsupportedPlatform)
        ));
        let (tx, _rx) = std::sync::mpsc::channel();
        assert!(matches!(
            sensor.run(&tx, &StopFlag::new()),
            Err(SensorError::UnsupportedPlatform)
        ));
    }

    // The Linux socket path — open/bind on NETLINK_KOBJECT_UEVENT group 1, the
    // `SO_RCVBUF` bump, `recvfrom`, and the drop of any datagram whose source
    // `pid != 0` — is not unit-tested: it needs a real kernel and a physical
    // plug/unplug. Manual check, with the daemon running as root under systemd
    // (or `sudo target/debug/killbilld --config config.example.toml`), observed
    // via `killbillctl events` in another terminal and the daemon's journal:
    //
    //   1. `killbillctl events` — expect `+ device <id>` / `- device <id>` lines,
    //      one per plug/unplug, with the right vendor:product.
    //   2. The journal shows the sensor "is watching" line before any event, and
    //      an `events_lost` warning if the receive buffer ever overflows.
    //   3. `udevadm trigger` while it runs: those uevents carry `SYNTH_UUID`, so
    //      the journal notes "NOT acting" for a synthetic add and `killbillctl
    //      devices` still lists the device.
    //
    // The pure parser this loop feeds is covered exhaustively in `uevent.rs`.
}
