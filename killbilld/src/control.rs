//! The control server: one `SOCK_SEQPACKET` Unix socket (charter §8).
//!
//! `killbillctl` and the TUI connect here. Three kinds of traffic:
//!
//! * a **[`Command`]** → the daemon answers with one **[`Reply`]**, then the
//!   connection closes;
//! * a **[`Command::Subscribe`]** → the daemon streams **[`Event`]s** on the
//!   connection until it closes.
//!
//! Framing is the length-prefixed JSON codec in [`killbill_proto`]. Over
//! `SOCK_SEQPACKET` each `write` is one datagram and each `read` returns exactly
//! one, so a whole message lands in a single read — the length prefix is
//! belt-and-suspenders (and keeps the codec testable off-socket).
//!
//! ## Isolation from the core
//!
//! Connection threads never touch daemon state. Each one reads its peer's
//! credentials, turns its request into a [`ControlRequest`], and hands it to the
//! single core thread over a channel; the core is the one authority (charter
//! §6). A slow or hostile client can stall only its own thread.
//!
//! ## Access control
//!
//! Two layers:
//!
//! * the socket file is mode `0660`, owned `root:root` — "who may connect" is a
//!   filesystem question (charter §8);
//! * every command except the read-only queries `GetStatus` / `ListDevices` /
//!   `WhitelistList` — including `Subscribe`, whose stream carries device ids
//!   and arm transitions — requires `uid == 0` on the connecting peer
//!   ([`PeerCred`] via `SO_PEERCRED`), so a misconfigured group or a non-root
//!   unit still cannot arm/disarm/rewrite config or watch the event stream.
//!   The check runs in the connection thread ([`Command::requires_root`]) so a
//!   denied request never touches the core; the core re-checks as defence in
//!   depth.
//!
//! Under the shipped `0660 root:root` mode the read-only tier is in fact
//! *unreachable* — a process that is neither uid 0 nor in group 0 cannot
//! `connect`. It is kept as a deliberate seam: if the socket's group is ever
//! loosened, that must not also hand out `Arm`/`Disarm`/config rewrites. See
//! [`Command::requires_root`].
//!
//! Concurrent connections are capped ([`MAX_CONNECTIONS`]): a root client that
//! opens many at once cannot pile core-thread work in front of a USB event.
//!
//! The socket is created with a restrictive `umask` and its mode is set
//! **before** `listen`, so there is no window in which it is both connectable
//! and permissive. A leftover socket at the path is unlinked only when a probe
//! connect proves nothing is listening (`ECONNREFUSED`); a live daemon's socket
//! — or any socket the probe cannot make sense of — aborts startup instead.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Sender, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use killbill_proto::{decode, encode, Command, Event, Reply, MAX_CONTROL_FRAME};

use crate::StopFlag;

/// The credentials of a connected control client.
#[derive(Debug, Clone, Copy)]
pub struct PeerCred {
    pub uid: u32,
    pub pid: i32,
    pub gid: u32,
}

impl PeerCred {
    /// The daemon itself (used for `armed_at_boot`) — always trusted.
    pub const SYSTEM: Self = Self {
        uid: 0,
        pid: 0,
        gid: 0,
    };

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

/// What a connection thread asks the daemon core to do.
pub enum ControlRequest {
    /// A one-shot command from `peer`. The core answers on `reply`.
    Command {
        cmd: Command,
        peer: PeerCred,
        reply: SyncSender<Reply>,
    },
    /// An event subscription from `peer`. The core answers `ack` (Ok, or an
    /// Error if refused) and then pushes [`Event`]s on `events` (lossily,
    /// dropping on a full or dead channel) until it goes away.
    Subscribe {
        peer: PeerCred,
        events: SyncSender<Event>,
        ack: SyncSender<Reply>,
    },
}

/// How long `serve` blocks in `accept` before re-checking the stop flag.
const ACCEPT_POLL: Duration = Duration::from_millis(200);

/// Most control connections alive at once. A root caller opening more than this
/// — a buggy client in a reconnect loop, say — is refused rather than allowed
/// to pile work onto the single core thread ahead of the next USB event.
const MAX_CONNECTIONS: usize = 32;

/// Depth of one subscriber's event queue before the core starts dropping events
/// for it. Generous for a UI that keeps up; a wedged client just misses events.
const SUBSCRIBER_QUEUE: usize = 256;

/// A client that connects and then neither sends nor reads is disconnected
/// after this long, rather than tying up a thread forever.
const CONN_TIMEOUT: Duration = Duration::from_secs(30);

/// Decrements the live-connection count on drop, so a panicking connection
/// thread cannot leak a slot. The control socket is the only way to disarm
/// (invariant 5) — a slowly leaking cap is a slow path to an un-disarmable
/// daemon.
struct ConnSlot(Arc<AtomicUsize>);

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve connections on an already-bound `listener` until `stop` is set. Runs on
/// the calling thread (the daemon spawns it). The listener is bound separately
/// with [`bind_listener`] so a bind failure is fatal to the daemon *before* it
/// starts its core loop — a daemon with no control socket can never be disarmed
/// (invariant 5). `socket_path` is used only for logging and shutdown cleanup.
pub fn serve(
    listener: UnixListener,
    socket_path: &Path,
    core: Sender<ControlRequest>,
    stop: StopFlag,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    tracing::info!(socket = %socket_path.display(), "control server listening");

    let live = Arc::new(AtomicUsize::new(0));

    while !stop.should_stop() {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    live.fetch_sub(1, Ordering::SeqCst);
                    tracing::warn!(
                        limit = MAX_CONNECTIONS,
                        "refusing a control connection — at the limit"
                    );
                    // The refusal is a courtesy, and the accept loop must never
                    // be able to block on a client: this loop is also what polls
                    // the stop flag, and the control socket is the only way to
                    // disarm (invariant 5). So force the socket non-blocking —
                    // `accept(2)` does NOT inherit O_NONBLOCK from the listener
                    // on Linux, so the accepted stream is blocking by default —
                    // and make exactly one attempt. The ~50-byte frame either
                    // fits the socket buffer immediately or the client, which is
                    // already misbehaving, gets a closed connection instead.
                    //
                    // A blocking write here, even a timed one, would let a peer
                    // that connects at the limit and never reads stall accept:
                    // an unprivileged DoS on the disarm path the moment the
                    // socket's group is loosened, which this design explicitly
                    // anticipates. Not worth a nicer error message.
                    if stream.set_nonblocking(true).is_ok() {
                        let _ = write_frame(
                            &mut stream,
                            &Reply::Error("too many control connections; try again".to_owned()),
                        );
                    }
                    continue;
                }
                // Held for the connection's lifetime; its `Drop` decrements
                // `live` even if `serve_connection` panics.
                let slot = ConnSlot(Arc::clone(&live));
                let core = core.clone();
                if let Err(e) = thread::Builder::new()
                    .name("control-conn".to_owned())
                    .spawn(move || {
                        let _slot = slot;
                        serve_connection(stream, &core);
                    })
                {
                    // `slot` moved into the failed closure and was dropped with
                    // it, so `live` is already back down — just log.
                    tracing::warn!(error = %e, "could not spawn a control connection thread");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(e) => {
                tracing::warn!(error = %e, "control socket accept failed");
                thread::sleep(ACCEPT_POLL);
            }
        }
    }

    remove_socket(socket_path);
    Ok(())
}

/// Remove `path` only if it is a socket. Safe to call on the operator-supplied
/// `--socket` path: a typo will not delete an arbitrary file.
pub fn remove_socket(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            let _ = std::fs::remove_file(path);
        }
        Ok(_) => tracing::warn!(
            path = %path.display(),
            "not removing it on shutdown — it is not a socket"
        ),
        Err(_) => {}
    }
}

/// Bind the control socket at `path` (charter §8: `SOCK_SEQPACKET`, mode 0660,
/// root-owned). Called on the daemon's main thread before the core loop starts:
/// any failure here — another daemon already listening, a stale non-socket file,
/// an unprobeable socket — is fatal, never a degraded run.
pub fn bind_listener(path: &Path) -> std::io::Result<UnixListener> {
    use nix::sys::socket::{
        bind, listen, socket, AddressFamily, Backlog, SockFlag, SockProtocol, SockType, UnixAddr,
    };
    use nix::sys::stat::{umask, Mode};

    ensure_path_is_free(path)?;

    let sock = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None::<SockProtocol>,
    )
    .map_err(std::io::Error::from)?;

    let addr = UnixAddr::new(path).map_err(std::io::Error::from)?;

    // Create the socket file with no group/other permissions from the start, so
    // it is never briefly world-anything. `bind` respects the umask.
    let previous_umask = umask(Mode::from_bits_truncate(0o177));
    let bind_result = bind(sock.as_raw_fd(), &addr).map_err(std::io::Error::from);
    umask(previous_umask);
    bind_result?;

    // charter §8: mode 0660, owned root:root. Set the mode *before* `listen` —
    // until `listen`, a `connect` gets ECONNREFUSED, so this closes the window
    // rather than shrinking it. `chown` is best effort (a non-root dev run
    // cannot, and does not need to).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    if let Err(e) = nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(0)),
    ) {
        tracing::warn!(error = %e, "could not chown the control socket to root:root");
    }

    listen(&sock, Backlog::MAXCONN).map_err(std::io::Error::from)?;
    Ok(UnixListener::from(sock))
}

/// Make sure nothing important is at `path`. A live daemon's socket → abort. A
/// stale socket (probe says `ECONNREFUSED`) → remove it. A non-socket, or a
/// socket the probe fails on for any other reason → refuse. Nothing there → fine.
fn ensure_path_is_free(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(meta) if !meta.file_type().is_socket() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists and is not a socket — refusing to touch it",
                    path.display()
                ),
            ));
        }
        Ok(_) => {}
    }

    // Something is at `path` and it *is* a socket. Probe it to tell a live
    // daemon from a leftover. We unlink only on a definitive "nothing is
    // listening" (`ECONNREFUSED`); every other probe outcome is ambiguous, so we
    // fail closed and refuse to start rather than risk unlinking a socket that
    // is in use (invariant 2).
    match probe_connect(path) {
        Ok(()) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!(
                "another killbilld is already listening at {} — refusing to start a second \
                 instance",
                path.display()
            ),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            // The socket is there but nothing is listening: a previous run left it.
            std::fs::remove_file(path)
        }
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!(
                "a socket already exists at {} and probing it failed ({e}) — refusing to \
                 start rather than unlink a socket that may be in use",
                path.display()
            ),
        )),
    }
}

fn probe_connect(path: &Path) -> std::io::Result<()> {
    use nix::sys::socket::{
        connect, socket, AddressFamily, SockFlag, SockProtocol, SockType, UnixAddr,
    };

    let sock = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None::<SockProtocol>,
    )
    .map_err(std::io::Error::from)?;
    let addr = UnixAddr::new(path).map_err(std::io::Error::from)?;
    connect(sock.as_raw_fd(), &addr).map_err(std::io::Error::from)
}

#[cfg(target_os = "linux")]
fn peer_cred(stream: &UnixStream) -> PeerCred {
    use nix::sys::socket::{getsockopt, sockopt};

    match getsockopt(stream, sockopt::PeerCredentials) {
        Ok(c) => PeerCred {
            uid: c.uid(),
            pid: c.pid(),
            gid: c.gid(),
        },
        Err(e) => {
            tracing::warn!(error = %e, "could not read control peer credentials; treating as untrusted");
            PeerCred {
                uid: u32::MAX,
                pid: 0,
                gid: u32::MAX,
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn peer_cred(_stream: &UnixStream) -> PeerCred {
    // Peer-credential auth (`SO_PEERCRED`) is Linux-only. A non-Linux daemon is
    // a dev-only build — the netlink sensor and poweroff are stubs — but it
    // still binds a real socket, so refuse rather than degrade: return a
    // credential that is definitively not root, so every privileged command is
    // denied (fail closed, invariant 2). The read-only queries still answer.
    PeerCred {
        uid: u32::MAX,
        pid: 0,
        gid: u32::MAX,
    }
}

fn serve_connection(mut stream: UnixStream, core: &Sender<ControlRequest>) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let _ = stream.set_read_timeout(Some(CONN_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONN_TIMEOUT));

    let peer = peer_cred(&stream);

    let cmd = match read_frame::<Command>(&mut stream) {
        Ok(Some(cmd)) => cmd,
        Ok(None) => return, // client closed without sending anything
        Err(e) => {
            let _ = write_frame(&mut stream, &Reply::Error(format!("bad request: {e}")));
            return;
        }
    };

    // Authorize in the connection thread so a denied command never reaches — or
    // delays — the single core thread. The core re-checks as defence in depth.
    if cmd.requires_root() && !peer.is_root() {
        tracing::warn!(
            peer_uid = peer.uid,
            peer_pid = peer.pid,
            "denied a privileged control command from a non-root peer"
        );
        let _ = write_frame(
            &mut stream,
            &Reply::Error(format!(
                "permission denied: this command requires uid 0 (peer uid {})",
                peer.uid
            )),
        );
        return;
    }

    if matches!(cmd, Command::Subscribe) {
        serve_subscription(stream, peer, core);
        return;
    }

    let (reply_tx, reply_rx) = sync_channel::<Reply>(1);
    if core
        .send(ControlRequest::Command {
            cmd,
            peer,
            reply: reply_tx,
        })
        .is_err()
    {
        let _ = write_frame(
            &mut stream,
            &Reply::Error("daemon is shutting down".to_owned()),
        );
        return;
    }

    let reply = reply_rx
        .recv()
        .unwrap_or_else(|_| Reply::Error("daemon dropped the request".to_owned()));
    if let Err(e) = write_frame(&mut stream, &reply) {
        if e.kind() == std::io::ErrorKind::InvalidData {
            // `encode` rejected the reply as over the frame limit (a huge
            // `Reply::Devices`, say). The client would otherwise just see the
            // connection close — send it a small error it can actually read.
            tracing::warn!(error = %e, "a control reply was too large to send");
            let _ = write_frame(
                &mut stream,
                &Reply::Error(
                    "the reply is too large to send over the control socket; narrow the request"
                        .to_owned(),
                ),
            );
        } else {
            // A broken pipe or a write timeout: the client is already gone,
            // nothing more to say to it.
            tracing::debug!(error = %e, "control reply write failed");
        }
    }
}

fn serve_subscription(mut stream: UnixStream, peer: PeerCred, core: &Sender<ControlRequest>) {
    let (events_tx, events_rx) = sync_channel::<Event>(SUBSCRIBER_QUEUE);
    let (ack_tx, ack_rx) = sync_channel::<Reply>(1);
    if core
        .send(ControlRequest::Subscribe {
            peer,
            events: events_tx,
            ack: ack_tx,
        })
        .is_err()
    {
        let _ = write_frame(
            &mut stream,
            &Reply::Error("daemon is shutting down".to_owned()),
        );
        return;
    }

    // The core answers the ack (Ok, or an Error if it refused the subscription)
    // before it registers the subscriber — write the real outcome, not an
    // optimistic Ok, so `killbillctl events` can tell "refused" from "no events".
    let ack = ack_rx
        .recv()
        .unwrap_or_else(|_| Reply::Error("daemon dropped the subscription".to_owned()));
    let accepted = matches!(ack, Reply::Ok);
    if write_frame(&mut stream, &ack).is_err() || !accepted {
        return;
    }

    // Forward events until the client disconnects (a write fails or times out)
    // or the core drops its sender (daemon shutdown / this subscriber pruned).
    for event in events_rx {
        if write_frame(&mut stream, &event).is_err() {
            break;
        }
    }
}

/// Read one length-prefixed frame. `Ok(None)` means the peer closed cleanly
/// before sending anything.
fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
) -> std::io::Result<Option<T>> {
    let mut buf = vec![0u8; MAX_CONTROL_FRAME];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    let (value, _consumed) = decode::<T>(&buf[..n])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(value))
}

fn write_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> std::io::Result<()> {
    let frame =
        encode(value).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // One `write` == one SEQPACKET datagram for our sub-kilobyte messages.
    stream.write_all(&frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("killbilld-control-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A bare `SOCK_SEQPACKET` listener at `path` — what a live daemon binds, but
    /// without `bind_listener`'s chmod/chown/`umask` steps. `umask` is
    /// process-global, so calling the real thing here would race the file
    /// creation in every other test running in parallel.
    fn seqpacket_listener(path: &Path) -> UnixListener {
        use nix::sys::socket::{
            bind, listen, socket, AddressFamily, Backlog, SockFlag, SockProtocol, SockType,
            UnixAddr,
        };
        let sock = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None::<SockProtocol>,
        )
        .unwrap();
        bind(sock.as_raw_fd(), &UnixAddr::new(path).unwrap()).unwrap();
        listen(&sock, Backlog::MAXCONN).unwrap();
        UnixListener::from(sock)
    }

    #[test]
    fn ensure_path_is_free_accepts_a_missing_path() {
        let dir = tmpdir("free-missing");
        assert!(ensure_path_is_free(&dir.join("nope.sock")).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_path_is_free_refuses_a_regular_file_and_leaves_it() {
        let dir = tmpdir("free-regular");
        let path = dir.join("not-a-socket");
        std::fs::write(&path, b"important").unwrap();

        let err = ensure_path_is_free(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"important",
            "file was touched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_path_is_free_removes_a_stale_socket() {
        let dir = tmpdir("free-stale");
        let path = dir.join("stale.sock");
        // Bind a listener, then drop it without unlinking: a stale socket file.
        {
            let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
            drop(l);
        }
        assert!(path.exists());
        assert!(ensure_path_is_free(&path).is_ok());
        assert!(!path.exists(), "stale socket was not removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_path_is_free_aborts_on_a_live_listener() {
        let dir = tmpdir("free-live");
        let path = dir.join("live.sock");
        // A real killbilld control socket — SOCK_SEQPACKET, exactly what a live
        // daemon binds — so the probe connects and startup must abort.
        let _listener = seqpacket_listener(&path);

        let err = ensure_path_is_free(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert!(path.exists(), "a live socket must not be removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_path_is_free_refuses_an_unprobeable_socket_and_leaves_it() {
        let dir = tmpdir("free-unprobeable");
        let path = dir.join("other.sock");
        // A SOCK_STREAM socket is not what killbilld speaks; a SEQPACKET connect
        // to it fails with something other than ECONNREFUSED. That is ambiguous
        // — maybe something is using it — so startup fails closed rather than
        // unlinking it (invariant 2).
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

        let err = ensure_path_is_free(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert!(path.exists(), "an in-use socket must not be removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_socket_refuses_a_non_socket() {
        let dir = tmpdir("rm-regular");
        let path = dir.join("regular");
        std::fs::write(&path, b"keep me").unwrap();
        remove_socket(&path);
        assert!(path.exists(), "remove_socket deleted a regular file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_socket_removes_a_socket() {
        let dir = tmpdir("rm-socket");
        let path = dir.join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener);
        remove_socket(&path);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn frames_round_trip_over_a_socketpair() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        write_frame(&mut a, &Command::Arm).unwrap();
        let got: Option<Command> = read_frame(&mut b).unwrap();
        assert_eq!(got, Some(Command::Arm));

        // A garbage datagram surfaces as an InvalidData error, not a panic.
        a.write_all(b"\x00\x00\x00\x02zz").unwrap();
        let err = read_frame::<Command>(&mut b).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
