//! Transport to the daemon's `SOCK_SEQPACKET` control socket.
//!
//! Two independent connections (plan §4):
//!
//! * the **command connection** — one fresh `SOCK_SEQPACKET` connection per
//!   [`ClientHandle::call`], matching the daemon's actual contract: each
//!   connection answers exactly one command, then the daemon closes it
//!   (`killbilld::control::serve_connection`). Reusing a connection across
//!   calls (the skeleton's original design) meant every second call failed —
//!   fixed here by never keeping one open.
//! * the **event connection** — a background thread ([`event_loop`]) that sends
//!   `Subscribe` and forwards each daemon-timestamped event onto an `mpsc`
//!   channel. It is the single authority on whether the daemon is reachable: it
//!   reconnects on its own and reports [`ClientMsg::Connected`] /
//!   [`ClientMsg::Disconnected`].
//!
//! Neither path caches daemon state. A dropped connection surfaces as the
//! "daemon unreachable" overlay; it never leaves stale data looking live —
//! see [`crate::app::Conn::Down`] and the status band's handling of it.
//!
//! Both connections carry a read/write timeout, so a wedged daemon (accepts a
//! connection, never answers) cannot freeze the render thread forever — the
//! defect the skeleton shipped with (`serve_connection` on the daemon side
//! already sets one; this was the missing other half).

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use killbill_proto::{decode, encode, Command, Reply, StreamEvent, MAX_CONTROL_FRAME};

/// How long a command call may block before it's treated as a wedged daemon.
/// The render loop is synchronous on [`ClientHandle::call`] — without a
/// bound, a daemon that accepts the connection and never answers would
/// freeze the whole UI forever.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the event connection's read blocks before it wakes up on its own.
/// Not a liveness check on the daemon — a genuinely quiet system can go far
/// longer than this between USB events — just a bound so the thread is never
/// wedged on a single `read` past any hope of noticing a real problem. A
/// timeout here is treated as "nothing happened yet", not a disconnect.
const EVENT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the event thread waits before retrying a dropped or absent
/// connection. This is a UI convenience socket — there is no kill-path timing
/// here, so a relaxed retry is fine.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// A message from the background event thread to the render loop.
pub enum ClientMsg {
    /// The event connection is up and the `Subscribe` was accepted.
    Connected,
    /// The event connection is gone; the string says why.
    Disconnected(String),
    /// An unsolicited event pushed by the daemon, with the daemon's own
    /// timestamp for it (kept for the event-log screen, plan build-order step
    /// 10; unused before then).
    Event(StreamEvent),
}

/// What [`App`](crate::app::App) needs from a control-socket client. Lets the
/// reducer (`App::on_event`, `App::handle`, …) be driven in tests with a
/// canned script and no socket, instead of only through [`ClientHandle`]
/// (plan §11).
pub trait Client {
    fn call(&mut self, cmd: &Command) -> Result<Reply>;
}

/// The render thread's handle for issuing commands. One owner — not `Clone`.
pub struct ClientHandle {
    socket: PathBuf,
}

impl ClientHandle {
    /// Start the background event thread and return the command handle plus
    /// the channel that thread reports on.
    pub fn spawn(socket: PathBuf) -> (Self, Receiver<ClientMsg>) {
        let (tx, rx) = mpsc::channel();
        let event_socket = socket.clone();
        // If the thread fails to spawn the UI still runs; it just never leaves
        // the "connecting" state, which is an honest thing to show.
        let _ = thread::Builder::new()
            .name("killbill-tui/events".to_owned())
            .spawn(move || event_loop(&event_socket, &tx));
        (Self { socket }, rx)
    }
}

impl Client for ClientHandle {
    /// Send one command and wait for its reply, over a fresh connection. On
    /// any failure the error is returned for the caller to surface as a toast
    /// — there is no connection state here to discard, since none is kept.
    fn call(&mut self, cmd: &Command) -> Result<Reply> {
        let mut conn = connect(&self.socket)?;
        conn.set_read_timeout(Some(COMMAND_TIMEOUT))
            .context("setting a read timeout")?;
        conn.set_write_timeout(Some(COMMAND_TIMEOUT))
            .context("setting a write timeout")?;

        conn.write_all(&encode(cmd)?)
            .context("sending the command")?;

        let mut buf = vec![0u8; MAX_CONTROL_FRAME];
        let n = conn.read(&mut buf).context("reading the reply")?;
        if n == 0 {
            bail!("the daemon closed the connection without replying");
        }
        let (reply, _) = decode::<Reply>(&buf[..n]).context("decoding the reply")?;
        Ok(reply)
    }
}

/// Open one connected `SOCK_SEQPACKET` stream to the control socket. Same
/// construction `killbillctl` uses.
fn connect(path: &Path) -> Result<UnixStream> {
    use nix::sys::socket::{
        connect as nix_connect, socket, AddressFamily, SockFlag, SockProtocol, SockType, UnixAddr,
    };

    let fd = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None::<SockProtocol>,
    )
    .context("creating a Unix socket")?;
    let addr = UnixAddr::new(path).context("bad socket path")?;
    nix_connect(fd.as_raw_fd(), &addr)
        .with_context(|| format!("connecting to {} — is killbilld running?", path.display()))?;
    Ok(UnixStream::from(fd))
}

/// Runs for the life of the process: (re)connect, subscribe, forward events,
/// and on any break report it and retry after [`RECONNECT_DELAY`]. Returns
/// only when the render thread has gone away (every `send` fails).
fn event_loop(socket: &Path, tx: &Sender<ClientMsg>) {
    loop {
        match subscribe(socket) {
            Ok(mut stream) => {
                if tx.send(ClientMsg::Connected).is_err() {
                    return;
                }
                if pump(&mut stream, tx).is_break() {
                    return;
                }
            }
            Err(e) => {
                if tx.send(ClientMsg::Disconnected(e.to_string())).is_err() {
                    return;
                }
            }
        }
        thread::sleep(RECONNECT_DELAY);
    }
}

/// Read frames until the stream breaks. `Break` means the render thread is
/// gone and the whole event loop should stop.
///
/// The daemon replays its event backlog as individual frames immediately
/// after the `Subscribe` ack, then switches to live ones — both are the same
/// `StreamEvent` shape on the wire, so this reads one frame type throughout
/// the connection with no special first-N-frames handling.
fn pump(stream: &mut UnixStream, tx: &Sender<ClientMsg>) -> std::ops::ControlFlow<()> {
    let mut buf = vec![0u8; MAX_CONTROL_FRAME];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return report_disconnect(tx, "the daemon closed the event stream".to_owned()),
            Ok(n) => match decode::<StreamEvent>(&buf[..n]) {
                Ok((se, _)) => {
                    if tx.send(ClientMsg::Event(se)).is_err() {
                        return std::ops::ControlFlow::Break(());
                    }
                }
                Err(e) => return report_disconnect(tx, format!("unreadable event frame: {e}")),
            },
            // A read timeout is not a disconnect — the daemon can legitimately
            // stay quiet far longer than EVENT_READ_TIMEOUT. Just try again.
            Err(e) if is_timeout(&e) => continue,
            Err(e) => return report_disconnect(tx, e.to_string()),
        }
    }
}

fn report_disconnect(tx: &Sender<ClientMsg>, reason: String) -> std::ops::ControlFlow<()> {
    match tx.send(ClientMsg::Disconnected(reason)) {
        Ok(()) => std::ops::ControlFlow::Continue(()),
        Err(_) => std::ops::ControlFlow::Break(()),
    }
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Connect and complete the `Subscribe` handshake, returning the stream ready
/// to read events from. Sets [`EVENT_READ_TIMEOUT`] once here, which stays in
/// effect for every read [`pump`] does afterward on this same stream.
fn subscribe(socket: &Path) -> Result<UnixStream> {
    let mut stream = connect(socket)?;
    stream
        .set_read_timeout(Some(EVENT_READ_TIMEOUT))
        .context("setting a read timeout")?;
    stream
        .set_write_timeout(Some(EVENT_READ_TIMEOUT))
        .context("setting a write timeout")?;
    stream
        .write_all(&encode(&Command::Subscribe)?)
        .context("subscribing")?;

    let mut buf = vec![0u8; MAX_CONTROL_FRAME];
    let n = stream
        .read(&mut buf)
        .context("reading the subscription ack")?;
    if n == 0 {
        bail!("the daemon closed the connection during Subscribe");
    }
    match decode::<Reply>(&buf[..n])?.0 {
        Reply::Ok => Ok(stream),
        Reply::Error(e) => Err(anyhow!("subscription refused: {e}")),
        other => Err(anyhow!("unexpected reply to Subscribe: {other:?}")),
    }
}

/// A fixed-response [`Client`] double — no socket, deterministic replies —
/// for testing [`crate::app::App`]'s reducer (plan §11). `pub(crate)` (not
/// nested in a private `mod tests`) so `app.rs`'s own tests can reach it.
/// Also records every command it was called with, in order, so a test can
/// assert not just that *a* call happened but that the reducer built the
/// right one — e.g. that a whitelist-add modal actually sends
/// `Command::WhitelistAdd` with the id and count the user picked.
#[cfg(test)]
pub(crate) struct ScriptedClient {
    replies: std::collections::VecDeque<Result<Reply>>,
    pub(crate) calls: Vec<Command>,
}

#[cfg(test)]
impl ScriptedClient {
    pub(crate) fn new(replies: Vec<Result<Reply>>) -> Self {
        Self {
            replies: replies.into(),
            calls: Vec::new(),
        }
    }
}

#[cfg(test)]
impl Client for ScriptedClient {
    fn call(&mut self, cmd: &Command) -> Result<Reply> {
        self.calls.push(cmd.clone());
        self.replies
            .pop_front()
            .unwrap_or_else(|| Err(anyhow!("ScriptedClient: no more scripted replies")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_client_returns_replies_in_order_then_errors() {
        let mut c = ScriptedClient::new(vec![Ok(Reply::Ok), Ok(Reply::Error("no".to_owned()))]);
        assert!(matches!(c.call(&Command::Arm), Ok(Reply::Ok)));
        assert!(matches!(c.call(&Command::Disarm), Ok(Reply::Error(_))));
        assert!(c.call(&Command::GetStatus).is_err());
    }
}
