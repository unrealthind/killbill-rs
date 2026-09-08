//! Transport to the daemon's `SOCK_SEQPACKET` control socket.
//!
//! Two independent connections (plan §4):
//!
//! * the **command connection** — owned by the render thread through
//!   [`ClientHandle`]; one synchronous request/reply per [`ClientHandle::call`].
//! * the **event connection** — a background thread ([`event_loop`]) that sends
//!   `Subscribe` and forwards each [`Event`] onto an `mpsc` channel. It is the
//!   single authority on whether the daemon is reachable: it reconnects on its
//!   own and reports [`ClientMsg::Connected`] / [`ClientMsg::Disconnected`].
//!
//! Neither path caches daemon state. A dropped connection surfaces as the
//! "daemon unreachable" overlay; it never leaves stale data looking live.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use killbill_proto::{decode, encode, Command, Event, Reply};

/// Read buffer for one control message. A SEQPACKET datagram is one whole
/// frame; control messages are never close to this. Mirrors `killbillctl`.
const MAX_MSG: usize = 128 * 1024;

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
    /// An unsolicited event pushed by the daemon.
    Event(Event),
}

/// The render thread's handle for issuing commands. One owner — not `Clone`.
pub struct ClientHandle {
    socket: PathBuf,
    /// Kept open between calls; dropped and re-established on any error.
    conn: Option<UnixStream>,
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
        (Self { socket, conn: None }, rx)
    }

    /// Send one command and wait for its reply. Reconnects transparently if the
    /// command connection has dropped. On any failure the connection is
    /// discarded so the next call starts clean, and the error is returned for
    /// the caller to surface as a toast.
    pub fn call(&mut self, cmd: &Command) -> Result<Reply> {
        match self.try_call(cmd) {
            Ok(reply) => Ok(reply),
            Err(e) => {
                self.conn = None;
                Err(e)
            }
        }
    }

    fn try_call(&mut self, cmd: &Command) -> Result<Reply> {
        if self.conn.is_none() {
            self.conn = Some(connect(&self.socket)?);
        }
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| anyhow!("no connection to the daemon"))?;

        conn.write_all(&encode(cmd)?)
            .context("sending the command")?;

        let mut buf = vec![0u8; MAX_MSG];
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
fn pump(stream: &mut UnixStream, tx: &Sender<ClientMsg>) -> std::ops::ControlFlow<()> {
    use std::ops::ControlFlow::{Break, Continue};

    let mut buf = vec![0u8; MAX_MSG];
    loop {
        let disconnect_reason = match stream.read(&mut buf) {
            Ok(0) => "the daemon closed the event stream".to_owned(),
            Ok(n) => match decode::<Event>(&buf[..n]) {
                Ok((ev, _)) => {
                    if tx.send(ClientMsg::Event(ev)).is_err() {
                        return Break(());
                    }
                    continue;
                }
                Err(e) => format!("unreadable event frame: {e}"),
            },
            Err(e) => e.to_string(),
        };
        return match tx.send(ClientMsg::Disconnected(disconnect_reason)) {
            Ok(()) => Continue(()),
            Err(_) => Break(()),
        };
    }
}

/// Connect and complete the `Subscribe` handshake, returning the stream ready
/// to read events from.
fn subscribe(socket: &Path) -> Result<UnixStream> {
    let mut stream = connect(socket)?;
    stream
        .write_all(&encode(&Command::Subscribe)?)
        .context("subscribing")?;

    let mut buf = vec![0u8; MAX_MSG];
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
