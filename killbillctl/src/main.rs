//! `killbillctl` — the command-line client (charter §7.3).
//!
//! The dependable, scriptable path: everything the TUI can do, the CLI can do.
//! A pure client of the control protocol in [`killbill_proto`] — it speaks to
//! the daemon over the `SOCK_SEQPACKET` socket and never touches the config file
//! or any daemon state directly.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use killbill_proto::{
    decode, encode, sanitize_device_string, Command, DeviceInfo, Event, KillReason, Reply,
    StatusPayload, UsbId, WhitelistEntry, MAX_CONTROL_FRAME,
};

#[derive(Parser)]
#[command(
    name = "killbillctl",
    version,
    about = "Control the killbill-rs daemon"
)]
struct Cli {
    /// Path to the daemon's control socket.
    #[arg(long, short, global = true, default_value = "/run/killbilld.sock")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show daemon status (armed state, config health, device/whitelist counts).
    Status,
    /// List the USB devices the daemon is currently tracking.
    Devices,
    /// Arm protection. Refused if the config is invalid or the sensor is down.
    Arm,
    /// Disarm protection.
    Disarm,
    /// Dry-run the policy over connected devices and print what would fire.
    Test,
    /// Re-read the config file from disk.
    Reload,
    /// Inspect or change the whitelist.
    Whitelist {
        #[command(subcommand)]
        action: WhitelistCmd,
    },
    /// Stream daemon events until interrupted (Ctrl-C).
    Events,
}

#[derive(Subcommand)]
enum WhitelistCmd {
    /// List whitelist entries.
    List,
    /// Add (or replace) an entry. ID is `vvvv:pppp` lowercase hex, as `lsusb` prints.
    Add {
        id: String,
        /// Human-readable label.
        #[arg(long)]
        label: Option<String>,
        /// Max copies of this id allowed connected at once (default 1).
        #[arg(long)]
        max_count: Option<u32>,
    },
    /// Remove the entry with this id.
    Remove { id: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("killbillctl: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Cmd::Status => {
            print_status(&expect_status(request(&cli.socket, &Command::GetStatus)?)?);
        }
        Cmd::Devices => {
            print_devices(&expect_devices(request(
                &cli.socket,
                &Command::ListDevices,
            )?)?);
        }
        Cmd::Arm => ok_or_error(request(&cli.socket, &Command::Arm)?, "armed")?,
        Cmd::Disarm => ok_or_error(request(&cli.socket, &Command::Disarm)?, "disarmed")?,
        Cmd::Reload => ok_or_error(
            request(&cli.socket, &Command::ReloadConfig)?,
            "config reloaded",
        )?,
        Cmd::Test => print_dry_run(&expect_dry_run(request(&cli.socket, &Command::RunDryRun)?)?),
        Cmd::Whitelist { action } => whitelist(&cli.socket, action)?,
        Cmd::Events => stream_events(&cli.socket)?,
    }
    Ok(())
}

fn whitelist(socket: &Path, action: &WhitelistCmd) -> Result<()> {
    match action {
        WhitelistCmd::List => {
            let reply = request(socket, &Command::WhitelistList)?;
            match reply {
                Reply::Whitelist(entries) => print_whitelist(&entries),
                other => bail!("unexpected reply: {other:?}"),
            }
        }
        WhitelistCmd::Add {
            id,
            label,
            max_count,
        } => {
            let id: UsbId = id.parse().map_err(|_| {
                anyhow!("{id:?} is not a valid USB id — expected vvvv:pppp lowercase hex")
            })?;
            let reply = request(
                socket,
                &Command::WhitelistAdd(WhitelistEntry {
                    id,
                    label: label.clone(),
                    max_count: *max_count,
                }),
            )?;
            ok_or_error(reply, "whitelist updated")?;
        }
        WhitelistCmd::Remove { id } => {
            let id: UsbId = id
                .parse()
                .map_err(|_| anyhow!("{id:?} is not a valid USB id"))?;
            ok_or_error(
                request(socket, &Command::WhitelistRemove(id))?,
                "whitelist updated",
            )?;
        }
    }
    Ok(())
}

// --- transport ---------------------------------------------------------------

fn connect(path: &Path) -> Result<std::os::unix::net::UnixStream> {
    use nix::sys::socket::{
        connect as nix_connect, socket, AddressFamily, SockFlag, SockProtocol, SockType, UnixAddr,
    };
    use std::os::fd::AsRawFd;

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
    Ok(std::os::unix::net::UnixStream::from(fd))
}

fn request(socket: &Path, cmd: &Command) -> Result<Reply> {
    let mut stream = connect(socket)?;
    let frame = encode(cmd).context("encoding the command")?;
    stream.write_all(&frame).context("sending the command")?;

    let mut buf = vec![0u8; MAX_CONTROL_FRAME];
    let n = stream.read(&mut buf).context("reading the reply")?;
    if n == 0 {
        bail!("the daemon closed the connection without replying");
    }
    let (reply, _) = decode::<Reply>(&buf[..n]).context("decoding the reply")?;
    Ok(reply)
}

fn stream_events(socket: &Path) -> Result<()> {
    let mut stream = connect(socket)?;
    stream
        .write_all(&encode(&Command::Subscribe)?)
        .context("subscribing")?;

    let mut buf = vec![0u8; MAX_CONTROL_FRAME];

    // First frame is the subscription ack.
    let n = stream
        .read(&mut buf)
        .context("reading the subscription ack")?;
    if n == 0 {
        bail!("the daemon closed the connection without acknowledging the subscription");
    }
    match decode::<Reply>(&buf[..n])?.0 {
        Reply::Ok => {}
        Reply::Error(e) => bail!("subscription refused: {e}"),
        other => bail!("unexpected reply to Subscribe: {other:?}"),
    }

    loop {
        let n = stream.read(&mut buf).context("reading an event")?;
        if n == 0 {
            break;
        }
        let (event, _) = decode::<Event>(&buf[..n])?;
        println!("{}", render_event(&event));
    }
    Ok(())
}

// --- reply handling ---------------------------------------------------------

fn ok_or_error(reply: Reply, success_msg: &str) -> Result<()> {
    match reply {
        Reply::Ok => {
            println!("{success_msg}");
            Ok(())
        }
        Reply::Error(e) => bail!("{e}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

fn expect_status(reply: Reply) -> Result<StatusPayload> {
    match reply {
        Reply::Status(s) => Ok(s),
        Reply::Error(e) => bail!("{e}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

fn expect_devices(reply: Reply) -> Result<Vec<DeviceInfo>> {
    match reply {
        Reply::Devices(d) => Ok(d),
        Reply::Error(e) => bail!("{e}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

fn expect_dry_run(reply: Reply) -> Result<Vec<KillReason>> {
    match reply {
        Reply::DryRun(r) => Ok(r),
        Reply::Error(e) => bail!("{e}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

// --- rendering -------------------------------------------------------------

fn print_status(s: &StatusPayload) {
    println!("armed:         {}", if s.armed { "yes" } else { "no" });
    println!("dry-run:       {}", if s.dry_run { "yes" } else { "no" });
    println!("power action:  {}", s.power_action);
    println!(
        "sensor:        {}",
        if s.sensor_ok { "ok" } else { "STOPPED" }
    );
    if s.events_lost {
        println!("               EVENTS LOST — some device changes were missed; restart killbilld");
    }
    println!("whitelist:     {} entries", s.whitelist_len);
    println!("devices seen:  {}", s.device_count);
    match &s.config_error {
        Some(err) => println!("config:        INVALID — will not arm\n\n{err}"),
        None if s.config_stale => println!(
            "config:        STALE — a reload was rejected; the running config differs from the \
             file on disk. Fix the file and run `killbillctl reload`."
        ),
        None => println!("config:        ok"),
    }
}

fn print_devices(devices: &[DeviceInfo]) {
    if devices.is_empty() {
        println!("(no devices tracked — the daemon sees devices from when it started)");
        return;
    }
    for d in devices {
        let id =
            d.id.map_or_else(|| "????:????".to_owned(), |i| i.to_string());
        let mark = if d.whitelisted { "ok " } else { "NEW" };
        let label = d
            .label
            .as_deref()
            .map(sanitize_device_string)
            .unwrap_or_default();
        let serial = d
            .serial
            .as_deref()
            .map(sanitize_device_string)
            .unwrap_or_default();
        println!("{mark}  {id}  {label} {serial}");
    }
}

fn print_whitelist(entries: &[WhitelistEntry]) {
    if entries.is_empty() {
        println!("(whitelist is empty — every device is unknown while armed)");
        return;
    }
    for e in entries {
        let label = e
            .label
            .as_deref()
            .map(sanitize_device_string)
            .unwrap_or_default();
        println!("{}  max={}  {label}", e.id, e.max_count.unwrap_or(1));
    }
}

fn print_dry_run(reasons: &[KillReason]) {
    if reasons.is_empty() {
        println!("dry run: nothing currently connected would trigger a kill");
        return;
    }
    println!("dry run: {} device(s) would trigger a kill:", reasons.len());
    for r in reasons {
        println!("  - {r}");
    }
}

fn render_event(event: &Event) -> String {
    let id = |d: &DeviceInfo| {
        d.id.map_or_else(|| "????:????".to_owned(), |i| i.to_string())
    };
    match event {
        Event::DeviceAdded(d) => format!("+ device {}", id(d)),
        Event::DeviceRemoved(d) => format!("- device {}", id(d)),
        Event::Armed => "! armed".to_owned(),
        Event::Disarmed => "! disarmed".to_owned(),
        Event::WouldKill(reason) => format!("! would kill: {reason}"),
        Event::SensorStopped => {
            "!! USB sensor stopped — daemon is respawning it, or exiting for a restart".to_owned()
        }
        Event::EventsLost => "!! USB events lost — some device changes were missed".to_owned(),
        other => format!("? {other:?}"),
    }
}
