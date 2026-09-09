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
use clap::{Parser, Subcommand, ValueEnum};
use killbill_proto::{
    decode, encode, sanitize_device_string, Command, ConfigChange, ConfigPayload, DeviceInfo,
    Event, KillReason, OnSensorGap, PowerAction, Reply, StatusPayload, StreamEvent, UsbId,
    WhitelistEntry, MAX_CONTROL_FRAME,
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
    /// Inspect or change the running configuration.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Engage or disengage LUKS header destruction on a kill (invariant 4:
    /// this is the *runtime* opt-in, layered on top of the config-time
    /// `i_understand_this_is_irreversible` acknowledgment — neither alone is
    /// enough). The wipe itself stays a stub in v1 (invariant 3).
    Luks {
        #[command(subcommand)]
        action: LuksCmd,
    },
    /// Print the current event backlog, then exit. With `--follow`, keep
    /// streaming live events afterward until interrupted (Ctrl-C).
    Events {
        #[arg(long)]
        follow: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the running configuration.
    Show,
    /// Change one field. The daemon validates the whole config before writing
    /// anything — a change that would make it invalid is rejected and nothing
    /// is written or applied (invariant 2).
    Set {
        #[command(subcommand)]
        field: SetField,
    },
}

#[derive(Subcommand)]
enum SetField {
    /// Whether a kill only logs instead of acting.
    DryRun { value: OnOff },
    /// What a kill does to the machine.
    PowerAction { value: PowerActionArg },
    /// Whether killbilld arms itself automatically at startup.
    ArmedAtBoot { value: OnOff },
    /// Which sensors to watch (v1: only "usb").
    Sensors { names: Vec<String> },
    /// What to do if the USB sensor reports lost events.
    OnSensorGap { value: OnSensorGapArg },
}

#[derive(Subcommand)]
enum LuksCmd {
    /// Engage (`on`) or disengage (`off`) header destruction on a future
    /// kill. Refused unless `[response.luks_destroy]` is configured and
    /// acknowledged in the running config.
    Engage { value: OnOff },
}

#[derive(Copy, Clone, ValueEnum)]
enum OnOff {
    On,
    Off,
}

impl From<OnOff> for bool {
    fn from(v: OnOff) -> Self {
        matches!(v, OnOff::On)
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum PowerActionArg {
    Poweroff,
    Halt,
    None,
}

impl From<PowerActionArg> for PowerAction {
    fn from(v: PowerActionArg) -> Self {
        match v {
            PowerActionArg::Poweroff => PowerAction::PowerOff,
            PowerActionArg::Halt => PowerAction::Halt,
            PowerActionArg::None => PowerAction::None,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum OnSensorGapArg {
    Warn,
    Kill,
}

impl From<OnSensorGapArg> for OnSensorGap {
    fn from(v: OnSensorGapArg) -> Self {
        match v {
            OnSensorGapArg::Warn => OnSensorGap::Warn,
            OnSensorGapArg::Kill => OnSensorGap::Kill,
        }
    }
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
        Cmd::Config { action } => config(&cli.socket, action)?,
        Cmd::Luks { action } => luks(&cli.socket, action)?,
        Cmd::Events { follow } => stream_events(&cli.socket, *follow)?,
    }
    Ok(())
}

fn config(socket: &Path, action: &ConfigCmd) -> Result<()> {
    match action {
        ConfigCmd::Show => {
            print_config(&expect_config(request(socket, &Command::GetConfig)?)?);
        }
        ConfigCmd::Set { field } => {
            let change = match field {
                SetField::DryRun { value } => ConfigChange::DryRun((*value).into()),
                SetField::PowerAction { value } => ConfigChange::PowerAction((*value).into()),
                SetField::ArmedAtBoot { value } => ConfigChange::ArmedAtBoot((*value).into()),
                SetField::Sensors { names } => ConfigChange::Sensors(names.clone()),
                SetField::OnSensorGap { value } => ConfigChange::OnSensorGap((*value).into()),
            };
            ok_or_error(
                request(socket, &Command::ConfigSet(change))?,
                "config updated",
            )?;
        }
    }
    Ok(())
}

fn luks(socket: &Path, action: &LuksCmd) -> Result<()> {
    match action {
        LuksCmd::Engage { value } => {
            let want: bool = (*value).into();
            ok_or_error(
                request(socket, &Command::SetLuksDestroyEngaged(want))?,
                if want {
                    "LUKS header destruction ENGAGED — recorded only: the v1 wipe is a stub, so \
                     a kill while armed will NOT touch the header (invariant 3)"
                } else {
                    "LUKS header destruction disengaged"
                },
            )?;
        }
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

/// Subscribe, print the backlog the daemon replays first, then either return
/// (plain `events`) or keep printing live events until interrupted
/// (`events --follow`). Backlog and live events are both `StreamEvent` frames
/// on the wire, sent back-to-back with no marker between them — this tells
/// them apart by *timing*, not shape: without `--follow`, a short read
/// timeout is enough to notice "nothing more was already queued" and stop,
/// since the daemon writes the whole backlog immediately after the ack.
fn stream_events(socket: &Path, follow: bool) -> Result<()> {
    let mut stream = connect(socket)?;
    stream
        .write_all(&encode(&Command::Subscribe)?)
        .context("subscribing")?;

    let mut buf = vec![0u8; MAX_CONTROL_FRAME];

    // First frame is the subscription ack — a plain Reply, not a StreamEvent.
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

    if !follow {
        // Only drain what the daemon already had queued for us (the backlog),
        // don't sit waiting for the next live event.
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .context("setting a read timeout")?;
    }

    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if !follow && is_timeout(&e) => break,
            Err(e) => return Err(e).context("reading an event"),
        };
        let (se, _) = decode::<StreamEvent>(&buf[..n])?;
        println!("{}  {}", se.at, render_event(&se.event));
    }
    Ok(())
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
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

fn expect_config(reply: Reply) -> Result<ConfigPayload> {
    match reply {
        Reply::Config(c) => Ok(c),
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

fn print_config(c: &ConfigPayload) {
    println!(
        "armed_at_boot: {}",
        if c.armed_at_boot { "yes" } else { "no" }
    );
    println!("sensors:       {}", c.sensors.join(", "));
    println!("dry_run:       {}", if c.dry_run { "yes" } else { "no" });
    println!("power_action:  {}", c.power_action);
    println!("on_sensor_gap: {}", c.on_sensor_gap);
    match &c.luks_destroy {
        Some(l) => println!(
            "luks_destroy:  configured, target {}  (engaged: {})",
            sanitize_device_string(&l.target_header),
            if l.engaged { "YES" } else { "no" }
        ),
        None => println!("luks_destroy:  not configured"),
    }
    if let Some(err) = &c.validation_error {
        println!(
            "\nNOTE: the config file on disk is currently INVALID; the above is the last-good \
             running configuration, not what's in the file:\n{err}"
        );
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
        Event::WhitelistChanged => "* whitelist changed".to_owned(),
        Event::ConfigChanged => "* config changed".to_owned(),
        Event::ReloadFailed(reason) => format!("!! reload failed: {reason}"),
        other => format!("? {other:?}"),
    }
}
