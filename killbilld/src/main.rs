//! `killbilld` — the killbill-rs daemon (charter §7.1).
//!
//! A thin shell: parse a couple of flags, install a non-blocking log sink, and
//! hand off to [`killbilld::daemon::run`], which owns the whole runtime. All the
//! logic lives in the library so it can be tested without spawning a process.

#![deny(unsafe_code)]

use std::path::PathBuf;

use anyhow::{bail, Context};

const DEFAULT_CONFIG: &str = "/etc/killbill/config.toml";
const DEFAULT_SOCKET: &str = "/run/killbilld.sock";

const HELP: &str = "\
killbilld — the killbill-rs USB-kill daemon

USAGE:
    killbilld [OPTIONS]

OPTIONS:
    -c, --config <PATH>    Config file [default: /etc/killbill/config.toml]
    -s, --socket <PATH>    Control socket [default: /run/killbilld.sock]
    -h, --help             Print help
    -V, --version          Print version

The daemon does not fork; run it under systemd. It reads its config, starts the
USB sensor and the control server, and (if `armed_at_boot`) arms. Disarm is a
control-socket command only, never a signal (invariant 5).";

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    let opts = parse_args().context("parsing arguments")?;

    // A non-blocking writer: the worker thread owns the actual stderr writes, so
    // no thread that logs — a responder on the kill path included — can ever be
    // parked behind the sink (the responder/mod.rs contract). `_guard` must live
    // for the whole program so buffered lines are flushed on exit.
    let (writer, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    install_panic_guard();

    killbilld::daemon::run(killbilld::daemon::RunOptions {
        config_path: opts.config,
        socket_path: opts.socket,
    })
}

/// If any thread panics while a kill is in flight, the process must not unwind
/// out of `main` and exit before the detached poweroff thread reaches
/// `reboot(2)` (invariant 5). Park instead; the machine is going down.
///
/// The exception is a poweroff that has already exhausted every path with the
/// machine still up ([`killbilld::kill_failed`]): parking then would only wedge
/// a daemon that protects nothing, so let the panic proceed.
#[cfg(unix)]
fn install_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        if killbilld::kill_in_flight() && !killbilld::kill_failed() {
            eprintln!("killbilld: panic while a kill is in flight — parking, not exiting");
            while killbilld::kill_in_flight() && !killbilld::kill_failed() {
                std::thread::park_timeout(std::time::Duration::from_secs(1));
            }
        }
    }));
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("killbilld runs only on Unix (it needs netlink and a Unix control socket)")
}

struct Opts {
    config: PathBuf,
    socket: PathBuf,
}

fn parse_args() -> anyhow::Result<Opts> {
    let mut config = PathBuf::from(DEFAULT_CONFIG);
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                config = args.next().context("--config needs a path")?.into();
            }
            "-s" | "--socket" => {
                socket = args.next().context("--socket needs a path")?.into();
            }
            "-h" | "--help" => {
                println!("{HELP}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("killbilld {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => bail!("unexpected argument {other:?} (try --help)"),
        }
    }

    Ok(Opts { config, socket })
}
