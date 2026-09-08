//! `killbill-tui` — the terminal UI client (charter §7.2, Phase 2).
//!
//! A pure client of the control protocol in [`killbill_proto`]. It holds no
//! authority: the daemon owns config and armed-state, and killing this process
//! never disarms protection (plan §4). If the TUI needs a daemon capability the
//! protocol lacks, that goes into `killbill-proto` *and* `killbillctl` — never a
//! TUI-only side channel.
//!
//! This is the Phase 2 skeleton (plan build-order step 3 + start of step 4):
//! the two-connection transport, a crash-safe render loop, the armed-state
//! band, the live device list, and the main-menu shell. The remaining screens
//! (whitelist, settings, dry-run, event log, config, LUKS destroy) are menu
//! placeholders until their build-order steps.

#![forbid(unsafe_code)]

mod app;
mod client;
mod input;
mod theme;
mod ui;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use ratatui::crossterm::event::{self, Event as TermEvent};

use crate::app::App;
use crate::client::{ClientHandle, ClientMsg};

#[derive(Parser)]
#[command(
    name = "killbill-tui",
    version,
    about = "Terminal UI for the killbill-rs daemon"
)]
struct Cli {
    /// Path to the daemon's control socket.
    #[arg(long, short, default_value = "/run/killbilld.sock")]
    socket: PathBuf,
}

/// How long a single loop blocks waiting for a keypress before it falls
/// through to drain the daemon-event channel and redraw. Short enough that
/// pushed events feel live, long enough to idle at ~zero CPU.
const TICK: Duration = Duration::from_millis(100);

fn main() -> Result<()> {
    let cli = Cli::parse();

    // `try_init` enters the alternate screen, turns on raw mode, and installs a
    // panic hook that restores the terminal *before* the panic is printed — so
    // a crash never leaves the terminal wedged (plan §4, crash-safety).
    let mut terminal = ratatui::try_init().context("setting up the terminal")?;

    let result = run(&mut terminal, &cli);

    // Non-panic exits (a clean quit, or a `?`-propagated error from `run`) land
    // here; the panic hook covers the rest.
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, cli: &Cli) -> Result<()> {
    let (client, events) = ClientHandle::spawn(cli.socket.clone());
    let mut app = App::new(client);

    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, &app))?;

        // Everything the background client thread has queued since last loop.
        while let Ok(msg) = events.try_recv() {
            match msg {
                ClientMsg::Connected => app.on_connected(),
                ClientMsg::Disconnected(why) => app.on_disconnected(why),
                ClientMsg::Event(ev) => app.on_event(ev),
            }
        }

        app.expire_toast(Instant::now());

        if event::poll(TICK).context("polling for input")? {
            match event::read().context("reading an input event")? {
                TermEvent::Key(key) => {
                    // Resolve the keypress before the mutable borrow in `handle`.
                    let intent = input::intent(&app, key);
                    app.handle(intent);
                }
                // A resize just means the next `draw` re-lays-out; nothing to do.
                TermEvent::Resize(_, _) => {}
                _ => {}
            }
        }
    }
    Ok(())
}
