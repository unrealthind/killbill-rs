//! The render-thread state store and its reducer.
//!
//! [`App`] is a *cache* of what the daemon has told us — never authoritative
//! state of its own (plan §4). Every field changes only in response to a
//! [`Reply`] we asked for or an [`Event`] the daemon pushed. When an event
//! means "authority changed" (`Armed`, `Disarmed`, a device change, …) the
//! reducer re-fetches from the daemon rather than guessing locally, so the
//! daemon stays the single source of truth.

use std::time::{Duration, Instant};

use killbill_proto::{Command, DeviceInfo, Event, Reply, StatusPayload};

use crate::client::ClientHandle;
use crate::theme::Theme;

/// How long a toast stays on screen.
const TOAST_TTL: Duration = Duration::from_secs(4);

/// Connection state, as reported by the background event thread.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Conn {
    /// Started, no connection established yet this session.
    Connecting,
    Up,
    Down,
}

/// The primary view behind any modal. `Placeholder` screens are menu targets
/// whose real UI lands in later plan build-order steps.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Devices,
    Placeholder(&'static str),
}

/// An entry in the main menu (plan §6).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    Devices,
    Whitelist,
    DryRun,
    Settings,
    EventLog,
    Config,
    LuksDestroy,
    Arm,
    Disarm,
    Reload,
    Help,
    Quit,
}

impl MenuItem {
    /// Menu order, top to bottom.
    pub const ORDER: [MenuItem; 12] = [
        MenuItem::Devices,
        MenuItem::Whitelist,
        MenuItem::DryRun,
        MenuItem::Settings,
        MenuItem::EventLog,
        MenuItem::Config,
        MenuItem::LuksDestroy,
        MenuItem::Arm,
        MenuItem::Disarm,
        MenuItem::Reload,
        MenuItem::Help,
        MenuItem::Quit,
    ];

    pub fn label(self) -> &'static str {
        match self {
            MenuItem::Devices => "Devices",
            MenuItem::Whitelist => "Whitelist",
            MenuItem::DryRun => "Dry-run",
            MenuItem::Settings => "Settings",
            MenuItem::EventLog => "Event log",
            MenuItem::Config => "Config",
            MenuItem::LuksDestroy => "LUKS destroy",
            MenuItem::Arm => "Arm",
            MenuItem::Disarm => "Disarm",
            MenuItem::Reload => "Reload config from file",
            MenuItem::Help => "Help",
            MenuItem::Quit => "Quit",
        }
    }

    /// A separator line is drawn *before* items that start a new group.
    pub fn starts_group(self) -> bool {
        matches!(self, MenuItem::Arm | MenuItem::Help)
    }
}

/// The overlay above the primary screen. Only the menu exists in the skeleton;
/// confirm / text-input / message modals arrive with their build-order steps.
#[derive(Clone, Copy)]
pub enum Modal {
    Menu { cursor: usize },
}

/// One decoded keypress, resolved against the current screen/modal by
/// [`crate::input::intent`].
pub enum Intent {
    None,
    Quit,
    /// Open the main menu, or close it if already open.
    ToggleMenu,
    /// Close a modal, else return to the Devices screen.
    Back,
    Up,
    Down,
    /// Activate the selected menu item / list row.
    Select,
    /// Re-fetch the current screen's data from the daemon.
    Refresh,
    /// Nudge a reconnect while the daemon is unreachable.
    Reconnect,
    Help,
}

pub struct App {
    client: ClientHandle,

    pub theme: Theme,
    pub conn: Conn,
    pub conn_error: Option<String>,

    pub status: Option<StatusPayload>,
    pub devices: Vec<DeviceInfo>,

    pub screen: Screen,
    pub modal: Option<Modal>,
    pub device_cursor: usize,

    pub toast: Option<(String, Instant)>,
    pub should_quit: bool,
}

impl App {
    pub fn new(client: ClientHandle) -> Self {
        Self {
            client,
            theme: Theme::detect(),
            conn: Conn::Connecting,
            conn_error: None,
            status: None,
            devices: Vec::new(),
            screen: Screen::Devices,
            modal: None,
            device_cursor: 0,
            toast: None,
            should_quit: false,
        }
    }

    // --- input ------------------------------------------------------------

    pub fn handle(&mut self, intent: Intent) {
        match intent {
            Intent::None => {}
            Intent::Quit => self.should_quit = true,
            Intent::ToggleMenu => {
                self.modal = match self.modal {
                    Some(Modal::Menu { .. }) => None,
                    None => Some(Modal::Menu { cursor: 0 }),
                };
            }
            Intent::Back => {
                // If a modal was open, closing it is the whole action.
                if self.modal.take().is_none() && !matches!(self.screen, Screen::Devices) {
                    self.screen = Screen::Devices;
                }
            }
            Intent::Up => self.move_cursor(-1),
            Intent::Down => self.move_cursor(1),
            Intent::Select => self.select(),
            Intent::Refresh => self.refresh(),
            Intent::Reconnect => self.set_toast("reconnecting…"),
            Intent::Help => {
                self.modal = None;
                self.screen = Screen::Placeholder("Help");
            }
        }
    }

    fn move_cursor(&mut self, delta: i32) {
        if let Some(Modal::Menu { cursor }) = &mut self.modal {
            let n = MenuItem::ORDER.len() as i32;
            *cursor = (*cursor as i32 + delta).rem_euclid(n) as usize;
            return;
        }
        if matches!(self.screen, Screen::Devices) && !self.devices.is_empty() {
            let n = self.devices.len() as i32;
            self.device_cursor = (self.device_cursor as i32 + delta).rem_euclid(n) as usize;
        }
    }

    fn select(&mut self) {
        let Some(Modal::Menu { cursor }) = self.modal else {
            return;
        };
        self.modal = None;
        match MenuItem::ORDER[cursor] {
            MenuItem::Devices => self.screen = Screen::Devices,
            MenuItem::Whitelist => self.screen = Screen::Placeholder("Whitelist"),
            MenuItem::DryRun => self.screen = Screen::Placeholder("Dry-run"),
            MenuItem::Settings => self.screen = Screen::Placeholder("Settings"),
            MenuItem::EventLog => self.screen = Screen::Placeholder("Event log"),
            MenuItem::Config => self.screen = Screen::Placeholder("Config"),
            MenuItem::LuksDestroy => self.screen = Screen::Placeholder("LUKS destroy"),
            // TODO(plan §6): Arm / Disarm / Reload each get a confirm modal in
            // the arming/disarming build-order step. Disarm especially — it is
            // the one action that lowers protection.
            MenuItem::Arm => self.command(&Command::Arm, "armed"),
            MenuItem::Disarm => self.command(&Command::Disarm, "disarmed"),
            MenuItem::Reload => self.command(&Command::ReloadConfig, "config reloaded"),
            MenuItem::Help => self.screen = Screen::Placeholder("Help"),
            MenuItem::Quit => self.should_quit = true,
        }
    }

    // --- daemon messages -------------------------------------------------

    pub fn on_connected(&mut self) {
        self.conn = Conn::Up;
        self.conn_error = None;
        self.refresh();
    }

    pub fn on_disconnected(&mut self, why: String) {
        self.conn = Conn::Down;
        self.conn_error = Some(why);
    }

    pub fn on_event(&mut self, ev: Event) {
        match ev {
            Event::DeviceAdded(_) | Event::DeviceRemoved(_) => {
                self.refresh_devices();
                self.refresh_status();
            }
            Event::Armed => {
                self.set_toast("Armed");
                self.refresh_status();
            }
            Event::Disarmed => {
                self.set_toast("Disarmed");
                self.refresh_status();
            }
            Event::WouldKill(reason) => self.set_toast(format!("would kill: {reason}")),
            Event::SensorStopped => {
                self.set_toast("USB sensor stopped — daemon is no longer watching");
                self.refresh_status();
            }
            Event::EventsLost => {
                self.set_toast("USB events lost — some device changes were missed");
                self.refresh_status();
            }
            // `Event` is `#[non_exhaustive]`: a newer daemon may push a variant
            // this build predates. Surface it rather than silently drop it.
            other => self.set_toast(format!("event: {other:?}")),
        }
    }

    // --- fetches --------------------------------------------------------

    fn refresh(&mut self) {
        self.refresh_status();
        self.refresh_devices();
    }

    fn refresh_status(&mut self) {
        match self.client.call(&Command::GetStatus) {
            Ok(Reply::Status(s)) => self.status = Some(s),
            Ok(other) => self.set_toast(format!("unexpected reply to GetStatus: {other:?}")),
            Err(e) => self.set_toast(format!("status: {e}")),
        }
    }

    fn refresh_devices(&mut self) {
        match self.client.call(&Command::ListDevices) {
            Ok(Reply::Devices(d)) => {
                self.devices = d;
                let last = self.devices.len().saturating_sub(1);
                if self.device_cursor > last {
                    self.device_cursor = last;
                }
            }
            Ok(other) => self.set_toast(format!("unexpected reply to ListDevices: {other:?}")),
            Err(e) => self.set_toast(format!("devices: {e}")),
        }
    }

    fn command(&mut self, cmd: &Command, ok_msg: &str) {
        match self.client.call(cmd) {
            Ok(Reply::Ok) => self.set_toast(ok_msg.to_owned()),
            Ok(Reply::Error(e)) => self.set_toast(format!("refused: {e}")),
            Ok(other) => self.set_toast(format!("unexpected reply: {other:?}")),
            Err(e) => self.set_toast(format!("error: {e}")),
        }
        // Reflect whatever actually changed.
        self.refresh_status();
    }

    // --- toast ---------------------------------------------------------

    fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    pub fn expire_toast(&mut self, now: Instant) {
        if let Some((_, shown_at)) = &self.toast {
            if now.duration_since(*shown_at) > TOAST_TTL {
                self.toast = None;
            }
        }
    }
}

// TODO(plan §11): once the reducer stabilises, put `ClientHandle` behind a
// trait so `on_event` / `on_connected` can be driven with canned Reply/Event
// sequences and asserted against `App` state, with no socket.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_order_is_complete_and_unique() {
        // Every variant appears exactly once, so cursor arithmetic over
        // `ORDER` can never land on a gap.
        let mut seen = MenuItem::ORDER.to_vec();
        seen.sort_by_key(|m| *m as u8);
        seen.dedup_by_key(|m| *m as u8);
        assert_eq!(seen.len(), MenuItem::ORDER.len());
    }

    #[test]
    fn group_separators_sit_before_arm_and_help() {
        let breaks: Vec<&str> = MenuItem::ORDER
            .iter()
            .filter(|m| m.starts_group())
            .map(|m| m.label())
            .collect();
        assert_eq!(breaks, ["Arm", "Help"]);
    }
}
