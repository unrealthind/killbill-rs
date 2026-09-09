//! The render-thread state store and its reducer.
//!
//! [`App`] is a *cache* of what the daemon has told us — never authoritative
//! state of its own (plan §4). Every field changes only in response to a
//! [`Reply`] we asked for or an [`Event`] the daemon pushed. When an event
//! means "authority changed" (`Armed`, `Disarmed`, a device change, …) the
//! reducer re-fetches from the daemon rather than guessing locally, so the
//! daemon stays the single source of truth.

use std::collections::VecDeque;
use std::str::FromStr;
use std::time::{Duration, Instant};

use killbill_proto::{
    Command, ConfigChange, ConfigPayload, DeviceInfo, Event, KillReason, OnSensorGap, PowerAction,
    Reply, StatusPayload, StreamEvent, UsbId, WhitelistEntry,
};

use crate::client::{Client, ClientHandle};
use crate::theme::Theme;

/// How long a toast stays on screen.
const TOAST_TTL: Duration = Duration::from_secs(4);

/// Rows in the device action modal (plan §6): one action plus Cancel, always.
const DEVICE_ACTION_OPTIONS: usize = 2;

/// Rows in the whitelist-entry action modal (plan §5): edit, remove, cancel.
const WHITELIST_ENTRY_ACTION_OPTIONS: usize = 3;

/// Editable rows on the Settings screen (plan §5): dry-run, power action,
/// armed-at-boot, on-sensor-gap. `sensors` is shown read-only (v1 only ever
/// holds `"usb"` — see [`crate::ui`]).
pub const SETTINGS_ROW_COUNT: usize = 4;

/// UI-only ceiling on the `↑`/`↓` stepper in the whitelist count modals. Not a
/// protocol or config limit — `WhitelistEntry.max_count` is a plain `u32` —
/// just a sane bound for a stepper with no free-text entry.
const MAX_WHITELIST_COUNT_UI: u32 = 32;

/// Longest string the `vendor:product` entry field accepts (`1050:0407` — four
/// hex, a colon, four hex).
const USB_ID_INPUT_LEN: usize = 9;

/// How many events the event-log ring keeps (plan §4). Older ones age out.
const EVENT_LOG_CAP: usize = 1000;

/// The exact word the LUKS-destroy fence demands, case-sensitive (charter §4,
/// plan §8). Nothing else — not `destroy`, not `DESTROY `, not `y` — advances it.
const DESTROY_WORD: &str = "DESTROY";

/// Longest string the `DESTROY` field accepts. A hair over the word itself, so
/// an over-long typo simply stops accepting characters rather than scrolling.
const DESTROY_WORD_INPUT_MAX: usize = 12;

/// One `↑`/`↓` step on a scrolling read screen (Help, LUKS destroy), in lines.
const SCROLL_STEP: u16 = 1;

/// Connection state, as reported by the background event thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conn {
    /// Started, no connection established yet this session.
    Connecting,
    Up,
    Down,
}

/// The primary view behind any modal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Devices,
    Whitelist,
    DryRun,
    Settings,
    EventLog,
    /// Read-only parsed-config inspector + validation report (plan §5, step 11).
    Config,
    /// Static keybinding reference (plan §5, step 11).
    Help,
    /// The fenced LUKS-header-destruction screen (plan §8, step 12). The wipe
    /// itself stays a stub in v1 (invariant 3) — this screen only toggles the
    /// runtime `engaged` flag via [`Command::SetLuksDestroyEngaged`].
    Destroy,
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

/// The three menu actions that change protection or reload from disk. Each one
/// opens a [`Modal::Confirm`] before it fires (plan §6) — `Disarm` especially,
/// since it is the one action that lowers protection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    Arm,
    Disarm,
    Reload,
}

impl ConfirmAction {
    fn to_command(self) -> Command {
        match self {
            ConfirmAction::Arm => Command::Arm,
            ConfirmAction::Disarm => Command::Disarm,
            ConfirmAction::Reload => Command::ReloadConfig,
        }
    }

    fn ok_msg(self) -> &'static str {
        match self {
            ConfirmAction::Arm => "armed",
            ConfirmAction::Disarm => "disarmed",
            ConfirmAction::Reload => "config reloaded",
        }
    }

    /// The question the confirm modal asks.
    pub fn prompt(self) -> &'static str {
        match self {
            ConfirmAction::Arm => "Arm protection now?",
            ConfirmAction::Disarm => "Disarm protection? This lowers protection until you re-arm.",
            ConfirmAction::Reload => "Reload the config from disk?",
        }
    }
}

/// The overlay above the primary screen. All variants are `Copy` — any text
/// being typed lives in [`App::input`], not here.
#[derive(Clone, Copy)]
pub enum Modal {
    Menu {
        cursor: usize,
    },
    /// Opened with `Enter` on a device row (plan §6). `device_index` indexes
    /// [`App::devices`] at the moment the modal opened — re-checked, not
    /// trusted, when an option is confirmed, since the list can change under
    /// a modal that's still open.
    DeviceAction {
        device_index: usize,
        cursor: usize,
    },
    /// Second step of the device screen's "Add to whitelist…": pick `max_count`
    /// before sending [`Command::WhitelistAdd`]. `↑`/`↓` adjust it.
    WhitelistAddCount {
        device_index: usize,
        max_count: u32,
    },
    /// Second step of the device screen's "Remove from whitelist": a confirm,
    /// since this lowers protection for that device the next time it's plugged
    /// in while armed.
    ConfirmRemove {
        device_index: usize,
    },
    /// `Arm` / `Disarm` / `Reload` from the menu (plan §7, build step 7).
    Confirm {
        action: ConfirmAction,
    },
    /// A Settings change that would *lower* protection while the daemon is
    /// armed (enable dry-run, or a power action that no longer cuts power).
    /// `row` re-derives the [`ConfigChange`] from [`App::config`] on confirm,
    /// so the modal stays `Copy`.
    ConfirmConfigSet {
        row: usize,
    },
    /// `Enter` on a whitelist-screen entry row: edit / remove / cancel.
    WhitelistEntryAction {
        entry_index: usize,
        cursor: usize,
    },
    /// The whitelist screen's "add entry" flow, step one: type a
    /// `vendor:product` id into [`App::input`].
    WhitelistAddId,
    /// Whitelist count picker — step two of "add entry", or "edit max count"
    /// on an existing entry (`editing` only changes the title).
    WhitelistCount {
        id: UsbId,
        max_count: u32,
        editing: bool,
    },
    /// Confirm removing an entry from the Whitelist screen.
    WhitelistRemoveEntry {
        id: UsbId,
    },
    /// A rejected [`Command::ConfigSet`]: shows the daemon's full validation
    /// report ([`App::report`]). The running config is unchanged (invariant 2).
    Report,
    /// LUKS-destroy fence, step one (plan §8): a text field that must be typed
    /// exactly [`DESTROY_WORD`] to advance. `engage` is the state the toggle
    /// would move *to* — `true` to engage, `false` to disengage. Anything other
    /// than the exact word cancels with nothing sent.
    DestroyText {
        engage: bool,
    },
    /// LUKS-destroy fence, step two (plan §8): a final `y`/anything-else after
    /// the word was typed correctly. Only `y`/`Y` sends
    /// [`Command::SetLuksDestroyEngaged`]; every other key cancels.
    DestroyConfirm {
        engage: bool,
    },
}

/// The device action modal's option labels, in cursor order. Whitelisted and
/// not-whitelisted devices get different first options; both always end in
/// Cancel — see [`DEVICE_ACTION_OPTIONS`].
pub fn device_action_labels(whitelisted: bool) -> [&'static str; DEVICE_ACTION_OPTIONS] {
    if whitelisted {
        ["Remove from whitelist", "Cancel"]
    } else {
        ["Add to whitelist…", "Cancel"]
    }
}

/// The whitelist-entry action modal's option labels, in cursor order.
pub fn whitelist_entry_action_labels() -> [&'static str; WHITELIST_ENTRY_ACTION_OPTIONS] {
    ["Edit max count…", "Remove from whitelist", "Cancel"]
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
    /// Activate the selected menu item / list row / confirm a modal.
    Select,
    /// Re-fetch the current screen's data from the daemon.
    Refresh,
    /// Nudge a reconnect while the daemon is unreachable.
    Reconnect,
    Help,
    /// A printable character typed into a text-entry modal.
    Char(char),
    /// Delete the last character in a text-entry modal.
    Backspace,
    /// Event log only: freeze / unfreeze auto-scroll (plan §5).
    TogglePause,
}

/// `C` is the control-socket client — [`ClientHandle`] in production, a
/// canned [`crate::client::ScriptedClient`] in tests (plan §11), so the
/// reducer below is testable with no socket.
pub struct App<C: Client = ClientHandle> {
    client: C,

    pub theme: Theme,
    pub conn: Conn,
    pub conn_error: Option<String>,

    pub status: Option<StatusPayload>,
    pub devices: Vec<DeviceInfo>,
    pub whitelist: Vec<WhitelistEntry>,
    pub config: Option<ConfigPayload>,
    /// Result of the last [`Command::RunDryRun`]; `None` until one has run.
    pub dryrun: Option<Vec<KillReason>>,
    /// Decision / event scrollback (plan §5), newest last. Capped ring.
    pub events: VecDeque<StreamEvent>,
    /// The validation report behind [`Modal::Report`].
    pub report: Option<String>,

    pub screen: Screen,
    pub modal: Option<Modal>,

    pub device_cursor: usize,
    /// Row 0 is the "add entry" action; entry `i` is at cursor `i + 1`.
    pub whitelist_cursor: usize,
    pub settings_cursor: usize,
    /// Lines the event log is scrolled up from the newest (0 = following).
    pub event_scroll: usize,
    /// Event log auto-scroll is frozen.
    pub events_paused: bool,
    /// Lines the Help screen is scrolled down from the top.
    pub help_scroll: u16,
    /// Lines the LUKS-destroy screen is scrolled down from the top. Reset to 0
    /// whenever that screen is (re-)entered from the menu.
    pub destroy_scroll: u16,

    /// The `vendor:product` string being typed in [`Modal::WhitelistAddId`].
    pub input: String,

    /// The LUKS target header captured when the [`Modal::DestroyText`] fence
    /// opened. [`App::set_luks_destroy_engaged`] re-checks it against the
    /// current config before sending: a concurrent `reload`/`config set` from
    /// another root client can repoint `target_header` under the open fence,
    /// and the operator confirmed the header shown then, not this one.
    pub destroy_target: Option<String>,

    pub toast: Option<(String, Instant)>,
    pub should_quit: bool,

    // Set by `on_event`, serviced once per render-loop tick by `settle()`
    // instead of a socket round-trip per event. A backlog-replay burst (up to
    // ~200 events the moment we subscribe) would otherwise fire ~400–600 fresh
    // `SOCK_SEQPACKET` connections back to back on the same control FIFO the
    // daemon services the kill decision on — bounded, but it adds latency there
    // and hangs the UI while it grinds. Private: only `on_event` sets, only
    // `settle` clears.
    dirty_status: bool,
    dirty_devices: bool,
    dirty_whitelist: bool,
    dirty_config: bool,
}

impl<C: Client> App<C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            theme: Theme::detect(),
            conn: Conn::Connecting,
            conn_error: None,
            status: None,
            devices: Vec::new(),
            whitelist: Vec::new(),
            config: None,
            dryrun: None,
            events: VecDeque::new(),
            report: None,
            screen: Screen::Devices,
            modal: None,
            device_cursor: 0,
            whitelist_cursor: 0,
            settings_cursor: 0,
            event_scroll: 0,
            events_paused: false,
            help_scroll: 0,
            destroy_scroll: 0,
            input: String::new(),
            destroy_target: None,
            toast: None,
            should_quit: false,
            dirty_status: false,
            dirty_devices: false,
            dirty_whitelist: false,
            dirty_config: false,
        }
    }

    /// Whether the current modal is a text-entry field — [`crate::input`] routes
    /// printable keys to [`Intent::Char`] instead of accelerators while true.
    pub fn capturing_text(&self) -> bool {
        matches!(
            self.modal,
            Some(Modal::WhitelistAddId | Modal::DestroyText { .. } | Modal::DestroyConfirm { .. })
        )
    }

    /// Whether LUKS header destruction is currently engaged, per the last
    /// [`ConfigPayload`] we fetched. `false` when unknown or unconfigured — the
    /// safe reading (invariant 4: engaged is never assumed).
    pub fn luks_engaged(&self) -> bool {
        self.config
            .as_ref()
            .and_then(|c| c.luks_destroy.as_ref())
            .is_some_and(|l| l.engaged)
    }

    /// Whether a device with this id is currently connected — the Whitelist
    /// screen marks entries that are present vs. absent.
    pub fn whitelist_entry_connected(&self, id: UsbId) -> bool {
        self.devices.iter().any(|d| d.id == Some(id))
    }

    // --- input ------------------------------------------------------------

    pub fn handle(&mut self, intent: Intent) {
        match intent {
            Intent::None => {}
            Intent::Quit => self.should_quit = true,
            Intent::ToggleMenu => {
                self.modal = match &self.modal {
                    Some(Modal::Menu { .. }) => None,
                    // `m` is a global key (always active); pressing it while
                    // any other modal is open replaces that modal with the
                    // main menu rather than doing nothing.
                    _ => Some(Modal::Menu { cursor: 0 }),
                };
                // Any modal-replacing global key drops in-progress modal state
                // so it can't outlive its modal (the fence's captured target,
                // a half-typed field).
                self.input.clear();
                self.destroy_target = None;
            }
            Intent::Back => {
                let closing_fence = matches!(
                    self.modal,
                    Some(Modal::DestroyText { .. } | Modal::DestroyConfirm { .. })
                );
                let had_modal = self.modal.take().is_some();
                self.input.clear();
                self.report = None;
                self.destroy_target = None;
                if closing_fence {
                    self.set_toast("cancelled — LUKS destruction unchanged");
                } else if !had_modal && !matches!(self.screen, Screen::Devices) {
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
                self.input.clear();
                self.destroy_target = None;
                self.screen = Screen::Help;
                self.help_scroll = 0;
            }
            Intent::Char(c) => self.input_char(c),
            Intent::Backspace => {
                if self.capturing_text() {
                    self.input.pop();
                }
            }
            Intent::TogglePause => {
                if matches!(self.screen, Screen::EventLog) {
                    self.events_paused = !self.events_paused;
                    if !self.events_paused {
                        self.event_scroll = 0;
                    }
                    self.set_toast(if self.events_paused {
                        "log paused"
                    } else {
                        "log following"
                    });
                }
            }
        }
    }

    fn input_char(&mut self, c: char) {
        match self.modal {
            Some(Modal::WhitelistAddId) => {
                // A USB id is `vvvv:pppp` — hex digits and a single colon.
                if self.input.chars().count() >= USB_ID_INPUT_LEN {
                    return;
                }
                if c.is_ascii_hexdigit() || (c == ':' && !self.input.contains(':')) {
                    self.input.push(c.to_ascii_lowercase());
                }
            }
            Some(Modal::DestroyText { .. }) => {
                // Accept letters only, un-folded — the fence is case-sensitive
                // (`DESTROY`, never `destroy`). Cap the length so a long typo
                // just stops rather than scrolling the field.
                if self.input.chars().count() < DESTROY_WORD_INPUT_MAX && c.is_ascii_alphabetic() {
                    self.input.push(c);
                }
            }
            Some(Modal::DestroyConfirm { engage }) => {
                // Step two: only `y`/`Y` confirms; every other key cancels
                // (plan §8, "anything else cancels"). `input` routes only
                // `y`/`Y` here now — see `crate::input::intent` — but keep the
                // guard so a direct `Intent::Char` in a test still cancels.
                self.modal = None;
                if c == 'y' || c == 'Y' {
                    self.set_luks_destroy_engaged(engage);
                } else {
                    self.destroy_target = None;
                    self.set_toast("cancelled — LUKS destruction unchanged");
                }
            }
            _ => {}
        }
    }

    fn move_cursor(&mut self, delta: i32) {
        // `Modal` is `Copy`: work on a local so the write-back doesn't fight a
        // `&mut self.modal` borrow held across a `self` method call.
        let Some(mut modal) = self.modal else {
            self.move_screen_cursor(delta);
            return;
        };
        match &mut modal {
            Modal::Menu { cursor } => wrap(cursor, delta, MenuItem::ORDER.len()),
            Modal::DeviceAction { cursor, .. } => wrap(cursor, delta, DEVICE_ACTION_OPTIONS),
            Modal::WhitelistEntryAction { cursor, .. } => {
                wrap(cursor, delta, WHITELIST_ENTRY_ACTION_OPTIONS)
            }
            Modal::WhitelistAddCount { max_count, .. }
            | Modal::WhitelistCount { max_count, .. } => {
                // `delta` is list-cursor sign (`Up` = -1, moving to an earlier
                // row) — inverted from what a numeric stepper wants (`Up`
                // should increase the count), so negate it here.
                let next = (*max_count as i32 - delta).clamp(1, MAX_WHITELIST_COUNT_UI as i32);
                *max_count = next as u32;
            }
            Modal::ConfirmRemove { .. }
            | Modal::Confirm { .. }
            | Modal::ConfirmConfigSet { .. }
            | Modal::WhitelistRemoveEntry { .. }
            | Modal::WhitelistAddId
            | Modal::Report
            | Modal::DestroyText { .. }
            | Modal::DestroyConfirm { .. } => {
                // Nothing to move — a yes/no confirm, a text field, or a report.
            }
        }
        self.modal = Some(modal);
    }

    fn move_screen_cursor(&mut self, delta: i32) {
        match self.screen {
            Screen::Devices => {
                if !self.devices.is_empty() {
                    wrap(&mut self.device_cursor, delta, self.devices.len());
                }
            }
            Screen::Whitelist => {
                // +1 for the "add entry" row that always sits at the top.
                wrap(&mut self.whitelist_cursor, delta, self.whitelist.len() + 1);
            }
            Screen::Settings => {
                wrap(&mut self.settings_cursor, delta, SETTINGS_ROW_COUNT);
            }
            Screen::EventLog => {
                if delta < 0 {
                    // Cap at `len - 1`, not `len`: scrolled all the way to
                    // `len` the viewport window is empty and the screen goes
                    // blank past the oldest line. Keep the oldest line visible.
                    self.event_scroll =
                        (self.event_scroll + 1).min(self.events.len().saturating_sub(1));
                    self.events_paused = true;
                } else {
                    self.event_scroll = self.event_scroll.saturating_sub(1);
                    if self.event_scroll == 0 {
                        self.events_paused = false;
                    }
                }
            }
            Screen::Help => {
                if delta < 0 {
                    self.help_scroll = self.help_scroll.saturating_sub(SCROLL_STEP);
                } else {
                    // Don't scroll past the content into blank space — a
                    // `Paragraph` offset has no natural ceiling.
                    let max = crate::ui::help_line_count().saturating_sub(1);
                    self.help_scroll = (self.help_scroll + SCROLL_STEP).min(max);
                }
            }
            Screen::Destroy => {
                // The fenced screen is taller than a small terminal; at MIN_H
                // the stub disclaimer and the "press Enter to ENGAGE" hint fall
                // off the bottom. Same bounded-offset scroll as Help — the
                // `destroy::body_lines` count is dynamic (config + conn) and
                // pre-wrapped so logical lines == rendered rows, so it takes
                // the whole `App`.
                if delta < 0 {
                    self.destroy_scroll = self.destroy_scroll.saturating_sub(SCROLL_STEP);
                } else {
                    let max = crate::ui::destroy_line_count(self).saturating_sub(1);
                    self.destroy_scroll = (self.destroy_scroll + SCROLL_STEP).min(max);
                }
            }
            // Read-only, single-action, or non-scrolling screens.
            Screen::Config | Screen::DryRun => {}
        }
    }

    fn select(&mut self) {
        match self.modal {
            Some(Modal::Menu { cursor }) => {
                self.modal = None;
                self.select_menu_item(MenuItem::ORDER[cursor]);
            }
            Some(Modal::DeviceAction {
                device_index,
                cursor,
            }) => self.select_device_action(device_index, cursor),
            Some(Modal::WhitelistAddCount {
                device_index,
                max_count,
            }) => self.confirm_device_whitelist_add(device_index, max_count),
            Some(Modal::ConfirmRemove { device_index }) => self.confirm_device_remove(device_index),
            Some(Modal::Confirm { action }) => {
                self.modal = None;
                self.command(&action.to_command(), action.ok_msg());
            }
            Some(Modal::WhitelistEntryAction {
                entry_index,
                cursor,
            }) => self.select_whitelist_entry_action(entry_index, cursor),
            Some(Modal::WhitelistAddId) => self.submit_whitelist_add_id(),
            Some(Modal::WhitelistCount { id, max_count, .. }) => {
                self.confirm_whitelist_count(id, max_count)
            }
            Some(Modal::WhitelistRemoveEntry { id }) => {
                self.modal = None;
                self.command(&Command::WhitelistRemove(id), "removed from whitelist");
            }
            Some(Modal::Report) => {
                self.modal = None;
                self.report = None;
            }
            Some(Modal::ConfirmConfigSet { row }) => self.confirm_config_set(row),
            Some(Modal::DestroyText { engage }) => self.submit_destroy_text(engage),
            Some(Modal::DestroyConfirm { .. }) => {
                // `Enter` is not a "yes" here — only the `y` key advances step
                // two (handled in `input_char`). Enter cancels.
                self.modal = None;
                self.destroy_target = None;
                self.set_toast("cancelled — LUKS destruction unchanged");
            }
            None => self.select_row(),
        }
    }

    fn select_menu_item(&mut self, item: MenuItem) {
        match item {
            MenuItem::Devices => self.screen = Screen::Devices,
            MenuItem::Whitelist => {
                self.screen = Screen::Whitelist;
                self.whitelist_cursor = 0;
                self.refresh_whitelist();
            }
            MenuItem::DryRun => {
                self.screen = Screen::DryRun;
                self.run_dry_run();
            }
            MenuItem::Settings => {
                self.screen = Screen::Settings;
                self.settings_cursor = 0;
                self.refresh_config();
            }
            MenuItem::EventLog => {
                self.screen = Screen::EventLog;
                self.event_scroll = 0;
                self.events_paused = false;
            }
            MenuItem::Config => {
                self.screen = Screen::Config;
                self.refresh_config();
            }
            MenuItem::LuksDestroy => {
                self.screen = Screen::Destroy;
                self.destroy_scroll = 0;
                // Always work from a fresh snapshot — `engaged` is never
                // persisted and another client may have just changed it.
                self.refresh_config();
            }
            MenuItem::Arm => {
                self.modal = Some(Modal::Confirm {
                    action: ConfirmAction::Arm,
                })
            }
            MenuItem::Disarm => {
                self.modal = Some(Modal::Confirm {
                    action: ConfirmAction::Disarm,
                })
            }
            MenuItem::Reload => {
                self.modal = Some(Modal::Confirm {
                    action: ConfirmAction::Reload,
                })
            }
            MenuItem::Help => {
                self.screen = Screen::Help;
                self.help_scroll = 0;
            }
            MenuItem::Quit => self.should_quit = true,
        }
    }

    /// `Enter` on a list row with no modal open, dispatched by screen.
    fn select_row(&mut self) {
        match self.screen {
            Screen::Devices => self.select_device_row(),
            Screen::Whitelist => self.select_whitelist_row(),
            Screen::Settings => {
                let row = self.settings_cursor;
                self.edit_setting(row);
            }
            Screen::Destroy => self.open_destroy_fence(),
            _ => {}
        }
    }

    // --- devices screen (plan §6) --------------------------------------------

    /// `Enter` on a device row: opens the device action modal, unless the
    /// device has no USB id — nothing to whitelist, since policy can't key on
    /// it either (invariant 7).
    fn select_device_row(&mut self) {
        let Some(d) = self.devices.get(self.device_cursor) else {
            return;
        };
        if d.id.is_none() {
            self.set_toast("device has no USB id — nothing to whitelist");
            return;
        }
        self.modal = Some(Modal::DeviceAction {
            device_index: self.device_cursor,
            cursor: 0,
        });
    }

    /// The device action modal's Enter. Re-reads the device at `device_index`
    /// rather than trusting what was true when the modal opened — the list can
    /// change (a device can be unplugged) while a modal sits open on top of it.
    fn select_device_action(&mut self, device_index: usize, cursor: usize) {
        self.modal = None;
        let Some(d) = self.devices.get(device_index) else {
            self.set_toast("device is no longer connected");
            return;
        };
        // Both option sets are [action, Cancel] — cursor 0 is always the
        // action, anything else is Cancel, i.e. do nothing.
        if cursor != 0 {
            return;
        }
        if d.whitelisted {
            self.modal = Some(Modal::ConfirmRemove { device_index });
        } else {
            self.modal = Some(Modal::WhitelistAddCount {
                device_index,
                max_count: 1,
            });
        }
    }

    fn confirm_device_whitelist_add(&mut self, device_index: usize, max_count: u32) {
        self.modal = None;
        let Some(d) = self.devices.get(device_index) else {
            self.set_toast("device is no longer connected");
            return;
        };
        let Some(id) = d.id else {
            self.set_toast("device is no longer connected");
            return;
        };
        let entry = WhitelistEntry {
            id,
            label: d.label.clone(),
            max_count: Some(max_count),
        };
        self.command(&Command::WhitelistAdd(entry), "added to whitelist");
    }

    fn confirm_device_remove(&mut self, device_index: usize) {
        self.modal = None;
        let Some(id) = self.devices.get(device_index).and_then(|d| d.id) else {
            self.set_toast("device is no longer connected");
            return;
        };
        self.command(&Command::WhitelistRemove(id), "removed from whitelist");
    }

    // --- whitelist screen (plan §5, build step 8) --------------------------

    fn select_whitelist_row(&mut self) {
        if self.whitelist_cursor == 0 {
            self.input.clear();
            self.modal = Some(Modal::WhitelistAddId);
            return;
        }
        let entry_index = self.whitelist_cursor - 1;
        if self.whitelist.get(entry_index).is_some() {
            self.modal = Some(Modal::WhitelistEntryAction {
                entry_index,
                cursor: 0,
            });
        }
    }

    fn select_whitelist_entry_action(&mut self, entry_index: usize, cursor: usize) {
        self.modal = None;
        let Some(e) = self.whitelist.get(entry_index) else {
            self.set_toast("that entry is no longer in the whitelist");
            return;
        };
        let id = e.id;
        let max_count = e.max_count.unwrap_or(1).clamp(1, MAX_WHITELIST_COUNT_UI);
        match cursor {
            0 => {
                self.modal = Some(Modal::WhitelistCount {
                    id,
                    max_count,
                    editing: true,
                })
            }
            1 => self.modal = Some(Modal::WhitelistRemoveEntry { id }),
            _ => {}
        }
    }

    /// `Enter` on the typed `vendor:product` field. A parse failure keeps the
    /// modal open with what was typed so it can be corrected (fail loud, don't
    /// guess — invariant 7's spirit at the UI layer).
    fn submit_whitelist_add_id(&mut self) {
        match UsbId::from_str(self.input.trim()) {
            Ok(id) => {
                self.input.clear();
                self.modal = Some(Modal::WhitelistCount {
                    id,
                    max_count: 1,
                    editing: false,
                });
            }
            Err(_) => {
                self.set_toast("invalid id — expected vendor:product hex, e.g. 1050:0407");
                self.modal = Some(Modal::WhitelistAddId);
            }
        }
    }

    fn confirm_whitelist_count(&mut self, id: UsbId, max_count: u32) {
        self.modal = None;
        // Preserve any existing label — `WhitelistAdd` is an upsert by id, so
        // an edit that only touches the count must not blank the label.
        let label = self
            .whitelist
            .iter()
            .find(|e| e.id == id)
            .and_then(|e| e.label.clone());
        let entry = WhitelistEntry {
            id,
            label,
            max_count: Some(max_count),
        };
        self.command(&Command::WhitelistAdd(entry), "whitelist updated");
    }

    // --- settings screen (plan §5, build step 9) --------------------------

    /// The [`ConfigChange`] a Settings row would apply, derived from the current
    /// config each time (the same value is used to preview the confirm modal and
    /// to send). `None` if no config is loaded or `row` is out of range.
    fn setting_change(&self, row: usize) -> Option<ConfigChange> {
        let cfg = self.config.as_ref()?;
        Some(match row {
            0 => ConfigChange::DryRun(!cfg.dry_run),
            1 => ConfigChange::PowerAction(next_power_action(cfg.power_action)),
            2 => ConfigChange::ArmedAtBoot(!cfg.armed_at_boot),
            3 => ConfigChange::OnSensorGap(next_sensor_gap(cfg.on_sensor_gap)),
            _ => return None,
        })
    }

    fn edit_setting(&mut self, row: usize) {
        let Some(change) = self.setting_change(row) else {
            self.set_toast("no config loaded — press r to retry");
            return;
        };
        if matches!(self.conn, Conn::Down) {
            self.set_toast("daemon unreachable — reconnect before changing settings");
            return;
        }
        // A change that *lowers* protection while armed gets a confirm step,
        // the same as Arm/Disarm/Reload do — one unconfirmed keystroke should
        // not be able to make every kill inert while `armed` still reads true.
        // Everything else stays a single keypress. Unknown armed state counts
        // as armed here — fail closed.
        let armed = self.status.as_ref().is_none_or(|s| s.armed);
        let lowers_protection = matches!(&change, ConfigChange::DryRun(true))
            || matches!(&change, ConfigChange::PowerAction(pa) if *pa != PowerAction::PowerOff)
            || matches!(&change, ConfigChange::OnSensorGap(OnSensorGap::Warn));
        if armed && lowers_protection {
            self.modal = Some(Modal::ConfirmConfigSet { row });
            return;
        }
        self.config_set(change);
    }

    fn confirm_config_set(&mut self, row: usize) {
        self.modal = None;
        match self.setting_change(row) {
            Some(change) => self.config_set(change),
            None => self.set_toast("no config loaded — press r to retry"),
        }
    }

    fn config_set(&mut self, change: ConfigChange) {
        match self.client.call(&Command::ConfigSet(change)) {
            Ok(Reply::Ok) => {
                self.set_toast("setting updated");
                self.refresh_config();
                self.refresh_status();
            }
            Ok(Reply::Error(report)) => {
                // Fail-closed (invariant 2): the daemon wrote and swapped
                // nothing. Show the whole report and re-fetch so the screen
                // reflects the still-running config, not the rejected change.
                self.report = Some(report);
                self.modal = Some(Modal::Report);
                self.refresh_config();
            }
            Ok(other) => self.set_toast(format!("unexpected reply to ConfigSet: {other:?}")),
            Err(e) => self.set_toast(format!("config set: {e}")),
        }
    }

    // --- dry-run screen (plan §5, build step 10) -------------------------

    fn run_dry_run(&mut self) {
        match self.client.call(&Command::RunDryRun) {
            Ok(Reply::DryRun(reasons)) => self.dryrun = Some(reasons),
            Ok(Reply::Error(e)) => self.set_toast(format!("dry run refused: {e}")),
            Ok(other) => self.set_toast(format!("unexpected reply to RunDryRun: {other:?}")),
            Err(e) => self.set_toast(format!("dry run: {e}")),
        }
    }

    // --- LUKS destroy screen (plan §8, build step 12) -------------------

    /// `Enter` on the fenced screen's single action row: open step one of the
    /// typed-`DESTROY` fence. The direction is derived from the *current*
    /// engaged state, so the same row toggles both ways.
    fn open_destroy_fence(&mut self) {
        // Refuse while the daemon is unreachable: the `engaged` state we'd base
        // the toggle direction on is a possibly-stale cache, and
        // `SetLuksDestroyEngaged` can't be delivered anyway (the Destroy screen
        // shows the state as UNKNOWN in this case).
        if matches!(self.conn, Conn::Down) {
            self.set_toast("daemon unreachable — reconnect before changing LUKS destruction");
            return;
        }
        let target = match &self.config {
            None => {
                self.set_toast("no config loaded — press r to retry");
                return;
            }
            Some(cfg) => cfg.luks_destroy.as_ref().map(|l| l.target_header.clone()),
        };
        let Some(target) = target else {
            // The menu item is greyed in this case, but a stale cache could
            // still land us here — refuse rather than open a fence over nothing.
            self.set_toast("LUKS destruction is not configured");
            return;
        };
        self.input.clear();
        // Remember the header the operator is about to confirm — re-checked in
        // `set_luks_destroy_engaged` in case a concurrent config change moves it.
        self.destroy_target = Some(target);
        let engage = !self.luks_engaged();
        self.modal = Some(Modal::DestroyText { engage });
    }

    /// `Enter` on the `DESTROY` text field. Only the exact word (case-sensitive)
    /// advances to the final `y/N`; anything else cancels with nothing sent
    /// (plan §8, charter §4).
    fn submit_destroy_text(&mut self, engage: bool) {
        let typed_the_word = self.input == DESTROY_WORD;
        self.input.clear();
        if typed_the_word {
            self.modal = Some(Modal::DestroyConfirm { engage });
        } else {
            self.modal = None;
            self.destroy_target = None;
            self.set_toast("cancelled — type DESTROY exactly to continue");
        }
    }

    fn set_luks_destroy_engaged(&mut self, engage: bool) {
        // Re-verify the target has not been repointed under the open fence: a
        // `reload` or another root client's `config set` can swap `target_header`
        // (the daemon clears its own engage flag when that happens). The
        // operator confirmed the header shown when the fence opened.
        let captured = self.destroy_target.take();
        let current = self
            .config
            .as_ref()
            .and_then(|c| c.luks_destroy.as_ref())
            .map(|l| l.target_header.clone());
        if captured != current {
            self.set_toast(
                "LUKS target changed while the fence was open — nothing sent, re-open to confirm",
            );
            self.refresh_config();
            return;
        }
        match self.client.call(&Command::SetLuksDestroyEngaged(engage)) {
            Ok(Reply::Ok) => {
                self.set_toast(if engage {
                    "LUKS header destruction ENGAGED (v1: recorded only — the wipe is a stub, \
                     the header is not touched)"
                } else {
                    "LUKS header destruction disengaged"
                });
                self.refresh_config();
                self.refresh_status();
            }
            Ok(Reply::Error(e)) => self.set_toast(format!("refused: {e}")),
            Ok(other) => self.set_toast(format!(
                "unexpected reply to SetLuksDestroyEngaged: {other:?}"
            )),
            Err(e) => self.set_toast(format!("luks engage: {e}")),
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

    /// A daemon-pushed event, with the daemon's own RFC 3339 timestamp
    /// (`se.at`). Recorded in the event-log ring first, then reduced.
    ///
    /// Reducing an event only marks *what* needs re-fetching — the actual
    /// socket round-trips happen once per render tick in [`settle`], so a
    /// backlog-replay burst costs one fetch of each kind, not one per event.
    /// Toasts are set inline: they touch no socket.
    pub fn on_event(&mut self, se: StreamEvent) {
        self.record_event(se.clone());
        match se.event {
            Event::DeviceAdded(_) | Event::DeviceRemoved(_) => {
                self.dirty_devices = true;
                self.dirty_status = true;
            }
            Event::Armed => {
                self.set_toast("Armed");
                self.dirty_status = true;
            }
            Event::Disarmed => {
                self.set_toast("Disarmed");
                self.dirty_status = true;
            }
            Event::WouldKill(reason) => self.set_toast(format!("would kill: {reason}")),
            Event::SensorStopped => {
                self.set_toast("USB sensor stopped — daemon is no longer watching");
                self.dirty_status = true;
            }
            Event::EventsLost => {
                self.set_toast("USB events lost — some device changes were missed");
                self.dirty_status = true;
            }
            Event::WhitelistChanged => {
                // `DeviceInfo.whitelisted` and the Whitelist screen are both
                // derived from it; re-fetch everything it touches (this
                // client's change or another's).
                self.set_toast("whitelist changed");
                self.dirty_devices = true;
                self.dirty_whitelist = true;
                self.dirty_status = true;
            }
            Event::ConfigChanged => {
                self.set_toast("config changed");
                self.dirty_config = true;
                self.dirty_status = true;
            }
            Event::ReloadFailed(reason) => {
                self.set_toast(format!("reload failed: {reason}"));
                self.dirty_status = true;
            }
            // `Event` is `#[non_exhaustive]`: a newer daemon may push a variant
            // this build predates. Surface it rather than silently drop it.
            other => self.set_toast(format!("event: {other:?}")),
        }
    }

    /// Service the dirty flags set since the last tick: at most one fetch of
    /// each kind, no matter how many events asked for it. Called by the render
    /// loop right after it drains the daemon-event channel. Order: status
    /// first (cheapest, always wanted), then the screen data.
    pub fn settle(&mut self) {
        if std::mem::take(&mut self.dirty_status) {
            self.refresh_status();
        }
        if std::mem::take(&mut self.dirty_devices) {
            self.refresh_devices();
        }
        if std::mem::take(&mut self.dirty_whitelist) {
            self.refresh_whitelist();
        }
        if std::mem::take(&mut self.dirty_config) {
            self.refresh_config();
        }
    }

    fn record_event(&mut self, se: StreamEvent) {
        self.events.push_back(se);
        while self.events.len() > EVENT_LOG_CAP {
            self.events.pop_front();
        }
        if matches!(self.screen, Screen::EventLog) {
            if self.events_paused {
                // Keep the viewport visually stable as new lines push in below,
                // with the same `len - 1` cap as the manual scroll above.
                self.event_scroll =
                    (self.event_scroll + 1).min(self.events.len().saturating_sub(1));
            } else {
                self.event_scroll = 0;
            }
        }
    }

    // --- fetches --------------------------------------------------------

    fn refresh(&mut self) {
        self.refresh_status();
        match self.screen {
            Screen::Devices => self.refresh_devices(),
            Screen::Whitelist => self.refresh_whitelist(),
            Screen::Settings | Screen::Config | Screen::Destroy => self.refresh_config(),
            Screen::DryRun => self.run_dry_run(),
            Screen::EventLog | Screen::Help => {}
        }
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
                clamp_cursor(&mut self.device_cursor, self.devices.len());
            }
            Ok(other) => self.set_toast(format!("unexpected reply to ListDevices: {other:?}")),
            Err(e) => self.set_toast(format!("devices: {e}")),
        }
    }

    fn refresh_whitelist(&mut self) {
        match self.client.call(&Command::WhitelistList) {
            Ok(Reply::Whitelist(w)) => {
                self.whitelist = w;
                // +1 for the always-present "add entry" row.
                clamp_cursor(&mut self.whitelist_cursor, self.whitelist.len() + 1);
            }
            Ok(other) => self.set_toast(format!("unexpected reply to WhitelistList: {other:?}")),
            Err(e) => self.set_toast(format!("whitelist: {e}")),
        }
    }

    fn refresh_config(&mut self) {
        match self.client.call(&Command::GetConfig) {
            Ok(Reply::Config(c)) => self.config = Some(c),
            Ok(other) => self.set_toast(format!("unexpected reply to GetConfig: {other:?}")),
            Err(e) => self.set_toast(format!("config: {e}")),
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
        // A toast is a single transient line. Daemon-origin strings
        // (`ReloadFailed`, a rejected `ConfigSet`) can be a whole multi-line
        // validation report — keep the first line, scrub stray control bytes,
        // and point at the screen that shows the rest.
        let raw = msg.into();
        let first = raw.lines().next().unwrap_or_default();
        let mut text: String = first
            .chars()
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .collect();
        if raw.lines().nth(1).is_some() {
            text.push_str(" … (see the screen for the full report)");
        }
        self.toast = Some((text, Instant::now()));
    }

    pub fn expire_toast(&mut self, now: Instant) {
        if let Some((_, shown_at)) = &self.toast {
            if now.duration_since(*shown_at) > TOAST_TTL {
                self.toast = None;
            }
        }
    }
}

/// Move `cursor` by `delta` within `0..len`, wrapping. No-op if `len == 0`.
fn wrap(cursor: &mut usize, delta: i32, len: usize) {
    if len == 0 {
        *cursor = 0;
        return;
    }
    let n = len as i32;
    *cursor = (*cursor as i32 + delta).rem_euclid(n) as usize;
}

/// Keep `cursor` inside `0..len` after the backing list shrank.
fn clamp_cursor(cursor: &mut usize, len: usize) {
    let last = len.saturating_sub(1);
    if *cursor > last {
        *cursor = last;
    }
}

fn next_power_action(p: PowerAction) -> PowerAction {
    match p {
        PowerAction::PowerOff => PowerAction::Halt,
        PowerAction::Halt => PowerAction::None,
        PowerAction::None => PowerAction::PowerOff,
        // `PowerAction` is `#[non_exhaustive]`; a variant this build predates
        // cycles back to the safe default.
        _ => PowerAction::PowerOff,
    }
}

fn next_sensor_gap(g: OnSensorGap) -> OnSensorGap {
    match g {
        OnSensorGap::Warn => OnSensorGap::Kill,
        OnSensorGap::Kill => OnSensorGap::Warn,
        _ => OnSensorGap::Warn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ScriptedClient;
    use killbill_proto::UsbId;

    fn app(replies: Vec<anyhow::Result<Reply>>) -> App<ScriptedClient> {
        App::new(ScriptedClient::new(replies))
    }

    fn stream_event(event: Event) -> StreamEvent {
        StreamEvent {
            at: "2024-01-02T03:04:05Z".to_owned(),
            event,
        }
    }

    fn status(armed: bool) -> StatusPayload {
        StatusPayload {
            armed,
            dry_run: false,
            power_action: killbill_proto::PowerAction::PowerOff,
            whitelist_len: 0,
            device_count: 0,
            config_error: None,
            sensor_ok: true,
            events_lost: false,
            config_stale: false,
        }
    }

    fn config() -> ConfigPayload {
        ConfigPayload {
            armed_at_boot: false,
            sensors: vec!["usb".to_owned()],
            dry_run: false,
            power_action: PowerAction::PowerOff,
            on_sensor_gap: OnSensorGap::Warn,
            luks_destroy: None,
            validation_error: None,
        }
    }

    fn config_with_luks(engaged: bool) -> ConfigPayload {
        config_with_luks_target("/dev/nvme0n1p3", engaged)
    }

    fn config_with_luks_target(target: &str, engaged: bool) -> ConfigPayload {
        ConfigPayload {
            luks_destroy: Some(killbill_proto::LuksDestroyInfo {
                acknowledged: true,
                target_header: target.to_owned(),
                engaged,
            }),
            ..config()
        }
    }

    fn device(id: Option<UsbId>, whitelisted: bool) -> DeviceInfo {
        DeviceInfo {
            source: killbill_proto::SensorSource::Usb,
            id,
            serial: None,
            label: None,
            whitelisted,
        }
    }

    fn wl(id: UsbId, max: u32) -> WhitelistEntry {
        WhitelistEntry {
            id,
            label: None,
            max_count: Some(max),
        }
    }

    #[test]
    fn on_connected_refreshes_status_and_devices_with_no_socket() {
        let mut a = app(vec![
            Ok(Reply::Status(status(true))),
            Ok(Reply::Devices(Vec::new())),
        ]);
        a.on_connected();
        assert_eq!(a.conn, Conn::Up);
        assert!(a.conn_error.is_none());
        assert!(a.status.is_some_and(|s| s.armed));
    }

    #[test]
    fn on_disconnected_sets_conn_down_and_keeps_the_reason() {
        let mut a = app(vec![]);
        a.on_disconnected("the daemon closed the event stream".to_owned());
        assert_eq!(a.conn, Conn::Down);
        assert_eq!(
            a.conn_error.as_deref(),
            Some("the daemon closed the event stream")
        );
    }

    #[test]
    fn armed_event_sets_a_toast_and_settle_refreshes_status() {
        let mut a = app(vec![Ok(Reply::Status(status(true)))]);
        a.on_event(stream_event(Event::Armed));
        assert!(a.toast.is_some(), "the toast is set inline");
        assert!(a.client.calls.is_empty(), "no fetch until settle");
        a.settle();
        assert!(a.status.is_some_and(|s| s.armed));
    }

    #[test]
    fn device_added_settles_to_one_status_then_one_devices_fetch() {
        let dev = device(Some(UsbId::new(0x1050, 0x0407)), false);
        let mut a = app(vec![
            Ok(Reply::Status(status(false))),
            Ok(Reply::Devices(vec![dev])),
        ]);
        a.on_event(stream_event(Event::DeviceAdded(device(None, false))));
        assert!(
            a.client.calls.is_empty(),
            "on_event never touches the socket"
        );
        a.settle();
        // `settle`'s fixed order: status first, then the screen data.
        assert_eq!(
            a.client.calls,
            vec![Command::GetStatus, Command::ListDevices]
        );
        assert_eq!(a.devices.len(), 1);
        assert!(a.status.is_some());
    }

    #[test]
    fn reload_failed_event_sets_a_toast_naming_the_reason() {
        let mut a = app(vec![Ok(Reply::Status(status(false)))]);
        a.on_event(stream_event(Event::ReloadFailed(
            "config on disk is invalid".to_owned(),
        )));
        let (msg, _) = a.toast.clone().expect("a toast was set");
        assert!(msg.contains("config on disk is invalid"), "got: {msg}");
        a.settle();
        assert_eq!(a.client.calls, vec![Command::GetStatus]);
    }

    #[test]
    fn a_backlog_burst_coalesces_to_one_fetch_of_each_kind() {
        let mut a = app(vec![
            Ok(Reply::Status(status(false))),
            Ok(Reply::Devices(Vec::new())),
            Ok(Reply::Whitelist(Vec::new())),
        ]);
        for _ in 0..50 {
            a.on_event(stream_event(Event::DeviceAdded(device(None, false))));
            a.on_event(stream_event(Event::WhitelistChanged));
        }
        assert!(
            a.client.calls.is_empty(),
            "no socket traffic during the burst"
        );
        a.settle();
        assert_eq!(
            a.client.calls,
            vec![
                Command::GetStatus,
                Command::ListDevices,
                Command::WhitelistList
            ]
        );
    }

    #[test]
    fn a_transport_error_sets_a_toast_not_a_panic() {
        let mut a = app(vec![Err(anyhow::anyhow!(
            "the daemon closed the connection"
        ))]);
        a.refresh_status();
        assert!(a.toast.is_some());
    }

    #[test]
    fn command_reports_a_refusal_and_still_refreshes_status() {
        let mut a = app(vec![
            Ok(Reply::Error("refusing to arm: config invalid".to_owned())),
            Ok(Reply::Status(status(false))),
        ]);
        a.command(&Command::Arm, "armed");
        let (msg, _) = a.toast.expect("a toast was set");
        assert!(msg.contains("refusing to arm"), "got: {msg}");
        assert!(a.status.is_some());
    }

    #[test]
    fn menu_order_is_complete_and_unique() {
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

    // --- plan §6: device action modal / plug-and-whitelist -----------------

    #[test]
    fn enter_on_a_device_row_opens_the_device_action_modal() {
        let mut a = app(vec![]);
        a.devices = vec![device(Some(UsbId::new(0x1050, 0x0407)), false)];
        a.handle(Intent::Select);
        assert!(matches!(
            a.modal,
            Some(Modal::DeviceAction {
                device_index: 0,
                cursor: 0
            })
        ));
    }

    #[test]
    fn enter_on_a_device_with_no_usb_id_toasts_instead_of_opening_a_modal() {
        let mut a = app(vec![]);
        a.devices = vec![device(None, false)];
        a.handle(Intent::Select);
        assert!(a.modal.is_none());
        let (msg, _) = a.toast.expect("a toast was set");
        assert!(msg.contains("no USB id"), "got: {msg}");
    }

    #[test]
    fn device_action_add_option_opens_the_whitelist_add_count_modal() {
        let mut a = app(vec![]);
        a.devices = vec![device(Some(UsbId::new(0x1050, 0x0407)), false)];
        a.modal = Some(Modal::DeviceAction {
            device_index: 0,
            cursor: 0,
        });
        a.handle(Intent::Select);
        assert!(matches!(
            a.modal,
            Some(Modal::WhitelistAddCount {
                device_index: 0,
                max_count: 1
            })
        ));
    }

    #[test]
    fn device_action_cancel_option_closes_the_modal_without_a_command() {
        let mut a = app(vec![]);
        a.devices = vec![device(Some(UsbId::new(0x1050, 0x0407)), false)];
        a.modal = Some(Modal::DeviceAction {
            device_index: 0,
            cursor: 1,
        });
        a.handle(Intent::Select);
        assert!(a.modal.is_none());
    }

    #[test]
    fn whitelist_add_count_stepper_stays_within_one_and_the_ui_cap() {
        let mut a = app(vec![]);
        a.modal = Some(Modal::WhitelistAddCount {
            device_index: 0,
            max_count: 1,
        });
        a.handle(Intent::Up);
        assert!(matches!(
            a.modal,
            Some(Modal::WhitelistAddCount { max_count: 2, .. })
        ));
        a.handle(Intent::Down);
        a.handle(Intent::Down);
        assert!(matches!(
            a.modal,
            Some(Modal::WhitelistAddCount { max_count: 1, .. })
        ));
    }

    #[test]
    fn confirming_whitelist_add_sends_the_chosen_id_and_count() {
        let id = UsbId::new(0x1050, 0x0407);
        let mut a = app(vec![Ok(Reply::Ok), Ok(Reply::Status(status(false)))]);
        a.devices = vec![device(Some(id), false)];
        a.modal = Some(Modal::WhitelistAddCount {
            device_index: 0,
            max_count: 3,
        });
        a.handle(Intent::Select);
        assert!(a.modal.is_none());
        assert!(matches!(
            a.client.calls.as_slice(),
            [Command::WhitelistAdd(entry), Command::GetStatus]
                if entry.id == id && entry.max_count == Some(3)
        ));
        let (msg, _) = a.toast.expect("a toast was set");
        assert!(msg.contains("added"), "got: {msg}");
    }

    #[test]
    fn device_action_remove_option_opens_a_confirm_for_a_whitelisted_device() {
        let mut a = app(vec![]);
        a.devices = vec![device(Some(UsbId::new(0x1050, 0x0407)), true)];
        a.modal = Some(Modal::DeviceAction {
            device_index: 0,
            cursor: 0,
        });
        a.handle(Intent::Select);
        assert!(matches!(
            a.modal,
            Some(Modal::ConfirmRemove { device_index: 0 })
        ));
    }

    #[test]
    fn confirming_remove_sends_whitelist_remove_for_that_id() {
        let id = UsbId::new(0x1050, 0x0407);
        let mut a = app(vec![Ok(Reply::Ok), Ok(Reply::Status(status(false)))]);
        a.devices = vec![device(Some(id), true)];
        a.modal = Some(Modal::ConfirmRemove { device_index: 0 });
        a.handle(Intent::Select);
        assert!(a.modal.is_none());
        assert_eq!(
            a.client.calls,
            vec![Command::WhitelistRemove(id), Command::GetStatus]
        );
    }

    #[test]
    fn a_device_that_vanished_while_a_modal_was_open_is_reported_not_acted_on() {
        let mut a = app(vec![]);
        a.devices = Vec::new();
        a.modal = Some(Modal::WhitelistAddCount {
            device_index: 0,
            max_count: 1,
        });
        a.handle(Intent::Select);
        assert!(a.modal.is_none());
        assert!(a.client.calls.is_empty());
        assert!(a.toast.is_some());
    }

    #[test]
    fn whitelist_changed_event_refreshes_devices_whitelist_and_status() {
        let dev = device(Some(UsbId::new(0x1050, 0x0407)), true);
        let mut a = app(vec![
            Ok(Reply::Status(status(false))),
            Ok(Reply::Devices(vec![dev])),
            Ok(Reply::Whitelist(vec![wl(UsbId::new(0x1050, 0x0407), 1)])),
        ]);
        a.on_event(stream_event(Event::WhitelistChanged));
        a.settle();
        assert_eq!(a.devices.len(), 1);
        assert_eq!(a.whitelist.len(), 1);
        assert!(a.status.is_some());
    }

    // --- plan §7 (build step 7): arm / disarm / reload confirm modals ------

    #[test]
    fn menu_arm_opens_a_confirm_modal_and_fires_nothing_yet() {
        let mut a = app(vec![]);
        a.select_menu_item(MenuItem::Arm);
        assert!(matches!(
            a.modal,
            Some(Modal::Confirm {
                action: ConfirmAction::Arm
            })
        ));
        assert!(a.client.calls.is_empty(), "no command before the confirm");
    }

    #[test]
    fn menu_disarm_confirm_then_select_sends_disarm() {
        let mut a = app(vec![Ok(Reply::Ok), Ok(Reply::Status(status(false)))]);
        a.select_menu_item(MenuItem::Disarm);
        a.handle(Intent::Select);
        assert!(a.modal.is_none());
        assert_eq!(a.client.calls, vec![Command::Disarm, Command::GetStatus]);
    }

    #[test]
    fn a_confirm_modal_is_dismissed_by_back_without_a_command() {
        let mut a = app(vec![]);
        a.select_menu_item(MenuItem::Reload);
        a.handle(Intent::Back);
        assert!(a.modal.is_none());
        assert!(a.client.calls.is_empty());
    }

    // --- plan §5 (build step 8): whitelist screen -------------------------

    #[test]
    fn whitelist_row_zero_opens_the_add_id_field() {
        let mut a = app(vec![]);
        a.screen = Screen::Whitelist;
        a.whitelist = vec![wl(UsbId::new(0x1050, 0x0407), 1)];
        a.whitelist_cursor = 0;
        a.handle(Intent::Select);
        assert!(matches!(a.modal, Some(Modal::WhitelistAddId)));
    }

    #[test]
    fn typing_a_valid_id_then_enter_moves_to_the_count_picker() {
        let mut a = app(vec![]);
        a.modal = Some(Modal::WhitelistAddId);
        for c in "1050:0407".chars() {
            a.handle(Intent::Char(c));
        }
        assert_eq!(a.input, "1050:0407");
        a.handle(Intent::Select);
        assert!(matches!(
            a.modal,
            Some(Modal::WhitelistCount {
                id,
                max_count: 1,
                editing: false
            }) if id == UsbId::new(0x1050, 0x0407)
        ));
        assert!(a.input.is_empty());
    }

    #[test]
    fn the_add_id_field_rejects_non_hex_and_a_second_colon() {
        let mut a = app(vec![]);
        a.modal = Some(Modal::WhitelistAddId);
        for c in "10:50:zz".chars() {
            a.handle(Intent::Char(c));
        }
        assert_eq!(a.input, "10:50");
    }

    #[test]
    fn an_unparseable_id_keeps_the_field_open_with_a_toast() {
        let mut a = app(vec![]);
        a.modal = Some(Modal::WhitelistAddId);
        for c in "10".chars() {
            a.handle(Intent::Char(c));
        }
        a.handle(Intent::Select);
        assert!(matches!(a.modal, Some(Modal::WhitelistAddId)));
        let (msg, _) = a.toast.expect("a toast was set");
        assert!(msg.contains("invalid id"), "got: {msg}");
    }

    #[test]
    fn confirming_the_count_picker_upserts_and_preserves_an_existing_label() {
        let id = UsbId::new(0x1050, 0x0407);
        let mut a = app(vec![Ok(Reply::Ok), Ok(Reply::Status(status(false)))]);
        a.whitelist = vec![WhitelistEntry {
            id,
            label: Some("YubiKey".to_owned()),
            max_count: Some(1),
        }];
        a.modal = Some(Modal::WhitelistCount {
            id,
            max_count: 4,
            editing: true,
        });
        a.handle(Intent::Select);
        assert!(matches!(
            a.client.calls.as_slice(),
            [Command::WhitelistAdd(e), Command::GetStatus]
                if e.id == id && e.max_count == Some(4) && e.label.as_deref() == Some("YubiKey")
        ));
    }

    #[test]
    fn whitelist_entry_action_remove_confirm_sends_whitelist_remove() {
        let id = UsbId::new(0x1050, 0x0407);
        let mut a = app(vec![Ok(Reply::Ok), Ok(Reply::Status(status(false)))]);
        a.screen = Screen::Whitelist;
        a.whitelist = vec![wl(id, 1)];
        a.whitelist_cursor = 1;
        a.handle(Intent::Select); // opens WhitelistEntryAction
        a.handle(Intent::Down); // cursor 0 -> 1 ("Remove from whitelist")
        a.handle(Intent::Select); // opens WhitelistRemoveEntry
        assert!(matches!(a.modal, Some(Modal::WhitelistRemoveEntry { .. })));
        a.handle(Intent::Select); // confirm
        assert_eq!(
            a.client.calls,
            vec![Command::WhitelistRemove(id), Command::GetStatus]
        );
    }

    #[test]
    fn whitelist_entry_action_on_a_vanished_entry_is_reported_not_acted_on() {
        let mut a = app(vec![]);
        a.whitelist = Vec::new();
        a.modal = Some(Modal::WhitelistEntryAction {
            entry_index: 3,
            cursor: 0,
        });
        a.handle(Intent::Select);
        assert!(a.modal.is_none());
        assert!(a.client.calls.is_empty());
        assert!(a.toast.is_some());
    }

    // --- plan §5 (build step 9): settings screen -------------------------

    #[test]
    fn settings_toggle_dry_run_sends_config_set_with_the_flipped_value() {
        let mut a = app(vec![
            Ok(Reply::Ok),
            Ok(Reply::Config(config())),
            Ok(Reply::Status(status(false))),
        ]);
        a.config = Some(config()); // dry_run = false
        a.status = Some(status(false)); // disarmed — no confirm step
        a.screen = Screen::Settings;
        a.settings_cursor = 0;
        a.handle(Intent::Select);
        assert_eq!(
            a.client.calls[0],
            Command::ConfigSet(ConfigChange::DryRun(true))
        );
    }

    #[test]
    fn settings_cycle_power_action_goes_poweroff_then_halt() {
        let mut a = app(vec![
            Ok(Reply::Ok),
            Ok(Reply::Config(config())),
            Ok(Reply::Status(status(false))),
        ]);
        a.config = Some(config()); // power_action = PowerOff
        a.status = Some(status(false)); // disarmed — no confirm step
        a.screen = Screen::Settings;
        a.settings_cursor = 1;
        a.handle(Intent::Select);
        assert_eq!(
            a.client.calls[0],
            Command::ConfigSet(ConfigChange::PowerAction(PowerAction::Halt))
        );
    }

    #[test]
    fn a_rejected_config_set_shows_the_report_and_re_fetches_the_running_config() {
        let mut running = config();
        running.dry_run = false;
        let mut a = app(vec![
            Ok(Reply::Error(
                "power_action = none is unsafe here".to_owned(),
            )),
            Ok(Reply::Config(running.clone())),
        ]);
        a.config = Some(running);
        a.status = Some(status(false)); // disarmed — the change goes straight through
        a.screen = Screen::Settings;
        a.settings_cursor = 0;
        a.handle(Intent::Select);
        assert!(matches!(a.modal, Some(Modal::Report)));
        assert_eq!(
            a.report.as_deref(),
            Some("power_action = none is unsafe here")
        );
        // Reverted: the screen still shows the running config, unchanged.
        assert!(a.config.is_some_and(|c| !c.dry_run));
    }

    #[test]
    fn the_report_modal_is_dismissed_by_select() {
        let mut a = app(vec![]);
        a.modal = Some(Modal::Report);
        a.report = Some("something".to_owned());
        a.handle(Intent::Select);
        assert!(a.modal.is_none());
        assert!(a.report.is_none());
    }

    // --- plan §5 (build step 10): dry-run + event log --------------------

    #[test]
    fn entering_the_dry_run_screen_runs_one_and_stores_the_reasons() {
        let reason = KillReason::UnknownDevice {
            id: UsbId::new(0x0781, 0x5567),
        };
        let mut a = app(vec![Ok(Reply::DryRun(vec![reason.clone()]))]);
        a.select_menu_item(MenuItem::DryRun);
        assert!(matches!(a.screen, Screen::DryRun));
        assert_eq!(a.dryrun.as_deref(), Some([reason].as_slice()));
    }

    #[test]
    fn the_event_log_ring_records_every_event_and_caps_its_length() {
        // `on_event` only records + marks dirty now — no socket, no scripted
        // replies needed.
        let mut a = app(vec![]);
        for _ in 0..EVENT_LOG_CAP + 50 {
            a.on_event(stream_event(Event::Armed));
        }
        assert_eq!(a.events.len(), EVENT_LOG_CAP);
        assert!(a.client.calls.is_empty());
    }

    #[test]
    fn scrolling_the_event_log_up_pauses_follow_and_back_down_resumes_it() {
        let mut a = app(vec![]);
        a.screen = Screen::EventLog;
        a.events = (0..5).map(|_| stream_event(Event::Armed)).collect();
        a.handle(Intent::Up);
        assert!(a.events_paused);
        assert_eq!(a.event_scroll, 1);
        a.handle(Intent::Down);
        assert_eq!(a.event_scroll, 0);
        assert!(!a.events_paused);
    }

    #[test]
    fn event_log_scroll_stops_at_the_oldest_line() {
        let mut a = app(vec![]);
        a.screen = Screen::EventLog;
        a.events = (0..5).map(|_| stream_event(Event::Armed)).collect();
        for _ in 0..100 {
            a.handle(Intent::Up);
        }
        // Capped at `len - 1` so the oldest line stays on screen, never a
        // blank window past it.
        assert_eq!(a.event_scroll, 4);
    }

    #[test]
    fn p_toggles_the_event_log_pause_only_on_that_screen() {
        let mut a = app(vec![]);
        a.screen = Screen::Devices;
        a.handle(Intent::TogglePause);
        assert!(!a.events_paused, "no effect off the event log");
        a.screen = Screen::EventLog;
        a.handle(Intent::TogglePause);
        assert!(a.events_paused);
    }

    // --- plan §5 / §8 (build step 11–12): config, help, LUKS destroy -----

    #[test]
    fn menu_config_opens_the_read_only_inspector_and_fetches_config() {
        let mut a = app(vec![Ok(Reply::Config(config()))]);
        a.select_menu_item(MenuItem::Config);
        assert!(matches!(a.screen, Screen::Config));
        assert_eq!(a.client.calls, vec![Command::GetConfig]);
    }

    #[test]
    fn the_help_key_opens_the_help_screen_from_anywhere() {
        let mut a = app(vec![]);
        a.screen = Screen::Settings;
        a.modal = Some(Modal::Report);
        a.handle(Intent::Help);
        assert!(matches!(a.screen, Screen::Help));
        assert!(a.modal.is_none());
    }

    #[test]
    fn menu_luks_destroy_opens_the_fenced_screen_and_refetches_config() {
        let mut a = app(vec![Ok(Reply::Config(config_with_luks(false)))]);
        a.select_menu_item(MenuItem::LuksDestroy);
        assert!(matches!(a.screen, Screen::Destroy));
        assert_eq!(a.client.calls, vec![Command::GetConfig]);
    }

    #[test]
    fn destroy_enter_opens_the_fence_toward_the_opposite_of_the_current_state() {
        let mut a = app(vec![]);
        a.screen = Screen::Destroy;

        a.config = Some(config_with_luks(false));
        a.handle(Intent::Select);
        assert!(matches!(a.modal, Some(Modal::DestroyText { engage: true })));

        a.modal = None;
        a.config = Some(config_with_luks(true));
        a.handle(Intent::Select);
        assert!(matches!(
            a.modal,
            Some(Modal::DestroyText { engage: false })
        ));
    }

    #[test]
    fn destroy_fence_refuses_while_the_daemon_is_unreachable() {
        let mut a = app(vec![]);
        a.screen = Screen::Destroy;
        a.config = Some(config_with_luks(false));
        a.on_disconnected("the daemon closed the connection".to_owned());
        a.handle(Intent::Select);
        assert!(a.modal.is_none(), "no fence opens while the daemon is down");
        assert!(a.client.calls.is_empty());
        let (msg, _) = a.toast.expect("a toast was set");
        assert!(msg.contains("unreachable"), "got: {msg}");
    }

    #[test]
    fn destroy_fence_refuses_when_luks_is_not_configured() {
        let mut a = app(vec![]);
        a.screen = Screen::Destroy;
        a.config = Some(config()); // luks_destroy: None
        a.handle(Intent::Select);
        assert!(a.modal.is_none());
        assert!(a.client.calls.is_empty());
        let (msg, _) = a.toast.expect("a toast was set");
        assert!(msg.contains("not configured"), "got: {msg}");
    }

    #[test]
    fn destroy_fence_rejects_a_wrong_word_and_sends_nothing() {
        let mut a = app(vec![]);
        a.screen = Screen::Destroy;
        a.config = Some(config_with_luks(false));
        a.handle(Intent::Select); // Modal::DestroyText { engage: true }
        for c in "destroy".chars() {
            a.handle(Intent::Char(c)); // lowercase — the fence is case-sensitive
        }
        assert_eq!(a.input, "destroy");
        a.handle(Intent::Select);
        assert!(a.modal.is_none(), "a wrong word cancels the fence");
        assert!(a.client.calls.is_empty());
        assert!(a.input.is_empty());
        let (msg, _) = a.toast.expect("a toast was set");
        assert!(msg.contains("DESTROY"), "got: {msg}");
    }

    #[test]
    fn destroy_fence_needs_the_exact_word_then_y_to_engage() {
        let mut a = app(vec![
            Ok(Reply::Ok),
            Ok(Reply::Config(config_with_luks(true))),
            Ok(Reply::Status(status(true))),
        ]);
        a.screen = Screen::Destroy;
        a.config = Some(config_with_luks(false));
        a.handle(Intent::Select);
        for c in "DESTROY".chars() {
            a.handle(Intent::Char(c));
        }
        a.handle(Intent::Select); // word accepted -> step two
        assert!(matches!(
            a.modal,
            Some(Modal::DestroyConfirm { engage: true })
        ));
        a.handle(Intent::Char('y'));
        assert!(a.modal.is_none());
        assert_eq!(a.client.calls[0], Command::SetLuksDestroyEngaged(true));
        assert!(a.luks_engaged(), "the re-fetch reflects the new state");
    }

    #[test]
    fn destroy_fence_step_two_cancels_on_any_key_but_y() {
        for cancel in [
            Intent::Char('n'),
            Intent::Char('x'),
            Intent::Select,
            Intent::Back,
        ] {
            let mut a = app(vec![]);
            a.modal = Some(Modal::DestroyConfirm { engage: true });
            a.handle(cancel);
            assert!(a.modal.is_none());
            assert!(a.client.calls.is_empty(), "nothing sent on cancel");
        }
    }

    #[test]
    fn destroy_fence_step_two_also_accepts_capital_y() {
        let mut a = app(vec![
            Ok(Reply::Ok),
            Ok(Reply::Config(config_with_luks(false))),
            Ok(Reply::Status(status(false))),
        ]);
        a.screen = Screen::Destroy;
        a.config = Some(config_with_luks(true)); // engaged -> the fence disengages
        a.handle(Intent::Select);
        for c in "DESTROY".chars() {
            a.handle(Intent::Char(c));
        }
        a.handle(Intent::Select); // -> DestroyConfirm { engage: false }
        a.handle(Intent::Char('Y'));
        assert_eq!(a.client.calls[0], Command::SetLuksDestroyEngaged(false));
    }

    #[test]
    fn destroy_fence_aborts_if_the_target_was_repointed_while_it_was_open() {
        // Client-side twin of the daemon's `swap_config` retarget clearing: a
        // concurrent `reload`/`config set` moves `target_header` under the open
        // fence. The operator confirmed the old header — nothing must be sent.
        let mut a = app(vec![Ok(Reply::Config(config_with_luks_target(
            "/dev/sdb", false,
        )))]);
        a.screen = Screen::Destroy;
        a.config = Some(config_with_luks_target("/dev/nvme0n1p3", false));
        a.handle(Intent::Select); // captures /dev/nvme0n1p3
                                  // ...target repointed under the fence (e.g. an Event::ConfigChanged).
        a.config = Some(config_with_luks_target("/dev/sdb", false));
        for c in "DESTROY".chars() {
            a.handle(Intent::Char(c));
        }
        a.handle(Intent::Select); // -> DestroyConfirm
        a.handle(Intent::Char('y'));
        assert!(a.modal.is_none());
        assert!(
            !a.client
                .calls
                .iter()
                .any(|c| matches!(c, Command::SetLuksDestroyEngaged(_))),
            "must not engage for a target the operator never confirmed"
        );
        let (msg, _) = a.toast.expect("a toast was set");
        assert!(msg.contains("target changed"), "got: {msg}");
    }

    // --- kill-path review H2: protection-lowering config changes -----------

    #[test]
    fn enabling_dry_run_while_armed_asks_to_confirm_first() {
        let mut a = app(vec![
            Ok(Reply::Ok),
            Ok(Reply::Config(config())),
            Ok(Reply::Status(status(true))),
        ]);
        a.conn = Conn::Up;
        a.config = Some(config()); // dry_run = false
        a.status = Some(status(true)); // armed
        a.screen = Screen::Settings;
        a.settings_cursor = 0;
        a.handle(Intent::Select);
        assert!(matches!(a.modal, Some(Modal::ConfirmConfigSet { row: 0 })));
        assert!(a.client.calls.is_empty(), "nothing sent before the confirm");
        a.handle(Intent::Select);
        assert_eq!(
            a.client.calls[0],
            Command::ConfigSet(ConfigChange::DryRun(true))
        );
    }

    #[test]
    fn a_settings_change_that_does_not_lower_protection_stays_one_keystroke_while_armed() {
        let mut a = app(vec![
            Ok(Reply::Ok),
            Ok(Reply::Config(config())),
            Ok(Reply::Status(status(true))),
        ]);
        a.conn = Conn::Up;
        a.config = Some(config());
        a.status = Some(status(true));
        a.screen = Screen::Settings;
        a.settings_cursor = 2; // armed-at-boot
        a.handle(Intent::Select);
        assert_eq!(
            a.client.calls[0],
            Command::ConfigSet(ConfigChange::ArmedAtBoot(true))
        );
    }

    #[test]
    fn a_settings_edit_is_refused_while_the_daemon_is_unreachable() {
        let mut a = app(vec![]);
        a.config = Some(config());
        a.screen = Screen::Settings;
        a.on_disconnected("gone".to_owned());
        a.settings_cursor = 0;
        a.handle(Intent::Select);
        assert!(a.client.calls.is_empty());
        assert!(a.modal.is_none());
        let (msg, _) = a.toast.expect("a toast was set");
        assert!(msg.contains("unreachable"), "got: {msg}");
    }

    #[test]
    fn help_scroll_stops_at_the_end_of_the_content() {
        let mut a = app(vec![]);
        a.screen = Screen::Help;
        for _ in 0..10_000 {
            a.handle(Intent::Down);
        }
        assert!(a.help_scroll > 0);
        assert!(a.help_scroll < crate::ui::help_line_count());
    }

    #[test]
    fn destroy_screen_scrolls_and_clamps_to_the_content() {
        let mut a = app(vec![]);
        a.conn = Conn::Up;
        a.screen = Screen::Destroy;
        a.config = Some(config_with_luks(false));
        for _ in 0..10_000 {
            a.handle(Intent::Down);
        }
        let count = crate::ui::destroy_line_count(&a);
        assert!(a.destroy_scroll > 0, "it scrolled");
        assert!(
            a.destroy_scroll < count,
            "scroll {} stays under the {count}-line body",
            a.destroy_scroll
        );
    }
}
