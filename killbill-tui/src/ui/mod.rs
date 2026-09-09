//! Rendering. `draw` is the whole frame: the status band, the active screen,
//! the hint line, then any modal and any transient overlay on top.
//!
//! Everything below reads from [`App`] and never mutates it.

mod config;
mod destroy;
mod devices;
mod dryrun;
mod eventlog;
mod help;
mod settings;
mod statusbar;
mod whitelist;

use killbill_proto::{sanitize_device_string, UsbId};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{
    device_action_labels, whitelist_entry_action_labels, App, ConfirmAction, Conn, MenuItem, Modal,
    Screen,
};

/// Total lines the Help screen renders — the reducer clamps `help_scroll` to it.
pub(crate) fn help_line_count() -> u16 {
    help::line_count()
}

/// Below this the layout can't be trusted; show a single message instead
/// (plan §9).
const MIN_W: u16 = 60;
const MIN_H: u16 = 18;

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width < MIN_W || area.height < MIN_H {
        too_small(frame, area);
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status band
            Constraint::Min(1),    // active screen
            Constraint::Length(1), // hint line
        ])
        .split(area);

    statusbar::render(frame, rows[0], app);

    match app.screen {
        Screen::Devices => devices::render(frame, rows[1], app),
        Screen::Whitelist => whitelist::render(frame, rows[1], app),
        Screen::DryRun => dryrun::render(frame, rows[1], app),
        Screen::Settings => settings::render(frame, rows[1], app),
        Screen::EventLog => eventlog::render(frame, rows[1], app),
        Screen::Config => config::render(frame, rows[1], app),
        Screen::Help => help::render(frame, rows[1], app),
        Screen::Destroy => destroy::render(frame, rows[1], app),
    }

    hints(frame, rows[2], app);

    match app.modal {
        Some(Modal::Menu { cursor }) => menu(frame, area, app, cursor),
        Some(Modal::DeviceAction {
            device_index,
            cursor,
        }) => device_action_modal(frame, area, app, device_index, cursor),
        Some(Modal::WhitelistAddCount {
            device_index,
            max_count,
        }) => whitelist_add_modal(frame, area, app, device_index, max_count),
        Some(Modal::ConfirmRemove { device_index }) => {
            confirm_remove_modal(frame, area, app, device_index)
        }
        Some(Modal::Confirm { action }) => confirm_modal(frame, area, app, action),
        Some(Modal::ConfirmConfigSet { row }) => confirm_config_set_modal(frame, area, app, row),
        Some(Modal::WhitelistEntryAction {
            entry_index,
            cursor,
        }) => whitelist_entry_action_modal(frame, area, app, entry_index, cursor),
        Some(Modal::WhitelistAddId) => whitelist_add_id_modal(frame, area, app),
        Some(Modal::WhitelistCount {
            id,
            max_count,
            editing,
        }) => whitelist_count_modal(frame, area, app, id, max_count, editing),
        Some(Modal::WhitelistRemoveEntry { id }) => {
            whitelist_remove_entry_modal(frame, area, app, id)
        }
        Some(Modal::Report) => report_modal(frame, area, app),
        Some(Modal::DestroyText { engage }) => destroy::text_modal(frame, area, app, engage),
        Some(Modal::DestroyConfirm { engage }) => destroy::confirm_modal(frame, area, app, engage),
        None => {}
    }

    if let Some((msg, _)) = &app.toast {
        toast(frame, area, app, msg);
    }

    // Drawn last so it sits above even the menu and any toast: nothing the user
    // does is meaningful until the daemon is back.
    if matches!(app.conn, Conn::Down) {
        unreachable(frame, area, app);
    }
}

fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// A read screen's border title, tagged ` — STALE` in `warn` style while the
/// daemon is unreachable. Everything such a screen shows is the last data we
/// received and may now be wrong; the centred "daemon unreachable" box and the
/// status band say so too, but that box does not cover the whole area, so the
/// deferred Phase 2 gap was that stale rows peeked around it unmarked. This puts
/// the warning on the screen frame itself. Child `ui` modules call it.
fn screen_title(app: &App, base: impl Into<String>) -> Line<'static> {
    let base = base.into();
    if matches!(app.conn, Conn::Down) {
        Line::from(vec![
            Span::raw(base),
            Span::styled("— STALE (daemon unreachable) ", app.theme.warn()),
        ])
    } else {
        Line::from(base)
    }
}

fn hints(frame: &mut Frame, area: Rect, app: &App) {
    let text = match &app.modal {
        Some(m) => modal_hint(m).to_owned(),
        None => screen_hint(app),
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(text, app.theme.dim()))),
        area,
    );
}

fn modal_hint(modal: &Modal) -> &'static str {
    match modal {
        Modal::Menu { .. } | Modal::DeviceAction { .. } | Modal::WhitelistEntryAction { .. } => {
            "↑↓ move · enter select · esc cancel"
        }
        Modal::WhitelistAddCount { .. } | Modal::WhitelistCount { .. } => {
            "↑↓ adjust · enter confirm · esc cancel"
        }
        Modal::Confirm { .. }
        | Modal::ConfirmConfigSet { .. }
        | Modal::ConfirmRemove { .. }
        | Modal::WhitelistRemoveEntry { .. } => "enter confirm · esc cancel",
        Modal::WhitelistAddId => "type vendor:product hex · enter next · esc cancel",
        Modal::Report => "enter / esc dismiss",
        Modal::DestroyText { .. } => "type DESTROY exactly · enter · esc cancel",
        Modal::DestroyConfirm { .. } => "y confirm · any other key cancels",
    }
}

fn screen_hint(app: &App) -> String {
    let base = "m menu · ↑↓ move · enter select · r refresh · ? help · q quit";
    match app.screen {
        Screen::Devices => match app.devices.get(app.device_cursor).and_then(|d| d.id) {
            Some(id) => format!("{base}   ·   selected {id}"),
            None => base.to_owned(),
        },
        Screen::Whitelist => "m menu · ↑↓ move · enter select · r refresh · esc back".to_owned(),
        Screen::Settings => "m menu · ↑↓ move · enter change · r refresh · esc back".to_owned(),
        Screen::DryRun => "m menu · r re-run · esc back".to_owned(),
        Screen::EventLog => "m menu · ↑↓ scroll · p follow/pause · esc back".to_owned(),
        Screen::Config => "m menu · r refresh · esc back".to_owned(),
        Screen::Help => "m menu · ↑↓ scroll · esc back".to_owned(),
        Screen::Destroy => "m menu · enter: change engaged state · esc back".to_owned(),
    }
}

fn menu(frame: &mut Frame, area: Rect, app: &App, cursor: usize) {
    // While the daemon is unreachable every marker below is drawn from a
    // possibly-stale cache — the menu can overhang the centred "daemon
    // unreachable" box, so the `(ENGAGED)` marker in particular must not read
    // as current fact (matches `destroy::state_line` and the status band).
    let down = matches!(app.conn, Conn::Down);
    let config_invalid = app
        .status
        .as_ref()
        .is_some_and(|s| s.config_error.is_some());
    // Only treat LUKS destroy as unconfigured once we've actually seen a
    // config; while it's unknown, leave the item live.
    let luks_unconfigured = app
        .config
        .as_ref()
        .is_some_and(|c| c.luks_destroy.is_none());

    let mut lines: Vec<Line> = Vec::new();
    for (i, item) in MenuItem::ORDER.iter().enumerate() {
        if item.starts_group() {
            lines.push(Line::from(Span::styled("──────────────", app.theme.dim())));
        }
        let disabled = match item {
            MenuItem::Arm => config_invalid,
            MenuItem::LuksDestroy => luks_unconfigured,
            _ => false,
        };
        // A dangerous state the operator must see without opening the screen
        // (invariant 4): LUKS destruction currently engaged.
        let luks_engaged = matches!(item, MenuItem::LuksDestroy) && app.luks_engaged();
        let marker = if i == cursor { " ▸ " } else { "   " };
        let suffix = if disabled && matches!(item, MenuItem::LuksDestroy) {
            "   (not configured)"
        } else if disabled {
            "   (config invalid)"
        } else if luks_engaged && down {
            "   (engaged? — daemon unreachable)"
        } else if luks_engaged {
            "   (ENGAGED)"
        } else {
            ""
        };
        let label = format!("{marker}{}{suffix}", item.label());
        let style = if disabled {
            app.theme.dim()
        } else if i == cursor {
            app.theme.selected()
        } else if luks_engaged && down {
            app.theme.warn()
        } else if luks_engaged {
            app.theme.invalid()
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(label, style)));
    }

    let rect = centered(area, 38, lines.len() as u16 + 2);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Menu ")),
        rect,
    );
}

/// `Enter` on a device row (plan §6). Options come from
/// [`device_action_labels`] — the single place that decides what's offered for
/// a whitelisted vs. not-whitelisted device.
fn device_action_modal(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    device_index: usize,
    cursor: usize,
) {
    let Some(d) = app.devices.get(device_index) else {
        return;
    };
    let id =
        d.id.map(|i| i.to_string())
            .unwrap_or_else(|| "????:????".to_owned());
    let label = d
        .label
        .as_deref()
        .map(sanitize_device_string)
        .unwrap_or_default();
    let status = if d.whitelisted {
        "whitelisted"
    } else {
        "NEW — not whitelisted"
    };

    let mut lines = vec![
        Line::from(Span::styled(format!("{id}  {label}  [{status}]"), bold())),
        Line::from(""),
    ];
    for (i, opt) in device_action_labels(d.whitelisted).iter().enumerate() {
        let marker = if i == cursor { " ▸ " } else { "   " };
        let style = if i == cursor {
            app.theme.selected()
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(format!("{marker}{opt}"), style)));
    }

    modal_box(frame, area, " Device ", 44, lines);
}

/// Second step of the device screen's "Add to whitelist…" — pick `max_count`.
fn whitelist_add_modal(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    device_index: usize,
    max_count: u32,
) {
    let Some(d) = app.devices.get(device_index) else {
        return;
    };
    let id =
        d.id.map(|i| i.to_string())
            .unwrap_or_else(|| "????:????".to_owned());

    let lines = vec![
        Line::from(Span::styled("Add to whitelist", bold())),
        Line::from(""),
        Line::from(id),
        Line::from(""),
        Line::from(vec![
            Span::raw("max connected at once:  "),
            Span::styled(max_count.to_string(), app.theme.selected()),
        ]),
    ];
    modal_box(frame, area, " Whitelist ", 44, lines);
}

/// Second step of the device screen's "Remove from whitelist" — a confirm.
fn confirm_remove_modal(frame: &mut Frame, area: Rect, app: &App, device_index: usize) {
    let Some(d) = app.devices.get(device_index) else {
        return;
    };
    let id =
        d.id.map(|i| i.to_string())
            .unwrap_or_else(|| "????:????".to_owned());

    let lines = vec![
        Line::from(Span::styled("Remove from whitelist?", app.theme.warn())),
        Line::from(""),
        Line::from(id),
    ];
    modal_box(frame, area, " Confirm ", 44, lines);
}

/// `Arm` / `Disarm` / `Reload` from the menu (plan §7).
fn confirm_modal(frame: &mut Frame, area: Rect, app: &App, action: ConfirmAction) {
    let (title, style) = match action {
        ConfirmAction::Arm => (" Arm ", app.theme.armed()),
        ConfirmAction::Disarm => (" Disarm ", app.theme.warn()),
        ConfirmAction::Reload => (" Reload ", app.theme.disarmed()),
    };
    let lines = vec![
        Line::from(Span::styled(action.prompt(), style)),
        Line::from(""),
        Line::from(Span::styled("enter confirm · esc cancel", app.theme.dim())),
    ];

    let rect = centered(area, 58, 8);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        rect,
    );
}

/// A Settings change that lowers protection while armed (plan §7 / kill-path
/// review) — a confirm step before it is sent.
fn confirm_config_set_modal(frame: &mut Frame, area: Rect, app: &App, row: usize) {
    let what = match row {
        0 => "Enable dry-run while ARMED? A kill would then only be logged, not carried out.",
        1 => "Change the power action while ARMED? A kill may no longer cut power.",
        3 => "Set on-sensor-gap to 'warn' while ARMED? A sensor blackout would no longer fire a kill.",
        _ => "Apply this change while ARMED?",
    };
    let lines = vec![
        Line::from(Span::styled(
            "Lower protection while ARMED?",
            app.theme.warn(),
        )),
        Line::from(""),
        Line::from(Span::raw(what)),
        Line::from(""),
        Line::from(Span::styled("enter confirm · esc cancel", app.theme.dim())),
    ];

    let rect = centered(area, 60, 9);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Confirm "))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        rect,
    );
}

/// `Enter` on a Whitelist-screen entry row.
fn whitelist_entry_action_modal(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    entry_index: usize,
    cursor: usize,
) {
    let Some(e) = app.whitelist.get(entry_index) else {
        return;
    };
    let label = e
        .label
        .as_deref()
        .map(sanitize_device_string)
        .unwrap_or_default();

    let mut lines = vec![
        Line::from(Span::styled(
            format!("{}  max {}  {label}", e.id, e.max_count.unwrap_or(1)),
            bold(),
        )),
        Line::from(""),
    ];
    for (i, opt) in whitelist_entry_action_labels().iter().enumerate() {
        let marker = if i == cursor { " ▸ " } else { "   " };
        let style = if i == cursor {
            app.theme.selected()
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(format!("{marker}{opt}"), style)));
    }

    modal_box(frame, area, " Whitelist entry ", 48, lines);
}

/// The Whitelist screen's "add entry", step one: type a `vendor:product` id.
fn whitelist_add_id_modal(frame: &mut Frame, area: Rect, app: &App) {
    let field = if app.input.is_empty() {
        "_".to_owned()
    } else {
        format!("{}_", app.input)
    };
    let lines = vec![
        Line::from(Span::styled("Add whitelist entry", bold())),
        Line::from(""),
        Line::from(vec![
            Span::raw("vendor:product  "),
            Span::styled(field, app.theme.selected()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "hex digits and one colon, e.g. 1050:0407",
            app.theme.dim(),
        )),
    ];
    modal_box(frame, area, " Whitelist ", 48, lines);
}

/// Whitelist count picker — step two of "add entry", or "edit max count".
fn whitelist_count_modal(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    id: UsbId,
    max_count: u32,
    editing: bool,
) {
    let heading = if editing {
        "Edit max count"
    } else {
        "Add to whitelist"
    };
    let lines = vec![
        Line::from(Span::styled(heading.to_owned(), bold())),
        Line::from(""),
        Line::from(id.to_string()),
        Line::from(""),
        Line::from(vec![
            Span::raw("max connected at once:  "),
            Span::styled(max_count.to_string(), app.theme.selected()),
        ]),
    ];
    modal_box(frame, area, " Whitelist ", 48, lines);
}

/// Confirm removing an entry from the Whitelist screen.
fn whitelist_remove_entry_modal(frame: &mut Frame, area: Rect, app: &App, id: UsbId) {
    let lines = vec![
        Line::from(Span::styled("Remove from whitelist?", app.theme.warn())),
        Line::from(""),
        Line::from(id.to_string()),
        Line::from(""),
        Line::from(Span::styled(
            "this device becomes unknown while armed",
            app.theme.dim(),
        )),
    ];
    modal_box(frame, area, " Confirm ", 48, lines);
}

/// A rejected `ConfigSet` — the daemon's full validation report, verbatim.
fn report_modal(frame: &mut Frame, area: Rect, app: &App) {
    let Some(report) = &app.report else {
        return;
    };
    let mut lines = vec![
        Line::from(Span::styled(
            "Change rejected — config unchanged",
            app.theme.invalid(),
        )),
        Line::from(""),
    ];
    for l in report.lines() {
        lines.push(Line::from(l.to_owned()));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "enter / esc dismiss",
        app.theme.dim(),
    )));

    let w = area.width.saturating_sub(8).min(84);
    let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(2));
    let rect = centered(area, w, h);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Rejected "))
            .wrap(Wrap { trim: false }),
        rect,
    );
}

fn unreachable(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = vec![
        Line::from(Span::styled(
            "  ⚠  daemon unreachable  ",
            app.theme.invalid(),
        )),
        Line::from(""),
    ];
    if let Some(why) = &app.conn_error {
        lines.push(Line::from(why.as_str()));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        "retrying every 2s — r to retry now, q to quit",
        app.theme.dim(),
    )));

    let rect = centered(area, 56, lines.len() as u16 + 2);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        rect,
    );
}

fn toast(frame: &mut Frame, area: Rect, app: &App, msg: &str) {
    let width = (msg.chars().count() as u16 + 4).min(area.width);
    let rect = Rect {
        x: area.x + area.width.saturating_sub(width),
        y: area.y + area.height.saturating_sub(4),
        width,
        height: 3,
    };
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(msg.to_owned())
            .block(Block::default().borders(Borders::ALL))
            .style(app.theme.selected())
            .wrap(Wrap { trim: true }),
        rect,
    );
}

fn too_small(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new("Terminal too small — resize to at least 60×18")
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        area,
    );
}

/// A centred, bordered modal with `lines` plus a trailing blank — the common
/// shape for the menu-style overlays.
fn modal_box(frame: &mut Frame, area: Rect, title: &str, w: u16, lines: Vec<Line>) {
    let rect = centered(area, w, lines.len() as u16 + 2);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_owned()),
        ),
        rect,
    );
}

/// A `w`×`h` rectangle centred in `area`, clamped to fit.
fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}
