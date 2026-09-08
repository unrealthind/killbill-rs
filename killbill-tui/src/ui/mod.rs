//! Rendering. `draw` is the whole frame: the status band, the active screen,
//! the hint line, then any modal and any transient overlay on top.
//!
//! Everything below reads from [`App`] and never mutates it.

mod devices;
mod statusbar;

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Conn, MenuItem, Modal, Screen};

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
        Screen::Placeholder(name) => placeholder(frame, rows[1], app, name),
    }

    hints(frame, rows[2], app);

    if let Some(Modal::Menu { cursor }) = app.modal {
        menu(frame, area, app, cursor);
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

fn placeholder(frame: &mut Frame, area: Rect, app: &App, name: &str) {
    let lines = vec![
        Line::from(Span::styled(
            name.to_owned(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "This screen arrives in a later Phase 2 step.",
            app.theme.dim(),
        )),
        Line::from(Span::styled(
            "Esc to go back · m for the menu",
            app.theme.dim(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {name} ")),
            )
            .alignment(Alignment::Center),
        area,
    );
}

fn hints(frame: &mut Frame, area: Rect, app: &App) {
    let text = if app.modal.is_some() {
        "↑↓ move · enter select · esc close menu".to_owned()
    } else {
        let base = "m menu · ↑↓ move · enter select · r refresh · ? help · q quit";
        match app
            .devices
            .get(app.device_cursor)
            .filter(|_| matches!(app.screen, Screen::Devices))
            .and_then(|d| d.id)
        {
            Some(id) => format!("{base}   ·   selected {id}"),
            None => base.to_owned(),
        }
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(text, app.theme.dim()))),
        area,
    );
}

fn menu(frame: &mut Frame, area: Rect, app: &App, cursor: usize) {
    let config_invalid = app
        .status
        .as_ref()
        .is_some_and(|s| s.config_error.is_some());

    let mut lines: Vec<Line> = Vec::new();
    for (i, item) in MenuItem::ORDER.iter().enumerate() {
        if item.starts_group() {
            lines.push(Line::from(Span::styled("──────────────", app.theme.dim())));
        }
        // `Arm` is refused by the daemon while the config is invalid; show that
        // rather than letting the user pick it and get a toast.
        let disabled = matches!(item, MenuItem::Arm) && config_invalid;
        let marker = if i == cursor { " ▸ " } else { "   " };
        let label = format!("{marker}{}", item.label());
        let style = if disabled {
            app.theme.dim()
        } else if i == cursor {
            app.theme.selected()
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(label, style)));
    }

    let rect = centered(area, 34, lines.len() as u16 + 2);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Menu ")),
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
