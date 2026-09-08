//! The Devices master list (plan §5) — the home screen.
//!
//! Every currently-tracked USB device, with un-whitelisted ones marked `NEW`.
//! The list scrolls; it never assumes it can show every row.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Conn, Screen};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Devices ({}) ", app.devices.len()));

    if app.devices.is_empty() {
        let msg = match app.conn {
            Conn::Up => "No USB devices tracked. The daemon reports devices seen since it started.",
            _ => "Waiting for the daemon…",
        };
        frame.render_widget(
            Paragraph::new(msg).block(block).wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let items: Vec<ListItem> = app
        .devices
        .iter()
        .map(|d| {
            let id =
                d.id.map(|i| i.to_string())
                    .unwrap_or_else(|| "????:????".to_owned());
            let (mark, mark_style) = if d.whitelisted {
                ("ok ", t.dim())
            } else {
                ("NEW", t.warn())
            };
            ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(mark, mark_style),
                Span::raw("  "),
                Span::raw(id),
                Span::raw("  "),
                Span::raw(d.label.as_deref().unwrap_or("")),
                Span::raw("  "),
                Span::styled(d.serial.as_deref().unwrap_or(""), t.dim()),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if app.modal.is_none() && matches!(app.screen, Screen::Devices) {
        let last = app.devices.len().saturating_sub(1);
        state.select(Some(app.device_cursor.min(last)));
    }

    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(t.selected())
            .highlight_symbol("▸"),
        area,
        &mut state,
    );
}
