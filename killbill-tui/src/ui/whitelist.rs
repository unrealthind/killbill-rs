//! The Whitelist management screen (plan §5, build step 8).
//!
//! The full whitelist — including entries whose device is not currently
//! connected, which `ListDevices` never shows. Row 0 is always the "add entry"
//! action; the real entries follow.

use killbill_proto::{sanitize_device_string, WhitelistEntry};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use super::screen_title;
use crate::app::App;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let block = Block::default().borders(Borders::ALL).title(screen_title(
        app,
        format!(" Whitelist ({}) ", app.whitelist.len()),
    ));

    let mut items: Vec<ListItem> = Vec::with_capacity(app.whitelist.len() + 1);
    items.push(ListItem::new(Line::from(Span::styled(
        "  +  Add entry",
        t.dim(),
    ))));
    for e in &app.whitelist {
        items.push(ListItem::new(entry_line(e, app, t)));
    }

    let mut state = ListState::default();
    if app.modal.is_none() {
        let last = items.len().saturating_sub(1);
        state.select(Some(app.whitelist_cursor.min(last)));
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

/// One whitelist row. `label` is a stored USB string descriptor — sanitize it
/// before it reaches the terminal, same as everywhere else.
fn entry_line(e: &WhitelistEntry, app: &App, t: &Theme) -> Line<'static> {
    let (mark, mark_style) = if app.whitelist_entry_connected(e.id) {
        ("connected", t.dim())
    } else {
        ("absent   ", t.dim())
    };
    let label = e
        .label
        .as_deref()
        .map(sanitize_device_string)
        .unwrap_or_default();
    Line::from(vec![
        Span::raw("  "),
        Span::styled(mark, mark_style),
        Span::raw("  "),
        Span::raw(e.id.to_string()),
        Span::raw("  "),
        Span::styled(format!("max {}", e.max_count.unwrap_or(1)), t.dim()),
        Span::raw("  "),
        Span::raw(label),
    ])
}
