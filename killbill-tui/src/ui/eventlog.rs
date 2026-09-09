//! The Event log screen (plan §5, build step 10).
//!
//! The daemon's decision / event stream with its own RFC 3339 timestamps —
//! backlog replay plus everything live since. Follows the newest line unless
//! the user scrolls up (`↑`/`↓`) or freezes it (`p`).

use killbill_proto::{DeviceInfo, Event, StreamEvent};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::screen_title;
use crate::app::App;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let mode = if app.events_paused {
        "paused"
    } else {
        "following"
    };
    let block = Block::default().borders(Borders::ALL).title(screen_title(
        app,
        format!(" Event log ({}) — {mode} ", app.events.len()),
    ));

    if app.events.is_empty() {
        frame.render_widget(
            Paragraph::new("No events yet.")
                .block(block)
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    // Show the window ending `event_scroll` lines from the newest.
    let inner_h = area.height.saturating_sub(2) as usize;
    let all: Vec<Line> = app.events.iter().map(|se| event_line(se, t)).collect();
    let end = all.len().saturating_sub(app.event_scroll);
    let start = end.saturating_sub(inner_h);
    let view = all[start..end].to_vec();

    frame.render_widget(Paragraph::new(view).block(block), area);
}

fn event_line(se: &StreamEvent, t: &Theme) -> Line<'static> {
    let (glyph, text, style) = describe(&se.event, t);
    Line::from(vec![
        Span::styled(format!("{}  ", se.at), t.dim()),
        Span::styled(format!("{glyph:<2} "), style),
        Span::styled(text, style),
    ])
}

/// `(glyph, text, style)` for one event. Mirrors `killbillctl`'s `render_event`
/// so the two clients describe the stream the same way.
fn describe(event: &Event, t: &Theme) -> (&'static str, String, Style) {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let id = |d: &DeviceInfo| {
        d.id.map_or_else(|| "????:????".to_owned(), |i| i.to_string())
    };
    match event {
        Event::DeviceAdded(d) => ("+", format!("device {} connected", id(d)), Style::default()),
        Event::DeviceRemoved(d) => (
            "-",
            format!("device {} disconnected", id(d)),
            Style::default(),
        ),
        Event::Armed => ("!", "armed".to_owned(), bold),
        Event::Disarmed => ("!", "disarmed".to_owned(), bold),
        Event::WouldKill(reason) => ("!", format!("would kill: {reason}"), t.warn()),
        Event::SensorStopped => ("!!", "USB sensor stopped".to_owned(), t.warn()),
        Event::EventsLost => (
            "!!",
            "USB events lost — some device changes were missed".to_owned(),
            t.warn(),
        ),
        Event::WhitelistChanged => ("*", "whitelist changed".to_owned(), t.dim()),
        Event::ConfigChanged => ("*", "config changed".to_owned(), t.dim()),
        Event::ReloadFailed(reason) => ("!!", format!("reload failed: {reason}"), t.warn()),
        // `Event` is `#[non_exhaustive]`: show an unknown variant, don't drop it.
        other => ("?", format!("{other:?}"), t.dim()),
    }
}
