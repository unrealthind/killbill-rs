//! The persistent one-line armed-state band (plan §7).
//!
//! Rendered on every screen. The state is carried by a glyph *and* a word, not
//! colour alone, so it survives `NO_COLOR`. `DRY-RUN` is tagged separately —
//! armed-but-dry is an easy state to miss.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, Conn};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let mut spans: Vec<Span> = Vec::new();

    let (glyph, word, style) = match &app.status {
        _ if matches!(app.conn, Conn::Connecting) => ("…", "CONNECTING", t.dim()),
        Some(s) if s.config_error.is_some() => ("▲", "CONFIG INVALID — WILL NOT ARM", t.invalid()),
        Some(s) if s.armed => ("●", "ARMED", t.armed()),
        Some(_) => ("○", "DISARMED", t.disarmed()),
        None => ("…", "NO STATUS", t.dim()),
    };
    spans.push(Span::styled(format!(" {glyph} {word} "), style));

    if let Some(s) = &app.status {
        if s.dry_run {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(" DRY-RUN ", t.disarmed()));
        }

        spans.push(Span::raw("   "));
        spans.push(if s.sensor_ok {
            Span::styled("sensor ok", t.dim())
        } else {
            Span::styled("SENSOR STOPPED", t.warn())
        });

        if s.events_lost {
            spans.push(Span::raw("   "));
            spans.push(Span::styled("EVENTS LOST", t.warn()));
        }

        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("whitelist {} · devices {}", s.whitelist_len, s.device_count),
            t.dim(),
        ));
    }

    if matches!(app.conn, Conn::Down) {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("[daemon unreachable]", t.warn()));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
