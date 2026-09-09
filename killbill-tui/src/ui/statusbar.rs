//! The persistent one-line armed-state band (plan §7).
//!
//! Rendered on every screen. The state is carried by a glyph *and* a word, not
//! colour alone, so it survives `NO_COLOR`. `DRY-RUN` is tagged separately —
//! armed-but-dry is an easy state to miss.

use killbill_proto::PowerAction;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, Conn};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let mut spans: Vec<Span> = Vec::new();

    // `Conn::Down` takes priority over the cached `status` even when one
    // exists: the daemon may have changed state since the connection was
    // lost, so the last-known armed/disarmed word must not be shown as
    // current fact (a deferred Phase 2 defect). What we last knew is still
    // useful context — just clearly marked as stale, not dropped.
    let (glyph, word, style) = match (&app.conn, &app.status) {
        (Conn::Connecting, _) => ("…", "CONNECTING", t.dim()),
        (Conn::Down, Some(s)) if s.armed => ("?", "LAST KNOWN: ARMED", t.warn()),
        (Conn::Down, Some(_)) => ("?", "LAST KNOWN: DISARMED", t.warn()),
        (Conn::Down, None) => ("…", "NO STATUS", t.dim()),
        (Conn::Up, Some(s)) if s.config_error.is_some() => {
            ("▲", "CONFIG INVALID — WILL NOT ARM", t.invalid())
        }
        (Conn::Up, Some(s)) if s.armed => ("●", "ARMED", t.armed()),
        (Conn::Up, Some(_)) => ("○", "DISARMED", t.disarmed()),
        (Conn::Up, None) => ("…", "NO STATUS", t.dim()),
    };
    spans.push(Span::styled(format!(" {glyph} {word} "), style));

    // The detail fields (dry-run, sensor health, events-lost, config-stale,
    // whitelist/device counts) are exactly as stale as the headline above —
    // only show them while `status` is both present and believed current.
    if let (Conn::Up, Some(s)) = (&app.conn, &app.status) {
        if s.dry_run {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(" DRY-RUN ", t.disarmed()));
        }

        // `power_action = "none"` is the other silent belt — an armed daemon
        // that will not actually cut power looks identical to one that will,
        // unless it is tagged (kill-path review H1). Glyph-and-word, not colour.
        match s.power_action {
            PowerAction::PowerOff => {}
            PowerAction::None => {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(" POWER: NONE — WILL NOT CUT POWER ", t.warn()));
            }
            PowerAction::Halt => {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(" POWER: HALT — WILL NOT CUT POWER ", t.warn()));
            }
            _ => {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(" POWER: ? ", t.warn()));
            }
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

        if s.config_stale {
            spans.push(Span::raw("   "));
            spans.push(Span::styled("CONFIG STALE", t.warn()));
        }

        // A destructive runtime state (invariant 4) — surfaced wherever the
        // band is, not only on the LUKS screen. `config` is a cache like the
        // rest of this block, so it is gated the same way.
        if app.luks_engaged() {
            spans.push(Span::raw("   "));
            spans.push(Span::styled("LUKS DESTROY ENGAGED", t.invalid()));
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
