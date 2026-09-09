//! The Devices master list (plan §5) — the home screen.
//!
//! Every currently-tracked USB device, with un-whitelisted ones marked `NEW`.
//! The list scrolls; it never assumes it can show every row.

use killbill_proto::{sanitize_device_string, DeviceInfo};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use super::screen_title;
use crate::app::{App, Conn, Screen};
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let block = Block::default().borders(Borders::ALL).title(screen_title(
        app,
        format!(" Devices ({}) ", app.devices.len()),
    ));

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
        .map(|d| ListItem::new(device_line(d, t)))
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

/// One device row. Pulled out of [`render`] so the sanitize step has a single
/// call site with its own test: `label` and `serial` are USB string
/// descriptors — fully attacker-controlled — and this was the one consumer in
/// the workspace that rendered them via `Span::raw` with no
/// [`sanitize_device_string`] pass (a deferred Phase 2 finding, fixed here).
fn device_line(d: &DeviceInfo, t: &Theme) -> Line<'static> {
    let id =
        d.id.map(|i| i.to_string())
            .unwrap_or_else(|| "????:????".to_owned());
    let (mark, mark_style) = if d.whitelisted {
        ("ok ", t.dim())
    } else {
        ("NEW", t.warn())
    };
    let label = d
        .label
        .as_deref()
        .map(sanitize_device_string)
        .unwrap_or_default();
    let serial = d
        .serial
        .as_deref()
        .map(sanitize_device_string)
        .unwrap_or_default();
    Line::from(vec![
        Span::raw("  "),
        Span::styled(mark, mark_style),
        Span::raw("  "),
        Span::raw(id),
        Span::raw("  "),
        Span::raw(label),
        Span::raw("  "),
        Span::styled(serial, t.dim()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use killbill_proto::{SensorSource, UsbId};

    #[test]
    fn device_line_sanitizes_a_hostile_label_and_serial() {
        let d = DeviceInfo {
            source: SensorSource::Usb,
            id: Some(UsbId::new(0x1234, 0x5678)),
            serial: Some("\x1b[2Jgotcha".to_owned()),
            label: Some("Caf\u{e9}".to_owned()),
            whitelisted: false,
        };
        let line = device_line(&d, &Theme::detect());
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();

        assert!(
            !rendered.contains('\x1b'),
            "an escape byte reached the rendered row: {rendered:?}"
        );
        assert!(rendered.contains(&sanitize_device_string("\x1b[2Jgotcha")));
        assert!(rendered.contains(&sanitize_device_string("Caf\u{e9}")));
    }
}
