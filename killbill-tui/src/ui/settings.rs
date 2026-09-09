//! The Settings screen (plan §5, build step 9).
//!
//! The four editable response-config fields, plus `sensors` and `luks_destroy`
//! read-only. `Enter` on a row toggles or cycles it via `ConfigSet`; a rejected
//! change surfaces as [`crate::app::Modal::Report`] and the screen re-fetches,
//! so it always shows the *running* config (invariant 2).

use killbill_proto::{sanitize_device_string, ConfigPayload};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::screen_title;
use crate::app::App;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(screen_title(app, " Settings "));

    let Some(cfg) = &app.config else {
        frame.render_widget(
            Paragraph::new("Loading config… press r to retry.")
                .block(block)
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    };

    let mut lines: Vec<Line> = Vec::new();

    if let Some(err) = &cfg.validation_error {
        lines.push(Line::from(Span::styled(
            " CONFIG ON DISK IS INVALID — running last-good ",
            t.invalid(),
        )));
        // The report is multi-line — render it as lines, the same as the Config
        // screen and the rejected-change modal do.
        for l in err.lines() {
            lines.push(Line::from(Span::styled(l.to_owned(), t.warn())));
        }
        lines.push(Line::from(""));
    }

    for (i, (name, value)) in editable_rows(cfg).iter().enumerate() {
        let selected = app.modal.is_none() && i == app.settings_cursor;
        let marker = if selected { " ▸ " } else { "   " };
        let style = if selected {
            t.selected()
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(
            format!("{marker}{name:<16}{value}"),
            style,
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("   {:<16}{}", "sensors", cfg.sensors.join(", ")),
        t.dim(),
    )));
    match &cfg.luks_destroy {
        Some(l) => lines.push(Line::from(Span::styled(
            format!(
                "   {:<16}{}  (engaged: {})",
                "luks destroy",
                sanitize_device_string(&l.target_header),
                if l.engaged { "yes" } else { "no" }
            ),
            t.dim(),
        ))),
        None => lines.push(Line::from(Span::styled(
            format!("   {:<16}not configured", "luks destroy"),
            t.dim(),
        ))),
    }
    lines.push(Line::from(Span::styled(
        "   (sensors / luks-destroy are edited with killbillctl in v1)",
        t.dim(),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "   enter toggles or cycles the selected row",
        Style::default().add_modifier(Modifier::DIM),
    )));

    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

/// The four editable rows, in cursor order — must line up with
/// `App::edit_setting`'s `row` match.
fn editable_rows(cfg: &ConfigPayload) -> [(&'static str, String); 4] {
    [
        ("dry run", on_off(cfg.dry_run)),
        ("power action", cfg.power_action.to_string()),
        ("armed at boot", on_off(cfg.armed_at_boot)),
        ("on sensor gap", cfg.on_sensor_gap.to_string()),
    ]
}

fn on_off(b: bool) -> String {
    (if b { "on" } else { "off" }).to_owned()
}
