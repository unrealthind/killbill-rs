//! The read-only Config inspector (plan §5, build step 11).
//!
//! The whole running (validated) config as the daemon reports it via
//! `Command::GetConfig`. Nothing here is editable — the editable subset lives
//! on the Settings screen; this view is for seeing everything at once,
//! including the fields Settings does not touch
//! (`sensors`, `luks_destroy`) and the full validation report when the file on
//! disk is broken (invariant 2: the daemon keeps running the last-good config).

use killbill_proto::{sanitize_device_string, ConfigPayload, PowerAction};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::screen_title;
use crate::app::App;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(screen_title(app, " Config (read-only) "));

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
            " ▲ CONFIG ON DISK IS INVALID — running last-good ",
            t.invalid(),
        )));
        lines.push(Line::from(""));
        for l in err.lines() {
            lines.push(Line::from(Span::styled(l.to_owned(), t.warn())));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "the fields below are the config the daemon is actually running:",
            t.dim(),
        )));
        lines.push(Line::from(""));
    }

    for (name, value) in rows(cfg, t) {
        lines.push(Line::from(vec![
            Span::styled(format!("  {name:<16}"), t.dim()),
            value,
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  edit dry-run / power-action / armed-at-boot / on-sensor-gap on the",
        t.dim(),
    )));
    lines.push(Line::from(Span::styled(
        "  Settings screen; sensors and luks-destroy are killbillctl-only in v1.",
        t.dim(),
    )));

    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

/// Every config field as a `(label, value-span)` pair, in a stable order.
fn rows(cfg: &ConfigPayload, t: &Theme) -> Vec<(&'static str, Span<'static>)> {
    // `halt` / `none` are the two the charter warns about — flag them. Match the
    // enum, not its `Display` text, so a rename can't flip the annotation.
    let power_span = match cfg.power_action {
        PowerAction::PowerOff => Span::raw(cfg.power_action.to_string()),
        _ => Span::styled(
            format!("{}  (does not cut power)", cfg.power_action),
            t.warn(),
        ),
    };

    let mut rows = vec![
        ("armed at boot", Span::raw(yes_no(cfg.armed_at_boot))),
        ("dry run", Span::raw(yes_no(cfg.dry_run))),
        ("power action", power_span),
        ("on sensor gap", Span::raw(cfg.on_sensor_gap.to_string())),
        ("sensors", Span::raw(cfg.sensors.join(", "))),
    ];

    match &cfg.luks_destroy {
        None => rows.push((
            "luks destroy",
            Span::styled("not configured".to_owned(), t.dim()),
        )),
        Some(l) => {
            rows.push((
                "luks destroy",
                Span::styled(sanitize_device_string(&l.target_header), t.warn()),
            ));
            rows.push(("  acknowledged", Span::raw(yes_no(l.acknowledged))));
            rows.push((
                "  engaged",
                if l.engaged {
                    Span::styled(
                        "YES  (v1: recorded only — the wipe is a stub, the header is not touched)"
                            .to_owned(),
                        t.invalid(),
                    )
                } else {
                    Span::raw("no".to_owned())
                },
            ));
        }
    }
    rows
}

fn yes_no(b: bool) -> String {
    (if b { "yes" } else { "no" }).to_owned()
}
