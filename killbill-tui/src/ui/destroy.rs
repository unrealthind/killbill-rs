//! The fenced LUKS-header-destruction screen (plan §8, build step 12).
//!
//! Visually distinct on purpose: a hazard border, no list, no other chrome.
//! It names the exact target device and shows whether destruction is currently
//! *engaged*. The wipe itself is a deliberate stub in v1 (invariant 3) — this
//! screen never implies otherwise; it only flips the runtime `engaged` flag,
//! and only behind the typed-`DESTROY` fence (charter §4, §5).
//!
//! Three review owners on this file: `tui-ux`, `security-auditor`,
//! `kill-path-reliability`.

use killbill_proto::sanitize_device_string;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Conn};
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let down = matches!(app.conn, Conn::Down);

    // The hazard frame is drawn regardless of state, so the screen is never
    // mistaken for an ordinary one. While the daemon is unreachable the title
    // also carries the stale tag: the `engaged` state below is a cache and
    // could be wrong (the deferred Phase 2 gap — sharpest on this screen).
    let mut title = vec![Span::styled(" ☠  LUKS HEADER DESTRUCTION ", t.invalid())];
    if down {
        title.push(Span::styled("— STALE (daemon unreachable) ", t.warn()));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(t.invalid())
        .title(Line::from(title));

    let Some(cfg) = &app.config else {
        frame.render_widget(
            Paragraph::new("Loading config… press r to retry.")
                .block(block)
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    };

    let Some(luks) = &cfg.luks_destroy else {
        // Reachable only from a stale cache — the menu greys the item.
        frame.render_widget(
            Paragraph::new(
                "LUKS header destruction is not configured. Add an acknowledged \
                 [response.luks_destroy] block to the config file first.",
            )
            .block(block)
            .wrap(Wrap { trim: true }),
            area,
        );
        return;
    };

    let engaged = luks.engaged;
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  target header:  ", t.dim()),
        Span::styled(sanitize_device_string(&luks.target_header), bold),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  acknowledged:   ", t.dim()),
        Span::raw(if luks.acknowledged { "yes" } else { "no" }),
    ]));
    lines.push(Line::from(""));

    // The current state, big and unmissable, colour *and* word. While the
    // daemon is unreachable we cannot vouch for the cached value, so it is
    // shown as UNKNOWN rather than as a stale "not engaged" (invariant 4:
    // the engaged state is never assumed).
    lines.push(state_line(&app.conn, engaged, t));
    lines.push(Line::from(""));

    for para in [
        "On an unauthorized device change while armed, the daemon powers the \
         machine off so the disk re-locks. With destruction ENGAGED it would \
         additionally overwrite the LUKS header on the target above, making the \
         data unrecoverable even with the passphrase.",
        "That wipe is NOT implemented in this version — the flag is real, the \
         config and this screen are real, but the header is never actually \
         touched (by design). Engaging it now records intent for a future \
         release; it changes nothing destructive today.",
        "The flag is never saved to disk: every daemon restart begins with \
         destruction disengaged.",
    ] {
        lines.push(Line::from(Span::raw(format!("  {para}"))));
        lines.push(Line::from(""));
    }

    if down {
        // The fence is refused while unreachable (see `App::open_destroy_fence`);
        // don't offer an action the daemon can't receive.
        lines.push(Line::from(Span::styled(
            "  reconnect to the daemon before changing the engaged state (r to retry)",
            t.dim(),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!(
                "  ▸ press Enter to {} — you will be asked to type DESTROY",
                if engaged { "DISENGAGE" } else { "ENGAGE" }
            ),
            bold,
        )));
    }

    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

/// The big colour-*and*-word engaged-state line. `Conn::Down` overrides the
/// cached `engaged` value with UNKNOWN — a downed daemon may have changed it,
/// and showing a stale "not engaged" on this screen is the one the review gate
/// flagged as sharpest.
fn state_line(conn: &Conn, engaged: bool, t: &Theme) -> Line<'static> {
    if matches!(conn, Conn::Down) {
        return Line::from(Span::styled(
            "  ??  ENGAGED STATE UNKNOWN — daemon unreachable, cannot confirm  ??",
            t.invalid(),
        ));
    }
    if engaged {
        Line::from(Span::styled(
            "  ▓▓  ENGAGED — a kill while armed will (in a future version) wipe this header  ▓▓",
            t.invalid(),
        ))
    } else {
        Line::from(Span::styled(
            "  ░░  not engaged — a kill will not touch the header  ░░",
            t.disarmed(),
        ))
    }
}

/// Step one of the fence: the `DESTROY` text field. Rendered centred over the
/// screen so it reads as a deliberate stop, not an inline prompt.
pub fn text_modal(frame: &mut Frame, area: Rect, app: &App, engage: bool) {
    let t = &app.theme;
    let field = if app.input.is_empty() {
        "_".to_owned()
    } else {
        format!("{}_", app.input)
    };
    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                "{} LUKS header destruction",
                if engage { "Engage" } else { "Disengage" }
            ),
            t.invalid(),
        )),
        Line::from(""),
    ];
    lines.extend(target_lines(app, t));
    lines.push(Line::from(Span::raw(
        "Type the word  DESTROY  (exactly, capitals) and press Enter.",
    )));
    lines.push(Line::from(Span::styled(
        "Anything else cancels and changes nothing.",
        t.dim(),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("  > "),
        Span::styled(field, t.selected()),
    ]));
    boxed(frame, area, " Confirm — 1 of 2 ", lines);
}

/// Step two of the fence: the final `y` / anything-else.
pub fn confirm_modal(frame: &mut Frame, area: Rect, app: &App, engage: bool) {
    let t = &app.theme;
    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                "{} LUKS header destruction now?",
                if engage { "ENGAGE" } else { "Disengage" }
            ),
            t.invalid(),
        )),
        Line::from(""),
    ];
    lines.extend(target_lines(app, t));
    lines.push(Line::from(Span::raw(
        "Press  y  to confirm.  Any other key cancels.",
    )));
    boxed(frame, area, " Confirm — 2 of 2 ", lines);
}

/// The `target header:` line for the fence modals, so the operator sees the
/// exact device at the moment of typing `DESTROY` / pressing `y` (charter §5),
/// not just on the screen behind the box. Reads the header captured when the
/// fence opened (`App::destroy_target`) — the same value
/// `App::set_luks_destroy_engaged` re-verifies before sending.
fn target_lines(app: &App, t: &Theme) -> Vec<Line<'static>> {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    match &app.destroy_target {
        Some(target) => vec![
            Line::from(vec![
                Span::styled("  target header:  ", t.dim()),
                Span::styled(sanitize_device_string(target), bold),
            ]),
            Line::from(""),
        ],
        None => Vec::new(),
    }
}

fn boxed(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line>) {
    let w = 66.min(area.width);
    let h = (lines.len() as u16 + 2).min(area.height);
    let rect = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double)
                    .border_style(Style::default().add_modifier(Modifier::BOLD))
                    .title(title.to_owned()),
            )
            .wrap(Wrap { trim: true }),
        rect,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn state_line_hides_the_cached_engaged_value_while_the_daemon_is_down() {
        let t = Theme::detect();

        // Even with a cached `engaged = false`, a downed daemon must not be
        // rendered as "not engaged" — that is the stale reading the review
        // gate flagged as sharpest on this screen.
        let down = text(&state_line(&Conn::Down, false, &t));
        assert!(down.contains("UNKNOWN"), "got: {down}");
        assert!(!down.contains("not engaged"), "got: {down}");

        // Connected, the real state shows through both ways.
        assert!(text(&state_line(&Conn::Up, true, &t)).contains("ENGAGED"));
        assert!(text(&state_line(&Conn::Up, false, &t)).contains("not engaged"));
    }
}
