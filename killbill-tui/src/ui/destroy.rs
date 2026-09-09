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
use crate::client::Client;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
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

    frame.render_widget(
        Paragraph::new(body_lines(app))
            .block(block)
            // `body_lines` is pre-wrapped to `BODY_WRAP`, so at any width the
            // layout accepts (>= `ui::MIN_W`) one logical line renders as one
            // row — this `Wrap` only mops up a pathologically long target path.
            // That equality is what lets the reducer clamp `destroy_scroll`
            // against `line_count` (a logical count) even though
            // `Paragraph::scroll` counts rendered rows.
            .wrap(Wrap { trim: true })
            .scroll((app.destroy_scroll, 0)),
        area,
    );
}

/// Wrap width for the scrolling body. `ui::MIN_W` (60) minus the double border
/// and the two-space indent leaves ~56 columns; 54 keeps a margin (and
/// multi-byte glyphs like `—` count as >1 byte here, wrapping a hair early,
/// which only ever under-fills a line).
const BODY_WRAP: usize = 54;

/// The screen body as owned lines, already wrapped to [`BODY_WRAP`] so its
/// length equals the rendered row count. Shared by [`render`] and
/// [`line_count`] so the scroll clamp can never drift from what is drawn — the
/// count is dynamic (a one-line "not configured" body, the full body, and a
/// `Conn::Down` hint swap), so hand-counting like `help::line_count` would be
/// fragile.
fn body_lines<C: Client>(app: &App<C>) -> Vec<Line<'static>> {
    let t = &app.theme;
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let down = matches!(app.conn, Conn::Down);

    let Some(cfg) = &app.config else {
        return vec![Line::from("Loading config… press r to retry.")];
    };
    let Some(luks) = &cfg.luks_destroy else {
        // Reachable only from a stale cache — the menu greys the item.
        return vec![Line::from(
            "LUKS header destruction is not configured. Add an acknowledged \
             [response.luks_destroy] block to the config file first.",
        )];
    };

    let engaged = luks.engaged;
    let mut lines: Vec<Line<'static>> = Vec::new();

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
    lines.extend(state_lines(&app.conn, engaged, t));
    lines.push(Line::from(""));

    // One line stating the v1 stub *above the fold* — on an 18-row terminal the
    // long prose below starts at/past the bottom edge, and the operator must not
    // be able to reach the fence without having seen that engaging is inert
    // today (invariant 3, plan §8). The full explanation still follows.
    for row in wrap_words(
        "v1: engaging records intent only — the LUKS header is never touched (the wipe is a stub).",
        BODY_WRAP,
    ) {
        lines.push(Line::from(Span::styled(format!("  {row}"), bold)));
    }
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
        for row in wrap_words(para, BODY_WRAP) {
            lines.push(Line::from(Span::raw(format!("  {row}"))));
        }
        lines.push(Line::from(""));
    }

    let hint = if down {
        // The fence is refused while unreachable (see `App::open_destroy_fence`);
        // don't offer an action the daemon can't receive.
        "reconnect to the daemon before changing the engaged state (r to retry)".to_owned()
    } else {
        format!(
            "▸ press Enter to {} — you will be asked to type DESTROY",
            if engaged { "DISENGAGE" } else { "ENGAGE" }
        )
    };
    let hint_style = if down { t.dim() } else { bold };
    for row in wrap_words(&hint, BODY_WRAP) {
        lines.push(Line::from(Span::styled(format!("  {row}"), hint_style)));
    }

    lines
}

/// Lines [`render`] draws for the current [`App`] state — the reducer clamps
/// `App::destroy_scroll` to this so a `Paragraph` offset can't run past the
/// content into blank space.
pub fn line_count<C: Client>(app: &App<C>) -> u16 {
    body_lines(app).len() as u16
}

/// Word-wrap `text` to rows no wider than `width` (byte length, which
/// over-counts multi-byte glyphs and so only wraps early). Keeps the body's
/// logical line count equal to its rendered row count.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    let mut row = String::new();
    for word in text.split_whitespace() {
        if !row.is_empty() && row.len() + 1 + word.len() > width {
            rows.push(std::mem::take(&mut row));
        }
        if !row.is_empty() {
            row.push(' ');
        }
        row.push_str(word);
    }
    if !row.is_empty() {
        rows.push(row);
    }
    rows
}

/// The big colour-*and*-word engaged-state block, pre-wrapped. `Conn::Down`
/// overrides the cached `engaged` value with UNKNOWN — a downed daemon may have
/// changed it, and showing a stale "not engaged" on this screen is the reading
/// the review gate flagged as sharpest.
fn state_lines(conn: &Conn, engaged: bool, t: &Theme) -> Vec<Line<'static>> {
    // A glyph prefix carries the weight too, not colour alone (NO_COLOR).
    let (words, style): (&str, Style) = if matches!(conn, Conn::Down) {
        (
            "??  ENGAGED STATE UNKNOWN — daemon unreachable",
            t.invalid(),
        )
    } else if engaged {
        (
            "▓▓  ENGAGED — a kill while armed would, in a future release, wipe this header",
            t.invalid(),
        )
    } else {
        (
            "░░  not engaged — a kill will not touch the header",
            t.disarmed(),
        )
    };
    wrap_words(words, BODY_WRAP)
        .into_iter()
        .map(|row| Line::from(Span::styled(format!("  {row}"), style)))
        .collect()
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
    use crate::client::ScriptedClient;
    use killbill_proto::{ConfigPayload, LuksDestroyInfo, OnSensorGap, PowerAction};

    fn text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn app_with_luks() -> App<ScriptedClient> {
        let mut a = App::new(ScriptedClient::new(vec![]));
        a.conn = Conn::Up;
        a.config = Some(ConfigPayload {
            armed_at_boot: false,
            sensors: vec!["usb".to_owned()],
            dry_run: false,
            power_action: PowerAction::PowerOff,
            on_sensor_gap: OnSensorGap::Warn,
            luks_destroy: Some(LuksDestroyInfo {
                acknowledged: true,
                target_header: "/dev/nvme0n1p3".to_owned(),
                engaged: false,
            }),
            validation_error: None,
        });
        a
    }

    fn joined(lines: &[Line]) -> String {
        lines.iter().map(|l| text(l)).collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn body_is_pre_wrapped_so_logical_lines_equal_rendered_rows() {
        let a = app_with_luks();
        let lines = body_lines(&a);
        // Well past `MIN_H` (18) minus chrome — the reason the screen scrolls.
        assert!(lines.len() > 12, "got {} lines", lines.len());
        assert_eq!(line_count(&a) as usize, lines.len());
        // Every prose/state/hint row already fits the wrap width (+ the
        // two-space indent), so `Paragraph` never re-wraps and the reducer's
        // clamp against this logical count is accurate. (The `target header`
        // line is a raw span and exempt — an exotic long path may still wrap.)
        for l in &lines {
            let s = text(l);
            if s.contains("target header") {
                continue;
            }
            assert!(s.len() <= BODY_WRAP + 2, "over-wide row: {s:?}");
        }
        // The engage hint is in the body, reachable by scrolling to the end.
        assert!(
            joined(&lines).contains("press Enter to ENGAGE"),
            "got: {}",
            joined(&lines)
        );

        // The "wipe is a stub" statement sits above the fold — an 18-row
        // terminal has ~14 body rows, so the stub line must land well inside
        // that (tui-ux S2, invariant 3).
        let stub = lines
            .iter()
            .position(|l| text(l).contains("the wipe is a stub"))
            .expect("stub line present");
        assert!(
            stub < 12,
            "stub line at row {stub}, at/below the ~14-row fold"
        );
    }

    #[test]
    fn wrap_words_keeps_every_row_within_width_and_loses_no_text() {
        let src = "the quick brown fox jumps over the lazy dog and then keeps on running";
        let rows = wrap_words(src, 20);
        assert!(rows.len() > 1);
        for r in &rows {
            assert!(r.len() <= 20, "over-wide row: {r:?}");
        }
        assert_eq!(rows.join(" "), src);
    }

    #[test]
    fn state_lines_hide_the_cached_engaged_value_while_the_daemon_is_down() {
        let t = Theme::detect();

        // Even with a cached `engaged = false`, a downed daemon must not be
        // rendered as "not engaged" — that is the stale reading the review
        // gate flagged as sharpest on this screen.
        let down = joined(&state_lines(&Conn::Down, false, &t));
        assert!(down.contains("UNKNOWN"), "got: {down}");
        assert!(!down.contains("not engaged"), "got: {down}");

        // Connected, the real state shows through both ways.
        assert!(joined(&state_lines(&Conn::Up, true, &t)).contains("ENGAGED"));
        assert!(joined(&state_lines(&Conn::Up, false, &t)).contains("not engaged"));
    }
}
