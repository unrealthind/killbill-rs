//! The Help screen (plan §5, build step 11).
//!
//! A static reference for the keys and the menu. It is kept in step with
//! [`crate::input`] by hand — the set is small and changes rarely; a key that
//! appears here and nowhere in `input::intent` (or the reverse) is the bug this
//! screen exists to catch.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;

/// `(key, meaning)` rows, grouped by a leading `None` marker line's heading.
const SECTIONS: &[(&str, &[(&str, &str)])] = &[
    (
        "Everywhere",
        &[
            ("↑ / ↓  (k / j)", "move the selection, or scroll"),
            ("Enter", "activate the selected item / confirm a modal"),
            ("Esc", "close a modal, else go back to Devices"),
            ("m", "open the main menu (also closes any other modal)"),
            ("?", "this help screen"),
            (
                "r",
                "refresh this screen — or retry while the daemon is down",
            ),
            ("q  (Ctrl-C)", "quit now (this never disarms the daemon)"),
        ],
    ),
    (
        "Devices (home)",
        &[(
            "Enter",
            "act on the selected device: add to / remove from whitelist",
        )],
    ),
    (
        "Whitelist",
        &[
            (
                "Enter (top row)",
                "add an entry by typing a vendor:product id",
            ),
            ("Enter (an entry)", "edit its max count, or remove it"),
        ],
    ),
    (
        "Settings",
        &[(
            "Enter",
            "toggle or cycle the selected field, via the daemon",
        )],
    ),
    (
        "Dry-run",
        &[("r", "run the policy engine again over the current devices")],
    ),
    (
        "Event log",
        &[
            (
                "↑ / ↓",
                "scroll back through the stream (this pauses following)",
            ),
            ("p", "freeze / resume following the newest line"),
        ],
    ),
    (
        "LUKS destroy",
        &[
            (
                "Enter",
                "start the typed-DESTROY fence to engage / disengage",
            ),
            (
                "↑ / ↓",
                "scroll — the screen is taller than a small terminal",
            ),
        ],
    ),
];

const MENU_NOTES: &[&str] = &[
    "Main menu (m): Devices · Whitelist · Dry-run · Settings · Event log · Config",
    "              LUKS destroy  (greyed until configured)",
    "              Arm  (greyed while the config is invalid) · Disarm · Reload",
    "              Help · Quit",
    "Arm, Disarm and Reload each ask for confirmation first.",
    "Quitting the TUI — or killing it — never changes the daemon's armed state.",
];

/// The number of lines [`render`] builds, so the reducer can bound
/// `App::help_scroll` (a `Paragraph` scrolled past its content just shows
/// blank). `render` does **not** wrap — one logical line is one rendered row,
/// so this count is exact and the clamp reaches the last row (a long
/// description clips at the right edge on a very narrow terminal; the key
/// column, on the left, always shows). Kept in step with `render` by hand —
/// same as the key list itself.
pub fn line_count() -> u16 {
    let mut n: u16 = 1; // title
    for (_, keys) in SECTIONS {
        n += 2 + keys.len() as u16; // blank + heading + rows
    }
    n += 1 + MENU_NOTES.len() as u16 + 2; // blank + notes + blank + footer
    n
}

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let bold = Style::default().add_modifier(Modifier::BOLD);

    let mut lines: Vec<Line> = vec![Line::from(Span::styled("killbill-tui — keys & menu", bold))];

    for (heading, keys) in SECTIONS {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled((*heading).to_owned(), bold)));
        for (key, what) in *keys {
            lines.push(Line::from(vec![
                Span::styled(format!("  {key:<18}"), bold),
                Span::raw((*what).to_owned()),
            ]));
        }
    }

    lines.push(Line::from(""));
    for note in MENU_NOTES {
        lines.push(Line::from(Span::styled((*note).to_owned(), t.dim())));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "↑ / ↓ to scroll · Esc to go back".to_owned(),
        t.dim(),
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Help "))
            .scroll((app.help_scroll, 0)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rebuild the line list exactly as [`render`] does (minus the styling) and
    /// assert [`line_count`] matches it. Since `render` no longer wraps, this
    /// count is the real rendered-row count and the `help_scroll` clamp reaches
    /// the last row.
    #[test]
    fn line_count_matches_the_rows_render_builds() {
        let mut n: u16 = 1; // title
        for (_, keys) in SECTIONS {
            n += 1; // blank
            n += 1; // heading
            n += keys.len() as u16;
        }
        n += 1; // blank before the notes
        n += MENU_NOTES.len() as u16;
        n += 1; // blank before the footer
        n += 1; // footer
        assert_eq!(line_count(), n);
    }

    /// Ctrl-C must appear in the reference (tui-ux S4) — raw mode makes it
    /// non-obvious that it is handled at all.
    #[test]
    fn the_everywhere_section_documents_ctrl_c() {
        let (_, everywhere) = SECTIONS[0];
        assert!(
            everywhere.iter().any(|(k, _)| k.contains("Ctrl-C")),
            "Ctrl-C quit is undocumented"
        );
    }
}
