//! The Dry-run screen (plan §5, build step 10).
//!
//! "What would happen right now": one line per currently-connected device that
//! the policy engine would fire a kill for, or a clear "nothing would fire".
//! Read-only — `r` re-runs it, nothing is ever powered off.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::screen_title;
use crate::app::App;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(screen_title(app, " Dry-run "));

    let lines: Vec<Line> = match &app.dryrun {
        None => vec![Line::from(Span::styled(
            "No dry run yet — press r to run one.",
            t.dim(),
        ))],
        Some(reasons) if reasons.is_empty() => vec![
            Line::from(Span::styled(
                "Nothing currently connected would trigger a kill.",
                t.disarmed(),
            )),
            Line::from(""),
            Line::from(Span::styled("r to re-run", t.dim())),
        ],
        Some(reasons) => {
            let mut v = vec![
                Line::from(Span::styled(
                    format!("{} device(s) would trigger a kill:", reasons.len()),
                    t.warn(),
                )),
                Line::from(""),
            ];
            for r in reasons {
                v.push(Line::from(format!("  - {r}")));
            }
            v.push(Line::from(""));
            v.push(Line::from(Span::styled(
                "this is a dry run — nothing was powered off · r to re-run",
                t.dim(),
            )));
            v
        }
    };

    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}
