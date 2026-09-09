//! Colour, with a monochrome fallback (plan §9).
//!
//! Two style sets. The monochrome set is used when `NO_COLOR` is set, `TERM` is
//! `dumb`, or stdout is not a terminal — and it must still make armed vs.
//! disarmed unmistakable, so it leans on bold / reverse / underline rather than
//! hue. Colour is never the *only* carrier of a state: the status band pairs
//! every colour with a glyph and a word.

use std::io::IsTerminal;

use ratatui::style::{Color, Modifier, Style};

pub struct Theme {
    mono: bool,
}

impl Theme {
    pub fn detect() -> Self {
        // `NO_COLOR`: honoured when set to a non-empty value (the informal spec).
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let dumb_term = std::env::var("TERM").is_ok_and(|t| t == "dumb");
        let mono = no_color || dumb_term || !std::io::stdout().is_terminal();
        Self { mono }
    }

    /// Foreground colour, dropped entirely in monochrome mode.
    fn fg(&self, c: Color) -> Style {
        if self.mono {
            Style::default()
        } else {
            Style::default().fg(c)
        }
    }

    /// `● ARMED` — the safe, protected state.
    pub fn armed(&self) -> Style {
        self.fg(Color::Green)
            .add_modifier(Modifier::BOLD | Modifier::REVERSED)
    }

    /// `○ DISARMED` — detect-and-report only.
    pub fn disarmed(&self) -> Style {
        self.fg(Color::Yellow).add_modifier(Modifier::BOLD)
    }

    /// `▲ CONFIG INVALID` — the daemon will refuse to arm.
    pub fn invalid(&self) -> Style {
        self.fg(Color::Red)
            .add_modifier(Modifier::BOLD | Modifier::REVERSED)
    }

    /// A non-fatal problem worth the eye: sensor stopped, events lost.
    pub fn warn(&self) -> Style {
        self.fg(Color::Red).add_modifier(Modifier::BOLD)
    }

    /// The selected row / menu item.
    pub fn selected(&self) -> Style {
        Style::default().add_modifier(Modifier::REVERSED)
    }

    /// Secondary text — hints, counts, separators.
    pub fn dim(&self) -> Style {
        Style::default().add_modifier(Modifier::DIM)
    }
}
