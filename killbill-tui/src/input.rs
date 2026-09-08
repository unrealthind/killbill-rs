//! Keypress → [`Intent`]. One small table, screen-aware only where it must be.
//!
//! Menu-driven navigation (plan §6): arrows + `Enter` + `Esc` do everything;
//! the letter keys are accelerators, never the only path to an action.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::app::{App, Conn, Intent};

pub fn intent(app: &App, key: KeyEvent) -> Intent {
    // Ignore key-release / key-repeat events from terminals that send them;
    // act on the press only.
    if key.kind != KeyEventKind::Press {
        return Intent::None;
    }

    match key.code {
        KeyCode::Char('q') => Intent::Quit,
        KeyCode::Char('m') => Intent::ToggleMenu,
        KeyCode::Char('?') => Intent::Help,
        KeyCode::Esc => Intent::Back,

        KeyCode::Up | KeyCode::Char('k') => Intent::Up,
        KeyCode::Down | KeyCode::Char('j') => Intent::Down,
        KeyCode::Enter => Intent::Select,

        // `r` reconnects while the daemon is down, otherwise it re-fetches.
        KeyCode::Char('r') => match app.conn {
            Conn::Down => Intent::Reconnect,
            _ => Intent::Refresh,
        },

        _ => Intent::None,
    }
}
