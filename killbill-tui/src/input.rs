//! Keypress → [`Intent`]. One small table, screen-aware only where it must be.
//!
//! Menu-driven navigation (plan §6): arrows + `Enter` + `Esc` do everything;
//! the letter keys are accelerators, never the only path to an action.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::{App, Conn, Intent, Modal};
use crate::client::Client;

pub fn intent<C: Client>(app: &App<C>, key: KeyEvent) -> Intent {
    // Ignore key-release / key-repeat events from terminals that send them;
    // act on the press only.
    if key.kind != KeyEventKind::Press {
        return Intent::None;
    }

    // Raw mode disables the terminal's own signal handling, so Ctrl-C arrives
    // as an ordinary key. Honour the universal "get me out": quitting never
    // touches the daemon's armed state (invariant 5). Other Ctrl-/Alt-chords
    // are swallowed rather than fed to a text field as their bare letter.
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Intent::Quit,
            _ => Intent::None,
        };
    }

    // Step two of the LUKS fence: only `y`/`Y` confirms; per plan §8 *any* other
    // key — arrows, Enter, Esc, Backspace included — cancels and sends nothing.
    if matches!(app.modal, Some(Modal::DestroyConfirm { .. })) {
        return match key.code {
            KeyCode::Char(c) if c == 'y' || c == 'Y' => Intent::Char(c),
            _ => Intent::Back,
        };
    }

    // A text-entry modal (the whitelist "add by id" field) captures printable
    // characters instead of letting them act as accelerators. `Enter` / `Esc`
    // / `Backspace` still mean what they always mean.
    if app.capturing_text() {
        return match key.code {
            KeyCode::Esc => Intent::Back,
            KeyCode::Enter => Intent::Select,
            KeyCode::Backspace => Intent::Backspace,
            KeyCode::Char(c) => Intent::Char(c),
            _ => Intent::None,
        };
    }

    match key.code {
        KeyCode::Char('q') => Intent::Quit,
        KeyCode::Char('m') => Intent::ToggleMenu,
        KeyCode::Char('?') => Intent::Help,
        // Event-log follow toggle (plan §5); inert on every other screen.
        KeyCode::Char('p') => Intent::TogglePause,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::client::ScriptedClient;

    fn app() -> App<ScriptedClient> {
        App::new(ScriptedClient::new(vec![]))
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn ctrl_c_quits_from_anywhere() {
        let a = app();
        assert!(matches!(intent(&a, ctrl(KeyCode::Char('c'))), Intent::Quit));
    }

    #[test]
    fn ctrl_c_quits_even_inside_a_text_modal() {
        let mut a = app();
        a.modal = Some(Modal::WhitelistAddId);
        assert!(matches!(intent(&a, ctrl(KeyCode::Char('c'))), Intent::Quit));
        // ...and a stray Ctrl-letter is swallowed, not typed as its bare char.
        assert!(matches!(intent(&a, ctrl(KeyCode::Char('u'))), Intent::None));
    }

    #[test]
    fn destroy_confirm_sends_nothing_on_any_key_but_y() {
        let mut a = app();
        a.modal = Some(Modal::DestroyConfirm { engage: true });
        assert!(matches!(
            intent(&a, press(KeyCode::Char('y'))),
            Intent::Char('y')
        ));
        assert!(matches!(
            intent(&a, press(KeyCode::Char('Y'))),
            Intent::Char('Y')
        ));
        for code in [
            KeyCode::Char('n'),
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Up,
            KeyCode::Backspace,
        ] {
            assert!(
                matches!(intent(&a, press(code)), Intent::Back),
                "{code:?} should cancel the fence"
            );
        }
    }
}
