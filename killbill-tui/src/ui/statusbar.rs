//! The persistent one-line armed-state band (plan §7).
//!
//! Rendered on every screen. The state is carried by a glyph *and* a word, not
//! colour alone, so it survives `NO_COLOR`. `DRY-RUN` is tagged separately —
//! armed-but-dry is an easy state to miss.
//!
//! Span order is priority order. At 60–80 columns the line overflows the right
//! edge with no wrap, so whatever sits last is what clips. After the headline,
//! spans emit in this order:
//!
//!   1. the failures the operator did *not* choose and must not miss —
//!      `SENSOR STOPPED`, `EVENTS LOST` (invariant 7: a blind daemon protects
//!      nothing);
//!   2. the silent belts the operator *did* choose — `DRY-RUN`, `POWER: NONE`,
//!      `POWER: HALT` — armed but will not cut power;
//!   3. `CONFIG STALE`, `CONFIG INVALID`, `LUKS DESTROY ENGAGED` (invariant 4);
//!   4. the low-value whitelist/device counts, dead last — the first thing
//!      allowed to clip off the right edge.

use killbill_proto::PowerAction;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, Conn};
use crate::client::Client;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    frame.render_widget(Paragraph::new(Line::from(band_spans(app))), area);
}

/// The band as an ordered span list. Split out from [`render`] so it is
/// testable without a `Frame` — the house pattern (`ui::destroy::state_line`,
/// `ui::devices::device_line`).
fn band_spans<C: Client>(app: &App<C>) -> Vec<Span<'static>> {
    let t = &app.theme;
    let mut spans: Vec<Span<'static>> = Vec::new();

    // `Conn::Down` takes priority over the cached `status` even when one
    // exists: the daemon may have changed state since the connection was
    // lost, so the last-known armed/disarmed word must not be shown as
    // current fact (a deferred Phase 2 defect). What we last knew is still
    // useful context — just clearly marked as stale, not dropped.
    //
    // While connected, `armed` wins the headline over `config_error`. The two
    // can only coexist transiently (`arm` refuses while `config_error` is set,
    // and clears it on a good reload), but if a bad reload lands beside a still-
    // armed daemon, the daemon is still protecting on its last-good config —
    // "ARMED" is the true headline and `CONFIG INVALID` shows as a tag below,
    // not as a headline that reads like "not protecting".
    let (glyph, word, style) = match (&app.conn, &app.status) {
        (Conn::Connecting, _) => ("…", "CONNECTING", t.dim()),
        (Conn::Down, Some(s)) if s.armed => ("?", "LAST KNOWN: ARMED", t.warn()),
        (Conn::Down, Some(_)) => ("?", "LAST KNOWN: DISARMED", t.warn()),
        (Conn::Down, None) => ("…", "NO STATUS", t.dim()),
        (Conn::Up, Some(s)) if s.armed => ("●", "ARMED", t.armed()),
        (Conn::Up, Some(s)) if s.config_error.is_some() => {
            ("▲", "DISARMED — CONFIG INVALID, WILL NOT ARM", t.invalid())
        }
        (Conn::Up, Some(_)) => ("○", "DISARMED", t.disarmed()),
        (Conn::Up, None) => ("…", "NO STATUS", t.dim()),
    };
    spans.push(Span::styled(format!(" {glyph} {word} "), style));

    if matches!(app.conn, Conn::Down) {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("[daemon unreachable]", t.warn()));
        return spans;
    }

    // The detail fields are exactly as stale as the headline above — only show
    // them while `status` is both present and believed current.
    let (Conn::Up, Some(s)) = (&app.conn, &app.status) else {
        return spans;
    };

    // --- failures the operator did not choose, highest priority after the
    //     headline: a daemon that cannot see devices is not protecting, and a
    //     gap may have hidden the unplug this tool exists to catch (invariant
    //     7). These must never be the span that clips.

    if !s.sensor_ok {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("SENSOR STOPPED", t.warn()));
    }

    if s.events_lost {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("EVENTS LOST", t.warn()));
    }

    // --- the silent belts the operator *did* set: armed but will not act. Lower
    //     priority than an unchosen failure, but still glyph-and-word not colour
    //     (kill-path review H1) so `NO_COLOR` keeps them.

    if s.dry_run {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(" DRY-RUN ", t.disarmed()));
    }

    match s.power_action {
        PowerAction::PowerOff => {}
        PowerAction::None => {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(" POWER: NONE — WILL NOT CUT POWER ", t.warn()));
        }
        PowerAction::Halt => {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(" POWER: HALT — WILL NOT CUT POWER ", t.warn()));
        }
        _ => {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(" POWER: ? ", t.warn()));
        }
    }

    if s.config_stale {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("CONFIG STALE", t.warn()));
    }

    // The on-disk config is invalid. Shown as a tag here (not the headline)
    // so it is visible even when `armed` legitimately owns the headline.
    if s.config_error.is_some() {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("CONFIG INVALID", t.invalid()));
    }

    // A destructive runtime state (invariant 4) — surfaced wherever the band
    // is, not only on the LUKS screen. `config` is a cache like the rest of
    // this block, so it is gated the same way.
    if app.luks_engaged() {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("LUKS DESTROY ENGAGED", t.invalid()));
    }

    // Lowest priority — the first thing allowed to clip off the right edge.
    spans.push(Span::raw("   "));
    spans.push(Span::styled(
        format!("whitelist {} · devices {}", s.whitelist_len, s.device_count),
        t.dim(),
    ));

    spans
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ScriptedClient;
    use killbill_proto::{ConfigPayload, LuksDestroyInfo, OnSensorGap, StatusPayload};

    fn app() -> App<ScriptedClient> {
        let mut a = App::new(ScriptedClient::new(vec![]));
        a.conn = Conn::Up;
        a
    }

    fn status() -> StatusPayload {
        StatusPayload {
            armed: false,
            dry_run: false,
            power_action: PowerAction::PowerOff,
            whitelist_len: 3,
            device_count: 5,
            config_error: None,
            sensor_ok: true,
            events_lost: false,
            config_stale: false,
        }
    }

    fn config_engaged() -> ConfigPayload {
        ConfigPayload {
            armed_at_boot: false,
            sensors: vec!["usb".to_owned()],
            dry_run: false,
            power_action: PowerAction::PowerOff,
            on_sensor_gap: OnSensorGap::Warn,
            luks_destroy: Some(LuksDestroyInfo {
                acknowledged: true,
                target_header: "/dev/nvme0n1p3".to_owned(),
                engaged: true,
            }),
            validation_error: None,
        }
    }

    fn text(spans: &[Span]) -> Vec<String> {
        spans.iter().map(|s| s.content.to_string()).collect()
    }

    fn index_of(spans: &[Span], needle: &str) -> Option<usize> {
        text(spans).iter().position(|s| s.contains(needle))
    }

    #[test]
    fn danger_tags_precede_the_counts_in_the_span_list() {
        let mut a = app();
        a.status = Some(StatusPayload {
            events_lost: true,
            config_stale: true,
            ..status()
        });
        a.config = Some(config_engaged());

        let spans = band_spans(&a);
        let counts = index_of(&spans, "whitelist 3").expect("counts span present");
        for tag in ["EVENTS LOST", "CONFIG STALE", "LUKS DESTROY ENGAGED"] {
            let at = index_of(&spans, tag).unwrap_or_else(|| panic!("{tag} present"));
            assert!(at < counts, "{tag} must sit before the counts");
        }
    }

    #[test]
    fn the_silent_belts_are_tagged_glyph_and_word_not_colour() {
        // `power_action = none` / `halt` and `dry_run` all leave `armed`
        // reading true while no kill actually cuts power — each must show as
        // text, not a colour a NO_COLOR terminal drops (kp H1).
        for (pa, needle) in [
            (PowerAction::None, "POWER: NONE"),
            (PowerAction::Halt, "POWER: HALT"),
        ] {
            let mut a = app();
            a.status = Some(StatusPayload {
                armed: true,
                power_action: pa,
                ..status()
            });
            assert!(
                index_of(&band_spans(&a), needle).is_some(),
                "{needle} tag missing"
            );
        }

        let mut a = app();
        a.status = Some(StatusPayload {
            armed: true,
            dry_run: true,
            ..status()
        });
        assert!(index_of(&band_spans(&a), "DRY-RUN").is_some());
    }

    #[test]
    fn unchosen_failures_precede_the_silent_belts_in_the_span_list() {
        // A tri-condition case: dry-run on, power=none, and the sensor died.
        // The failure the operator did not choose (SENSOR STOPPED) must sit
        // ahead of the belts they did (DRY-RUN, POWER) so it is not the span
        // that clips off a narrow terminal (tui-ux S1, invariant 7).
        let mut a = app();
        a.status = Some(StatusPayload {
            armed: true,
            dry_run: true,
            power_action: PowerAction::None,
            sensor_ok: false,
            events_lost: true,
            ..status()
        });
        let spans = band_spans(&a);
        let sensor = index_of(&spans, "SENSOR STOPPED").expect("SENSOR STOPPED present");
        let events = index_of(&spans, "EVENTS LOST").expect("EVENTS LOST present");
        let dry = index_of(&spans, "DRY-RUN").expect("DRY-RUN present");
        let power = index_of(&spans, "POWER: NONE").expect("POWER tag present");
        assert!(
            sensor < dry && sensor < power,
            "SENSOR STOPPED must precede the belts"
        );
        assert!(
            events < dry && events < power,
            "EVENTS LOST must precede the belts"
        );
    }

    #[test]
    fn a_stopped_sensor_is_shown_and_a_healthy_one_is_silent() {
        let mut a = app();
        a.status = Some(StatusPayload {
            sensor_ok: false,
            ..status()
        });
        assert!(index_of(&band_spans(&a), "SENSOR STOPPED").is_some());

        let mut a = app();
        a.status = Some(status()); // sensor_ok = true
        let spans = band_spans(&a);
        assert!(
            index_of(&spans, "SENSOR").is_none(),
            "a healthy sensor needs no shout"
        );
    }

    #[test]
    fn a_downed_daemon_suppresses_the_stale_detail_rows() {
        let mut a = app();
        a.on_disconnected("gone".to_owned());
        a.status = Some(StatusPayload {
            armed: true,
            events_lost: true,
            ..status()
        });
        let spans = band_spans(&a);
        assert!(spans[0].content.contains("LAST KNOWN: ARMED"));
        assert!(index_of(&spans, "[daemon unreachable]").is_some());
        // The cached detail fields are exactly as stale as the headline — none
        // of them render while down.
        assert!(index_of(&spans, "EVENTS LOST").is_none());
        assert!(index_of(&spans, "whitelist").is_none());
    }

    #[test]
    fn armed_beats_config_invalid_in_the_headline() {
        let mut a = app();
        a.status = Some(StatusPayload {
            armed: true,
            config_error: Some("bad key on line 4".to_owned()),
            ..status()
        });

        let spans = band_spans(&a);
        assert!(
            spans[0].content.contains("ARMED"),
            "got: {}",
            spans[0].content
        );
        assert!(
            index_of(&spans, "CONFIG INVALID").is_some(),
            "the invalid-config tag is still shown, just not as the headline"
        );
    }
}
