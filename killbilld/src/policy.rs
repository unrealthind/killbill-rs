//! The policy engine (charter §6, build step 3).
//!
//! One pure function: [`SensorEvent`] + [`Config`] + [`DeviceTable`] → a
//! [`Decision`]. No clock, no I/O, no logging, no `async`. This is deliberately
//! the most readable file in the daemon — the entire decision surface is here,
//! and it is exhaustively unit-tested below, rejection cases included.
//!
//! Armed/disarmed is *not* this function's concern. The daemon calls [`decide`]
//! for every event so control-socket subscribers always see the reasoning; it
//! then dispatches to responders only when armed. Dry-run is carried on the
//! resulting [`Action`], not decided here.
//!
//! ## The v1 rule set (armed)
//!
//! | event | condition | decision |
//! |---|---|---|
//! | added | id not on whitelist | `Act(UnknownDevice)` |
//! | added | no readable id | `Act(UnidentifiedDevice)` |
//! | added | whitelisted, copies now > `max_count` | `Act(CountExceeded)` |
//! | added | whitelisted, within `max_count` | `Ignore` |
//! | removed | id is on the whitelist | `Act(WhitelistedDeviceRemoved)` |
//! | removed | anything else | `Act(DeviceRemoved)` |
//!
//! Removing *any* device while armed fires: unplugging hardware is the classic
//! seizure signal, and it is what the original `usbkill` did. The whitelist
//! suppresses *additions* you expect; it does not make a device safe to yank.

use killbill_proto::{Action, EventKind, KillReason, SensorEvent};

use crate::config::Config;
use crate::device_table::DeviceTable;

/// The outcome of evaluating one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The event is authorized or harmless. Do nothing.
    Ignore,
    /// The event is unauthorized. When armed, dispatch this to every responder.
    Act(Action),
}

/// Evaluate one sensor event against policy.
///
/// `table` must be the device table as it was **before** `event` is applied —
/// the daemon calls `decide` first, then updates the table. This is why
/// [`KillReason::CountExceeded`]'s `seen` is `table.count(id) + 1`.
///
/// `luks_destroy_engaged` is the runtime toggle from
/// [`killbill_proto::Command::SetLuksDestroyEngaged`] (`Core` state, not
/// config) — see [`act`] for why it takes two flags, not one, to set
/// `Action::luks_destroy`.
pub fn decide(
    event: &SensorEvent,
    cfg: &Config,
    table: &DeviceTable,
    luks_destroy_engaged: bool,
) -> Decision {
    match event.kind {
        EventKind::Added => decide_added(event, cfg, table, luks_destroy_engaged),
        EventKind::Removed => decide_removed(event, cfg, luks_destroy_engaged),
    }
}

fn decide_added(
    event: &SensorEvent,
    cfg: &Config,
    table: &DeviceTable,
    luks_destroy_engaged: bool,
) -> Decision {
    let Some(id) = event.identity.usb_id else {
        return act(cfg, KillReason::UnidentifiedDevice, luks_destroy_engaged);
    };

    match cfg.whitelist.iter().find(|rule| rule.id == id) {
        None => act(cfg, KillReason::UnknownDevice { id }, luks_destroy_engaged),
        Some(rule) => {
            let seen = table.count(id).saturating_add(1);
            if seen > rule.max_count {
                act(
                    cfg,
                    KillReason::CountExceeded {
                        id,
                        max: rule.max_count,
                        seen,
                    },
                    luks_destroy_engaged,
                )
            } else {
                Decision::Ignore
            }
        }
    }
}

fn decide_removed(event: &SensorEvent, cfg: &Config, luks_destroy_engaged: bool) -> Decision {
    match event.identity.usb_id {
        Some(id) if cfg.whitelist.iter().any(|rule| rule.id == id) => act(
            cfg,
            KillReason::WhitelistedDeviceRemoved { id },
            luks_destroy_engaged,
        ),
        id => act(cfg, KillReason::DeviceRemoved { id }, luks_destroy_engaged),
    }
}

/// Build an `Act` decision, stamping it with the config's response settings.
///
/// `Action::luks_destroy` requires **both** flags: `cfg.luks_destroy.is_some()`
/// (the config-time acknowledgment, `i_understand_this_is_irreversible`) *and*
/// `luks_destroy_engaged` (the runtime toggle, `Core`'s twin of the config
/// flag — see `killbill_proto::Command::SetLuksDestroyEngaged`). Invariant 4:
/// the dangerous thing needs its own distinctly-named opt-in, and here there
/// are deliberately two of them, config-time and runtime, neither sufficient
/// alone. `killbilld` restarts with `luks_destroy_engaged = false` always —
/// it is never persisted — so this can never come back silently engaged.
fn act(cfg: &Config, reason: KillReason, luks_destroy_engaged: bool) -> Decision {
    Decision::Act(Action {
        reason,
        power: cfg.power_action,
        luks_destroy: cfg.luks_destroy.is_some() && luks_destroy_engaged,
        dry_run: cfg.dry_run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{validate, RawConfig, WhitelistRule};
    use killbill_proto::{DeviceIdentity, PowerAction, SensorSource, UsbId};

    const WHITELISTED: UsbId = UsbId::new(0x1050, 0x0407);
    const STRANGER: UsbId = UsbId::new(0x0781, 0x5567);

    /// A config with one whitelist entry (`max_count = max`) and the given
    /// response knobs.
    fn config(max: u32, dry_run: bool, power: PowerAction) -> Config {
        let mut cfg = validate(RawConfig::default()).unwrap();
        cfg.whitelist = vec![WhitelistRule {
            id: WHITELISTED,
            label: Some("YubiKey".to_owned()),
            max_count: max,
        }];
        cfg.dry_run = dry_run;
        cfg.power_action = power;
        cfg
    }

    fn event(kind: EventKind, id: Option<UsbId>) -> SensorEvent {
        SensorEvent {
            source: SensorSource::Usb,
            kind,
            identity: DeviceIdentity {
                usb_id: id,
                serial: None,
                label: None,
            },
            raw: Default::default(),
        }
    }

    fn reason(decision: Decision) -> KillReason {
        match decision {
            Decision::Act(a) => a.reason,
            Decision::Ignore => panic!("expected Act, got Ignore"),
        }
    }

    /// A config with an acknowledged `[response.luks_destroy]` targeting an
    /// arbitrary `/dev` path — validity of the path itself is `config.rs`'s
    /// concern, not policy's; this only needs `luks_destroy` to be `Some`.
    fn config_with_luks_destroy(power: PowerAction) -> Config {
        let mut cfg = config(1, false, power);
        cfg.luks_destroy = Some(crate::config::LuksDestroy {
            target_header: std::path::PathBuf::from("/dev/nvme0n1p3"),
        });
        cfg
    }

    // --- added -----------------------------------------------------------

    #[test]
    fn unknown_device_added_fires() {
        let d = decide(
            &event(EventKind::Added, Some(STRANGER)),
            &config(1, false, PowerAction::PowerOff),
            &DeviceTable::new(),
            false,
        );
        assert_eq!(reason(d), KillReason::UnknownDevice { id: STRANGER });
    }

    #[test]
    fn unidentified_device_added_fires() {
        let d = decide(
            &event(EventKind::Added, None),
            &config(1, false, PowerAction::PowerOff),
            &DeviceTable::new(),
            false,
        );
        assert_eq!(reason(d), KillReason::UnidentifiedDevice);
    }

    #[test]
    fn whitelisted_device_added_within_count_is_ignored() {
        let d = decide(
            &event(EventKind::Added, Some(WHITELISTED)),
            &config(1, false, PowerAction::PowerOff),
            &DeviceTable::new(),
            false,
        );
        assert_eq!(d, Decision::Ignore);
    }

    #[test]
    fn whitelisted_device_added_at_the_limit_is_ignored() {
        // max_count = 2, one already present, this is the second -> ok.
        let table: DeviceTable = [WHITELISTED].into_iter().collect();
        let d = decide(
            &event(EventKind::Added, Some(WHITELISTED)),
            &config(2, false, PowerAction::PowerOff),
            &table,
            false,
        );
        assert_eq!(d, Decision::Ignore);
    }

    #[test]
    fn whitelisted_device_added_over_the_limit_fires_with_counts() {
        // max_count = 1, one already present, this is the second -> fire.
        let table: DeviceTable = [WHITELISTED].into_iter().collect();
        let d = decide(
            &event(EventKind::Added, Some(WHITELISTED)),
            &config(1, false, PowerAction::PowerOff),
            &table,
            false,
        );
        assert_eq!(
            reason(d),
            KillReason::CountExceeded {
                id: WHITELISTED,
                max: 1,
                seen: 2,
            }
        );
    }

    // --- removed --------------------------------------------------------

    #[test]
    fn whitelisted_device_removed_fires() {
        let d = decide(
            &event(EventKind::Removed, Some(WHITELISTED)),
            &config(1, false, PowerAction::PowerOff),
            &DeviceTable::new(),
            false,
        );
        assert_eq!(
            reason(d),
            KillReason::WhitelistedDeviceRemoved { id: WHITELISTED }
        );
    }

    #[test]
    fn unknown_device_removed_fires() {
        let d = decide(
            &event(EventKind::Removed, Some(STRANGER)),
            &config(1, false, PowerAction::PowerOff),
            &DeviceTable::new(),
            false,
        );
        assert_eq!(reason(d), KillReason::DeviceRemoved { id: Some(STRANGER) });
    }

    #[test]
    fn unidentified_device_removed_fires() {
        let d = decide(
            &event(EventKind::Removed, None),
            &config(1, false, PowerAction::PowerOff),
            &DeviceTable::new(),
            false,
        );
        assert_eq!(reason(d), KillReason::DeviceRemoved { id: None });
    }

    // --- response knobs are threaded onto the Action --------------------

    #[test]
    fn dry_run_flag_is_carried_but_does_not_change_the_decision() {
        let ev = event(EventKind::Added, Some(STRANGER));
        let table = DeviceTable::new();

        let wet = decide(&ev, &config(1, false, PowerAction::PowerOff), &table, false);
        let dry = decide(&ev, &config(1, true, PowerAction::PowerOff), &table, false);

        match (wet, dry) {
            (Decision::Act(wet), Decision::Act(dry)) => {
                assert!(!wet.dry_run);
                assert!(dry.dry_run);
                assert_eq!(wet.reason, dry.reason);
            }
            other => panic!("expected both to Act, got {other:?}"),
        }
    }

    #[test]
    fn power_action_is_taken_from_config() {
        let d = decide(
            &event(EventKind::Added, Some(STRANGER)),
            &config(1, false, PowerAction::Halt),
            &DeviceTable::new(),
            false,
        );
        match d {
            Decision::Act(a) => assert_eq!(a.power, PowerAction::Halt),
            Decision::Ignore => panic!("expected Act"),
        }
    }

    #[test]
    fn luks_destroy_flag_reflects_config_presence() {
        // Default config has no luks_destroy and the runtime toggle is off
        // too -> flag is false. `engaged_flag_alone_does_nothing_without_
        // config_acknowledgment` below covers the same config with the
        // toggle *on*, to isolate that neither flag alone is sufficient.
        let d = decide(
            &event(EventKind::Added, Some(STRANGER)),
            &config(1, false, PowerAction::PowerOff),
            &DeviceTable::new(),
            false,
        );
        match d {
            Decision::Act(a) => assert!(!a.luks_destroy),
            Decision::Ignore => panic!("expected Act"),
        }
    }

    #[test]
    fn luks_destroy_requires_both_config_and_the_runtime_engaged_flag() {
        let ev = event(EventKind::Added, Some(STRANGER));
        let table = DeviceTable::new();
        let cfg = config_with_luks_destroy(PowerAction::PowerOff);

        // Configured and acknowledged, but not engaged at runtime -> false.
        match decide(&ev, &cfg, &table, false) {
            Decision::Act(a) => assert!(
                !a.luks_destroy,
                "must not destroy the header without the runtime engage toggle"
            ),
            Decision::Ignore => panic!("expected Act"),
        }

        // Configured, acknowledged, AND engaged -> true.
        match decide(&ev, &cfg, &table, true) {
            Decision::Act(a) => assert!(a.luks_destroy),
            Decision::Ignore => panic!("expected Act"),
        }
    }

    #[test]
    fn engaged_flag_alone_does_nothing_without_config_acknowledgment() {
        // The mirror of the above: engaged = true but no [response.luks_destroy]
        // in config at all -> still false. Neither flag alone is sufficient
        // (invariant 4).
        let d = decide(
            &event(EventKind::Added, Some(STRANGER)),
            &config(1, false, PowerAction::PowerOff),
            &DeviceTable::new(),
            true,
        );
        match d {
            Decision::Act(a) => assert!(!a.luks_destroy),
            Decision::Ignore => panic!("expected Act"),
        }
    }

    #[test]
    fn empty_whitelist_means_every_addition_is_unknown() {
        let cfg = validate(RawConfig::default()).unwrap();
        assert!(cfg.whitelist.is_empty());
        let d = decide(
            &event(EventKind::Added, Some(WHITELISTED)),
            &cfg,
            &DeviceTable::new(),
            false,
        );
        assert_eq!(reason(d), KillReason::UnknownDevice { id: WHITELISTED });
    }
}
