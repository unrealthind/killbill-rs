//! What a kill decision does.
//!
//! The policy engine produces an [`Action`]; responders consume it. Responders
//! are independent subscribers to the same `Action`, never a pipeline — a
//! logging failure can't gate the poweroff (invariant 1, charter §6).

use serde::{Deserialize, Serialize};

use crate::sensor_event::UsbId;

/// The power operation a kill performs. Mirrors `response.power_action` in config.
// `rename_all = "lowercase"` (not `snake_case`) so `PowerOff` is the one-word
// `"poweroff"` — matching config's `power_action = "poweroff"`, `Display`, and
// the charter. `snake_case` would give `"power_off"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "lowercase")]
pub enum PowerAction {
    /// Power the machine off so the LUKS disk re-locks. The default and the
    /// whole point of the tool.
    #[default]
    PowerOff,
    /// Halt the CPU without cutting power.
    Halt,
    /// Take no power action. The decision still fires (it is logged, and the
    /// `luks_destroy` stub still runs), but the machine stays up.
    None,
}

impl std::fmt::Display for PowerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PowerAction::PowerOff => "poweroff",
            PowerAction::Halt => "halt",
            PowerAction::None => "none",
        })
    }
}

/// Why the policy engine decided an event warrants a kill.
///
/// Carried into the log and the [`crate::Event::WouldKill`] dry-run event, so
/// the operator's account of what happened is exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum KillReason {
    /// A device whose id is not on the whitelist was connected.
    UnknownDevice { id: UsbId },
    /// A device with no readable USB id was connected.
    UnidentifiedDevice,
    /// A whitelisted device was connected, but more copies are now present than
    /// its `max_count` allows. `seen` counts the device from this event.
    CountExceeded { id: UsbId, max: u32, seen: u32 },
    /// A whitelisted device was disconnected.
    WhitelistedDeviceRemoved { id: UsbId },
    /// Any other device was disconnected (`id` absent if it had no readable id).
    DeviceRemoved { id: Option<UsbId> },
}

impl std::fmt::Display for KillReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KillReason::UnknownDevice { id } => write!(f, "unknown device {id} was connected"),
            KillReason::UnidentifiedDevice => {
                f.write_str("a device with no readable USB id was connected")
            }
            KillReason::CountExceeded { id, max, seen } => write!(
                f,
                "too many copies of {id} connected ({seen} present, limit {max})"
            ),
            KillReason::WhitelistedDeviceRemoved { id } => {
                write!(f, "whitelisted device {id} was disconnected")
            }
            KillReason::DeviceRemoved { id: Some(id) } => {
                write!(f, "device {id} was disconnected")
            }
            KillReason::DeviceRemoved { id: None } => {
                f.write_str("an unidentified device was disconnected")
            }
        }
    }
}

/// A kill decision, ready to fan out to every responder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// What triggered the decision.
    pub reason: KillReason,
    /// The power operation to perform.
    pub power: PowerAction,
    /// Whether the fenced LUKS-header-destruction responder should engage.
    /// Even when `true`, v1's responder only logs — the wipe is a stub
    /// (invariant 3). This flag exists so the schema and dry-run path are real.
    pub luks_destroy: bool,
    /// When `true`, responders log what they *would* do and perform no
    /// destructive or power action.
    pub dry_run: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_action_json_is_one_lowercase_word() {
        assert_eq!(
            serde_json::to_string(&PowerAction::PowerOff).unwrap(),
            "\"poweroff\""
        );
        assert_eq!(PowerAction::default(), PowerAction::PowerOff);
    }

    #[test]
    fn kill_reason_display_uses_hex_usb_ids() {
        let text = KillReason::CountExceeded {
            id: UsbId::new(0x1050, 0x0407),
            max: 1,
            seen: 2,
        }
        .to_string();
        assert!(text.contains("1050:0407"), "got: {text}");
        assert!(text.contains("limit 1"), "got: {text}");

        assert_eq!(
            KillReason::DeviceRemoved { id: None }.to_string(),
            "an unidentified device was disconnected"
        );
    }

    #[test]
    fn kill_reason_is_internally_tagged() {
        let reason = KillReason::CountExceeded {
            id: UsbId::new(0x1050, 0x0407),
            max: 1,
            seen: 2,
        };
        let json = serde_json::to_value(&reason).unwrap();
        assert_eq!(json["kind"], "count_exceeded");
        assert_eq!(json["id"], "1050:0407");
        assert_eq!(serde_json::from_value::<KillReason>(json).unwrap(), reason);
    }

    #[test]
    fn kill_reason_unit_and_null_variants_round_trip() {
        for reason in [
            KillReason::UnidentifiedDevice,
            KillReason::DeviceRemoved { id: None },
            KillReason::DeviceRemoved {
                id: Some(UsbId::new(0x1d6b, 0x0002)),
            },
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            assert_eq!(serde_json::from_str::<KillReason>(&json).unwrap(), reason);
        }
    }

    #[test]
    fn action_round_trips() {
        let action = Action {
            reason: KillReason::UnknownDevice {
                id: UsbId::new(0x0781, 0x5567),
            },
            power: PowerAction::PowerOff,
            luks_destroy: false,
            dry_run: true,
        };
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(serde_json::from_str::<Action>(&json).unwrap(), action);
    }
}
