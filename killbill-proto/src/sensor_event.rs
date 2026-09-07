//! Normalized sensor input.
//!
//! A [`SensorEvent`] is what the policy engine sees. Whether it came from the
//! netlink uevent socket or (one day) a lid switch is invisible past this point.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Where a [`SensorEvent`] originated.
///
/// v1 has only USB. The enum is `#[non_exhaustive]` so adding a sensor later is
/// not a breaking change for downstream crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SensorSource {
    /// USB device add/remove, via the kernel netlink uevent socket.
    Usb,
}

impl fmt::Display for SensorSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SensorSource::Usb => f.write_str("usb"),
        }
    }
}

/// The kind of change a sensor observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A device appeared.
    Added,
    /// A device went away.
    Removed,
}

/// A USB vendor/product pair.
///
/// Rendered as `vvvv:pppp` in lowercase hex (e.g. `1050:0407`) — the exact form
/// the config whitelist matches on and `lsusb` prints. Parsing is strict:
/// exactly four hex digits on each side of a single colon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UsbId {
    pub vendor: u16,
    pub product: u16,
}

impl UsbId {
    /// Construct from raw vendor/product numbers.
    pub const fn new(vendor: u16, product: u16) -> Self {
        Self { vendor, product }
    }
}

impl fmt::Display for UsbId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}:{:04x}", self.vendor, self.product)
    }
}

/// Returned when a string is not a well-formed `vvvv:pppp` USB id.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid USB id {input:?}: expected four hex digits, a colon, four hex digits (e.g. 1050:0407)"
)]
pub struct UsbIdParseError {
    pub input: String,
}

impl FromStr for UsbId {
    type Err = UsbIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let reject = || UsbIdParseError {
            input: s.to_owned(),
        };
        let (vendor, product) = s.split_once(':').ok_or_else(reject)?;

        // Reject "12:34" (too short), "12345:6789" (too long), "0x12:0x34".
        if vendor.len() != 4 || product.len() != 4 {
            return Err(reject());
        }

        let hex = |part: &str| -> Option<u16> {
            if part.bytes().all(|b| b.is_ascii_hexdigit()) {
                u16::from_str_radix(part, 16).ok()
            } else {
                None
            }
        };

        match (hex(vendor), hex(product)) {
            (Some(vendor), Some(product)) => Ok(UsbId { vendor, product }),
            _ => Err(reject()),
        }
    }
}

// USB ids travel as strings on the wire and in config, not as `{vendor, product}`
// objects — that keeps them greppable in logs and identical to how a user writes
// them in `config.toml`.
impl Serialize for UsbId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for UsbId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Best-effort identity for a device a sensor saw.
///
/// Every field is optional because an unusual device may not carry all of them.
/// A *parse failure*, though, is never silently an empty identity — the sensor
/// surfaces it as an error (invariant 7).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Vendor/product id, when the sensor could read one.
    pub usb_id: Option<UsbId>,
    /// Device serial string, when present.
    pub serial: Option<String>,
    /// Human-readable product/manufacturer string, when present.
    pub label: Option<String>,
}

/// One normalized event from a sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorEvent {
    pub source: SensorSource,
    pub kind: EventKind,
    pub identity: DeviceIdentity,
    /// The raw key/value payload the sensor parsed (uevent lines, for USB).
    /// Kept for logging and debugging; the policy engine ignores it.
    #[serde(default)]
    pub raw: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_id_round_trips_through_string() {
        let id = UsbId::new(0x1050, 0x0407);
        assert_eq!(id.to_string(), "1050:0407");
        assert_eq!("1050:0407".parse::<UsbId>().unwrap(), id);
    }

    #[test]
    fn usb_id_display_is_zero_padded_lowercase() {
        assert_eq!(UsbId::new(0x0a, 0x0b).to_string(), "000a:000b");
    }

    #[test]
    fn usb_id_rejects_malformed_input() {
        for bad in [
            "",
            "1050",
            "1050:",
            ":0407",
            "12:34",      // too few digits
            "12345:6789", // too many digits
            "105g:0407",  // non-hex
            "0x10:0x04",
            "1050:0407:0000", // trailing junk lands in `product` -> wrong length
            " 1050:0407",
        ] {
            assert!(
                bad.parse::<UsbId>().is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn usb_id_json_is_a_bare_string() {
        let id = UsbId::new(0x1d6b, 0x0003);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"1d6b:0003\"");
        assert_eq!(serde_json::from_str::<UsbId>(&json).unwrap(), id);
    }

    #[test]
    fn usb_id_json_rejects_bad_string() {
        assert!(serde_json::from_str::<UsbId>("\"nope\"").is_err());
    }

    #[test]
    fn sensor_event_json_round_trips() {
        let mut raw = BTreeMap::new();
        raw.insert("ACTION".to_owned(), "add".to_owned());
        raw.insert("SUBSYSTEM".to_owned(), "usb".to_owned());
        let event = SensorEvent {
            source: SensorSource::Usb,
            kind: EventKind::Added,
            identity: DeviceIdentity {
                usb_id: Some(UsbId::new(0x1050, 0x0407)),
                serial: Some("0001234".to_owned()),
                label: Some("YubiKey".to_owned()),
            },
            raw,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(serde_json::from_str::<SensorEvent>(&json).unwrap(), event);
    }

    #[test]
    fn sensor_event_raw_defaults_to_empty_when_absent() {
        let json = r#"{
            "source": "usb",
            "kind": "removed",
            "identity": { "usb_id": null, "serial": null, "label": null }
        }"#;
        let event: SensorEvent = serde_json::from_str(json).unwrap();
        assert!(event.raw.is_empty());
    }
}
