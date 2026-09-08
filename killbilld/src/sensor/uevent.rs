//! The pure uevent parser: raw kernel netlink bytes -> [`SensorEvent`].
//!
//! This is the security-critical seam of the USB sensor — every byte it sees
//! comes from a physical device an attacker may control — so it is a single
//! pure function with no I/O, exhaustively tested against captured-shape byte
//! payloads, the same way [`crate::policy::decide`] is. The socket loop in
//! [`super::netlink`] is the only caller and does nothing but feed it datagrams.
//!
//! ## Wire format
//!
//! A message on the kernel's `NETLINK_KOBJECT_UEVENT` group 1 is:
//!
//! ```text
//! add@/devices/.../1-3\0ACTION=add\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0PRODUCT=1050/407/543\0...\0
//! ```
//!
//! a NUL-separated list: a leading `ACTION@DEVPATH` summary line, then
//! `KEY=VALUE` pairs. `PRODUCT` for a `usb_device` is `vendor/product/bcd` in
//! hex with no leading zeros. udev's *re-broadcast* on group 2 uses a different
//! `libudev`-prefixed binary framing; we never join that group, and a message
//! in that shape here is treated as a hard error rather than misparsed.
//!
//! ## What comes out
//!
//! * `Ok(Some(event))` — a USB device was added or removed. If its id could not
//!   be read, `identity.usb_id` is `None` and the policy engine fails closed on
//!   it (`KillReason::UnidentifiedDevice`); it is never dropped.
//! * `Ok(None)` — a well-formed uevent that is not a USB device add/remove
//!   (an interface, a different subsystem, a `change`/`bind`/`move` action).
//! * `Err(_)` — the bytes could not be understood as a uevent at all. Invariant
//!   7: the caller logs this loudly and keeps listening; it must never become a
//!   silent "no device seen".
//!
//! Kernel-synthesized uevents (from a `udevadm trigger` or a write to
//! `/sys/.../uevent`) carry a `SYNTH_UUID=` pair, which lands in
//! [`SensorEvent::raw`]. The core uses that to tell a re-broadcast of an
//! already-present device from a real physical plug — see `daemon::Core`.
//!
//! `identity.serial` is sanitized here (see [`sanitize_device_string`]); the
//! `raw` map keeps every `KEY=VALUE` pair **verbatim**, unsanitized. Nothing
//! renders `raw` — it is read only for keys like `SYNTH_UUID` — and it must
//! stay that way.

use std::collections::BTreeMap;

use killbill_proto::{
    sanitize_device_string, DeviceIdentity, EventKind, SensorEvent, SensorSource, UsbId,
};

/// The bytes handed to [`parse_uevent`] were not a uevent we could parse.
///
/// Crate-private: it is logged as a string by the sensor loop and never leaves
/// the daemon. Promote to `pub` only if a fuzz target or another crate needs
/// to match on it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UeventParseError {
    /// A zero-length datagram.
    #[error("empty uevent payload")]
    Empty,
    /// A `libudev`-framed message — we only ever bind the kernel group, so this
    /// means something is wrong with the socket setup, not a stray packet.
    #[error("received a libudev-framed message on the kernel uevent group")]
    LibudevFraming,
    /// A byte payload that is not valid UTF-8. Every field the kernel puts in a
    /// `usb_device` uevent is ASCII, so this is corruption or misframing.
    #[error("uevent payload is not valid UTF-8")]
    NotUtf8,
    /// A segment that is not `KEY=VALUE` (and is not the leading summary line).
    #[error("uevent segment {segment:?} is not KEY=VALUE")]
    MalformedSegment { segment: String },
    /// No `ACTION=` among the pairs.
    #[error("uevent has no ACTION")]
    MissingAction,
}

/// Parse one raw netlink uevent datagram.
///
/// See the module docs for the `Ok(Some)` / `Ok(None)` / `Err` contract.
pub(crate) fn parse_uevent(bytes: &[u8]) -> Result<Option<SensorEvent>, UeventParseError> {
    if bytes.is_empty() {
        return Err(UeventParseError::Empty);
    }
    // libudev monitor messages start with the literal "libudev\0".
    if bytes.starts_with(b"libudev") {
        return Err(UeventParseError::LibudevFraming);
    }

    let text = std::str::from_utf8(bytes).map_err(|_| UeventParseError::NotUtf8)?;

    let mut pairs: BTreeMap<String, String> = BTreeMap::new();
    for (i, segment) in text.split('\0').filter(|s| !s.is_empty()).enumerate() {
        // Segment 0 is the "ACTION@DEVPATH" summary line: it carries a '@' and
        // no '='. Everything ACTION@DEVPATH says is repeated in the ACTION= and
        // DEVPATH= pairs, so we skip it rather than special-case it.
        if i == 0 && segment.contains('@') && !segment.contains('=') {
            continue;
        }
        let (key, value) =
            segment
                .split_once('=')
                .ok_or_else(|| UeventParseError::MalformedSegment {
                    segment: segment.to_owned(),
                })?;
        // A duplicate key from the kernel would be a bug; last-wins is a safe,
        // quiet way to handle it and not worth failing over.
        pairs.insert(key.to_owned(), value.to_owned());
    }

    let action = pairs
        .get("ACTION")
        .ok_or(UeventParseError::MissingAction)?
        .as_str();
    let kind = match action {
        "add" => EventKind::Added,
        "remove" => EventKind::Removed,
        // change / bind / unbind / move / online / offline: real events, but
        // not ones the policy engine has a rule for.
        _ => return Ok(None),
    };

    // We track whole devices, not their interfaces, and only the USB subsystem.
    if pairs.get("SUBSYSTEM").map(String::as_str) != Some("usb") {
        return Ok(None);
    }
    if pairs.get("DEVTYPE").map(String::as_str) != Some("usb_device") {
        return Ok(None);
    }

    // A USB device really was added or removed. If we cannot read its id we
    // still emit the event (usb_id: None) — losing it would be the invariant-7
    // failure; the policy engine turns "unidentified device" into a kill.
    let usb_id = pairs.get("PRODUCT").and_then(|p| parse_product(p));

    Ok(Some(SensorEvent {
        source: SensorSource::Usb,
        kind,
        identity: DeviceIdentity {
            usb_id,
            // The kernel's usb_device uevent carries no serial/manufacturer
            // strings (those live in sysfs). SERIAL is read opportunistically
            // in case a future kernel adds it; label stays None in v1.
            //
            // Sanitize it here, at the point it enters a `SensorEvent`: a USB
            // string descriptor is fully device-controlled, and doing it at the
            // parser means the value in `identity.serial` is safe for every
            // downstream consumer (tracing fields, `killbillctl`, any TUI
            // screen) without each having to remember. `raw` above is *not*
            // sanitized — see the module docs.
            serial: pairs
                .get("SERIAL")
                .map(String::as_str)
                .map(sanitize_device_string),
            label: None,
        },
        raw: pairs,
    }))
}

/// `PRODUCT=vendor/product/bcdDevice`, hex, no leading zeros (e.g. `1050/407/543`).
/// Returns `None` for anything that is not two parseable hex `u16`s — the caller
/// turns that into a fail-closed "unidentified device", not an error.
fn parse_product(product: &str) -> Option<UsbId> {
    let mut parts = product.split('/');
    let vendor = u16::from_str_radix(parts.next()?, 16).ok()?;
    let product_id = u16::from_str_radix(parts.next()?, 16).ok()?;
    Some(UsbId::new(vendor, product_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a NUL-separated uevent datagram from its segments, the way the
    /// kernel lays one out. The first entry is the `ACTION@DEVPATH` line.
    fn wire(segments: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for segment in segments {
            buf.extend_from_slice(segment.as_bytes());
            buf.push(0);
        }
        buf
    }

    /// A representative real `add` for a whole USB device, matching
    /// `udevadm monitor --kernel --property` output.
    fn add_yubikey() -> Vec<u8> {
        wire(&[
            "add@/devices/pci0000:00/0000:00:14.0/usb1/1-3",
            "ACTION=add",
            "DEVPATH=/devices/pci0000:00/0000:00:14.0/usb1/1-3",
            "SUBSYSTEM=usb",
            "DEVNAME=bus/usb/001/017",
            "DEVTYPE=usb_device",
            "PRODUCT=1050/407/543",
            "TYPE=0/0/0",
            "BUSNUM=001",
            "DEVNUM=017",
            "SEQNUM=8412",
            "MAJOR=189",
            "MINOR=16",
        ])
    }

    fn parse(bytes: &[u8]) -> Result<Option<SensorEvent>, UeventParseError> {
        parse_uevent(bytes)
    }

    #[test]
    fn add_of_a_usb_device_yields_an_added_event_with_its_id() {
        let event = parse(&add_yubikey()).unwrap().unwrap();
        assert_eq!(event.source, SensorSource::Usb);
        assert_eq!(event.kind, EventKind::Added);
        assert_eq!(event.identity.usb_id, Some(UsbId::new(0x1050, 0x0407)));
        assert_eq!(event.raw.get("DEVNUM").map(String::as_str), Some("017"));
        assert_eq!(event.raw.get("SEQNUM").map(String::as_str), Some("8412"));
        // The ACTION@DEVPATH summary line is not a pair.
        assert!(!event
            .raw
            .contains_key("add@/devices/pci0000:00/0000:00:14.0/usb1/1-3"));
    }

    #[test]
    fn remove_of_a_usb_device_yields_a_removed_event() {
        let bytes = wire(&[
            "remove@/devices/pci0000:00/0000:00:14.0/usb1/1-3",
            "ACTION=remove",
            "SUBSYSTEM=usb",
            "DEVTYPE=usb_device",
            "PRODUCT=1050/407/543",
        ]);
        let event = parse(&bytes).unwrap().unwrap();
        assert_eq!(event.kind, EventKind::Removed);
        assert_eq!(event.identity.usb_id, Some(UsbId::new(0x1050, 0x0407)));
    }

    #[test]
    fn product_hex_is_read_without_leading_zeros() {
        // 1d6b/2/... is a root hub; product 0x0002 must not be misread.
        let bytes = wire(&[
            "add@/devices/x",
            "ACTION=add",
            "SUBSYSTEM=usb",
            "DEVTYPE=usb_device",
            "PRODUCT=1d6b/2/606",
        ]);
        let event = parse(&bytes).unwrap().unwrap();
        assert_eq!(event.identity.usb_id, Some(UsbId::new(0x1d6b, 0x0002)));
    }

    #[test]
    fn serial_is_captured_when_the_kernel_provides_it() {
        let bytes = wire(&[
            "add@/devices/x",
            "ACTION=add",
            "SUBSYSTEM=usb",
            "DEVTYPE=usb_device",
            "PRODUCT=0781/5567/100",
            "SERIAL=4C530001234567890123",
        ]);
        let event = parse(&bytes).unwrap().unwrap();
        assert_eq!(
            event.identity.serial.as_deref(),
            Some("4C530001234567890123")
        );
    }

    #[test]
    fn a_hostile_serial_is_sanitized_at_the_parser() {
        let bytes = wire(&[
            "add@/devices/x",
            "ACTION=add",
            "SUBSYSTEM=usb",
            "DEVTYPE=usb_device",
            "PRODUCT=0781/5567/100",
            "SERIAL=\x1b[2Jowned\x07",
        ]);
        let event = parse(&bytes).unwrap().unwrap();
        let serial = event.identity.serial.unwrap();
        assert!(
            !serial.contains('\x1b') && !serial.contains('\x07'),
            "control characters must not survive: {serial:?}"
        );
        assert!(serial.contains("owned"));
    }

    #[test]
    fn an_over_long_serial_is_truncated() {
        let long = "A".repeat(killbill_proto::MAX_DEVICE_STRING * 4);
        let bytes = wire(&[
            "add@/devices/x",
            "ACTION=add",
            "SUBSYSTEM=usb",
            "DEVTYPE=usb_device",
            "PRODUCT=0781/5567/100",
            &format!("SERIAL={long}"),
        ]);
        let event = parse(&bytes).unwrap().unwrap();
        assert_eq!(
            event.identity.serial.unwrap().chars().count(),
            killbill_proto::MAX_DEVICE_STRING
        );
    }

    // --- Ok(None): well-formed, but not our concern ------------------------

    #[test]
    fn a_usb_interface_event_is_ignored() {
        let bytes = wire(&[
            "add@/devices/x/1-3:1.0",
            "ACTION=add",
            "SUBSYSTEM=usb",
            "DEVTYPE=usb_interface",
            "PRODUCT=1050/407/543",
        ]);
        assert_eq!(parse(&bytes).unwrap(), None);
    }

    #[test]
    fn a_non_usb_subsystem_is_ignored() {
        let bytes = wire(&[
            "add@/devices/virtual/block/loop0",
            "ACTION=add",
            "SUBSYSTEM=block",
            "DEVTYPE=disk",
        ]);
        assert_eq!(parse(&bytes).unwrap(), None);
    }

    #[test]
    fn a_missing_subsystem_is_ignored_not_an_error() {
        let bytes = wire(&["add@/devices/x", "ACTION=add", "DEVTYPE=usb_device"]);
        assert_eq!(parse(&bytes).unwrap(), None);
    }

    #[test]
    fn non_add_remove_actions_are_ignored() {
        for action in ["change", "bind", "unbind", "move", "online", "offline"] {
            let mut bytes = wire(&[
                "x@/devices/y",
                "SUBSYSTEM=usb",
                "DEVTYPE=usb_device",
                "PRODUCT=1050/407/543",
            ]);
            bytes.extend_from_slice(format!("ACTION={action}\0").as_bytes());
            assert_eq!(parse(&bytes).unwrap(), None, "action {action:?}");
        }
    }

    // --- Ok(Some) with no id: fail closed, never dropped ------------------

    #[test]
    fn a_usb_device_with_no_product_still_emits_an_event_without_an_id() {
        let bytes = wire(&[
            "add@/devices/x",
            "ACTION=add",
            "SUBSYSTEM=usb",
            "DEVTYPE=usb_device",
        ]);
        let event = parse(&bytes).unwrap().unwrap();
        assert_eq!(event.kind, EventKind::Added);
        assert_eq!(event.identity.usb_id, None);
    }

    #[test]
    fn a_usb_device_with_a_malformed_product_still_emits_without_an_id() {
        for product in [
            "PRODUCT=garbage",
            "PRODUCT=1050",
            "PRODUCT=/",
            "PRODUCT=zzzz/0407/1",
        ] {
            let bytes = wire(&[
                "add@/devices/x",
                "ACTION=add",
                "SUBSYSTEM=usb",
                "DEVTYPE=usb_device",
                product,
            ]);
            let event = parse(&bytes).unwrap().unwrap();
            assert_eq!(event.identity.usb_id, None, "{product}");
        }
    }

    // --- Err: unparseable, invariant 7 -----------------------------------

    #[test]
    fn an_empty_payload_is_an_error() {
        assert_eq!(parse(b""), Err(UeventParseError::Empty));
    }

    #[test]
    fn a_libudev_framed_message_is_an_error() {
        let mut bytes = b"libudev\0\xfe\xed\xca\xfe".to_vec();
        bytes.extend_from_slice(b"ACTION=add\0");
        assert_eq!(parse(&bytes), Err(UeventParseError::LibudevFraming));
    }

    #[test]
    fn a_non_utf8_payload_is_an_error() {
        let bytes = b"add@/devices/x\0ACTION=add\0SUBSYSTEM=\xff\xfe\0".to_vec();
        assert_eq!(parse(&bytes), Err(UeventParseError::NotUtf8));
    }

    #[test]
    fn a_segment_that_is_not_key_value_is_an_error() {
        let bytes = wire(&[
            "add@/devices/x",
            "ACTION=add",
            "SUBSYSTEM=usb",
            "this-has-no-equals-sign",
        ]);
        assert_eq!(
            parse(&bytes),
            Err(UeventParseError::MalformedSegment {
                segment: "this-has-no-equals-sign".to_owned(),
            })
        );
    }

    #[test]
    fn a_payload_with_no_action_is_an_error() {
        let bytes = wire(&["add@/devices/x", "SUBSYSTEM=usb", "DEVTYPE=usb_device"]);
        assert_eq!(parse(&bytes), Err(UeventParseError::MissingAction));
    }

    #[test]
    fn a_value_may_contain_an_equals_sign() {
        let bytes = wire(&[
            "add@/devices/x",
            "ACTION=add",
            "SUBSYSTEM=usb",
            "DEVTYPE=usb_device",
            "PRODUCT=1050/407/543",
            "DEVLINKS=/dev/foo=bar",
        ]);
        let event = parse(&bytes).unwrap().unwrap();
        assert_eq!(
            event.raw.get("DEVLINKS").map(String::as_str),
            Some("/dev/foo=bar")
        );
    }

    #[test]
    fn a_trailing_nul_does_not_produce_an_empty_segment_error() {
        let mut bytes = add_yubikey();
        bytes.push(0);
        bytes.push(0);
        assert!(parse(&bytes).unwrap().is_some());
    }
}
