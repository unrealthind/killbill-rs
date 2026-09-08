//! The control-socket protocol (charter §8).
//!
//! One `SOCK_SEQPACKET` Unix socket at `/run/killbilld.sock` carries three
//! kinds of traffic:
//!
//! * **[`Command`]** — client → daemon, expects a [`Reply`].
//! * **[`Reply`]** — daemon → client, answers one command.
//! * **[`Event`]** — daemon → subscribed clients, unsolicited.
//!
//! Wire format: a 4-byte big-endian body length, then a `serde_json` body
//! ([`encode`] / [`decode`]). JSON is chosen for a learning codebase — readable
//! and debuggable with `socat`; swappable for a binary codec later without
//! changing any of the types here. The length prefix is redundant over
//! SEQPACKET (datagram boundaries already frame messages) but keeps the codec
//! usable over a plain stream and testable with no socket at all.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::action::{KillReason, PowerAction};
use crate::sensor_event::{SensorSource, UsbId};

/// A whitelist entry as carried over the wire (mirrors `[[whitelist]]` in config).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub id: UsbId,
    #[serde(default)]
    pub label: Option<String>,
    /// Maximum copies of this id allowed connected at once. `None` is resolved
    /// to `1` by the daemon's config validation.
    #[serde(default)]
    pub max_count: Option<u32>,
}

/// A currently-connected device, as reported by `ListDevices` and device events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub source: SensorSource,
    pub id: Option<UsbId>,
    pub serial: Option<String>,
    pub label: Option<String>,
    /// Whether this device matches a current whitelist entry.
    pub whitelisted: bool,
}

/// A USB string descriptor is at most 126 UTF-16 code units; anything longer is
/// not a real serial or label. Also the ceiling on any device string kept or
/// rendered anywhere in the workspace — see [`sanitize_device_string`].
pub const MAX_DEVICE_STRING: usize = 256;

/// A device's `label` and `serial` come from USB string descriptors and are
/// fully attacker-controlled. **Any consumer that renders one to a terminal —
/// or keeps one — must pass it through here first.**
///
/// This is an **allowlist**: printable ASCII and the space survive, everything
/// else becomes U+FFFD. A denylist was tried and rejected — enumerating the
/// terminal-hostile codepoints means chasing C0/C1 escapes, Trojan-Source bidi
/// overrides and isolates, zero-width and tag characters, variation selectors,
/// and unbounded combining-mark stacking, and missing any one of them is a
/// silent hole. An allowlist cannot have that shape of bug.
///
/// The cost is real but small: a device whose descriptor legitimately carries
/// non-ASCII renders with replacement characters. That is the right trade here —
/// this is a security tool's operator output, `config::validate` already demands
/// ASCII of `target_header` for the same reason, and USB serials are ASCII in
/// practice.
///
/// It then truncates to [`MAX_DEVICE_STRING`] characters. Truncation is
/// identity-lossy: two devices whose strings share a `MAX_DEVICE_STRING`-char
/// prefix become indistinguishable here. Callers that match on the string
/// (device tracking) accept that — a compliant descriptor is far shorter, and
/// the USB id is the authoritative key.
#[must_use]
pub fn sanitize_device_string(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '\u{fffd}'
            }
        })
        .take(MAX_DEVICE_STRING)
        .collect()
}

/// Snapshot of daemon state, returned by `GetStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusPayload {
    pub armed: bool,
    pub dry_run: bool,
    pub power_action: PowerAction,
    /// Number of entries in the active whitelist.
    pub whitelist_len: usize,
    /// Number of currently-connected devices the daemon is tracking.
    pub device_count: usize,
    /// Set when the loaded config failed validation: the daemon is refusing to
    /// arm until it is fixed (invariant 2). Rendered as the full report.
    pub config_error: Option<String>,
    /// `false` if the USB sensor thread has stopped — the daemon can no longer
    /// see device changes and refuses to arm (invariant 7). `#[serde(default)]`
    /// so an older daemon that omits it reads as "not ok", the safe default.
    #[serde(default)]
    pub sensor_ok: bool,
    /// `true` once the sensor has reported a gap — a kernel receive-buffer
    /// overflow, an unparseable datagram, or a sensor-thread restart: some
    /// device add/remove events were missed. Sticky until the daemon restarts;
    /// the daemon refuses to (re)arm while it holds. With `on_sensor_gap =
    /// "kill"` a kill fired instead.
    #[serde(default)]
    pub events_lost: bool,
    /// `true` if a `reload` or whitelist change was rejected and the running
    /// config now differs from what is on disk. The daemon keeps running the
    /// last-good config (invariant 2); this flags that the file needs attention.
    #[serde(default)]
    pub config_stale: bool,
}

/// A request from a client. `#[non_exhaustive]`: the daemon answers an
/// unrecognized command with [`Reply::Error`] rather than the protocol breaking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case", tag = "cmd", content = "args")]
pub enum Command {
    /// Return a [`StatusPayload`].
    GetStatus,
    /// Return the list of currently-connected devices.
    ListDevices,
    /// Arm protection. Refused (fail-closed) if the config is invalid.
    Arm,
    /// Disarm protection. The only way to disarm — never a signal (invariant 5).
    Disarm,
    /// Add an entry to the whitelist; the daemon validates and persists it.
    /// Upsert by id — adding an id already present replaces its entry.
    WhitelistAdd(WhitelistEntry),
    /// Remove the whitelist entry with this id.
    WhitelistRemove(UsbId),
    /// Return the active whitelist as [`Reply::Whitelist`].
    WhitelistList,
    /// Run the policy engine over the current device set without acting.
    /// Answers with [`Reply::DryRun`] and also broadcasts an
    /// [`Event::WouldKill`] per hit to subscribers.
    RunDryRun,
    /// Re-read and re-validate the config file. Refused if the new file is
    /// invalid; prior state is kept (invariant 2).
    ReloadConfig,
    /// Ask the daemon to stream [`Event`]s on this connection until it closes.
    Subscribe,
}

impl Command {
    /// Whether this command changes state or exposes more than a public status
    /// snapshot, and so requires an authenticated (uid 0) caller. The read-only
    /// queries are listed explicitly; everything else — including any variant
    /// added later — is privileged, so the authz check fails closed.
    ///
    /// Note the read-only tier (`GetStatus` / `ListDevices` / `WhitelistList`)
    /// is currently *unreachable*: the socket ships `0660 root:root`, so a
    /// process that is neither uid 0 nor in group 0 cannot connect at all. This
    /// split is deliberate defence-in-depth — if the socket's group is ever
    /// loosened, loosening it must not silently expose `Arm`/`Disarm`/config
    /// rewrites along with the status queries.
    #[must_use]
    pub fn requires_root(&self) -> bool {
        !matches!(
            self,
            Command::GetStatus | Command::ListDevices | Command::WhitelistList
        )
    }
}

/// The daemon's answer to one [`Command`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case", tag = "reply", content = "data")]
pub enum Reply {
    /// Command succeeded, no payload.
    Ok,
    Status(StatusPayload),
    Devices(Vec<DeviceInfo>),
    /// The active whitelist, answering [`Command::WhitelistList`].
    Whitelist(Vec<WhitelistEntry>),
    /// The kill reasons a dry run produced, answering [`Command::RunDryRun`].
    /// Empty means nothing connected would trigger a kill.
    DryRun(Vec<KillReason>),
    /// Command failed; the string is a human-readable reason.
    Error(String),
}

/// An unsolicited message the daemon pushes to subscribed clients. This is what
/// lets the TUI see exactly what the daemon sees (charter §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case", tag = "event", content = "data")]
pub enum Event {
    DeviceAdded(DeviceInfo),
    DeviceRemoved(DeviceInfo),
    Armed,
    Disarmed,
    /// Emitted during a dry run in place of dispatching responders.
    WouldKill(KillReason),
    /// The USB sensor thread has stopped: the daemon is no longer seeing device
    /// changes (invariant 7). Either the supervisor is respawning it (a gap —
    /// see [`Self::EventsLost`]) or, after repeated failures, the daemon is
    /// exiting non-zero for a supervisor restart.
    SensorStopped,
    /// The daemon missed some device add/remove events and its device set can no
    /// longer be fully accounted for — a kernel receive-buffer overflow, an
    /// unparseable datagram, or a sensor-thread restart. Sticky until the daemon
    /// restarts; the daemon refuses to (re)arm while it holds. Advisory unless
    /// `on_sensor_gap = "kill"`, which fires the power action instead.
    EventsLost,
}

/// The maximum size of a whole control-socket frame — header **and** body —
/// in bytes: 64 KiB. This is exactly the read buffer every reader on the wire
/// allocates (the daemon's `read_frame`, `killbillctl`, the TUI), so a frame
/// this size or smaller always fits in one `read`.
///
/// [`encode`] enforces it (see [`MAX_BODY_LEN`] for the body's share) and
/// [`decode`] rejects a larger declared length *before* allocating — the length
/// prefix is attacker-influenced on the control socket. A reply that could not
/// be read back must not be sendable in the first place.
///
/// Commands and replies are normally well under a kilobyte; this ceiling still
/// covers thousands of tracked devices in a `Reply::Devices`. If a genuine
/// reply ever needs more, the fix is a paged command, not a larger buffer —
/// a hostile client must not be able to make three processes allocate more.
pub const MAX_CONTROL_FRAME: usize = 64 * 1024;

/// Length-prefix header size, in bytes.
const HEADER_LEN: usize = 4;

/// The largest JSON body [`encode`] will accept: [`MAX_CONTROL_FRAME`] minus the
/// 4-byte length prefix, so the frame it produces fits a reader's buffer exactly.
pub const MAX_BODY_LEN: usize = MAX_CONTROL_FRAME - HEADER_LEN;

/// A framing or serialization failure.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("frame body is {len} bytes, over the {max} byte limit", max = MAX_BODY_LEN)]
    FrameTooLarge { len: usize },
    #[error("frame is truncated: header declares {expected} body bytes, {actual} present")]
    Truncated { expected: usize, actual: usize },
    #[error("frame header is incomplete: need 4 bytes, got {0}")]
    ShortHeader(usize),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serialize `value` into a length-prefixed JSON frame.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_BODY_LEN {
        return Err(ProtocolError::FrameTooLarge { len: body.len() });
    }
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    // `body.len() <= MAX_BODY_LEN` (< 64 KiB) so this cast cannot truncate.
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode one length-prefixed JSON frame from the front of `bytes`.
///
/// Returns the value and the total number of bytes the frame occupied
/// (`HEADER_LEN + body`), so a caller reading from a stream buffer knows how
/// much to consume. Trailing bytes after the frame are ignored.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<(T, usize), ProtocolError> {
    let header = match bytes.get(..HEADER_LEN) {
        Some(h) => h,
        None => return Err(ProtocolError::ShortHeader(bytes.len())),
    };
    let mut len_bytes = [0u8; HEADER_LEN];
    len_bytes.copy_from_slice(header);
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_BODY_LEN {
        return Err(ProtocolError::FrameTooLarge { len });
    }

    let end = HEADER_LEN + len;
    let body = match bytes.get(HEADER_LEN..end) {
        Some(b) => b,
        None => {
            return Err(ProtocolError::Truncated {
                expected: len,
                actual: bytes.len().saturating_sub(HEADER_LEN),
            })
        }
    };

    Ok((serde_json::from_slice(body)?, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_unit_variant_has_no_args() {
        let json = serde_json::to_value(Command::GetStatus).unwrap();
        assert_eq!(json, serde_json::json!({ "cmd": "get_status" }));
    }

    #[test]
    fn command_payload_variant_round_trips() {
        let cmd = Command::WhitelistAdd(WhitelistEntry {
            id: UsbId::new(0x1050, 0x0407),
            label: Some("YubiKey 5C".to_owned()),
            max_count: Some(1),
        });
        let json = serde_json::to_string(&cmd).unwrap();
        assert_eq!(serde_json::from_str::<Command>(&json).unwrap(), cmd);
    }

    #[test]
    fn reply_and_event_round_trip() {
        let reply = Reply::Status(StatusPayload {
            armed: true,
            dry_run: false,
            power_action: PowerAction::PowerOff,
            whitelist_len: 2,
            device_count: 5,
            config_error: None,
            sensor_ok: true,
            events_lost: false,
            config_stale: false,
        });
        let json = serde_json::to_string(&reply).unwrap();
        assert_eq!(serde_json::from_str::<Reply>(&json).unwrap(), reply);

        let event = Event::WouldKill(KillReason::UnknownDevice {
            id: UsbId::new(0x0781, 0x5567),
        });
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), event);
    }

    #[test]
    fn added_status_fields_default_when_a_peer_omits_them() {
        // An older daemon's status JSON without `sensor_ok` / `events_lost`.
        let json = r#"{"reply":"status","data":{
            "armed":false,"dry_run":true,"power_action":"poweroff",
            "whitelist_len":0,"device_count":0,"config_error":null}}"#;
        match serde_json::from_str::<Reply>(json).unwrap() {
            Reply::Status(s) => {
                assert!(!s.sensor_ok);
                assert!(!s.events_lost);
                assert!(!s.config_stale);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn whitelist_and_dry_run_replies_round_trip() {
        let wl = Reply::Whitelist(vec![WhitelistEntry {
            id: UsbId::new(0x1050, 0x0407),
            label: Some("YubiKey".to_owned()),
            max_count: Some(1),
        }]);
        let json = serde_json::to_string(&wl).unwrap();
        assert_eq!(serde_json::from_str::<Reply>(&json).unwrap(), wl);

        let dr = Reply::DryRun(vec![KillReason::UnidentifiedDevice]);
        let json = serde_json::to_string(&dr).unwrap();
        assert_eq!(serde_json::from_str::<Reply>(&json).unwrap(), dr);
    }

    #[test]
    fn requires_root_is_a_closed_allow_list() {
        assert!(!Command::GetStatus.requires_root());
        assert!(!Command::ListDevices.requires_root());
        assert!(!Command::WhitelistList.requires_root());
        assert!(Command::Arm.requires_root());
        assert!(Command::Disarm.requires_root());
        assert!(Command::ReloadConfig.requires_root());
        assert!(Command::RunDryRun.requires_root());
        assert!(Command::Subscribe.requires_root());
        assert!(Command::WhitelistRemove(UsbId::new(0x1050, 0x0407)).requires_root());
    }

    #[test]
    fn sanitize_device_string_keeps_printable_ascii_and_replaces_the_rest() {
        assert_eq!(sanitize_device_string("YubiKey 5C"), "YubiKey 5C");
        assert_eq!(
            sanitize_device_string("4C530001234567890123"),
            "4C530001234567890123"
        );
        // Every printable ASCII byte survives unchanged.
        let printable: String = (0x20u8..=0x7e).map(char::from).collect();
        assert_eq!(sanitize_device_string(&printable), printable);

        assert_eq!(sanitize_device_string("\x1b[2Jgotcha"), "\u{fffd}[2Jgotcha");
        assert_eq!(sanitize_device_string("a\tb\nc"), "a\u{fffd}b\u{fffd}c");
        // Non-ASCII is replaced too — this is an allowlist, and legible output
        // for an operator beats round-tripping a hostile descriptor.
        assert_eq!(sanitize_device_string("Café"), "Caf\u{fffd}");
    }

    #[test]
    fn sanitize_device_string_admits_nothing_outside_printable_ascii() {
        // The allowlist's whole point: no need to enumerate what is hostile.
        // C0/C1, Trojan-Source bidi, zero-width, tag characters, variation
        // selectors, combining marks, line/paragraph separators — all gone.
        let hostile = [
            "\u{1b}[2J",
            "\u{9b}0m",
            "\u{202e}gnihtemos",
            "a\u{200b}b",
            "\u{feff}x",
            "y\u{2066}z",
            "\u{061c}m",
            "\u{e0041}tag",
            "e\u{fe0f}",
            "a\u{0301}\u{0301}",
            "l\u{2028}p",
            "\u{00ad}soft",
        ];
        for input in hostile {
            let out = sanitize_device_string(input);
            assert!(
                out.chars()
                    .all(|c| c.is_ascii_graphic() || c == ' ' || c == '\u{fffd}'),
                "something outside printable ASCII survived {input:?}: {out:?}"
            );
        }
    }

    #[test]
    fn sanitize_device_string_caps_length() {
        let n = sanitize_device_string(&"A".repeat(MAX_DEVICE_STRING * 3))
            .chars()
            .count();
        assert_eq!(n, MAX_DEVICE_STRING);
    }

    #[test]
    fn frame_round_trips() {
        let cmd = Command::Arm;
        let frame = encode(&cmd).unwrap();
        let (decoded, consumed): (Command, usize) = decode(&frame).unwrap();
        assert_eq!(decoded, cmd);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn decode_reports_frame_length_so_a_buffer_can_advance() {
        let mut buf = encode(&Command::Arm).unwrap();
        let first_len = buf.len();
        buf.extend(encode(&Command::Disarm).unwrap());

        let (a, consumed): (Command, usize) = decode(&buf).unwrap();
        assert_eq!(a, Command::Arm);
        assert_eq!(consumed, first_len);
        let (b, _): (Command, usize) = decode(&buf[consumed..]).unwrap();
        assert_eq!(b, Command::Disarm);
    }

    #[test]
    fn decode_rejects_short_header() {
        let err = decode::<Command>(&[0, 0, 1]).unwrap_err();
        assert!(matches!(err, ProtocolError::ShortHeader(3)));
    }

    #[test]
    fn decode_rejects_truncated_body() {
        let mut frame = encode(&Command::Arm).unwrap();
        frame.pop();
        let err = decode::<Command>(&frame).unwrap_err();
        assert!(matches!(err, ProtocolError::Truncated { .. }));
    }

    #[test]
    fn decode_rejects_oversized_length_without_allocating() {
        // Header claims ~4 GiB; body is empty. Must fail on the length check.
        let frame = [0xff, 0xff, 0xff, 0xff];
        let err = decode::<Command>(&frame).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }

    /// The longest `String` whose *serialized* JSON body is exactly
    /// [`MAX_BODY_LEN`]. The limit is on the encoded body, and serializing a
    /// string wraps it in two quote bytes — so the payload is two chars shorter
    /// than the byte budget. `x` needs no escaping, so nothing else is added.
    fn max_body_payload() -> String {
        let s = "x".repeat(MAX_BODY_LEN - 2);
        assert_eq!(
            serde_json::to_vec(&s).unwrap().len(),
            MAX_BODY_LEN,
            "the JSON quoting overhead assumed here has changed"
        );
        s
    }

    #[test]
    fn encode_rejects_a_body_that_would_not_fit_a_readers_buffer() {
        // A serialized body of exactly MAX_BODY_LEN is fine; one byte more makes
        // the frame (body + 4-byte header) exceed MAX_CONTROL_FRAME and be
        // truncated on read (SEQPACKET discards the remainder), so `encode` must
        // reject it rather than emit something no reader can take back.
        assert!(encode(&max_body_payload()).is_ok());

        let one_too_long = format!("{}x", max_body_payload());
        let err = encode(&one_too_long).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { len } if len == MAX_BODY_LEN + 1));
    }

    #[test]
    fn a_max_size_frame_survives_a_reader_sized_buffer() {
        // The property M1 is about: anything `encode` accepts round-trips
        // through the fixed buffer every reader on the wire allocates.
        let body = max_body_payload();
        let frame = encode(&body).unwrap();
        assert_eq!(
            frame.len(),
            MAX_CONTROL_FRAME,
            "a maximal frame must fill the reader buffer exactly, not overflow it"
        );

        let mut buf = vec![0u8; MAX_CONTROL_FRAME]; // exactly what readers use
        let n = frame.len();
        buf[..n].copy_from_slice(&frame);
        let (decoded, consumed): (String, usize) = decode(&buf[..n]).unwrap();
        assert_eq!(decoded, body);
        assert_eq!(consumed, n);
    }

    #[test]
    fn decode_rejects_a_declared_length_over_the_body_limit() {
        let header = ((MAX_BODY_LEN + 1) as u32).to_be_bytes();
        let err = decode::<Command>(&header).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }
}
