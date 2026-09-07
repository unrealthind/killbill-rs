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
    WhitelistAdd(WhitelistEntry),
    /// Remove the whitelist entry with this id.
    WhitelistRemove(UsbId),
    /// Run the policy engine over the current device set without acting, and
    /// stream the resulting [`Event::WouldKill`]s.
    RunDryRun,
    /// Re-read and re-validate the config file. Refused if the new file is
    /// invalid; prior state is kept (invariant 2).
    ReloadConfig,
    /// Ask the daemon to stream [`Event`]s on this connection until it closes.
    Subscribe,
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
}

/// Largest accepted frame body: 1 MiB. A frame claiming more than this is
/// rejected *before* any buffer is allocated — the length prefix is
/// attacker-influenced on the control socket.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Length-prefix header size, in bytes.
const HEADER_LEN: usize = 4;

/// A framing or serialization failure.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("frame body is {len} bytes, over the {max} byte limit", max = MAX_FRAME_LEN)]
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
    if body.len() > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge { len: body.len() });
    }
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    // `body.len() <= MAX_FRAME_LEN` (1 MiB) so this cast cannot truncate.
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

    if len > MAX_FRAME_LEN {
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

    #[test]
    fn encode_rejects_oversized_body() {
        let huge = "x".repeat(MAX_FRAME_LEN + 1);
        let err = encode(&huge).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }
}
