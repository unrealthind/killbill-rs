//! The control-socket protocol (charter §8).
//!
//! One `SOCK_SEQPACKET` Unix socket at `/run/killbilld.sock` carries three
//! kinds of traffic:
//!
//! * **[`Command`]** — client → daemon, expects a [`Reply`].
//! * **[`Reply`]** — daemon → client, answers one command.
//! * **[`Event`]** — daemon → subscribed clients, unsolicited. Carried on the
//!   wire inside a [`StreamEvent`] envelope, never bare — a subscription's
//!   backlog replay and its live events are both `StreamEvent` frames, so a
//!   subscriber reads one frame shape throughout the connection.
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

/// What to do if a sensor reports lost events. Mirrors `response.on_sensor_gap`
/// in config (`killbilld::config::SensorGapAction` is the validated,
/// daemon-internal twin of this wire type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum OnSensorGap {
    /// Surface `events_lost` in `status`, log loudly, keep running.
    #[default]
    Warn,
    /// Treat the gap as an unauthorized change: fire a kill.
    Kill,
}

impl std::fmt::Display for OnSensorGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OnSensorGap::Warn => "warn",
            OnSensorGap::Kill => "kill",
        })
    }
}

/// The LUKS-header-destruction slice of [`ConfigPayload`].
///
/// `acknowledged` is always `true` when this is present in a `ConfigPayload` —
/// `killbilld`'s `config::validate` only ever produces a `Some`
/// `Config::luks_destroy` once `i_understand_this_is_irreversible` has been
/// checked, so a target that is configured but *not* acknowledged fails
/// validation and the whole config is rejected (invariant 2), not surfaced
/// here as a half-armed state. The field is kept explicit anyway rather than
/// implied, so a client never has to know that rule to render this correctly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuksDestroyInfo {
    pub acknowledged: bool,
    /// The target block device path, e.g. `/dev/nvme0n1p3`.
    pub target_header: String,
    /// The separate runtime toggle set by [`Command::SetLuksDestroyEngaged`].
    /// Being configured and acknowledged is necessary but not sufficient for a
    /// kill to actually destroy the header — this must also be `true`
    /// (invariant 4: the dangerous thing needs its own distinctly-named
    /// opt-in, on top of config). Never persisted; every daemon start begins
    /// with this `false`.
    pub engaged: bool,
}

/// A read-only snapshot of the daemon's configuration, answering
/// [`Command::GetConfig`]. Reflects the currently **running** (validated)
/// config, not the raw file — see `validation_error` for when they differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigPayload {
    pub armed_at_boot: bool,
    /// v1 only ever contains `"usb"`, but this is the raw string list (as
    /// config-file `detection.sensors` is), not a fixed enum, since the whole
    /// point of the field is to stay pluggable.
    pub sensors: Vec<String>,
    pub dry_run: bool,
    pub power_action: PowerAction,
    pub on_sensor_gap: OnSensorGap,
    /// `None` if `[response.luks_destroy]` is absent from the running config.
    pub luks_destroy: Option<LuksDestroyInfo>,
    /// `Some` if the config **on disk** currently fails validation — the
    /// fields above are the last-good running config, not a reflection of the
    /// broken file (invariant 2: the daemon never runs on a half-understood
    /// config, so there is nothing else to show).
    pub validation_error: Option<String>,
}

/// One field of the running config, as [`Command::ConfigSet`] changes it. The
/// daemon applies this to a **clone** of its in-memory raw config, re-runs
/// validation on the whole thing, and only on success persists and swaps —
/// exactly like a `whitelist add` (invariant 2: a change that would make the
/// config invalid touches neither the file nor the running state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case", tag = "field", content = "value")]
pub enum ConfigChange {
    DryRun(bool),
    PowerAction(PowerAction),
    ArmedAtBoot(bool),
    Sensors(Vec<String>),
    OnSensorGap(OnSensorGap),
}

/// One [`Event`], stamped with when the daemon broadcast it. This is the
/// subscribe stream's actual wire envelope — both the backlog replay and every
/// live push after it carry this, not a bare `Event` (charter §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamEvent {
    /// RFC 3339, UTC, second precision (e.g. `"2024-01-02T03:04:05Z"`). See
    /// [`rfc3339_now`].
    pub at: String,
    pub event: Event,
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
    /// Return a [`Reply::Config`] snapshot of the running configuration.
    /// Unlike `GetStatus`/`ListDevices`/`WhitelistList`, this **requires
    /// root** — a `LuksDestroyInfo::target_header` is arguably as sensitive
    /// as the whitelist and config-mutating commands it sits next to on the
    /// same closed allow-list ([`Command::requires_root`]).
    GetConfig,
    /// Change one field of the running config. Validated as a whole against a
    /// clone before anything is written or swapped (invariant 2) — see
    /// [`ConfigChange`].
    ConfigSet(ConfigChange),
    /// Engage (`true`) or disengage (`false`) LUKS header destruction on a
    /// future kill. Refused unless the running config has an acknowledged
    /// `[response.luks_destroy]` — engaging is a *runtime* opt-in layered on
    /// top of the *config-time* one (invariant 4), and neither alone is
    /// enough. The header wipe itself stays a stub in v1 regardless
    /// (invariant 3); this only affects what `Action::luks_destroy` reads as.
    SetLuksDestroyEngaged(bool),
    /// Ask the daemon to stream [`Event`]s on this connection until it closes.
    /// A plain `Reply::Ok`/`Reply::Error` acks the subscription as before; on
    /// success the connection then writes the current event backlog as
    /// individual [`StreamEvent`] frames, oldest first, before switching to
    /// forwarding live ones — never one batched frame (a 200-entry backlog
    /// stays well inside [`MAX_CONTROL_FRAME`] per-frame either way, but
    /// batching is needless coupling between the backlog depth and the frame
    /// limit that individual frames simply don't have).
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
    /// Answers [`Command::GetConfig`].
    Config(ConfigPayload),
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
    /// The whitelist changed (`WhitelistAdd`/`WhitelistRemove` succeeded). A
    /// prompt to re-fetch it — `WhitelistList` — rather than a diff.
    WhitelistChanged,
    /// The running config changed for a reason other than the whitelist
    /// (`ConfigSet` or a successful `ReloadConfig`). A prompt to re-fetch
    /// [`Command::GetConfig`] and [`Command::GetStatus`], not a diff.
    ConfigChanged,
    /// A [`Command::ReloadConfig`] was rejected — the file could not be read,
    /// failed validation, or (while armed) would have left a responder unable
    /// to act. The running config and armed state are unchanged (invariant
    /// 2); the string is the same human-readable reason the caller got back.
    /// Broadcast (not just answered to the caller) because it also means
    /// `status.config_stale` just became `true` for every other client.
    ReloadFailed(String),
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

/// The current wall-clock time as RFC 3339 UTC, second precision (e.g.
/// `"2024-01-02T03:04:05Z"`) — used to stamp every [`StreamEvent`] as the
/// daemon broadcasts it.
///
/// Hand-rolled from [`std::time::SystemTime`] rather than pulling in a date
/// crate for one timestamp string: no dependency, no `unsafe` (`time`'s
/// UTC-only path needs none either, but this needs nothing at all), and it is
/// exactly as testable as a library would be — see the test vectors below.
/// Not meant for anything sub-second or performance-sensitive; it is called
/// once per broadcast event, never on the kill path itself.
#[must_use]
pub fn rfc3339_now() -> String {
    format_rfc3339(std::time::SystemTime::now())
}

fn format_rfc3339(t: std::time::SystemTime) -> String {
    let secs = match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        // A clock set before 1970 (or a test vector probing it) — still a
        // real instant, just a negative one; render it rather than panic.
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    // `{year:04}` is proleptic Gregorian with no era sign: not RFC 3339 for
    // year < 1000 or a negative year, neither of which can occur here — this is
    // only ever called for a real wall-clock instant, always post-1970 (the
    // pre-epoch `Err` branch above exists purely for the test vectors).
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days-since-1970-01-01 to a proleptic-Gregorian `(year, month, day)`.
/// Howard Hinnant's `civil_from_days`
/// (<http://howardhinnant.github.io/date_algorithms.html>), public domain —
/// correct over the entire `i64` range, leap years included.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

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
        // Added in step 1: privileged by default (the allow-list is closed),
        // asserted explicitly per the doc comment's promise.
        assert!(Command::GetConfig.requires_root());
        assert!(Command::ConfigSet(ConfigChange::DryRun(true)).requires_root());
        assert!(Command::SetLuksDestroyEngaged(true).requires_root());
    }

    #[test]
    fn config_payload_round_trips_with_and_without_luks_destroy() {
        let with_luks = Reply::Config(ConfigPayload {
            armed_at_boot: true,
            sensors: vec!["usb".to_owned()],
            dry_run: false,
            power_action: PowerAction::PowerOff,
            on_sensor_gap: OnSensorGap::Kill,
            luks_destroy: Some(LuksDestroyInfo {
                acknowledged: true,
                target_header: "/dev/nvme0n1p3".to_owned(),
                engaged: false,
            }),
            validation_error: None,
        });
        let json = serde_json::to_string(&with_luks).unwrap();
        assert_eq!(serde_json::from_str::<Reply>(&json).unwrap(), with_luks);

        let without_luks = Reply::Config(ConfigPayload {
            armed_at_boot: false,
            sensors: vec!["usb".to_owned()],
            dry_run: true,
            power_action: PowerAction::Halt,
            on_sensor_gap: OnSensorGap::Warn,
            luks_destroy: None,
            validation_error: Some("configuration is invalid".to_owned()),
        });
        let json = serde_json::to_string(&without_luks).unwrap();
        assert_eq!(serde_json::from_str::<Reply>(&json).unwrap(), without_luks);
    }

    #[test]
    fn config_change_variants_round_trip() {
        for change in [
            ConfigChange::DryRun(true),
            ConfigChange::PowerAction(PowerAction::Halt),
            ConfigChange::ArmedAtBoot(false),
            ConfigChange::Sensors(vec!["usb".to_owned()]),
            ConfigChange::OnSensorGap(OnSensorGap::Kill),
        ] {
            let cmd = Command::ConfigSet(change.clone());
            let json = serde_json::to_string(&cmd).unwrap();
            assert_eq!(serde_json::from_str::<Command>(&json).unwrap(), cmd);
        }
    }

    #[test]
    fn set_luks_destroy_engaged_round_trips() {
        for want in [true, false] {
            let cmd = Command::SetLuksDestroyEngaged(want);
            let json = serde_json::to_string(&cmd).unwrap();
            assert_eq!(serde_json::from_str::<Command>(&json).unwrap(), cmd);
        }
    }

    #[test]
    fn stream_event_round_trips() {
        let se = StreamEvent {
            at: "2024-01-02T03:04:05Z".to_owned(),
            event: Event::WhitelistChanged,
        };
        let json = serde_json::to_string(&se).unwrap();
        assert_eq!(serde_json::from_str::<StreamEvent>(&json).unwrap(), se);
    }

    #[test]
    fn new_events_round_trip() {
        for event in [
            Event::WhitelistChanged,
            Event::ConfigChanged,
            Event::ReloadFailed("the config on disk is invalid".to_owned()),
        ] {
            let json = serde_json::to_string(&event).unwrap();
            assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), event);
        }
    }

    #[test]
    fn on_sensor_gap_default_is_warn_and_json_is_one_lowercase_word() {
        assert_eq!(OnSensorGap::default(), OnSensorGap::Warn);
        assert_eq!(
            serde_json::to_string(&OnSensorGap::Kill).unwrap(),
            "\"kill\""
        );
    }

    #[test]
    fn rfc3339_now_has_the_right_shape() {
        // Not pinned to a value (it's wall-clock), just the shape every
        // consumer (and the length-prefixed frame budget) can rely on:
        // exactly 20 ASCII bytes, seconds precision, `Z` suffix.
        let s = rfc3339_now();
        assert_eq!(s.len(), 20, "got: {s}");
        assert!(s.ends_with('Z'), "got: {s}");
        assert_eq!(s.as_bytes()[4], b'-');
        assert_eq!(s.as_bytes()[7], b'-');
        assert_eq!(s.as_bytes()[10], b'T');
        assert_eq!(s.as_bytes()[13], b':');
        assert_eq!(s.as_bytes()[16], b':');
    }

    #[test]
    fn format_rfc3339_matches_known_instants() {
        use std::time::{Duration, UNIX_EPOCH};

        assert_eq!(
            format_rfc3339(UNIX_EPOCH),
            "1970-01-01T00:00:00Z",
            "the epoch itself"
        );
        assert_eq!(
            format_rfc3339(UNIX_EPOCH + Duration::from_secs(86_400)),
            "1970-01-02T00:00:00Z",
            "one day later"
        );
        // 946684800 is the well-known Unix time for 2000-01-01T00:00:00Z.
        assert_eq!(
            format_rfc3339(UNIX_EPOCH + Duration::from_secs(946_684_800)),
            "2000-01-01T00:00:00Z"
        );
        // 59 days after that (Jan has 31) is the leap day the whole point of
        // this test is to exercise.
        assert_eq!(
            format_rfc3339(UNIX_EPOCH + Duration::from_secs(946_684_800 + 59 * 86_400)),
            "2000-02-29T00:00:00Z",
            "leap day"
        );
        // A day before the epoch: still a real instant, must render, not panic.
        assert_eq!(
            format_rfc3339(UNIX_EPOCH - Duration::from_secs(86_400)),
            "1969-12-31T00:00:00Z"
        );
        // Mid-day, to exercise the H:M:S math, not just the date.
        assert_eq!(
            format_rfc3339(UNIX_EPOCH + Duration::from_secs(946_684_800 + 3661)),
            "2000-01-01T01:01:01Z"
        );
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
