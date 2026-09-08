//! Configuration: load, typed deserialization, and **fail-closed validation**.
//!
//! Validation is security-critical code (invariant 2, charter §9). The daemon
//! refuses to arm on an invalid config and says exactly why — it never guesses
//! intent and never fires on a half-understood file. So the rejection cases are
//! tested as hard as the accept cases (see the `tests` module).
//!
//! Two layers:
//!
//! * [`RawConfig`] — the file exactly as written. Every field optional. Parsed
//!   by [`load`].
//! * [`Config`] — the validated, fully-resolved form the daemon runs on.
//!   Produced by [`validate`], or a [`ValidationReport`] listing *every* problem.

use std::path::{Path, PathBuf};

use killbill_proto::{PowerAction, UsbId};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Raw form (the file as written)
// ---------------------------------------------------------------------------

/// The configuration file before validation. `deny_unknown_fields` everywhere:
/// a typo'd key is a hard error, not a silently-ignored setting.
///
/// Also `Serialize`: the daemon owns config writes (charter §9), so it round-
/// trips this back to TOML through [`crate::config_store`]. Comments and layout
/// in the file are not preserved across a daemon-side write.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    #[serde(default)]
    pub general: RawGeneral,
    #[serde(default)]
    pub detection: RawDetection,
    #[serde(default)]
    pub whitelist: Vec<RawWhitelistEntry>,
    #[serde(default)]
    pub response: RawResponse,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawGeneral {
    #[serde(default)]
    pub armed_at_boot: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawDetection {
    #[serde(default = "default_sensors")]
    pub sensors: Vec<String>,
}

impl Default for RawDetection {
    fn default() -> Self {
        Self {
            sensors: default_sensors(),
        }
    }
}

fn default_sensors() -> Vec<String> {
    vec!["usb".to_owned()]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawWhitelistEntry {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_count: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawResponse {
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_action: Option<String>,
    /// Charter §9 knob. v1 rejects `= true` in [`validate`] — see
    /// [`ConfigError::LockScreenFirstUnsupported`]. Kept here so the rejection
    /// can be specific rather than a `deny_unknown_fields` "unknown key".
    #[serde(default)]
    pub lock_screen_first: bool,
    /// What to do if the USB sensor reports lost events (kernel receive-buffer
    /// overflow): `"warn"` (default — surface in `status`, keep running) or
    /// `"kill"` (treat the gap as an unauthorized change and fire).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_sensor_gap: Option<String>,
    /// Absent from the default config entirely. Its mere presence means the
    /// operator is asking for LUKS header destruction, which then must be
    /// acknowledged and targeted correctly or the whole config is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub luks_destroy: Option<RawLuksDestroy>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawLuksDestroy {
    #[serde(default)]
    pub i_understand_this_is_irreversible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_header: Option<String>,
}

// ---------------------------------------------------------------------------
// Validated form (what the daemon runs on)
// ---------------------------------------------------------------------------

/// A validated configuration. Every value is resolved — no `Option` that the
/// daemon has to second-guess at runtime.
///
/// `#[non_exhaustive]`: the **only** supported way to obtain a `Config` is
/// [`validate`]. Blocking struct-literal construction from other crates keeps a
/// half-built `Config` (e.g. a field-by-field reload merge) from ever reaching
/// the policy engine or the responders.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    pub armed_at_boot: bool,
    pub sensors: Vec<SensorName>,
    pub whitelist: Vec<WhitelistRule>,
    pub dry_run: bool,
    pub power_action: PowerAction,
    /// Resolved from `response.on_sensor_gap`; defaults to [`SensorGapAction::Warn`].
    pub on_sensor_gap: SensorGapAction,
    // `response.lock_screen_first` is intentionally absent: v1 rejects `= true`
    // at validation (see [`ConfigError::LockScreenFirstUnsupported`]) and `false`
    // carries no information. A real implementation re-adds it.
    /// `Some` only if `[response.luks_destroy]` was present *and* fully valid
    /// *and* acknowledged. `None` is the normal case.
    pub luks_destroy: Option<LuksDestroy>,
}

/// What the daemon does when the USB sensor reports a kernel receive-buffer
/// overflow (`ENOBUFS`) — some add/remove events were missed. A closed set, so a
/// plain enum: a new variant is a deliberate schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SensorGapAction {
    /// Set `events_lost` in `status`, log loudly, keep running. The operator
    /// investigates and restarts.
    #[default]
    Warn,
    /// Treat the gap as an unauthorized change: fire a kill
    /// ([`killbill_proto::KillReason::SensorGap`]).
    Kill,
}

/// A sensor the daemon should start. v1 has exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SensorName {
    Usb,
}

/// A validated whitelist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistRule {
    pub id: UsbId,
    pub label: Option<String>,
    /// Resolved: a missing `max_count` becomes `1`.
    pub max_count: u32,
}

/// A validated LUKS-header-destruction target.
///
/// There is no `enabled` field: a `LuksDestroy` value existing *is* the
/// acknowledgment. In v1 the responder that consumes this only logs — the wipe
/// is a stub (invariant 3). [`validate`] checks the path shape (absolute,
/// control-char-free, under `/dev/`); the arm-time `preflight` in
/// [`crate::responder`] checks the target actually exists and is a block device
/// (a real LUKS-header probe waits for Phase 3, with the wipe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuksDestroy {
    pub target_header: PathBuf,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A failure reading or parsing the config file (as opposed to it being
/// well-formed TOML that fails validation — that is [`ValidationReport`]).
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("reading config {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing config {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// One reason a config was rejected. [`validate`] collects *all* of these before
/// returning, so the operator can fix everything in one pass.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("detection.sensors is empty — nothing would be watched")]
    NoSensors,

    #[error("unknown sensor {name:?} (v1 supports only \"usb\")")]
    UnknownSensor { name: String },

    #[error("whitelist entry {index}: id {id:?} is not a valid `vvvv:pppp` USB id")]
    MalformedWhitelistId { index: usize, id: String },

    #[error("whitelist entry {index}: id {id} appears more than once")]
    DuplicateWhitelistId { index: usize, id: UsbId },

    #[error("whitelist entry {index} ({id}): max_count must be at least 1")]
    ZeroMaxCount { index: usize, id: UsbId },

    #[error("response.power_action {value:?} is not one of poweroff, halt, none")]
    BadPowerAction { value: String },

    #[error("response.on_sensor_gap {value:?} is not one of warn, kill")]
    BadSensorGapAction { value: String },

    #[error(
        "response.lock_screen_first = true is not supported in v1: a pre-poweroff wait \
         would contend with the sacred kill path (invariant 1), and a fire-and-forget \
         lock never completes before power is cut. Set it to false or remove the line. \
         See PROJECT_CHARTER.md §13."
    )]
    LockScreenFirstUnsupported,

    #[error(
        "[response.luks_destroy] is present but not acknowledged: set \
         `i_understand_this_is_irreversible = true` to enable it, or remove the section"
    )]
    LuksDestroyNotAcknowledged,

    #[error("[response.luks_destroy]: target_header is required")]
    LuksDestroyMissingTarget,

    #[error("[response.luks_destroy]: target_header {path:?} must be an absolute path")]
    LuksDestroyTargetNotAbsolute { path: String },

    #[error("[response.luks_destroy]: target_header {path:?} must not contain `..`")]
    LuksDestroyTargetHasParentRefs { path: String },

    #[error(
        "[response.luks_destroy]: target_header {path:?} must be plain ASCII with no \
         control characters (a /dev node name always is)"
    )]
    LuksDestroyTargetHasControlChars { path: String },

    #[error(
        "[response.luks_destroy]: target_header {path:?} must be a block device under /dev/ \
         (this is the antidote to the original's `dirname('/etc')` disaster — charter §12)"
    )]
    LuksDestroyTargetNotUnderDev { path: String },
}

/// Every reason the config was rejected. The daemon logs this in full and
/// refuses to arm (invariant 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub errors: Vec<ConfigError>,
}

impl std::fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "configuration is invalid ({} problems):",
            self.errors.len()
        )?;
        for e in &self.errors {
            writeln!(f, "  - {e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationReport {}

// ---------------------------------------------------------------------------
// Load + validate
// ---------------------------------------------------------------------------

/// Read and parse the config file. Does no validation — the result is a
/// [`RawConfig`] that still needs [`validate`].
pub fn load(path: &Path) -> Result<RawConfig, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Validate a [`RawConfig`] into a [`Config`], or return *every* problem found.
///
/// Fail-closed: any error at all means the daemon must not arm. Validation
/// never partially accepts a config.
pub fn validate(raw: RawConfig) -> Result<Config, ValidationReport> {
    let mut errors: Vec<ConfigError> = Vec::new();

    let sensors = validate_sensors(&raw.detection.sensors, &mut errors);
    let whitelist = validate_whitelist(&raw.whitelist, &mut errors);
    let power_action = validate_power_action(raw.response.power_action.as_deref(), &mut errors);
    let on_sensor_gap = validate_sensor_gap(raw.response.on_sensor_gap.as_deref(), &mut errors);
    let luks_destroy = validate_luks_destroy(raw.response.luks_destroy.as_ref(), &mut errors);

    // v1 cannot honour a pre-poweroff screen lock without touching the kill
    // path, so it refuses the config rather than silently ignore the knob
    // (invariant 2). `false` / absent is fine. See PROJECT_CHARTER.md §13.
    if raw.response.lock_screen_first {
        errors.push(ConfigError::LockScreenFirstUnsupported);
    }

    if errors.is_empty() {
        Ok(Config {
            armed_at_boot: raw.general.armed_at_boot,
            sensors,
            whitelist,
            dry_run: raw.response.dry_run,
            power_action,
            on_sensor_gap,
            luks_destroy,
        })
    } else {
        Err(ValidationReport { errors })
    }
}

fn validate_sensors(names: &[String], errors: &mut Vec<ConfigError>) -> Vec<SensorName> {
    if names.is_empty() {
        errors.push(ConfigError::NoSensors);
    }
    let mut sensors = Vec::new();
    for name in names {
        match name.as_str() {
            "usb" => {
                if !sensors.contains(&SensorName::Usb) {
                    sensors.push(SensorName::Usb);
                }
            }
            other => errors.push(ConfigError::UnknownSensor {
                name: other.to_owned(),
            }),
        }
    }
    sensors
}

fn validate_whitelist(
    raw: &[RawWhitelistEntry],
    errors: &mut Vec<ConfigError>,
) -> Vec<WhitelistRule> {
    let mut rules: Vec<WhitelistRule> = Vec::with_capacity(raw.len());
    for (index, entry) in raw.iter().enumerate() {
        let id = match entry.id.parse::<UsbId>() {
            Ok(id) => id,
            Err(_) => {
                errors.push(ConfigError::MalformedWhitelistId {
                    index,
                    id: entry.id.clone(),
                });
                continue;
            }
        };
        if rules.iter().any(|r| r.id == id) {
            errors.push(ConfigError::DuplicateWhitelistId { index, id });
            continue;
        }
        let max_count = entry.max_count.unwrap_or(1);
        if max_count == 0 {
            errors.push(ConfigError::ZeroMaxCount { index, id });
            continue;
        }
        rules.push(WhitelistRule {
            id,
            label: entry.label.clone(),
            max_count,
        });
    }
    rules
}

fn validate_power_action(value: Option<&str>, errors: &mut Vec<ConfigError>) -> PowerAction {
    match value {
        None | Some("poweroff") => PowerAction::PowerOff,
        Some("halt") => PowerAction::Halt,
        Some("none") => PowerAction::None,
        Some(other) => {
            errors.push(ConfigError::BadPowerAction {
                value: other.to_owned(),
            });
            // Placeholder; `errors` is non-empty so `validate` returns Err.
            PowerAction::PowerOff
        }
    }
}

fn validate_sensor_gap(value: Option<&str>, errors: &mut Vec<ConfigError>) -> SensorGapAction {
    match value {
        None | Some("warn") => SensorGapAction::Warn,
        Some("kill") => SensorGapAction::Kill,
        Some(other) => {
            errors.push(ConfigError::BadSensorGapAction {
                value: other.to_owned(),
            });
            // Placeholder; `errors` is non-empty so `validate` returns Err.
            SensorGapAction::Warn
        }
    }
}

fn validate_luks_destroy(
    raw: Option<&RawLuksDestroy>,
    errors: &mut Vec<ConfigError>,
) -> Option<LuksDestroy> {
    let raw = raw?;
    let before = errors.len();

    if !raw.i_understand_this_is_irreversible {
        errors.push(ConfigError::LuksDestroyNotAcknowledged);
    }

    let target = match raw.target_header.as_deref() {
        None | Some("") => {
            errors.push(ConfigError::LuksDestroyMissingTarget);
            None
        }
        Some(t) => {
            let path = Path::new(t);
            if !t.is_ascii() || t.chars().any(char::is_control) {
                // The target is logged as a field, and the log is the
                // operator's only account of what happened — reject anything
                // that could forge or obfuscate a log line. A `/dev` node name
                // is plain ASCII; newlines, escapes, and bidi/zero-width
                // characters have no business here.
                errors.push(ConfigError::LuksDestroyTargetHasControlChars {
                    path: t.escape_default().collect(),
                });
                None
            } else if !path.is_absolute() {
                errors.push(ConfigError::LuksDestroyTargetNotAbsolute { path: t.to_owned() });
                None
            } else if path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                errors.push(ConfigError::LuksDestroyTargetHasParentRefs { path: t.to_owned() });
                None
            } else if !is_dev_node(path) {
                // A LUKS header lives on a block device, always `/dev/...`.
                // Requiring that (rather than blocklisting `/etc`, `/usr`, …) is
                // the fail-closed choice: anything unexpected is refused.
                errors.push(ConfigError::LuksDestroyTargetNotUnderDev { path: t.to_owned() });
                None
            } else {
                Some(PathBuf::from(t))
            }
        }
    };

    match target {
        Some(target_header) if errors.len() == before => Some(LuksDestroy { target_header }),
        _ => None,
    }
}

/// True if `path` is under `/dev/` (and not `/dev` itself).
fn is_dev_node(path: &Path) -> bool {
    path.starts_with("/dev") && path != Path::new("/dev")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_src: &str) -> RawConfig {
        toml::from_str(toml_src).expect("test TOML should parse")
    }

    // --- load ------------------------------------------------------------

    #[test]
    fn the_shipped_example_config_loads_and_validates() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config.example.toml");
        let raw = load(&path).expect("example config should load");
        let cfg = validate(raw).expect("example config should validate");
        assert!(cfg.dry_run, "the example ships in dry-run mode");
        assert_eq!(cfg.whitelist.len(), 1);
        assert!(cfg.luks_destroy.is_none(), "luks_destroy is commented out");
    }

    #[test]
    fn load_reports_a_missing_file() {
        let err = load(Path::new("/nonexistent/killbill/config.toml")).unwrap_err();
        assert!(matches!(err, LoadError::Io { .. }));
    }

    #[test]
    fn load_reports_a_parse_error() {
        let path =
            std::env::temp_dir().join(format!("killbilld-badcfg-{}.toml", std::process::id()));
        std::fs::write(&path, "not = = valid toml").unwrap();
        let err = load(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    // --- accept cases ------------------------------------------------------

    #[test]
    fn empty_config_is_valid_and_uses_defaults() {
        let cfg = validate(RawConfig::default()).expect("defaults are valid");
        assert_eq!(cfg.sensors, vec![SensorName::Usb]);
        assert_eq!(cfg.power_action, PowerAction::PowerOff);
        assert!(cfg.whitelist.is_empty());
        assert!(cfg.luks_destroy.is_none());
        assert!(!cfg.armed_at_boot);
        assert!(!cfg.dry_run);
    }

    #[test]
    fn full_config_from_the_charter_example_validates() {
        let cfg = validate(parse(
            r#"
            [general]
            armed_at_boot = true

            [detection]
            sensors = ["usb"]

            [[whitelist]]
            id = "1234:5678"
            label = "YubiKey 5C"
            max_count = 1

            [[whitelist]]
            id = "1d6b:0002"
            label = "Linux Foundation root hub"
            max_count = 4

            [response]
            dry_run = false
            power_action = "poweroff"
            lock_screen_first = false
            "#,
        ))
        .expect("charter example should validate");

        assert!(cfg.armed_at_boot);
        assert_eq!(cfg.whitelist.len(), 2);
        assert_eq!(cfg.whitelist[0].id, UsbId::new(0x1234, 0x5678));
        assert_eq!(cfg.whitelist[1].max_count, 4);
    }

    #[test]
    fn missing_max_count_resolves_to_one() {
        let cfg = validate(parse(
            r#"
            [[whitelist]]
            id = "1050:0407"
            "#,
        ))
        .unwrap();
        assert_eq!(cfg.whitelist[0].max_count, 1);
    }

    #[test]
    fn acknowledged_luks_destroy_with_dev_target_validates() {
        let cfg = validate(parse(
            r#"
            [response.luks_destroy]
            i_understand_this_is_irreversible = true
            target_header = "/dev/nvme0n1p3"
            "#,
        ))
        .expect("acknowledged + /dev target is valid");
        assert_eq!(
            cfg.luks_destroy.unwrap().target_header,
            PathBuf::from("/dev/nvme0n1p3")
        );
    }

    // --- reject cases ----------------------------------------------------

    fn errs(toml_src: &str) -> Vec<ConfigError> {
        validate(parse(toml_src))
            .expect_err("expected this config to be rejected")
            .errors
    }

    #[test]
    fn explicit_empty_sensor_list_is_rejected() {
        let raw = parse(
            r#"
            [detection]
            sensors = []
            "#,
        );
        assert!(validate(raw)
            .unwrap_err()
            .errors
            .contains(&ConfigError::NoSensors));
    }

    #[test]
    fn unknown_sensor_is_rejected() {
        assert!(errs(
            r#"
            [detection]
            sensors = ["usb", "bluetooth"]
            "#,
        )
        .iter()
        .any(|e| matches!(e, ConfigError::UnknownSensor { name } if name == "bluetooth")));
    }

    #[test]
    fn malformed_whitelist_id_is_rejected() {
        assert!(errs(
            r#"
            [[whitelist]]
            id = "not-an-id"
            "#,
        )
        .iter()
        .any(|e| matches!(e, ConfigError::MalformedWhitelistId { .. })));
    }

    #[test]
    fn duplicate_whitelist_id_is_rejected() {
        assert!(errs(
            r#"
            [[whitelist]]
            id = "1050:0407"
            [[whitelist]]
            id = "1050:0407"
            "#,
        )
        .iter()
        .any(|e| matches!(e, ConfigError::DuplicateWhitelistId { .. })));
    }

    #[test]
    fn zero_max_count_is_rejected() {
        assert!(errs(
            r#"
            [[whitelist]]
            id = "1050:0407"
            max_count = 0
            "#,
        )
        .iter()
        .any(|e| matches!(e, ConfigError::ZeroMaxCount { .. })));
    }

    #[test]
    fn bad_power_action_is_rejected() {
        assert!(errs(
            r#"
            [response]
            power_action = "explode"
            "#,
        )
        .iter()
        .any(|e| matches!(e, ConfigError::BadPowerAction { value } if value == "explode")));
    }

    #[test]
    fn on_sensor_gap_defaults_to_warn_and_accepts_kill() {
        assert_eq!(
            validate(RawConfig::default()).unwrap().on_sensor_gap,
            SensorGapAction::Warn
        );
        let cfg = validate(parse("[response]\non_sensor_gap = \"kill\"\n")).unwrap();
        assert_eq!(cfg.on_sensor_gap, SensorGapAction::Kill);
    }

    #[test]
    fn bad_on_sensor_gap_is_rejected() {
        assert!(errs("[response]\non_sensor_gap = \"maybe\"\n")
            .iter()
            .any(|e| matches!(e, ConfigError::BadSensorGapAction { value } if value == "maybe")));
    }

    #[test]
    fn lock_screen_first_true_is_rejected() {
        assert!(errs(
            r#"
            [response]
            lock_screen_first = true
            "#,
        )
        .contains(&ConfigError::LockScreenFirstUnsupported));
    }

    #[test]
    fn lock_screen_first_false_is_fine() {
        validate(parse(
            r#"
            [response]
            lock_screen_first = false
            "#,
        ))
        .expect("lock_screen_first = false is valid");
    }

    #[test]
    fn unknown_key_is_rejected_by_deny_unknown_fields() {
        let parsed: Result<RawConfig, _> = toml::from_str(
            r#"
            [response]
            power_acton = "poweroff"
            "#,
        );
        assert!(parsed.is_err(), "typo'd key must not be silently ignored");
    }

    #[test]
    fn luks_destroy_without_acknowledgment_is_rejected() {
        let e = errs(
            r#"
            [response.luks_destroy]
            target_header = "/dev/nvme0n1p3"
            "#,
        );
        assert!(e.contains(&ConfigError::LuksDestroyNotAcknowledged));
        assert!(
            e.iter()
                .all(|e| !matches!(e, ConfigError::LuksDestroyTargetNotUnderDev { .. })),
            "the /dev target is fine; only the missing acknowledgment is wrong"
        );
    }

    #[test]
    fn luks_destroy_acknowledged_by_a_generic_bool_does_not_count() {
        // There is no generic `enabled = true`; the only key that works is the
        // spelled-out one. A stray `enabled` is an unknown field.
        let parsed: Result<RawConfig, _> = toml::from_str(
            r#"
            [response.luks_destroy]
            enabled = true
            target_header = "/dev/nvme0n1p3"
            "#,
        );
        assert!(parsed.is_err());
    }

    #[test]
    fn luks_destroy_missing_target_is_rejected() {
        assert!(errs(
            r#"
            [response.luks_destroy]
            i_understand_this_is_irreversible = true
            "#,
        )
        .contains(&ConfigError::LuksDestroyMissingTarget));
    }

    #[test]
    fn luks_destroy_relative_target_is_rejected() {
        assert!(errs(
            r#"
            [response.luks_destroy]
            i_understand_this_is_irreversible = true
            target_header = "dev/nvme0n1p3"
            "#,
        )
        .iter()
        .any(|e| matches!(e, ConfigError::LuksDestroyTargetNotAbsolute { .. })));
    }

    #[test]
    fn luks_destroy_target_with_control_chars_is_rejected() {
        assert!(errs(
            r#"
            [response.luks_destroy]
            i_understand_this_is_irreversible = true
            target_header = "/dev/sda\n<forged log line>"
            "#,
        )
        .iter()
        .any(|e| matches!(e, ConfigError::LuksDestroyTargetHasControlChars { .. })));
    }

    #[test]
    fn luks_destroy_target_with_parent_refs_is_rejected() {
        assert!(errs(
            r#"
            [response.luks_destroy]
            i_understand_this_is_irreversible = true
            target_header = "/dev/../etc/shadow"
            "#,
        )
        .iter()
        .any(|e| matches!(e, ConfigError::LuksDestroyTargetHasParentRefs { .. })));
    }

    #[test]
    fn luks_destroy_target_outside_dev_is_rejected() {
        for target in [
            "/etc/killbill/config.toml",
            "/",
            "/home/user/disk.img",
            "/dev",
        ] {
            let src = format!(
                r#"
                [response.luks_destroy]
                i_understand_this_is_irreversible = true
                target_header = "{target}"
                "#,
            );
            assert!(
                errs(&src)
                    .iter()
                    .any(|e| matches!(e, ConfigError::LuksDestroyTargetNotUnderDev { .. })),
                "{target:?} should be rejected as not under /dev/"
            );
        }
    }

    #[test]
    fn all_problems_are_reported_at_once() {
        let report = validate(parse(
            r#"
            [detection]
            sensors = ["usb", "lid"]

            [[whitelist]]
            id = "bogus"

            [[whitelist]]
            id = "1050:0407"
            max_count = 0

            [response]
            power_action = "nope"
            "#,
        ))
        .unwrap_err();

        // unknown sensor + malformed id + zero max_count + bad power action
        assert_eq!(report.errors.len(), 4, "report was: {report}");
    }
}
