//! `killbilld` — the daemon's logic, without the process wrapper.
//!
//! Everything that decides *what the daemon does* lives here as a library so it
//! can be unit-tested without spawning a process, opening a socket, or touching
//! hardware (charter §7.1). `main.rs` is a thin shell over this crate.
//!
//! Build order (see `CLAUDE.md`): steps 1–3 are config load and fail-closed
//! validation and the pure policy engine; step 4 adds the responders; step 5
//! the USB sensor; step 6 the control server ([`control`]) and the runtime
//! wiring ([`daemon`]).
//!
//! [`control`] and [`daemon`] are `#[cfg(unix)]` — the control transport is a
//! `SOCK_SEQPACKET` Unix socket, a third genuinely OS-bound piece alongside the
//! netlink sensor and the poweroff responder. Everything else builds anywhere.

#![deny(unsafe_code)]

pub mod config;
pub mod config_store;
pub mod device_table;
pub mod policy;
pub mod responder;
pub mod sensor;

#[cfg(unix)]
pub mod control;
#[cfg(unix)]
pub mod daemon;

pub use config::{
    load, validate, Config, ConfigError, LoadError, LuksDestroy, RawConfig, SensorGapAction,
    SensorName, ValidationReport, WhitelistRule,
};
pub use config_store::write_atomic as write_config;
pub use device_table::DeviceTable;
pub use policy::{decide, Decision};
pub use responder::{
    build_responders, dispatch, kill_failed, kill_in_flight, preflight, Responder,
    ResponderNotReady,
};
pub use sensor::{
    spawn as spawn_sensor, Sensor, SensorError, SensorHandle, SensorMessage, StopFlag,
    UsbNetlinkSensor,
};

#[cfg(unix)]
pub use daemon::{run as run_daemon, RunOptions};
