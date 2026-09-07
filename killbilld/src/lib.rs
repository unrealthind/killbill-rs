//! `killbilld` — the daemon's logic, without the process wrapper.
//!
//! Everything that decides *what the daemon does* lives here as a library so it
//! can be unit-tested without spawning a process, opening a socket, or touching
//! hardware (charter §7.1). `main.rs` is a thin shell over this crate.
//!
//! Build order (see `CLAUDE.md`): steps 1–3 are config load and fail-closed
//! validation and the pure policy engine; step 4 adds the responders. The USB
//! sensor, control server, and the wiring in `daemon.rs` land in later steps.

#![deny(unsafe_code)]

pub mod config;
pub mod device_table;
pub mod policy;
pub mod responder;

pub use config::{
    load, validate, Config, ConfigError, LoadError, LuksDestroy, RawConfig, SensorName,
    ValidationReport, WhitelistRule,
};
pub use device_table::DeviceTable;
pub use policy::{decide, Decision};
pub use responder::{
    build_responders, dispatch, kill_in_flight, preflight, Responder, ResponderNotReady,
};
