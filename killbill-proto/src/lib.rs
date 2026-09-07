//! `killbill-proto` — the shared vocabulary spoken across killbill-rs's three
//! layers.
//!
//! The founding architectural decision (charter §6) is to separate **detection**
//! from **decision** from **response**. That separation is only real if the
//! layers share a small, stable set of types and nothing else:
//!
//! * [`SensorEvent`] — what a sensor observed, normalized so the policy engine
//!   never learns what a sensor *is*.
//! * [`Action`] — what a kill decision does, so a responder never learns what
//!   the policy engine *is*.
//! * [`Command`] / [`Reply`] / [`Event`] — the control-socket protocol, a
//!   first-class public interface (charter §8), not an afterthought.
//!
//! This crate has no I/O and no async runtime, so every other crate — and every
//! test — can depend on it freely.

#![forbid(unsafe_code)]

pub mod action;
pub mod protocol;
pub mod sensor_event;

pub use action::{Action, KillReason, PowerAction};
pub use protocol::{
    decode, encode, Command, DeviceInfo, Event, ProtocolError, Reply, StatusPayload,
    WhitelistEntry, MAX_FRAME_LEN,
};
pub use sensor_event::{
    DeviceIdentity, EventKind, SensorEvent, SensorSource, UsbId, UsbIdParseError,
};
