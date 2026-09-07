//! `killbilld` — the killbill-rs daemon (charter §7.1).
//!
//! Phase 1 is being built bottom-up (see `CLAUDE.md`). Done so far: shared
//! types, config, the policy engine, and the responders — all in the
//! [`killbilld`] library and tested there. The runnable daemon — the USB
//! sensor and the control server — arrives in steps 5–7, at which point this
//! file grows a real `tokio` entry point.

#![deny(unsafe_code)]

fn main() -> std::process::ExitCode {
    eprintln!(
        "killbilld is not runnable yet: the Phase 1 backend is under construction \
         (steps 1-4 of 7 done). See CLAUDE.md for the build order."
    );
    std::process::ExitCode::FAILURE
}
