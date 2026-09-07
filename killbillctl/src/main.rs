//! `killbillctl` — the command-line client (charter §7.3).
//!
//! The dependable, scriptable path: everything the TUI can do, the CLI can do.
//! It is a pure client of the control protocol in [`killbill_proto`].
//!
//! Not implemented yet — it lands in Phase 1 step 7, once the control server
//! (step 6) exists for it to talk to.

fn main() -> std::process::ExitCode {
    eprintln!(
        "killbillctl is not implemented yet: it arrives in Phase 1 step 7, after \
         the control server. See CLAUDE.md."
    );
    std::process::ExitCode::FAILURE
}
