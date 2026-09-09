# Contributing to killbill-rs

Thanks for your interest. killbill-rs is a security tool that powers a machine
off on an unauthorized USB change, and it is also written to be a *readable*
codebase. Both of those shape how changes are reviewed.

`PROJECT_CHARTER.md` is the source of truth for **what** v1 is and **why**. Read
it before proposing anything non-trivial.

## Building and testing

The toolchain is pinned by `rust-toolchain.toml` (stable + rustfmt + clippy);
`rustup` picks it up automatically. MSRV is recorded as `rust-version` in
`Cargo.toml`.

```bash
cargo build --workspace
cargo test --workspace          # the policy engine and config validation carry the weight
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Every change must leave all four green.

The netlink sensor is tested against **captured uevent byte payloads**, not live
hardware (`killbilld/src/sensor/uevent.rs`). The poweroff responder's decision
logic is a pure function with unit tests; only the syscall itself is untested.

## The non-negotiable invariants

These are design guarantees, not preferences. A change that weakens one will not
be merged, even if it makes a task easier. If a task seems to require it, open an
issue first.

1. **The kill path is sacred.** Once a kill decision is made, nothing may block
   or delay the poweroff — not logging, not config, not a connected UI.
   Responders are independent subscribers, never a chain.
2. **Fail closed.** An invalid config means the daemon refuses to arm, loudly. It
   never guesses intent and never fires on a half-understood config.
3. **`luks_destroy` stays a stub in v1.** Schema, validation, TUI screen, and
   dry-run messaging are all real. The header wipe itself is deliberately
   unimplemented — do not implement it, even behind a flag.
4. **Dangerous things need distinctly-named opt-in.** Never a generic
   `enabled = true`. The acknowledgment key is spelled out
   (`i_understand_this_is_irreversible`), and the TUI additionally requires a
   typed confirmation word.
5. **Disarm is a socket command, never a signal.** `SIGTERM` / `SIGINT` mean only
   "stop the process" — they must never disarm protection.
6. **No shelling out with built strings.** Responders act through typed calls
   (syscall / `Command` with argv vectors), never `format!`-ed shell lines.
7. **Sensors fail loud.** A parse failure surfaces as an error. It must never
   degrade into "no devices seen", which silently means "no protection".
8. **No network. No telemetry. Ever.** The only IPC is the local Unix socket.

## Architecture — three seams

```
SENSORS  →  CORE (policy)  →  RESPONDERS
  usb          engine            poweroff / logger / luks-destroy (stub)
               ↓
        CONTROL SOCKET → TUI / CLI
```

- **Seam 1 — `Sensor`:** start, emit normalized `SensorEvent`s on a channel,
  stop. Knows nothing about policy or response.
- **Seam 2 — `Responder`:** receives an `Action` and acts. Independent
  subscribers, not a pipeline.
- **Seam 3 — control protocol:** request/reply plus an event stream over the Unix
  socket. A first-class public interface.

**Adding a sensor or a responder must not require touching the core.** If your
change to add one does, the seam is wrong — raise it. The normalized
`SensorEvent` / `Action` vocabularies in `killbill-proto` are what make this
work; extend those (additively, on `#[non_exhaustive]` types) rather than
special-casing the core.

The daemon is one authority: it owns config, armed-state, and config *writes*.
UIs request changes; the daemon validates and persists. If `killbill-tui` needs
a capability the protocol lacks, add it to `killbill-proto` **and** `killbillctl`
— never a TUI-only side channel.

## Conventions

- **Rust 2021, stable.** No async runtime — `std::thread` + `std::sync::mpsc`
  throughout (charter §13.1). Each concurrent piece is one blocking loop; the
  kill path must not depend on an executor.
- **No `unwrap()` / `expect()` in daemon runtime paths.** Startup and tests are
  fine. Anything that runs while armed handles its errors.
- **Errors:** `thiserror` for library error types, `anyhow` at binary
  boundaries.
- **Logging:** `tracing`. Log the *decision* — what fired and why — as carefully
  as the event. The log is the operator's only account of what happened.
- **`unsafe` needs a comment** stating the invariant it upholds. `killbilld` is
  `#![deny(unsafe_code)]`; every syscall goes through `nix`'s safe wrappers.
- **Tests:** the policy engine and config validation are pure — test the
  rejection cases as hard as the accept cases.

### The learning-codebase bias

Where clarity and maximum hardening conflict, choose clarity: prefer the obvious
construct over the clever one, and comment the *why* behind non-obvious security
decisions.

**The one exception is the kill path**, which prefers correctness above
everything, clarity included. Code under `killbilld/src/responder/` and the
dispatch path in `daemon.rs` is held to that stricter bar.

## Out of scope for v1

Please don't open PRs for these — they are deliberate non-goals (charter §11):
non-USB sensors, file shredding, RAM/swap wiping, live LUKS destruction,
networking, telemetry, fleet or central config, non-systemd init, or anything to
do with setting up disk encryption.

## Submitting changes

- One logical change per PR. Keep the diff reviewable.
- Update `PROJECT_CHARTER.md` if you change the protocol (§8) or config schema
  (§9), and add a `CHANGELOG.md` entry under `## [Unreleased]`.
- Security-sensitive reports go through `SECURITY.md`, not a public issue.

## Cutting a release

Before tagging `vX.Y.Z`, run — and require green:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
sh packaging/scripts/check-sync.sh      # maintainer-script copies in sync
cargo deny check                        # no network deps, advisories clean
sh packaging/scripts/check-release.sh   # PKGBUILD has a real digest, pkgver matches
```

`check-release.sh` fails on the `sha256sums=('SKIP')` placeholder — clear it with
`updpkgsums` (pacman-contrib) against the published release tarball and commit
the real digest. CI (`.github/workflows/ci.yml`) runs the first four on every
push; the release workflow runs `check-release.sh` before building artifacts.

Then: move the `CHANGELOG.md` `## [Unreleased]` items under a dated `## [X.Y.Z]`
heading, commit, `git tag -a vX.Y.Z`, and push the tag — `release.yml` builds the
static musl tarball, `.deb`, `.rpm`, `SHA256SUMS`, and minisign signatures into a
draft release.
