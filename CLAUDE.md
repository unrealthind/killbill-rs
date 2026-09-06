# killbill-rs

Event-driven Rust successor to the Python `usbkill`. A root daemon watches USB
add/remove events via the kernel netlink uevent socket and, when armed and an
unauthorized change occurs, powers the machine off so the LUKS disk re-locks.

[PROJECT_CHARTER.md](PROJECT_CHARTER.md) is the source of truth for **what and
why**. This file is the source of truth for **how we build it**. If the two ever
disagree, the charter wins — and update this file.

---

## Non-negotiable invariants

These are design guarantees, not preferences. Do not weaken one to make a task
easier; if a task seems to require it, stop and raise it.

1. **The kill path is sacred.** Once a kill decision is made, nothing may block
   or delay the poweroff — not logging, not config, not a connected UI. In
   practice: responders are independent subscribers, never a chain, and no
   responder's failure or slowness can gate another's.
2. **Fail closed.** Invalid config means the daemon refuses to arm, loudly. It
   never guesses intent and never fires on a half-understood config.
3. **`luks_destroy` stays a stub in v1.** Config schema, validation, TUI screen,
   and dry-run messaging are all real. The header wipe itself is deliberately
   unimplemented. Do not implement it, even behind a flag.
4. **Dangerous things need distinctly-named opt-in.** Never a generic `enabled =
   true`. The acknowledgment key is spelled out
   (`i_understand_this_is_irreversible`), and the TUI additionally requires a
   typed confirmation word.
5. **Disarm is a socket command, never a signal.** Signals (`SIGTERM`/`SIGINT`)
   mean only "stop the process" — they must never disarm protection. This was
   the original's worst flaw.
6. **No shelling out with built strings.** Responders act through typed calls
   (syscall / `Command` with argv vectors), never `format!`-ed shell lines.
7. **Sensors fail loud.** A parse failure surfaces as an error. It must never
   degrade into "no devices seen", which silently means "no protection".
8. **No network. No telemetry.** Ever. The only IPC is the local Unix socket.

Section 12 of the charter lists each original defect and the design that
prevents it — consult it before changing anything in these areas.

---

## Current state

Pre-code. The repo contains the charter and this file; nothing is scaffolded yet.

**Platform note:** development is currently on macOS arm64; we move to Linux
soon. Target is Linux-only regardless (netlink, systemd, poweroff). Write
platform-neutral code — types, config, policy, protocol, CLI, TUI — so it
compiles and tests anywhere, and `#[cfg(target_os = "linux")]`-gate the two
genuinely Linux-bound pieces (the netlink sensor, the poweroff responder). Don't
invest in elaborate macOS emulation of netlink; real verification happens on
Linux.

The Rust toolchain is not installed yet — `rustup` first.

---

## Phases

Three phases, in order. Do not start a phase before the previous one's exit
criteria are met; that ordering is the point — the backend has to be trustworthy
before anything renders it, and it ships only once it's been proven on real
hardware.

### Phase 1 — Backend (current)

The daemon and the headless path. Everything the tool *is*, minus the pretty
front end.

Build order within the phase:

1. **Workspace + shared types.** Cargo workspace; `killbill-proto` holding
   `SensorEvent`, `Action`, and the control-protocol command/reply/event enums.
   These vocabularies are what make the layer boundaries real — get them right
   before anything depends on them.
2. **Config.** TOML load, typed deserialization, and fail-closed validation as a
   separate, heavily-tested step. Validation is security-critical code: test the
   rejection cases as hard as the accept cases.
3. **Policy engine.** `SensorEvent` + config → `Action` or no-op. Pure, sync,
   trivially unit-testable, no I/O. Should be the easiest code in the repo to
   read.
4. **Responders.** The `Responder` trait, then `logger` and `poweroff`, then the
   `luks-destroy` stub. Independent subscribers — see invariant 1.
5. **USB sensor.** The `Sensor` trait, then the netlink uevent implementation:
   open `NETLINK_KOBJECT_UEVENT`, parse add/remove into `SensorEvent`.
6. **Control server.** `SOCK_SEQPACKET` at `/run/killbilld.sock`, mode 0660,
   root-owned. Length-prefixed frames, serde JSON bodies. Handles commands and
   fans out the event stream to subscribers.
7. **`killbillctl`.** `status`, `arm`, `disarm`, `test`, `whitelist
   add|remove|list`, `reload`.

**Exit criteria:** on a Linux box, `killbilld` runs under systemd; plugging and
unplugging a device produces correct decisions; dry-run reports what would
happen and touches nothing; `killbillctl` drives every command; an invalid
config refuses to arm; poweroff fires for real on an unauthorized event.

### Phase 2 — TUI

`killbill-tui` on ratatui, a **separate binary** so a UI crash can never touch
protection. It is a pure client of the Phase 1 protocol — if it needs a daemon
capability that doesn't exist, add it to the protocol and the CLI too, never a
TUI-only side channel.

Screens: live device list (new/unknown highlighted), plug-and-whitelist
(keypress → daemon performs the write), armed/disarmed toggle, dry-run results,
and the fenced destruction screen — visually distinct, names the exact target
device, requires typing `DESTROY`.

**Exit criteria:** a device can be whitelisted end-to-end by plugging it in and
pressing a key; killing the TUI mid-session leaves the daemon armed and healthy.

### Phase 3 — Ship

Packaging and hardening. `killbilld.service` with `ProtectSystem`,
`ProtectHome`, `NoNewPrivileges`, and a minimal `CapabilityBoundingSet` — only
what netlink and poweroff need, not ambient root. `.deb` (cargo-deb), `.rpm`
(cargo-generate-rpm), AUR `PKGBUILD`, plain install script. Man pages.

`postinst` must be idempotent: install the default config **only if absent**,
create the log directory, enable the service but **do not auto-arm** — a fresh
install must never be able to lock the user out.

**Exit criteria:** install from package on a clean machine, configure a
whitelist, arm, and have it work — with no manual repair steps.

---

## Architecture

Three stages with clean seams; this separation is the founding decision, and the
reason the original couldn't be extended.

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
- **Seam 3 — control protocol:** request/reply plus event stream over the Unix
  socket. A first-class public interface, not an afterthought.

The daemon is one authority: it owns config, owns armed-state, and owns config
*writes*. UIs request changes; the daemon validates and persists them. This is
why running-state and the file can't drift.

The raw sensor stream fans out to two consumers — the policy engine and
subscribed control clients — so the TUI sees exactly what the daemon sees.

**Adding a sensor or responder must not require touching the core.** If it does,
the seam is wrong.

### Proposed crate layout

```
killbill-proto/   wire + shared types (SensorEvent, Action, protocol messages)
killbilld/        daemon; lib.rs (config, policy, sensors, responders) + main.rs
killbillctl/      CLI client
killbill-tui/     ratatui client (Phase 2)
```

The daemon's logic lives in its `lib.rs` so it's testable without spawning a
process. Adjust the layout if it stops fitting — just note the change here.

---

## Conventions

- **Rust 2021+, stable toolchain.** Tokio is the recommended async runtime
  (charter §13.1 leaves `mio`+threads open — if that's chosen instead, record it
  in the charter).
- **`unsafe` needs a comment** stating the invariant it upholds. Expect it only
  around netlink socket setup and the poweroff syscall.
- **No `unwrap()`/`expect()` in daemon runtime paths.** Startup and tests are
  fine. Anywhere that runs while armed must handle its errors.
- **Errors:** `thiserror` for library error types, `anyhow` at binary
  boundaries.
- **Logging:** `tracing`. Log the *decision* (what fired and why) as carefully as
  the event — this is a security tool, and the log is the user's only account of
  what happened.
- **Tests:** the policy engine and config validation are pure and must have
  thorough unit tests, rejection cases included. The netlink sensor gets tests
  against captured uevent byte payloads rather than live hardware.

## Learning-codebase bias

This is deliberately a teachable codebase. Where clarity and maximum hardening
conflict, choose clarity — prefer the obvious construct over the clever one, and
comment the *why* behind non-obvious security decisions.

**The one exception is the kill path**, which prefers correctness above
everything, clarity included.

---

## Out of scope for v1

Don't build these, and don't add abstractions in anticipation of them beyond the
two existing traits: non-USB sensors, file shredding, RAM/swap wiping, live LUKS
destruction, networking, telemetry, fleet or central config, non-systemd init,
and anything to do with setting up disk encryption (LUKS is assumed to exist).
