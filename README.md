<div align="center">

# killbill-rs

**An event-driven USB kill switch for machines that must not be seized unlocked.**

[![Language: Rust](https://img.shields.io/badge/language-Rust_2021-orange.svg)](https://www.rust-lang.org/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux_%2B_systemd-blue.svg)](#platform-support)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-green.svg)](#license)
[![Status: Phase 2 (TUI)](https://img.shields.io/badge/status-Phase_2_%E2%80%94_TUI-yellow.svg)](#project-status)

</div>

---

`killbill-rs` is a ground-up Rust successor to the Python [`usbkill`](https://github.com/hephaest0s/usbkill).
A small root daemon watches USB add/remove events on the kernel netlink uevent
socket. When it is **armed** and an unauthorized device change occurs, it powers
the machine off immediately — so a LUKS-encrypted disk re-locks and its contents
become inaccessible.

It is built for **one specific person**: a high-risk individual — journalist,
activist, researcher — protecting their own laptop against physical seizure or
tampering. It is not a fleet tool, it has no network features, and it never
phones home.

> [!IMPORTANT]
> This is a **rewrite, not a port**. The original's polling loop, embedded
> interpreter, silent-failure modes, and destructive-by-accident behavior are
> all deliberately discarded. Every design decision is traceable to a concrete
> defect in the original — see [Lessons from the original](#lessons-from-the-original).

---

## Table of contents

- [Why a rewrite](#why-a-rewrite)
- [How it works](#how-it-works)
- [Architecture](#architecture)
- [The non-negotiable invariants](#the-non-negotiable-invariants)
- [Components](#components)
- [Configuration](#configuration)
- [The decision table](#the-decision-table)
- [Control protocol](#control-protocol)
- [LUKS header destruction (fenced, stub-only)](#luks-header-destruction-fenced-stub-only)
- [Project status](#project-status)
- [Repository layout](#repository-layout)
- [Building and testing](#building-and-testing)
- [Platform support](#platform-support)
- [Out of scope for v1](#out-of-scope-for-v1)
- [Documentation](#documentation)
- [License](#license)

---

## Why a rewrite

The original `usbkill` worked, but its architecture made it impossible to trust
or extend:

| Problem in the original | Consequence |
|---|---|
| Detection, decision, and response fused into one polling loop | A logging failure could crash the process *before* it powered off |
| Polling every 250 ms | Fast USB swaps slipped through the gap |
| `SIGTERM` / `SIGINT` disarmed protection | Anyone who could signal the process could disable it silently |
| `dirname('/etc/usbkill.ini')` used as a wipe target | "Melt mode" could wipe `/etc` |
| Destructive actions behind a plain boolean | One stray `true` armed an irreversible action |
| `os.system` with concatenated strings | Shell-injection and quoting hazards |
| Silent parse failure → empty device list | "No devices seen" silently means "no protection" |

`killbill-rs` fixes each of these **by design**, not by patching. The founding
decision is a hard separation of the three stages, with typed vocabularies at
every seam.

---

## How it works

```
  ┌──────────────┐        ┌──────────────┐        ┌─────────────────────┐
  │   SENSORS    │        │  CORE        │        │     RESPONDERS      │
  │              │ event  │  policy      │ action │                     │
  │  USB sensor  ├───────►│  engine      ├───────►│  poweroff           │
  │  (netlink    │ stream │  (pure fn)   │  fan-  │  logger             │
  │   uevent)    │        │              │  out   │  luks-destroy (stub)│
  └──────────────┘        └──────┬───────┘        └─────────────────────┘
                                 │
                                 │ same event stream
                                 ▼
                        ┌─────────────────┐
                        │ CONTROL SOCKET  │──► killbillctl (CLI)
                        │ /run/killbilld  │──► killbill-tui (Phase 2)
                        │      .sock      │
                        └─────────────────┘
```

1. The **USB sensor** opens `NETLINK_KOBJECT_UEVENT` and turns each kernel
   add/remove announcement into a normalized `SensorEvent`.
2. The **policy engine** — one pure, synchronous function — maps
   `SensorEvent` + config + current device table to a `Decision`:
   `Ignore` or `Act(Action)`.
3. When the daemon is **armed**, an `Act` decision fans out to every
   **responder** as independent subscribers. No responder can block or delay
   another; the poweroff is never gated on logging.
4. The **raw event stream** also feeds subscribed control clients, so the TUI
   and CLI see exactly what the daemon sees.

Reaction time is bounded by the kernel's own event delivery — milliseconds — and
idle CPU is effectively zero.

---

## Architecture

Three stages, three clean seams. **Adding a sensor or a responder must never
require touching the core.** If it does, the seam is wrong.

| Seam | Trait | Contract |
|---|---|---|
| **1 — input** | `Sensor` | Start, emit normalized `SensorEvent`s on a channel, stop. Knows nothing about policy or response. |
| **2 — output** | `Responder` | Receive an `Action` and act. An independent subscriber — **not** a link in a pipeline. |
| **3 — control** | wire protocol | Request/reply **plus** an unsolicited event stream over the Unix socket. A first-class public interface. |

The daemon is the **single authority**: it owns the config, owns armed-state,
and owns config *writes*. UIs request changes; the daemon validates and
persists them. Running-state and the config file can never drift.

---

## The non-negotiable invariants

These are design guarantees, not preferences.

1. **The kill path is sacred.** Once a kill decision is made, nothing may block
   or delay the poweroff — not logging, not config, not a connected UI.
   Responders are independent subscribers, never a chain.
2. **Fail closed.** An invalid config means the daemon refuses to arm, loudly.
   It never guesses intent and never fires on a half-understood config.
3. **`luks_destroy` stays a stub in v1.** Schema, validation, TUI screen, and
   dry-run messaging are all real. The header wipe itself is deliberately
   unimplemented.
4. **Dangerous things need distinctly-named opt-in.** Never a generic
   `enabled = true`. The acknowledgment key is spelled out
   (`i_understand_this_is_irreversible`), and the TUI additionally requires a
   typed confirmation word.
5. **Disarm is a socket command, never a signal.** `SIGTERM` / `SIGINT` mean
   only "stop the process" — they must never disarm protection. This was the
   original's worst flaw.
6. **No shelling out with built strings.** Responders act through typed calls
   (syscall / `Command` with argv vectors), never `format!`-ed shell lines.
7. **Sensors fail loud.** A parse failure surfaces as an error. It must never
   degrade into "no devices seen", which silently means "no protection".
8. **No network. No telemetry. Ever.** The only IPC is the local Unix socket.

---

## Components

| Binary | Role | Runs as |
|---|---|---|
| **`killbilld`** | The daemon. Owns config and armed-state, runs sensors, evaluates policy, dispatches responders, serves the control socket. | root, under systemd |
| **`killbillctl`** | The CLI client. Scriptable, headless-friendly. Everything the TUI can do. | any user with socket access |
| **`killbill-tui`** | *(Phase 2)* A ratatui client — live device list, plug-and-whitelist, armed toggle, dry-run, the fenced destruction screen. A **separate binary** so a UI crash can never touch protection. | any user with socket access |

### `killbillctl` commands

```
killbillctl status                     # armed? sensor healthy? config? whitelist?
killbillctl devices                    # what the daemon is currently tracking
killbillctl arm | disarm               # disarm is a logged socket command
killbillctl test                       # dry-run: report what would happen, touch nothing
killbillctl whitelist add|remove|list
killbillctl reload                     # re-read and re-validate the config file
killbillctl events                     # stream the daemon's event feed
```

---

## Configuration

**Location:** `/etc/killbill/config.toml` — the daemon owns writes to it.
A fully-commented [`config.example.toml`](config.example.toml) lives at the repo root.

```toml
[general]
# Arm automatically when the daemon starts (e.g. at boot under systemd).
# A fresh install ships this as false so installation can never lock you out.
armed_at_boot = false

[detection]
# v1 implements only "usb". The list is what makes the sensor layer pluggable.
sensors = ["usb"]

# One [[whitelist]] block per device allowed to be connected while armed.
# `id` is the USB vendor:product pair in lowercase hex, as `lsusb` prints.
[[whitelist]]
id = "1050:0407"
label = "YubiKey 5C"
max_count = 1

[response]
dry_run = true              # log what *would* happen and touch nothing — use this first
power_action = "poweroff"   # poweroff | halt | none
lock_screen_first = false   # must be false in v1 — `= true` is rejected at validation
```

> [!WARNING]
> **Any unrecognized key is a hard error.** The daemon collects *every*
> validation failure, reports them all, and refuses to arm — it never silently
> ignores a typo. A broken config disables protection **loudly**.

---

## The decision table

The policy engine's entire v1 rule set, evaluated only while **armed**:

| Event | Condition | Decision |
|---|---|---|
| device added | id **not** on whitelist | `Act(UnknownDevice)` |
| device added | no readable USB id | `Act(UnidentifiedDevice)` |
| device added | whitelisted, copies now **>** `max_count` | `Act(CountExceeded)` |
| device added | whitelisted, within `max_count` | `Ignore` |
| device removed | id **is** on the whitelist | `Act(WhitelistedDeviceRemoved)` |
| device removed | anything else | `Act(DeviceRemoved)` |

Removing **any** device while armed fires. Unplugging hardware is the classic
seizure signal. The whitelist suppresses *additions* you expect; it never makes
a device safe to yank.

The engine is a pure function — no clock, no I/O, no `async`, no logging. It is
exhaustively unit-tested, rejection cases included, and is meant to be the
easiest file in the repo to read:
[`killbilld/src/policy.rs`](killbilld/src/policy.rs).

---

## Control protocol

One `SOCK_SEQPACKET` Unix socket at `/run/killbilld.sock`, **mode `0660`,
root-owned**. "Who may talk to the daemon" is a filesystem question.

| Traffic | Messages |
|---|---|
| **Commands** (client → daemon, expects a reply) | `GetStatus`, `ListDevices`, `Arm`, `Disarm`, `WhitelistAdd`, `WhitelistRemove`, `WhitelistList`, `RunDryRun`, `ReloadConfig`, `Subscribe` |
| **Replies** (daemon → client) | `Ok`, `Status`, `Devices`, `Whitelist`, `DryRun`, `Error` |
| **Events** (daemon → subscribers, unsolicited) | `DeviceAdded`, `DeviceRemoved`, `Armed`, `Disarmed`, `WouldKill(reason)`, `SensorStopped`, `EventsLost` |

Everything except the three read-only queries requires `uid 0` on the connecting
peer (`SO_PEERCRED`) — including `Subscribe`, whose stream carries device ids.

**Framing:** length-prefixed frames. **Serialization:** serde + JSON for v1 —
readable and debuggable, swappable to a binary codec later without changing the
protocol shape.

---

## LUKS header destruction (fenced, stub-only)

Because LUKS is assumed to already exist, the correct "destroy data" primitive
is not per-file shredding but wiping the **LUKS header / keyslot**, which makes
the whole disk unrecoverable in milliseconds and is reliable on flash storage.

In **v1 this is a stub.** The config schema, validation, dry-run message, and
(Phase 2) the TUI screen are all real and correct. The header wipe itself is
**deliberately not implemented** — there is no live footgun during development.

Enabling it requires, all at once:

- An explicit block that is **absent from the default config**.
- The spelled-out acknowledgment key `i_understand_this_is_irreversible = true`
  — never a generic `enabled`.
- A `target_header` that resolves to a real block device under `/dev/`.
- *(Phase 2)* A visually-distinct TUI screen that names the exact target device
  and requires typing `DESTROY`.

Dry-run always logs `would destroy LUKS header on /dev/…` and touches nothing.

---

## Project status

Three phases, strictly ordered — the backend has to be trustworthy before
anything renders it, and it ships only once it is proven on real hardware.

### Phase 1 — Backend  ·  ✅ **done, hardware-verified 2026-09-08**

| Step | Item | State |
|---|---|---|
| 1 | Cargo workspace + `killbill-proto` shared types | ✅ implemented |
| 2 | Config: TOML load + fail-closed validation | ✅ implemented |
| 3 | Policy engine (`decide`) + decision table | ✅ implemented |
| 4 | Responders: `Responder` trait, `logger`, `poweroff`, `luks-destroy` stub | ✅ implemented |
| 5 | USB sensor: `Sensor` trait + netlink uevent implementation | ✅ implemented |
| 6 | Control server: `SOCK_SEQPACKET`, framed JSON, event fan-out | ✅ implemented |
| 7 | `killbillctl`: all commands | ✅ implemented |

> All seven steps are code-complete, reviewed, and green on
> `cargo test --workspace` / `clippy -D warnings`. **All exit criteria are now
> verified on real hardware:** a real netlink add/remove run, dry-run, a
> `killbilld` run under systemd, and a real poweroff on an unauthorized event
> all confirmed on 2026-09-08. See [`CLAUDE.md`](CLAUDE.md) for the full
> results and the one packaging-relevant finding (an SELinux label gotcha for
> Phase 3). Phase 2 (`killbill-tui`) is now the active phase.

**Exit criteria:** `killbilld` runs under systemd; plug/unplug produces correct
decisions; dry-run reports and touches nothing; `killbillctl` drives every
command; an invalid config refuses to arm; poweroff fires for real on an
unauthorized event.

### Phase 2 — TUI  ·  *current*

`killbill-tui` on ratatui, a separate binary and a pure client of the Phase 1
protocol. Screens: live device list, plug-and-whitelist, armed toggle, dry-run
results, and the fenced destruction screen.

**Exit criteria:** a device can be whitelisted end-to-end by plugging it in and
pressing a key; killing the TUI mid-session leaves the daemon armed and healthy.

### Phase 3 — Ship

`killbilld.service` with `ProtectSystem`, `ProtectHome`, `NoNewPrivileges`, and
a minimal `CapabilityBoundingSet`. Packaging: `.deb` (cargo-deb), `.rpm`
(cargo-generate-rpm), AUR `PKGBUILD`, plain install script, man pages.
`postinst` is idempotent: install the default config only if absent, enable the
service but **never auto-arm**.

**Exit criteria:** install from a package on a clean machine, configure a
whitelist, arm, and have it work — with no manual repair steps.

---

## Repository layout

```
killbill-rs/
├── Cargo.toml                  workspace: killbill-proto, killbilld, killbillctl
├── rust-toolchain.toml         pinned: stable + rustfmt + clippy
├── config.example.toml         fully-commented reference config (mirrors charter §9)
├── PROJECT_CHARTER.md          source of truth for WHAT and WHY
├── CLAUDE.md                   source of truth for HOW we build
│
├── killbill-proto/             the shared wire vocabulary — #![forbid(unsafe_code)]
│   └── src/
│       ├── sensor_event.rs     SensorEvent, EventKind, DeviceIdentity, UsbId
│       ├── action.rs           Action, KillReason, PowerAction
│       └── protocol.rs         Command / Reply / Event + framed JSON codec
│
├── killbilld/                  the daemon — logic in lib.rs, thin main.rs, #![deny(unsafe_code)]
│   └── src/
│       ├── lib.rs              re-exports; what the tests target
│       ├── config.rs           TOML load + fail-closed validate (collects every error)
│       ├── config_store.rs     atomic config write-back (the daemon owns config writes)
│       ├── policy.rs           the pure `decide` fn + decision table
│       ├── device_table.rs     what is currently connected
│       ├── daemon.rs           run(): the one authority thread wiring it all together
│       ├── control.rs          SOCK_SEQPACKET control server, SO_PEERCRED authz
│       ├── sensor/             Seam 1 — the Sensor trait and the USB implementation
│       │   ├── mod.rs          Sensor trait, spawn/SensorHandle, StopFlag
│       │   ├── netlink.rs      NETLINK_KOBJECT_UEVENT socket loop (Linux-gated)
│       │   └── uevent.rs       the pure byte parser — tested against captured payloads
│       ├── responder/          independent subscribers to an Action (invariant 1)
│       │   ├── mod.rs          Responder trait, dispatch fan-out, preflight, kill_in_flight
│       │   ├── logger.rs       structured tracing record of each decision
│       │   ├── poweroff.rs     reboot(2) via nix + SysRq/halt fallbacks; arm-time CAP_SYS_BOOT check
│       │   └── luks_destroy.rs LUKS-header-wipe — logging stub only (invariant 3)
│       └── main.rs             thin shell: flags, log sink, hand off to daemon::run
│
├── killbillctl/                the CLI client — #![forbid(unsafe_code)]
│   └── src/main.rs
│
└── killbill-tui/               the ratatui client (Phase 2, in progress)
    └── src/
```

The daemon's logic lives in `lib.rs` so it is testable without spawning a
process.

---

## Building and testing

> [!NOTE]
> The toolchain is pinned by [`rust-toolchain.toml`](rust-toolchain.toml)
> (stable + rustfmt + clippy). `rustup` picks it up automatically.

```bash
# Build the whole workspace
cargo build --workspace

# Run all tests — the policy engine and config validation carry the weight,
# with rejection cases tested as hard as the accept cases
cargo test --workspace

# Lint and format — clippy is warning-clean and CI-gated with -D warnings
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

The netlink sensor (step 5) is tested against **captured uevent byte payloads**,
not live hardware.

### Conventions

- **Rust 2021+, stable toolchain.** No async runtime — `std::thread` +
  `std::sync::mpsc` throughout (charter §13.1); the kill path must not depend on
  an executor.
- **No `unwrap()` / `expect()` in daemon runtime paths.** Startup and tests are fine.
- **Errors:** `thiserror` for library error types, `anyhow` at binary boundaries.
- **Logging:** `tracing`. The *decision* — what fired and why — is logged as
  carefully as the event. The log is the operator's only account of what happened.
- **`unsafe` needs a comment** stating the invariant it upholds. `killbilld` is
  `#![deny(unsafe_code)]` today (the poweroff syscall goes through `nix`); expect
  a local `#[allow]` only if netlink socket setup in step 5 needs one.

This is deliberately a **teachable codebase**: where clarity and maximum
hardening conflict, clarity wins — the one exception being the kill path, which
prefers correctness above everything.

---

## Platform support

The tool targets **Linux with systemd** (any mainstream distro from the last
several years — the netlink uevent interface has been stable for ~20 years, so
kernel version is a non-constraint).

The code is otherwise **platform-neutral**: types, config, policy, protocol,
CLI, and TUI compile and test anywhere. Only two pieces are genuinely
Linux-bound and are `#[cfg(target_os = "linux")]`-gated with non-Linux stub
fallbacks: the **netlink sensor** and the **poweroff responder**.

---

## Out of scope for v1

Not built, and not abstracted for in advance beyond the two existing traits:

- Non-USB sensors (lid, AC power, Bluetooth — the abstraction permits them; v1
  does not ship them)
- File shredding, RAM/swap wiping
- Live LUKS destruction (scaffolded stub only)
- Networking, telemetry, fleet or central configuration
- Non-systemd init support
- Anything to do with *setting up* disk encryption — LUKS is assumed to exist

---

## Lessons from the original

Every row is a concrete defect in the Python `usbkill`, and the design that
prevents it in v1. Charter §12 is the authority.

| Original defect | How v1 prevents it |
|---|---|
| `dirname('/etc/usbkill.ini')` → wiping `/etc` in melt mode | Fail-closed validation; explicit `/dev/` targets only; destruction is a stub |
| Logging failure could crash before poweroff | Logger is an independent responder; it can never block the kill path |
| Backgrounded wipe killed instantly by shutdown | No wiping in v1; responder completion semantics are defined |
| Catchable signals silently disabled protection | Disarm is an authenticated, logged socket command; signals only stop the process |
| Polling missed fast USB swaps | Event-driven netlink; reacts on the kernel's own announcement |
| Destructive action enabled by a plain boolean | Distinctly-named opt-in key + typed TUI confirmation |
| Broken first-run config copy | Idempotent `postinst` installs the default config only if absent |
| `os.system` string concatenation | No shell strings; responders act via typed calls |
| Python 2/3 straddling, runtime fragility | Single static Rust binary; no interpreter |
| Silent parse failure → empty device list → no protection | Sensors surface parse failures; the system fails loud |

---

## Documentation

| Document | Purpose |
|---|---|
| [`PROJECT_CHARTER.md`](PROJECT_CHARTER.md) | The single source of truth for **what** v1 is, what it is not, and **why**. |
| [`CLAUDE.md`](CLAUDE.md) | The source of truth for **how** the codebase is built — invariants, phases, conventions, review process. |
| [`config.example.toml`](config.example.toml) | A fully-commented reference configuration. |

If the charter and `CLAUDE.md` ever disagree, the charter wins.

---

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE) and the `license` field in
[`Cargo.toml`](Cargo.toml).
