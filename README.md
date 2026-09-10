<div align="center">

# killbill-rs

**An event-driven USB kill switch for machines that must not be seized unlocked.**

[![Language: Rust](https://img.shields.io/badge/language-Rust_2021-orange.svg)](https://www.rust-lang.org/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux_%2B_systemd-blue.svg)](#platform-support)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-green.svg)](#license)
[![Release: v0.1.0](https://img.shields.io/badge/release-v0.1.0-green.svg)](#status)

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

## Status

**v0.1.0 — first public release**, for distribution and testing. The daemon,
CLI, and TUI are feature-complete for v1; the netlink add/remove path, dry-run,
`killbilld` under systemd, and a real poweroff on an unauthorized event are all
verified on hardware. `luks_destroy` ships as a stub (see below). Report issues
privately per [`SECURITY.md`](SECURITY.md).

---

## Table of contents

- [Why a rewrite](#why-a-rewrite)
- [How it works](#how-it-works)
- [Install](#install)
- [First run](#first-run)
- [Architecture](#architecture)
- [The non-negotiable invariants](#the-non-negotiable-invariants)
- [Components](#components)
- [`killbillctl`](#killbillctl)
- [The TUI](#the-tui)
- [Configuration](#configuration)
- [The decision table](#the-decision-table)
- [Control protocol](#control-protocol)
- [LUKS header destruction (fenced, stub-only)](#luks-header-destruction-fenced-stub-only)
- [Security model](#security-model)
- [Uninstall](#uninstall)
- [Repository layout](#repository-layout)
- [Building and testing](#building-and-testing)
- [Platform support](#platform-support)
- [Out of scope for v1](#out-of-scope-for-v1)
- [Contributing](#contributing)
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
                        │ /run/killbilld  │──► killbill-tui           
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

## Install

Every install path **enables the daemon but leaves it disarmed**, and installs
the default config only if `/etc/killbill/config.toml` is absent. A fresh
install can never lock you out.

### From a package

```bash
# Debian / Ubuntu
sudo apt install ./killbill-rs_0.1.0_amd64.deb

# Fedora / RHEL
sudo dnf install ./killbill-rs-0.1.0-1.x86_64.rpm

# Arch (AUR)
git clone https://aur.archlinux.org/killbill-rs.git && cd killbill-rs && makepkg -si
```

### From the release tarball

```bash
tar xzf killbill-rs-0.1.0-x86_64-linux-musl.tar.gz
sudo ./install.sh                      # or: sudo ./install.sh --prefix /opt/killbill
```

### From source

```bash
cargo build --release --workspace
sudo packaging/install.sh --from-build
```

### Verifying downloads

Release artifacts are signed with [minisign](https://jedisct1.github.io/minisign/).
The public key is published in the GitHub release notes and at
`https://github.com/unrealthind/killbill-rs`.

```bash
minisign -Vm SHA256SUMS -P <published-public-key>
sha256sum -c SHA256SUMS
```

> [!NOTE]
> A package **upgrade** restarts the daemon, and a restart always comes back
> **disarmed** (armed state is deliberately never persisted). The maintainer
> scripts warn when this happens — run `sudo killbillctl arm` again afterward.

---

## First run

```bash
# 1. See the daemon (enabled, disarmed, empty whitelist)
killbillctl status

# 2. Whitelist the devices you keep plugged in — vendor:product in lowercase hex
lsusb
sudo killbillctl whitelist add 1050:0407 --label "YubiKey 5C" --max-count 1
#    ...or plug the device in and press Enter on it in `killbill-tui`.

# 3. Check what a kill decision would look like right now — touches nothing
killbillctl test

# 4. Arm in dry-run first: decisions are logged, no poweroff
sudo killbillctl config set dry-run on
sudo killbillctl arm
#    unplug something, watch `journalctl -u killbilld -f` and `killbillctl events`

# 5. Go live
sudo killbillctl config set dry-run off
sudo killbillctl arm
```

Disarm is always `sudo killbillctl disarm` — never a signal.

> **`max_count` and already-connected devices.** `killbilld` counts only the
> `add` events it has seen since it started; it does not enumerate USB devices
> that were already plugged in at startup (a v1 limitation). A device present
> before the daemon started counts as zero against its `max_count`. To seed the
> count table, run `udevadm trigger --action=add --subsystem-match=usb` **while
> disarmed** — the synthetic `add` events are recorded and never fire. Don't run
> it while armed under `on_sensor_gap = "kill"`: the burst can overflow the
> netlink buffer and trip a real `SensorGap` kill.

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
| **`killbill-tui`** | A ratatui client — live device list, plug-and-whitelist, armed toggle, dry-run, event log, config inspector, and the fenced destruction screen. A **separate binary** so a UI crash can never touch protection. | any user with socket access |

---

## `killbillctl`

Everything the daemon can do, headless. Read-only commands work as any user with
socket access; state changes require root.

| Command | What it does |
|---|---|
| `killbillctl status` | armed? sensor healthy? config valid? whitelist / device counts |
| `killbillctl devices` | devices the daemon is currently tracking |
| `sudo killbillctl arm` / `disarm` | flip protection — both logged with the calling peer; disarm is socket-only, never a signal |
| `killbillctl test` | dry-run over the connected devices: report what would fire, touch nothing |
| `killbillctl whitelist list` | the active whitelist, connected/absent marked |
| `sudo killbillctl whitelist add 1050:0407 --label "YubiKey 5C" --max-count 1` | allow a device while armed |
| `sudo killbillctl whitelist remove 1050:0407` | remove an entry |
| `killbillctl config show` | the running config |
| `sudo killbillctl config set dry-run on\|off` | toggle dry-run (immediate) |
| `sudo killbillctl config set power-action poweroff\|halt\|none` | change the power action (immediate) |
| `sudo killbillctl config set armed-at-boot on\|off` | arm automatically at daemon start |
| `sudo killbillctl config set on-sensor-gap warn\|kill` | what to do if the sensor loses events |
| `sudo killbillctl config set sensors usb` | sensor set — **applied at daemon start**, restart required |
| `sudo killbillctl luks engage on\|off` | flip the runtime LUKS-destroy toggle (v1: records intent, wipes nothing) |
| `sudo killbillctl reload` | re-read and re-validate the config file; a bad file is rejected, the running config kept |
| `killbillctl events [--follow]` | the daemon's event stream; without `--follow`, drains the backlog and exits |

---

## The TUI

`killbill-tui` is a full-screen client. It never changes the daemon's armed
state on its own, and **killing it — even `kill -9` — leaves the daemon exactly
as armed as it was**.

| Key | Action |
|---|---|
| `↑` / `↓` (`k` / `j`) | move the selection, or scroll |
| `Enter` | activate the selection / confirm a modal |
| `Esc` | close a modal, else back to Devices |
| `m` | main menu (Devices · Whitelist · Dry-run · Settings · Event log · Config · LUKS destroy · Arm · Disarm · Reload · Help · Quit) |
| `?` | help screen |
| `r` | refresh, or retry while the daemon is unreachable |
| `p` | on the event log: freeze / resume following |
| `q` or `Ctrl-C` | quit (never disarms) |

Arm, Disarm, Reload, and any settings change that *lowers* protection while
armed each go through a confirm step. The LUKS-destroy screen is visually
distinct, names the exact target device, and requires typing `DESTROY` then `y`
— any other key cancels.

The armed state is shown by a **glyph and a word**, not colour alone, so it
survives `NO_COLOR` and a monochrome terminal.

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

In **v1 this is a stub.** The config schema, validation, dry-run message, and the TUI screen are all real and correct. The header wipe itself is
**deliberately not implemented** — there is no live footgun during development.

Enabling it requires, all at once:

- An explicit block that is **absent from the default config**.
- The spelled-out acknowledgment key `i_understand_this_is_irreversible = true`
  — never a generic `enabled`.
- A `target_header` that resolves to a real block device under `/dev/`.
- A visually-distinct TUI screen that names the exact target device and
  requires typing `DESTROY`, then `y`.

Dry-run always logs `would destroy LUKS header on /dev/…` and touches nothing.

---

## Security model

The full statement is [`SECURITY.md`](SECURITY.md). In short:

- **Threat model** — physical seizure or tampering of one person's own,
  LUKS-encrypted laptop. Not a remote-attacker or fleet tool.
- **Privilege** — the daemon runs as root with exactly one capability,
  `CAP_SYS_BOOT` (for `reboot(2)`). It explicitly does **not** hold
  `CAP_NET_ADMIN` — receiving kernel uevents needs no capability, and holding it
  would let anything sharing the daemon's user forge them. The systemd unit adds
  `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome`, seccomp, and
  `RestrictAddressFamilies=AF_UNIX AF_NETLINK`.
- **The socket** — `0660 root:root`; "who may talk to the daemon" is a
  filesystem question. The daemon refuses to start if the socket's parent
  directory is writable by non-root.
- **Fail closed** — an invalid config disables protection *loudly*: the daemon
  runs but refuses to arm until the config is fixed and reloaded.
- **The kill path is never blocked** — logging, config I/O, and connected UIs
  are all off it. Once a kill decision is made, nothing delays the poweroff.
- **No network, no telemetry** — ever. The only IPC is the local Unix socket.
- **`luks_destroy` is a stub in v1** — "it didn't wipe the header" is not a
  vulnerability.

---

## Uninstall

```bash
sudo apt remove killbill-rs          # or: dnf remove / pacman -Rns
sudo ./uninstall.sh                  # for an install.sh install (reads its manifest)
```

Removal stops and disables the daemon and leaves `/etc/killbill/` in place. A
`.deb` **purge** (`apt purge`) also removes the config directory.

---

## Repository layout

```
killbill-rs/
├── Cargo.toml                  workspace: killbill-proto, killbilld, killbillctl, killbill-tui
├── rust-toolchain.toml         pinned: stable + rustfmt + clippy
├── config.example.toml         fully-commented reference config (mirrors charter §9)
├── PROJECT_CHARTER.md          source of truth for WHAT and WHY
├── CONTRIBUTING.md · SECURITY.md · CHANGELOG.md · docs/DESIGN-NOTES.md
├── packaging/                  systemd unit, .deb/.rpm/AUR metadata, install.sh, man pages
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
└── killbill-tui/               the ratatui client — #![forbid(unsafe_code)]
    └── src/
        ├── app.rs              the reducer: a cache of daemon state + the modal state machine
        ├── client.rs           the transport (fresh connection per command) + a Client trait
        ├── input.rs            keys → intents
        └── ui/                 one module per screen + the persistent status band
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

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) — building and testing (rejection cases
carry the weight), the non-negotiable invariants, the three-seam architecture,
and how to propose a sensor or responder without touching the core.

| Document | Purpose |
|---|---|
| [`PROJECT_CHARTER.md`](PROJECT_CHARTER.md) | Source of truth for **what** v1 is, what it is not, and **why**. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to build, test, and extend the codebase. |
| [`docs/DESIGN-NOTES.md`](docs/DESIGN-NOTES.md) | Deeper rationale for the non-obvious decisions. |
| [`SECURITY.md`](SECURITY.md) | Threat model, scope, and private reporting. |
| [`CHANGELOG.md`](CHANGELOG.md) | What ships in each release. |
| [`config.example.toml`](config.example.toml) | A fully-commented reference configuration. |

---

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE) and the `license` field in
[`Cargo.toml`](Cargo.toml).
