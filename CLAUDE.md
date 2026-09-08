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

## How we work

**Division of labour is fixed:**

- **Claude writes code and guides.** It never installs toolchains or packages,
  never runs builds, tests, the daemon, `cargo`, `rustup`, `systemctl`, or any
  other program, and never touches real hardware. It produces source, configs,
  docs, and step-by-step instructions.
- **The human runs everything.** Installing the toolchain, compiling, running
  tests, exercising the daemon, plugging/unplugging devices, and reporting
  results back. When a step needs verification, Claude writes the exact commands
  to paste and waits for the output.
- This constraint also binds Claude's subagents — a review agent inspects source
  and `git` state only; it does not build or run anything either.
- Claude may still *read* files, search the tree, and inspect `git` history.

If a task genuinely cannot progress without something being run, Claude stops and
hands the human a precise command plus what to look for in the result.

**Claude is an invisible contributor.**

- No "Claude", "Claude Code", "AI-generated", or co-author trailers anywhere —
  not in source comments, not in commit messages, not in PR/release text, not in
  docs. The human is the sole author of record on every commit and publish.
- Commit messages Claude drafts for the human to use carry no attribution
  trailer and no tool branding.
- Assistant working files are git-ignored (see `.gitignore`): the `.claude/`
  tree, `CLAUDE.local.md`, `CLAUDE.*.md`, agent configs, MCP configs, and
  similar. **The only tracked assistant-facing files are `CLAUDE.md` and
  `PROJECT_CHARTER.md`** — those two are project documentation and belong in
  history. If a new assistant file type appears, add it to `.gitignore`.

## Review agents

Non-trivial changes get a review pass from the relevant subagent(s) before the
change is considered done. They live in `~/.claude/agents/`. Each is read-only
(source + `git` inspection, no building or running) and reports findings rather
than editing.

| Agent | Owns | Invoke when a change touches… |
|---|---|---|
| `security-auditor` | Invariants 3, 4, 6, 8. Privilege, capabilities, socket ownership/mode, `unsafe`, untrusted-input parsing, no shell strings, no network/telemetry, dangerous opt-in naming. | responders, control socket, netlink parsing, config of destructive actions, anything with `unsafe` or syscalls |
| `kill-path-reliability` | Invariants 1, 2, 5, 7. Kill path never blocked or chained, fail-closed on bad config, disarm-only-via-socket, sensors surface errors instead of going quiet. | policy engine, responder fan-out, arming/disarming, signal handling, sensor error paths |
| `code-quality` | Rust idiom, the learning-codebase clarity bias, no `unwrap()`/`expect()` in runtime paths, `thiserror`/`anyhow` split, `tracing` on decisions, test coverage incl. rejection cases. | any Rust source |
| `tui-ux` | ratatui interaction and layout, clarity of armed/disarmed state, the fenced `DESTROY` screen, keybinding sanity, terminal-resize and no-color behaviour, crash-safety of the client. | anything in `killbill-tui/` (Phase 2) |

`security-auditor` and `kill-path-reliability` overlap by design — for the kill
path and destructive config, run both.

---

## Current state

**Phase 1 steps 1–7 are committed and code-complete.** Steps 1–4 landed in
`c5ec882`; steps 5–7 (USB sensor, control server, `killbillctl`) landed on the
`phase-2-tui` branch after a full read-only audit and three rounds of fixes.

**The review gate is green.** `security-auditor`, `kill-path-reliability` and
`code-quality` were each run against the final tree as a sign-off gate (not a
delta review) and all three returned PASS. `cargo fmt`/`clippy -D warnings`/
`cargo test --workspace` are clean (161 tests).

Findings deliberately **deferred** — do not re-raise these as new, and do not
"fix" them without reading why they were left:

- *Phase 2 (TUI).* `killbill-tui/src/ui/devices.rs` renders `label`/`serial`
  through `Span::raw` without `sanitize_device_string`. Inert today (the parser
  sanitizes at source and `label` is always `None` in v1) but it is the one
  consumer that does not re-sanitize. Its `client.rs` also reuses one command
  connection while the daemon closes after a single reply — every second command
  fails — and has no socket timeouts, no `config_stale` in the status band, and a
  stale armed-state cache on disconnect. Its `MAX_MSG` (128 KiB) claims in a
  comment to mirror `killbillctl` (64 KiB); it does not.
- *Phase 2 (protocol).* An armed **dry-run** kill broadcasts nothing to
  subscribers, so a client watching a dry-run daemon sees a device appear and
  then silence. Needs a protocol-visible event.
- *Phase 3.* `killbilld.service` needs `SendSIGKILL=no` (or a long
  `TimeoutStopSec`) or systemd will kill a daemon deliberately parked on
  `kill_in_flight`. And `bind_listener` should refuse to start when the socket's
  parent directory is group- or other-writable: mode and ownership are set by
  path, not fd, so a non-`/run` `--socket` there is a symlink-swap window.
- *Noted, not fixed.* An allowed device event while armed logs at `debug!`,
  below the default journal level. Device-string truncation at
  `MAX_DEVICE_STRING` is identity-lossy — acceptable because `usb_id`, not the
  serial, is what policy keys on.
- *Future idea, not committed.* `killbilld` runs as an ordinary `SCHED_OTHER`
  process — no real-time scheduling priority (`SCHED_FIFO`/`SCHED_RR`), no
  `mlockall`. Invariant 1's "sacred" guarantee is a software-architecture
  guarantee (no responder blocks another, nothing does I/O on the kill path) —
  it is not a kernel scheduling guarantee against external interference (e.g. a
  BadUSB HID device racing a countermanding command against `dispatch`). The
  step 0.6 hardware test showed kernel-enumeration-to-power-cut well under a
  second in practice, but there is no scheduling floor under that number. One
  day: elevate the core/responder threads to `SCHED_FIFO` (plus `mlockall` to
  remove page-fault latency) to drive the window toward **zero** lag, not
  merely a low one. Any such change touches the sacred kill path directly and
  needs `security-auditor` + `kill-path-reliability` sign-off — do not add ad
  hoc.

**Phase 1's hardware gate passed 2026-09-08 — every exit criterion is now
verified on real hardware**, run directly on this machine (not yet packaged):

- netlink add/remove decisions: confirmed correct across repeated real
  plug/unplug cycles — an unwhitelisted add or remove fires, a whitelisted
  *add* is suppressed, and (by design, see `policy.rs`) a whitelisted
  *remove* still fires every time;
- dry-run reports what would happen and touches nothing: confirmed — every
  unwhitelisted add/remove while `dry_run = true` (and, independently,
  `power_action = "none"`) logged the kill decision it would have taken and
  never reached the poweroff syscall; `killbillctl test` also returned a
  clean "nothing would fire" report for a whitelisted, connected device;
- a real poweroff on an unauthorized event: confirmed — armed, with both
  belts off, an unwhitelisted USB add fired `RB_POWER_OFF` immediately; the
  machine cut power hard (no `sync`/unmount/graceful shutdown, by design),
  corroborated by the next boot's journal ending mid-stream with no
  shutdown-target sequence;
- `killbilld` under systemd: confirmed — start/status/stop lifecycle correct,
  `systemctl stop` sends only `SIGTERM` (`signal=15` in the daemon's own log,
  systemd reports "Deactivated successfully", never `failed`), and a stop
  neither persists nor implies disarm (restarting came back `armed: no`
  purely because `armed_at_boot = false`, not because anything remembered a
  prior armed state);
- the socket permission check the security pass specifically asked for:
  `stat -c '%A %U %G %F' /run/killbilld*.sock` printed exactly
  `srw-rw---- root root socket`, confirmed under both a manual launch and
  under systemd.

One packaging-relevant finding from this run: SELinux (`Enforcing` on this
Fedora box) denies `init_t` (the systemd service domain) `execute` on a binary
labeled `user_home_t` — a hand-copied binary under `/home` cannot be exec'd by
a systemd unit (`status=203/EXEC`, confirmed via `ausearch -m avc`). Phase 3's
`.rpm`/`.deb` install to a conventional path and should pick up a correct label
automatically, but verify this on the packaged install rather than assuming
it — never point a unit's `ExecStart` at a path under a user's home directory.

**Phase 1 is done.** Phase 2 is now the active phase.

**Phase 2 is formally underway** — `killbill-tui/` is a ratatui skeleton on the
same branch, started before the hardware gate passed but now in correct phase
order. Its known defects are the Phase 2 list above.

Cargo workspace:

- `killbill-proto` — `SensorEvent`/`Action`/`KillReason` vocabularies, the
  `Command`/`Reply`/`Event` control protocol, and a length-prefixed JSON frame
  codec. `#![forbid(unsafe_code)]`.
- `killbilld` (lib) — `config` (TOML load + fail-closed `validate` that collects
  every error; rejects `lock_screen_first = true`, see charter §13.4), `policy`
  (the pure `decide` fn + its decision table), `device_table`, and `responder`
  (`Responder` trait, thread-per-responder `dispatch` with inline+panic-caught
  spawn-failure fallback, `preflight` arm-time capability check, `logger`,
  `poweroff` via `nix::sys::reboot`, `luks-destroy` logging stub).
  `#![deny(unsafe_code)]`. `killbilld`/`killbillctl` binaries are real (steps
  6–7), not stubs.
- `sensor` (step 5) — `Sensor` trait (Seam 1) + `spawn`/`SensorHandle` thread
  wrapper + `StopFlag`; the trait emits a `SensorMessage` stream (`Started` once
  the source is open, then `Event` / `EventsLost`). `sensor::uevent` is a
  crate-private pure `parse_uevent(&[u8]) -> Result<Option<SensorEvent>, _>`
  (mirrors `policy::decide`), exhaustively tested against captured-shape byte
  payloads; `UsbNetlinkSensor` opens `NETLINK_KOBJECT_UEVENT` group 1 via `nix`
  (no `unsafe`, **no capability** — `NL_CFG_F_NONROOT_RECV`; `CAP_NET_ADMIN`
  must NOT be granted, it would allow forging uevents), `recvfrom` + drop any
  datagram whose source `pid != 0`, `SO_RCVBUF` bump; `#[cfg(target_os =
  "linux")]` with a refuse-to-arm stub elsewhere. Fails loud (invariant 7):
  parse errors log + keep listening, a USB device with no readable id emits
  `usb_id: None` so policy fails closed, a dead socket ends `run` with `Err`,
  a receive-buffer overflow (`ENOBUFS`) surfaces as `EventsLost`.
- `config_store` (step 6) — `RawConfig` gained `Serialize`; atomic write-back
  (temp `create_new` at 0600 / existing mode preserved, `fsync`, `rename`, dir
  `fsync`) since the daemon owns config writes (charter §9).
- `control` (step 6, `#[cfg(unix)]`) — `SOCK_SEQPACKET` server at
  `/run/killbilld.sock`, root-owned, mode 0660 set **before** `listen`, `umask`
  around `bind`, `is_socket()`-guarded unlink + a `connect()` probe: a leftover
  socket is unlinked only on `ECONNREFUSED` (nothing listening) — a live daemon
  or any probe error it can't classify aborts startup (fail closed). The
  listener is bound by `control::bind_listener` on the daemon's main thread
  *before* the core loop starts, so a bind failure is fatal, never a run with no
  control socket (invariant 5). Thread per connection; each reads the peer's
  `SO_PEERCRED`, turns its request into a `ControlRequest`, and hands it to the
  core — connection threads never touch state. Privileged commands
  (`Arm`/`Disarm`/`Whitelist*`/`ReloadConfig`/`RunDryRun`) require `uid 0`.
- `daemon` (step 6, `#[cfg(unix)]`) — `run()` wires sensor → core → responders +
  control server + a dedicated `config-writer` thread + a `signal-hook` thread.
  **One authority thread** owns all mutable state (`Core`): sensor events and
  control requests arrive on one channel, handled serially, no locks. `dispatch`
  is called inline on that thread (the responder contract is trivially
  satisfied). **All config file I/O is off-loaded to the `config-writer` thread**
  so `fsync` never sits on the kill path (`Core` validates + swaps in memory
  only). Invalid config → runs but won't arm; dead sensor → `sensor_ok=false`
  (it starts `false`), `Event::SensorStopped`, process exits non-zero for a
  supervisor restart, armed state untouched (only `Disarm` disarms — invariant
  5); sensor *restart* → also a gap: sets sticky `events_lost` + clears any
  pending boot arm, so the daemon won't re-arm across a restart without an
  operator restart; events lost → sticky `events_lost`, `on_sensor_gap` decides
  warn-vs-kill; a synthetic (`SYNTH_UUID`) *add* is recorded-not-acted, a
  synthetic *remove* still fires — nothing re-announces a device that is gone,
  and an unplug is the event this tool exists to catch; kill in flight at
  shutdown or on panic → process parks, never exits.
  **Every gap notification goes through `Core::maybe_dispatch_gap_kill`**, which
  runs kill-path-first and *above* the sticky-`events_lost` early return (so a
  gap seen under `warn`, or while disarmed, cannot poison a later one that does
  warrant a kill), latched against a notification burst, and the latch is cleared
  on any config swap so a post-gap `reload` re-enables it. `on_sensor_event`
  dispatches immediately after `policy::decide` — the device-table update
  allocates and is deliberately sequenced *after* it. The shutdown drain routes
  **every** sensor variant, not just device events: a queued `SensorRestarting`
  or `SensorEnded` is a gap, and a signal must never be a way to skip a pending
  kill (invariant 5).
- `killbilld` bin — `main.rs`: two flags (`--config`, `--socket`), a
  `tracing-appender` non-blocking stderr sink, hand off to `daemon::run`.
- `killbillctl` (step 7) — `clap` subcommands (`status`, `devices`, `arm`,
  `disarm`, `test`, `reload`, `whitelist list|add|remove`, `events`); a pure
  protocol client over the SEQPACKET socket. `#![forbid(unsafe_code)]`.
- Protocol additions (all additive to `#[non_exhaustive]` types, charter §8
  updated): `Command::WhitelistList`, `Reply::Whitelist`, `Reply::DryRun`,
  `Event::SensorStopped`, `Event::EventsLost`, `StatusPayload.sensor_ok` +
  `StatusPayload.events_lost` (both `#[serde(default)]`), `KillReason::SensorGap`,
  `sanitize_device_string` (one shared copy for every wire end; also applied in
  `sensor::uevent` so `serial` is safe before it enters a `SensorEvent`). It is
  an **allowlist** — printable ASCII plus space, everything else → U+FFFD, capped
  at `MAX_DEVICE_STRING`. A denylist was tried and rejected: enumerating hostile
  codepoints (C0/C1, Trojan-Source bidi, zero-width, tag chars, variation
  selectors, combining-mark stacking) cannot be completed, and missing one is a
  silent hole. Do not "fix" this back into a denylist.
  One frame-size limit — `MAX_CONTROL_FRAME` (64 KiB) is the whole-frame ceiling
  every reader allocates; `encode`/`decode` bound the JSON body by `MAX_BODY_LEN`
  (`= MAX_CONTROL_FRAME - 4`) so nothing encodable is unreadable. An unsendable
  reply comes back as `Reply::Error`, not a dropped frame.
- Config addition: `response.on_sensor_gap = "warn" | "kill"` (default `warn`),
  parsed to `config::SensorGapAction`.
- `config.example.toml` at the repo root mirrors charter §9 and is exercised by
  a test.

The `decide` v1 rule set is documented at the top of
[killbilld/src/policy.rs](killbilld/src/policy.rs); the kill-path contracts the
sensor/server wiring must honour are at the top of
[killbilld/src/responder/mod.rs](killbilld/src/responder/mod.rs) (core logs the
decision *after* `dispatch`; shutdown honours `kill_in_flight`; arm calls
`preflight`; `Action` is never queued).

**Not built for v1 (owed to Phase 2):** startup sysfs enumeration of already-
connected USB devices — `ListDevices` / `test` currently see only devices added
since the daemon started. Config comments are lost on daemon-side writes.

**Open:** the policy `DeviceTable` pre-event `+1` convention (keep vs flip to
post-event) is still undecided — it did not block steps 5–7 and does not block
the hardware run.

**Owed to Phase 3 (from the sign-off gate, not yet done):** `killbilld.service`
needs `SendSIGKILL=no` or a long `TimeoutStopSec`, or systemd will `SIGKILL` a
daemon deliberately parked on `kill_in_flight` (validated as necessary via a
local test unit in the step 0.5 hardware-gate run — carry `KillSignal=SIGTERM`
+ `SendSIGKILL=no` into the packaged unit); and `bind_listener` should refuse
to start if the socket's parent directory is group- or other-writable (socket
mode/ownership are set by path, not fd, so a non-`/run` `--socket` in a writable
directory is a symlink-swap window).

**Platform note:** development is now on Fedora Linux (the earlier macOS note is
retired). Still write platform-neutral code — types, config, policy, protocol,
CLI, TUI compile and test anywhere — and `#[cfg(target_os = "linux")]`-gate only
the two genuinely Linux-bound pieces (the netlink sensor, the poweroff
responder) with non-Linux stub fallbacks. Real netlink/poweroff verification now
happens directly on this machine.

**Toolchain:** pinned by [rust-toolchain.toml](rust-toolchain.toml) (stable +
rustfmt + clippy). The user installs and runs it; see "How we work".

---

## Phases

Three phases, in order. Do not start a phase before the previous one's exit
criteria are met; that ordering is the point — the backend has to be trustworthy
before anything renders it, and it ships only once it's been proven on real
hardware.

### Phase 1 — Backend (done — hardware-verified 2026-09-08)

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

### Phase 2 — TUI (current)

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

- **Rust 2021+, stable toolchain.** No async runtime: the daemon is `std::thread`
  + `std::sync::mpsc` throughout (charter §13.1 — recorded there). Each concurrent
  piece is one blocking loop; the kill path must not depend on an executor.
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
