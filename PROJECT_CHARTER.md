# Project Charter — killbill-rs

**Document status:** Draft v1 — guiding document for the engineering team
**Last updated:** 2026-09-06
**Owner:** Project lead
**Audience:** Programmers building v1, and anyone extending the tool later

---

## 1. Purpose

Build a modern, event-driven successor to the original `usbkill` Python tool. The program monitors USB device add/remove events and, when an unauthorized change is detected while armed, powers off the machine quickly so that a LUKS-encrypted disk re-locks and its contents become inaccessible.

This is a ground-up rewrite, not a port. The original's polling loop, embedded interpreter fragility, silent-failure modes, and destructive-by-accident behavior are explicitly discarded. This charter is the single source of truth for what v1 is, what it is not, and why.

The project is also a **learning-oriented codebase**. Where a clear, teachable design conflicts with maximum hardening, favor clarity — but never at the cost of the correctness of the kill path itself.

---

## 2. Target user & threat model

**User:** A single high-risk individual (e.g. journalist, activist, researcher) protecting their own machine against physical seizure or tampering.

**Implications that shape the whole design:**

- On-device only. No network, no telemetry, no central management, no fleet features.
- The user is root on their own machine and accepts the risk of destructive response.
- One user, one authority. No multi-tenant privilege model is needed.
- Full-disk encryption (LUKS) is **assumed to be in place**. The tool's job is to cut power so the disk re-locks; it is not responsible for encrypting the disk.

**Non-users / out of scope:** Managed corporate fleets, audited endpoints, anything requiring remote configuration or logging.

---

## 3. Guiding principles

1. **The kill path is sacred.** Nothing — logging, config quirks, UI state — may be able to prevent or delay a poweroff once a kill decision is made.
2. **Fail closed.** An invalid config disarms the tool loudly; it never fires blindly or guesses intent.
3. **Dangerous features require deliberate, unambiguous opt-in.** No destructive action can be enabled by a stray boolean.
4. **Separation of concerns.** Detection, decision, and response are independent stages with clean seams.
5. **Portable and pluggable foundation.** v1 implements USB only, but the architecture must let others add sensors and responders without touching the core.
6. **One authority for state.** The daemon owns configuration and armed-state; UIs are clients, never competing sources of truth.
7. **Prefer clarity for a learning codebase**, except in the kill path, which prefers correctness above all.

---

## 4. Language & platform decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | **Rust** | Single static binary, no runtime to install, memory safety for a root daemon operating under adversarial physical access. |
| Detection foundation | **Kernel netlink uevent socket** (`NETLINK_KOBJECT_UEVENT`) | Event-driven, millisecond reaction, near-zero idle CPU, closes the fast-swap evasion gap. Interface is ~20 years stable, so kernel version is a non-constraint. |
| Init / supervision | **systemd** | Restart-on-crash, boot-time arming, clean status, hardening directives. Non-systemd init is out of scope for v1. |
| Async runtime | **None** — `std::thread` + channels (was: Tokio recommended) | Each concurrent piece is one blocking loop (responder fan-out, netlink `recv`, control server); a thread each needs no executor. The kill path must not depend on a runtime being healthy. See §13.1 for the full rationale. |
| Config format | **TOML** | Typed, human-editable, Rust-ecosystem default. Replaces the original's ini-with-embedded-JSON. |
| TUI toolkit | **ratatui** | Actively maintained, mature. |
| Control transport | **Unix domain socket**, `SOCK_SEQPACKET` | Local-only, permission-controlled, no network exposure. |

**Kernel floor:** Not feature-driven. Effectively "whatever runs a current systemd" — any mainstream distro from the last several years. Build against the stable, decades-old netlink interface so kernel version never becomes a compatibility concern.

---

## 5. Response model

**Core response (v1):** Fast, reliable **poweroff**, assuming LUKS. The destructive side of the tool exists only to cut power so the encrypted disk re-locks. No file shredding. No RAM/swap wiping. These were the original's least reliable features on modern SSDs and are deliberately dropped.

**Option B — LUKS header destruction (scaffolded, fenced off, NOT live in v1):**

Because LUKS is assumed, the correct "destroy data" primitive is not per-file shredding but **destroying the LUKS header/keyslot**, which renders the whole disk unrecoverable in milliseconds and is reliable on flash storage.

This feature is **fenced behind deliberate friction** so it cannot be armed by accident:

- **Off by default**, and absent from the default config entirely.
- Cannot be enabled implicitly. Requires a distinctly-named, unambiguous acknowledgment key in config (e.g. `i_understand_this_is_irreversible = true`), not a generic `enabled = true`.
- In the TUI it lives on a **separate, visually-distinct warning screen** and requires typing a confirmation word (e.g. `DESTROY`), and it names the exact target device so the user can verify it is real.
- **Daemon refuses to arm** if the destruction target is invalid or does not resolve to a real LUKS device (fail-closed).
- **Dry-run treats it specially:** always logs "would destroy LUKS header on `/dev/…`" and never touches the header.

**v1 ships this as a stub.** The config schema, validation, TUI screen, and dry-run messaging are all present and correct; the actual header-wipe is deliberately not implemented, so there is no live footgun during development. It can be flipped on in a later version.

---

## 6. Architecture overview

The founding decision: **separate detection from decision from response.** The original fused all three into one polling loop, which is why it could not be extended and why a logging failure could block a shutdown.

```
  SENSORS          →   CORE (decision)   →   RESPONDERS
  (pluggable)          (policy engine)       (pluggable)
      │                     │                     │
  USB sensor ──┐            │                ┌── poweroff responder
  [lid]     ──┤            │                ├── luks-destroy responder (fenced/stub)
  [ac-power]──┤──► event ──►  policy  ──► action ──┤── logger (as a responder)
  [bluetooth]─┘   stream       engine     decision └── [alert] [custom]
                                 │
                                 ├──────────► CONTROL SOCKET ──► TUI / CLI
                                 │            (query + subscribe + command)
                                 └── config (owned by daemon)
```

Bracketed `[…]` items are **not built in v1** — they are what the pluggable abstraction permits. Only the USB sensor and the poweroff + logger responders are implemented.

### The three seams

**Seam 1 — the `Sensor` trait (input).** A sensor produces tamper-relevant events. Contract: "start, emit normalized `SensorEvent`s onto a channel until stopped." It knows nothing about policy or response. The USB sensor opens the netlink uevent socket, parses add/remove messages into `SensorEvent { source, kind, identity, raw }`, and pushes them onto the shared channel. A future lid sensor emits its own events onto the *same* channel; the core treats them identically.

**Seam 2 — the `Responder` trait (output).** A responder receives an `Action` and acts. `poweroff` cuts power; `logger` records; `luks-destroy` (stub) wipes the header. **The logger is just another responder, not a prerequisite** — responders are independent subscribers to the action decision, so a logging failure can never block the poweroff. This directly fixes a real bug in the original.

**Seam 3 — the control protocol (the TUI's window in).** The request/reply + event-stream protocol over the Unix socket. Because v1 has a live TUI, this is a first-class public interface, not an afterthought.

The normalized `SensorEvent` and `Action` vocabularies in the middle are the entire secret to portability: sensors and responders share common types, so the policy engine is decoupled from both ends.

---

## 7. Components

### 7.1 `killbilld` — the daemon (root, systemd-managed)

The heart of the system. Responsibilities:

- Owns and loads config; single source of truth for policy and armed-state.
- Instantiates enabled sensors and starts them.
- **Policy engine:** for each `SensorEvent`, decides against the whitelist/policy whether it warrants an `Action`; if so, dispatches to all responders.
- **Control server:** accepts TUI/CLI connections; answers queries, streams events, executes commands.
- **Event fan-out:** the raw sensor stream feeds two consumers — the policy engine *and* any subscribed control clients — so the TUI sees exactly what the daemon sees.

**Internal shape (recommended):** an async runtime with a few tasks over channels: sensor tasks → central event bus → {policy task, control-server broadcast}. Testable, and where much of the concurrency learning lives.

### 7.2 `killbill-tui` — the live configurator

A **separate binary** so a UI crash can never touch protection. Connects to the control socket and provides:

- Live view of currently-connected USB devices.
- **Plug-and-whitelist:** plug a device, it appears highlighted as new/unknown, press a key to add it to the whitelist (the daemon performs the write).
- Show and toggle armed/disarmed.
- Run dry-run and display what *would* happen.
- The fenced-off destruction screen with its typed-confirmation guard rail (§5).

### 7.3 `killbillctl` — the CLI

The dependable, scriptable, headless-friendly path. Everything the TUI can do, the CLI can do — the TUI is a nicety on the same protocol, never the only way in.

Commands: `status`, `arm`, `disarm`, `test` (dry-run), `whitelist add|remove|list`, `reload`, `config show|set <field> <value>`, `luks engage <on|off>`, `events [--follow]`.

---

## 8. Control protocol

One `SOCK_SEQPACKET` Unix socket at `/run/killbilld.sock`. Three traffic types:

- **Commands (client → daemon, expect reply):** `GetStatus`, `ListDevices`, `Arm`, `Disarm`, `WhitelistAdd(entry)` (upsert by id), `WhitelistRemove(id)`, `WhitelistList`, `RunDryRun`, `ReloadConfig`, `GetConfig`, `ConfigSet(change)`, `SetLuksDestroyEngaged(bool)`, `Subscribe`.
- **Replies (daemon → client):** `Ok`, `Status(payload)`, `Devices(list)`, `Whitelist(entries)`, `DryRun(reasons)`, `Config(payload)`, `Error(message)`.
- **Event stream (daemon → client, unsolicited, to subscribers):** `DeviceAdded`, `DeviceRemoved`, `Armed`, `Disarmed`, `WouldKill(reason)` (dry-run — now also broadcast for an armed dry-run kill on the normal event path, not just `RunDryRun`), `SensorStopped` (the USB sensor thread died — daemon is exiting non-zero for a supervisor restart), `EventsLost` (the kernel receive buffer overflowed and add/remove events were dropped), `WhitelistChanged`, `ConfigChanged`, `ReloadFailed(reason)`. Every event on the wire is wrapped in a `StreamEvent { at, event }` envelope (`at` is an RFC 3339 UTC timestamp) — a new subscriber's ack is followed by its event backlog (the last 200 broadcasts, oldest first) replayed as individual `StreamEvent` frames, then live ones, both the same frame shape.

`WhitelistList` / `Reply::Whitelist` and `Reply::DryRun` were added in Phase 1 step 6 so `killbillctl whitelist list` and `killbillctl test` (§7.3) work over the protocol rather than reading the file. `StatusPayload` gained `sensor_ok` (false when the USB sensor thread has died) and `events_lost` (sticky once the sensor reports a gap). The `SensorStopped` / `EventsLost` events mirror those. When the sensor is not running, or `events_lost` is set under `on_sensor_gap = "warn"`, the daemon refuses to arm (invariant 7); under `on_sensor_gap = "kill"` a gap fires the power action (`KillReason::SensorGap`). All additive to `#[non_exhaustive]` types.

**Phase 2 step 1 additions.** `GetConfig` answers a read-only `ConfigPayload` snapshot of the *running* (validated) config — never a reflection of a broken on-disk file; `validation_error` carries why they might differ. `ConfigSet(ConfigChange)` changes one field (`DryRun`, `PowerAction`, `ArmedAtBoot`, `Sensors`, `OnSensorGap`) the same way `WhitelistAdd` does: applied to a clone of the raw config, the whole thing re-validated, and only on success written and swapped (invariant 2) — nothing is a partial update. `SetLuksDestroyEngaged(bool)` is `Core`'s own `luks_destroy_engaged` flag, refused unless the running config has an acknowledged `[response.luks_destroy]`. This is deliberately a *second*, purely runtime, opt-in on top of the config-time `i_understand_this_is_irreversible` acknowledgment (invariant 4) — `Action::luks_destroy` requires both, never persisted, and always starts `false` on daemon start. All three commands sit on the closed `requires_root` allow-list (privileged by default) alongside `Arm`/`Disarm`/the whitelist commands, even though `GetConfig` is read-only, because `LuksDestroyInfo::target_header` is as sensitive as anything else gated there.

**Framing:** length-prefixed messages. **Serialization:** serde + JSON for v1 (readable and debuggable for a learning codebase; swappable to a binary codec later without changing the protocol shape).

**Access control:** socket file permissions — mode `0660`, owned by root. "Who can talk to the daemon" is a filesystem question. Sufficient for a single-user personal tool.

**Disarm is a command, never a signal.** This replaces the original's fatal flaw of using catchable `SIGTERM`/`SIGINT`/`SIGQUIT` to disarm. To disarm, a client sends an authenticated `Disarm` over the socket, which is logged. OS signals go back to meaning only "shut down the process."

---

## 9. Configuration

**Location:** `/etc/killbill/config.toml`
**Ownership:** The **daemon owns writes.** The TUI requests changes; the daemon validates and writes them. This guarantees running-state and file never drift, and gives one validation authority.

**Example shape:**

```toml
[general]
armed_at_boot = true

[detection]
# v1: only "usb" is implemented. This list is what makes the sensor layer pluggable.
sensors = ["usb"]

[[whitelist]]
id = "1234:5678"
label = "YubiKey 5C"
max_count = 1

[response]
dry_run = false
power_action = "poweroff"   # poweroff | halt | none
lock_screen_first = false   # v1: must be false; `= true` is rejected (see §13.4)
on_sensor_gap = "warn"      # warn | kill — what to do if the USB sensor drops events

# Fenced-off option B. Absent by default. Requires explicit, unambiguous opt-in.
# [response.luks_destroy]
# i_understand_this_is_irreversible = true
# target_header = "/dev/nvme0n1p3"
```

**Two non-negotiable config rules (carried directly from the review of the original):**

1. **Fail-closed validation.** The daemon refuses to arm on an invalid config — malformed device ID, a `luks_destroy` target that doesn't resolve to a real LUKS device, missing required fields, or any destruction path that resolves to a system directory. A broken config disables protection loudly; it never fires blindly. This is the antidote to the original's `dirname('/etc/usbkill.ini') → /etc` disaster.
2. **The dangerous option cannot be enabled implicitly.** `luks_destroy` requires its distinctly-named acknowledgment key *and* a typed TUI confirmation. Scaffolded in v1; header-wipe is a stub.

**`lock_screen_first` in v1:** rejected at validation when set to `true` — a pre-poweroff screen lock cannot be implemented without either delaying the kill path (invariant 1) or firing-and-forgetting a lock that never completes before power is cut. `false` / absent is valid. Revisit per §13.4.

**`on_sensor_gap` (added Phase 1 step 6 review):** the netlink uevent socket has a bounded kernel receive buffer; a device storm (deliberate or not) can overflow it and the kernel then drops uevents. A dropped add/remove means the daemon's device set is no longer trustworthy — a silent blind spot, which invariant 7 forbids. `warn` (default): surface it in `killbillctl status` (`events_lost`), emit `Event::EventsLost`, and refuse to (re)arm until the daemon is restarted. `kill`: treat the gap as an unauthorized change and fire `power_action` (`KillReason::SensorGap`) — for users who would rather the machine go down than run with a gap. It fires the power action **only**, never `luks_destroy`. Absent → `warn`; an unrecognized value is a hard validation error (fail closed — the daemon never guesses intent).

---

## 10. Packaging & installation

**Artifacts (v0.1.0):** three binaries (`killbilld`, `killbill-tui`, `killbillctl`), a `killbilld.service` systemd unit + a `luks-destroy.conf.example` drop-in, `config.example.toml`, four man pages (`killbilld.8`, `killbillctl.1`, `killbill-tui.1`, `killbill.conf.5`), a static `x86_64` musl tarball with `SHA256SUMS` and `minisign` signatures on the GitHub release.

**Build → package** (all in `packaging/`):
- `.deb` via `cargo-deb` (`[package.metadata.deb]` in `killbilld/Cargo.toml`)
- `.rpm` via `cargo-generate-rpm` (`[package.metadata.generate-rpm]`)
- Arch via an AUR `PKGBUILD` + `killbill-rs.install`
- `install.sh` / `uninstall.sh` as the universal fallback (validates `--prefix` is root-owned and not user-writable — a root unit's `ExecStart` must never point into a writable tree)

The maintainer-script contract lives once in `packaging/scripts/lib.sh` and is inlined verbatim into the `.deb`/`.rpm` scriptlets; `packaging/scripts/check-sync.sh` (CI) fails on drift. `packaging/scripts/check-release.sh` gates the release on a real `PKGBUILD` digest.

**Install / upgrade behavior:**
- Create `/etc/killbill/` and install the default config **only if absent** (idempotent — fixes the original's broken first-run copy). The shipped config has an **empty whitelist**: arming allows nothing until the operator edits it.
- Enable the service but **never auto-arm** — installation can never lock the user out. The install verifies `systemctl start` succeeded and warns loudly (to stderr) if it did not.
- An upgrade restarts the daemon; a restart always returns it **disarmed** (armed state is deliberately not persisted). The scripts warn before the restart if the running daemon is armed.

**systemd unit hardening:**
- `NoNewPrivileges`, `ProtectSystem=full` (not `=strict`: the control socket lives at `/run/killbilld.sock` and `=strict` would mount `/run` read-only — see §13.6), `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any`, seccomp (`@system-service @reboot`, never `~@privileged`).
- `CapabilityBoundingSet=CAP_SYS_BOOT` **only** — nothing else, and explicitly *not* `CAP_NET_ADMIN` (uevent receive needs no capability; holding it would allow forging uevents).
- `KillSignal=SIGTERM` + `SendSIGKILL=no` + `TimeoutStopSec=infinity` so systemd never interrupts an in-progress poweroff (safe because `KILL_IN_FLIGHT` latches only on a real power action — see §13.5).
- `ProtectKernelTunables=no` and **no** `ProcSubset=pid` — both would hide `/proc/sysrq-trigger`, the poweroff responder's last-resort fallback.
- `landlock` (kernel 5.13+) is a future addition, gated so the daemon runs fine without it.

---

## 11. Explicit non-goals for v1

Naming non-goals keeps scope honest:

- **No non-USB sensors.** The abstraction exists; only the USB sensor is implemented.
- **No file shredding, no RAM/swap wiping.**
- **No live LUKS destruction.** Scaffolded stub only.
- **No networking, no telemetry.**
- **No fleet or central configuration.**
- **No non-systemd init support.**
- **No responsibility for setting up disk encryption.** LUKS is assumed to already exist.

---

## 12. Lessons carried from the original (what we are deliberately fixing)

Each of these was a concrete defect in the Python `usbkill`; the new architecture addresses each by design.

| Original defect | How v1 prevents it |
|---|---|
| `dirname('/etc/usbkill.ini')` → wiping `/etc` in melt mode | Fail-closed config validation; explicit targets only; no `dirname()` of config paths; destruction is a stub. |
| Logging failure could crash before poweroff | Logger is an independent responder; it can never block the kill path. |
| Backgrounded RAM/swap wipe killed instantly by shutdown | No wiping in v1; response ordering is explicit and each responder's completion semantics are defined. |
| Catchable signals silently disabled protection | Disarm is an authenticated, logged socket command; signals only stop the process. |
| Polling missed fast USB swaps | Event-driven netlink; reacts on the kernel's own add/remove announcement. |
| Destructive action enabled by a plain boolean | Dangerous features require distinctly-named opt-in plus typed TUI confirmation. |
| Broken first-run config copy | Idempotent `postinst` that installs default config only if absent. |
| `os.system` string concatenation (injection/quoting) | No shell string building; responders act via typed calls, not shelled-out concatenated commands. |
| Python 2/3 straddling, runtime fragility | Single static Rust binary; no interpreter or module dependencies. |
| Silent parse failure → empty device list → no protection | Sensors surface parse failures; the system fails loud, never silently to "nothing connected." |

---

## 13. Open decisions for the engineering team

These were chosen during architecture but are reasonable to revisit. Document any change here.

1. **Tokio vs. hand-rolled `mio`+threads.** Tokio is the recommended default (natural fit, good to learn) at the cost of a real dependency and concept load. A minimal-dependency alternative is acceptable if the team prefers. **v1 decision (steps 4–5):** neither Tokio *nor* `mio` — the daemon runs on plain `std::thread` + `std::sync::mpsc` channels throughout. The kill path (invariant 1 / principle 1) must not depend on an async runtime being healthy and schedulable, and every concurrent piece here is a single blocking loop (responder fan-out, the netlink `recv` loop, and the step-6 control server): a thread each, no executor, no `mio` reactor. Fewer dependencies for a root daemon, one concurrency model end to end. Revisit only if a future sensor or responder genuinely needs many-tasks-on-one-thread multiplexing.
2. **JSON vs. binary wire format.** JSON chosen for readability/debuggability; swappable later without changing the protocol shape.
3. **Daemon-owns-config-writes.** Chosen to avoid file/running-state drift; the tradeoff is the daemon needs write logic a pure editor-TUI wouldn't. Considered settled unless a strong reason emerges.
4. **`lock_screen_first`.** §9 introduced it as an "optional pre-poweroff nicety". Building it surfaced a conflict with principle 1 (the kill path is sacred): "lock *before* the power action" and "never delay the poweroff" cannot both hold — a real wait delays the kill, and a fire-and-forget lock loses the race against power being cut, so it would never actually lock. **v1 decision:** `validate` rejects `lock_screen_first = true` (fail closed, principle 2) rather than silently ignore it; `false`/absent is valid; the poweroff responder does not touch it. **If revisited:** the only kill-path-safe design is a *separate* fast responder that locks the screen the instant an unauthorized event is detected — concurrently with everything else, never awaited, independent of `power_action` — not a step sequenced before the poweroff. That is a new responder, not a poweroff-responder feature.
5. **`KILL_IN_FLIGHT` latches on a *power action*, not on "irreversible".** The flag makes the process (and, under `SendSIGKILL=no`, the host's shutdown transaction) park forever — correct only because `reboot(2)` is not expected to return. A `power_action = "none"` kill with `luks_destroy` engaged is irreversible in intent but the responder *returns* (a stub in v1; a bounded operation when the wipe is real). **v1 decision:** the latch is gated strictly on `!dry_run && power != none`. When the LUKS wipe is implemented it gets its own *bounded* in-flight guard, separate from this latch — latching here on a response that returns would make the daemon unstoppable.
6. **Control socket path & `ProtectSystem`.** The socket is `/run/killbilld.sock` (flat, in `/run`). This forces the unit to `ProtectSystem=full` rather than `=strict` (which mounts `/run` read-only). **v1 decision:** keep the flat path + `=full` — one line, no code churn, and `=full` still makes `/usr`/`/etc`/`/boot` read-only. A future move of the socket into a systemd `RuntimeDirectory` (`/run/killbilld/killbilld.sock`) would let the unit go to `=strict`; it needs the compiled defaults in all three binaries changed in lockstep.
7. **systemd start-rate limit.** Left at the systemd default (5 starts / 10 s → `failed`). A persistently-failing sensor then lands in a visible `failed` state a monitor can see, rather than an endless restart loop; a dead sensor means no protection either way. Revisit if an operator wants unlimited restarts (`StartLimitIntervalSec=0`) instead.

---

## 14. Suggested next design layers (not yet specified)

The following are the natural next documents, none of which exist yet:

1. Internal concurrency / data-flow diagram for the daemon (tasks, channels, event bus).
2. Full `Sensor` and `Responder` trait contracts (method signatures, lifecycle, error semantics).
3. Message-by-message control protocol specification (wire format, every command and event).
4. TUI screen flows, including the plug-and-whitelist interaction and the fenced destruction screen.

---

## 15. Glossary

- **Armed / disarmed:** Whether the daemon will act on an unauthorized event. Disarmed means detect-and-report only.
- **Sensor:** A pluggable event source (v1: USB via netlink). Emits normalized `SensorEvent`s.
- **Responder:** A pluggable action handler (v1: poweroff, logger; stub: luks-destroy). Independent subscriber to an `Action`.
- **Policy engine:** The core decision stage; maps `SensorEvent` + config → `Action` or no-op.
- **Dry-run:** A true test mode that logs what *would* happen and performs no destructive or power action.
- **Kill path:** The sequence from kill decision to poweroff. Must never be blockable by non-essential work.
- **LUKS header destruction:** The fenced-off "option B" data-destruction primitive; renders a LUKS disk unrecoverable by wiping the header/keyslot. Stub only in v1.
