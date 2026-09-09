# Design notes

Background on decisions that aren't obvious from the code. `PROJECT_CHARTER.md`
is the authority for *what* and *why*; this file records the *how* and the
"why not the other way".

## No async runtime

The daemon is `std::thread` + `std::sync::mpsc` end to end — no Tokio, no `mio`
reactor (charter §13.1). Every concurrent piece is a single blocking loop: the
netlink `recv` loop, the responder fan-out, the control-server accept loop, one
thread per control connection, the config-writer, the signal thread. A thread
each needs no executor.

The reason is invariant 1. The kill path must not depend on a runtime being
healthy and schedulable. A blocking `reboot(2)` on a plain thread has no
scheduler between it and the syscall.

## One authority thread

All mutable daemon state lives in `Core`, touched by exactly one thread (the
loop in `daemon::run`). Sensor events and control requests arrive on one channel
and are handled serially. No locks. "The decision site calls `dispatch`
synchronously on the thread that decided" is trivially true because that thread
*is* the authority thread.

Config file writes (the `fsync` in particular) are the one thing moved off it —
to a dedicated `config-writer` thread — so a slow disk can never sit in front of
a queued USB event.

## The kill path parks the process, forever, on purpose

Once a real power action is dispatched, `KILL_IN_FLIGHT` latches and is never
cleared. The shutdown path, the panic hook, and the signal thread all check it
and refuse to let the process exit while it is set — because `reboot(2)` does
not return on success, so "park forever" means "the machine is going down".

The only escape is `KILL_FAILED`: if `reboot(2)` and every fallback failed with
the machine still up, the process exits non-zero so a supervisor can restart a
daemon that can be re-armed.

The latch is gated strictly on a *power* action — not on an engaged
`luks_destroy` with `power_action = "none"`. That responder *returns* (it is a
stub in v1, and even the real header wipe would finish in bounded time), and
parking the process forever on a response that returns would make the daemon
unstoppable and the host un-shutdownable. When the wipe becomes real it gets its
own *bounded* in-flight guard, separate from this latch.

**This is why the systemd unit must set `KillSignal=SIGTERM` + `SendSIGKILL=no`
(or `TimeoutStopSec=infinity`).** Without it, systemd's stop timeout fires a
`SIGKILL` at a daemon deliberately parked mid-poweroff.

## `panic = "unwind"` in the release profile

Not a size knob — do **not** switch it to `"abort"`. Responders run on
independent threads; a panic in the logger or the luks-destroy stub must unwind
only that thread, never abort the process and take an in-flight poweroff with
it. The panic-isolation test only means something under unwind.

## `on_sensor_gap`

The netlink uevent socket has a bounded kernel receive buffer. A device storm
(deliberate or not) can overflow it, and the kernel then drops uevents. A
dropped add/remove means the device set is no longer trustworthy — a silent
blind spot, which invariant 7 forbids.

- `warn` (default): surface it (`events_lost` in status, `Event::EventsLost`)
  and refuse to (re)arm until the daemon is restarted.
- `kill`: treat the gap as an unauthorized change and fire `power_action`
  (`KillReason::SensorGap`). Never triggers `luks_destroy` — header destruction
  is reserved for an actual identified device event.

An unrecognized value is a hard validation error. The daemon never guesses.

## The `luks_destroy` engage flag is scoped to one armed session

The runtime "engaged" toggle (set behind the typed-`DESTROY` fence) is never
persisted. It clears on daemon restart, on a config change that drops or
retargets `luks_destroy`, and on **disarm**. Re-engaging always means walking
the fence again. A destructive opt-in that outlived the session it was made in
would be a footgun — the operator's mental model is "I armed this session with
destruction on", not "destruction is on until I remember to turn it off".

There is also a `sanitize_report` / `cap_report` split: a config
`ValidationReport` and the daemon's own composed diagnostics are trusted,
escape-safe text (every interpolated value formats with `{:?}`) and only need a
length cap (`cap_report`, on a UTF-8 boundary). The one untrusted report string
— a raw TOML *parse* error, which echoes a source line from the config file
verbatim — additionally goes through the `sanitize_device_string`-style
allowlist scrub (`sanitize_report`). The full, uncapped report always reaches
the journal first; only the wire copy is capped.

## `sanitize_device_string` is an allowlist, deliberately

Printable ASCII plus space; everything else becomes U+FFFD; capped at
`MAX_DEVICE_STRING`. A denylist was tried and rejected: enumerating the
terminal-hostile codepoints (C0/C1 controls, Trojan-Source bidi overrides,
zero-width characters, tag characters, variation selectors, combining-mark
stacks) cannot be completed, and missing one is a silent hole. Do not "fix" this
back into a denylist.

## Device-string truncation is identity-lossy, and that's acceptable

`MAX_DEVICE_STRING` can cut a serial mid-string. Policy keys on `usb_id`
(vendor:product), not the serial, so a truncated serial never changes a
decision. The serial is shown to the operator as context, not used as an
identifier.

## SELinux (Fedora / RHEL)

On an enforcing system, `init_t` (the systemd service domain) cannot `execute` a
binary labelled `user_home_t`. A hand-copied binary under `/home` run from a
systemd unit fails with `status=203/EXEC`. Packaged installs to `/usr/bin` get
`bin_t` automatically and work. Never point a unit's `ExecStart` at a path under
a home directory. A tailored `killbilld.te` policy module is possible future
work; v1 relies on the stock `bin_t` labelling.

## Future hardening, not in v1

- **Real-time scheduling for the core/responder threads** (`SCHED_FIFO` +
  `mlockall`). Invariant 1's guarantee today is a software-architecture one — no
  responder blocks another, nothing does I/O on the kill path. It is *not* a
  kernel-scheduling guarantee against external interference (e.g. a BadUSB HID
  device racing a countermanding command). Hardware testing showed
  kernel-enumeration-to-power-cut well under a second, but there is no scheduling
  floor under that number. Elevating the threads to `SCHED_FIFO` would push the
  window toward zero. Any such change touches the kill path directly — and the
  shipped systemd unit sets `RestrictRealtime=yes`, which must be relaxed for it.
- **`landlock`** (kernel 5.13+) self-sandbox, gated so the daemon still runs
  without it. The systemd unit's `ProtectSystem=full` + capability set delivers
  most of the benefit for v1. (`=strict` would be tighter still, but it mounts
  `/run` read-only and the daemon binds its control socket there; a future move
  of the socket into a `RuntimeDirectory` would let the unit go to `=strict`.)
- **Live LUKS header destruction.** The `luks_destroy` responder is a stub
  (invariant 3). The config schema, validation, dry-run messaging, and TUI
  screen are all real; the header wipe is deliberately unimplemented so there is
  no live footgun during development. It can be flipped on in a later version —
  behind the existing two opt-ins plus a real LUKS2-magic preflight.

## Startup device enumeration — not in v1

The daemon sees only devices added *since it started*. There is no sysfs walk of
already-connected USB devices at boot, so `killbillctl devices` / `test` under-
report until something is plugged. Owed to a future version.
