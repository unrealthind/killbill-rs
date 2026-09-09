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
  comment to mirror `killbillctl` (64 KiB); it does not. **New as of step 1–2**:
  `client.rs` still decodes a subscription's post-ack frames as bare `Event`;
  the daemon now sends `StreamEvent { at, event }` for both the backlog replay
  and every live push, so this will fail to decode against a real daemon until
  step 4 fixes it — decode `StreamEvent` and read `.event`, same as
  `killbillctl`'s `stream_events` now does.
- *Phase 3 — both now DONE (2026-09-09 review gate).* `killbilld.service`
  carries `KillSignal=SIGTERM` + `SendSIGKILL=no` + `TimeoutStopSec=infinity`
  (safe only because `KILL_IN_FLIGHT` latches strictly on a power action, not on
  an engaged `luks_destroy` — the widened predicate was reverted, see below).
  `control::bind_listener` refuses to start when the socket's parent directory
  is group/other-writable without the sticky bit (`ensure_parent_dir_is_safe`,
  3 tests).
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

**Phase 2 steps 1–3 are implemented, fixed against one review round, and
build/test-clean.** `cargo fmt --all`, `cargo clippy --workspace --all-targets
-- -D warnings`, and `cargo test --workspace` are all green — 187 tests (the
161-test Phase 1 baseline plus 26 new: protocol round-trip/`rfc3339` tests,
policy engine two-opt-in tests, and daemon tests for `GetConfig`/`ConfigSet`/
`SetLuksDestroyEngaged`/the event backlog/the `WouldKill` fix). `security-
auditor`, `kill-path-reliability`, and `code-quality` each reviewed the diff
before the fixes below (all three read-only, source + `git` only).
`code-quality` returned a clean PASS (a few non-blocking "consider" items,
listed below). `security-auditor` and `kill-path-reliability` both returned
**BLOCK**, converging independently on the same core gap plus one each of
their own; all of those are fixed, each with a regression test:

**Note for whoever picks this up next: the fixes below have not been
re-reviewed.** The review agents ran once, against the pre-fix diff; their
findings were addressed and the fixes are covered by new tests and traced by
hand, but no agent has confirmed the *post-fix* diff. This was a deliberate
choice (2026-09-08) to proceed to step 4 rather than spend another review
round first — treat steps 1–3 as high-confidence, not signed off, and get a
confirmation pass (at least `security-auditor` + `kill-path-reliability`,
scoped to just the three fixes below) before or alongside step 13's full-tree
sign-off, the way Phase 1's sign-off worked.

- **Fixed.** `swap_config` cleared the runtime `luks_destroy_engaged` toggle
  only when `luks_destroy` disappeared entirely — a config change that kept
  `luks_destroy` present but *retargeted* `target_header` at a different
  device silently carried the old engagement over to a target the operator
  never confirmed. Now cleared whenever the target changes at all, not only
  when it vanishes; covered by two new tests (retarget clears it, an
  unrelated `config_set` does not).
- **Fixed.** The armed-dry-run `WouldKill` broadcast (below) originally fired
  only for `action.dry_run`. `power_action = "none"` is the *other* documented
  safety belt (both are used throughout the step-0 hardware-gate protocol) and
  is equally silent to a subscriber — the kill dispatches for real, but the
  poweroff responder's plan is `Skip`. Now fires for `action.dry_run ||
  action.power == PowerAction::None`; covered by tests for both belts plus a
  negative test that a genuine kill (neither belt on) does *not* also claim to
  be a would-kill.
- **Fixed.** `Event::ReloadFailed`'s reason is a whole `ValidationReport`,
  unbounded in principle (e.g. a config with hundreds of malformed whitelist
  entries) — a single broadcast could exceed `MAX_CONTROL_FRAME`. Unlike a
  direct command reply (already handled — `control::serve_connection`
  substitutes a small "too large" error), an unsendable *broadcast* had
  nowhere to go and would sit poisoned in `event_backlog`, breaking replay for
  every subsequent subscriber. Fixed at the source (`daemon::
  truncate_for_broadcast`, 4 KiB cap, full report still in the direct
  `Reply::Error` and the log) *and* defensively in `control::
  write_event_frame` (an oversized frame is now skipped with a `tracing::warn!`,
  never drops the connection) — belt and suspenders, per both reviewers'
  recommendation.

**Deliberately deferred, not fixed** — low-severity findings from the same
review round; do not "fix" these ad hoc without reading why they were left:

- The backlog snapshot in `Core::subscribe` deep-clones up to 200
  `StreamEvent`s on the single authority thread before handing them to the
  connection thread to replay. Bounded and root-gated, but a tight
  subscribe/disconnect loop could add repeated small delays ahead of a queued
  USB event. A future fix would use `VecDeque<Arc<StreamEvent>>` so the
  snapshot is pointer clones; not done here to avoid widening this diff
  further after two BLOCK rounds already landed.
- `SetLuksDestroyEngaged(true)` does not re-run the LUKS-target preflight
  (exists-and-is-a-block-device) at engage time — only `arm` and a config swap
  do. Harmless while the responder is a stub (invariant 3); tighten before the
  wipe is ever implemented.
- **DECIDED (2026-09-08): `Disarm` clears `luks_destroy_engaged`.** The
  destructive opt-in is scoped to a single armed session — a disarm clears the
  runtime toggle, so re-engaging always means walking the typed-`DESTROY`
  fence again. Already cleared on daemon restart and on a config target
  change; this adds disarm. Implemented in `Core::disarm` (logs `peer_uid`/
  `peer_pid`, broadcasts `Event::ConfigChanged` so other clients re-fetch),
  covered by `disarm_clears_the_luks_destroy_engage_toggle`.
- `swap_config` picks `WhitelistChanged` vs `ConfigChanged` by checking
  whether `label` starts with `"whitelist"` rather than a dedicated
  `ChangeKind` enum threaded through `WriteJob`/`Msg`. `code-quality` flagged
  this as stringly-typed; it is safe today (every `label` is an internal
  `&'static str`, never client input) and is covered by a test per broadcast
  kind, but a real enum would make a future mismatch a compile error instead
  of a silently-wrong event. Worth doing if this area is touched again.
- `Event::ReloadFailed`'s reason and `ConfigPayload`'s `target_header`/
  `validation_error` are rendered by `killbillctl` without
  `sanitize_device_string`. These strings originate in the root-owned config
  file (not a privilege boundary — `security-auditor` did not flag it as a
  finding), but it's the one place raw file content reaches a terminal
  unsanitized. Low priority; revisit if either becomes attacker-influenced.

What steps 1–3 changed:

- `killbill-proto`: `OnSensorGap` (wire twin of `SensorGapAction`),
  `LuksDestroyInfo`, `ConfigPayload`, `ConfigChange`, `StreamEvent { at, event
  }`, `rfc3339_now` (hand-rolled RFC 3339 UTC formatter — no date crate
  pulled in for one timestamp string). New commands `GetConfig`, `ConfigSet`,
  `SetLuksDestroyEngaged` (all privileged — the closed `requires_root`
  allow-list needed no code change, only new test assertions).
  `Command::Subscribe`'s ack is still a bare `Reply::Ok`/`Error` — no new
  `Reply` variant for it — but everything after the ack, backlog and live
  alike, is now a `StreamEvent` frame, individually, never batched.
- `killbilld`: `policy::decide` gained a fourth parameter,
  `luks_destroy_engaged: bool` — `Action::luks_destroy` is now `cfg.
  luks_destroy.is_some() && luks_destroy_engaged`, i.e. two opt-ins, config-
  time and runtime, neither sufficient alone (invariant 4). `Core` gained
  `luks_destroy_engaged` (never persisted, always `false` on daemon start,
  cleared by `swap_config` whenever the new config drops `luks_destroy` *or*
  points it at a different `target_header`) and
  `event_backlog: VecDeque<StreamEvent>` (cap 200, appended in `broadcast`,
  replayed by the *connection thread* on subscribe — never the core thread).
  Fixed the deferred defect: an armed dry-run kill now also broadcasts
  `WouldKill` from `on_sensor_event` itself, not just from `RunDryRun`.
  `WhitelistChanged`/`ConfigChanged` are broadcast from `swap_config` (picked
  by whether `label` starts with `"whitelist"` — safe because every `label`
  is a `&'static str` this module itself supplies, never client input);
  `ReloadFailed(reason)` is broadcast from all three `on_config_reloaded`
  rejection paths, alongside the existing `config_stale = true` /
  `Reply::Error`.
- `killbillctl`: `config show`, `config set dry-run|power-action|armed-at-boot
  |sensors|on-sensor-gap <value>`, `luks engage <on|off>`, and `events
  [--follow]` — without `--follow` it now drains just the backlog (a short
  read timeout after the ack, since the daemon writes the whole backlog
  immediately and there is no explicit backlog-end marker on the wire) and
  exits, rather than blocking forever.

**Phase 2 step 4 (TUI transport repair) is implemented and build/test-clean**
(`cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace` all green — 195 tests, the 187-test steps-1–3
baseline plus 8 new in `killbill-tui`). **Review deferred by the operator's own
choice** (2026-09-08: "we will run review gate later") — `code-quality` +
`tui-ux`, the pair the plan calls for on this step, were launched once and
both **errored out on a session rate limit** before reviewing anything; that
attempt does not count as a completed pass. Run the review gate — now scoped
to steps 4–6 together, since 5 and 6 landed on top of 4 before any review
happened — before or alongside step 7. All in `killbill-tui/`:

- `client.rs`: the connection-reuse defect is fixed — `ClientHandle::call`
  now opens a fresh `SOCK_SEQPACKET` connection per call instead of trying to
  reuse one, matching the daemon's actual one-shot-per-connection contract
  (`serve_connection` answers exactly one command then closes). Both the
  command connection and the event connection now carry read/write timeouts
  (`COMMAND_TIMEOUT` = 5s, `EVENT_READ_TIMEOUT` = 30s — a timeout on the event
  connection is treated as "nothing happened yet", not a disconnect, since a
  quiet system can legitimately go longer than that between USB events).
  `MAX_MSG` (128 KiB, claimed-not-actual parity with `killbillctl`) is gone;
  both connections now size their buffer from `killbill_proto::
  MAX_CONTROL_FRAME` directly. The event connection decodes `StreamEvent` now
  (it was still decoding bare `Event`, which would have failed against a real
  post-step-2 daemon — the defect flagged in the deferred-findings list above
  is fixed by this). A new `Client` trait (`ClientHandle` is the production
  impl) lets `App`'s reducer be driven by a canned `ScriptedClient` in tests,
  with no socket (the plan §11 `TODO` this closes).
- `app.rs`: `App` is now generic over `Client` (`App<C: Client = ClientHandle>`
  — every existing bare-`App` reference elsewhere resolves via the default, no
  other file changed). `on_event` takes the full `StreamEvent` (the timestamp
  is unused until the event-log screen, step 10, but the wire-format plumbing
  for it is already in place). Added handling for `WhitelistChanged`/
  `ConfigChanged`/`ReloadFailed` — previously fell into the generic
  `#[non_exhaustive]` catch-all. New reducer tests using `ScriptedClient`.
- `ui/statusbar.rs`: fixed the deferred "stale armed-state cache on
  disconnect" defect — while `Conn::Down`, the headline glyph/word no longer
  claims live truth from the cached `status` (`"● ARMED"`); it now reads
  `"? LAST KNOWN: ARMED"`/`"? LAST KNOWN: DISARMED"`, and the secondary detail
  row (dry-run, sensor health, events-lost, whitelist/device counts) — every
  bit as stale — is suppressed entirely rather than shown as current. Also
  added the missing `config_stale` tag next to `EVENTS LOST`.
- Step 4 did not touch (now addressed by steps 5/6 below, or still open):
  `ui/devices.rs`'s `sanitize_device_string` gap (step 5, fixed), the device
  list still rendering unconditionally during `Conn::Down` (still open, not on
  any step's defect list yet), and `Intent::Reconnect` still being cosmetic
  (`set_toast` only — the background thread already retries on its own timer
  regardless of the keypress; not a correctness issue, just a slightly
  misleading hint string, still open, not on any step's list).

**Phase 2 steps 5 and 6 (Devices screen finish + plug-and-whitelist) are
implemented and build/test-clean** (`cargo fmt --all`, `cargo clippy
--workspace --all-targets -- -D warnings`, `cargo test --workspace` all
green — 206 tests, the 195-test step-4 baseline plus 11 new: the sanitize
regression test plus 10 covering the device-action/whitelist-add/remove
reducer flow). Two real bugs surfaced and were fixed before the human's build
was clean, neither by a review agent (none has run yet):

- A first `cargo test` run failed to compile: `Intent::ToggleMenu`'s
  `match self.modal { Some(Modal::Menu {..}) => None, None => ... }` predated
  the three new `Modal` variants and was no longer exhaustive. Fixed by
  routing every other `Some(_)` (a device-action/whitelist modal open when `m`
  is pressed) to replace it with the main menu, rather than adding a
  `todo!()` — `m` is a global key per the design doc and doing nothing would
  have been the wrong fix, not just an exhaustiveness patch.
- After that, `cargo test` compiled but one new test failed on real semantics,
  not a bad assertion: `move_cursor`'s `delta` is list-cursor sign (`Up` =
  `-1`, moving to an earlier row), which is the opposite of what `↑`/`↓`
  should mean for the whitelist-add modal's `max_count` **stepper** — `Up`
  was decreasing the count. Fixed by negating `delta` in that one match arm
  only; the list-cursor arms are untouched. The modal's own hint text already
  said "↑↓ adjust" implying `Up` increases, so this was a real inversion, not
  a test written backwards.

Both are described together here (rather than getting their own status
blocks) since they're small and land on unreviewed step 4 — the pending
review gate above now covers all three.

- Step 5 turned out to be almost entirely the one listed defect:
  `ui/devices.rs` rendered `label`/`serial` via bare `Span::raw`, the one
  place in the workspace that skipped `sanitize_device_string`. Fixed by
  pulling the row-building code into its own `device_line` function so the
  sanitize call has one call site and its own test (a hostile label/serial —
  an ANSI escape and a non-ASCII byte — asserted absent from the rendered
  spans). The rest of the design-doc §7 status-band spec (glyph+word never
  colour-only, `DRY-RUN` tag, `CONFIG INVALID` red state, `sensor_ok` /
  `events_lost` / `config_stale`) was already delivered by step 4's
  `statusbar.rs` rewrite — nothing left to add there.
- Step 6: `Enter` on a device row (with an id — a device with none has
  nothing to key a whitelist entry on, invariant 7) opens a device action
  modal (`Modal::DeviceAction`) offering "Add to whitelist…" or "Remove from
  whitelist" depending on `DeviceInfo.whitelisted`, plus Cancel, both ending
  in `Command::WhitelistAdd`/`WhitelistRemove`. Add has a second step
  (`Modal::WhitelistAddCount`) to pick `max_count` via `↑`/`↓` (default 1,
  capped at a UI-only 32 — no free-text entry yet, that's a later polish, not
  a protocol limit); Remove has a confirm step (`Modal::ConfirmRemove`) since
  it's a protection-relevant action while armed. Every confirm re-reads the
  device at its stored index rather than trusting what was true when the
  modal opened, and reports rather than panics if the device vanished
  (unplugged) while the modal sat open — covered by a regression test.
  `Event::WhitelistChanged` now also calls `refresh_devices()` (previously
  toast-only) — `DeviceInfo.whitelisted` is derived from the whitelist, so
  the Devices screen's NEW/ok marks would otherwise go stale after a
  successful add/remove, this client's own or another client's.
- Not built for either step: the design doc's "View raw uevent" device-action
  option (no raw-uevent data exists on `DeviceInfo` — out of protocol scope,
  not just out of TUI scope, so not attempted here) and editing an existing
  whitelist entry's `label`/`max_count` in place (that belongs to the
  Whitelist screen, step 8, which can show absent/disconnected entries this
  modal never sees).

**Phase 2 steps 7–12 (confirm modals + Whitelist / Settings / Dry-run /
Event-log / Config-inspector / Help / fenced LUKS-destroy screens) are
implemented — NOT yet reviewed, and NOT yet re-verified by the operator's
build.** Steps 7–10 were written 2026-09-08 at the operator's request to
finish the UI layer without a review gate; steps 11–12 followed the same day,
same instruction ("upto step 10 is done finish the rest"). At the 7–10 mark
`cargo fmt --all` / `clippy --workspace --all-targets -- -D warnings` /
`cargo test --workspace` were green — 224 tests (37 `killbill-proto` + 39
`killbill-tui` + 148 `killbilld`). Steps 11–12 add ~9 more `killbill-tui`
reducer tests (config/help/luks-destroy menu targets, the typed-`DESTROY`
fence: wrong word cancels, exact word then `y`/`Y` sends
`SetLuksDestroyEngaged`, any other key cancels, unconfigured refuses) — the
7–10 gate's "trace the reducer by hand, the green tests prove compilation not
intent" caveat applies here too, and this batch has NOT been compiled by the
operator yet. **No review agent has seen any of steps 4–12.** Still owed
before step 13's sign-off: the deferred steps 1–3 confirmation pass, and a
steps 4–12 review gate — `code-quality` + `tui-ux` across the lot, plus
`security-auditor` + `kill-path-reliability` on the Arm/Disarm confirm path
**and** the LUKS-destroy screen (plan §8 mandates all three on that file).

**Review-gate attempt 2026-09-08 (post-Conn::Down-fix): all four agents
launched, all four died on the session rate limit** (`security-auditor` /
`kill-path-reliability` on Opus 5, `code-quality` / `tui-ux` on Sonnet 5;
"resets 8pm America/Edmonton"). `kill-path-reliability` got far enough to
say Part A (the steps 1–3 daemon fixes) "looks solid" before it was cut off —
not a completed pass, but a data point. A by-hand self-review the same day
(reading only, no build) walked all three steps 1–3 fixes — `swap_config`
target-change clearing, the `dry_run || power == None` `WouldKill` broadcast,
and `truncate_for_broadcast` + `write_event_frame`'s `InvalidData` skip — and
found them correct.

**Review gate RUN 2026-09-08 (steps 1–12, full working tree vs `a66c5c7`):**
all four agents completed a real read-only pass.

- `code-quality` — **PASS**, nothing blocking (9 polish items).
- `tui-ux` — **PASS**, no blockers (4 should-fix).
- `kill-path-reliability` — **PASS**. Confirmed the steps 1–3 daemon fixes
  each correct, complete, and off the kill path; two-opt-in enforced at the
  daemon. Raised H1/H2 as a fail-open surface (fixed below).
- `security-auditor` — **BLOCK** on one finding + 4 mediums it asked be
  fixed in the same pass. Confirmed steps 1–3 correct; invariants 3/6/8
  clean; zero `unsafe`; zero new deps; authz allow-list still closed.

**All BLOCK/High/Medium findings fixed in the same pass** (2026-09-08), each
with a regression test where behavioural:

- *(sec BLOCK #1)* the `DESTROY` fence now captures `target_header` when it
  opens (`App::destroy_target`), renders it in both fence modals, and
  `App::set_luks_destroy_engaged` re-verifies it against the current config
  before sending — a concurrent `reload`/`config set` that repoints the
  target under the open fence now aborts with a toast, nothing sent
  (`destroy_fence_aborts_if_the_target_was_repointed_while_it_was_open`).
- *(sec #2)* `Core::config_set` and `Core::set_luks_destroy_engaged` take
  `PeerCred` and log `peer_uid`/`peer_pid`, same as `arm`/`disarm`.
- *(sec #3)* `set_luks_destroy_engaged` broadcasts `Event::ConfigChanged` on
  a real change so other clients re-fetch the engaged state.
- *(sec #4 / kp L3)* the "will wipe the header" wording in `app.rs`,
  `ui/config.rs` and `killbillctl` now matches `ui/destroy.rs` — v1 records
  intent only, the wipe is a stub, the header is not touched.
- *(sec #5)* the `on_sensor_event` `WouldKill` broadcast now fires for
  `dry_run || (power == None && !luks_destroy)` — a `power = none` kill that
  still runs the LUKS responder for real is not announced as hypothetical
  (`armed_kill_with_power_none_but_luks_destroy_engaged_does_not_broadcast_would_kill`).
- *(sec #6)* `truncate_for_broadcast` scrubs C0/C1 control bytes (keeping
  `\n`/`\t`) before a reason goes on the wire.
- *(kp H1)* the status band tags `POWER: NONE — WILL NOT CUT POWER` /
  `POWER: HALT` (glyph-and-word, not colour) so an armed-but-inert daemon is
  not indistinguishable from a live one.
- *(kp H2)* a Settings change that lowers protection while armed
  (`dry_run = true`, or a non-`poweroff` power action) now routes through a
  `Modal::ConfirmConfigSet` step; everything else stays one keystroke
  (`enabling_dry_run_while_armed_asks_to_confirm_first`).
- *(kp L1)* `swap_config` logs the automatic engage-clear on a target change.
- *(tui #1)* Ctrl-C → quit from anywhere (quitting never disarms); other
  Ctrl-/Alt-chords are swallowed, not typed as their bare letter.
- *(tui #2)* the `DestroyConfirm` step cancels on *any* non-`y` key —
  arrows, Enter, Esc, Backspace included (handled in `input::intent`).
- *(tui #3 / cq #6)* multi-line validation reports render as lines on the
  Settings screen; toasts keep the first line only and scrub control bytes.
- *(tui #4)* the Settings screen refuses edits while `Conn::Down`, mirroring
  `open_destroy_fence`.
- *(tui + cq)* `help_scroll` is clamped to the content length.
- *(cq #1)* `ui/config.rs` matches the `PowerAction` enum, not its `Display`
  text, for the "does not cut power" annotation.
- *(cq #7 nit)* a comment on `format_rfc3339`'s proleptic-year formatting.

**Deliberately NOT done** (non-blocking, reasons hold): `#[non_exhaustive]`
on `ConfigPayload`/`LuksDestroyInfo`/`StreamEvent` (`cq #5`) — the daemon
constructs all three directly, so it needs constructors/builders first, a
wider change than this pass warrants; the `SETTINGS_ROW_COUNT` /
`edit_setting` / `editable_rows` three-way coupling (`cq #2`) — now partly
mitigated by the shared `App::setting_change` helper; `MenuItem::ORDER`
completeness assert (`cq #3`); the render-thread refresh coalescing
(`cq #4` / `kp M1`) — the `VecDeque<Arc<StreamEvent>>` backlog item is
already parked for the same reason; the remaining low-severity
config-origin sanitization sites (`sec #7`, `sec #8` beyond `target_header`,
`cq #6` toast — `{:?}`-escaped at source, root-owned, not a privilege
boundary).

**Build/test on this batch: green (2026-09-08).** `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test
--workspace` all pass — **245 tests** (37 `killbill-proto` + 58 `killbill-tui`
+ 150 `killbilld`), the 235-test post-`Conn::Down` baseline plus 10 new: 2 in
`killbilld` (`disarm_clears_the_luks_destroy_engage_toggle`,
`armed_kill_with_power_none_but_luks_destroy_engaged_does_not_broadcast_would_kill`)
and 8 in `killbill-tui` (3 `input` — Ctrl-C, fence any-key-cancel; 5 `app` —
target-change abort, settings-confirm-while-armed ×2, settings-refused-while-
down, help-scroll clamp). One existing `app` test
(`destroy_fence_step_two_also_accepts_capital_y`) was rewritten to drive
through `open_destroy_fence` so it exercises the new target-capture.

**Scoped re-review of the fix batch — both PASS (2026-09-08):**

- `security-auditor` (BLOCK + 4 mediums + sec #6 + the disarm decision):
  **PASS.** All six items "correctly and completely implemented, each with a
  regression test that asserts the security-relevant behaviour". Disarm
  decision "consistent with invariants 4 and 5 and does not touch the kill
  path". No deps/network/unsafe; `requires_root` still closed.
  - *Residual Medium, documented not fixed:* the fence↔target binding is
    client-side only — `Command::SetLuksDestroyEngaged(bool)` carries no
    target, so the daemon cannot verify which header the operator confirmed.
    Narrow (needs a concurrent root `reload`/`config set` inside the
    `call()` window) and inert today (stub + `swap_config` clears on
    retarget). **Close before the LUKS wipe is ever implemented**, together
    with the `SetLuksDestroyEngaged` preflight item above: extend the command
    to `{ engage: bool, target_header: String }` (or a config-generation
    counter) and refuse a mismatch in `Core::set_luks_destroy_engaged` — that
    also covers `killbillctl luks engage`, which has no fence at all.
- `kill-path-reliability` (H1/H2/L1 + disarm + the WouldKill guard):
  **PASS.** "No kill-path, fail-closed, or invariant-5 regression." Three
  non-blocking follow-ups it raised were **applied in the same pass**:
  (1) `ConfigChange::OnSensorGap(Warn)` added to `lowers_protection` +
  a row-3 confirm string; (2) unknown armed state (`status == None` while
  `Conn::Up`) now counts as armed for the confirm gate — fail closed
  (`edit_setting` uses `map_or(true, ..)`; the three status-less Settings
  tests now set an explicit disarmed status); (3) `POWER: HALT` in the
  status band spells out `— WILL NOT CUT POWER`, matching `ui/config.rs`.
  Also: `destroy_target` is now cleared on any modal-replacing global key
  (`m`/`?`), so the fence's captured target can't outlive its modal; the
  disarm test asserts the `ConfigChanged` broadcast reaches a subscriber.

**Full-tree review gate RUN 2026-09-09** (Phase 2 committed `f3c6d88` + the
Phase 3 sub-phase 3.5 daemon+TUI batch + the packaging tree, all four agents,
read-only). This clears both the deferred steps 1–3 confirmation and the
steps 4–12 gate.

- `code-quality` — **PASS**. Two must-fix-before-tag, both fixed:
  `sanitize_report` (an ASCII allowlist) was being applied to the daemon's own
  trusted, escape-safe validation prose, turning legitimate `—`/`§` into
  U+FFFD, and `Core::load` logged the *capped* report so a >4 KiB report
  reached no sink in full. Split into `cap_report` (length-only, for trusted
  reports — non-ASCII survives) and `sanitize_report` (scrub + cap, for the
  one untrusted string, a raw TOML parse echo); `Core::load` now logs
  `%report` uncapped; `begin_apply` replies capped too. New proto tests.
- `tui-ux` — **PASS**. Four should-fix, all fixed: status band now emits
  `SENSOR STOPPED`/`EVENTS LOST` *before* the `DRY-RUN`/`POWER` belts (an
  unchosen failure must not be the span that clips); `help::line_count` was
  undercounting because `render` wrapped — `Wrap` dropped, count now exact;
  the DESTROY "wipe is a v1 stub" line moved above the 18-row fold; Ctrl-C
  documented in Help. Handed over a 10-item manual-test checklist (NO_COLOR,
  resize, `kill -9`, fence rigor) for the operator.
- `security-auditor` — **BLOCK → cleared**, entirely in packaging (zero
  invariant violations; the daemon batch itself clean). `ProtectSystem=strict`
  made `/run` read-only so the daemon could never bind its socket → `full`.
  `ProcSubset=pid` hid `/proc/sysrq-trigger`, killing the poweroff last-resort
  fallback → removed. `killbilld.8` documented a socket parent-dir guard that
  did not exist → implemented (`ensure_parent_dir_is_safe`). `install.sh
  --prefix` was unvalidated (root unit `ExecStart` → user-writable binary) →
  now refuses a non-root-owned / world-writable / `/home|/tmp` prefix. Socket
  path reconciled to `/run/killbilld.sock` across the man pages.
  `PKGBUILD sha256sums=('SKIP')` → `packaging/scripts/check-release.sh` fails
  the release while it stands. `begin_apply` reply cap (L1), installer
  start-then-verify (M5), `rm -rf "${dir:?}"` (N2) also done.
- `kill-path-reliability` — **BLOCK → cleared**. One real code bug: the 3.5
  batch had widened `KILL_IN_FLIGHT` to latch on `power = none && luks_destroy`
  — but that path never calls `reboot(2)` and never sets `KILL_FAILED`, so the
  latch never cleared → daemon unstoppable, `systemctl stop`/system-shutdown
  hang forever under `SendSIGKILL=no`, panic guard parks forever → a path to an
  un-disarmable daemon (invariant 5). Reverted: `KILL_IN_FLIGHT` latches
  strictly on a real power action (`attempts_power_action`); an irreversible
  *responder that returns* (the LUKS wipe, once real) will need its own
  *bounded* guard, documented in `responder/mod.rs`. Also: package upgrade now
  warns loudly before a restart disarms a running armed daemon (M1);
  `peer_has_closed` treats `EINTR` as "still here" (L2); `After=local-fs.target`
  not `multi-user.target` so protection comes up earlier in boot (M3).
- *Deferred, recorded, NOT fixed for v0.1.0:* the two agents gave **opposed**
  recommendations on the systemd start-rate limit (`security` wants
  `StartLimitIntervalSec=0` / infinite restart; `kill-path` wants it to land
  deterministically in `failed`). Left at the systemd default (→ `failed`),
  which is `kill-path`'s side — a dead sensor means no protection either way and
  `failed` is the monitorable state. Revisit if an operator asks.
  `sec` L3 (AUR `.install` re-implements the maintainer contract instead of
  inlining `lib.sh`), L5 (`install.sh` manifest ignores `--prefix`), L7 (the
  LUKS drop-in re-exposes all of `/dev`) also deferred.
**Scoped re-review 2026-09-09** — `security-auditor` + `kill-path-reliability`
on the `KILL_IN_FLIGHT` revert + the packaging tree: **both PASS, the BLOCK
clears.** `kill-path` confirmed "the latch predicate now matches the syscall
predicate exactly" and no invariant regression. `security` re-traced every
`cap_report` call site and confirmed no untrusted string reaches it, and that
`deny.toml` now enforces the no-network rule at the dependency level. Follow-ups
applied in the same pass: the AUR `post_upgrade` armed-warning + `timeout 5` on
the `killbillctl status` probe everywhere (it runs under the dpkg/rpm lock);
`ensure_parent_dir_is_safe` now requires every ancestor to be **root-owned** and
not group/other-writable (matching `install.sh`'s definition), canonicalizes
first, and the sticky-bit carve-out is gone; `install.sh --prefix` perm check is
`stat`-based (one tool, fails closed); `check-release.sh` fails closed on an
unreadable version and its `SKIP` grep is widened; `CONTRIBUTING.md` gained a
"Cutting a release" gate list. No must-fix code items remain.

**Owed to Phase 3 — all DONE.** Sub-phase 9 (`.github/workflows/{ci,release}.yml`),
sub-phase 10 (README rewrite, `.gitignore` reword, source comments repointed off
`CLAUDE.md` — `git grep -i claude` on tracked files is clean bar the necessary
`.gitignore` patterns), sub-phase 11 (charter §10 rewritten, §13 decisions 5–7
added). Remaining for the tag: the full-tree 4-agent sign-off, the manual TUI
checks (`NO_COLOR` / resize / `kill -9`), a clean-VM package install, `minisign
-G`, then commit + tag.

After the `Conn::Down` fix + `cargo fmt --all`: `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test
--workspace` are all green — 235 tests (37 `killbill-proto` + 50 `killbill-tui`
+ 148 `killbilld`), the 2 new being `destroy_fence_refuses_while_the_daemon_is_unreachable`
and `state_line_hides_the_cached_engaged_value_while_the_daemon_is_down`. The
step 11–12 screen files needed `cargo fmt` applied (they never had been); that
run also reflowed the new `.title(screen_title(...))` call sites.

- **Step 7** — `Modal::Confirm { action: ConfirmAction }` (`Arm` / `Disarm` /
  `Reload`). The three menu items open a confirm modal instead of calling
  `command()` directly; `Enter` fires, `Esc` cancels with no command sent
  (invariant 5 is unaffected either way — disarm was already socket-only, this
  just adds a keystroke of intent). Menu also now greys `LUKS destroy` when a
  loaded `ConfigPayload` has `luks_destroy: None`.
- **Step 8** — `Screen::Whitelist`: full list from `WhitelistList` including
  entries whose device is absent, each marked connected/absent by cross-ref
  against `devices`. Row 0 is a permanent "+ Add entry" action (no key
  collision with the `a`=arm accelerator the design reserves). Add is
  type-an-id (`Modal::WhitelistAddId`, hex+colon only, parsed by
  `UsbId::from_str` — a bad id keeps the field open, fails loud) → count
  stepper. Edit reuses the stepper (`Modal::WhitelistCount { editing: true }`)
  and preserves the existing `label` on the upsert. Remove is a confirm
  (`Modal::WhitelistRemoveEntry`). Every confirm re-reads the entry by index
  and reports (not panics) if it vanished. `WhitelistChanged` now also
  re-fetches the whitelist and status, not just devices.
- **Step 9** — `Screen::Settings`: `GetConfig` snapshot; `Enter` on a row
  toggles `dry_run` / `armed_at_boot` or cycles `power_action`
  (poweroff→halt→none) / `on_sensor_gap` (warn↔kill) via `ConfigSet`. A
  rejected `ConfigSet` shows the daemon's full validation report verbatim in
  `Modal::Report` and re-fetches `GetConfig`, so the screen always reflects
  the still-running config (invariant 2 — nothing was written or swapped).
  `sensors` and `luks_destroy` are shown read-only (edited via `killbillctl`
  in v1 — no free-text list editor).
- **Step 10** — `Screen::DryRun`: runs one `RunDryRun` on entry and on `r`,
  renders `Reply::DryRun` as one line per `KillReason` or a clear "nothing
  would fire"; read-only, never dispatches. `Screen::EventLog`: a capped
  1000-entry `VecDeque<StreamEvent>` ring appended in `on_event` for *every*
  event, rendered newest-last with the daemon's `se.at` timestamp; `↑`/`↓`
  scroll, `p` freezes auto-follow. No filter yet (design §5's `/` — deferred).
- **Step 11** — `Screen::Config` (`ui/config.rs`): read-only dump of the whole
  running `ConfigPayload` — every field Settings edits plus `sensors`,
  `luks_destroy` (target sanitized, `acknowledged`, `engaged`), and the full
  `validation_error` report inline with a red banner when the file on disk is
  broken (invariant 2). `halt`/`none` power actions are flagged "does not cut
  power". `Screen::Help` (`ui/help.rs`): a static key/menu reference built from
  `const SECTIONS`, hand-kept in step with `input::intent` (a key here and not
  there, or vice versa, is the bug it exists to catch); `↑`/`↓` scroll via a
  `help_scroll: u16` Paragraph offset. Both are plain menu targets, no new
  protocol.
- **Step 12** — `Screen::Destroy` (`ui/destroy.rs`): the fenced screen. Double
  hazard border in `theme.invalid()`, names the sanitized `target_header`,
  shows `acknowledged` + a big colour-**and**-word `engaged` state, and says
  in plain text three times over that the wipe is a v1 stub (invariant 3) —
  engaging changes nothing destructive today. `Enter` opens a two-step fence:
  `Modal::DestroyText { engage }` captures a letters-only field that must equal
  exactly `DESTROY` (`DESTROY_WORD`, case-sensitive — `input_char` does not
  fold case for this modal), then `Modal::DestroyConfirm { engage }` takes a
  final `y`/`Y`; **any** other key, `Enter`, or `Esc` at either step cancels
  with nothing sent. Only on `y` does `SetLuksDestroyEngaged(engage)` go out,
  followed by a `GetConfig` + `GetStatus` re-fetch. `engage` is always derived
  from the *current* `engaged` state (`app.luks_engaged()` reads the config
  cache, `false` when unknown) so the one row toggles both directions. The
  engaged state is also surfaced outside this screen: the status band shows a
  red `LUKS DESTROY ENGAGED` tag and the menu item gets a red `(ENGAGED)`
  suffix (invariant 4 — the dangerous state is visible everywhere, not just on
  its own screen). No kill-path code touched — this only sets a flag the
  daemon already had; the wipe stub is unchanged.
- Known gap carried in from step 4 — **now fixed** (2026-09-08): the read
  screens (Devices, Whitelist, Config, Dry-run, Event log, Settings, Destroy)
  render during `Conn::Down` with a ` — STALE (daemon unreachable)` tag in the
  border title (`ui::screen_title`), on top of the existing status band + the
  centred "daemon unreachable" box. The Destroy screen — the sharpest case —
  additionally replaces the cached engaged-state line with `?? ENGAGED STATE
  UNKNOWN` (`destroy::state_line`) rather than a stale `not engaged`, drops the
  "press Enter to ENGAGE" hint, and `App::open_destroy_fence` refuses outright
  while `Conn::Down`. The main menu's `(ENGAGED)` marker (which can overhang the
  centred box) becomes `(engaged? — daemon unreachable)` in `warn` not the
  reversed-red `invalid()`. Help is untouched (fully static, nothing to go
  stale).
  Covered by `destroy_fence_refuses_while_the_daemon_is_unreachable` (app.rs)
  and `state_line_hides_the_cached_engaged_value_while_the_daemon_is_down`
  (ui/destroy.rs). Still not re-reviewed — part of the pending steps 4–12 gate.
- Not built: the design-doc device-action "View raw uevent" option (no
  raw-uevent data on `DeviceInfo` — out of protocol scope), the Event-log `/`
  filter (design §5 — deferred), and any Config-screen copy-path affordance.

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
  **Phase 2 step 2** added handlers for `GetConfig`/`ConfigSet`/
  `SetLuksDestroyEngaged`, the event backlog, and the broadcasts described in
  the Phase 2 status block above — all still on the one authority thread, none
  of it touching the kill path itself.
- `killbilld` bin — `main.rs`: two flags (`--config`, `--socket`), a
  `tracing-appender` non-blocking stderr sink, hand off to `daemon::run`.
- `killbillctl` (step 7) — `clap` subcommands (`status`, `devices`, `arm`,
  `disarm`, `test`, `reload`, `whitelist list|add|remove`, `events`); a pure
  protocol client over the SEQPACKET socket. `#![forbid(unsafe_code)]`.
  **Phase 2 step 3** added `config show|set`, `luks engage`, and `--follow` on
  `events` — see the Phase 2 status block above.
- Protocol additions from Phase 1 (all additive to `#[non_exhaustive]` types,
  charter §8 updated; Phase 2 step 1's additions — `OnSensorGap`,
  `ConfigPayload`, `ConfigChange`, `StreamEvent`, `GetConfig`, `ConfigSet`,
  `SetLuksDestroyEngaged` — are in the Phase 2 status block above rather than
  repeated here): `Command::WhitelistList`, `Reply::Whitelist`, `Reply::DryRun`,
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

**Owed to Phase 3 — DONE (2026-09-09).** `packaging/systemd/killbilld.service`
carries `KillSignal=SIGTERM` + `SendSIGKILL=no` + `TimeoutStopSec=infinity`;
`control::bind_listener` refuses a group/other-writable (non-sticky) socket
parent directory. Both landed in the Phase 3 review gate below.

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
