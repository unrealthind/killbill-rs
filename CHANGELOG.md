# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-09

First public release — a fully working USB-kill daemon for distribution and
testing.

### Added

- **`killbilld`** — the root daemon. Watches USB add/remove events on the kernel
  `NETLINK_KOBJECT_UEVENT` socket; while armed, an unauthorized device change
  powers the machine off immediately so a LUKS disk re-locks.
  - Fail-closed TOML configuration: every validation error is collected and
    reported, and the daemon refuses to arm on an invalid config. Unknown keys
    are hard errors.
  - Pure, synchronous policy engine (`decide`) with a documented decision table.
  - Independent responders — poweroff, logger, and a deliberately stubbed
    `luks-destroy` — that can never block or delay one another.
  - One authority thread owns all state; config `fsync` is off the kill path.
  - `armed_at_boot`, and sensor-gap handling (`on_sensor_gap = warn | kill`).
  - Disarm is a control-socket command, never a signal.
- **`killbillctl`** — full command-line client over the control protocol:
  `status`, `devices`, `arm`, `disarm`, `test`, `reload`,
  `whitelist list|add|remove`, `config show|set`, `luks engage`,
  `events [--follow]`.
- **`killbill-tui`** — a ratatui terminal client: live device list,
  plug-and-whitelist, armed toggle with confirmation, dry-run, event log,
  read-only config inspector, and the fenced typed-`DESTROY` LUKS screen.
  A crash or `kill -9` of the client never changes the daemon's armed state.
- **Packaging** — a hardened `killbilld.service` (minimal capability set —
  `CAP_SYS_BOOT` only; `ProtectSystem=full`, `KillSignal=SIGTERM` +
  `SendSIGKILL=no` so systemd never interrupts an in-progress poweroff); `.deb`,
  `.rpm`, an AUR `PKGBUILD`, and a universal `install.sh`; man pages for all
  three binaries and the config format. A fresh install is enabled but **never
  armed**, and ships an **empty whitelist** (arming allows nothing until you add
  your own devices). A package **upgrade restarts the daemon, which clears the
  armed state** — the maintainer scripts warn when this happens and you must
  `killbillctl arm` again.
- Prebuilt static (musl) `x86_64` binaries attached to the GitHub release, with
  `SHA256SUMS` and `minisign` signatures.

### Security

- `luks_destroy` ships as a stub in v1: the schema, validation, dry-run
  messaging and TUI screen are real; the header wipe is deliberately not
  implemented.
- No network activity and no telemetry. The only IPC is the local
  `SOCK_SEQPACKET` Unix socket (mode `0660`, `root:root`). The daemon refuses to
  start unless the socket's parent directory and every ancestor is root-owned and
  not group/other-writable (the sticky bit is not an exemption) — the socket's
  mode and owner are applied by path after `bind(2)`.
- `SetLuksDestroyEngaged` carries no target on the wire, so the TUI's
  typed-`DESTROY` fence↔target binding is client-side; the daemon clears the
  runtime engage flag on any config retarget, on disarm, and on restart. To be
  closed (server-side target/generation check) before the header wipe is ever
  implemented.

### Known limitations

- `killbilld` does not enumerate already-connected USB devices at startup. It
  counts only `add` events seen since it started, so `max_count` treats a device
  present before the daemon started as zero. Seed the table with
  `udevadm trigger --action=add --subsystem-match=usb` while disarmed. See
  `killbill.conf(5)` and the README.
- A configured `[response.luks_destroy]` target is hidden by the shipped unit's
  `PrivateDevices=yes` and will fail the arm-time preflight until the
  `killbilld.service.d/luks-destroy.conf` drop-in is installed. The preflight
  error and `killbilld(8)` both say so.
- Config comments are lost when the daemon rewrites the file (a `whitelist add`
  or `config set`).

[Unreleased]: https://github.com/unrealthind/killbill-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/unrealthind/killbill-rs/releases/tag/v0.1.0
