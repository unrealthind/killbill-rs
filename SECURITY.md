# Security policy

## Supported versions

killbill-rs is pre-1.0. Security fixes land on the latest `0.1.x` release and
`main`. There is no back-porting to older tags.

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting:
<https://github.com/unrealthind/killbill-rs/security/advisories/new>

Please include the version or commit, your platform, and a concrete
reproduction or the reasoning behind the finding. You will get an
acknowledgement; a fix and coordinated disclosure follow from there.

## Scope

killbill-rs is a root daemon whose job is to power the machine off. The findings
that matter most:

- **Kill-path bypass or stall** — any way to make an unauthorized USB change
  *not* fire, or to delay the poweroff once a kill decision is made (invariant
  1).
- **Disarm without the socket command** — anything that lowers protection
  without an authenticated `Disarm` over the control socket: a signal, a crash,
  a config reload, a resource-exhaustion state that makes `Disarm` unreachable
  (invariant 5).
- **Config-validation escape** — a config that should be rejected but arms
  anyway, or a `luks_destroy` target that resolves somewhere it should not
  (invariant 2).
- **Control-socket authorization** — any non-root peer reaching a privileged
  command, or the socket being created with a weaker mode/owner than
  `0660 root:root` for any window.
- **Privilege** — the daemon acquiring more than `CAP_SYS_BOOT`, or the systemd
  unit's sandbox being escapable in a way that matters.
- **Untrusted-input parsing** — the netlink uevent parser or the control-frame
  codec mishandling hostile bytes.

## Not in scope

- **`luks_destroy` not wiping anything.** It is a deliberate stub in v1
  (invariant 3). "It didn't destroy the header" is expected behaviour, not a
  vulnerability.
- **Physical attacks that don't involve USB** and are outside the threat model
  (charter §2): cold-boot RAM extraction, a debugger on an unlocked machine,
  etc. The tool's job is to get the machine powered off quickly so the LUKS disk
  re-locks; what happens to a *running, unlocked* machine is out of its remit.
- **Denial of service by someone who is already root** on the machine. The
  threat model is a single trusted operator; root can always stop the daemon.

## Verifying release artifacts

Every release attaches `SHA256SUMS` and a detached minisign signature for each
file. The signing public key (minisign key ID `C03C331F753B2D0D`) is:

```
untrusted comment: minisign public key C03C331F753B2D0D
RWQNLTt1HzM8wP1YLZXT+/3VnT8s2t8ZA+UvQRXCZ8ze8Eqjc3ZHW1dK
```

```bash
minisign -Vm SHA256SUMS -P RWQNLTt1HzM8wP1YLZXT+/3VnT8s2t8ZA+UvQRXCZ8ze8Eqjc3ZHW1dK
sha256sum -c SHA256SUMS
```

The secret key is held offline by the maintainer and is never on a build or
development machine. If the key is ever rotated, the new key is announced in a
release and committed here in the same change.

## Design guarantees

The threat model, the invariants, and the reasoning behind each are in
`PROJECT_CHARTER.md` (§2, §3, §12) and `CONTRIBUTING.md`. There is no network
activity and no telemetry — the only IPC is the local Unix socket.
