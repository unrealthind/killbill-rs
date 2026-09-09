#!/bin/sh
# killbill-rs universal installer — the fallback when no native package fits.
#
#   From an unpacked release tarball:   sudo ./install.sh
#   From a source checkout:             sudo packaging/install.sh --from-build
#
# Installs killbilld / killbillctl / killbill-tui under a prefix (default
# /usr/local), a hardened systemd unit at /etc/systemd/system/killbilld.service
# with ExecStart pointed at the prefix, man pages, and a default config at
# /etc/killbill/config.toml ONLY if one is not already there. Enables and
# starts the daemon DISARMED. Never arms.
#
# Requires: root, systemd, a POSIX sh, coreutils (install, sed).

set -eu
unset CDPATH

PREFIX="${PREFIX:-/usr/local}"
MODE="tarball"
CONFIG_DIR="/etc/killbill"
CONFIG="${CONFIG_DIR}/config.toml"
UNIT="/etc/systemd/system/killbilld.service"
MANIFEST="/usr/local/share/killbill-rs/install-manifest.txt"

die() { echo "install.sh: $*" >&2; exit 1; }

usage() {
	cat <<EOF
Usage: sudo ./install.sh [--from-build] [--prefix DIR]

  --from-build     install from ./target/release of a source checkout
                   (default: install from files next to this script)
  --prefix DIR     install binaries under DIR/bin (default: /usr/local)
EOF
	exit "${1:-0}"
}

while [ $# -gt 0 ]; do
	case "$1" in
		--from-build) MODE="build" ;;
		--prefix) shift; [ $# -gt 0 ] || die "--prefix needs a directory"; PREFIX="$1" ;;
		--prefix=*) PREFIX="${1#--prefix=}" ;;
		-h | --help) usage 0 ;;
		*) die "unrecognized argument '$1' (try --help)" ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -d /run/systemd/system ] || die "systemd is required (no other init is supported)"
command -v install >/dev/null 2>&1 || die "coreutils 'install' not found"

# --prefix ends up in the ExecStart= of a root systemd unit, so a user-writable
# prefix is root code execution at the next boot or restart (Phase 1 hardware
# run: "never point a unit's ExecStart at a path under a user's home").
case "$PREFIX" in
	/*) ;;
	*) die "--prefix must be an absolute path" ;;
esac
# -P: resolve symlinks, so the deny-list and the perm checks see the real path.
_pp=$(cd -P -- "$(dirname -- "$PREFIX")" 2>/dev/null && pwd -P) ||
	die "--prefix parent does not exist: $(dirname -- "$PREFIX")"
_prefix_real="${_pp%/}/$(basename -- "$PREFIX")"
case "$_prefix_real/" in
	/home/* | /root/* | /tmp/* | /var/tmp/* | /dev/shm/*)
		die "refusing --prefix under a user-writable tree: $_prefix_real" ;;
esac
# The prefix (or its parent, if it does not exist yet) must be root-owned and
# not group/other-writable. One tool, one failure mode: stat fails closed.
_check="$_prefix_real"; [ -d "$_check" ] || _check="$_pp"
_perm=$(stat -c '%u %a' "$_check") || die "cannot stat $_check — refusing"
set -- $_perm
[ "$1" = 0 ] || die "$_check is not root-owned (uid $1) — refusing"
case "$2" in
	*[2367]) die "$_check is other-writable (mode $2) — refusing" ;;
esac
case "$2" in
	*[2367]?) die "$_check is group-writable (mode $2) — refusing" ;;
esac
PREFIX="$_prefix_real"

here=$(cd -- "$(dirname -- "$0")" && pwd)

# Resolve the source layout.
if [ "$MODE" = "build" ]; then
	repo=$(cd -- "$here/.." && pwd)
	bindir="${CARGO_TARGET_DIR:-$repo/target}/release"
	unit_src="$repo/packaging/systemd/killbilld.service"
	dropin_src="$repo/packaging/systemd/killbilld.service.d/luks-destroy.conf.example"
	man_dir="$repo/packaging/man"
	example_src="$repo/config.example.toml"
	license_src="$repo/LICENSE"
else
	bindir="$here/bin"
	unit_src="$here/systemd/killbilld.service"
	dropin_src="$here/systemd/killbilld.service.d/luks-destroy.conf.example"
	man_dir="$here/man"
	example_src="$here/config.example.toml"
	license_src="$here/LICENSE"
fi

for b in killbilld killbillctl killbill-tui; do
	[ -x "$bindir/$b" ] || die "missing $bindir/$b — build first, or run without --from-build"
done
[ -f "$unit_src" ] || die "missing $unit_src"
[ -f "$example_src" ] || die "missing $example_src"

echo "install.sh: prefix $PREFIX, unit $UNIT"

# --- binaries --------------------------------------------------------------
install -d -m 0755 "$(dirname -- "$MANIFEST")"
: > "$MANIFEST.tmp"
record() { echo "$1" >> "$MANIFEST.tmp"; }

for b in killbilld killbillctl killbill-tui; do
	install -Dm755 "$bindir/$b" "$PREFIX/bin/$b"
	record "$PREFIX/bin/$b"
done

# --- man pages ------------------------------------------------------------
if [ -d "$man_dir" ]; then
	for m in "$man_dir"/*.[1-9]; do
		[ -f "$m" ] || continue
		sec=${m##*.}
		install -Dm644 "$m" "$PREFIX/share/man/man${sec}/$(basename "$m")"
		record "$PREFIX/share/man/man${sec}/$(basename "$m")"
	done
fi

# --- shared files -------------------------------------------------------
install -Dm644 "$example_src" "$PREFIX/share/killbill-rs/config.example.toml"
record "$PREFIX/share/killbill-rs/config.example.toml"
if [ -f "$dropin_src" ]; then
	install -Dm644 "$dropin_src" \
		"$PREFIX/share/killbill-rs/killbilld.service.d/luks-destroy.conf.example"
	record "$PREFIX/share/killbill-rs/killbilld.service.d/luks-destroy.conf.example"
fi
[ -f "$license_src" ] && {
	install -Dm644 "$license_src" "$PREFIX/share/licenses/killbill-rs/LICENSE"
	record "$PREFIX/share/licenses/killbill-rs/LICENSE"
}

# --- systemd unit (ExecStart rewritten to the chosen prefix) -------------
tmp_unit=$(mktemp)
sed "s|^ExecStart=/usr/bin/killbilld|ExecStart=$PREFIX/bin/killbilld|" "$unit_src" > "$tmp_unit"
install -Dm644 "$tmp_unit" "$UNIT"
rm -f "$tmp_unit"
record "$UNIT"

# --- default config, only if absent -----------------------------------
install -d -m 0755 "$CONFIG_DIR"
if [ ! -e "$CONFIG" ]; then
	install -m 0640 "$example_src" "$CONFIG"
	echo "install.sh: wrote default config to $CONFIG (disarmed)"
else
	echo "install.sh: keeping existing $CONFIG"
fi

mv "$MANIFEST.tmp" "$MANIFEST"

# --- enable + start, DISARMED ----------------------------------------
systemctl daemon-reload
systemctl enable killbilld.service >/dev/null 2>&1 || true
if systemctl is-active --quiet killbilld.service; then
	# Re-install over a running daemon: pick up the new binary/unit. A restart
	# always comes back DISARMED (armed state is not persisted) — warn first.
	if command -v killbillctl >/dev/null 2>&1 &&
		timeout 5 killbillctl status 2>/dev/null | grep -qi '^armed: *yes'; then
		echo "install.sh: WARNING — killbilld is ARMED; the restart will leave it DISARMED." >&2
		echo "            Run 'sudo killbillctl arm' again once this finishes." >&2
	fi
	systemctl restart killbilld.service ||
		die "killbilld failed to restart — check: systemctl status killbilld"
elif ! systemctl start killbilld.service; then
	die "killbilld failed to start — the machine is NOT protected. Check: systemctl status killbilld"
fi

cat <<EOF

killbill-rs installed. The daemon is enabled and running, DISARMED.

  1. edit    $CONFIG        (add your [[whitelist]] devices)
  2. check   killbillctl status
  3. dry-run sudo killbillctl config set dry-run on && sudo killbillctl arm
  4. arm     sudo killbillctl config set dry-run off && sudo killbillctl arm

To remove: run uninstall.sh (it reads $MANIFEST).
EOF
