#!/bin/sh
# killbill-rs universal uninstaller — reverses packaging/install.sh.
#
#   sudo ./uninstall.sh            remove binaries, unit, man pages; keep /etc/killbill
#   sudo ./uninstall.sh --purge    also remove /etc/killbill
#
# Reads the manifest install.sh wrote. Does not touch anything a native package
# manager owns.

set -eu
unset CDPATH

MANIFEST="/usr/local/share/killbill-rs/install-manifest.txt"
CONFIG_DIR="/etc/killbill"
PURGE=0

die() { echo "uninstall.sh: $*" >&2; exit 1; }

case "${1:-}" in
	--purge) PURGE=1 ;;
	"") ;;
	-h | --help) echo "Usage: sudo ./uninstall.sh [--purge]"; exit 0 ;;
	*) die "unrecognized argument '$1'" ;;
esac

[ "$(id -u)" -eq 0 ] || die "must run as root"

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl disable --now killbilld.service >/dev/null 2>&1 || true
fi

if [ -f "$MANIFEST" ]; then
	while IFS= read -r path; do
		[ -n "$path" ] || continue
		if [ -e "$path" ] || [ -L "$path" ]; then
			rm -f "$path" && echo "removed $path"
		fi
	done < "$MANIFEST"
	rm -f "$MANIFEST"
	# Tidy now-empty dirs we created.
	rmdir -p /usr/local/share/killbill-rs 2>/dev/null || true
else
	echo "uninstall.sh: no manifest at $MANIFEST — removing known paths"
	for p in \
		/usr/local/bin/killbilld /usr/local/bin/killbillctl /usr/local/bin/killbill-tui \
		/usr/bin/killbilld /usr/bin/killbillctl /usr/bin/killbill-tui \
		/etc/systemd/system/killbilld.service; do
		[ -e "$p" ] && rm -f "$p" && echo "removed $p"
	done
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi

if [ "$PURGE" -eq 1 ]; then
	rm -rf "$CONFIG_DIR" && echo "removed $CONFIG_DIR"
else
	[ -d "$CONFIG_DIR" ] && echo "kept $CONFIG_DIR (use --purge to remove)"
fi

echo "uninstall.sh: done."
