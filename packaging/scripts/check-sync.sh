#!/bin/sh
# Fail if any packaging scriptlet's inlined copy of the maintainer-script
# contract has drifted from the canonical packaging/scripts/lib.sh.
#
# The .deb/.rpm scriptlets cannot source a file from the package payload, so
# each inlines the block between the "# >>> lib.sh" and "# <<< lib.sh" markers.
# This check keeps the copies honest. Run in CI.
set -eu
unset CDPATH

here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../.." && pwd)

# Print the lines strictly between the first "# >>> lib.sh" line and the
# following "# <<< lib.sh" line.
extract() {
	awk '
		/^# >>> lib\.sh/ { grab = 1; next }
		/^# <<< lib\.sh/ { grab = 0 }
		grab { print }
	' "$1"
}

canonical=$(extract "$root/packaging/scripts/lib.sh")
if [ -z "$canonical" ]; then
	echo "check-sync: no marker block found in packaging/scripts/lib.sh" >&2
	exit 2
fi

status=0
for f in \
	packaging/deb/postinst \
	packaging/deb/postrm \
	packaging/rpm/post.sh \
	packaging/rpm/postun.sh; do
	if [ "$(extract "$root/$f")" != "$canonical" ]; then
		echo "check-sync: $f has drifted from packaging/scripts/lib.sh" >&2
		status=1
	fi
done

# The AUR hook cannot inline the block (pacman needs its own function names), so
# it is checked for the one behaviour most easily lost in a hand edit: warning
# before an upgrade restart disarms a running armed daemon.
aur="$root/packaging/aur/killbill-rs.install"
for marker in "killbilld is ARMED" "failed to start"; do
	if ! grep -q "$marker" "$aur"; then
		echo "check-sync: packaging/aur/killbill-rs.install is missing: $marker" >&2
		status=1
	fi
done

if [ "$status" -eq 0 ]; then
	echo "check-sync: all inlined copies match packaging/scripts/lib.sh"
fi
exit "$status"
