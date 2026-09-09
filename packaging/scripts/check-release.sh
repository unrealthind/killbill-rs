#!/bin/sh
# Release-readiness gate for the packaging tree. Unlike check-sync.sh (which
# runs on every push), this is meant to run only when cutting a tag — it fails
# on placeholders that are fine during development but must be resolved before
# a signed release is published.
#
# Wire this into the release workflow (packaging sub-phase 9), not push CI.
set -eu
unset CDPATH

here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../.." && pwd)
status=0

fail() {
	echo "check-release: $*" >&2
	status=1
}

pkgbuild="$root/packaging/aur/PKGBUILD"

# The AUR PKGBUILD must carry a real tarball digest, not the 'SKIP' placeholder:
# killbilld runs as root, and 'SKIP' means the build trusts whatever the
# download server returned.
if grep -qE "^sha256sums=\(.*SKIP" "$pkgbuild"; then
	fail "packaging/aur/PKGBUILD still has a SKIP digest — run updpkgsums against the release tarball"
fi

# pkgver in the PKGBUILD must match the workspace version. Unreadable = fail,
# not skip: this is a release gate.
ws_ver=$(sed -n 's/^version = "\([0-9][^"]*\)".*/\1/p' "$root/Cargo.toml" | head -n1)
pb_ver=$(sed -n "s/^pkgver=//p" "$pkgbuild" | head -n1)
[ -n "$ws_ver" ] || fail "could not read the workspace version from Cargo.toml"
[ -n "$pb_ver" ] || fail "could not read pkgver from packaging/aur/PKGBUILD"
if [ -n "$ws_ver" ] && [ -n "$pb_ver" ] && [ "$ws_ver" != "$pb_ver" ]; then
	fail "PKGBUILD pkgver ($pb_ver) != workspace version ($ws_ver)"
fi

if [ "$status" -eq 0 ]; then
	echo "check-release: packaging is release-ready"
fi
exit "$status"
