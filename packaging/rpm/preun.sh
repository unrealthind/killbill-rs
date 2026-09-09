#!/bin/sh
# killbill-rs .rpm %preun. See packaging/scripts/lib.sh for the contract.
# $1 == 0 : final erase.   $1 >= 1 : upgrade (leave the running daemon alone).
set -e

if [ "$1" -eq 0 ]; then
	if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
		systemctl --no-reload disable killbilld.service >/dev/null 2>&1 || true
		systemctl stop killbilld.service || true
	fi
fi

exit 0
