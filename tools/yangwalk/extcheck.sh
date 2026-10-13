#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# The extensions the generator must read, found by yangwalk through
# libyang's extension plugins in the modules of a directory: sx:structure
# and the data nodes it holds, sx:augment-structure and the nodes it puts
# into its target, yangmnt:mount-point, nacm:default-deny-write and
# -all, and sn:subscription-state-notification.  No module of Arcana's
# corpus augments a structure, so yangwalk-augment-structure.yang, beside
# this script, does.
#
#	extcheck.sh yangwalk dir

set -eu

yw=$1
dir=$2
fixture=$(cd "$(dirname "$0")" && pwd)/yangwalk-augment-structure.yang
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cd "$dir"
"$yw" -p . $(grep -l '^module ' *.yang) "$fixture" > "$tmp/walk"
fail=0
for e in ietf-yang-structure-ext:structure \
    ietf-yang-structure-ext:augment-structure \
    ietf-yang-schema-mount:mount-point \
    ietf-netconf-acm:default-deny-write \
    ietf-netconf-acm:default-deny-all \
    ietf-subscribed-notifications:subscription-state-notification; do
	n=$(awk -v e="$e" '$2 == "extension" && $4 == e && $NF != "inherited"' \
	    "$tmp/walk" | wc -l)
	i=$(awk -v e="$e" '$2 == "extension" && $4 == e && $NF == "inherited"' \
	    "$tmp/walk" | wc -l)
	echo "$e: $n, $i inherited"
	[ "$n" -gt 0 ] || fail=1
done
# A structure's nodes, and the augmenting one among them.
s=$(grep -c ' {ietf-yang-structure-ext:structure ' "$tmp/walk" || true)
echo "nodes in structures: $s"
[ "$s" -gt 0 ] || fail=1
grep -q '^yangwalk-augment-structure leaf {ietf-yang-structure-ext:structure sid-file}/ietf-sid-file:item/yangwalk-augment-structure:note ' "$tmp/walk" ||
    { echo "the augmenting leaf is not in the structure" >&2; fail=1; }
# Where the mount points are.
awk '$2 == "extension" && $4 == "ietf-yang-schema-mount:mount-point" {
    print "  mount-point", $5, "at", $3 }' "$tmp/walk"
exit $fail
