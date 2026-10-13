#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# cblink-gen's structs and schema tables for every module of a directory
# compiled together (PLAN-SDN-YANG 1.6.1, 1.6.2): each module numbered
# into a .sid file of its own first, in a range of its own (-a), its
# identities too, which identityref bases are keyed by; then -m
# h,schema over all of them, the two files compiled at -Wall -Werror,
# and what each module's tables come to printed.  The SIDs are made up
# for the check: a module's own .sid file, where it has one, is not
# used.  Then every struct, filled by the tables, through YANG-CBOR and
# back (PLAN-SDN-YANG 1.6.5): three passes, every optional leaf and only
# what must be, encoded, decoded, encoded again to the same bytes.
#
#	tablecheck.sh cblink-gen dir libcblink-src libcblink-obj

set -eu

gen=$1
dir=$2
inc=$3
lib=$4
fill=$(cd "$(dirname "$0")/../../usr.bin/cblink-gen/tests" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cd "$dir"
mains=$(grep -l '^module ' *.yang)
i=0
sids=
for f in $mains; do
	m=$(sed -n '1s/^module \([^ ]*\).*/\1/p' "$f")
	r=$(sed -n 's/^ *revision \([0-9-]*\).*/\1/p' "$f" | head -1)
	# From 2^40, 100 000 a module.
	entry=$((1099511627776 + i * 100000))
	printf '{"ietf-sid-file:sid-file": {"module-name": "%s",%s\n' \
	    "$m" "${r:+ \"module-revision\": \"$r\",}" > "$tmp/$m.sid"
	printf ' "assignment-range": [{"entry-point": "%s", "size": ' \
	    "$entry" >> "$tmp/$m.sid"
	printf '"100000"}]}}\n' >> "$tmp/$m.sid"
	"$gen" -n -a -p . -s "$tmp/$m.sid" "$f" > /dev/null
	sids="$sids -s $tmp/$m.sid"
	i=$((i + 1))
done
# shellcheck disable=SC2086
"$gen" -m h,schema -b corpus -o "$tmp" -p . $sids $mains
printf '#include "corpus.h"\n' > "$tmp/use.c"
for c in use.c corpus_schema.c; do
	cc -std=c23 -Wall -Wextra -Werror -Wshadow -Wcast-qual \
	    -Wwrite-strings -Wmissing-variable-declarations -I"$inc" \
	    -I"$tmp" -c "$tmp/$c" -o "$tmp/$c.o"
done
size "$tmp/corpus_schema.c.o"
echo "$i modules: structs and tables compiled"

cat > "$tmp/round.c" <<'EOF'
#include <stdio.h>

#include "corpus.h"
#include "yfill.h"

int
main(void)
{
	char why[512];
	size_t n, bad;

	bad = yround_all(&corpus_schema, &n, why, sizeof(why));
	printf("%zu round trips, %zu not the same\n", n, bad);
	return (bad != 0);
}
EOF
cc -std=c23 -Wall -Werror -I"$inc" -I"$tmp" -I"$fill" -o "$tmp/round" \
    "$tmp/round.c" "$fill/yfill.c" "$tmp/corpus_schema.c.o" -L"$lib" \
    -lcblink
LD_LIBRARY_PATH="$lib" "$tmp/round"
