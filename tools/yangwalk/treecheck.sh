#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# yangwalk against yanglint, for every module of a directory compiled
# together:
#
#  - against yanglint -f info, which prints the compiled schema: the
#    nodes in each module's tree, augments into it included, must be the
#    same kind for kind and name for name, as many times;
#  - against yanglint -f tree, which prints the module as written: every
#    node the tree shows the module defining must be among those the walk
#    finds it defining.  The tree keeps a grouping used in an augment as
#    one "-u" line and prints an augment once; the compiled schema has
#    the grouping's nodes, wherever it is used, so that direction is a
#    subset.
#
# Left out of both: structures and yang-data (extension instances, not
# the data tree), and empty input and output, which the compiled schema
# has and the printers do not show.  /ietf-netconf:rpc-error, which
# libyang adds to ietf-netconf for parsing NETCONF replies, is in the
# compiled schema and not in the module's tree.
#
#	treecheck.sh yangwalk dir

set -eu

yw=$1
dir=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cd "$dir"
mains=$(grep -l '^module ' *.yang)
"$yw" -p . $mains > "$tmp/walk"
yanglint -i -p . -f info $mains > "$tmp/info"
fail=0
n=0
for f in $mains; do
	m=$(sed -n '1s/^module \([^ ]*\).*/\1/p' "$f")
	n=$((n + 1))

	# The compiled tree of m: by the first step of each path.
	awk -v m="$m" '$2 != "extension" && index($3, "/" m ":") == 1 &&
	    !(($2 == "input" || $2 == "output") && $4 == "empty") {
	    k = split($3, p, "/");
	    s = p[k]; sub(/^[^:]*:/, "", s); print $2, s }' "$tmp/walk" |
	    sort > "$tmp/a"
	awk -v m="$m" 'function quotes(l) { gsub(/\\./, "", l);
	        return gsub(/"/, "", l) }
	    /^module / { cur = $2; depth = 0; next }
	    cur != m { next }
	    instr { if (quotes($0) % 2) instr = 0; next }
	    quotes($0) % 2 { instr = 1 }
	    /^ *[a-z0-9-]+:[a-z-]+ "[^"]*" \{$/ { skip = 1 }
	    skip { o = gsub(/\{/, "{"); c = gsub(/\}/, "}");
	        depth += o - c; if (depth <= 0) { skip = 0; depth = 0 }; next }
	    /^ *(input|output) \{$/ { print $1, $1; next }
	    /^ *(container|leaf|leaf-list|list|choice|case|anydata|anyxml|rpc|action|notification) [^ ]+ \{/ {
	        print $1, $2 }' "$tmp/info" | sort > "$tmp/b"
	if ! cmp -s "$tmp/a" "$tmp/b"; then
		echo "$m: $(wc -l < "$tmp/a") walked, $(wc -l < "$tmp/b")" \
		    "in yanglint -f info"
		diff "$tmp/a" "$tmp/b" | head -5
		fail=1
	fi

	# What m defines, by the walk's owner, against the tree.
	awk -v m="$m" '$1 == m && $2 != "extension" &&
	    $3 !~ /^\/ietf-netconf:rpc-error/ {
	    k = split($3, p, "/"); s = p[k];
	    sub(/^[^:]*:/, "", s); print s }' "$tmp/walk" | sort -u > "$tmp/c"
	yanglint -i -p . -f tree "$f" | awk '
	    /^  [a-z].*:$/ { skip = ($1 == "structure" ||
	        $1 == "augment-structure" || $1 == "yang-data"); next }
	    /^[a-z]/ { skip = 0 }
	    !skip && /^[ |]*[+xo]--/ && !/^[ |]*[+xo]---u / { s = $0;
	        sub(/^[ |]*[+xo]--+[a-z]*[ :]*/, "", s); sub(/[ ].*/, "", s);
	        gsub(/[()?!*]/, "", s); sub(/^[^:]*:/, "", s); print s }' |
	    sort -u > "$tmp/d"
	if [ -n "$(comm -13 "$tmp/c" "$tmp/d")" ]; then
		echo "$m: in the tree, not walked:" $(comm -13 "$tmp/c" "$tmp/d")
		fail=1
	fi
done
nodes=$(awk '$2 != "extension" && $3 ~ /^\// && $1 != "module" &&
    $1 != "feature" && $1 != "deviated-by"' "$tmp/walk" | wc -l)
[ $fail -eq 0 ] && echo "$n modules, $nodes nodes: the walk agrees with" \
    "yanglint's compiled schema and its trees"
exit $fail
