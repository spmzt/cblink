#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# cblink-gen: golden files, determinism, every validation error with its
# exact location, malformed YAML, the committed control family,
# cblink.mk, and the YANG front end.
#

# The generator under test is installed next to this script.
gen=

setup()
{
	gen="$(atf_get_srcdir)/cblink-gen"
}

atf_test_case golden
golden_head()
{
	atf_set "descr" "Generated output matches the golden files"
}
golden_body()
{
	setup

	for spec in types kv; do
		mkdir "out_${spec}"
		atf_check $gen -o "out_${spec}" \
		    "$(atf_get_srcdir)/golden/${spec}.yaml"
		for f in "$(atf_get_srcdir)/golden/${spec}"/*; do
			atf_check -o file:"${f}" cat "out_${spec}/${f##*/}"
		done
		atf_check -o inline:"5\n" \
		    sh -c "ls out_${spec} | wc -l | tr -d ' '"
	done
}

atf_test_case determinism
determinism_head()
{
	atf_set "descr" "The same spec gives byte-identical output"
}
determinism_body()
{
	setup
	mkdir a b
	atf_check $gen -o a "$(atf_get_srcdir)/golden/types.yaml"
	atf_check $gen -o b "$(atf_get_srcdir)/golden/types.yaml"
	atf_check diff -r a b
	# The output does not depend on where the spec lives.
	mkdir -p c sub/dir
	cp "$(atf_get_srcdir)/golden/types.yaml" sub/dir/
	atf_check $gen -o c sub/dir/types.yaml
	atf_check diff -r a c
}

atf_test_case errors
errors_head()
{
	atf_set "descr" "Validation and YAML errors, with exact locations"
}
errors_body()
{
	setup
	n=0

	for f in "$(atf_get_srcdir)"/errors/*.yaml; do
		atf_check -s exit:1 -e file:"${f%.yaml}.err" $gen -n "${f}"
		n=$((n + 1))
	done
	[ "${n}" -ge 40 ] || atf_fail "only ${n} error cases found"
}

# Written here, not stored: a stored CRLF file is at the mercy of git's
# end-of-line conversion (core.autocrlf), which would quietly make it LF.
atf_test_case crlf
crlf_head()
{
	atf_set "descr" "CRLF line endings are refused with their location"
}
crlf_body()
{
	setup

	printf 'name: t\r\nversion: 1\r\n' > crlf.yaml
	msg="crlf.yaml:1:8: error: carriage return; use LF line endings"
	atf_check -s exit:1 -e inline:"${msg}\n" $gen -n crlf.yaml
}

atf_test_case ctrl_regen
ctrl_regen_head()
{
	atf_set "descr" "The committed control family matches its spec"
}
ctrl_regen_body()
{
	setup

	mkdir out
	atf_check $gen -B -b cbl_ctrl_gen -m h,c,client,server -o out \
	    "$(atf_get_srcdir)/ctrl/control.yaml"
	for f in cbl_ctrl_gen.h cbl_ctrl_gen.c cbl_ctrl_gen_client.c \
	    cbl_ctrl_gen_server.c; do
		atf_check -o file:"$(atf_get_srcdir)/ctrl/${f}" cat "out/${f}"
	done
	# Its reference documentation, committed as docs/ctrl.md.
	atf_check $gen -B -b ctrl -m md -o out \
	    "$(atf_get_srcdir)/ctrl/control.yaml"
	atf_check -o file:"$(atf_get_srcdir)/ctrl/ctrl.md" cat out/ctrl.md
	# Without -B the reserved name and fixed id are refused.
	atf_check -s exit:1 -e match:"reserved" $gen -n \
	    "$(atf_get_srcdir)/ctrl/control.yaml"
}

atf_test_case ymod_regen
ymod_regen_head()
{
	atf_set "descr" "The committed cblink module's structs and tables" \
	    "match the module (wire version 2's framework)"
}
ymod_regen_body()
{
	setup
	y="$(atf_get_srcdir)/yang"

	if $gen -n "$y/cblink@2026-10-13.yang" 2>&1 |
	    grep -q 'needs cblink-gen built with libyang'; then
		atf_skip "cblink-gen built without libyang"
	fi
	mkdir out
	atf_check -o ignore $gen -m h,schema -b cbl_ymod -o out \
	    -s "$y/cblink@2026-10-13.sid" "$y/cblink@2026-10-13.yang"
	for f in cbl_ymod.h cbl_ymod_schema.c; do
		atf_check -o file:"$(atf_get_srcdir)/ctrl/${f}" cat "out/${f}"
	done
}

atf_test_case cli
cli_head()
{
	atf_set "descr" "Command line handling"
}
cli_body()
{
	setup
	atf_check -o match:"^cblink-gen [0-9]" $gen -V
	atf_check -s exit:2 -e match:"usage" $gen
	atf_check -s exit:2 -e match:"usage" $gen -x foo.yaml
	atf_check -s exit:2 -e match:"nosuch.yaml" $gen nosuch.yaml
	atf_check -s exit:2 -e match:"not a regular file" $gen -n .
	mkdir out
	atf_check $gen -m h -o out "$(atf_get_srcdir)/golden/kv.yaml"
	atf_check -o inline:"kv.h\n" ls out
	atf_check $gen -m md -b other -o out \
	    "$(atf_get_srcdir)/golden/kv.yaml"
	atf_check -o inline:"kv.h\nother.md\n" ls out
	atf_check -s exit:2 -e match:"invalid output base" $gen -b a/b -o out \
	    "$(atf_get_srcdir)/golden/kv.yaml"
	atf_check -s exit:2 -e ignore $gen -o nosuchdir \
	    "$(atf_get_srcdir)/golden/kv.yaml"
	# -n checks without writing anything.
	mkdir empty
	atf_check -o empty $gen -n -o empty "$(atf_get_srcdir)/golden/kv.yaml"
	atf_check -o empty ls empty
}

atf_test_case big_input
big_input_head()
{
	atf_set "descr" "Oversized spec files are refused"
}
big_input_body()
{
	setup
	dd if=/dev/zero bs=1024 count=1100 2>/dev/null | tr '\0' '#' > big.yaml
	atf_check -s exit:1 -e match:"too large" $gen -n big.yaml
}

atf_test_case cblink_mk
cblink_mk_head()
{
	atf_set "descr" \
	    "cblink.mk finds specs given relative, with ../, or absolute"
	atf_set "require.progs" "make"
}
cblink_mk_body()
{
	setup
	# Build here, whatever object directory the caller's make uses.
	unset MAKEOBJDIRPREFIX MAKEOBJDIR

	mkdir prog specs
	cp "$(atf_get_srcdir)/golden/kv.yaml" prog/rel.yaml
	cp "$(atf_get_srcdir)/golden/kv.yaml" up.yaml
	cp "$(atf_get_srcdir)/golden/kv.yaml" specs/abs.yaml
	cat > prog/Makefile <<EOF
CBLINK_SPECS=	rel.yaml ../up.yaml $(pwd)/specs/abs.yaml
CBLINK_GEN=	${gen}
.include "$(atf_get_srcdir)/cblink.mk"
EOF
	for s in rel up abs; do
		atf_check -o ignore -e ignore make -C prog ${s}.h
		atf_check test -s prog/${s}.h -a -s prog/${s}_server.c
	done
}

atf_test_case yang_frontend
yang_frontend_head()
{
	atf_set "descr" "A YANG module is compiled through libyang, or" \
	    "refused by a generator built without it"
}
yang_frontend_body()
{
	setup
	y="$(atf_get_srcdir)/yang"

	if $gen -n "$y/good@2026-10-13.yang" 2>&1 |
	    grep -q 'needs cblink-gen built with libyang'; then
		atf_check -s exit:2 -e match:'CBLINK_GEN_LIBYANG=yes' \
		    $gen -n "$y/good@2026-10-13.yang"
		return
	fi
	# Its import, ietf-yang-types, is libyang's own.
	atf_check -o match:'^good@2026-10-13.yang: compiled, .* schema nodes' \
	    $gen -n "$y/good@2026-10-13.yang"
	# The generator's model of it, a node a line.
	atf_check -o save:dump $gen -d "$y/good@2026-10-13.yang"
	atf_check -o inline:"good container /good:things rw
good list /good:things/thing rw min 0 max 4294967295
good leaf /good:things/thing/name rw key string length 1..63
" grep '^good [a-z]* /good:things\(/thing\(/name\)\{0,1\}\)\{0,1\} ' dump
	# A typedef's name and its pattern, whichever revision libyang has.
	atf_check -o match:"^good leaf /good:things/thing/seen rw string\(date-and-time\) pattern '" \
	    cat dump
	atf_check -o match:'^module good@2026-10-13$' cat dump
	atf_check -s exit:1 -e match:'^bad@2026-10-13.yang:.*uint33' \
	    $gen -n "$y/bad@2026-10-13.yang"
	# Features: all on without -F, as named with it; what a disabled one
	# guards is left out, identities too.
	atf_check -o match:'/good:things/thing/extra rw identityref base good:kind$' \
	    $gen -d "$y/good@2026-10-13.yang"
	atf_check -o match:'^feature extra off$' -o not-match:'/extra ' \
	    $gen -d -F good: "$y/good@2026-10-13.yang"
	atf_check -o match:'^feature extra on$' -o match:'/thing/extra ' \
	    $gen -d -F good:extra "$y/good@2026-10-13.yang"
	atf_check -s exit:1 -e match:'Feature "nope" not found' \
	    $gen -n -F good:nope "$y/good@2026-10-13.yang"
	atf_check -s exit:1 -e match:"no module nosuch implemented" \
	    $gen -n -F nosuch:x "$y/good@2026-10-13.yang"
	# A deviation applied, and said.
	atf_check -o match:'^deviated-by good-dev$' -o not-match:'/seen ' \
	    $gen -d "$y/good@2026-10-13.yang" "$y/good-dev@2026-10-13.yang"
	# Extensions: a structure and its nodes, a mount point.
	atf_check -o save:ext $gen -d "$y/ext@2026-10-13.yang"
	atf_check -o inline:"ext extension /ext:root ietf-yang-schema-mount:mount-point inner
ext extension ext ietf-yang-structure-ext:structure note
ext leaf {ietf-yang-structure-ext:structure note}/ext:text ro string
" grep '^ext .*\(extension\|{\)' ext
	# XPath beyond XPath-lite is refused, at its node.
	atf_check -s exit:1 -e match:'^beyond@2026-10-13.yang:.*/beyond:item/first: must "position\(\) = 1": outside XPath-lite: the function position\(\)' \
	    $gen -n "$y/beyond@2026-10-13.yang"
	# .sid files (RFC 9595): its own example, read and attached whole,
	# but short of the SIDs Appendix B says empty input and output MUST
	# have; -a gives them theirs, in its order, after the last SID taken,
	# and a new version; again, it changes nothing.
	atf_check -s exit:1 -e match:'data /ietf-system:set-current-datetime/output: no SID' \
	    $gen -n -s "$y/ietf-system@2014-08-06.sid" \
	    "$y/ietf-system@2014-08-06.yang"
	cat "$y/ietf-system@2014-08-06.sid" > full.sid
	atf_check -o match:'^full.sid: 5 SIDs assigned, version 1$' \
	    $gen -n -a -s full.sid "$y/ietf-system@2014-08-06.yang"
	atf_check -o match:', 81 SIDs from 1 .sid files$' $gen -n \
	    -s full.sid "$y/ietf-system@2014-08-06.yang"
	atf_check -o match:'"sid-file-version": 1,' cat full.sid
	atf_check -o match:'"identifier": "/ietf-system:system-restart/input",' \
	    cat full.sid
	cp full.sid again.sid
	atf_check -o match:', 81 SIDs from 1 .sid files$' $gen -n -a \
	    -s again.sid "$y/ietf-system@2014-08-06.yang"
	atf_check cmp full.sid again.sid
	# From nothing but a range, the module first.
	cat > empty.sid <<-EOF
	{"ietf-sid-file:sid-file": {"module-name": "ietf-system",
	 "module-revision": "2014-08-06",
	 "assignment-range": [{"entry-point": "60000", "size": "100"}]}}
	EOF
	atf_check -o match:'^empty.sid: 81 SIDs assigned, version 0$' \
	    $gen -n -a -s empty.sid "$y/ietf-system@2014-08-06.yang"
	atf_check -o match:'"namespace": "module",.*"identifier": "ietf-system",.*"sid": "60000"' \
	    tr -d '\n' < empty.sid
	# Ranges too small for the module: refused, the file left alone.
	cat > small.sid <<-EOF
	{"ietf-sid-file:sid-file": {"module-name": "ietf-system",
	 "assignment-range": [{"entry-point": "60000", "size": "10"}]}}
	EOF
	cp small.sid small.orig
	atf_check -s exit:1 -e match:'ranges are full: 71 items left' \
	    $gen -n -a -s small.sid "$y/ietf-system@2014-08-06.yang"
	atf_check cmp small.sid small.orig
	# An item the module does not have, refused.
	sed 's|/ietf-system:system/contact|/ietf-system:system/kontakt|' \
	    "$y/ietf-system@2014-08-06.sid" > bad.sid
	atf_check -s exit:1 -e match:'^bad.sid:.*data /ietf-system:system/kontakt: not in ietf-system' \
	    $gen -n -s bad.sid "$y/ietf-system@2014-08-06.yang"
	# Verified: a SID given twice, one outside the file's range, an
	# item left without one.
	sed 's|"sid": "1702"|"sid": "1701"|' "$y/ietf-system@2014-08-06.sid" \
	    > twice.sid
	atf_check -s exit:1 -e match:'SID 1701 given to identity' \
	    $gen -n -s twice.sid "$y/ietf-system@2014-08-06.yang"
	sed 's|"sid": "1702"|"sid": "1900"|' "$y/ietf-system@2014-08-06.sid" \
	    > outside.sid
	atf_check -s exit:1 -e match:'SID 1900 outside the file.s assignment ranges' \
	    $gen -n -s outside.sid "$y/ietf-system@2014-08-06.yang"
	# (an item's object, its braces alone on their lines, six spaces in,
	# dropped whole)
	awk '/^      \{$/ { buf = $0; inb = 1; next }
	    inb { buf = buf "\n" $0 }
	    inb && /^      \},?$/ { inb = 0;
	        if (buf !~ /"\/ietf-system:system\/contact"/) print buf; next }
	    !inb { print }' "$y/ietf-system@2014-08-06.sid" > missing.sid
	atf_check -s exit:1 -e match:'data /ietf-system:system/contact: no SID' \
	    $gen -n -s missing.sid "$y/ietf-system@2014-08-06.yang"
	echo '{"x": 1}' > notsid.sid
	atf_check -s exit:1 -e match:'no "ietf-sid-file:sid-file" object' \
	    $gen -n -s notsid.sid "$y/ietf-system@2014-08-06.yang"
	# A pattern beyond what cblink matches is refused, at its node.
	atf_check -s exit:1 -e match:"^subtract@2026-10-13.yang:.*/subtract:consonants: pattern '\\[a-z-\\[aeiou\\]\\]\\+': outside what cblink matches: class subtraction" \
	    $gen -n "$y/subtract@2026-10-13.yang"
	# A module file's name says its module.
	cp "$y/good@2026-10-13.yang" ".yang"
	atf_check -s exit:2 -e match:'not a YANG module file' $gen -n .yang
	# Without -m: C generation from YANG is not all written yet.
	atf_check -s exit:2 -e match:'not written yet but for -m h,md,schema,server,sid,sidjson,tree' \
	    $gen -o . "$y/good@2026-10-13.yang"
}

atf_test_case sid_cbor
sid_cbor_head()
{
	atf_set "descr" "A .sid file written in YANG-CBOR, as GET-SID" \
	    "answers it, decodes to the file; JSON written back is the same"
}
sid_cbor_body()
{
	setup
	y="$(atf_get_srcdir)/yang"
	m="$y/ietf-system@2014-08-06.yang"

	if $gen -n "$y/good@2026-10-13.yang" 2>&1 |
	    grep -q 'needs cblink-gen built with libyang'; then
		atf_skip "cblink-gen built without libyang"
	fi
	# ietf-sid-file's own SIDs: IANA's range, numbered by Appendix B,
	# and the ones the encoder keys by.
	cat "$y/ietf-sid-file@2024-07-31.sid" > sf.sid
	atf_check -o match:', 18 SIDs from 1 .sid files$' $gen -n -a \
	    -s sf.sid "$y/ietf-sid-file@2024-07-31.yang"
	atf_check cmp sf.sid "$y/ietf-sid-file@2024-07-31.sid"
	awk -F'"' '/"identifier"/ { id = $4 } /"sid"/ { print $4, id }' \
	    sf.sid > sids
	cat > sids.want <<-EOF
	1300 ietf-sid-file
	1301 /ietf-sid-file:sid-file
	1302 /ietf-sid-file:sid-file/assignment-range
	1303 /ietf-sid-file:sid-file/assignment-range/entry-point
	1304 /ietf-sid-file:sid-file/assignment-range/size
	1305 /ietf-sid-file:sid-file/dependency-revision
	1306 /ietf-sid-file:sid-file/dependency-revision/module-name
	1307 /ietf-sid-file:sid-file/dependency-revision/module-revision
	1308 /ietf-sid-file:sid-file/description
	1309 /ietf-sid-file:sid-file/item
	1310 /ietf-sid-file:sid-file/item/identifier
	1311 /ietf-sid-file:sid-file/item/namespace
	1312 /ietf-sid-file:sid-file/item/sid
	1313 /ietf-sid-file:sid-file/item/status
	1314 /ietf-sid-file:sid-file/module-name
	1315 /ietf-sid-file:sid-file/module-revision
	1316 /ietf-sid-file:sid-file/sid-file-status
	1317 /ietf-sid-file:sid-file/sid-file-version
	EOF
	atf_check cmp sids sids.want

	# RFC 9595's example, completed: JSON to CBOR and back, the same.
	cat "$y/ietf-system@2014-08-06.sid" > full.sid
	atf_check -o ignore $gen -n -a -s full.sid "$m"
	mkdir one two
	atf_check $gen -m sid,sidjson -o one -s full.sid "$m"
	atf_check cmp one/ietf-system@2014-08-06.sid full.sid
	# {1301: {...}}: a map of one, keyed by sid-file's SID.
	atf_check -o match:'^ *a1 +19 +05 +15 *$' \
	    od -A n -t x1 -N 4 one/ietf-system@2014-08-06.sid.cbor
	atf_check $gen -m sidjson -o two \
	    -s one/ietf-system@2014-08-06.sid.cbor "$m"
	atf_check cmp two/ietf-system@2014-08-06.sid full.sid
	# Read as the file, verified as the file.
	atf_check -o match:', 81 SIDs from 1 .sid files$' $gen -n \
	    -s one/ietf-system@2014-08-06.sid.cbor "$m"
	# A .sid file with a status per item and a file status.
	awk '{ print }
	    /"sid-file-version": 1,/ {
	        print "    \"sid-file-status\": \"unpublished\"," }
	    /"identifier": "ietf-system",/ && !done {
	        print "        \"status\": \"unstable\","; done = 1 }' \
	    full.sid > status.sid
	mkdir three
	atf_check $gen -m sid -o three -s status.sid "$m"
	atf_check $gen -m sidjson -o three \
	    -s three/ietf-system@2014-08-06.sid.cbor "$m"
	atf_check cmp three/ietf-system@2014-08-06.sid status.sid

	# Malformed: cut short, a byte after, a key twice, one unknown, an
	# indefinite length.
	c=one/ietf-system@2014-08-06.sid.cbor
	head -c 200 $c > short.cbor
	atf_check -s exit:1 -e match:'YANG-CBOR: truncated' \
	    $gen -n -s short.cbor "$m"
	{ cat $c; printf '\0'; } > after.cbor
	atf_check -s exit:1 -e match:'YANG-CBOR: bytes after the structure' \
	    $gen -n -s after.cbor "$m"
	printf '\241\031\005\025\242\015\141x\015\141y' > twice.cbor
	atf_check -s exit:1 -e match:'YANG-CBOR: a key given twice at byte 9$' \
	    $gen -n -s twice.cbor "$m"
	printf '\241\031\005\025\241\030\040\000' > unknown.cbor
	atf_check -s exit:1 -e match:'YANG-CBOR: a key not in ietf-sid-file' \
	    $gen -n -s unknown.cbor "$m"
	printf '\241\031\005\025\277\377' > indef.cbor
	atf_check -s exit:1 -e match:'YANG-CBOR: an indefinite length' \
	    $gen -n -s indef.cbor "$m"
	# Parts: only these yet, and only with a file.
	atf_check -s exit:2 -e match:'-m c: not written for YANG yet' \
	    $gen -m sid,c -s full.sid "$m"
	atf_check -s exit:2 -e match:'no -s file' $gen -m sid "$m"
}

atf_test_case yang_h
yang_h_head()
{
	atf_set "descr" "-m h writes the structs of the YANG modules named," \
	    "and refuses two nodes that would have one C name"
}
yang_h_body()
{
	setup
	y="$(atf_get_srcdir)/yang"

	if $gen -n "$y/good@2026-10-13.yang" 2>&1 |
	    grep -q 'needs cblink-gen built with libyang'; then
		atf_skip "cblink-gen built without libyang"
	fi
	# Named after the first module, or -b; the modules named only,
	# not what libyang implements of its own.
	atf_check $gen -m h "$y/ietf-system@2014-08-06.yang"
	atf_check -o match:'^struct ietf_system_system \{' cat ietf-system.h
	atf_check -o match:'^#ifndef _IETF_SYSTEM_H_$' cat ietf-system.h
	atf_check -s exit:1 -o empty grep -e ietf_yang_library ietf-system.h
	mkdir out
	atf_check $gen -m h -b both -o out "$y/good@2026-10-13.yang" \
	    "$y/shapes@2026-10-13.yang"
	atf_check -o match:'^struct good_things_thing \{' cat out/both.h
	atf_check -o match:'^struct shapes_note \{' cat out/both.h
	# Generating again: the same bytes.
	cp out/both.h both.before
	atf_check $gen -m h -b both -o out "$y/good@2026-10-13.yang" \
	    "$y/shapes@2026-10-13.yang"
	atf_check cmp out/both.h both.before
	# The schema tables: every node keyed by its SID, so a module's .sid
	# file is wanted; what each module's tables come to is said.
	atf_check -s exit:1 -e match:'/shapes:shapes: no SID' \
	    $gen -m schema "$y/shapes@2026-10-13.yang"
	atf_check -o match:'^shapes: [0-9]+ nodes, [0-9]+ types, [0-9]+ bytes$' \
	    -o match:'^in all: ' $gen -m schema -o out \
	    -s "$y/shapes@2026-10-13.sid" "$y/shapes@2026-10-13.yang"
	atf_check -o match:'^const struct cbl_yschema shapes_schema = \{$' \
	    cat out/shapes_schema.c
	# a-b and a.b are both a_b in C.
	atf_check -s exit:1 -e match:'struct clash_top: two members named a_b' \
	    $gen -m h "$y/clash@2026-10-13.yang"
	atf_check -s exit:1 test -e clash.h
	# Parts not written for YANG yet.
	atf_check -s exit:2 -e match:'-m c: not written for YANG yet' \
	    $gen -m h,c "$y/good@2026-10-13.yang"
}

atf_test_case yang_tree
yang_tree_head()
{
	atf_set "descr" "Tree diagrams (RFC 8340) as yanglint -f tree" \
	    "prints them, and the Markdown reference with the SIDs"
	atf_set "require.progs" "yanglint"
}
yang_tree_body()
{
	setup
	y="$(atf_get_srcdir)/yang"

	if $gen -n "$y/good@2026-10-13.yang" 2>&1 |
	    grep -q 'needs cblink-gen built with libyang'; then
		atf_skip "cblink-gen built without libyang"
	fi
	# Each alone, then a module with another's augments in its tree,
	# then a deviation: line for line what yanglint prints.  tree has
	# every kind of node and mark, compiled and as written.
	for m in good ext ietf-system ietf-netconf-acm ietf-sid-file tree \
	    "tree good" "good good-dev"; do
		set --
		for f in $m; do
			set -- "$@" "$y/$f"@*.yang
		done
		b=$(echo $m | tr ' ' -)
		atf_check $gen -m tree -b "$b" "$@"
		atf_check -o save:"$b.want" yanglint -i -p "$y" -f tree "$@"
		atf_check -o file:"$b.want" cat "$b.tree"
	done
	# The module's own nodes compiled, its augment of good's as written.
	atf_check -o match:'^     \|  \+--rw \(shape\)\?$' cat tree.tree
	atf_check -o match:'^    \+---u stamp$' cat tree.tree
	atf_check -o match:'^        \+--rw t:who\?      string \{fast or slow\}\?$' \
	    cat tree-good.tree

	# The Markdown: the tree diagram, the nodes with their SIDs.
	cat "$y/ietf-system@2014-08-06.sid" > full.sid
	atf_check -o ignore $gen -n -a -s full.sid "$y/ietf-system@2014-08-06.yang"
	atf_check $gen -m md,tree -s full.sid "$y/ietf-system@2014-08-06.yang"
	atf_check -o match:'^# Module `ietf-system`$' \
	    -o match:'^\| SID \| 1700 \|$' cat ietf-system.md
	sed -n '/^```$/,/^```$/p' ietf-system.md | sed '1d;$d' > md.tree
	atf_check cmp md.tree ietf-system.tree
	atf_check -o match:'^\| `/ietf-system:system/ntp/server/udp/port` \| leaf \| `inet:port-number` \(uint16\) \| true \|  \| `123` \|  \| 1763 \|$' \
	    cat ietf-system.md
	atf_check -o match:'^\| `/ietf-system:system/clock/timezone-utc-offset` \| leaf \| `int16` \| true \|  \|  \| minutes \| [0-9]+ \|$' \
	    cat ietf-system.md
	atf_check -o match:'^\| `ntp` \| yes \| [0-9]+ \|$' cat ietf-system.md
	# Without a .sid file, no SID column.
	atf_check $gen -m md "$y/good@2026-10-13.yang"
	atf_check -o match:'^\| Node \| Kind \| Type \| Config \| Mandatory \| Default \| Units \|$' \
	    -o match:'^\| `/good:things/thing` \| list \[name\] \|  \| true \|  \|  \|  \|$' \
	    cat good.md
}

atf_init_test_cases()
{
	atf_add_test_case golden
	atf_add_test_case determinism
	atf_add_test_case errors
	atf_add_test_case crlf
	atf_add_test_case ctrl_regen
	atf_add_test_case ymod_regen
	atf_add_test_case cli
	atf_add_test_case big_input
	atf_add_test_case cblink_mk
	atf_add_test_case yang_frontend
	atf_add_test_case sid_cbor
	atf_add_test_case yang_h
	atf_add_test_case yang_tree
}
