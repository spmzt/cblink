#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# cblink-gen: the YANG front end, determinism, the command line,
# cblink.mk, the committed tables of cblink's own modules, .sid files.
#

# The generator under test is installed next to this script.
gen=

setup()
{
	gen="$(atf_get_srcdir)/cblink-gen"
}

atf_test_case determinism
determinism_head()
{
	atf_set "descr" "The same modules give byte-identical output"
}
determinism_body()
{
	setup
	y="$(atf_get_srcdir)/yang"
	mkdir a b c sub
	for d in a b; do
		atf_check -o ignore $gen -m h,schema,server,md,tree -b s -o $d \
		    -s "$y/shapes@2026-10-13.sid" "$y/shapes@2026-10-13.yang"
	done
	atf_check diff -r a b
	# The output does not depend on where the module lives.
	cp "$y/shapes@2026-10-13.yang" "$y/shapes@2026-10-13.sid" sub/
	atf_check -o ignore $gen -m h,schema,server,md,tree -b s -o c \
	    -s sub/shapes@2026-10-13.sid sub/shapes@2026-10-13.yang
	atf_check diff -r a c
}

atf_test_case ymod_regen
ymod_regen_head()
{
	atf_set "descr" "The committed structs and tables of the cblink" \
	    "modules match them: the framework's and the control family's," \
	    "and fuzz_ycodec's of shapes"
}
ymod_regen_body()
{
	setup
	y="$(atf_get_srcdir)/yang"

	mkdir out
	atf_check -o ignore $gen -m h,schema -b cbl_ymod -o out \
	    -s "$y/cblink@2026-10-13.sid" "$y/cblink@2026-10-13.yang"
	atf_check -o ignore $gen -m h,schema -b cbl_yctrl -o out \
	    -s "$y/cblink-ctrl@2026-10-13.sid" "$y/cblink-ctrl@2026-10-13.yang"
	# The control family's reference, committed as docs/ctrl.md.
	atf_check $gen -m md -b ctrl -o out \
	    -s "$y/cblink-ctrl@2026-10-13.sid" "$y/cblink-ctrl@2026-10-13.yang"
	# The tables fuzz_ycodec decodes by, committed in fuzz.
	atf_check -o ignore $gen -m h,schema -b yshapes -o out \
	    -s "$y/shapes@2026-10-13.sid" "$y/shapes@2026-10-13.yang"
	for f in cbl_ymod.h cbl_ymod_schema.c cbl_yctrl.h cbl_yctrl_schema.c \
	    ctrl.md yshapes.h yshapes_schema.c; do
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
	y="$(atf_get_srcdir)/yang"
	m="$y/shapes@2026-10-13.yang"
	sid="$y/shapes@2026-10-13.sid"

	atf_check -o match:"^cblink-gen [0-9]" $gen -V
	atf_check -s exit:2 -e match:"usage" $gen
	atf_check -s exit:2 -e match:"usage" $gen -x "$m"
	# A YANG module, nothing else.
	atf_check -s exit:2 -e match:"usage" $gen spec.yaml
	atf_check -s exit:2 -e match:"nosuch.yang" $gen -n nosuch.yang
	mkdir out
	atf_check $gen -m h -s "$sid" -o out "$m"
	atf_check -o inline:"shapes.h\n" ls out
	atf_check $gen -m md -b other -s "$sid" -o out "$m"
	atf_check -o inline:"other.md\nshapes.h\n" ls out
	atf_check -s exit:2 -e match:"invalid output base" \
	    $gen -m h -b a/b -s "$sid" -o out "$m"
	atf_check -s exit:2 -e ignore $gen -m h -s "$sid" -o nosuchdir "$m"
	# -n checks without writing anything.
	mkdir empty
	atf_check -o match:"compiled" $gen -n -s "$sid" -o empty "$m"
	atf_check -o empty ls empty
}

atf_test_case big_input
big_input_head()
{
	atf_set "descr" "An oversized .sid file is refused"
}
big_input_body()
{
	setup
	dd if=/dev/zero bs=1024 count=17000 2>/dev/null | tr '\0' ' ' \
	    > big.sid
	atf_check -s exit:1 -e match:"too large" $gen -n -s big.sid \
	    "$(atf_get_srcdir)/yang/shapes@2026-10-13.yang"
}

atf_test_case cblink_mk
cblink_mk_head()
{
	atf_set "descr" \
	    "cblink.mk finds a module given relative, with ../, or absolute"
	atf_set "require.progs" "make"
}
cblink_mk_body()
{
	setup
	y="$(atf_get_srcdir)/yang"
	# Build here, whatever object directory the caller's make uses.
	unset MAKEOBJDIRPREFIX MAKEOBJDIR

	mkdir rel up abs mods
	cp "$y/shapes@2026-10-13.yang" "$y/shapes@2026-10-13.sid" rel/
	cp "$y/shapes@2026-10-13.yang" "$y/shapes@2026-10-13.sid" .
	cp "$y/shapes@2026-10-13.yang" "$y/shapes@2026-10-13.sid" mods/
	for d in rel up abs; do
		case $d in
		rel)	p= ;;
		up)	p=../ ;;
		abs)	p="$(pwd)/mods/" ;;
		esac
		cat > $d/Makefile <<EOF
CBLINK_YANG=	${p}shapes@2026-10-13.yang
CBLINK_SIDS=	${p}shapes@2026-10-13.sid
CBLINK_GEN=	${gen}
.include "$(atf_get_srcdir)/cblink.mk"
EOF
		atf_check -o ignore -e ignore make -C $d shapes.h
		atf_check test -s $d/shapes.h -a -s $d/shapes_schema.c \
		    -a -s $d/shapes_server.c
	done
}

atf_test_case yang_frontend
yang_frontend_head()
{
	atf_set "descr" "A YANG module is compiled through libyang"
}
yang_frontend_body()
{
	setup
	y="$(atf_get_srcdir)/yang"

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
	# The server's table carries it for GET-SID: the value, after 1301.
	mkdir three
	atf_check $gen -m server -b sys -o three -s full.sid "$m"
	sed -n '/^static const uint8_t sid0\[\] = {/,/^};/p' \
	    three/sys_server.c | grep -o '0x[0-9a-f][0-9a-f]' |
	    sed 's/^0x//' > embedded
	od -A n -t x1 -v one/ietf-system@2014-08-06.sid.cbor |
	    tr -s ' ' '\n' | grep . | tail -n +5 > value
	atf_check -o not-empty cat value
	atf_check cmp embedded value
	atf_check -o match:'\{ "ietf-system", "2014-08-06", sid0' \
	    cat three/sys_server.c
	# Read as the file, verified as the file.
	atf_check -o match:', 81 SIDs from 1 .sid files$' $gen -n \
	    -s one/ietf-system@2014-08-06.sid.cbor "$m"
	# A file numbers every item of its module, whatever features a
	# program enables (RFC 9595): read with them all off, numbered with
	# them all off as with them on, and the tables made without them.
	atf_check -o match:', 81 SIDs from 1 .sid files$' $gen -n \
	    -F ietf-system: -s full.sid "$m"
	cat "$y/ietf-system@2014-08-06.sid" > nofeat.sid
	atf_check -o ignore $gen -n -a -F ietf-system: -s nofeat.sid "$m"
	atf_check cmp nofeat.sid full.sid
	mkdir four
	atf_check -o ignore $gen -m h,schema -b sys -o four -F ietf-system: \
	    -s full.sid "$m"
	atf_check -o not-match:'radius' cat four/sys.h
	# Nor whatever another module deviates: a file is verified and
	# numbered against its module alone, and the tables made without
	# what is deviated away.
	cat > dvbase@2026-10-14.yang <<-EOF
	module dvbase {
	  yang-version 1.1;
	  namespace "urn:test:dvbase";
	  prefix dvb;
	  revision 2026-10-14;
	  container c {
	    leaf kept { type string; }
	    leaf dropped { type string; }
	  }
	}
	EOF
	cat > dvdev@2026-10-14.yang <<-EOF
	module dvdev {
	  yang-version 1.1;
	  namespace "urn:test:dvdev";
	  prefix dvd;
	  import dvbase { prefix dvb; }
	  revision 2026-10-14;
	  deviation "/dvb:c/dvb:dropped" { deviate not-supported; }
	}
	EOF
	cat > dvbase.sid <<-EOF
	{
	  "ietf-sid-file:sid-file": {
	    "module-name": "dvbase",
	    "module-revision": "2026-10-14",
	    "assignment-range": [
	      { "entry-point": "70000", "size": "10" }
	    ],
	    "item": [
	      { "namespace": "module", "identifier": "dvbase", "sid": "70000" }
	    ]
	  }
	}
	EOF
	cp dvbase.sid dvbase-dev.sid
	atf_check -o match:'^dvbase.sid: 3 SIDs assigned' $gen -n -a -p . \
	    -s dvbase.sid dvbase@2026-10-14.yang
	atf_check -o match:'^dvbase-dev.sid: 3 SIDs assigned' $gen -n -a -p . \
	    -s dvbase-dev.sid dvbase@2026-10-14.yang dvdev@2026-10-14.yang
	atf_check cmp dvbase.sid dvbase-dev.sid
	atf_check -o match:'/dvbase:c/dropped' cat dvbase.sid
	atf_check -o match:', 4 SIDs from 1 .sid files$' $gen -n -p . \
	    -s dvbase.sid dvbase@2026-10-14.yang dvdev@2026-10-14.yang
	mkdir five
	atf_check -o ignore $gen -m h,schema -b dv -o five -p . \
	    -s dvbase.sid dvbase@2026-10-14.yang dvdev@2026-10-14.yang
	atf_check -o match:'kept' -o not-match:'dropped' cat five/dv.h
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

# The modules a module's import or include statements name: a statement,
# not the word in a description.
stmts()
{
	sed -nE "s/^[[:space:]]*$1[[:space:]]+([A-Za-z_][A-Za-z0-9_.-]*)[[:space:]]*[{;].*/\\1/p" "$2"
}

# A module and every module it imports, its submodules' imports too, by
# name, from the directory: the modules whose features it may use.
imports()
{
	local dir=$1 todo=$2 seen= m f i

	while [ -n "$todo" ]; do
		set -- $todo
		m=$1
		shift
		todo="$*"
		case " $seen " in *" $m "*) continue ;; esac
		seen="$seen $m"
		for f in "$dir/$m"@*.yang; do
			[ -f "$f" ] || continue
			todo="$todo $(stmts import "$f")"
			for i in $(stmts include "$f"); do
				todo="$todo $(cat "$dir/$i"@*.yang |
				    stmts import /dev/stdin)"
			done
		done
	done
	echo $seen
}

atf_test_case corpus
corpus_head()
{
	atf_set "descr" "The IETF and IANA modules of the corpus: each" \
	    "tree as yanglint draws it, all their tables compiled and every" \
	    "struct through YANG-CBOR and back"
	atf_set "require.progs" "yanglint cc"
	atf_set "timeout" "600"
}
corpus_body()
{
	local c prefix f m n i r mains

	setup
	c="$(atf_get_srcdir)/corpus"
	prefix=$(cd "$(atf_get_srcdir)/../../.." && pwd)
	mains=$(cd "$c" && grep -l '^module ' *.yang)

	# Each tree, line for line, with every feature of the module and
	# of those it imports on for both: without -F, yanglint turns off
	# those of a module an import implements, cblink-gen turns on all
	# (cblink-gen(1)).  cblink-gen implements an imported module only
	# where the module refers to it, yanglint -i every one: those it
	# does not, whose features cannot bear on its tree, are named by
	# neither.
	n=0
	for f in $mains; do
		m=${f%%@*}
		feats=$(imports "$c" "$m")
		while :; do
			set --
			for i in $feats; do
				set -- "$@" -F "$i:*"
			done
			$gen -m tree -b "$m" "$@" "$c/$f" 2> err && break
			x=$(sed -n "s/.*'\([^:']*\):\*': no module .* implemented\$/\1/p" err)
			[ -n "$x" ] || atf_fail "$m: $(cat err)"
			feats=$(echo $feats | tr ' ' '\n' | grep -vx "$x")
		done
		atf_check -o save:"$m.want" yanglint -i -p "$c" "$@" -f tree \
		    "$c/$f"
		atf_check -o file:"$m.want" cat "$m.tree"
		n=$((n + 1))
	done
	[ "$n" -ge 50 ] || atf_fail "only $n modules in the corpus"

	# The structs and tables of all of them together, their SIDs made
	# up for the check (a range a module): compiled, and every struct,
	# filled three ways, through YANG-CBOR and back to the same bytes.
	set --
	i=0
	for f in $mains; do
		m=${f%%@*}
		r=$(sed -n 's/^ *revision \([0-9-]*\).*/\1/p' "$c/$f" | head -1)
		printf '{"ietf-sid-file:sid-file": {"module-name": "%s",%s "assignment-range": [{"entry-point": "%s", "size": "100000"}]}}\n' \
		    "$m" "${r:+ \"module-revision\": \"$r\",}" \
		    $((1099511627776 + i * 100000)) > "$m.sid"
		atf_check -o ignore $gen -n -a -p "$c" -s "$m.sid" "$c/$f"
		set -- "$@" -s "$PWD/$m.sid"
		i=$((i + 1))
	done
	for f in $mains; do
		set -- "$@" "$c/$f"
	done
	atf_check -o match:'^in all: ' $gen -m h,schema,server -b corpus \
	    -p "$c" "$@"
	printf '#include "corpus.h"\n' > use.c
	# CC, CFLAGS, LDFLAGS as the library was built with: a sanitizer's.
	for f in use.c corpus_schema.c corpus_server.c; do
		atf_check ${CC:-cc} ${CFLAGS:-} -std=c23 -Wall -Wextra -Werror \
		    -Wshadow -Wcast-qual -Wwrite-strings \
		    -Wmissing-variable-declarations -I"$prefix/include" -I. \
		    -c "$f" -o "$f.o"
	done
	cat > round.c <<'EOF'
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
	if (bad != 0)
		printf("%s\n", why);
	return (bad != 0);
}
EOF
	atf_check ${CC:-cc} ${CFLAGS:-} ${LDFLAGS:-} -std=c23 -Wall -Werror \
	    -I"$prefix/include" -I. -I"$(atf_get_srcdir)" -o round round.c \
	    "$(atf_get_srcdir)/yfill.c" corpus_schema.c.o -L"$prefix/lib" \
	    -Wl,-rpath,"$prefix/lib" -lcblink
	atf_check -o match:'^[0-9]+ round trips, 0 not the same$' ./round

	# The leafrefs' paths on sample data (PLAN-SDN-YANG 2.2.1): every
	# top-level node filled by yfill, three ways, in one tree; each
	# leafref's path, as the tables hold it, evaluated from it; what it
	# finds, every node its target's.
	cat > paths.c <<'EOF'
#include <stdio.h>
#include <string.h>

#include "cbl_data.h"
#include "corpus.h"
#include "yfill.h"

static size_t npaths, nfound, nwrong;

static void
walk(const cbl_dtree *t, const cbl_dnode *n)
{
	for (const cbl_dnode *c = cbl_dnode_first(n); c != NULL;
	    c = cbl_dnode_next(c)) {
		const struct cbl_ynode *s = cbl_dnode_schema(c);
		struct cbl_xval v;
		char why[256];

		if (s->type != NULL && (s->type->flags & CBL_YTF_LEAFREF) &&
		    s->type->path >= 0) {
			npaths++;
			if (cbl_xp_eval(t, corpus_schema.xpath[s->type->path],
			    c, c, &v, why, sizeof(why)) != 0) {
				printf("%s: %s: %s\n", s->name,
				    corpus_schema.xpath[s->type->path], why);
				nwrong++;
			} else {
				for (size_t i = 0; i < v.n; i++)
					if (s->lref != NULL &&
					    cbl_dnode_schema(v.nodes[i]) !=
					    s->lref) {
						printf("%s: found %s\n", s->name,
						    cbl_dnode_schema(
						    v.nodes[i])->name);
						nwrong++;
					}
				nfound += v.n;
				cbl_xval_free(&v);
			}
		}
		walk(t, c);
	}
}

int
main(void)
{
	for (int pass = 0; pass < 3; pass++) {
		cbl_dtree *t = cbl_dtree_new(&corpus_schema);

		for (uint32_t i = 0; i < corpus_schema.nmod; i++)
			for (uint32_t j = 0; j < corpus_schema.mod[i]->ntop;
			    j++) {
				const struct cbl_ynode *n =
				    corpus_schema.mod[i]->top[j];
				struct cbl_ybuf b = { 0 };

				if (n->size == 0 || (n->kind !=
				    CBL_YN_CONTAINER && n->kind != CBL_YN_LIST))
					continue;
				if (yencoded(n, pass, true, &b) == 0)
					(void)cbl_dnode_decode(cbl_dtree_root(t),
					    n, b.p, b.len, CBL_YD_STRICT, NULL, 0,
					    NULL);
				cbl_ybuf_free(&b);
			}
		walk(t, cbl_dtree_root(t));
		cbl_dtree_free(t);
	}
	printf("%zu paths evaluated, %zu nodes found, %zu wrong\n", npaths,
	    nfound, nwrong);
	return (nwrong != 0 || npaths == 0);
}
EOF
	atf_check ${CC:-cc} ${CFLAGS:-} ${LDFLAGS:-} -std=c23 -Wall -Werror \
	    -I"$prefix/include" -I. -I"$(atf_get_srcdir)" -o paths paths.c \
	    "$(atf_get_srcdir)/yfill.c" corpus_schema.c.o -L"$prefix/lib" \
	    -Wl,-rpath,"$prefix/lib" -lcblink
	atf_check -o match:'^[0-9]+ paths evaluated, [0-9]+ nodes found, 0 wrong$' \
	    ./paths

	# RFC 8349's router advertisement musts (PLAN-SDN-YANG 2.2.2), on an
	# interface's configuration with its defaults made, as XPath in YANG
	# sees them (RFC 7950 section 6.4.1): min-rtr-adv-interval within 75%
	# of max-rtr-adv-interval, a prefix's preferred lifetime within its
	# valid one, each as it holds and as it does not.
	cat > ra.c <<'EOF'
#include <stdio.h>
#include <string.h>

#include "cbl_data.h"
#include "corpus.h"

static int bad;

static const struct cbl_ynode *
kid(const struct cbl_ynode *n, const char *name)
{
	for (uint32_t i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	printf("no %s under %s\n", name, n->name);
	bad = 1;
	return (n);
}

static cbl_dnode *
add(cbl_dnode *p, const struct cbl_ynode *s, const void *v)
{
	cbl_dnode *x = cbl_dnode_child(p, s);

	if (x == NULL && cbl_dnode_add(p, s, v, &x) != 0) {
		printf("%s not added\n", s->name);
		bad = 1;
	}
	return (x);
}

/* The must of node x's schema node, from x: as want? */
static void
must(const cbl_dtree *t, const cbl_dnode *x, int want, const char *what)
{
	const struct cbl_ynode *s = cbl_dnode_schema(x);
	struct cbl_xval v;
	char why[256];

	if (s->nmust == 0 || cbl_xp_eval(t, corpus_schema.xpath[
	    s->must[0].expr], x, x, &v, why, sizeof(why)) != 0) {
		printf("%s: %s\n", what, s->nmust == 0 ? "no must" : why);
		bad = 1;
		return;
	}
	if (v.kind != CBL_XV_BOOL || v.b != want) {
		printf("%s: %s, not %s\n", what, corpus_schema.xpath[
		    s->must[0].expr], want ? "true" : "false");
		bad = 1;
	}
	cbl_xval_free(&v);
}

int
main(void)
{
	const struct cbl_ynode *ifs = NULL, *ifc, *ip6, *ra, *pfx;
	cbl_dtree *t = cbl_dtree_new(&corpus_schema);
	const char *name = "eth0", *spec = "2001:db8::/64";
	const void *k[1];
	cbl_dnode *x, *rax, *mn, *e;
	uint16_t min = 200;
	uint32_t life;

	for (uint32_t i = 0; i < corpus_schema.nmod; i++)
		if (strcmp(corpus_schema.mod[i]->name, "ietf-interfaces") == 0)
			for (uint32_t j = 0; j < corpus_schema.mod[i]->ntop;
			    j++)
				if (strcmp(corpus_schema.mod[i]->top[j]->name,
				    "interfaces") == 0)
					ifs = corpus_schema.mod[i]->top[j];
	if (ifs == NULL)
		return (1);
	ifc = kid(ifs, "interface");
	ip6 = kid(ifc, "ipv6");
	ra = kid(ip6, "ipv6-router-advertisements");
	pfx = kid(kid(ra, "prefix-list"), "prefix");
	x = add(cbl_dtree_root(t), ifs, NULL);
	k[0] = &name;
	if (cbl_dnode_add_entry(x, ifc, k, &x) != 0)
		return (1);
	rax = add(add(x, ip6, NULL), ra, NULL);
	mn = add(rax, kid(ra, "min-rtr-adv-interval"), &min);
	k[0] = &spec;
	if (cbl_dnode_add_entry(add(rax, kid(ra, "prefix-list"), NULL), pfx,
	    k, &e) != 0)
		return (1);
	if (cbl_dtree_defaults(cbl_dtree_root(t)) < 0)
		return (1);

	/* 200 <= 0.75 * 600, max's default; 500 is not; with max 800 it is. */
	must(t, mn, 1, "min 200");
	min = 500;
	cbl_dnode_set(mn, &min);
	must(t, mn, 0, "min 500");
	cbl_dnode_set(cbl_dnode_child(rax, kid(ra, "max-rtr-adv-interval")),
	    &(uint16_t){ 800 });
	must(t, mn, 1, "min 500, max 800");
	/* 604800 <= 2592000, the defaults; 3000000 is not; then it is. */
	x = cbl_dnode_child(e, kid(pfx, "preferred-lifetime"));
	must(t, x, 1, "preferred's default");
	life = 3000000;
	cbl_dnode_set(x, &life);
	must(t, x, 0, "preferred 3000000");
	life = 4000000;
	cbl_dnode_set(cbl_dnode_child(e, kid(pfx, "valid-lifetime")), &life);
	must(t, x, 1, "valid 4000000");
	cbl_dtree_free(t);
	if (!bad)
		printf("RFC 8349's musts: as the RFC has them\n");
	return (bad);
}
EOF
	atf_check ${CC:-cc} ${CFLAGS:-} ${LDFLAGS:-} -std=c23 -Wall -Werror \
	    -I"$prefix/include" -I. -o ra ra.c corpus_schema.c.o \
	    -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcblink
	atf_check -o inline:"RFC 8349's musts: as the RFC has them\n" ./ra

	# RFC 8349's IPv4 augments' whens (PLAN-SDN-YANG 2.2.4): a RIB of
	# IPv4 unicast with a route (its destination prefix), a simple next
	# hop's address and a next-hop list's; all hold.  The RIB made IPv6
	# unicast, each of the three refused in turn, unknown-element: the
	# augment of the route, of a case, of a list's entries.
	cat > v4ur.c <<'EOF'
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "cbl_data.h"
#include "corpus.h"

static int bad;

static const struct cbl_ynode *
kid(const struct cbl_ynode *n, const char *name)
{
	for (uint32_t i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	printf("no %s under %s\n", name, n->name);
	bad = 1;
	return (n);
}

static cbl_dnode *
add(cbl_dnode *p, const struct cbl_ynode *s, const void *v)
{
	cbl_dnode *x = cbl_dnode_child(p, s);

	if (x == NULL && (s->kind == CBL_YN_LIST ? cbl_dnode_add_entry(p, s,
	    v, &x) : cbl_dnode_add(p, s, v, &x)) != 0) {
		printf("%s not added\n", s->name);
		bad = 1;
	}
	return (x);
}

static uint64_t
ident(const char *mod, const char *name)
{
	for (uint32_t i = 0; i < corpus_schema.nident; i++)
		if (strcmp(corpus_schema.ident[i].name, name) == 0 &&
		    strcmp(corpus_schema.ident[i].module->name, mod) == 0)
			return (corpus_schema.ident[i].sid);
	printf("no identity %s:%s\n", mod, name);
	bad = 1;
	return (0);
}

int
main(void)
{
	const struct cbl_ynode *routing = NULL, *rib, *route, *nh, *nhl;
	cbl_dtree *t = cbl_dtree_new(&corpus_schema);
	const char *name = "ipv4-main", *dst = "192.0.2.0/24";
	const char *gw = "198.51.100.1", *gw2 = "198.51.100.2";
	const void *k[1] = { &name };
	uint64_t af = ident("ietf-ipv4-unicast-routing", "ipv4-unicast");
	struct cbl_dederr err;
	cbl_dnode *x, *r, *routes;
	int refused = 0, error;

	for (uint32_t i = 0; i < corpus_schema.nmod; i++)
		if (strcmp(corpus_schema.mod[i]->name, "ietf-routing") == 0)
			for (uint32_t j = 0; j < corpus_schema.mod[i]->ntop;
			    j++)
				if (strcmp(corpus_schema.mod[i]->top[j]->name,
				    "routing") == 0)
					routing = corpus_schema.mod[i]->top[j];
	if (routing == NULL)
		return (1);
	rib = kid(kid(routing, "ribs"), "rib");
	route = kid(kid(rib, "routes"), "route");
	nh = kid(route, "next-hop");
	nhl = kid(kid(nh, "next-hop-list"), "next-hop");
	x = add(add(add(cbl_dtree_root(t), routing, NULL), kid(routing,
	    "ribs"), NULL), rib, k);
	add(x, kid(rib, "address-family"), &af);
	routes = add(x, kid(rib, "routes"), NULL);
	/* A route by a simple next hop, one by a list. */
	if (cbl_dnode_add_entry(routes, route, NULL, &r) != 0)
		return (1);
	add(r, kid(route, "destination-prefix"), &dst);
	add(add(r, nh, NULL), kid(nh, "next-hop-address"), &gw);
	if (cbl_dnode_add_entry(routes, route, NULL, &r) != 0)
		return (1);
	if (cbl_dnode_add_entry(add(add(r, nh, NULL), kid(nh,
	    "next-hop-list"), NULL), nhl, NULL, &x) != 0)
		return (1);
	add(x, kid(nhl, "address"), &gw2);
	if ((error = cbl_dtree_check_conds(t, &err)) != 0) {
		printf("IPv4: %s\n", err.msg);
		bad = 1;
	}
	af = ident("ietf-ipv6-unicast-routing", "ipv6-unicast");
	cbl_dnode_set(cbl_dnode_child(cbl_dnode_parent(routes),
	    kid(rib, "address-family")), &af);
	while ((error = cbl_dtree_check_conds(t, &err)) == EINVAL &&
	    refused < 10) {
		const struct cbl_ynode *s = cbl_dnode_schema(err.node);

		if (strcmp(err.tag, "unknown-element") != 0 ||
		    strcmp(s->module->name, "ietf-ipv4-unicast-routing") != 0) {
			printf("%s: %s\n", s->name, err.msg);
			bad = 1;
			break;
		}
		printf("%s refused\n", s->name);
		refused++;
		cbl_dnode_remove((cbl_dnode *)(uintptr_t)err.node);
	}
	cbl_dtree_free(t);
	return (bad || error != 0);
}
EOF
	atf_check ${CC:-cc} ${CFLAGS:-} ${LDFLAGS:-} -std=c23 -Wall -Werror \
	    -I"$prefix/include" -I. -o v4ur v4ur.c corpus_schema.c.o \
	    -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcblink
	atf_check -o inline:"destination-prefix refused\nnext-hop-address refused\naddress refused\n" \
	    ./v4ur

	# The evaluator against libyang's (PLAN-SDN-YANG 2.2.6): xpdiff on
	# the corpus, every when, must and leafref path, and expressions made
	# of the data, two seeds; none differs.
	atf_check ${CC:-cc} ${CFLAGS:-} ${LDFLAGS:-} -std=c23 -Wall -Werror \
	    -I"$prefix/include" -I"${LOCALBASE:-/usr/local}/include" -I. \
	    -I"$(atf_get_srcdir)" -o xpdiff "$(atf_get_srcdir)/xpdiff.c" \
	    "$(atf_get_srcdir)/yfill.c" corpus_schema.c.o -L"$prefix/lib" \
	    -Wl,-rpath,"$prefix/lib" -lcblink \
	    -L"${LOCALBASE:-/usr/local}/lib" -lyang -lm
	for seed in 1 2; do
		atf_check -o match:', 0 differ$' ./xpdiff "$c" $seed 20000
	done
}

atf_init_test_cases()
{
	atf_add_test_case determinism
	atf_add_test_case ymod_regen
	atf_add_test_case cli
	atf_add_test_case big_input
	atf_add_test_case cblink_mk
	atf_add_test_case yang_frontend
	atf_add_test_case sid_cbor
	atf_add_test_case yang_h
	atf_add_test_case yang_tree
	atf_add_test_case corpus
}
