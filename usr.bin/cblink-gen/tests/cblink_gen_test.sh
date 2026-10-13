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
	# Code generation from YANG is not written yet.
	atf_check -s exit:2 -e match:'not written yet' \
	    $gen -o . "$y/good@2026-10-13.yang"
}

atf_init_test_cases()
{
	atf_add_test_case golden
	atf_add_test_case determinism
	atf_add_test_case errors
	atf_add_test_case crlf
	atf_add_test_case ctrl_regen
	atf_add_test_case cli
	atf_add_test_case big_input
	atf_add_test_case cblink_mk
	atf_add_test_case yang_frontend
}
