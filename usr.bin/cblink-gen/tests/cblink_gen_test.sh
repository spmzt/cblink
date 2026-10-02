#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# cblink-gen: golden files, determinism, every validation error with its
# exact location, malformed YAML, the committed control family, and
# cblink.mk.
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
}
