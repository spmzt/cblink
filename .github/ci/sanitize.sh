#!/bin/sh
#
# Build cblink with sanitizers and run its test suite, or build the
# libFuzzer harnesses and run each one for a short while:
#
#	.github/ci/sanitize.sh asan|tsan|fuzz
#
#	asan	AddressSanitizer and UndefinedBehaviorSanitizer
#	tsan	ThreadSanitizer
#	fuzz	fuzz_frame, fuzz_proxy and fuzz_spec, FUZZ_TIME seconds
#		each (default 60)
#
# The environment reaches make(1): CC, LD, CFLAGS and LDFLAGS are used
# as given, with the sanitizer flags appended.  Everything is built and
# installed in a scratch directory, CI_WORKDIR if set (kept), else a new
# one under ${TMPDIR:-/tmp} (removed on success, kept on failure).  The
# fuzzers add new inputs there, never to fuzz/corpus; on a crash, the
# input is printed (b64decode(1) restores it) and copied to
# FUZZ_ARTIFACTS if set.  The SCTP tests skip without sctp(4).
#
# Any failed or broken test, and any fuzzer crash, makes this exit 1.

set -eu

prog=${0##*/}

usage()
{
	echo "usage: ${prog} asan|tsan|fuzz" >&2
	exit 2
}

[ $# -eq 1 ] || usage
mode=$1
case ${mode} in
asan)
	san="-fsanitize=address,undefined -fno-sanitize-recover=all"
	;;
tsan)
	san="-fsanitize=thread"
	;;
fuzz)
	san=
	;;
*)
	usage
	;;
esac

top=$(cd "$(dirname "$0")/../.." && pwd -P)
jobs=${JOBS:-$(sysctl -n hw.ncpu)}
FUZZ_TIME=${FUZZ_TIME:-60}

if [ -n "${CI_WORKDIR:-}" ]; then
	mkdir -p "${CI_WORKDIR}"
	work=$(cd "${CI_WORKDIR}" && pwd -P)
	keep=yes
else
	work=$(mktemp -d "${TMPDIR:-/tmp}/cblink-${mode}.XXXXXX")
	keep=no
fi

cleanup()
{
	status=$?
	if [ "${status}" -eq 0 ] && [ "${keep}" = no ]; then
		rm -rf "${work}"
	else
		echo "${prog}: build output kept in ${work}" >&2
	fi
	exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export MAKEOBJDIRPREFIX="${work}/obj"
# Outside a jail or VM, as a user: install files as that user.
if [ "$(id -u)" -ne 0 ]; then
	export WITH_INSTALL_AS_USER=yes
fi

if [ -n "${san}" ]; then
	san="${san} -fno-omit-frame-pointer"
	CFLAGS="${CFLAGS:+${CFLAGS} }-O1 -g ${san}"
	LDFLAGS="${LDFLAGS:+${LDFLAGS} }${san}"
	export CFLAGS LDFLAGS
fi

# LeakSanitizer does not work on FreeBSD.  A TSan report makes the
# process exit 66 when it ends, which kyua reports as broken.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1}"
export TSAN_OPTIONS="${TSAN_OPTIONS:-second_deadlock_stack=1}"

run_tests()
{
	dest=${work}/dest
	results=${work}/results.db

	cd "${top}"
	make obj >/dev/null
	make -j "${jobs}"
	make install DESTDIR="${dest}"

	cd "${dest}/usr/local/tests/cblink"
	rm -f "${results}"
	if env LD_LIBRARY_PATH="${dest}/usr/local/lib" \
	    kyua test -r "${results}" -k Kyuafile; then
		return 0
	fi
	kyua report --verbose -r "${results}" \
	    --results-filter broken,failed || true
	echo "${prog}: ${mode}: tests failed" >&2
	return 1
}

# Print each file libFuzzer left in $1 and copy it to FUZZ_ARTIFACTS.
show_artifacts()
{
	for f in "$1"/*; do
		[ -f "${f}" ] || continue
		echo "--- ${f} ($(wc -c <"${f}" | tr -d ' ') bytes)"
		hexdump -C -n 1024 "${f}"
		b64encode "${f}" "${f##*/}"
		if [ -n "${FUZZ_ARTIFACTS:-}" ]; then
			mkdir -p "${FUZZ_ARTIFACTS}/$2"
			cp "${f}" "${FUZZ_ARTIFACTS}/$2/"
		fi
	done
}

run_fuzz()
{
	cd "${top}"
	make -C fuzz obj >/dev/null
	make -C fuzz -j "${jobs}"
	fobj=$(make -C fuzz -V .OBJDIR)

	failed=
	for h in frame proxy spec; do
		corpus=${work}/corpus/${h}
		crashes=${work}/crashes/${h}
		mkdir -p "${corpus}" "${crashes}"
		echo "==> fuzz_${h}: ${FUZZ_TIME} s"
		# New inputs go to the first, scratch corpus directory.
		if ! "${fobj}/fuzz_${h}" -max_total_time="${FUZZ_TIME}" \
		    -print_final_stats=1 -artifact_prefix="${crashes}/" \
		    "${corpus}" "${top}/fuzz/corpus/${h}"; then
			failed="${failed} fuzz_${h}"
			show_artifacts "${crashes}" "${h}"
		fi
	done
	if [ -n "${failed}" ]; then
		echo "${prog}: fuzz: failed:${failed}" >&2
		return 1
	fi
	return 0
}

if [ "${mode}" = fuzz ]; then
	run_fuzz
else
	run_tests
fi
