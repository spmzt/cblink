#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# The example programs, each against its own server on a unix socket.
#

# retry seconds command [args]: run the command until it succeeds, once a
# second, for at most "seconds" seconds.
retry()
{
	_retry_n=$1
	shift
	while ! "$@"; do
		[ "${_retry_n}" -le 0 ] && return 1
		_retry_n=$((_retry_n - 1))
		sleep 1
	done
}

server_start()
{
	_prog=$1
	shift
	"$(atf_get_srcdir)/${_prog}" -l "$@" > server.out 2> server.err &
	echo $! >> servers.pid
	retry 10 grep -q '^listening' server.out ||
	    atf_fail "${_prog}: $(cat server.err)"
	rm -f server.out
}

servers_stop()
{
	[ -f servers.pid ] && kill $(cat servers.pid) 2>/dev/null
	true
}

atf_test_case echo cleanup
echo_head()
{
	atf_set "descr" "cbl-echo: one request, one reply"
}
echo_body()
{
	E="$(atf_get_srcdir)/cbl-echo"
	server_start cbl-echo "unix:$(pwd)/e.sock"
	atf_check -o \
	    inline:"hello cblink (as seen by the server: uid $(id -u))\n" \
	    "${E}" "unix:$(pwd)/e.sock" "hello cblink"
	# TCP without TLS configured needs an explicit opt-in.
	atf_check -s exit:1 -e match:"mTLS required" "${E}" \
	    tcp://127.0.0.1:1 hi
}
echo_cleanup()
{
	servers_stop
}

atf_test_case stream cleanup
stream_head()
{
	atf_set "descr" \
	    "cbl-stream: credit flow control, a bidirectional stream"
}
stream_body()
{
	S="$(atf_get_srcdir)/cbl-stream"
	server_start cbl-stream "unix:$(pwd)/s.sock"
	# Far more than the 4096-byte initial credit: flow control at work.
	atf_check -o inline:"received 1..100000 in order\n" \
	    "${S}" "unix:$(pwd)/s.sock" count 100000
	printf 'hello\nflow control\n' > in.txt
	atf_check -o inline:"HELLO\nFLOW CONTROL\n" -x \
	    "'${S}' 'unix:$(pwd)/s.sock' upper < in.txt"
}
stream_cleanup()
{
	servers_stop
}

atf_test_case notify cleanup
notify_head()
{
	atf_set "descr" "cbl-notify: multicast notifications"
}
notify_body()
{
	N="$(atf_get_srcdir)/cbl-notify"
	server_start cbl-notify -i 50 "unix:$(pwd)/n.sock"
	atf_check -o save:ticks.out "${N}" "unix:$(pwd)/n.sock" 3
	atf_check -o inline:"3\n" sh -c "grep -c '^tick ' ticks.out"
}
notify_cleanup()
{
	servers_stop
}

atf_test_case kv
kv_head()
{
	atf_set "descr" "cbl-kv: the kv example in YANG, its table served" \
	    "by family 1: an edit, the store read back, an rpc, a" \
	    "notification"
}
kv_body()
{
	K="$(atf_get_srcdir)/cbl-kv"

	atf_check -o save:out "$K"
	atf_check -o match:'^edit: 2 entries$' cat out
	atf_check -o match:'^get: 2 entries, count 2$' cat out
	# {+1 count: 2, +2 entry: [{+1 key: "alpha", ...}, ...]}
	atf_check -o match:'^store: a2 01 02 02 82 a4 01 65 61 6c 70 68 61 ' \
	    cat out
	atf_check -o match:'^decoded: alpha ttl 60, beta persistent$' cat out
	atf_check -o match:'^get-sid: 1 file, [0-9]+ bytes, as the table has it$' \
	    cat out
	atf_check -o match:'^touch: ttl 300$' cat out
	atf_check -o match:'^clear al: 1 removed, 1 left$' cat out
	# {SID of changed: {+1 key: "beta", +2 what: deleted (1)}}
	atf_check -o match:'^changed: a1 1b .* a2 01 64 62 65 74 61 02 01$' \
	    cat out
	atf_check -o match:'^notified: changed beta deleted$' cat out
}

atf_init_test_cases()
{
	atf_add_test_case echo
	atf_add_test_case kv
	atf_add_test_case stream
	atf_add_test_case notify
}
