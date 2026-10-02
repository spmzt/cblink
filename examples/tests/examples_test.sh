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

# Wait for a backgrounded client to print "ready".
client_ready()
{
	retry 10 grep -q '^ready' "$1" ||
	    atf_fail "client not ready: $(cat "$1")"
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

atf_test_case kv cleanup
kv_head()
{
	atf_set "descr" "cbl-kv: do, dump, auth, notifications, a stream"
}
kv_body()
{
	K="$(atf_get_srcdir)/cbl-kv"
	T="unix:$(pwd)/trusted.sock"
	U="unix:$(pwd)/untrusted.sock"
	server_start cbl-kv -t "${T}"

	"${K}" "${T}" changes 2 > changes.out 2>&1 &
	client_ready changes.out
	atf_check "${K}" "${T}" set apple red
	atf_check "${K}" "${T}" set banana yellow
	wait $!
	atf_check -o \
	    inline:"ready\nchanged apple flags=0\nchanged banana flags=0\n" \
	    cat changes.out

	atf_check -o inline:"apple = red\n" "${K}" "${T}" get apple
	atf_check -o inline:"apple = red\nbanana = yellow\n" \
	    "${K}" "${T}" list
	atf_check -o inline:"banana = yellow\n" "${K}" "${T}" list ban
	atf_check -s exit:1 -e match:"no such key" "${K}" "${T}" get cherry

	# A watch starts with the matching entries, then follows changes.
	"${K}" "${T}" watch app 2 > watch.out 2>&1 &
	client_ready watch.out
	atf_check "${K}" "${T}" set banana green
	atf_check "${K}" "${T}" set apple green
	wait $!
	atf_check -o inline:"ready\napple = red\napple = green\n" cat watch.out

	# "set" is auth: true; an untrusted unix socket is anonymous.
	server_start cbl-kv "${U}"
	atf_check -s exit:1 -e match:"set:" "${K}" "${U}" set apple x
	atf_check -s exit:1 -e ignore "${K}" "${U}" get apple
}
kv_cleanup()
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

atf_init_test_cases()
{
	atf_add_test_case echo
	atf_add_test_case kv
	atf_add_test_case stream
	atf_add_test_case notify
}
