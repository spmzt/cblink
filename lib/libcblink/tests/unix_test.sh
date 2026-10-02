#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# AF_UNIX: credentials, socket permissions, stale sockets, trust.
#

. "$(atf_get_srcdir)/cbl_test.subr"


atf_test_case basics cleanup
basics_head()
{
	atf_set "descr" "Requests, dumps and push streams over AF_UNIX"
}
basics_body()
{
	start_server unix:$(pwd)/s.sock || atf_fail "$(cat server.err)"
	# Local peers are identified by credentials, not certificates.
	atf_check -o match:"authenticated=0" -o match:"transport=unix" \
	    -o match:"uid=$(id -u)" ${PEER} call unix:$(pwd)/s.sock
	atf_check -o inline:"value=42\n" ${PEER} call -o echo -N 42 \
	    unix:$(pwd)/s.sock
	atf_check -o inline:"items=500\n" ${PEER} call -o dump -N 500 \
	    unix:$(pwd)/s.sock
	atf_check -o inline:"items=300\n" ${PEER} call -o feed -N 300 \
	    unix:$(pwd)/s.sock
	# Without CBL_LF_UNIX_TRUSTED, auth-only commands are refused.
	atf_check -s exit:1 -e match:"Permission denied" ${PEER} call \
	    -o secret unix:$(pwd)/s.sock
	# The default mode keeps other users out.
	atf_check -o inline:"srw-------\n" -x "ls -l s.sock | cut -c1-10"
}
basics_cleanup()
{
	stop_server
}

atf_test_case trusted cleanup
trusted_head()
{
	atf_set "descr" "CBL_LF_UNIX_TRUSTED and a configured socket mode"
}
trusted_body()
{
	start_server -t -u 0660 unix:$(pwd)/s.sock ||
	    atf_fail "$(cat server.err)"
	atf_check -o inline:"srw-rw----\n" -x "ls -l s.sock | cut -c1-10"
	atf_check -o match:"authenticated=1" ${PEER} call unix:$(pwd)/s.sock
	atf_check -o inline:"ok\n" ${PEER} call -o secret unix:$(pwd)/s.sock
}
trusted_cleanup()
{
	stop_server
}

# True when nothing answers on s.sock.
refused()
{
	! "${PEER}" call -o ping "unix:$(pwd)/s.sock" >/dev/null 2>&1
}

atf_test_case stale cleanup
stale_head()
{
	atf_set "descr" "Stale sockets are replaced, live ones are not stolen"
}
stale_body()
{
	start_server unix:$(pwd)/s.sock || atf_fail "$(cat server.err)"
	# A second listener on a live socket is refused.
	mv server.pid first.pid
	atf_check -s exit:1 -e match:"another listener is active" \
	    "$(atf_get_srcdir)/cbl_testpeer" serve unix:$(pwd)/s.sock
	# After a crash the leftover socket file is reused.
	kill -9 $(cat first.pid)
	# It is gone once its socket refuses connections (a killed process
	# can linger as a zombie where nothing reaps it, as in a container).
	retry 10 refused || atf_fail "the killed server still answers"
	[ -S s.sock ] || atf_fail "socket file was not left behind"
	start_server unix:$(pwd)/s.sock || atf_fail "$(cat server.err)"
	atf_check -o ignore ${PEER} call -o ping unix:$(pwd)/s.sock
	# Anything that is not a socket is never removed.
	stop_server
	echo data > notasocket
	atf_check -s exit:1 -e match:"File exists" \
	    "$(atf_get_srcdir)/cbl_testpeer" serve unix:$(pwd)/notasocket
	atf_check -o inline:"data\n" cat notasocket
}
stale_cleanup()
{
	stop_server
	[ -f first.pid ] && kill -9 $(cat first.pid) 2>/dev/null
	true
}

atf_init_test_cases()
{
	atf_add_test_case basics
	atf_add_test_case trusted
	atf_add_test_case stale
}
