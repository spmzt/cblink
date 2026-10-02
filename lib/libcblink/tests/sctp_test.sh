#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# SCTP: message framing, streams over SCTP streams, multihoming, and
# DTLS 1.2 over SCTP (RFC 6083) with mutual authentication.
#

. "$(atf_get_srcdir)/cbl_test.subr"

: ${OPENSSL:=/usr/bin/openssl}

sctp_available()
{
	# sctp(4) may be a module that is not loaded.
	sysctl -n net.inet.sctp.auth_enable >/dev/null 2>&1 ||
	    atf_skip "SCTP is not available in this kernel"
}

mkcerts()
{
	cat > ext.cnf <<'XEOF'
[srv]
basicConstraints = CA:FALSE
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1
[cli]
basicConstraints = CA:FALSE
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://cblink.test/sctp
XEOF
	for ca in ca otherca; do
		${OPENSSL} req -x509 -newkey ec \
		    -pkeyopt ec_paramgen_curve:P-256 \
		    -nodes -keyout ${ca}.key -out ${ca}.crt -days 2 \
		    -subj "/CN=${ca}" -config /dev/null \
		    -addext "basicConstraints=critical,CA:TRUE" \
		    -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1 ||
		    atf_fail "ca"
	done
	for c in server:ca:srv client:ca:cli stranger:otherca:cli; do
		set -- $(echo $c | tr : ' ')
		${OPENSSL} req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
		    -nodes -keyout $1.key -out $1.csr -subj "/CN=$1" \
		    -config /dev/null >/dev/null 2>&1 &&
		${OPENSSL} x509 -req -in $1.csr -CA $2.crt -CAkey $2.key \
		    -CAcreateserial -out $1.crt -days 2 -extfile ext.cnf \
		    -extensions $3 >/dev/null 2>&1 || atf_fail "cert $1"
	done
}

atf_test_case plain cleanup
plain_head()
{
	atf_set "descr" "Plain SCTP: requests, dumps and streams"
}
plain_body()
{
	sctp_available
	start_server -p sctp://127.0.0.1:0
	atf_check -o match:"transport=sctp" -o match:"authenticated=0" \
	    ${PEER} call -p sctp://127.0.0.1:${port}
	atf_check -o inline:"value=9\n" ${PEER} call -p -o echo -N 9 \
	    sctp://127.0.0.1:${port}
	atf_check -o inline:"items=2000\n" ${PEER} call -p -o dump -N 2000 \
	    sctp://127.0.0.1:${port}
	# A cblink stream rides on its own SCTP stream.
	atf_check -o inline:"items=3000\n" ${PEER} call -p -o feed -N 3000 \
	    sctp://127.0.0.1:${port}
	# Frames far larger than one SCTP chunk are reassembled.
	atf_check -o inline:"bytes=900000\n" ${PEER} call -p -o echo \
	    -B 900000 sctp://127.0.0.1:${port}
	atf_check -s exit:1 -e match:"mTLS required" ${PEER} call \
	    sctp://127.0.0.1:${port}
}
plain_cleanup()
{
	stop_server
}

atf_test_case multihome cleanup
multihome_head()
{
	atf_set "descr" "A multihomed SCTP listener and client"
}
multihome_body()
{
	sctp_available
	# Both ends list two addresses of the loopback interface.
	ifconfig lo0 | grep -q 'inet6 ::1 ' ||
	    atf_skip "lo0 has no ::1 for a second address"
	start_server -p "sctp://127.0.0.1,[::1]:0"
	# The association has a path to each of the two addresses.
	atf_check -o match:"^paths=2$" -o match:"transport=sctp" \
	    ${PEER} call -p \
	    "sctp://127.0.0.1,[::1]:${port}"
	atf_check -o inline:"value=1\n" ${PEER} call -p -o echo -N 1 \
	    "sctp://127.0.0.1,[::1]:${port}"
	atf_check -o inline:"value=2\n" ${PEER} call -p -o echo -N 2 \
	    "sctp://[::1]:${port}"
}
multihome_cleanup()
{
	stop_server
}

atf_test_case dtls cleanup
dtls_head()
{
	atf_set "descr" "DTLS 1.2 over SCTP (RFC 6083) with mutual auth"
	atf_set "require.progs" "${OPENSSL}"
}
dtls_body()
{
	sctp_available
	mkcerts
	start_server -c server.crt -k server.key -a ca.crt \
	    sctp://127.0.0.1:0
	atf_check -o match:"subject=CN=client" -o match:"authenticated=1" \
	    -o match:"san=URI:spiffe://cblink.test/sctp" \
	    -o match:"transport=sctp" ${PEER} call -c client.crt -k client.key \
	    -a ca.crt sctp://127.0.0.1:${port}
	atf_check -o inline:"ok\n" ${PEER} call -o secret -c client.crt \
	    -k client.key -a ca.crt sctp://127.0.0.1:${port}
	atf_check -o inline:"items=500\n" ${PEER} call -o feed -N 500 \
	    -c client.crt -k client.key -a ca.crt sctp://127.0.0.1:${port}
	# Frames span many 16 KiB records.
	atf_check -o inline:"bytes=200000\n" ${PEER} call -o echo -B 200000 \
	    -c client.crt -k client.key -a ca.crt sctp://127.0.0.1:${port}
	atf_check -s exit:1 -e match:"." ${PEER} call -c stranger.crt \
	    -k stranger.key -a ca.crt sctp://127.0.0.1:${port}
	atf_check -s exit:1 -e match:"certificate verify failed" ${PEER} call \
	    -c client.crt -k client.key -a otherca.crt sctp://127.0.0.1:${port}
	atf_check -s exit:1 -e match:"." ${PEER} call -p \
	    sctp://127.0.0.1:${port}
}
dtls_cleanup()
{
	stop_server
}

atf_init_test_cases()
{
	atf_add_test_case plain
	atf_add_test_case multihome
	atf_add_test_case dtls
}
