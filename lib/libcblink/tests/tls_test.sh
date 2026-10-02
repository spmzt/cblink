#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# mTLS over TCP: certificates made with openssl(1), the identity handlers
# see, and the negative cases.
#

. "$(atf_get_srcdir)/cbl_test.subr"

: ${OPENSSL:=/usr/bin/openssl}


# A CA, a server certificate and client certificates, good and bad.
mkcerts()
{
	cat > ext.cnf <<'XEOF'
[srv]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
[cli]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://cblink.test/client1, email:client1@cblink.test
XEOF
	for ca in ca otherca; do
		${OPENSSL} req -x509 -newkey ec \
		    -pkeyopt ec_paramgen_curve:P-256 \
		    -nodes -keyout ${ca}.key -out ${ca}.crt -days 2 \
		    -subj "/CN=cblink test ${ca}" -config /dev/null \
		    -addext "basicConstraints=critical,CA:TRUE" \
		    -addext "keyUsage=critical,keyCertSign,cRLSign" \
		    >/dev/null 2>&1 ||
		    atf_fail "cannot create ${ca}"
	done
	leaf server ca srv
	leaf client ca cli
	leaf stranger otherca cli
	leaf expired ca cli -not_before 20200101000000Z \
	    -not_after 20200102000000Z
	leaf notclient ca srv	# serverAuth only: not a client
}

# leaf name ca extensions [x509 validity options]
leaf()
{
	_leaf_name=$1
	_leaf_ca=$2
	_leaf_ext=$3
	shift 3
	[ $# -eq 0 ] && set -- -days 2

	${OPENSSL} req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout ${_leaf_name}.key -out ${_leaf_name}.csr \
	    -subj "/O=cblink/CN=${_leaf_name}" -config /dev/null \
	    >/dev/null 2>&1 || atf_fail "csr ${_leaf_name}"
	${OPENSSL} x509 -req -in ${_leaf_name}.csr -CA ${_leaf_ca}.crt \
	    -CAkey ${_leaf_ca}.key -CAcreateserial -out ${_leaf_name}.crt \
	    -extfile ext.cnf -extensions ${_leaf_ext} "$@" \
	    >/dev/null 2>&1 || atf_fail "cert ${_leaf_name}"
}

tls_server()
{
	start_server -c server.crt -k server.key -a ca.crt \
	    tcp://127.0.0.1:0
}

atf_test_case mtls cleanup
mtls_head()
{
	atf_set "descr" "Mutual TLS 1.3: the handler sees the client identity"
	atf_set "require.progs" "${OPENSSL}"
}
mtls_body()
{
	mkcerts
	tls_server
	atf_check -o match:"subject=CN=client,O=cblink" \
	    -o match:"issuer=CN=cblink test ca" \
	    -o match:"san=URI:spiffe://cblink.test/client1" \
	    -o match:"san=email:client1@cblink.test" \
	    -o match:"sha256=[0-9a-f]{64}" -o match:"authenticated=1" \
	    $PEER call -c client.crt -k client.key -a ca.crt \
	    tcp://127.0.0.1:${port}
	# The fingerprint is the certificate's SHA-256.
	fp=$(${OPENSSL} x509 -in client.crt -noout -fingerprint -sha256 |
	    sed 's/.*=//; s/://g' | tr A-F a-f)
	atf_check -o match:"sha256=${fp}" $PEER call -c client.crt \
	    -k client.key -a ca.crt tcp://127.0.0.1:${port}
	# An authenticated peer may use auth-only commands.
	atf_check -o inline:"ok\n" $PEER call -o secret -c client.crt \
	    -k client.key -a ca.crt tcp://127.0.0.1:${port}
	# Name checks: the URI host (an IP SAN here), or an explicit name.
	atf_check -o ignore $PEER call -n localhost -c client.crt \
	    -k client.key -a ca.crt tcp://127.0.0.1:${port}
	# TLS 1.3 is the only version on offer.
	atf_check -o match:"TLSv1.3" -e ignore sh -c "echo | ${OPENSSL} \
	    s_client -connect 127.0.0.1:${port} -cert client.crt \
	    -key client.key -CAfile ca.crt -brief 2>&1"
	atf_check -s not-exit:0 -o ignore -e ignore sh -c "echo | \
	    ${OPENSSL} s_client -connect 127.0.0.1:${port} -tls1_2 \
	    -cert client.crt -key client.key -CAfile ca.crt"
}
mtls_cleanup()
{
	stop_server
}

atf_test_case no_client_cert cleanup
no_client_cert_head()
{
	atf_set "descr" "A client without a certificate is refused"
	atf_set "require.progs" "${OPENSSL}"
}
no_client_cert_body()
{
	mkcerts
	tls_server
	# libcblink will not even try mTLS without a certificate ...
	atf_check -s exit:1 -e match:"certificate and key are required" \
	    $PEER call -a ca.crt tcp://127.0.0.1:${port}
	# ... and the server refuses a client that does not present one.
	atf_check -s not-exit:0 -o ignore -e ignore sh -c "echo | \
	    ${OPENSSL} s_client -connect 127.0.0.1:${port} -CAfile ca.crt \
	    -ign_eof"
	atf_check -s ignore -o match:"alert certificate required" \
	    -e ignore sh -c \
	    "echo | ${OPENSSL} s_client -connect 127.0.0.1:${port} \
	    -CAfile ca.crt -ign_eof 2>&1"
}
no_client_cert_cleanup()
{
	stop_server
}

atf_test_case wrong_ca cleanup
wrong_ca_head()
{
	atf_set "descr" "Certificates from an untrusted CA are refused"
	atf_set "require.progs" "${OPENSSL}"
}
wrong_ca_body()
{
	mkcerts
	tls_server
	# A client certificate from another CA.
	atf_check -s exit:1 -e match:"." $PEER call -c stranger.crt \
	    -k stranger.key -a ca.crt tcp://127.0.0.1:${port}
	# A client that trusts another CA rejects the server.
	atf_check -s exit:1 -e match:"certificate verify failed" $PEER call \
	    -c client.crt -k client.key -a otherca.crt \
	    tcp://127.0.0.1:${port}
	# A server certificate for another name.
	atf_check -s exit:1 -e match:"hostname mismatch|certificate verify" \
	    $PEER call -n wrong.example -c client.crt -k client.key -a ca.crt \
	    tcp://127.0.0.1:${port}
}
wrong_ca_cleanup()
{
	stop_server
}

atf_test_case expired cleanup
expired_head()
{
	atf_set "descr" "Expired and wrong-purpose client certificates fail"
	atf_set "require.progs" "${OPENSSL}"
}
expired_body()
{
	mkcerts
	tls_server
	atf_check -s exit:1 -e match:"." $PEER call -c expired.crt \
	    -k expired.key -a ca.crt tcp://127.0.0.1:${port}
	atf_check -s ignore \
	    -o match:"certificate has expired|alert certificate expired" \
	    -e ignore sh -c "echo | ${OPENSSL} s_client -connect \
	    127.0.0.1:${port} -cert expired.crt -key expired.key \
	    -CAfile ca.crt -ign_eof 2>&1"
	atf_check -s exit:1 -e match:"." $PEER call -c notclient.crt \
	    -k notclient.key -a ca.crt tcp://127.0.0.1:${port}
}
expired_cleanup()
{
	stop_server
}

atf_test_case plaintext cleanup
plaintext_head()
{
	atf_set "descr" "Plaintext needs an explicit opt-in on both sides"
	atf_set "require.progs" "${OPENSSL}"
}
plaintext_body()
{
	mkcerts
	tls_server
	# A plaintext client cannot talk to a TLS server.
	atf_check -s exit:1 -e match:"." $PEER call -p tcp://127.0.0.1:${port}
	stop_server
	# A TLS client cannot talk to a plaintext server.
	start_server -p tcp://127.0.0.1:0
	atf_check -s exit:1 -e match:"TLS" $PEER call -c client.crt \
	    -k client.key -a ca.crt tcp://127.0.0.1:${port}
	# Without the opt-in a plaintext connection is not even attempted.
	atf_check -s exit:1 -e match:"mTLS required" $PEER call \
	    tcp://127.0.0.1:${port}
	atf_check -o match:"authenticated=0" $PEER call -p \
	    tcp://127.0.0.1:${port}
	atf_check -s exit:1 -e match:"Permission denied: authenticated" \
	    $PEER call -p -o secret tcp://127.0.0.1:${port}
}
plaintext_cleanup()
{
	stop_server
}

atf_test_case proxy cleanup
proxy_head()
{
	atf_set "descr" "mTLS end to end through a proxy sending a PROXY header"
	atf_set "require.progs" "${OPENSSL}"
}
proxy_body()
{
	mkcerts
	start_server -P -c server.crt -k server.key -a ca.crt \
	    tcp://127.0.0.1:0
	for v in 1 2; do
		opt=
		[ $v -eq 1 ] && opt=-1
		"${PEER}" relay ${opt} -d relay${v}.pid ${port} \
		    > relay${v}.out 2> relay${v}.err ||
		    atf_fail "relay did not start: $(cat relay${v}.err)"
		rport=$(awk '/^ready/ { print $2 }' relay${v}.out)
		# The client's certificate still reaches the server, and the
		# address is the one the proxy names.
		atf_check -o match:"subject=CN=client,O=cblink" \
		    -o match:"authenticated=1" -o match:"proxied=1" \
		    -o match:"addr=192\.0\.2\.7" \
		    $PEER call -c client.crt -k client.key -a ca.crt \
		    tcp://127.0.0.1:${rport}
	done
	# Without a PROXY header the connection is refused.
	atf_check -s exit:1 -e match:"." $PEER call -c client.crt \
	    -k client.key -a ca.crt tcp://127.0.0.1:${port}
}
proxy_cleanup()
{
	stop_server
	for f in relay1.pid relay2.pid; do
		[ -s $f ] && kill "$(cat $f)" 2>/dev/null
	done
	true
}

# A root CA, an intermediate CA, leaves signed by the intermediate, and a
# CRL from each CA (openssl ca keeps each one's revocations in its dir).
mkchain()
{
	cat > ca.cnf <<'XEOF'
[ca]
default_ca = ca_default
[ca_default]
database = $ENV::CADIR/index.txt
crlnumber = $ENV::CADIR/crlnumber
default_md = sha256
default_crl_days = 2
XEOF
	cat > chain.cnf <<'XEOF'
[inter]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[srv]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1
[cli]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
XEOF
	${OPENSSL} req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
	    -nodes -keyout root.key -out root.crt -days 2 \
	    -subj "/CN=cblink test root" -config /dev/null \
	    -addext "basicConstraints=critical,CA:TRUE" \
	    -addext "keyUsage=critical,keyCertSign,cRLSign" \
	    >/dev/null 2>&1 || atf_fail "root CA"
	sign inter root inter
	sign server inter srv
	sign client inter cli
	cat server.crt inter.crt > server-chain.crt
	cat client.crt inter.crt > client-chain.crt
	for ca in root inter; do
		mkdir ${ca}db
		: > ${ca}db/index.txt
		echo 01 > ${ca}db/crlnumber
	done
	crls
}

# sign name issuer extensions: a key and a certificate issued by "issuer".
sign()
{
	${OPENSSL} req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout $1.key -out $1.csr -subj "/O=cblink/CN=$1" \
	    -config /dev/null >/dev/null 2>&1 || atf_fail "csr $1"
	${OPENSSL} x509 -req -in $1.csr -CA $2.crt -CAkey $2.key \
	    -CAcreateserial -out $1.crt -days 2 -extfile chain.cnf \
	    -extensions $3 >/dev/null 2>&1 || atf_fail "cert $1"
}

# crls: one file with both CAs' CRLs, the root's first.
crls()
{
	for ca in root inter; do
		CADIR=${ca}db ${OPENSSL} ca -config ca.cnf -gencrl \
		    -keyfile ${ca}.key -cert ${ca}.crt -out ${ca}.crl \
		    >/dev/null 2>&1 || atf_fail "CRL of ${ca}"
	done
	cat root.crl inter.crl > crls.pem
}

atf_test_case crl_chain cleanup
crl_chain_head()
{
	atf_set "descr" "CRLs for every CA of a chain with an intermediate"
	atf_set "require.progs" "${OPENSSL}"
}
crl_chain_body()
{
	mkchain
	start_server -c server-chain.crt -k server.key -a root.crt \
	    -r crls.pem tcp://127.0.0.1:0
	atf_check -o match:"subject=CN=client,O=cblink" \
	    -o match:"authenticated=1" \
	    $PEER call -c client-chain.crt -k client.key -a root.crt \
	    tcp://127.0.0.1:${port}
	# Revoked by the intermediate: refused.
	CADIR=interdb ${OPENSSL} ca -config ca.cnf -revoke client.crt \
	    -keyfile inter.key -cert inter.crt >/dev/null 2>&1 ||
	    atf_fail "revoke"
	crls
	# Not before the configuration is reloaded.
	atf_check -o match:"authenticated=1" \
	    $PEER call -c client-chain.crt -k client.key -a root.crt \
	    tcp://127.0.0.1:${port}
	# The running server rereads it on cbl_tls_reload() (SIGHUP here).
	kill -HUP "$(cat server.pid)"
	retry 5 refused || atf_fail "still accepted after the reload"
}

# The revoked client is turned away.
refused()
{
	! $PEER call -c client-chain.crt -k client.key -a root.crt \
	    tcp://127.0.0.1:${port} >/dev/null 2>&1
}

crl_chain_cleanup()
{
	stop_server
}

atf_init_test_cases()
{
	atf_add_test_case mtls
	atf_add_test_case no_client_cert
	atf_add_test_case wrong_ca
	atf_add_test_case expired
	atf_add_test_case plaintext
	atf_add_test_case proxy
	atf_add_test_case crl_chain
}
