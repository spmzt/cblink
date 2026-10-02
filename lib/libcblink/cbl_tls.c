/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * TLS and DTLS with base OpenSSL (docs/SECURITY.md).
 *
 * TLS is 1.3 only.  DTLS is 1.2 (the newest base OpenSSL has), restricted
 * to ECDHE with AEAD ciphers.  Peers are always verified: a server
 * demands a client certificate, a client checks the server's certificate
 * and name.  SSL_CTXs are built lazily per role and protocol and are
 * immutable afterwards, so connections share them without locking.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "cbl_impl.h"

#define	DTLS_CIPHERS	"ECDHE-ECDSA-AES256-GCM-SHA384:" \
			"ECDHE-RSA-AES256-GCM-SHA384:" \
			"ECDHE-ECDSA-CHACHA20-POLY1305:" \
			"ECDHE-RSA-CHACHA20-POLY1305:" \
			"ECDHE-ECDSA-AES128-GCM-SHA256:" \
			"ECDHE-RSA-AES128-GCM-SHA256"

struct cbl_tls {
	pthread_mutex_t	 mtx;
	atomic_uint	 refs;
	char		*cert;
	char		*key;
	char		*cafile;
	char		*capath;
	char		*crl;
	char		*peer_name;	/* NULL: the URI host; "": none */
	int		 depth;
	SSL_CTX		*ctx[CBL_TLS__KINDS];
	char		 err[256];
};

int
cbl_tls_new(cbl_tls **tlsp)
{
	cbl_tls *tls;

	if (tlsp == NULL)
		return (EINVAL);
	if ((tls = calloc(1, sizeof(*tls))) == NULL)
		return (ENOMEM);
	if (pthread_mutex_init(&tls->mtx, NULL) != 0) {
		free(tls);
		return (ENOMEM);
	}
	atomic_init(&tls->refs, 1);
	tls->depth = 8;
	*tlsp = tls;
	return (0);
}

void
cbl_tls_ref(cbl_tls *tls)
{

	atomic_fetch_add(&tls->refs, 1);
}

void
cbl_tls_free(cbl_tls *tls)
{

	if (tls == NULL || atomic_fetch_sub(&tls->refs, 1) != 1)
		return;
	for (int i = 0; i < CBL_TLS__KINDS; i++)
		SSL_CTX_free(tls->ctx[i]);
	free(tls->cert);
	free(tls->key);
	free(tls->cafile);
	free(tls->capath);
	free(tls->crl);
	free(tls->peer_name);
	pthread_mutex_destroy(&tls->mtx);
	free(tls);
}

const char *
cbl_tls_errstr(const cbl_tls *tls)
{

	if (tls == NULL)
		return ("invalid TLS configuration");
	return (tls->err[0] != '\0' ? tls->err : NULL);
}

/* Configuration is fixed once the first SSL_CTX exists. */
static int
set_str(cbl_tls *tls, char **dst, const char *src)
{
	char *s = NULL;
	int error = 0;

	if (tls == NULL)
		return (EINVAL);
	if (src != NULL && (s = strdup(src)) == NULL)
		return (ENOMEM);
	/*
	 * Any time: contexts already built keep what they were built with;
	 * the next one, or cbl_tls_reload(), reads the new setting.
	 */
	pthread_mutex_lock(&tls->mtx);
	free(*dst);
	*dst = s;
	pthread_mutex_unlock(&tls->mtx);
	return (error);
}

int
cbl_tls_set_cert(cbl_tls *tls, const char *certfile, const char *keyfile)
{
	int error;

	if (certfile == NULL || keyfile == NULL)
		return (EINVAL);
	if ((error = set_str(tls, &tls->cert, certfile)) != 0)
		return (error);
	return (set_str(tls, &tls->key, keyfile));
}

int
cbl_tls_set_ca(cbl_tls *tls, const char *cafile, const char *capath)
{
	int error;

	if (cafile == NULL && capath == NULL)
		return (EINVAL);
	if ((error = set_str(tls, &tls->cafile, cafile)) != 0)
		return (error);
	return (set_str(tls, &tls->capath, capath));
}

int
cbl_tls_set_crl(cbl_tls *tls, const char *crlfile)
{

	return (set_str(tls, &tls->crl, crlfile));
}

int
cbl_tls_set_peer_name(cbl_tls *tls, const char *name)
{

	return (set_str(tls, &tls->peer_name, name));
}

int
cbl_tls_set_verify_depth(cbl_tls *tls, int depth)
{

	if (tls == NULL || depth < 1 || depth > 32)
		return (EINVAL);
	pthread_mutex_lock(&tls->mtx);
	tls->depth = depth;
	pthread_mutex_unlock(&tls->mtx);
	return (0);
}

/* The most useful OpenSSL error, for errstr. */
static void
ssl_errstr(char *buf, size_t len, const char *what)
{
	unsigned long e = ERR_peek_last_error();
	char reason[160];

	if (e == 0)
		snprintf(buf, len, "%s failed", what);
	else {
		ERR_error_string_n(e, reason, sizeof(reason));
		snprintf(buf, len, "%s: %s", what, reason);
	}
	ERR_clear_error();
}

static int
no_password(char *buf __unused, int size __unused, int rwflag __unused,
    void *arg __unused)
{

	return (-1);
}

static SSL_CTX *
build_ctx(cbl_tls *tls, enum cbl_tls_kind kind)
{
	bool server = kind == CBL_TLS_SERVER || kind == CBL_DTLS_SERVER;
	bool dtls = kind == CBL_DTLS_SERVER || kind == CBL_DTLS_CLIENT;
	X509_LOOKUP *lookup;
	X509_STORE *store;
	SSL_CTX *c;

	ERR_clear_error();
	c = SSL_CTX_new(dtls ? (server ? DTLS_server_method() :
	    DTLS_client_method()) : (server ? TLS_server_method() :
	    TLS_client_method()));
	if (c == NULL) {
		ssl_errstr(tls->err, sizeof(tls->err), "SSL_CTX_new");
		return (NULL);
	}
	if (dtls) {
		if (!SSL_CTX_set_min_proto_version(c, DTLS1_2_VERSION) ||
		    !SSL_CTX_set_max_proto_version(c, DTLS1_2_VERSION) ||
		    !SSL_CTX_set_cipher_list(c, DTLS_CIPHERS))
			goto fail;
	} else if (!SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION) ||
	    !SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION))
		goto fail;
	/*
	 * No resumption: every connection does the full mutual verification,
	 * CRL included.
	 */
	SSL_CTX_set_options(c, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION |
	    SSL_OP_NO_TICKET);
	SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF);
	if (!dtls)
		(void)SSL_CTX_set_num_tickets(c, 0);
	/* An encrypted key fails to load instead of prompting on a tty. */
	SSL_CTX_set_default_passwd_cb(c, no_password);
	SSL_CTX_set_mode(c, SSL_MODE_ENABLE_PARTIAL_WRITE |
	    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	/* mTLS: both sides need a certificate and a trust anchor. */
	if (tls->cert == NULL || tls->key == NULL) {
		snprintf(tls->err, sizeof(tls->err),
		    "a certificate and key are required (cbl_tls_set_cert)");
		SSL_CTX_free(c);
		return (NULL);
	}
	if (tls->cafile == NULL && tls->capath == NULL) {
		snprintf(tls->err, sizeof(tls->err),
		    "a CA is required to verify peers (cbl_tls_set_ca)");
		SSL_CTX_free(c);
		return (NULL);
	}
	if (SSL_CTX_use_certificate_chain_file(c, tls->cert) != 1) {
		ssl_errstr(tls->err, sizeof(tls->err), tls->cert);
		SSL_CTX_free(c);
		return (NULL);
	}
	if (SSL_CTX_use_PrivateKey_file(c, tls->key, SSL_FILETYPE_PEM) != 1 ||
	    SSL_CTX_check_private_key(c) != 1) {
		ssl_errstr(tls->err, sizeof(tls->err), tls->key);
		SSL_CTX_free(c);
		return (NULL);
	}
	if (SSL_CTX_load_verify_locations(c, tls->cafile, tls->capath) != 1) {
		ssl_errstr(tls->err, sizeof(tls->err), "CA");
		SSL_CTX_free(c);
		return (NULL);
	}
	if (tls->crl != NULL) {
		/*
		 * Every CRL in the file: CRL_CHECK_ALL wants one for each CA
		 * of the chain, intermediates included.
		 */
		store = SSL_CTX_get_cert_store(c);
		if ((lookup = X509_STORE_add_lookup(store,
		    X509_LOOKUP_file())) == NULL ||
		    X509_load_crl_file(lookup, tls->crl, X509_FILETYPE_PEM) <=
		    0) {
			ssl_errstr(tls->err, sizeof(tls->err), tls->crl);
			SSL_CTX_free(c);
			return (NULL);
		}
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
		    X509_V_FLAG_CRL_CHECK_ALL);
	}
	SSL_CTX_set_verify_depth(c, tls->depth);
	if (server) {
		SSL_CTX_set_verify(c, SSL_VERIFY_PEER |
		    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		if (tls->cafile != NULL) {
			STACK_OF(X509_NAME) *names =
			    SSL_load_client_CA_file(tls->cafile);

			if (names != NULL)
				SSL_CTX_set_client_CA_list(c, names);
		}
	} else
		SSL_CTX_set_verify(c, SSL_VERIFY_PEER, NULL);
	return (c);
fail:
	ssl_errstr(tls->err, sizeof(tls->err), "TLS configuration");
	SSL_CTX_free(c);
	return (NULL);
}

SSL_CTX *
cbl_tls_ctx(cbl_tls *tls, enum cbl_tls_kind kind)
{
	SSL_CTX *c;

	pthread_mutex_lock(&tls->mtx);
	if ((c = tls->ctx[kind]) == NULL)
		c = tls->ctx[kind] = build_ctx(tls, kind);
	if (c != NULL)
		SSL_CTX_up_ref(c);	/* a reload may replace it any time */
	pthread_mutex_unlock(&tls->mtx);
	return (c);
}

/* Check the configuration early, for listeners and connections. */
int
cbl_tls_prepare(cbl_tls *tls, enum cbl_tls_kind kind, char *err,
    size_t errlen)
{
	SSL_CTX *c;

	if ((c = cbl_tls_ctx(tls, kind)) == NULL) {
		snprintf(err, errlen, "TLS: %s", tls->err);
		return (EINVAL);
	}
	SSL_CTX_free(c);
	return (0);
}

/*
 * Pick up renewed certificates, keys, CAs and CRLs (the files, or new
 * paths set meanwhile): every context in use is built again and replaces
 * the old one for connections made from now on; open connections keep
 * theirs.  Nothing changes if any of them fails to build.  Any thread.
 */
int
cbl_tls_reload(cbl_tls *tls)
{
	SSL_CTX *fresh[CBL_TLS__KINDS] = { 0 };
	int error = 0;

	if (tls == NULL)
		return (EINVAL);
	pthread_mutex_lock(&tls->mtx);
	for (int k = 0; k < CBL_TLS__KINDS && error == 0; k++)
		if (tls->ctx[k] != NULL &&
		    (fresh[k] = build_ctx(tls, (enum cbl_tls_kind)k)) == NULL)
			error = EINVAL;
	for (int k = 0; k < CBL_TLS__KINDS; k++) {
		if (fresh[k] == NULL)
			continue;
		if (error != 0) {
			SSL_CTX_free(fresh[k]);
			continue;
		}
		SSL_CTX_free(tls->ctx[k]);	/* SSLs keep their references */
		tls->ctx[k] = fresh[k];
	}
	pthread_mutex_unlock(&tls->mtx);
	return (error);
}

/*
 * Peer identity from a verified certificate: RFC 2253 subject and
 * issuer, SANs, SHA-256 and SHA-1 fingerprints.
 */
static char *
name_str(const X509_NAME *n)
{
	BIO *bio;
	char *s = NULL;
	long len;
	char *p;

	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		return (NULL);
	if (X509_NAME_print_ex(bio, n, 0, XN_FLAG_RFC2253) >= 0 &&
	    (len = BIO_get_mem_data(bio, &p)) >= 0 &&
	    (s = malloc((size_t)len + 1)) != NULL) {
		memcpy(s, p, (size_t)len);
		s[len] = '\0';
	}
	BIO_free(bio);
	return (s);
}

static void
add_san(struct cbl_peer *peer, const char *prefix, const char *v, size_t len)
{
	char **ns, *s;

	if (peer->nsans >= 64 || memchr(v, '\0', len) != NULL)
		return;
	if ((s = malloc(strlen(prefix) + len + 1)) == NULL)
		return;
	memcpy(s, prefix, strlen(prefix));
	memcpy(s + strlen(prefix), v, len);
	s[strlen(prefix) + len] = '\0';
	if ((ns = reallocarray(peer->sans, peer->nsans + 1,
	    sizeof(*ns))) == NULL) {
		free(s);
		return;
	}
	peer->sans = ns;
	peer->sans[peer->nsans++] = s;
}

int
cbl_peer_from_x509(struct cbl_peer *peer, X509 *x)
{
	GENERAL_NAMES *gens;
	unsigned int len;
	char ip[INET6_ADDRSTRLEN];

	peer->subject = name_str(X509_get_subject_name(x));
	peer->issuer = name_str(X509_get_issuer_name(x));
	len = sizeof(peer->fp_sha256);
	peer->has_sha256 = X509_digest(x, EVP_sha256(), peer->fp_sha256,
	    &len) == 1;
	len = sizeof(peer->fp_sha1);
	peer->has_sha1 = X509_digest(x, EVP_sha1(), peer->fp_sha1, &len) == 1;
	gens = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
	for (int i = 0; gens != NULL && i < sk_GENERAL_NAME_num(gens); i++) {
		const GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
		const ASN1_STRING *a;

		switch (g->type) {
		case GEN_DNS:
			a = g->d.dNSName;
			add_san(peer, "DNS:",
			    (const char *)ASN1_STRING_get0_data(a),
			    (size_t)ASN1_STRING_length(a));
			break;
		case GEN_URI:
			a = g->d.uniformResourceIdentifier;
			add_san(peer, "URI:",
			    (const char *)ASN1_STRING_get0_data(a),
			    (size_t)ASN1_STRING_length(a));
			break;
		case GEN_EMAIL:
			a = g->d.rfc822Name;
			add_san(peer, "email:",
			    (const char *)ASN1_STRING_get0_data(a),
			    (size_t)ASN1_STRING_length(a));
			break;
		case GEN_IPADD:
			/* Only an IPv4 or IPv6 address, checked before use. */
			a = g->d.iPAddress;
			if ((ASN1_STRING_length(a) == 4 ||
			    ASN1_STRING_length(a) == 16) &&
			    inet_ntop(ASN1_STRING_length(a) == 4 ? AF_INET :
			    AF_INET6, ASN1_STRING_get0_data(a), ip,
			    sizeof(ip)) != NULL)
				add_san(peer, "IP:", ip, strlen(ip));
			break;
		default:
			break;
		}
	}
	GENERAL_NAMES_free(gens);
	return (peer->subject != NULL ? 0 : ENOMEM);
}

/* TLS transport. */
struct tls_tr {
	SSL	*ssl;
	bool	 tcp_pending;	/* DTLS/SCTP client: connect not finished */
	/* DTLS over SCTP: frames reassembled per SCTP stream. */
	struct cbl_sctp_mux *mux;
	unsigned char *chunk;
};

static int
want_from(cbl_conn *conn, int rv, const char *what)
{
	struct tls_tr *t = conn->trpriv;
	long vr;

	switch (SSL_get_error(t->ssl, rv)) {
	case SSL_ERROR_WANT_READ:
		conn->want = CBL_EV_READ;
		return (EAGAIN);
	case SSL_ERROR_WANT_WRITE:
		conn->want = CBL_EV_WRITE;
		return (EAGAIN);
	case SSL_ERROR_ZERO_RETURN:
		ERR_clear_error();
		return (ECONNRESET);
	case SSL_ERROR_SYSCALL:
		if (ERR_peek_error() == 0) {
			int e = errno != 0 ? errno : ECONNRESET;

			cbl_conn_seterr(conn, e, "%s: %s", what, strerror(e));
			return (e);
		}
		/* FALLTHROUGH */
	default:
		vr = SSL_get_verify_result(t->ssl);
		if (vr != X509_V_OK) {
			cbl_conn_seterr(conn, EAUTH, "%s: certificate verify "
			    "failed: %s", what,
			    X509_verify_cert_error_string(vr));
			ERR_clear_error();
			return (EAUTH);
		}
		ssl_errstr(conn->errstr, sizeof(conn->errstr), what);
		return (EPROTO);
	}
}

static int
tls_handshake(cbl_conn *conn)
{
	struct tls_tr *t = conn->trpriv;
	struct pollfd pfd = { .fd = conn->fd, .events = POLLOUT };
	socklen_t len = sizeof(int);
	X509 *x;
	int rv, soerr = 0;

	if (t->tcp_pending) {
		if (poll(&pfd, 1, 0) == 0) {
			conn->want = CBL_EV_WRITE;
			return (EAGAIN);
		}
		if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &soerr,
		    &len) == -1 || soerr != 0)
			return (cbl_conn_seterr(conn,
			    soerr != 0 ? soerr : errno, "connect: %s",
			    strerror(soerr != 0 ? soerr : errno)));
		t->tcp_pending = false;
	}
	ERR_clear_error();
	if ((rv = SSL_do_handshake(t->ssl)) != 1)
		return (want_from(conn, rv, "TLS handshake"));
	conn->want = 0;
	/* Both directions are verified; record who is on the other side. */
	if ((x = SSL_get0_peer_certificate(t->ssl)) == NULL ||
	    SSL_get_verify_result(t->ssl) != X509_V_OK)
		return (cbl_conn_seterr(conn, EAUTH,
		    "peer presented no verifiable certificate"));
	cbl_peer_clear_identity(&conn->peer);
	(void)cbl_peer_from_x509(&conn->peer, x);
	conn->peer.flags |= CBL_PEER_AUTHENTICATED;
	return (0);
}

static int
tls_read(cbl_conn *conn, void *buf, size_t len, size_t *got)
{
	struct tls_tr *t = conn->trpriv;
	int rv, error;

	ERR_clear_error();
	if ((rv = SSL_read_ex(t->ssl, buf, len, got)) == 1)
		return (0);
	error = want_from(conn, rv, "TLS read");
	if (error == ECONNRESET) {
		*got = 0;		/* close_notify: orderly EOF */
		return (0);
	}
	return (error);
}

static int
tls_write(cbl_conn *conn, const void *buf, size_t len, size_t *put)
{
	struct tls_tr *t = conn->trpriv;
	int rv;

	ERR_clear_error();
	if ((rv = SSL_write_ex(t->ssl, buf, len, put)) == 1)
		return (0);
	return (want_from(conn, rv, "TLS write"));
}

static void
tls_shutdown(cbl_conn *conn)
{
	struct tls_tr *t = conn->trpriv;

	if (t != NULL && SSL_is_init_finished(t->ssl))
		(void)SSL_shutdown(t->ssl);	/* best effort, no wait */
	ERR_clear_error();
	if (conn->fd != -1)
		(void)shutdown(conn->fd, SHUT_WR);
}

static void
tls_free(cbl_conn *conn)
{
	struct tls_tr *t = conn->trpriv;

	if (t == NULL)
		return;
	SSL_free(t->ssl);
	cbl_sctp_mux_free(t->mux);
	free(t->chunk);
	free(t);
	conn->trpriv = NULL;
}

const struct cbl_tr_ops cbl_tr_tls_ops = {
	.name = "tls",
	.handshake = tls_handshake,
	.read = tls_read,
	.write = tls_write,
	.shutdown = tls_shutdown,
	.free = tls_free,
};

static bool
is_ip(const char *s)
{
	struct in6_addr a6;
	struct in_addr a4;

	return (inet_pton(AF_INET, s, &a4) == 1 ||
	    inet_pton(AF_INET6, s, &a6) == 1);
}

/*
 * Client name check: cbl_tls_set_peer_name(), or by default the first
 * host of the URI (an IP address is matched against IP SANs).
 */
static void
set_peer_name(cbl_conn *conn, cbl_tls *tls, SSL *ssl)
{
	const char *name = NULL;
	char host[256], set[256];

	pthread_mutex_lock(&tls->mtx);
	if (tls->peer_name != NULL) {
		strlcpy(set, tls->peer_name, sizeof(set));
		name = set;
	}
	pthread_mutex_unlock(&tls->mtx);
	if (name == NULL) {
		strlcpy(host, conn->uri.host, sizeof(host));
		host[strcspn(host, ",")] = '\0';
		if (host[0] == '[') {
			memmove(host, host + 1, strlen(host));
			host[strcspn(host, "]")] = '\0';
		}
		name = host;
	}
	if (*name == '\0')
		return;
	if (is_ip(name))
		(void)X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), name);
	else {
		char sni[256];

		/* The macro wants a mutable string. */
		strlcpy(sni, name, sizeof(sni));
		(void)SSL_set_tlsext_host_name(ssl, sni);
		(void)SSL_set1_host(ssl, name);
	}
}

/*
 * Put TLS on a connected (or connecting) socket.  A client checks the
 * server certificate against cbl_tls_set_peer_name() or, by default, the
 * host in its URI.
 */
int
cbl_tls_attach(cbl_conn *conn, cbl_tls *tls, bool server)
{
	struct tls_tr *t;
	SSL_CTX *c;

	if ((c = cbl_tls_ctx(tls, server ? CBL_TLS_SERVER :
	    CBL_TLS_CLIENT)) == NULL)
		return (cbl_conn_seterr(conn, EINVAL, "TLS: %s", tls->err));
	if ((t = calloc(1, sizeof(*t))) == NULL) {
		SSL_CTX_free(c);
		return (ENOMEM);
	}
	t->ssl = SSL_new(c);
	SSL_CTX_free(c);		/* the SSL holds its own reference */
	if (t->ssl == NULL || SSL_set_fd(t->ssl, conn->fd) != 1) {
		SSL_free(t->ssl);
		free(t);
		return (cbl_conn_seterr(conn, ENOMEM, "SSL_new failed"));
	}
	if (server)
		SSL_set_accept_state(t->ssl);
	else {
		SSL_set_connect_state(t->ssl);
		set_peer_name(conn, tls, t->ssl);
	}
	conn->trpriv = t;
	conn->ops = &cbl_tr_tls_ops;
	conn->want = server ? CBL_EV_READ : CBL_EV_WRITE;
	return (0);
}

#define	DTLS_SCTP_RECORD	16384	/* the most plaintext in a record */

/*
 * DTLS 1.2 over SCTP (RFC 6083).  Each SCTP stream carries a byte stream
 * of frames delimited by their length field, and cblink streams are mapped
 * to SCTP streams as in plaintext.  OpenSSL's SCTP BIO fixes the MTU at
 * 16 KiB including the record overhead, so a frame is written one
 * record's worth of plaintext at a time.
 */
static void
dtls_sctp_frame_start(cbl_conn *conn, const void *frame, size_t len)
{
	struct tls_tr *t = conn->trpriv;
	struct bio_dgram_sctp_sndinfo si = { 0 };

	/* Application data only: handshake records stay on stream 0. */
	si.snd_sid = cbl_sctp_mux_sid(t->mux, conn->fd, frame, len);
	(void)BIO_ctrl(SSL_get_wbio(t->ssl), BIO_CTRL_DGRAM_SCTP_SET_SNDINFO,
	    sizeof(si), &si);
}

/*
 * Read records; OpenSSL keeps the SCTP stream of each one, buffered ones
 * included (BIO_CTRL_DGRAM_SCTP_GET_RCVINFO).
 */
static int
dtls_sctp_rx_frames(cbl_conn *conn, int budget)
{
	struct tls_tr *t = conn->trpriv;
	struct bio_dgram_sctp_rcvinfo ri;
	size_t got;
	int error;

	if (t->chunk == NULL && (t->chunk = malloc(DTLS_SCTP_RECORD)) == NULL)
		return (ENOMEM);
	while (budget > 0 && conn->state == CBL_CS_OPEN) {
		error = tls_read(conn, t->chunk, DTLS_SCTP_RECORD, &got);
		if (error == EAGAIN)
			return (0);
		if (error != 0)
			return (error);
		if (got == 0)
			return (ECONNRESET);
		memset(&ri, 0, sizeof(ri));
		(void)BIO_ctrl(SSL_get_rbio(t->ssl),
		    BIO_CTRL_DGRAM_SCTP_GET_RCVINFO, sizeof(ri), &ri);
		if ((error = cbl_sctp_mux_bytes(conn, t->mux, ri.rcv_sid,
		    t->chunk, got)) != 0)
			return (error);
		budget--;
	}
	if (budget == 0)
		conn->rx_pending = true;
	return (0);
}

static int
dtls_sctp_write(cbl_conn *conn, const void *buf, size_t len, size_t *put)
{
	struct tls_tr *t = conn->trpriv;
	size_t max;

	if ((max = DTLS_get_data_mtu(t->ssl)) == 0 || max > 16384)
		max = 16384 - 256;
	return (tls_write(conn, buf, len > max ? max : len, put));
}

/*
 * Before switching keys, OpenSSL waits for the SCTP SENDER_DRY event.  If
 * the event arrives while OpenSSL is reading for alerts, its BIO consumes
 * it, and nothing else arrives to make the socket readable: the peer is
 * waiting for our Finished.  Retrying the handshake re-arms the event,
 * which FreeBSD raises at once on an idle association, so poll for it.
 */
#define	DTLS_SCTP_DRY_POLL	50	/* ms */

static int
dtls_sctp_timeout(cbl_conn *conn)
{
	struct tls_tr *t = conn->trpriv;

	return (SSL_is_init_finished(t->ssl) ? -1 : DTLS_SCTP_DRY_POLL);
}

static void
dtls_sctp_on_timeout(cbl_conn *conn __unused)
{

	/* cbl_conn_process() and handshake_wait() retry the handshake. */
}

const struct cbl_tr_ops cbl_tr_dtls_sctp_ops = {
	.name = "dtls-sctp",
	.handshake = tls_handshake,
	.timeout = dtls_sctp_timeout,
	.on_timeout = dtls_sctp_on_timeout,
	.write = dtls_sctp_write,
	.frame_start = dtls_sctp_frame_start,
	.rx_frames = dtls_sctp_rx_frames,
	.shutdown = tls_shutdown,
	.free = tls_free,
};

int
cbl_dtls_sctp_attach(cbl_conn *conn, cbl_tls *tls, bool server)
{
	struct tls_tr *t;
	SSL_CTX *c;
	BIO *bio;

	if ((c = cbl_tls_ctx(tls, server ? CBL_DTLS_SERVER :
	    CBL_DTLS_CLIENT)) == NULL)
		return (cbl_conn_seterr(conn, EINVAL, "DTLS: %s", tls->err));
	if ((t = calloc(1, sizeof(*t))) == NULL) {
		SSL_CTX_free(c);
		return (ENOMEM);
	}
	if ((t->mux = cbl_sctp_mux_new()) == NULL) {
		SSL_CTX_free(c);
		free(t);
		return (ENOMEM);
	}
	t->ssl = SSL_new(c);
	SSL_CTX_free(c);		/* the SSL holds its own reference */
	if (t->ssl == NULL ||
	    (bio = BIO_new_dgram_sctp(conn->fd, BIO_NOCLOSE)) == NULL) {
		cbl_sctp_mux_free(t->mux);
		SSL_free(t->ssl);
		free(t);
		return (cbl_conn_seterr(conn, EPROTONOSUPPORT,
		    "DTLS over SCTP is not available"));
	}
	SSL_set_bio(t->ssl, bio, bio);
	/* Non-blocking clients first finish the SCTP association. */
	t->tcp_pending = !server && (conn->flags & CBL_CF_NONBLOCK) != 0;
	if (server)
		SSL_set_accept_state(t->ssl);
	else {
		SSL_set_connect_state(t->ssl);
		set_peer_name(conn, tls, t->ssl);
	}
	conn->trpriv = t;
	conn->ops = &cbl_tr_dtls_sctp_ops;
	conn->want = server ? CBL_EV_READ : CBL_EV_WRITE;
	return (0);
}

