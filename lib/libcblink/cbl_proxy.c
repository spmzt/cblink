/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The PROXY protocol, versions 1 and 2, on listeners created with
 * CBL_LF_PROXY.  A TCP proxy in front (nginx "stream" with proxy_protocol,
 * HAProxy with send-proxy or send-proxy-v2) starts every connection with a
 * header that names the client's address.  The header is read before TLS
 * and never past its end: what follows, such as a TLS ClientHello, stays
 * in the socket for the transport.  Only the source address is used.
 * TLVs are skipped: identity comes from the end-to-end mTLS
 * (docs/TRANSPORTS.md section 5).
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"

#define	PP_MIN		15	/* "PROXY UNKNOWN\r\n", the shortest header */
#define	PP1_MAX		107	/* the longest version 1 line */
#define	PP2_HDR		16	/* version 2 fixed part */
#define	PP2_MAX		536	/* the size a receiver must accept */

static const unsigned char pp2_sig[12] = {
	0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
};

/* One recv(2); 0 with *np > 0, or EAGAIN (waiting for READ) or an error. */
static int
pp_recv(cbl_conn *conn, size_t len, int flags, size_t *np)
{
	ssize_t n;

	for (;;) {
		n = recv(conn->fd, conn->proxy_buf + conn->proxy_len, len,
		    flags);
		if (n > 0) {
			*np = (size_t)n;
			return (0);
		}
		if (n == 0)
			return (ECONNRESET);
		if (errno == EAGAIN) {
			conn->want = CBL_EV_READ;
			return (EAGAIN);
		}
		if (errno != EINTR)
			return (errno);
	}
}

/* Have at least "want" bytes of header: read exactly up to it. */
static int
pp_fill(cbl_conn *conn, size_t want)
{
	size_t n;
	int error;

	while (conn->proxy_len < want) {
		if ((error = pp_recv(conn, want - conn->proxy_len, 0, &n)) != 0)
			return (error);
		conn->proxy_len += n;
	}
	return (0);
}

/* Version 1: read through the LF, peeking first so as not to pass it. */
static int
pp1_fill(cbl_conn *conn)
{
	unsigned char *p = conn->proxy_buf, *lf;
	size_t n;
	int error;

	while ((lf = memchr(p, '\n', conn->proxy_len)) == NULL) {
		if (conn->proxy_len >= PP1_MAX)
			return (EMSGSIZE);
		if ((error = pp_recv(conn, PP1_MAX - conn->proxy_len, MSG_PEEK,
		    &n)) != 0)
			return (error);
		lf = memchr(p + conn->proxy_len, '\n', n);
		if ((error = pp_fill(conn, lf != NULL ?
		    (size_t)(lf - p) + 1 : conn->proxy_len + n)) != 0)
			return (error);
	}
	return ((size_t)(lf - p) + 1 == conn->proxy_len ? 0 : EBADMSG);
}

static bool
pp1_port(const char *s, in_port_t *portp)
{
	unsigned long v = 0;

	if (*s == '\0' || strlen(s) > 5 || (s[0] == '0' && s[1] != '\0'))
		return (false);
	for (; *s != '\0'; s++) {
		if (*s < '0' || *s > '9')
			return (false);
		v = v * 10 + (unsigned long)(*s - '0');
	}
	if (v > 65535)
		return (false);
	*portp = htons((in_port_t)v);
	return (true);
}

/*
 * "PROXY TCP4 src dst sport dport\r\n", likewise TCP6, or "PROXY UNKNOWN"
 * followed by anything.  Returns why it is malformed, or NULL.
 */
static const char *
pp1_parse(cbl_conn *conn, struct sockaddr_storage *ss, bool *have)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)(void *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)ss;
	char line[PP1_MAX], *f[7], *last;
	size_t len = conn->proxy_len;
	in_port_t dport;
	int nf = 0;

	if (len < 2 || conn->proxy_buf[len - 2] != '\r' ||
	    memchr(conn->proxy_buf, '\0', len) != NULL)
		return ("malformed version 1 line");
	memcpy(line, conn->proxy_buf, len - 2);
	line[len - 2] = '\0';
	for (char *s = strtok_r(line, " ", &last); s != NULL && nf < 7;
	    s = strtok_r(NULL, " ", &last))
		f[nf++] = s;
	if (nf >= 2 && strcmp(f[1], "UNKNOWN") == 0)
		return (NULL);
	if (nf != 6)
		return ("malformed version 1 line");
	memset(ss, 0, sizeof(*ss));
	if (strcmp(f[1], "TCP4") == 0) {
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		if (inet_pton(AF_INET, f[2], &sin->sin_addr) != 1 ||
		    !pp1_port(f[4], &sin->sin_port))
			return ("bad TCP4 source");
	} else if (strcmp(f[1], "TCP6") == 0) {
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, f[2], &sin6->sin6_addr) != 1 ||
		    !pp1_port(f[4], &sin6->sin6_port))
			return ("bad TCP6 source");
	} else
		return ("unknown version 1 protocol");
	if (!pp1_port(f[5], &dport))
		return ("bad destination port");
	*have = true;
	return (NULL);
}

/* The fixed part, then the addresses; TLVs are skipped. */
static const char *
pp2_parse(cbl_conn *conn, struct sockaddr_storage *ss, bool *have)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)(void *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)ss;
	const unsigned char *b = conn->proxy_buf;
	size_t len = conn->proxy_len - PP2_HDR;

	if ((b[12] >> 4) != 2)
		return ("unsupported version");
	switch (b[12] & 0x0f) {
	case 0:
		return (NULL);	/* LOCAL: the proxy's own connection */
	case 1:
		break;		/* PROXY */
	default:
		return ("unknown command");
	}
	memset(ss, 0, sizeof(*ss));
	switch (b[13]) {
	case 0x11:		/* TCP over IPv4 */
		if (len < 12)
			return ("short IPv4 addresses");
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, b + 16, 4);
		memcpy(&sin->sin_port, b + 24, 2);
		break;
	case 0x21:		/* TCP over IPv6 */
		if (len < 36)
			return ("short IPv6 addresses");
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, b + 16, 16);
		memcpy(&sin6->sin6_port, b + 48, 2);
		break;
	default:
		return (NULL);	/* unspecified or not TCP: keep the socket's */
	}
	*have = true;
	return (NULL);
}

/*
 * Read the PROXY header of an accepted connection: 0 when done (with the
 * client's address in conn->peer), EAGAIN while it is incomplete, or an
 * error with conn->errstr set.
 */
int
cbl_proxy_read(cbl_conn *conn)
{
	struct sockaddr_storage ss;
	const char *why = NULL;
	bool have = false;
	size_t total;
	int error;

	if (conn->proxy_buf == NULL &&
	    (conn->proxy_buf = malloc(PP2_MAX)) == NULL)
		return (ENOMEM);
	/* Every header is at least PP_MIN bytes, so reading that is safe. */
	if ((error = pp_fill(conn, PP_MIN)) != 0)
		goto out;
	if (memcmp(conn->proxy_buf, pp2_sig, sizeof(pp2_sig)) == 0) {
		if ((error = pp_fill(conn, PP2_HDR)) != 0)
			goto out;
		total = PP2_HDR + ((size_t)conn->proxy_buf[14] << 8 |
		    conn->proxy_buf[15]);
		if (total > PP2_MAX) {
			error = EMSGSIZE;
			goto out;
		}
		if ((error = pp_fill(conn, total)) == 0)
			why = pp2_parse(conn, &ss, &have);
	} else if (memcmp(conn->proxy_buf, "PROXY ", 6) == 0) {
		if ((error = pp1_fill(conn)) == 0)
			why = pp1_parse(conn, &ss, &have);
	} else
		why = "no PROXY protocol header";
	if (why != NULL)
		error = EBADMSG;
out:
	if (error == EAGAIN)
		return (EAGAIN);
	free(conn->proxy_buf);
	conn->proxy_buf = NULL;
	conn->proxy_len = 0;
	if (error != 0)
		return (cbl_conn_seterr(conn, error, "PROXY protocol: %s",
		    why != NULL ? why : error == EMSGSIZE ? "header too long" :
		    error == ECONNRESET ? "closed before the header" :
		    error == EBADMSG ? "malformed version 1 line" :
		    strerror(error)));
	if (have) {
		memcpy(&conn->peer.addr, &ss, ss.ss_len);
		conn->peer.addrlen = ss.ss_len;
		conn->peer.flags |= CBL_PEER_PROXIED;
	}
	return (0);
}

/*
 * Who may send a PROXY header: "addr" or "addr/bits", IPv4 or IPv6, up to
 * CBL_PROXY_NETS of them, before the listener starts.  Without any, a
 * CBL_LF_PROXY listener takes the header from whoever connects.
 */
int
cbl_listener_add_proxy(cbl_listener *l, const char *net)
{
	struct cbl_proxy_net *p;
	char buf[INET6_ADDRSTRLEN + 4], *slash, *end;
	long bits, max;

	if (l == NULL || net == NULL || (l->flags & CBL_LF_PROXY) == 0)
		return (EINVAL);
	if (l->started)
		return (EBUSY);
	if (l->nproxies == CBL_PROXY_NETS)
		return (ENOSPC);
	if (strlcpy(buf, net, sizeof(buf)) >= sizeof(buf))
		return (EINVAL);
	p = &l->proxies[l->nproxies];
	memset(p, 0, sizeof(*p));
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';
	if (inet_pton(AF_INET, buf, p->addr) == 1) {
		p->family = AF_INET;
		max = 32;
	} else if (inet_pton(AF_INET6, buf, p->addr) == 1) {
		p->family = AF_INET6;
		max = 128;
	} else
		return (EINVAL);
	bits = max;
	if (slash != NULL) {
		bits = strtol(slash, &end, 10);
		if (*slash == '\0' || *end != '\0' || bits < 0 || bits > max)
			return (EINVAL);
	}
	p->bits = (int)bits;
	l->nproxies++;
	return (0);
}

static bool
prefix_match(const unsigned char *a, const unsigned char *net, int bits)
{
	int full = bits / 8, rest = bits % 8;

	if (memcmp(a, net, (size_t)full) != 0)
		return (false);
	return (rest == 0 ||
	    ((a[full] ^ net[full]) & (0xff << (8 - rest)) & 0xff) == 0);
}

/*
 * May the peer at "ss" send the header?  An IPv4 peer of a dual-stack
 * listener arrives as an IPv4-mapped IPv6 address and is matched as IPv4.
 */
bool
cbl_proxy_allowed(const cbl_listener *l, const struct sockaddr_storage *ss)
{
	const struct sockaddr_in6 *sin6;
	const unsigned char *a;
	int family;

	if (l->nproxies == 0)
		return (true);
	if (ss->ss_family == AF_INET) {
		a = (const unsigned char *)&((const struct sockaddr_in *)
		    (const void *)ss)->sin_addr;
		family = AF_INET;
	} else if (ss->ss_family == AF_INET6) {
		sin6 = (const struct sockaddr_in6 *)(const void *)ss;
		a = (const unsigned char *)&sin6->sin6_addr;
		family = AF_INET6;
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			a += 12;
			family = AF_INET;
		}
	} else
		return (false);
	for (int i = 0; i < l->nproxies; i++)
		if (l->proxies[i].family == family &&
		    prefix_match(a, l->proxies[i].addr, l->proxies[i].bits))
			return (true);
	return (false);
}
