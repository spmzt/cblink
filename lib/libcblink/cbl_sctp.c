/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * SCTP, one-to-one style (docs/TRANSPORTS.md).
 *
 * SCTP stream 0 carries requests, responses and notifications; cblink
 * stream n travels on SCTP stream 1 + n mod (outbound streams - 1), so
 * cblink streams do not block each other or control traffic.  Several
 * hosts in the URI give multihoming (sctp_bindx, sctp_connectx).
 *
 * Plaintext: every frame is one SCTP message, so message boundaries do
 * the framing.  Fragment interleaving (level 2, with I-DATA when both
 * ends support RFC 8260) keeps a large message from stalling other
 * streams; partial deliveries are reassembled per SCTP stream.
 *
 * DTLS 1.2 over SCTP (RFC 6083) uses OpenSSL's SCTP BIO, which needs
 * SCTP-AUTH.  Records are at most 16 KiB, so each SCTP stream carries a
 * byte stream of frames delimited by their length field, reassembled per
 * SCTP stream here (see cbl_tls.c for the DTLS side).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/sctp.h>

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>

#include "cbl_impl.h"

#define	SCTP_OSTREAMS	64
#define	SCTP_CHUNK	(64 * 1024)	/* one recvmsg */

/* What has arrived so far on one SCTP stream. */
struct sctp_part {
	LIST_ENTRY(sctp_part)	 link;
	uint16_t		 sid;
	unsigned char		*buf;
	size_t			 len;
	size_t			 cap;
	size_t			 discard;	/* bytes still to skip */
	bool			 overflow;	/* skip to the end of message */
};

struct cbl_sctp_mux {
	uint16_t		 ostreams;	/* 0: not known yet */
	LIST_HEAD(, sctp_part)	 parts;
};

struct sctp_tr {
	struct cbl_sctp_mux	*mux;
	unsigned char		*chunk;
};

/*
 * A socket for the hosts of "u", with the options every SCTP socket gets
 * before listen() or connect().  Mixed IPv4 and IPv6 hosts need an IPv6
 * socket that also takes IPv4 addresses.
 */
int
cbl_sctp_socket(const struct cbl_uri *u, bool dtls, int *fdp)
{
	struct sctp_initmsg im = {
		.sinit_num_ostreams = SCTP_OSTREAMS,
		.sinit_max_instreams = SCTP_OSTREAMS,
	};
	struct sctp_assoc_value av = {
		.assoc_id = SCTP_FUTURE_ASSOC, .assoc_value = 1 };
	int family = u->addr[0].ss_family;
	int fd, one = 1, zero = 0, level = 2, error;
	bool mixed = false;
	BIO *tmp;

	for (int i = 1; i < u->naddr; i++)
		if (u->addr[i].ss_family != family)
			mixed = true;
	if (cbl_uri_dualstack(u))
		mixed = true;
	if (mixed)
		family = AF_INET6;
	fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    IPPROTO_SCTP);
	if (fd == -1)
		return (errno);
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &one,
	    sizeof(one)) == -1 ||
	    (mixed && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero,
	    sizeof(zero)) == -1) ||
	    setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &im, sizeof(im)) == -1 ||
	    setsockopt(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &one,
	    sizeof(one)) == -1) {
		error = errno;
		close(fd);
		return (error);
	}
	/*
	 * Best effort: interleaving needs RFC 8260 on both ends.  Not with
	 * DTLS, whose SCTP BIO relies on whole records (no partial delivery).
	 */
	if (!dtls) {
		(void)setsockopt(fd, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE,
		    &level, sizeof(level));
		(void)setsockopt(fd, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED,
		    &av, sizeof(av));
	}
	(void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
	if (dtls) {
		/*
		 * The SCTP BIO turns on SCTP-AUTH for DATA chunks; that has to
		 * happen before the association exists (as openssl s_server).
		 */
		if ((tmp = BIO_new_dgram_sctp(fd, BIO_NOCLOSE)) == NULL) {
			close(fd);
			return (EPROTONOSUPPORT);
		}
		BIO_free(tmp);
	}
	*fdp = fd;
	return (0);
}

/* Multihoming: bind the listener to every host of the URI. */
int
cbl_sctp_bind_more(int fd, const struct cbl_uri *u)
{
	struct sockaddr_storage ss;

	for (int i = 1; i < u->naddr; i++) {
		memcpy(&ss, &u->addr[i], u->addrlen[i]);
		if (sctp_bindx(fd, (struct sockaddr *)&ss, 1,
		    SCTP_BINDX_ADD_ADDR) == -1)
			return (errno);
	}
	return (0);
}

struct cbl_sctp_mux *
cbl_sctp_mux_new(void)
{
	struct cbl_sctp_mux *m;

	if ((m = calloc(1, sizeof(*m))) == NULL)
		return (NULL);
	LIST_INIT(&m->parts);
	return (m);
}

static void
part_free(struct sctp_part *p)
{

	LIST_REMOVE(p, link);
	free(p->buf);
	free(p);
}

void
cbl_sctp_mux_free(struct cbl_sctp_mux *m)
{
	struct sctp_part *p;

	if (m == NULL)
		return;
	while ((p = LIST_FIRST(&m->parts)) != NULL)
		part_free(p);
	free(m);
}

/*
 * SCTP stream for a frame, from its header.  The number of outbound
 * streams is known once the association is up.
 */
uint16_t
cbl_sctp_mux_sid(struct cbl_sctp_mux *m, int fd, const void *frame,
    size_t len)
{
	struct sctp_status st;
	socklen_t slen = sizeof(st);
	uint32_t flags, id;

	if (m->ostreams == 0) {
		memset(&st, 0, sizeof(st));
		if (getsockopt(fd, IPPROTO_SCTP, SCTP_STATUS, &st,
		    &slen) == -1 || st.sstat_outstrms == 0)
			return (0);
		m->ostreams = st.sstat_outstrms;
	}
	if (len < CBL_HDRLEN || m->ostreams < 2)
		return (0);
	flags = cbl_be32dec((const unsigned char *)frame + 12);
	id = cbl_be32dec((const unsigned char *)frame + 20);
	if ((flags & CBL_F_S_ANY) == 0 || id == 0)
		return (0);
	return ((uint16_t)(1 + id % (uint32_t)(m->ostreams - 1)));
}

static struct sctp_part *
part_get(struct cbl_sctp_mux *m, uint16_t sid, bool create)
{
	struct sctp_part *p;

	LIST_FOREACH(p, &m->parts, link)
		if (p->sid == sid)
			return (p);
	if (!create || (p = calloc(1, sizeof(*p))) == NULL)
		return (NULL);
	p->sid = sid;
	LIST_INSERT_HEAD(&m->parts, p, link);
	return (p);
}

/* Append to a part; the caller has checked the size against max_frame. */
static int
part_append(struct sctp_part *p, const void *data, size_t n, size_t max)
{
	size_t ncap;

	if (p->len + n > p->cap) {
		ncap = p->cap == 0 ? SCTP_CHUNK : p->cap * 2;
		while (ncap < p->len + n)
			ncap *= 2;
		if (ncap > max)
			ncap = max;
		if ((p->buf = reallocf(p->buf, ncap)) == NULL) {
			p->len = p->cap = 0;
			return (ENOMEM);
		}
		p->cap = ncap;
	}
	memcpy(p->buf + p->len, data, n);
	p->len += n;
	return (0);
}

/*
 * DTLS mode: "n" bytes of the byte stream on SCTP stream "sid".  Complete
 * frames are delivered; a bad header is handled as on TCP.
 */
int
cbl_sctp_mux_bytes(cbl_conn *conn, struct cbl_sctp_mux *m, uint16_t sid,
    const void *data, size_t n)
{
	const unsigned char *in = data;
	struct sctp_part *p;
	struct cbl_hdr h;
	size_t max = conn->lim.v[CBL_LIM_MAX_FRAME], k, need;
	int error;

	if ((p = part_get(m, sid, true)) == NULL)
		return (ENOMEM);
	while (n > 0 && conn->state == CBL_CS_OPEN) {
		if (p->discard > 0) {
			k = n < p->discard ? n : p->discard;
			in += k;
			n -= k;
			p->discard -= k;
			continue;
		}
		/* The header first, then exactly the rest of the frame. */
		if (p->len < CBL_HDRLEN)
			need = CBL_HDRLEN - p->len;
		else {
			error = cbl_hdr_decode(p->buf, p->len, &conn->lim, &h);
			if (error != 0) {
				p->len = 0;
				if (!cbl_conn_bad_header(conn, error, &h))
					return (0);
				p->discard = h.length - CBL_HDRLEN;
				continue;
			}
			need = h.length - p->len;
		}
		k = n < need ? n : need;
		if ((error = part_append(p, in, k, max)) != 0)
			return (error);
		in += k;
		n -= k;
		if (p->len >= CBL_HDRLEN &&
		    p->len == cbl_be32dec(p->buf + 4)) {
			cbl_conn_rx_message(conn, p->buf, p->len);
			p->len = 0;
		}
	}
	return (0);
}

static int
sctp_handshake(cbl_conn *conn)
{
	struct pollfd pfd = { .fd = conn->fd, .events = POLLOUT };
	socklen_t len = sizeof(int);
	int soerr = 0;

	if (poll(&pfd, 1, 0) == 0) {
		conn->want = CBL_EV_WRITE;
		return (EAGAIN);
	}
	if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &soerr, &len) == -1)
		return (errno);
	if (soerr != 0)
		return (cbl_conn_seterr(conn, soerr, "sctp connect: %s",
		    strerror(soerr)));
	conn->want = 0;
	return (0);
}

static int
sctp_write(cbl_conn *conn, const void *buf, size_t len, size_t *put)
{
	struct sctp_tr *t = conn->trpriv;
	struct sctp_sndinfo si = { 0 };
	struct iovec iov = { .iov_base = (void *)(uintptr_t)buf,
	    .iov_len = len };
	ssize_t n;

	si.snd_sid = cbl_sctp_mux_sid(t->mux, conn->fd, buf, len);
	n = sctp_sendv(conn->fd, &iov, 1, NULL, 0, &si, sizeof(si),
	    SCTP_SENDV_SNDINFO, 0);
	if (n == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return (EAGAIN);
		return (errno);
	}
	/* The message boundary is the framing: never part of a frame. */
	if ((size_t)n != len)
		return (cbl_conn_seterr(conn, EMSGSIZE,
		    "sctp: partial message send"));
	*put = (size_t)n;
	return (0);
}

/*
 * Plaintext: read SCTP messages.  A message may come in pieces (partial
 * delivery), possibly interleaved with pieces of other streams; each SCTP
 * stream is reassembled separately, bounded by max_frame.
 */
static int
sctp_rx_frames(cbl_conn *conn, int budget)
{
	struct sctp_tr *t = conn->trpriv;
	unsigned char cbuf[CMSG_SPACE(sizeof(struct sctp_rcvinfo))];
	struct sctp_rcvinfo ri;
	struct sctp_part *p;
	struct cmsghdr *cm;
	struct msghdr mh;
	struct iovec iov;
	uint16_t sid;
	size_t max = conn->lim.v[CBL_LIM_MAX_FRAME];
	ssize_t n;
	bool eor;

	if (t->chunk == NULL && (t->chunk = malloc(SCTP_CHUNK)) == NULL)
		return (ENOMEM);
	while (budget > 0 && conn->state == CBL_CS_OPEN) {
		memset(&mh, 0, sizeof(mh));
		iov.iov_base = t->chunk;
		iov.iov_len = SCTP_CHUNK;
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		mh.msg_control = cbuf;
		mh.msg_controllen = sizeof(cbuf);
		n = recvmsg(conn->fd, &mh, 0);
		if (n == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return (0);
			return (errno);
		}
		eor = (mh.msg_flags & MSG_EOR) != 0;
		if (n == 0 && !eor)
			return (ECONNRESET);	/* association shut down */
		if ((mh.msg_flags & MSG_NOTIFICATION) != 0)
			continue;
		sid = 0;
		for (cm = CMSG_FIRSTHDR(&mh); cm != NULL;
		    cm = CMSG_NXTHDR(&mh, cm)) {
			if (cm->cmsg_level == IPPROTO_SCTP &&
			    cm->cmsg_type == SCTP_RCVINFO) {
				memcpy(&ri, CMSG_DATA(cm), sizeof(ri));
				sid = ri.rcv_sid;
			}
		}
		/* The common case: a whole message in one piece. */
		p = part_get(t->mux, sid, !eor);
		if (p == NULL && eor) {
			cbl_conn_rx_message(conn, t->chunk, (size_t)n);
			budget--;
			continue;
		}
		if (p == NULL)
			return (ENOMEM);
		if (!p->overflow && p->len + (size_t)n > max) {
			/* Larger than any frame: drop the message. */
			p->overflow = true;
			conn->rx_dropped++;
		}
		if (!p->overflow &&
		    part_append(p, t->chunk, (size_t)n, max) != 0) {
			part_free(p);
			return (ENOMEM);
		}
		if (eor) {
			if (!p->overflow)
				cbl_conn_rx_message(conn, p->buf, p->len);
			part_free(p);
			budget--;
		}
	}
	if (budget == 0)
		conn->rx_pending = true;
	return (0);
}

static void
sctp_shutdown(cbl_conn *conn)
{

	if (conn->fd != -1)
		(void)shutdown(conn->fd, SHUT_WR);	/* SHUTDOWN chunk */
}

static void
sctp_free(cbl_conn *conn)
{
	struct sctp_tr *t = conn->trpriv;

	if (t == NULL)
		return;
	cbl_sctp_mux_free(t->mux);
	free(t->chunk);
	free(t);
	conn->trpriv = NULL;
}

const struct cbl_tr_ops cbl_tr_sctp_ops = {
	.name = "sctp",
	.handshake = sctp_handshake,
	.write = sctp_write,
	.rx_frames = sctp_rx_frames,
	.shutdown = sctp_shutdown,
	.free = sctp_free,
};

/*
 * Socket buffers that hold a max_frame message: a plaintext frame is
 * sent and received as one SCTP message.  Best effort, within
 * kern.ipc.maxsockbuf.
 */
void
cbl_sctp_buffers(cbl_conn *conn)
{
	int want, have;
	socklen_t len;

	want = (int)(conn->lim.v[CBL_LIM_MAX_FRAME] + SCTP_CHUNK);
	for (int opt = SO_SNDBUF; ; opt = SO_RCVBUF) {
		len = sizeof(have);
		if (getsockopt(conn->fd, SOL_SOCKET, opt, &have, &len) == 0 &&
		    have < want)
			(void)setsockopt(conn->fd, SOL_SOCKET, opt, &want,
			    sizeof(want));
		if (opt == SO_RCVBUF)
			break;
	}
}

/* Plaintext SCTP on a connected or accepted socket. */
int
cbl_sctp_attach(cbl_conn *conn)
{
	struct sctp_tr *t;

	if ((t = calloc(1, sizeof(*t))) == NULL)
		return (ENOMEM);
	if ((t->mux = cbl_sctp_mux_new()) == NULL) {
		free(t);
		return (ENOMEM);
	}
	cbl_sctp_buffers(conn);
	conn->trpriv = t;
	conn->ops = &cbl_tr_sctp_ops;
	return (0);
}

/* Client: associate with every host of the URI (multihoming). */
int
cbl_sctp_connect(cbl_conn *conn, cbl_tls *tls, uint64_t deadline)
{
	char packed[CBL_URI_MAXADDR * sizeof(struct sockaddr_storage)];
	struct pollfd pfd;
	size_t off = 0;
	int fd, error, timeout;

	if ((error = cbl_sctp_socket(&conn->uri, tls != NULL, &fd)) != 0)
		return (cbl_conn_seterr(conn, error, "sctp: %s",
		    strerror(error)));
	/* sctp_connectx() takes the addresses packed back to back. */
	for (int i = 0; i < conn->uri.naddr; i++) {
		memcpy(packed + off, &conn->uri.addr[i], conn->uri.addrlen[i]);
		off += conn->uri.addrlen[i];
	}
	if (sctp_connectx(fd, (struct sockaddr *)packed, conn->uri.naddr,
	    NULL) == -1 && errno != EINPROGRESS) {
		error = errno;
		close(fd);
		return (cbl_conn_seterr(conn, error, "sctp connect: %s",
		    strerror(error)));
	}
	conn->fd = fd;
	conn->peer.transport = CBL_TR_SCTP;
	memcpy(&conn->peer.addr, &conn->uri.addr[0], conn->uri.addrlen[0]);
	conn->peer.addrlen = conn->uri.addrlen[0];
	/* Wait for the association (the INIT/COOKIE exchange). */
	pfd.fd = fd;
	pfd.events = POLLOUT;
	timeout = (int)(deadline - cbl_now_ms());
	if ((conn->flags & CBL_CF_NONBLOCK) == 0 &&
	    poll(&pfd, 1, timeout < 0 ? 0 : timeout) != 1) {
		close(fd);
		conn->fd = -1;
		return (cbl_conn_seterr(conn, ETIMEDOUT,
		    "sctp connect: timed out"));
	}
	if (tls != NULL)
		return (cbl_dtls_sctp_attach(conn, tls, false));
	return (cbl_sctp_attach(conn));
}
