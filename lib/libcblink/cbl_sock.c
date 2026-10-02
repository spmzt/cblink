/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Stream sockets (TCP, and later AF_UNIX): transport operations,
 * outgoing connections and listeners.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cbl_impl.h"

#define	CBL_ACCEPT_BACKOFF_MS	100

#define	LERR(l, e, ...)	(snprintf((l)->errstr, sizeof((l)->errstr),	\
	__VA_ARGS__), (e))

int
cbl_sock_nonblock(int fd)
{
	int fl;

	if ((fl = fcntl(fd, F_GETFL)) == -1 ||
	    fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1)
		return (errno);
	return (0);
}

static void
sock_tune(int fd, enum cbl_transport tr)
{
	int one = 1;

	(void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
	if (tr == CBL_TR_TCP)
		(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one,
		    sizeof(one));
}

/* Plain stream socket I/O. */
static int
stream_handshake(cbl_conn *conn)
{
	struct pollfd pfd = { .fd = conn->fd, .events = POLLOUT };
	socklen_t len = sizeof(int);
	int soerr = 0;

	/* Completion of a non-blocking connect(2). */
	if (poll(&pfd, 1, 0) == 0)
		return (EAGAIN);
	if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &soerr, &len) == -1)
		return (errno);
	if (soerr != 0)
		return (cbl_conn_seterr(conn, soerr, "connect: %s",
		    strerror(soerr)));
	return (0);
}

/* Queued frames in one sendmsg(2): fewer calls, fuller segments. */
static int
stream_writev(cbl_conn *conn, const struct iovec *iov, int n, size_t *put)
{
	struct msghdr mh = { .msg_iov = (struct iovec *)(uintptr_t)iov,
	    .msg_iovlen = n };
	ssize_t w;

	w = sendmsg(conn->fd, &mh, MSG_NOSIGNAL);
	if (w == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return (EAGAIN);
		return (errno);
	}
	*put = (size_t)w;
	return (0);
}

static int
stream_read(cbl_conn *conn, void *buf, size_t len, size_t *got)
{
	ssize_t n;

	n = read(conn->fd, buf, len);
	if (n == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return (EAGAIN);
		return (errno);
	}
	*got = (size_t)n;
	return (0);
}

static int
stream_write(cbl_conn *conn, const void *buf, size_t len, size_t *put)
{
	ssize_t n;

	n = send(conn->fd, buf, len, MSG_NOSIGNAL);
	if (n == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return (EAGAIN);
		return (errno);
	}
	*put = (size_t)n;
	return (0);
}

static void
stream_shutdown(cbl_conn *conn)
{

	if (conn->fd != -1)
		(void)shutdown(conn->fd, SHUT_WR);
}

const struct cbl_tr_ops cbl_tr_tcp_ops = {
	.name = "tcp",
	.handshake = stream_handshake,
	.read = stream_read,
	.write = stream_write,
	.writev = stream_writev,
	.shutdown = stream_shutdown,
};

const struct cbl_tr_ops cbl_tr_unix_ops = {
	.name = "unix",
	.handshake = stream_handshake,
	.read = stream_read,
	.write = stream_write,
	.writev = stream_writev,
	.shutdown = stream_shutdown,
};

static const struct cbl_tr_ops *
tr_ops_for(const struct cbl_uri *u)
{

	switch (u->transport) {
	case CBL_TR_TCP:
		return (&cbl_tr_tcp_ops);
	case CBL_TR_UNIX:
		return (&cbl_tr_unix_ops);
	case CBL_TR_SCTP:
		return (&cbl_tr_sctp_ops);
	default:
		return (NULL);
	}
}

/* Copy the limits and freeze the context's configuration. */
void
cbl_ctx_freeze(cbl_ctx *ctx, struct cbl_limits *lim)
{

	pthread_mutex_lock(&ctx->mtx);
	ctx->frozen = true;
	if (lim != NULL)
		*lim = ctx->lim;
	pthread_mutex_unlock(&ctx->mtx);
}

int
cbl_ctx_set_conn_cbs(cbl_ctx *ctx, const struct cbl_conn_cbs *cbs, void *arg)
{
	int error = 0;

	if (ctx == NULL)
		return (EINVAL);
	pthread_mutex_lock(&ctx->mtx);
	if (ctx->frozen)
		error = EBUSY;
	else {
		if (cbs != NULL)
			ctx->conn_cbs = *cbs;
		else
			memset(&ctx->conn_cbs, 0, sizeof(ctx->conn_cbs));
		ctx->conn_cbs_arg = arg;
	}
	pthread_mutex_unlock(&ctx->mtx);
	return (error);
}

/* Common checks for listeners and connections. */
static int
endpoint_check(const struct cbl_uri *u, uint32_t flags, bool listener,
    char *err, size_t errlen)
{

	if (tr_ops_for(u) == NULL) {
		snprintf(err, errlen, "transport not supported yet");
		return (EPROTONOSUPPORT);
	}
	if ((flags & CBL_LF_PROXY) != 0 &&
	    (!listener || u->transport != CBL_TR_TCP)) {
		snprintf(err, errlen, "CBL_LF_PROXY needs a tcp:// listener");
		return (EINVAL);
	}
	return (0);
}

/*
 * mTLS by default on direct network transports: TLS must be configured
 * unless CBL_PLAINTEXT was given.  Returns the configuration to use (or
 * NULL for plaintext) in *tlsp.
 */
static int
tls_choose(const struct cbl_uri *u, uint32_t flags, cbl_tls *own,
    cbl_ctx *ctx, cbl_tls **tlsp, char *err, size_t errlen)
{

	*tlsp = NULL;
	if (u->transport == CBL_TR_UNIX || (flags & CBL_PLAINTEXT) != 0)
		return (0);
	*tlsp = own != NULL ? own : ctx->tls;
	if (*tlsp == NULL) {
		snprintf(err, errlen,
		    "mTLS required: configure TLS or pass CBL_PLAINTEXT");
		return (EPERM);
	}
	return (0);
}

static void
peer_set_addr(cbl_conn *conn, const struct sockaddr *sa, socklen_t len)
{

	conn->peer.transport = conn->uri.transport;
	if (sa != NULL && len > 0 && len <= sizeof(conn->peer.addr)) {
		memcpy(&conn->peer.addr, sa, len);
		conn->peer.addrlen = len;
	}
}

/*
 * Before cbl_listener_start(): the configuration to use.  On a started TLS
 * listener: a new configuration for the connections accepted from now on
 * (a renewed certificate, say); it is checked first, and a listener cannot
 * change between TLS and plaintext.  Any thread.
 */
int
cbl_listener_set_tls(cbl_listener *l, cbl_tls *tls)
{
	char err[256];
	cbl_tls *old;
	int error;

	if (l == NULL)
		return (EINVAL);
	if (l->started) {
		if (tls == NULL || !l->use_tls)
			return (EINVAL);
		if ((error = cbl_tls_prepare(tls, l->uri.transport ==
		    CBL_TR_TCP ? CBL_TLS_SERVER : CBL_DTLS_SERVER, err,
		    sizeof(err))) != 0)
			return (LERR(l, error, "%s", err));
	}
	if (tls != NULL)
		cbl_tls_ref(tls);
	pthread_mutex_lock(&l->mtx);
	old = l->tls;
	l->tls = tls;
	pthread_mutex_unlock(&l->mtx);
	cbl_tls_free(old);
	return (0);
}

int
cbl_conn_set_tls(cbl_conn *conn, cbl_tls *tls)
{

	if (conn == NULL)
		return (EINVAL);
	if (conn->state != CBL_CS_NEW)
		return (EBUSY);
	if (tls != NULL)
		cbl_tls_ref(tls);
	cbl_tls_free(conn->tls);
	conn->tls = tls;
	return (0);
}

int
cbl_conn_new(cbl_ctx *ctx, const char *uri, uint32_t flags,
    cbl_conn **connp)
{
	struct cbl_limits lim;
	struct cbl_uri u;
	char err[256];
	cbl_conn *conn;
	int error;

	if (ctx == NULL || connp == NULL)
		return (EINVAL);
	if ((error = cbl_uri_parse(uri, &u, err, sizeof(err))) != 0)
		return (error);
	if ((error = endpoint_check(&u, flags, false, err, sizeof(err))) != 0)
		return (error);
	pthread_mutex_lock(&ctx->mtx);
	lim = ctx->lim;
	pthread_mutex_unlock(&ctx->mtx);
	if ((error = cbl_conn_alloc(ctx, &lim, &conn)) != 0)
		return (error);
	conn->uri = u;
	conn->flags = flags;
	conn->ops = tr_ops_for(&u);
	conn->initiator = true;
	*connp = conn;
	return (0);
}

static int
wait_fd(int fd, short events, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = events };
	int n;

	do
		n = poll(&pfd, 1, timeout_ms);
	while (n == -1 && errno == EINTR);
	if (n == -1)
		return (errno);
	return (n == 0 ? ETIMEDOUT : 0);
}

static int sctp_connect(cbl_conn *conn, cbl_tls *tls, uint64_t deadline);

static const char *
conn_host(const cbl_conn *conn)
{

	return (conn->uri.host[0] != '\0' ? conn->uri.host : conn->uri.path);
}

/*
 * Non-blocking connect(2) to the next address that takes one: 0 with
 * conn->fd set (connected or in progress), or the last address's error.
 */
static int
connect_start(cbl_conn *conn)
{
	int fd, i, error = ECONNREFUSED;

	while (conn->next_addr < conn->uri.naddr) {
		i = conn->next_addr++;
		fd = socket(conn->uri.addr[i].ss_family,
		    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    conn->uri.transport == CBL_TR_UNIX ? 0 : IPPROTO_TCP);
		if (fd == -1) {
			error = errno;
			continue;
		}
		sock_tune(fd, conn->uri.transport);
		if (connect(fd, (struct sockaddr *)&conn->uri.addr[i],
		    conn->uri.addrlen[i]) == 0 || errno == EINPROGRESS) {
			conn->fd = fd;
			peer_set_addr(conn,
			    (struct sockaddr *)&conn->uri.addr[i],
			    conn->uri.addrlen[i]);
			return (0);
		}
		error = errno;
		close(fd);
	}
	return (error);
}

/*
 * cbl_conn_process(), for a CBL_CF_NONBLOCK client: has connect(2)
 * finished?  An address that failed is replaced by the next one, so the
 * descriptor may change (and its kqueue registration with it).  Once
 * connected, TLS is set up, to be driven by the transport's handshake.
 */
int
cbl_sock_connect_done(cbl_conn *conn)
{
	struct pollfd pfd;
	socklen_t len;
	int soerr, error;

	for (;;) {
		pfd.fd = conn->fd;
		pfd.events = POLLOUT;
		pfd.revents = 0;
		if (poll(&pfd, 1, 0) == 0) {
			conn->want = CBL_EV_WRITE;
			return (EAGAIN);
		}
		soerr = 0;
		len = sizeof(soerr);
		if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &soerr,
		    &len) == -1)
			soerr = errno;
		if (soerr == 0)
			break;
		close(conn->fd);
		conn->fd = -1;
		conn->kq_events = 0;	/* the next descriptor is new */
		if (connect_start(conn) != 0)
			return (cbl_conn_seterr(conn, soerr,
			    "connect to %s: %s", conn_host(conn),
			    strerror(soerr)));
	}
	conn->tcp_pending = false;
	conn->want = 0;
	if (conn->tls_after_tcp &&
	    (error = cbl_tls_attach(conn, conn->tls, false)) != 0)
		return (error);
	return (0);
}

/* Finish a blocking TLS handshake before the deadline. */
static int
handshake_wait(cbl_conn *conn, uint64_t deadline)
{
	int error, timeout, t;

	for (;;) {
		error = conn->ops->handshake(conn);
		if (error != EAGAIN)
			return (error);
		timeout = (int)(deadline - cbl_now_ms());
		if (timeout <= 0)
			return (cbl_conn_seterr(conn, ETIMEDOUT,
			    "TLS handshake timed out"));
		/* Some transports act on a timer (DTLS over SCTP). */
		if (conn->ops->timeout != NULL &&
		    (t = conn->ops->timeout(conn)) >= 0 && t < timeout)
			timeout = t;
		error = wait_fd(conn->fd, (conn->want & CBL_EV_READ) != 0 ?
		    POLLIN : POLLOUT, timeout);
		if (error == ETIMEDOUT && conn->ops->on_timeout != NULL) {
			conn->ops->on_timeout(conn);
			continue;
		}
		if (error != 0)
			return (cbl_conn_seterr(conn, error,
			    "TLS handshake: %s", strerror(error)));
	}
}

int
cbl_conn_connect(cbl_conn *conn)
{
	struct sockaddr_storage ss;
	socklen_t sslen = sizeof(ss);
	char err[256];
	int error = ECONNREFUSED, fd = -1, timeout;
	uint64_t deadline;
	cbl_tls *tls;

	if (conn == NULL)
		return (EINVAL);
	if (conn->state != CBL_CS_NEW)
		return (EBUSY);
	cbl_ctx_freeze(conn->ctx, NULL);
	if ((error = tls_choose(&conn->uri, conn->flags, conn->tls, conn->ctx,
	    &tls, err, sizeof(err))) != 0)
		return (cbl_conn_seterr(conn, error, "%s", err));
	if (tls != NULL) {
		if ((error = cbl_tls_prepare(tls, conn->uri.transport ==
		    CBL_TR_TCP ? CBL_TLS_CLIENT : CBL_DTLS_CLIENT, err,
		    sizeof(err))) != 0)
			return (cbl_conn_seterr(conn, error, "%s", err));
		if (conn->tls == NULL) {
			cbl_tls_ref(tls);
			conn->tls = tls;
		}
	}
	if ((error = cbl_uri_resolve(&conn->uri, false, err,
	    sizeof(err))) != 0)
		return (cbl_conn_seterr(conn, error, "%s", err));
	deadline = cbl_now_ms() + conn->lim.v[CBL_LIM_HANDSHAKE_MS];
	if (conn->uri.transport == CBL_TR_SCTP)
		return (sctp_connect(conn, tls, deadline));
	if ((conn->flags & CBL_CF_NONBLOCK) != 0) {
		/*
		 * cbl_conn_process() finishes it: connect(2), trying the
		 * addresses in turn, then TLS (cbl_sock_connect_done()).
		 * Even a connect(2) that succeeds at once is left to it,
		 * so that nothing here waits for the TLS handshake.
		 */
		if ((error = connect_start(conn)) != 0)
			return (cbl_conn_seterr(conn, error,
			    "connect to %s: %s", conn_host(conn),
			    strerror(error)));
		conn->tcp_pending = true;
		conn->tls_after_tcp = tls != NULL;
		conn->state = CBL_CS_CONNECTING;
		conn->open_deadline = deadline;
		return (EINPROGRESS);
	}

	for (int i = 0; i < conn->uri.naddr; i++) {
		fd = socket(conn->uri.addr[i].ss_family,
		    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    conn->uri.transport == CBL_TR_UNIX ? 0 : IPPROTO_TCP);
		if (fd == -1) {
			error = errno;
			continue;
		}
		sock_tune(fd, conn->uri.transport);
		if (connect(fd, (struct sockaddr *)&conn->uri.addr[i],
		    conn->uri.addrlen[i]) == 0) {
			error = 0;
			break;
		}
		if (errno != EINPROGRESS) {
			error = errno;
			close(fd);
			fd = -1;
			continue;
		}
		conn->fd = fd;
		timeout = (int)(deadline - cbl_now_ms());
		error = wait_fd(fd, POLLOUT, timeout < 0 ? 0 : timeout);
		if (error == 0)
			error = conn->ops->handshake(conn);
		conn->fd = -1;
		if (error == 0)
			break;
		close(fd);
		fd = -1;
	}
	if (fd == -1)
		return (cbl_conn_seterr(conn, error, "connect to %s: %s",
		    conn_host(conn), strerror(error)));
	conn->fd = fd;
	if (getpeername(fd, (struct sockaddr *)&ss, &sslen) == 0)
		peer_set_addr(conn, (struct sockaddr *)&ss, sslen);
	else
		peer_set_addr(conn, NULL, 0);
	conn->state = CBL_CS_CONNECTING;
	if (tls != NULL) {
		if ((error = cbl_tls_attach(conn, tls, false)) != 0 ||
		    (error = handshake_wait(conn, deadline)) != 0) {
			close(conn->fd);
			conn->fd = -1;
			if (conn->ops->free != NULL)
				conn->ops->free(conn);
			conn->ops = &cbl_tr_tcp_ops;
			conn->state = CBL_CS_NEW;
			return (error);
		}
	}
	cbl_conn_opened(conn);
	return (0);
}

/* SCTP: the association, then the DTLS handshake when configured. */
static int
sctp_connect(cbl_conn *conn, cbl_tls *tls, uint64_t deadline)
{
	int error;

	if ((error = cbl_sctp_connect(conn, tls, deadline)) != 0)
		return (error);
	conn->state = CBL_CS_CONNECTING;
	if ((conn->flags & CBL_CF_NONBLOCK) != 0) {
		conn->open_deadline = deadline;
		return (EINPROGRESS);
	}
	if ((error = handshake_wait(conn, deadline)) != 0) {
		if (conn->ops->free != NULL)
			conn->ops->free(conn);
		conn->ops = &cbl_tr_sctp_ops;
		close(conn->fd);
		conn->fd = -1;
		conn->state = CBL_CS_NEW;
		return (error);
	}
	cbl_conn_opened(conn);
	return (0);
}

/* Listeners. */
int
cbl_listener_new(cbl_ctx *ctx, const char *uri, uint32_t flags,
    cbl_listener **lp)
{
	cbl_listener *l;
	struct cbl_uri u;
	char err[256];
	int error;

	if (ctx == NULL || lp == NULL)
		return (EINVAL);
	if ((error = cbl_uri_parse(uri, &u, err, sizeof(err))) != 0)
		return (error);
	if ((error = endpoint_check(&u, flags, true, err, sizeof(err))) != 0)
		return (error);
	if ((l = calloc(1, sizeof(*l))) == NULL)
		return (ENOMEM);
	if ((error = pthread_mutex_init(&l->mtx, NULL)) != 0) {
		free(l);
		return (error);
	}
	l->src.type = CBL_SRC_LISTENER;
	l->src.obj = l;
	l->ctx = ctx;
	l->uri = u;
	l->flags = flags;
	l->fd = -1;
	l->unix_uid = (uid_t)-1;
	l->unix_gid = (gid_t)-1;
	pthread_mutex_lock(&ctx->mtx);
	l->lim = ctx->lim;
	pthread_mutex_unlock(&ctx->mtx);
	atomic_fetch_add(&ctx->nobjs, 1);
	*lp = l;
	return (0);
}

int
cbl_listener_set_limit(cbl_listener *l, enum cbl_limit lim, uint64_t v)
{
	int error;

	if (l == NULL)
		return (EINVAL);
	if ((error = cbl_limit_check(lim, v)) != 0)
		return (error);
	if (l->started)
		return (EBUSY);
	l->lim.v[lim] = v;
	return (0);
}

const char *
cbl_listener_errstr(const cbl_listener *l)
{

	if (l == NULL)
		return ("invalid listener");
	return (l->errstr[0] != '\0' ? l->errstr : NULL);
}

int
cbl_listener_fd(const cbl_listener *l)
{

	return (l != NULL ? l->fd : -1);
}

int
cbl_listener_addr(const cbl_listener *l, struct sockaddr_storage *ss,
    socklen_t *lenp)
{
	socklen_t len = sizeof(*ss);

	if (l == NULL || ss == NULL || l->fd == -1)
		return (EINVAL);
	if (getsockname(l->fd, (struct sockaddr *)ss, &len) == -1)
		return (errno);
	if (lenp != NULL)
		*lenp = len;
	return (0);
}

/*
 * A socket file left behind by a dead process is removed; a live
 * listener or any other kind of file is not touched.
 */
static int
unix_clear_stale(const char *path)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	struct stat sb;
	int fd, rv;

	if (lstat(path, &sb) == -1)
		return (errno == ENOENT ? 0 : errno);
	if (!S_ISSOCK(sb.st_mode))
		return (EEXIST);
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);
	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
		return (errno);
	rv = connect(fd, (struct sockaddr *)&sun, sun.sun_len);
	close(fd);
	if (rv == 0)
		return (EADDRINUSE);
	if (errno != ECONNREFUSED)
		return (errno);
	return (unlink(path) == -1 ? errno : 0);
}

int
cbl_listener_set_unix_perm(cbl_listener *l, mode_t mode, uid_t uid, gid_t gid)
{

	if (l == NULL || l->uri.transport != CBL_TR_UNIX ||
	    (mode & ~07777) != 0)
		return (EINVAL);
	if (l->started)
		return (EBUSY);
	l->unix_mode = mode;
	l->unix_uid = uid;
	l->unix_gid = gid;
	return (0);
}

int
cbl_listener_start(cbl_listener *l, cbl_loop *loop)
{
	char err[256];
	cbl_tls *tls;
	int error, fd, one = 1, zero = 0;

	if (l == NULL || (loop != NULL && loop->ctx != l->ctx))
		return (EINVAL);
	if (l->started)
		return (EBUSY);
	cbl_ctx_freeze(l->ctx, NULL);
	if ((error = tls_choose(&l->uri, l->flags, l->tls, l->ctx, &tls, err,
	    sizeof(err))) != 0)
		return (LERR(l, error, "%s", err));
	l->use_tls = tls != NULL;
	if (tls != NULL) {
		if ((error = cbl_tls_prepare(tls, l->uri.transport ==
		    CBL_TR_TCP ? CBL_TLS_SERVER : CBL_DTLS_SERVER, err,
		    sizeof(err))) != 0)
			return (LERR(l, error, "%s", err));
		if (l->tls == NULL) {
			cbl_tls_ref(tls);
			l->tls = tls;
		}
	}
	if ((error = cbl_uri_resolve(&l->uri, true, err, sizeof(err))) != 0)
		return (LERR(l, error, "%s", err));
	if (l->uri.transport == CBL_TR_SCTP) {
		if ((error = cbl_sctp_socket(&l->uri, tls != NULL, &fd)) != 0)
			return (LERR(l, error, "sctp: %s", strerror(error)));
	} else {
		fd = socket(l->uri.addr[0].ss_family,
		    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    l->uri.transport == CBL_TR_UNIX ? 0 : IPPROTO_TCP);
		if (fd == -1)
			return (LERR(l, errno, "socket: %s", strerror(errno)));
		if (cbl_uri_dualstack(&l->uri) && setsockopt(fd, IPPROTO_IPV6,
		    IPV6_V6ONLY, &zero, sizeof(zero)) == -1) {
			error = errno;
			close(fd);
			return (LERR(l, error, "IPV6_V6ONLY: %s",
			    strerror(error)));
		}
	}
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if ((l->flags & CBL_LF_REUSEPORT) != 0 &&
	    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT_LB, &one,
	    sizeof(one)) == -1) {
		error = errno;
		close(fd);
		return (LERR(l, error, "SO_REUSEPORT_LB: %s",
		    strerror(error)));
	}
	if (l->uri.transport == CBL_TR_UNIX &&
	    (error = unix_clear_stale(l->uri.path)) != 0) {
		close(fd);
		return (LERR(l, error, "%s: %s", l->uri.path,
		    error == EADDRINUSE ? "another listener is active" :
		    strerror(error)));
	}
	if (bind(fd, (struct sockaddr *)&l->uri.addr[0],
	    l->uri.addrlen[0]) == -1 ||
	    (l->uri.transport == CBL_TR_SCTP &&
	    (errno = cbl_sctp_bind_more(fd, &l->uri)) != 0)) {
		error = errno;
		close(fd);
		return (LERR(l, error, "bind: %s", strerror(error)));
	}
	if (l->uri.transport == CBL_TR_UNIX) {
		/*
		 * Filesystem permissions are the access control on AF_UNIX
		 * (docs/SECURITY.md).  Set them before listen(): until then
		 * every connect(2) is refused, so nobody gets in under the
		 * umask's looser mode.
		 */
		mode_t mode = l->unix_mode != 0 ? l->unix_mode : 0600;

		/* Never through a symlink someone put in its place. */
		if (fchmodat(AT_FDCWD, l->uri.path, mode,
		    AT_SYMLINK_NOFOLLOW) == -1 ||
		    ((l->unix_uid != (uid_t)-1 || l->unix_gid != (gid_t)-1) &&
		    lchown(l->uri.path, l->unix_uid, l->unix_gid) == -1)) {
			error = errno;
			close(fd);
			(void)unlink(l->uri.path);
			return (LERR(l, error, "%s: %s", l->uri.path,
			    strerror(error)));
		}
	}
	if (listen(fd, 128) == -1) {
		error = errno;
		close(fd);
		if (l->uri.transport == CBL_TR_UNIX)
			(void)unlink(l->uri.path);
		return (LERR(l, error, "listen: %s", strerror(error)));
	}
	l->fd = fd;
	l->loop = loop;
	if (loop != NULL && (error = cbl_loop_add_listener(loop, l)) != 0) {
		close(fd);
		l->fd = -1;
		return (LERR(l, error, "kevent: %s", strerror(error)));
	}
	l->started = true;
	return (0);
}

/* Accept one connection; EAGAIN when none is pending. */
static int
listener_accept(cbl_listener *l, cbl_conn **connp)
{
	struct sockaddr_storage ss;
	socklen_t sslen = sizeof(ss);
	cbl_conn *conn;
	int fd, error;

	fd = accept4(l->fd, (struct sockaddr *)&ss, &sslen,
	    SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd == -1)
		return (errno == EINTR || errno == ECONNABORTED ?
		    EAGAIN : errno);
	/* Only an allowed proxy may claim another address. */
	if ((l->flags & CBL_LF_PROXY) != 0 && !cbl_proxy_allowed(l, &ss)) {
		close(fd);
		return (EAGAIN);
	}
	if (atomic_fetch_add(&l->ctx->nconns, 1) >=
	    l->lim.v[CBL_LIM_MAX_CONNS]) {
		atomic_fetch_sub(&l->ctx->nconns, 1);
		close(fd);
		return (EAGAIN);
	}
	sock_tune(fd, l->uri.transport);
	if ((error = cbl_conn_alloc(l->ctx, &l->lim, &conn)) != 0) {
		atomic_fetch_sub(&l->ctx->nconns, 1);
		close(fd);
		return (error);
	}
	conn->counted = true;
	conn->fd = fd;
	conn->uri = l->uri;
	conn->flags = l->flags;
	conn->ops = tr_ops_for(&l->uri);
	if (l->uri.transport == CBL_TR_UNIX) {
		/* Local peers: credentials, trusted only if asked to. */
		if (getpeereid(fd, &conn->peer.uid, &conn->peer.gid) == 0)
			conn->peer.has_cred = true;
		conn->peer.flags |= CBL_PEER_LOCAL;
		if ((l->flags & CBL_LF_UNIX_TRUSTED) != 0)
			conn->peer.flags |= CBL_PEER_AUTHENTICATED;
	}
	peer_set_addr(conn, (struct sockaddr *)&ss, sslen);
	/* The proxy's header comes before anything else, TLS included. */
	conn->proxy_wait = (l->flags & CBL_LF_PROXY) != 0;
	if (l->uri.transport == CBL_TR_SCTP && !l->use_tls &&
	    (error = cbl_sctp_attach(conn)) != 0) {
		cbl_conn_rele(conn);
		return (EAGAIN);
	}
	/* What cbl_listener_start() chose, not just whether TLS is set. */
	if (l->use_tls) {
		/* cbl_listener_set_tls() may replace it meanwhile. */
		pthread_mutex_lock(&l->mtx);
		cbl_tls_ref(l->tls);
		conn->tls = l->tls;
		pthread_mutex_unlock(&l->mtx);
		error = l->uri.transport == CBL_TR_SCTP ?
		    cbl_dtls_sctp_attach(conn, conn->tls, true) :
		    cbl_tls_attach(conn, conn->tls, true);
		if (error != 0) {
			cbl_conn_rele(conn);
			return (EAGAIN);
		}
	}
	conn->next_stream_id = 2;	/* the acceptor uses even ids */
	*connp = conn;
	return (0);
}

int
cbl_listener_process(cbl_listener *l, cbl_conn **connp)
{
	cbl_conn *conn;
	int error;

	if (l == NULL || connp == NULL || l->fd == -1)
		return (EINVAL);
	if ((error = listener_accept(l, &conn)) != 0)
		return (error);
	cbl_conn_accepted(conn);
	*connp = conn;
	return (0);
}

void
cbl_listener_on_ready(cbl_listener *l)
{
	cbl_conn *conn;
	int error;

	if (l->fd == -1)
		return;		/* freed earlier in this batch of events */
	for (int i = 0; i < 64; i++) {
		if ((error = listener_accept(l, &conn)) != 0) {
			/*
			 * Out of descriptors or memory: the connection stays
			 * in the backlog and the socket readable.  Look again
			 * a little later rather than at once, forever.
			 */
			if (error != EAGAIN)
				cbl_loop_pause_listener(l->loop, l,
				    CBL_ACCEPT_BACKOFF_MS);
			return;
		}
		/* The loop owns accepted connections. */
		if (cbl_conn_attach(conn, l->loop) != 0) {
			cbl_conn_rele(conn);
			continue;
		}
		cbl_conn_rele(conn);
		cbl_conn_accepted(conn);
		if (!conn->dead)
			cbl_loop_update(l->loop, conn);
	}
}

/* Stop listening; the loop, if any, forgets the socket. */
static void
listener_stop(cbl_listener *l)
{

	if (l->fd == -1)
		return;
	if (l->loop != NULL)
		cbl_loop_del_listener(l->loop, l);
	close(l->fd);
	l->fd = -1;
	if (l->uri.transport == CBL_TR_UNIX)
		(void)unlink(l->uri.path);
}

static void
listener_destroy(void *arg)
{
	cbl_listener *l = arg;

	listener_stop(l);
	cbl_tls_free(l->tls);
	atomic_fetch_sub(&l->ctx->nobjs, 1);
	pthread_mutex_destroy(&l->mtx);
	free(l);
}

/*
 * On a running loop the memory goes away from the loop, after the batch
 * of events being handled: one of them may still name this listener.
 * From the loop's own thread the socket is closed at once; another
 * thread leaves that to the loop too, which may be in accept(2) on it.
 */
void
cbl_listener_free(cbl_listener *l)
{

	if (l == NULL)
		return;
	if (l->loop != NULL && atomic_load(&l->loop->running)) {
		if (cbl_loop_on_thread(l->loop))
			listener_stop(l);
		if (cbl_loop_post(l->loop, listener_destroy, l) == 0)
			return;
	}
	listener_destroy(l);
}
