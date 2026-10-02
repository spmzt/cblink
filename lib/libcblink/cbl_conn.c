/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Connection core: framing, send queue, response correlation, timeouts.
 *
 * I/O on a connection happens on one thread at a time: the thread running
 * its cbl_loop, or, for a connection without a loop, the application
 * thread calling cbl_conn_process() or a synchronous request.  conn->mtx
 * protects the send queue, the pending-request tree and the state, which
 * other threads touch through cbl_conn_send() and synchronous requests.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cbl_impl.h"
#include "cbl_ctrl_gen.h"

#define	CBL_RX_RING	(64 * 1024)
#define	CBL_RX_BUDGET	64		/* frames per process call */
#define	CBL_IOV_MAX	64		/* frames per gathering write */

static int
pend_cmp(struct cbl_pending *a, struct cbl_pending *b)
{

	return ((a->seq > b->seq) - (a->seq < b->seq));
}

RB_GENERATE_STATIC(cbl_pend_tree, cbl_pending, link, pend_cmp);

int
cbl_conn_alloc(cbl_ctx *ctx, const struct cbl_limits *lim, cbl_conn **connp)
{
	pthread_condattr_t ca;
	cbl_conn *conn;
	int error;

	if ((conn = calloc(1, sizeof(*conn))) == NULL)
		return (ENOMEM);
	if ((error = pthread_mutex_init(&conn->mtx, NULL)) != 0) {
		free(conn);
		return (error);
	}
	/* Synchronous requests wait with CLOCK_MONOTONIC deadlines. */
	if ((error = pthread_condattr_init(&ca)) != 0) {
		pthread_mutex_destroy(&conn->mtx);
		free(conn);
		return (error);
	}
	if ((error = pthread_condattr_setclock(&ca, CLOCK_MONOTONIC)) != 0 ||
	    (error = pthread_cond_init(&conn->cv, &ca)) != 0) {
		pthread_condattr_destroy(&ca);
		pthread_mutex_destroy(&conn->mtx);
		free(conn);
		return (error);
	}
	pthread_condattr_destroy(&ca);
	atomic_fetch_add(&ctx->nobjs, 1);
	atomic_init(&conn->refs, 1);
	conn->src.type = CBL_SRC_CONN;
	conn->src.obj = conn;
	conn->ctx = ctx;
	conn->lim = *lim;
	conn->fd = -1;
	conn->next_seq = 1;
	STAILQ_INIT(&conn->txq);
	RB_INIT(&conn->pending);
	TAILQ_INIT(&conn->dumps);
	TAILQ_INIT(&conn->deferred);
	RB_INIT(&conn->streams);
	LIST_INIT(&conn->memberships);
	LIST_INIT(&conn->subs);
	TAILQ_INIT(&conn->ended);
	conn->next_stream_id = 1;	/* the initiator uses odd ids */
	*connp = conn;
	return (0);
}

void
cbl_conn_ref(cbl_conn *conn)
{

	atomic_fetch_add(&conn->refs, 1);
}

static void
txq_drop(cbl_conn *conn)
{
	struct cbl_txent *e;

	while ((e = STAILQ_FIRST(&conn->txq)) != NULL) {
		STAILQ_REMOVE_HEAD(&conn->txq, link);
		cbl_msg_free(e->msg);
		free(e);
	}
	conn->txq_bytes = 0;
	conn->txq_frames = 0;
}

void
cbl_conn_rele(cbl_conn *conn)
{

	if (atomic_fetch_sub(&conn->refs, 1) != 1)
		return;
	if (conn->fd != -1)
		close(conn->fd);
	cbl_sub_free_all(conn);
	cbl_peer_clear(&conn->peer);
	cbl_tls_free(conn->tls);
	txq_drop(conn);
	free(conn->rx);
	free(conn->big);
	free(conn->proxy_buf);
	if (conn->ops != NULL && conn->ops->free != NULL)
		conn->ops->free(conn);
	if (conn->counted)
		atomic_fetch_sub(&conn->ctx->nconns, 1);
	atomic_fetch_sub(&conn->ctx->nobjs, 1);
	pthread_cond_destroy(&conn->cv);
	pthread_mutex_destroy(&conn->mtx);
	free(conn);
}

int
cbl_conn_seterr(cbl_conn *conn, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(conn->errstr, sizeof(conn->errstr), fmt, ap);
	va_end(ap);
	return (error);
}

const char *
cbl_conn_errstr(const cbl_conn *conn)
{

	if (conn == NULL)
		return ("invalid connection");
	return (conn->errstr[0] != '\0' ? conn->errstr : NULL);
}

bool
cbl_conn_is_open(const cbl_conn *conn)
{

	return (conn != NULL && conn->state == CBL_CS_OPEN);
}

enum cbl_transport
cbl_conn_transport(const cbl_conn *conn)
{

	return (conn->uri.transport);
}

void
cbl_conn_set_udata(cbl_conn *conn, void *udata)
{

	conn->udata = udata;
}

void *
cbl_conn_udata(const cbl_conn *conn)
{

	return (conn != NULL ? conn->udata : NULL);
}

int
cbl_conn_fd(const cbl_conn *conn)
{

	return (conn != NULL ? conn->fd : -1);
}

int
cbl_conn_set_limit(cbl_conn *conn, enum cbl_limit l, uint64_t v)
{
	int error;

	if (conn == NULL)
		return (EINVAL);
	if ((error = cbl_limit_check(l, v)) != 0)
		return (error);
	if (conn->state != CBL_CS_NEW)
		return (EBUSY);
	conn->lim.v[l] = v;
	return (0);
}

/*
 * Complete a pending request.  Called with conn->mtx held; returns true
 * if an async callback must be run (after dropping the lock).
 */
static bool
pend_complete(cbl_conn *conn, struct cbl_pending *p, int error)
{

	RB_REMOVE(cbl_pend_tree, &conn->pending, p);
	conn->pend_dirty = true;
	conn->npending--;
	p->done = true;
	p->error = error;
	if (p->kind == CBL_PEND_SYNC) {
		pthread_cond_broadcast(&conn->cv);
		return (false);
	}
	return (true);
}

/* An asynchronous request is freed once no callback of it runs any more. */
static void
pend_rele(struct cbl_pending *p)
{

	if (atomic_fetch_sub(&p->refs, 1) == 1)
		free(p);
}

/* Fail every outstanding request, e.g. when the connection dies. */
static void
pend_fail_all(cbl_conn *conn, int error)
{
	struct cbl_pending *p;

	for (;;) {
		pthread_mutex_lock(&conn->mtx);
		p = RB_MIN(cbl_pend_tree, &conn->pending);
		if (p == NULL) {
			pthread_mutex_unlock(&conn->mtx);
			return;
		}
		if (!pend_complete(conn, p, error)) {
			pthread_mutex_unlock(&conn->mtx);
			continue;
		}
		pthread_mutex_unlock(&conn->mtx);
		p->cb(conn, NULL, true, error, p->arg);
		pend_rele(p);
	}
}

/* Tear the connection down.  Safe to call more than once. */
void
cbl_conn_fail(cbl_conn *conn, int error)
{
	enum cbl_conn_state prev;
	cbl_ctx *ctx = conn->ctx;

	pthread_mutex_lock(&conn->mtx);
	prev = conn->state;
	if (prev == CBL_CS_CLOSED) {
		pthread_mutex_unlock(&conn->mtx);
		return;
	}
	conn->state = CBL_CS_CLOSED;
	conn->error = error;
	txq_drop(conn);
	pthread_cond_broadcast(&conn->cv);
	pthread_mutex_unlock(&conn->mtx);

	cbl_conn_ref(conn);
	if (conn->fd != -1) {
		close(conn->fd);
		conn->fd = -1;
	}
	free(conn->rx);
	conn->rx = NULL;
	free(conn->big);
	conn->big = NULL;
	cbl_notify_conn_closed(conn);
	cbl_stream_conn_closed(conn, error != 0 ? error : ECONNRESET);
	cbl_server_abort(conn);
	pend_fail_all(conn, error != 0 ? error : ECONNRESET);
	if (conn->loop != NULL)
		cbl_loop_detach(conn->loop, conn);
	if ((prev == CBL_CS_OPEN || prev == CBL_CS_CLOSING) &&
	    ctx->conn_cbs.on_close != NULL)
		ctx->conn_cbs.on_close(conn, error, ctx->conn_cbs_arg);
	cbl_conn_rele(conn);
}

/*
 * The connection became usable.  A client is done with its handshake
 * deadline; an accepted peer stays bound by it until its first frame.
 */
void
cbl_conn_opened(cbl_conn *conn)
{
	cbl_ctx *ctx = conn->ctx;

	pthread_mutex_lock(&conn->mtx);
	conn->state = CBL_CS_OPEN;
	pthread_cond_broadcast(&conn->cv);
	pthread_mutex_unlock(&conn->mtx);
	if (conn->initiator)
		conn->open_deadline = 0;
	conn->last_rx = cbl_now_ms();
	if (ctx->conn_cbs.on_open != NULL)
		ctx->conn_cbs.on_open(conn, ctx->conn_cbs_arg);
}

/* The PROXY header comes first, then the transport's own handshake. */
static int
conn_handshake(cbl_conn *conn)
{
	int error;

	/* A non-blocking client: its connect(2) first, address by address. */
	if (conn->tcp_pending && (error = cbl_sock_connect_done(conn)) != 0)
		return (error);
	if (conn->proxy_wait) {
		if ((error = cbl_proxy_read(conn)) != 0)
			return (error);
		conn->proxy_wait = false;
	}
	return (conn->ops->handshake != NULL ? conn->ops->handshake(conn) : 0);
}

/* An accepted connection whose transport is ready. */
void
cbl_conn_accepted(cbl_conn *conn)
{
	int error;

	/* Until its first frame, a peer is bound by handshake_timeout. */
	conn->open_deadline = cbl_now_ms() +
	    conn->lim.v[CBL_LIM_HANDSHAKE_MS];
	conn->state = CBL_CS_CONNECTING;
	if ((error = conn_handshake(conn)) == 0)
		cbl_conn_opened(conn);
	else if (error != EAGAIN)
		cbl_conn_fail(conn, error);
}

/*
 * conn_flush() for transports that take several frames at once: the
 * queue goes out in batches of up to CBL_IOV_MAX frames.  conn->mtx held.
 */
static int
conn_flush_gather(cbl_conn *conn, bool *sent)
{
	struct iovec iov[CBL_IOV_MAX];
	struct cbl_txent *e;
	size_t put, left;
	int n, error;

	while (!STAILQ_EMPTY(&conn->txq)) {
		n = 0;
		STAILQ_FOREACH(e, &conn->txq, link) {
			if (n == CBL_IOV_MAX)
				break;
			iov[n].iov_base = e->msg->buf + e->off;
			iov[n].iov_len = e->msg->len - e->off;
			n++;
		}
		if ((error = conn->ops->writev(conn, iov, n, &put)) != 0)
			return (error);
		/* Retire what went out; a frame may be left half sent. */
		while (put > 0 && (e = STAILQ_FIRST(&conn->txq)) != NULL) {
			left = e->msg->len - e->off;
			if (put < left) {
				e->off += put;
				break;
			}
			put -= left;
			STAILQ_REMOVE_HEAD(&conn->txq, link);
			conn->txq_bytes -= e->msg->len;
			conn->txq_frames--;
			cbl_msg_free(e->msg);
			free(e);
			*sent = true;
		}
	}
	return (0);
}

/* Write as much of the send queue as the transport takes. */
static int
conn_flush(cbl_conn *conn)
{
	struct cbl_txent *e;
	size_t put;
	bool sent = false;
	int error = 0;

	if (conn->ops->writev != NULL) {
		pthread_mutex_lock(&conn->mtx);
		conn->want &= ~CBL_EV_WRITE;
		if ((error = conn_flush_gather(conn, &sent)) == EAGAIN) {
			conn->want |= CBL_EV_WRITE;
			error = 0;
		}
		pthread_mutex_unlock(&conn->mtx);
		if (sent)
			conn->last_tx = cbl_now_ms();
		return (error);
	}
	pthread_mutex_lock(&conn->mtx);
	conn->want &= ~CBL_EV_WRITE;
	while ((e = STAILQ_FIRST(&conn->txq)) != NULL) {
		if (e->off == 0 && conn->ops->frame_start != NULL)
			conn->ops->frame_start(conn, e->msg->buf, e->msg->len);
		error = conn->ops->write(conn, e->msg->buf + e->off,
		    e->msg->len - e->off, &put);
		if (error == EAGAIN) {
			conn->want |= CBL_EV_WRITE;
			error = 0;
			break;
		}
		if (error != 0)
			break;
		e->off += put;
		if (e->off < e->msg->len)
			continue;
		STAILQ_REMOVE_HEAD(&conn->txq, link);
		conn->txq_bytes -= e->msg->len;
		conn->txq_frames--;
		cbl_msg_free(e->msg);
		free(e);
		sent = true;
	}
	if (sent)
		conn->last_tx = cbl_now_ms();
	pthread_mutex_unlock(&conn->mtx);
	return (error);
}

/*
 * Queue an encoded frame.  Consumes "msg" in all cases.  May be called
 * from any thread.  "ctl" frames (ACK, ERROR, DONE, stream control) end
 * something the peer waits for: they are queued beyond sendq_bytes, since
 * dropping one would leave the peer waiting for good.  Not without end,
 * though: at twice sendq_bytes the peer is not reading its answers, and
 * ENOBUFS tells cbl_conn_enqueue_ctl() to give the connection up.
 */
static int
conn_enqueue(cbl_conn *conn, cbl_msg *msg, bool ctl)
{
	struct cbl_txent *e;
	cbl_loop *loop;
	bool left;
	int error;

	if ((error = cbl_msg_encode(msg, NULL, NULL)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	if ((e = calloc(1, sizeof(*e))) == NULL) {
		cbl_msg_free(msg);
		return (ENOMEM);
	}
	e->msg = msg;
	pthread_mutex_lock(&conn->mtx);
	if (conn->state == CBL_CS_CLOSED || conn->state == CBL_CS_CLOSING) {
		pthread_mutex_unlock(&conn->mtx);
		cbl_msg_free(msg);
		free(e);
		return (ENOTCONN);
	}
	if (msg->len > conn->lim.v[CBL_LIM_MAX_FRAME] ||
	    (conn->peer_max_frame != 0 && msg->len > conn->peer_max_frame)) {
		/*
		 * The peer would refuse it: larger than it said it takes
		 * (ctrl hello), or than we take.
		 */
		pthread_mutex_unlock(&conn->mtx);
		cbl_msg_free(msg);
		free(e);
		return (EMSGSIZE);
	}
	if (conn->txq_bytes + msg->len >
	    conn->lim.v[CBL_LIM_SENDQ_BYTES] * (ctl ? 2 : 1)) {
		pthread_mutex_unlock(&conn->mtx);
		cbl_msg_free(msg);
		free(e);
		return (ENOBUFS);
	}
	STAILQ_INSERT_TAIL(&conn->txq, e, link);
	conn->txq_bytes += msg->len;
	conn->txq_frames++;
	pthread_mutex_unlock(&conn->mtx);

	loop = cbl_conn_loop(conn);
	if (loop != NULL && !cbl_loop_on_thread(loop)) {
		cbl_loop_kick(loop, conn);
		return (0);
	}
	/*
	 * Our thread drives the I/O: try to send right away.  What is left,
	 * and a write error, are for cbl_conn_process(): callers may hold
	 * locks that tearing the connection down would need.  On a loop, a
	 * kick makes sure that runs and that the write filter is armed, also
	 * when this connection has no event of its own coming (a send from a
	 * timer, or from another connection's handler).
	 */
	if (conn->state != CBL_CS_OPEN)
		return (0);
	if ((error = conn_flush(conn)) != 0)
		conn->want |= CBL_EV_WRITE;
	pthread_mutex_lock(&conn->mtx);
	left = !STAILQ_EMPTY(&conn->txq);
	pthread_mutex_unlock(&conn->mtx);
	if (loop != NULL && (error != 0 || left))
		cbl_loop_kick(loop, conn);
	return (0);
}

int
cbl_conn_enqueue(cbl_conn *conn, cbl_msg *msg)
{

	return (conn_enqueue(conn, msg, false));
}

/*
 * A frame that must not be lost.  If even it cannot be queued (out of
 * memory, or a peer that sends requests without reading the answers),
 * the connection is closed: better than a peer waiting forever, or a
 * queue growing forever.
 */
int
cbl_conn_enqueue_ctl(cbl_conn *conn, cbl_msg *msg)
{
	int error;

	error = conn_enqueue(conn, msg, true);
	if (error == ENOMEM || error == ENOBUFS) {
		if (cbl_conn_io_thread(conn))	/* errstr is its thread's */
			cbl_conn_seterr(conn, error, "send queue overflow");
		(void)cbl_conn_close(conn);
	}
	return (error);
}

int
cbl_conn_send(cbl_conn *conn, cbl_msg *msg)
{

	if (conn == NULL || msg == NULL) {
		cbl_msg_free(msg);
		return (EINVAL);
	}
	return (cbl_conn_enqueue(conn, msg));
}

/*
 * Answer a frame we could not process with an ERROR echoing its header.
 * Only requests get an answer; anything else is dropped.
 */
int
cbl_conn_send_error(cbl_conn *conn, const struct cbl_hdr *h, int code,
    const char *text)
{
	cbl_msg *msg;
	uint32_t flags = CBL_F_ERROR;
	int error;

	if ((h->flags & CBL_F_REQUEST) == 0)
		return (0);
	if ((h->flags & CBL_F_S_OPEN) != 0)
		flags |= CBL_F_S_OPEN;
	if ((error = cbl_msg_alloc_empty(&conn->lim, &msg)) != 0)
		return (error);
	msg->hdr.family = h->family;
	msg->hdr.cmd = h->cmd;
	msg->hdr.flags = flags;
	msg->hdr.seq = h->seq;
	msg->hdr.stream = (flags & CBL_F_S_OPEN) != 0 ? h->stream : 0;
	(void)cbl_msg_put_error(msg, code, text, NULL, 0, -1);
	return (cbl_conn_enqueue_ctl(conn, msg));
}

/* Route a response to the request that is waiting for it. */
static void
conn_deliver_response(cbl_conn *conn, cbl_msg *msg)
{
	struct cbl_pending key, *p;
	uint32_t f = msg->hdr.flags;
	bool final;
	int error;

	final = (f & (CBL_F_ERROR | CBL_F_ACK | CBL_F_DONE)) != 0;
	error = (f & CBL_F_ERROR) != 0 ? cbl_msg_err_code(msg) : 0;

	pthread_mutex_lock(&conn->mtx);
	key.seq = msg->hdr.seq;
	p = RB_FIND(cbl_pend_tree, &conn->pending, &key);
	if (p == NULL) {
		/* Late reply to a request that timed out: drop it. */
		pthread_mutex_unlock(&conn->mtx);
		cbl_msg_free(msg);
		return;
	}
	/* A dump that keeps producing is alive: push its deadline out. */
	if (!final && p->dump) {
		p->deadline = cbl_now_ms() + conn->lim.v[CBL_LIM_REQUEST_MS];
		conn->pend_dirty = true;
	}
	if (p->kind == CBL_PEND_SYNC) {
		/*
		 * Keep the first reply, or the ERROR if one arrives; a bare
		 * ACK or DONE is not a reply.
		 */
		if ((f & CBL_F_ERROR) != 0 ||
		    (p->reply == NULL && (f & (CBL_F_ACK | CBL_F_DONE)) == 0)) {
			cbl_msg_free(p->reply);
			p->reply = msg;
		} else
			cbl_msg_free(msg);
		msg = NULL;
		if (final)
			(void)pend_complete(conn, p, error);
		pthread_mutex_unlock(&conn->mtx);
		return;
	}
	if (final)
		(void)pend_complete(conn, p, error);
	else
		atomic_fetch_add(&p->refs, 1);	/* not freed in the callback */
	pthread_mutex_unlock(&conn->mtx);
	p->cb(conn, msg, final, error, p->arg);
	cbl_msg_free(msg);
	pend_rele(p);
}

/* A complete frame (malloc'd buffer, ownership passes here). */
static void
conn_rx_frame(cbl_conn *conn, unsigned char *buf, size_t len)
{
	cbl_msg *msg = NULL;
	struct cbl_hdr h;
	int error;

	conn->last_rx = cbl_now_ms();
	conn->open_deadline = 0;
	error = cbl_msg_from_frame(&conn->lim, buf, len, &msg);
	if (error != 0) {
		if (msg == NULL)
			return;
		h = msg->hdr;
		if ((h.flags & CBL_F_REQUEST) != 0)
			(void)cbl_conn_send_error(conn, &h, error,
			    msg->errstr != NULL ? msg->errstr :
			    "malformed message");
		else if ((h.flags & CBL_F_S_ANY) != 0)
			cbl_stream_rx_malformed(conn, &h, error);
		else if ((h.flags & CBL_F_NOTIFY) == 0) {
			/* A broken response still ends its request. */
			struct cbl_pending key, *p;
			bool run_cb = false;

			pthread_mutex_lock(&conn->mtx);
			key.seq = h.seq;
			p = RB_FIND(cbl_pend_tree, &conn->pending, &key);
			if (p != NULL)
				run_cb = pend_complete(conn, p, error);
			pthread_mutex_unlock(&conn->mtx);
			if (run_cb) {
				p->cb(conn, NULL, true, error, p->arg);
				pend_rele(p);
			}
		}
		cbl_msg_free(msg);
		return;
	}
	if ((msg->hdr.flags & CBL_F_REQUEST) != 0)
		cbl_server_dispatch(conn, msg);
	else if ((msg->hdr.flags & CBL_F_S_ANY) != 0)
		cbl_stream_rx(conn, msg);
	else if ((msg->hdr.flags & CBL_F_NOTIFY) != 0)
		cbl_notify_rx(conn, msg);
	else
		conn_deliver_response(conn, msg);
}

/*
 * Stop taking new work and send what is queued, within
 * stream_close_timeout: a peer that stops reading cannot keep the
 * connection, its buffers and its max_conns slot.  conn->mtx held.
 */
static void
conn_closing(cbl_conn *conn)
{

	conn->state = CBL_CS_CLOSING;
	conn->close_deadline = cbl_now_ms() +
	    conn->lim.v[CBL_LIM_STREAM_CLOSE_MS];
}

/*
 * Handle a header that failed validation on a byte stream.  Returns
 * true if the stream can continue (the body is skipped).
 */
bool
cbl_conn_bad_header(cbl_conn *conn, int error, const struct cbl_hdr *h)
{

	switch (error) {
	case EINVAL:
		/* Invalid flags: framing is intact, skip the body. */
		(void)cbl_conn_send_error(conn, h, EINVAL, "invalid flags");
		return (true);
	case EMSGSIZE:
		/* Cannot resynchronise without reading the body: close. */
		{
			struct cbl_hdr rh = *h;

			rh.flags |= CBL_F_REQUEST;	/* always answer */
			rh.flags &= ~CBL_F_S_OPEN;
			(void)cbl_conn_send_error(conn, &rh, EMSGSIZE,
			    "frame exceeds max_frame");
		}
		break;
	case EPROTONOSUPPORT:
		{
			struct cbl_hdr rh = *h;

			rh.flags = CBL_F_REQUEST;
			(void)cbl_conn_send_error(conn, &rh, EPROTONOSUPPORT,
			    "unsupported protocol version");
		}
		break;
	default:
		/* Bad magic: not a cblink peer; close without a word. */
		cbl_conn_seterr(conn, EPROTO, "protocol error: bad magic");
		cbl_conn_fail(conn, EPROTO);
		return (false);
	}
	cbl_conn_seterr(conn, error, "protocol error: %s", strerror(error));
	pthread_mutex_lock(&conn->mtx);
	conn_closing(conn);
	pthread_mutex_unlock(&conn->mtx);
	return (false);
}

/*
 * Read backpressure.  An accepted connection stops reading while its send
 * queue (replies, notifications) is over three quarters of sendq_bytes,
 * until it is under a quarter: a peer that does not read its replies is
 * not read either, rather than having replies dropped.  Any connection
 * stops reading while a client dump's queue is full (cbl_conn_rx_hold()).
 * The initiator's own queue holds its requests, which are refused with
 * ENOBUFS instead, so two peers can never wait on each other.
 */
static bool
conn_rx_paused(cbl_conn *conn)
{
	uint64_t q = conn->lim.v[CBL_LIM_SENDQ_BYTES];
	size_t bytes;

	if (!conn->initiator) {
		pthread_mutex_lock(&conn->mtx);
		bytes = conn->txq_bytes;
		pthread_mutex_unlock(&conn->mtx);
		if (!conn->rx_paused && bytes >= q / 4 * 3)
			conn->rx_paused = true;
		else if (conn->rx_paused && bytes <= q / 4)
			conn->rx_paused = false;
	}
	return (conn->rx_paused || atomic_load(&conn->rx_holds) > 0);
}

/*
 * A client dump's queue is full (hold), or has room again: stop or resume
 * reading.  Any thread; the I/O thread is told to look again.
 */
void
cbl_conn_rx_hold(cbl_conn *conn, bool hold)
{
	cbl_loop *loop;

	if (hold) {
		atomic_fetch_add(&conn->rx_holds, 1);
		return;
	}
	if (atomic_fetch_sub(&conn->rx_holds, 1) == 1 &&
	    (loop = cbl_conn_loop(conn)) != NULL)
		cbl_loop_kick(loop, conn);
}

/* Parse complete frames out of the receive ring. */
static int
conn_parse_ring(cbl_conn *conn, int *budget)
{
	struct cbl_hdr h;
	unsigned char *frame;
	size_t avail, n;
	int error;

	while (*budget > 0 && conn->state == CBL_CS_OPEN) {
		if (conn_rx_paused(conn)) {
			conn->rx_pending = true;	/* resume from here */
			return (0);
		}
		avail = conn->rx_end - conn->rx_start;
		if (conn->discard > 0) {
			n = avail < conn->discard ? avail : conn->discard;
			conn->rx_start += n;
			conn->discard -= n;
			if (conn->discard > 0)
				return (0);
			continue;
		}
		if (avail < CBL_HDRLEN)
			return (0);
		error = cbl_hdr_decode(conn->rx + conn->rx_start, avail,
		    &conn->lim, &h);
		if (error != 0) {
			if (!cbl_conn_bad_header(conn, error, &h))
				return (0);
			conn->rx_start += CBL_HDRLEN;
			conn->discard = h.length - CBL_HDRLEN;
			continue;
		}
		if ((frame = malloc(h.length)) == NULL)
			return (ENOMEM);
		if (h.length <= avail) {
			memcpy(frame, conn->rx + conn->rx_start, h.length);
			conn->rx_start += h.length;
			(*budget)--;
			conn_rx_frame(conn, frame, h.length);
			continue;
		}
		/* Larger than what is buffered: read the rest directly. */
		memcpy(frame, conn->rx + conn->rx_start, avail);
		conn->rx_start = conn->rx_end = 0;
		conn->big = frame;
		conn->big_len = h.length;
		conn->big_have = avail;
		return (0);
	}
	return (0);
}

/*
 * One message of a message transport (SCTP): exactly one frame.  Anything
 * wrong with it is dropped and counted; a request that can be identified
 * gets an ERROR.  The connection itself is never closed for it.
 */
void
cbl_conn_rx_message(cbl_conn *conn, const void *buf, size_t len)
{
	unsigned char *frame;
	struct cbl_hdr h;
	int error;

	if (len == 0)
		return;
	error = cbl_hdr_decode(buf, len, &conn->lim, &h);
	if (error == 0 && h.length != len)
		error = EBADMSG;
	if (error != 0) {
		conn->rx_dropped++;
		if (len >= CBL_HDRLEN && error != EPROTO)
			(void)cbl_conn_send_error(conn, &h, error,
			    error == EMSGSIZE ? "frame exceeds max_frame" :
			    error == EBADMSG ? "length does not match message" :
			    "invalid header");
		return;
	}
	if ((frame = malloc(len)) == NULL)
		return;
	memcpy(frame, buf, len);
	conn_rx_frame(conn, frame, len);
}

/* Message transports read and reassemble frames themselves. */
static int
conn_read_messages(cbl_conn *conn)
{

	conn->rx_pending = false;
	return (conn->ops->rx_frames(conn, CBL_RX_BUDGET));
}

static int
conn_read(cbl_conn *conn)
{
	int budget = CBL_RX_BUDGET;
	size_t got;
	int error;

	conn->want &= ~CBL_EV_READ;
	if (conn->ops->rx_frames != NULL)
		return (conn_read_messages(conn));
	if (conn->rx == NULL) {
		if ((conn->rx = malloc(CBL_RX_RING)) == NULL)
			return (ENOMEM);
		conn->rx_cap = CBL_RX_RING;
	}
	/* Frames left over from a previous call go first. */
	conn->rx_pending = false;
	if (conn->big == NULL && conn->rx_end > conn->rx_start &&
	    (error = conn_parse_ring(conn, &budget)) != 0)
		return (error);
	while (budget > 0 && conn->state == CBL_CS_OPEN) {
		if (conn_rx_paused(conn)) {
			conn->rx_pending = conn->rx_end > conn->rx_start;
			return (0);
		}
		if (conn->big != NULL) {
			error = conn->ops->read(conn,
			    conn->big + conn->big_have,
			    conn->big_len - conn->big_have, &got);
		} else {
			if (conn->rx_start == conn->rx_end)
				conn->rx_start = conn->rx_end = 0;
			else if (conn->rx_cap - conn->rx_end < CBL_HDRLEN_MAX) {
				memmove(conn->rx, conn->rx + conn->rx_start,
				    conn->rx_end - conn->rx_start);
				conn->rx_end -= conn->rx_start;
				conn->rx_start = 0;
			}
			error = conn->ops->read(conn, conn->rx + conn->rx_end,
			    conn->rx_cap - conn->rx_end, &got);
		}
		if (error == EAGAIN)
			return (0);
		if (error != 0)
			return (error);
		if (got == 0)
			return (ECONNRESET);	/* orderly EOF */
		if (conn->big != NULL) {
			conn->big_have += got;
			if (conn->big_have == conn->big_len) {
				unsigned char *f = conn->big;

				conn->big = NULL;
				budget--;
				conn_rx_frame(conn, f, conn->big_len);
			}
			continue;
		}
		conn->rx_end += got;
		if ((error = conn_parse_ring(conn, &budget)) != 0)
			return (error);
	}
	/*
	 * Out of budget with data still buffered: the socket may have
	 * nothing more to say, so ask to be called again right away.
	 */
	if (budget == 0)
		conn->rx_pending = true;
	return (0);
}

/* The last frame in either direction. */
static uint64_t
conn_last_io(const cbl_conn *conn)
{

	return (conn->last_rx > conn->last_tx ? conn->last_rx : conn->last_tx);
}

/*
 * When the idle timer next needs attention: half of idle_timeout after
 * the last frame (time for a keepalive), or all of it once one is out.
 */
static uint64_t
conn_idle_deadline(const cbl_conn *conn)
{
	uint64_t idle = conn->lim.v[CBL_LIM_IDLE_MS];

	if (conn->state != CBL_CS_OPEN || idle == 0)
		return (0);
	return (conn_last_io(conn) + (conn->ka_pending ? idle : idle / 2));
}

static void
keepalive_done(cbl_conn *conn, cbl_msg *reply __unused, bool final, int error,
    void *arg __unused)
{

	if (!final)
		return;
	conn->ka_pending = false;
	if (error == ETIMEDOUT) {
		cbl_conn_seterr(conn, ETIMEDOUT,
		    "idle timeout: keepalive not answered");
		cbl_conn_fail(conn, ETIMEDOUT);
	}
}

static int req_issue(cbl_conn *, cbl_msg *, struct cbl_pending *, int);

/*
 * idle_timeout is dead-peer detection (WIRE-FORMAT.md section 11): no
 * frame in either direction for half of it sends a ctrl ping, which must
 * be answered within the other half.  Returns an error when the
 * connection was failed.
 */
static int
conn_idle(cbl_conn *conn, uint64_t now)
{
	uint64_t idle = conn->lim.v[CBL_LIM_IDLE_MS], last;
	struct cbl_pending *p;
	cbl_msg *msg;

	if (idle == 0)
		return (0);
	last = conn_last_io(conn);
	if (now >= last + idle) {
		/* Not even a keepalive could be sent. */
		cbl_conn_seterr(conn, ETIMEDOUT, "idle timeout");
		cbl_conn_fail(conn, ETIMEDOUT);
		return (ETIMEDOUT);
	}
	if (conn->ka_pending || now < last + idle / 2)
		return (0);
	if (cbl_msg_new(conn->ctx, CBL_CTRL_FAMILY_ID, CBL_CTRL_CMD_PING, 0,
	    &msg) != 0)
		return (0);
	if ((p = calloc(1, sizeof(*p))) == NULL) {
		cbl_msg_free(msg);
		return (0);
	}
	p->kind = CBL_PEND_ASYNC;
	p->cb = keepalive_done;
	conn->ka_pending = true;
	if (req_issue(conn, msg, p, (int)(idle - idle / 2)) != 0) {
		conn->ka_pending = false;
		free(p);
	}
	return (0);
}

/*
 * Nearest pending-request deadline, or 0.  Cached: the tree is walked
 * only after a request was added, finished or had its deadline moved.
 */
static uint64_t
conn_min_deadline(cbl_conn *conn)
{
	struct cbl_pending *p;
	uint64_t next;

	pthread_mutex_lock(&conn->mtx);
	if (conn->pend_dirty) {
		next = 0;
		RB_FOREACH(p, cbl_pend_tree, &conn->pending)
			if (p->deadline != 0 &&
			    (next == 0 || p->deadline < next))
				next = p->deadline;
		conn->pend_next = next;
		conn->pend_dirty = false;
	}
	next = conn->pend_next;
	pthread_mutex_unlock(&conn->mtx);
	return (next);
}

/* Fail requests whose deadline passed; returns the nearest deadline. */
static uint64_t
conn_expire(cbl_conn *conn, uint64_t now)
{
	struct cbl_pending *p, *tmp;
	uint64_t next = 0;

	for (;;) {
		bool run_cb = false;
		struct cbl_pending *hit = NULL;

		pthread_mutex_lock(&conn->mtx);
		next = 0;
		RB_FOREACH_SAFE(p, cbl_pend_tree, &conn->pending, tmp) {
			if (p->deadline == 0)
				continue;
			if (p->deadline <= now) {
				hit = p;
				run_cb = pend_complete(conn, p, ETIMEDOUT);
				break;
			}
			if (next == 0 || p->deadline < next)
				next = p->deadline;
		}
		pthread_mutex_unlock(&conn->mtx);
		if (hit == NULL)
			return (next);
		if (run_cb) {
			hit->cb(conn, NULL, true, ETIMEDOUT, hit->arg);
			pend_rele(hit);
		}
	}
}

/*
 * What the connection waits for: the events, and the absolute time (ms,
 * cbl_now_ms()) when it next needs attention, or 0.
 */
uint64_t
cbl_conn_wants(cbl_conn *conn, int *eventsp)
{
	uint64_t now, next = 0, d;
	int events = 0, t;

	switch (conn->state) {
	case CBL_CS_CONNECTING:
		events = conn->want != 0 ? conn->want : CBL_EV_WRITE;
		break;
	case CBL_CS_OPEN:
		events = (conn_rx_paused(conn) ? 0 : CBL_EV_READ) | conn->want;
		break;
	case CBL_CS_CLOSING:
		events = conn->want;
		break;
	default:
		break;
	}
	pthread_mutex_lock(&conn->mtx);
	if (!STAILQ_EMPTY(&conn->txq) && conn->state != CBL_CS_CONNECTING)
		events |= CBL_EV_WRITE;
	pthread_mutex_unlock(&conn->mtx);

	now = cbl_now_ms();
	if (conn->open_deadline != 0)
		next = conn->open_deadline;
	if ((d = conn_idle_deadline(conn)) != 0 && (next == 0 || d < next))
		next = d;
	if (conn->state == CBL_CS_CLOSING &&
	    (next == 0 || conn->close_deadline < next))
		next = conn->close_deadline;
	if ((d = conn_min_deadline(conn)) != 0 && (next == 0 || d < next))
		next = d;
	if ((d = cbl_stream_next_deadline(conn)) != 0 &&
	    (next == 0 || d < next))
		next = d;
	*eventsp = conn->state == CBL_CS_CLOSED ? 0 : events;
	if (conn->rx_pending && conn->state == CBL_CS_OPEN &&
	    !conn_rx_paused(conn))
		next = now;
	if (conn->state == CBL_CS_OPEN && cbl_server_dump_ready(conn))
		next = now;		/* a dump waits for its next turn */
	if (conn->ops != NULL && conn->ops->timeout != NULL &&
	    (t = conn->ops->timeout(conn)) >= 0 &&
	    (next == 0 || now + (uint64_t)t < next))
		next = now + (uint64_t)t;
	return (conn->state == CBL_CS_CLOSED ? 0 : next);
}

int
cbl_conn_interest(cbl_conn *conn, int *eventsp, int *timeoutp)
{
	uint64_t now, next;

	if (conn == NULL || eventsp == NULL || timeoutp == NULL)
		return (EINVAL);
	next = cbl_conn_wants(conn, eventsp);
	now = cbl_now_ms();
	if (next == 0)
		*timeoutp = -1;
	else
		*timeoutp = next <= now ? 0 :
		    (next - now > INT32_MAX ? INT32_MAX : (int)(next - now));
	return (0);
}

/* Drive a connection: I/O for "revents", then timers. */
int
cbl_conn_process(cbl_conn *conn, int revents)
{
	uint64_t now;
	int error = 0;

	if (conn == NULL)
		return (EINVAL);
	cbl_conn_ref(conn);
	if (conn->ops->timeout != NULL && conn->ops->timeout(conn) == 0)
		conn->ops->on_timeout(conn);	/* DTLS retransmission */
	if (conn->state == CBL_CS_CONNECTING) {
		error = conn_handshake(conn);
		if (error == 0)
			cbl_conn_opened(conn);
		else if (error != EAGAIN) {
			cbl_conn_fail(conn, error);
			goto out;
		}
	}
	if (conn->state == CBL_CS_OPEN && !conn_rx_paused(conn) &&
	    (conn->rx_pending || (revents & CBL_EV_READ) != 0 ||
	    (conn->want & CBL_EV_READ) != 0)) {
		if ((error = conn_read(conn)) != 0) {
			if (conn->errstr[0] == '\0')
				cbl_conn_seterr(conn, error, "%s",
				    error == ECONNRESET ?
				    "connection closed by peer" :
				    strerror(error));
			cbl_conn_fail(conn, error);
			goto out;
		}
	}
	if (conn->state == CBL_CS_OPEN || conn->state == CBL_CS_CLOSING) {
		if ((error = conn_flush(conn)) != 0) {
			cbl_conn_seterr(conn, error, "write: %s",
			    strerror(error));
			cbl_conn_fail(conn, error);
			goto out;
		}
	}
	/* Room in the send queue again: continue throttled dumps. */
	if (conn->state == CBL_CS_OPEN && !TAILQ_EMPTY(&conn->dumps)) {
		cbl_server_resume(conn);
		if (conn->state == CBL_CS_OPEN &&
		    (error = conn_flush(conn)) != 0) {
			cbl_conn_fail(conn, error);
			goto out;
		}
	}
	if (conn->state == CBL_CS_CLOSING && STAILQ_EMPTY(&conn->txq)) {
		if (conn->ops->shutdown != NULL)
			conn->ops->shutdown(conn);
		cbl_conn_fail(conn, conn->error);
		goto out;
	}
	now = cbl_now_ms();
	if (conn->open_deadline != 0 && now >= conn->open_deadline) {
		cbl_conn_seterr(conn, ETIMEDOUT, "handshake timeout");
		cbl_conn_fail(conn, ETIMEDOUT);
		goto out;
	}
	if (conn->state == CBL_CS_CLOSING && now >= conn->close_deadline) {
		cbl_conn_seterr(conn, ETIMEDOUT, "close timed out");
		cbl_conn_fail(conn, ETIMEDOUT);
		goto out;
	}
	if (conn->state == CBL_CS_OPEN && conn_idle(conn, now) != 0)
		goto out;
	(void)conn_expire(conn, now);
	if (conn->state == CBL_CS_OPEN) {
		cbl_stream_reap(conn);
		(void)cbl_stream_expire(conn, now);
	}
	error = 0;
out:
	if (conn->state == CBL_CS_CLOSED)
		error = conn->error != 0 ? conn->error : ECONNRESET;
	cbl_conn_rele(conn);
	return (error);
}

/* Close on the I/O thread: the state is the I/O thread's to change. */
static void
conn_close(cbl_conn *conn)
{
	cbl_loop *loop;

	pthread_mutex_lock(&conn->mtx);
	if (conn->state == CBL_CS_OPEN)
		conn_closing(conn);
	pthread_mutex_unlock(&conn->mtx);
	if (conn->state != CBL_CS_CLOSING) {
		cbl_conn_fail(conn, 0);
		return;
	}
	/* On a loop, its thread drains the queue and arms the filters. */
	if ((loop = cbl_conn_loop(conn)) != NULL)
		cbl_loop_kick(loop, conn);
	else
		(void)cbl_conn_process(conn, 0);
}

static void
conn_close_cb(void *arg)
{
	cbl_conn *conn = arg;

	conn_close(conn);
	cbl_conn_rele(conn);
}

int
cbl_conn_close(cbl_conn *conn)
{
	cbl_loop *loop;

	if (conn == NULL)
		return (EINVAL);
	if (!cbl_conn_io_thread(conn) && (loop = cbl_conn_loop(conn)) != NULL) {
		cbl_conn_ref(conn);
		if (cbl_loop_post(loop, conn_close_cb, conn) == 0)
			return (0);
		cbl_conn_rele(conn);
		return (ENOMEM);
	}
	conn_close(conn);
	return (0);
}

static void
conn_free_cb(void *arg)
{
	cbl_conn *conn = arg;

	cbl_conn_fail(conn, ECONNABORTED);
	cbl_conn_rele(conn);
}

void
cbl_conn_free(cbl_conn *conn)
{
	cbl_loop *loop;

	if (conn == NULL)
		return;
	if (!cbl_conn_io_thread(conn)) {
		/* Let the loop thread tear it down. */
		loop = cbl_conn_loop(conn);
		if (loop != NULL &&
		    cbl_loop_post(loop, conn_free_cb, conn) == 0)
			return;
	}
	conn_free_cb(conn);
}

/*
 * Client requests.  Every request asks for an ACK, so it always ends with
 * exactly one terminal frame (ACK, ERROR or DONE).
 */
static int
req_issue(cbl_conn *conn, cbl_msg *req, struct cbl_pending *p,
    int timeout_ms)
{
	struct cbl_pending *dup;
	bool async = p->kind == CBL_PEND_ASYNC, done;
	int error;

	if (conn->state != CBL_CS_OPEN) {
		cbl_msg_free(req);
		return (ENOTCONN);
	}
	if ((req->hdr.flags & ~(CBL_F_REQUEST | CBL_F_ACK | CBL_F_DUMP)) != 0) {
		cbl_msg_free(req);
		return (EINVAL);
	}
	req->hdr.flags |= CBL_F_REQUEST | CBL_F_ACK;
	atomic_init(&p->refs, 1);
	p->dump = (req->hdr.flags & CBL_F_DUMP) != 0;
	p->deadline = cbl_now_ms() + (timeout_ms >= 0 ? (uint64_t)timeout_ms :
	    conn->lim.v[CBL_LIM_REQUEST_MS]);
	pthread_mutex_lock(&conn->mtx);
	do {
		p->seq = conn->next_seq++;
		if (conn->next_seq == 0)
			conn->next_seq = 1;
		dup = RB_INSERT(cbl_pend_tree, &conn->pending, p);
		conn->pend_dirty = true;
	} while (dup != NULL);
	conn->npending++;
	pthread_mutex_unlock(&conn->mtx);
	req->hdr.seq = p->seq;
	if ((error = cbl_conn_enqueue(conn, req)) != 0) {
		pthread_mutex_lock(&conn->mtx);
		if (!(done = p->done)) {
			RB_REMOVE(cbl_pend_tree, &conn->pending, p);
			conn->pend_dirty = true;
			conn->npending--;
		}
		pthread_mutex_unlock(&conn->mtx);
		/*
		 * Completed meanwhile (the connection died on another
		 * thread): its callback has the error, and owns "p" now.
		 */
		if (done && async)
			return (0);
		return (error);
	}
	return (0);
}

static short
ev2poll(int events)
{

	return (((events & CBL_EV_READ) != 0 ? POLLIN : 0) |
	    ((events & CBL_EV_WRITE) != 0 ? POLLOUT : 0));
}

/* One round of poll(2) + cbl_conn_process() on a loop-less connection. */
static void
drive_once(cbl_conn *conn)
{
	struct pollfd pfd;
	int events, timeout, rev = 0, n;

	(void)cbl_conn_interest(conn, &events, &timeout);
	pfd.fd = conn->fd;
	pfd.events = ev2poll(events);
	pfd.revents = 0;
	n = poll(&pfd, 1, timeout);
	if (n == -1 && errno != EINTR) {
		cbl_conn_seterr(conn, errno, "poll: %s", strerror(errno));
		cbl_conn_fail(conn, errno);
		return;
	}
	if (n > 0) {
		if ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0)
			rev |= CBL_EV_READ;
		if ((pfd.revents & POLLOUT) != 0)
			rev |= CBL_EV_WRITE;
	}
	(void)cbl_conn_process(conn, rev);
}

/* Drive a loop-less connection until "p" completes. */
static void
req_drive(cbl_conn *conn, struct cbl_pending *p)
{

	while (!p->done && conn->state != CBL_CS_CLOSED)
		drive_once(conn);
}

/*
 * Wait until cond(arg) holds or the connection dies.  With a loop,
 * cond() is evaluated with conn->mtx held; callbacks that change what it
 * looks at must take conn->mtx and broadcast conn->cv.
 */
int
cbl_conn_wait(cbl_conn *conn, bool (*cond)(void *), void *arg)
{
	cbl_loop *loop = cbl_conn_loop(conn);

	if (loop != NULL) {
		if (cbl_loop_on_thread(loop))
			return (EDEADLK);
		pthread_mutex_lock(&conn->mtx);
		while (!cond(arg) && conn->state != CBL_CS_CLOSED)
			pthread_cond_wait(&conn->cv, &conn->mtx);
		pthread_mutex_unlock(&conn->mtx);
		return (0);
	}
	while (!cond(arg) && conn->state != CBL_CS_CLOSED)
		drive_once(conn);
	return (0);
}

int
cbl_request(cbl_conn *conn, cbl_msg *req, cbl_msg **replyp, int timeout_ms)
{
	struct cbl_pending *p;
	struct timespec abst;
	cbl_msg *reply;
	uint64_t ms;
	int error;

	if (replyp != NULL)
		*replyp = NULL;
	if (conn == NULL || req == NULL) {
		cbl_msg_free(req);
		return (EINVAL);
	}
	if (cbl_conn_loop(conn) != NULL && cbl_loop_on_thread(conn->loop)) {
		cbl_msg_free(req);
		return (EDEADLK);
	}
	if ((p = calloc(1, sizeof(*p))) == NULL) {
		cbl_msg_free(req);
		return (ENOMEM);
	}
	p->kind = CBL_PEND_SYNC;
	if ((error = req_issue(conn, req, p, timeout_ms)) != 0) {
		free(p);
		return (error);
	}
	if (cbl_conn_loop(conn) != NULL) {
		ms = p->deadline;
		abst.tv_sec = (time_t)(ms / 1000);
		abst.tv_nsec = (long)(ms % 1000) * 1000000;
		pthread_mutex_lock(&conn->mtx);
		while (!p->done) {
			if (pthread_cond_timedwait(&conn->cv, &conn->mtx,
			    &abst) == ETIMEDOUT && !p->done)
				(void)pend_complete(conn, p, ETIMEDOUT);
		}
		pthread_mutex_unlock(&conn->mtx);
	} else
		req_drive(conn, p);

	pthread_mutex_lock(&conn->mtx);
	if (!p->done) {		/* the connection died under us */
		RB_REMOVE(cbl_pend_tree, &conn->pending, p);
		conn->pend_dirty = true;
		conn->npending--;
		p->error = conn->error != 0 ? conn->error : ECONNRESET;
	}
	pthread_mutex_unlock(&conn->mtx);
	error = p->error;
	reply = p->reply;
	free(p);
	if (replyp != NULL)
		*replyp = reply;
	else
		cbl_msg_free(reply);
	return (error);
}

int
cbl_request_async(cbl_conn *conn, cbl_msg *req, cbl_reply_f *cb, void *arg)
{
	struct cbl_pending *p;
	int error;

	if (conn == NULL || req == NULL || cb == NULL) {
		cbl_msg_free(req);
		return (EINVAL);
	}
	if ((p = calloc(1, sizeof(*p))) == NULL) {
		cbl_msg_free(req);
		return (ENOMEM);
	}
	p->kind = CBL_PEND_ASYNC;
	p->cb = cb;
	p->arg = arg;
	if ((error = req_issue(conn, req, p, -1)) != 0) {
		free(p);
		return (error);
	}
	return (0);
}

cbl_ctx *
cbl_conn_ctx(const cbl_conn *conn)
{

	return (conn != NULL ? conn->ctx : NULL);
}

/* What the connection is doing, for monitoring.  Any thread. */
int
cbl_conn_stats(cbl_conn *conn, struct cbl_conn_stats *st)
{

	if (conn == NULL || st == NULL)
		return (EINVAL);
	memset(st, 0, sizeof(*st));
	st->rx_dropped = atomic_load(&conn->rx_dropped);
	st->ntf_dropped = atomic_load(&conn->ntf_dropped);
	st->inflight = atomic_load(&conn->inflight);
	st->rx_paused = atomic_load(&conn->rx_paused) ||
	    atomic_load(&conn->rx_holds) > 0;
	pthread_mutex_lock(&conn->mtx);
	st->txq_bytes = conn->txq_bytes;
	st->txq_frames = conn->txq_frames;
	st->pending = conn->npending;
	st->streams = conn->nstreams;
	pthread_mutex_unlock(&conn->mtx);
	return (0);
}
