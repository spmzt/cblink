/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Streams (docs/WIRE-FORMAT.md section 8, docs/STREAMS.md): long-lived,
 * ordered, bidirectional channels multiplexed on a connection, with
 * credit-based flow control.
 *
 * Callbacks run on the connection's I/O thread.  Stream state is guarded
 * by conn->mtx, so cbl_stream_send() and friends may be called from any
 * thread, callbacks included.  A call that ends the stream only marks it
 * "ending"; the I/O thread runs on_close and frees the stream later, at
 * a fixed point (cbl_stream_reap()), never inside a callback.  A
 * cbl_stream pointer is valid until its on_close callback returns.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"

static int
stream_cmp(struct cbl_stream *a, struct cbl_stream *b)
{

	return ((a->id > b->id) - (a->id < b->id));
}

RB_GENERATE_STATIC(cbl_stream_tree, cbl_stream, link, stream_cmp);

/*
 * A new stream: one reference, the library's, dropped once on_close has
 * run.  Each stream holds its connection, so a stream kept with
 * cbl_stream_ref() is safe to call (and answers EPIPE) after it ended.
 */
static cbl_stream *
stream_alloc(cbl_conn *conn)
{
	cbl_stream *s;

	if ((s = calloc(1, sizeof(*s))) == NULL)
		return (NULL);
	atomic_init(&s->refs, 1);
	cbl_conn_ref(conn);
	s->conn = conn;
	return (s);
}

void
cbl_stream_ref(cbl_stream *s)
{

	if (s != NULL)
		atomic_fetch_add(&s->refs, 1);
}

void
cbl_stream_rele(cbl_stream *s)
{

	if (s == NULL || atomic_fetch_sub(&s->refs, 1) != 1)
		return;
	cbl_conn_rele(s->conn);
	free(s->close_text);
	free(s);
}

static cbl_stream *
stream_find(cbl_conn *conn, uint32_t id)
{
	struct cbl_stream key;

	key.id = id;
	return (RB_FIND(cbl_stream_tree, &conn->streams, &key));
}

/* Send a control frame (no family attributes). */
static int
send_ctl(cbl_conn *conn, const cbl_stream *s, uint32_t id, uint32_t flags,
    int code, const char *text, uint64_t credit)
{
	cbl_msg *msg;
	int error;

	if ((error = cbl_msg_alloc_empty(&conn->lim, &msg)) != 0)
		return (error);
	msg->hdr.family = s != NULL ? s->family : 0;
	msg->hdr.cmd = s != NULL ? s->cmd : 0;
	msg->hdr.flags = flags;
	msg->hdr.stream = id;
	if (code > 0 || text != NULL)
		(void)cbl_msg_put_error(msg, code, text, NULL, 0, -1);
	if ((flags & CBL_F_S_CREDIT) != 0)
		(void)cbl_msg_put_fw_uint(msg, CBL_FW_CREDIT, credit);
	return (cbl_conn_enqueue_ctl(conn, msg));
}

/* Is the stream finished or about to be?  Callers re-check after callbacks. */
static bool
stream_gone(cbl_stream *s)
{
	cbl_conn *conn = s->conn;
	bool gone;

	pthread_mutex_lock(&conn->mtx);
	gone = s->ending || s->state == CBL_SS_DONE;
	pthread_mutex_unlock(&conn->mtx);
	return (gone);
}

/*
 * Remove a stream, run its final callback and free it: the only place a
 * stream is freed once it is in the tree.  I/O thread only, with
 * conn->mtx not held, and never while a callback of this stream runs.
 */
static void
stream_finish(cbl_stream *s, int code, const char *text)
{
	cbl_conn *conn = s->conn;
	bool present;

	pthread_mutex_lock(&conn->mtx);
	present = stream_find(conn, s->id) == s;
	if (present) {
		RB_REMOVE(cbl_stream_tree, &conn->streams, s);
		conn->nstreams--;
		conn->strm_dirty = true;
	}
	if (s->ending) {
		TAILQ_REMOVE(&conn->ended, s, done_link);
		s->ending = false;
	}
	s->state = CBL_SS_DONE;
	pthread_mutex_unlock(&conn->mtx);
	if (!present)
		return;
	if (s->cbs.on_close != NULL)
		s->cbs.on_close(s, code, text, s->arg);
	cbl_stream_rele(s);
}

/*
 * The stream is over: have the I/O thread finish it at its next reaping
 * point.  Never finishes inline, so callers (callbacks among them) may go
 * on using the stream until they return.
 */
static void
stream_end(cbl_stream *s, int code, const char *text)
{
	cbl_conn *conn = s->conn;
	cbl_loop *loop;

	pthread_mutex_lock(&conn->mtx);
	if (!s->ending && s->state != CBL_SS_DONE) {
		s->ending = true;
		conn->strm_dirty = true;
		s->close_code = code;
		s->close_text = text != NULL ? strdup(text) : NULL;
		TAILQ_INSERT_TAIL(&conn->ended, s, done_link);
	}
	pthread_mutex_unlock(&conn->mtx);
	if ((loop = cbl_conn_loop(conn)) != NULL)
		cbl_loop_kick(loop, conn);
}

/*
 * Finish the streams that ended: from cbl_conn_process(), and when a
 * stream frame or a stream timeout has been handled.
 */
void
cbl_stream_reap(cbl_conn *conn)
{
	cbl_stream *s;

	for (;;) {
		pthread_mutex_lock(&conn->mtx);
		s = TAILQ_FIRST(&conn->ended);
		pthread_mutex_unlock(&conn->mtx);
		if (s == NULL)
			return;
		stream_finish(s, s->close_code, s->close_text);
	}
}

static void
reset_and_end(cbl_stream *s, int code, const char *text)
{

	(void)send_ctl(s->conn, s, s->id, CBL_F_S_RESET, code, text, 0);
	stream_end(s, code, text);
}

static uint64_t
fw_uint(const cbl_msg *msg, int key, bool *found)
{
	const cbl_attr *a = cbl_map_lookup(cbl_msg_body(msg), key);

	*found = a != NULL && a->kind == CBL_K_UINT;
	return (*found ? a->v.u : 0);
}

int
cbl_stream_open(cbl_conn *conn, cbl_msg *open_req, uint32_t flags,
    const struct cbl_stream_cbs *cbs, void *arg, cbl_stream **sp)
{
	cbl_stream *s;
	uint32_t id;
	int error;

	if (conn == NULL || open_req == NULL || cbs == NULL || sp == NULL) {
		cbl_msg_free(open_req);
		return (EINVAL);
	}
	*sp = NULL;
	if (conn->state != CBL_CS_OPEN) {
		cbl_msg_free(open_req);
		return (ENOTCONN);
	}
	if ((s = stream_alloc(conn)) == NULL) {
		cbl_msg_free(open_req);
		return (ENOMEM);
	}
	s->local = true;
	s->push = (flags & CBL_SF_PUSH) != 0;
	s->flags = flags;
	s->family = open_req->hdr.family;
	s->cmd = open_req->hdr.cmd;
	s->state = CBL_SS_OPENING;
	s->window = open_req->window != 0 ? open_req->window :
	    conn->lim.v[CBL_LIM_STREAM_WINDOW];
	s->rx_window = s->window;
	s->cbs = *cbs;
	s->arg = arg;
	s->deadline = cbl_now_ms() + conn->lim.v[CBL_LIM_REQUEST_MS];

	pthread_mutex_lock(&conn->mtx);
	if (conn->nstreams >= conn->lim.v[CBL_LIM_MAX_STREAMS] ||
	    conn->next_stream_id > UINT32_MAX - 2) {
		pthread_mutex_unlock(&conn->mtx);
		cbl_msg_free(open_req);
		cbl_stream_rele(s);
		return (ENOSPC);
	}
	id = conn->next_stream_id;
	conn->next_stream_id += 2;
	s->id = id;
	s->open_seq = conn->next_seq++;
	if (conn->next_seq == 0)
		conn->next_seq = 1;
	RB_INSERT(cbl_stream_tree, &conn->streams, s);
	conn->nstreams++;
	conn->strm_dirty = true;
	pthread_mutex_unlock(&conn->mtx);

	open_req->hdr.flags = CBL_F_REQUEST | CBL_F_S_OPEN;
	open_req->hdr.stream = id;
	open_req->hdr.seq = s->open_seq;
	(void)cbl_msg_put_fw_uint(open_req, CBL_FW_CREDIT, s->window);
	if ((error = cbl_conn_enqueue(conn, open_req)) != 0) {
		pthread_mutex_lock(&conn->mtx);
		RB_REMOVE(cbl_stream_tree, &conn->streams, s);
		conn->nstreams--;
		conn->strm_dirty = true;
		pthread_mutex_unlock(&conn->mtx);
		cbl_stream_rele(s);
		return (error);
	}
	*sp = s;
	return (0);
}

/*
 * The peer asks to open a stream; "req" passed policy checks.  Returns 0
 * when the stream was accepted, else an errno for the ERROR|S_OPEN.
 */
int
cbl_stream_server_open(cbl_req *req, cbl_conn *conn, cbl_msg *msg, bool push)
{
	const struct cbl_hdr *h = &msg->hdr;
	uint32_t parity = conn->initiator ? 0 : 1;	/* the peer's ids */
	cbl_stream *s;
	uint64_t credit;
	bool found;
	bool accepted, ended;
	int error;

	if ((h->stream & 1) != parity || h->stream <= conn->peer_stream_id) {
		(void)cbl_req_set_err(req, "bad stream id", NULL, 0, -1);
		return (EPROTO);
	}
	credit = fw_uint(msg, CBL_FW_CREDIT, &found);
	if (!found)
		credit = conn->lim.v[CBL_LIM_STREAM_WINDOW];
	if (credit > INT32_MAX) {
		(void)cbl_req_set_err(req, "credit out of range", NULL, 0, -1);
		return (EPROTO);
	}
	if ((s = stream_alloc(conn)) == NULL)
		return (ENOMEM);
	s->id = h->stream;
	s->family = h->family;
	s->cmd = h->cmd;
	s->open_seq = h->seq;
	s->push = push;
	s->state = CBL_SS_OPENING;
	s->tx_credit = credit;
	s->window = conn->lim.v[CBL_LIM_STREAM_WINDOW];
	pthread_mutex_lock(&conn->mtx);
	conn->peer_stream_id = h->stream;
	if (conn->nstreams >= conn->lim.v[CBL_LIM_MAX_STREAMS]) {
		pthread_mutex_unlock(&conn->mtx);
		cbl_stream_rele(s);
		(void)cbl_req_set_err(req, "too many streams", NULL, 0, -1);
		return (ENOSPC);
	}
	RB_INSERT(cbl_stream_tree, &conn->streams, s);
	conn->nstreams++;
	pthread_mutex_unlock(&conn->mtx);

	error = req->op->stream_open(req, msg, s, req->fam->arg);
	pthread_mutex_lock(&conn->mtx);
	accepted = s->accepted;
	ended = s->ending;
	pthread_mutex_unlock(&conn->mtx);
	if (error == 0 && req->deferred) {
		/*
		 * Accepted (cbl_stream_accept()) or refused later, from
		 * any thread; cbl_req_complete() settles the open.
		 */
		cbl_stream_ref(s);
		req->stream = s;
		return (EINPROGRESS);
	}
	if (error == 0 && !accepted) {
		(void)cbl_req_set_err(req, "stream not accepted", NULL, 0, -1);
		error = ECONNREFUSED;
	}
	if (error != 0 && accepted) {
		/* The handler has callbacks: they see the stream close. */
		if (!ended)
			reset_and_end(s, error, NULL);
	} else if (error != 0) {
		pthread_mutex_lock(&conn->mtx);
		if (stream_find(conn, s->id) == s) {
			RB_REMOVE(cbl_stream_tree, &conn->streams, s);
			conn->nstreams--;
		}
		if (s->ending)
			TAILQ_REMOVE(&conn->ended, s, done_link);
		s->ending = false;
		s->state = CBL_SS_DONE;
		pthread_mutex_unlock(&conn->mtx);
		cbl_stream_rele(s);
	}
	return (error);
}

int
cbl_stream_accept(cbl_stream *s, cbl_msg *accept, uint32_t flags,
    const struct cbl_stream_cbs *cbs, void *arg)
{
	cbl_conn *conn;
	int error;

	if (s == NULL || cbs == NULL || s->local || s->accepted) {
		cbl_msg_free(accept);
		return (EINVAL);
	}
	conn = s->conn;
	if (stream_gone(s)) {
		cbl_msg_free(accept);
		return (EPIPE);
	}
	if (accept == NULL &&
	    (error = cbl_msg_alloc_empty(&conn->lim, &accept)) != 0)
		return (error);
	if (accept->window != 0)
		s->window = accept->window;
	pthread_mutex_lock(&conn->mtx);
	s->cbs = *cbs;
	s->arg = arg;
	s->flags = flags;
	s->accepted = true;
	s->state = CBL_SS_OPEN;
	if (s->push) {
		/* The opener never sends data on a push stream. */
		s->rx_hclosed = true;
		s->rx_window = 0;
	} else
		s->rx_window = s->window;
	pthread_mutex_unlock(&conn->mtx);

	accept->hdr.family = s->family;
	accept->hdr.cmd = s->cmd;
	accept->hdr.flags = CBL_F_S_OPEN;
	accept->hdr.seq = s->open_seq;
	accept->hdr.stream = s->id;
	(void)cbl_msg_put_fw_uint(accept, CBL_FW_CREDIT, s->rx_window);
	if ((error = cbl_conn_enqueue_ctl(conn, accept)) != 0) {
		/*
		 * Not sent, so not accepted: the caller keeps what "arg"
		 * points to, and no callback will run for this stream.
		 */
		pthread_mutex_lock(&conn->mtx);
		memset(&s->cbs, 0, sizeof(s->cbs));
		s->arg = NULL;
		s->accepted = false;
		if (s->state == CBL_SS_OPEN)
			s->state = CBL_SS_OPENING;
		pthread_mutex_unlock(&conn->mtx);
	}
	return (error);
}

int
cbl_stream_msg_new(cbl_stream *s, cbl_msg **msgp)
{
	cbl_msg *msg;
	int error;

	if (s == NULL || msgp == NULL)
		return (EINVAL);
	if ((error = cbl_msg_alloc_empty(&s->conn->lim, &msg)) != 0)
		return (error);
	msg->hdr.family = s->family;
	msg->hdr.cmd = s->cmd;
	msg->hdr.flags = CBL_F_S_DATA;
	msg->hdr.stream = s->id;
	*msgp = msg;
	return (0);
}

/*
 * Send data.  Consumes "msg", except when it returns EAGAIN for lack of
 * credit: then the caller keeps it and waits for on_writable.
 */
int
cbl_stream_send(cbl_stream *s, cbl_msg *msg)
{
	cbl_conn *conn;
	bool last, end = false;
	int error;

	if (s == NULL || msg == NULL) {
		cbl_msg_free(msg);
		return (EINVAL);
	}
	conn = s->conn;
	last = (msg->hdr.flags & CBL_F_S_HCLOSE) != 0;
	msg->hdr.flags = CBL_F_S_DATA | (last ? CBL_F_S_HCLOSE : 0);
	msg->hdr.stream = s->id;
	msg->hdr.family = s->family;
	msg->hdr.cmd = s->cmd;
	if ((error = cbl_msg_encode(msg, NULL, NULL)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	pthread_mutex_lock(&conn->mtx);
	if (s->state != CBL_SS_OPEN || s->tx_hclosed || (s->push && s->local)) {
		pthread_mutex_unlock(&conn->mtx);
		cbl_msg_free(msg);
		return (EPIPE);
	}
	if (msg->len > s->tx_credit) {
		s->blocked = true;
		pthread_mutex_unlock(&conn->mtx);
		return (EAGAIN);
	}
	s->tx_credit -= msg->len;
	if (last) {
		s->tx_hclosed = true;
		end = s->rx_hclosed;
	}
	pthread_mutex_unlock(&conn->mtx);
	error = cbl_conn_enqueue(conn, msg);
	if (end)
		stream_end(s, 0, NULL);
	return (error);
}

size_t
cbl_stream_credit(const cbl_stream *s)
{

	return (s != NULL ? (size_t)s->tx_credit : 0);
}

/* Give credit back for "bytes" of data the application consumed. */
int
cbl_stream_consumed(cbl_stream *s, size_t bytes)
{
	cbl_conn *conn;
	uint64_t grant = 0;

	if (s == NULL)
		return (EINVAL);
	conn = s->conn;
	pthread_mutex_lock(&conn->mtx);
	if (s->state != CBL_SS_OPEN || s->rx_hclosed) {
		pthread_mutex_unlock(&conn->mtx);
		return (0);
	}
	s->rx_unacked += bytes;
	/* Batch grants: return credit once half the window is used. */
	if (s->rx_unacked >= s->window / 2 || s->rx_window == 0) {
		grant = s->rx_unacked;
		s->rx_window += grant;
		s->rx_unacked = 0;
	}
	pthread_mutex_unlock(&conn->mtx);
	if (grant == 0)
		return (0);
	return (send_ctl(conn, s, s->id, CBL_F_S_CREDIT, 0, NULL, grant));
}

int
cbl_stream_half_close(cbl_stream *s)
{
	cbl_conn *conn;
	bool end;
	int error;

	if (s == NULL)
		return (EINVAL);
	conn = s->conn;
	pthread_mutex_lock(&conn->mtx);
	if (s->state != CBL_SS_OPEN || s->tx_hclosed) {
		pthread_mutex_unlock(&conn->mtx);
		return (EPIPE);
	}
	s->tx_hclosed = true;
	end = s->rx_hclosed;
	pthread_mutex_unlock(&conn->mtx);
	error = send_ctl(conn, s, s->id, CBL_F_S_HCLOSE, 0, NULL, 0);
	if (end)
		stream_end(s, 0, NULL);
	return (error);
}

int
cbl_stream_close(cbl_stream *s, int code, const char *text)
{
	cbl_conn *conn;
	cbl_loop *loop;

	if (s == NULL || code < 0)
		return (EINVAL);
	conn = s->conn;
	pthread_mutex_lock(&conn->mtx);
	if (s->state != CBL_SS_OPEN) {
		pthread_mutex_unlock(&conn->mtx);
		return (EPIPE);
	}
	s->state = CBL_SS_CLOSING;
	s->tx_hclosed = true;
	s->deadline = cbl_now_ms() + conn->lim.v[CBL_LIM_STREAM_CLOSE_MS];
	conn->strm_dirty = true;
	pthread_mutex_unlock(&conn->mtx);
	if ((loop = cbl_conn_loop(conn)) != NULL)
		cbl_loop_kick(loop, conn);	/* arm the close deadline */
	return (send_ctl(conn, s, s->id, CBL_F_S_CLOSE, code, text, 0));
}

int
cbl_stream_reset(cbl_stream *s, int code)
{
	cbl_conn *conn;

	if (s == NULL || code < 0)
		return (EINVAL);
	conn = s->conn;
	pthread_mutex_lock(&conn->mtx);
	if (s->state == CBL_SS_DONE || s->ending) {
		pthread_mutex_unlock(&conn->mtx);
		return (EPIPE);
	}
	pthread_mutex_unlock(&conn->mtx);
	reset_and_end(s, code != 0 ? code : ECANCELED, NULL);
	return (0);
}

uint32_t
cbl_stream_id(const cbl_stream *s)
{

	return (s != NULL ? s->id : 0);
}

cbl_conn *
cbl_stream_conn(const cbl_stream *s)
{

	return (s != NULL ? s->conn : NULL);
}

/*
 * cbl_req_complete() of a deferred stream open.  Returns the code of the
 * ERROR|S_OPEN to send (the open is refused: an error, or no accept),
 * or 0.  An accepted stream is reset if the request failed.  Any thread.
 */
int
cbl_stream_settle(cbl_stream *s, int error)
{
	cbl_conn *conn = s->conn;
	bool accepted;

	if (stream_gone(s))
		return (0);	/* reset by the peer, or connection closed */
	pthread_mutex_lock(&conn->mtx);
	accepted = s->accepted;
	pthread_mutex_unlock(&conn->mtx);
	if (accepted) {
		if (error != 0)
			reset_and_end(s, error, NULL);
		return (0);
	}
	if (error == 0)
		error = ECONNREFUSED;
	stream_end(s, error, NULL);	/* no callbacks: never accepted */
	return (error);
}

/*
 * A frame for no live stream (WIRE-FORMAT.md section 8.2).  Ids only grow
 * on each side, so an id at or below the highest opened with its parity
 * belonged to a stream that is closed now: late frames for it are dropped
 * without a word.  A higher id was never opened: it gets an S_RESET, once.
 * The highest id answered is remembered for each side, and nothing at or
 * below it is answered again, so no pattern of ids gets a reset per frame.
 */
static void
stream_unknown(cbl_conn *conn, uint32_t id, uint32_t flags)
{
	bool ours, answer;
	uint32_t highest;

	pthread_mutex_lock(&conn->mtx);
	ours = (id & 1) == (conn->initiator ? 1u : 0u);
	if (ours)
		highest = conn->next_stream_id > 2 ?
		    conn->next_stream_id - 2 : 0;
	else
		highest = conn->peer_stream_id;
	answer = id > highest && id > conn->unknown_reset[id & 1] &&
	    (flags & (CBL_F_S_RESET | CBL_F_ERROR)) == 0;
	if (answer)
		conn->unknown_reset[id & 1] = id;
	pthread_mutex_unlock(&conn->mtx);
	if (answer)
		(void)send_ctl(conn, NULL, id, CBL_F_S_RESET, EPROTO,
		    "unknown stream", 0);
}

/*
 * A stream frame whose body did not decode: the stream it belongs to is
 * reset, since its credit accounting can no longer be trusted.
 */
void
cbl_stream_rx_malformed(cbl_conn *conn, const struct cbl_hdr *h, int error)
{
	cbl_stream *s;

	pthread_mutex_lock(&conn->mtx);
	s = stream_find(conn, h->stream);
	if (s != NULL && (s->ending || s->state == CBL_SS_DONE))
		s = NULL;
	pthread_mutex_unlock(&conn->mtx);
	if (s == NULL)
		stream_unknown(conn, h->stream, h->flags);
	else if ((h->flags & CBL_F_S_RESET) != 0)
		stream_end(s, error, "malformed reset");
	else
		reset_and_end(s, error, "malformed frame");
	cbl_stream_reap(conn);
}

/*
 * One stream frame.  Streams that end here, or in a callback run from
 * here, are finished by the caller once this returns.
 */
static void
stream_rx(cbl_conn *conn, cbl_msg *msg)
{
	uint32_t f = msg->hdr.flags, id = msg->hdr.stream;
	cbl_stream *s;
	uint64_t v;
	bool found, writable = false, end = false, rx_end = false;
	int code;

	pthread_mutex_lock(&conn->mtx);
	s = stream_find(conn, id);
	if (s != NULL && (s->ending || s->state == CBL_SS_DONE))
		s = NULL;
	pthread_mutex_unlock(&conn->mtx);
	if (s == NULL) {
		stream_unknown(conn, id, f);
		cbl_msg_free(msg);
		return;
	}
	if (s->family != msg->hdr.family || s->cmd != msg->hdr.cmd) {
		reset_and_end(s, EPROTO, "family/command mismatch");
		cbl_msg_free(msg);
		return;
	}

	if ((f & CBL_F_ERROR) != 0) {
		/* The open was rejected. */
		code = cbl_msg_err_code(msg);
		if (s->local && s->state == CBL_SS_OPENING) {
			if (s->cbs.on_open != NULL)
				s->cbs.on_open(s, msg, code, s->arg);
			stream_finish(s, code, cbl_msg_err_str(msg));
		}
		cbl_msg_free(msg);
		return;
	}
	if ((f & CBL_F_S_RESET) != 0) {
		code = msg->err_code != 0 ? msg->err_code :
		    (int)fw_uint(msg, CBL_FW_CODE, &found);
		stream_finish(s, code != 0 ? code : ECONNRESET,
		    cbl_msg_err_str(msg));
		cbl_msg_free(msg);
		return;
	}
	if ((f & CBL_F_S_CLOSE) != 0) {
		code = (int)fw_uint(msg, CBL_FW_CODE, &found);
		if (s->state != CBL_SS_CLOSING)
			(void)send_ctl(conn, s, s->id, CBL_F_S_CLOSE, 0,
			    NULL, 0);
		stream_finish(s, code, cbl_msg_err_str(msg));
		cbl_msg_free(msg);
		return;
	}
	if ((f & CBL_F_S_CREDIT) != 0) {
		v = fw_uint(msg, CBL_FW_CREDIT, &found);
		pthread_mutex_lock(&conn->mtx);
		if (found)
			s->tx_credit += v;
		if (!found || s->tx_credit > INT32_MAX) {
			pthread_mutex_unlock(&conn->mtx);
			reset_and_end(s, EPROTO, "bad credit");
			cbl_msg_free(msg);
			return;
		}
		if (s->blocked && s->state == CBL_SS_OPEN) {
			s->blocked = false;
			writable = true;
		}
		v = s->tx_credit;
		pthread_mutex_unlock(&conn->mtx);
		if (writable && s->cbs.on_writable != NULL)
			s->cbs.on_writable(s, (size_t)v, s->arg);
		cbl_msg_free(msg);
		return;
	}
	if ((f & CBL_F_S_OPEN) != 0) {
		/* Our open was accepted. */
		if (!s->local || s->state != CBL_SS_OPENING) {
			reset_and_end(s, EPROTO, "unexpected accept");
			cbl_msg_free(msg);
			return;
		}
		if (msg->hdr.seq != s->open_seq) {
			if (s->cbs.on_open != NULL)
				s->cbs.on_open(s, NULL, EPROTO, s->arg);
			if (!stream_gone(s))
				reset_and_end(s, EPROTO,
				    "accept does not match the open");
			cbl_msg_free(msg);
			return;
		}
		v = fw_uint(msg, CBL_FW_CREDIT, &found);
		if (!found)
			v = conn->lim.v[CBL_LIM_STREAM_WINDOW];
		if (v > INT32_MAX) {
			reset_and_end(s, EPROTO, "credit out of range");
			cbl_msg_free(msg);
			return;
		}
		pthread_mutex_lock(&conn->mtx);
		s->tx_credit = v;
		s->state = CBL_SS_OPEN;
		s->deadline = 0;
		conn->strm_dirty = true;
		if (s->push)
			s->tx_hclosed = true;
		pthread_mutex_unlock(&conn->mtx);
		if (s->cbs.on_open != NULL)
			s->cbs.on_open(s, msg, 0, s->arg);
		if ((f & (CBL_F_S_DATA | CBL_F_S_HCLOSE)) == 0 ||
		    stream_gone(s)) {
			cbl_msg_free(msg);
			return;
		}
	}
	/* Data and/or half-close. */
	pthread_mutex_lock(&conn->mtx);
	if (s->state != CBL_SS_OPEN && s->state != CBL_SS_CLOSING) {
		pthread_mutex_unlock(&conn->mtx);
		reset_and_end(s, EPROTO, "stream not open");
		cbl_msg_free(msg);
		return;
	}
	if ((f & CBL_F_S_DATA) != 0) {
		if (s->rx_hclosed) {
			pthread_mutex_unlock(&conn->mtx);
			reset_and_end(s, EPROTO, "data after half-close");
			cbl_msg_free(msg);
			return;
		}
		if (msg->len > s->rx_window) {
			pthread_mutex_unlock(&conn->mtx);
			reset_and_end(s, ENOBUFS,
			    "flow-control window exceeded");
			cbl_msg_free(msg);
			return;
		}
		s->rx_window -= msg->len;
	}
	if ((f & CBL_F_S_HCLOSE) != 0) {
		s->rx_hclosed = true;
		rx_end = true;
		end = s->tx_hclosed && s->state == CBL_SS_OPEN;
	}
	pthread_mutex_unlock(&conn->mtx);
	if ((f & CBL_F_S_DATA) != 0) {
		size_t len = msg->len;

		if (s->cbs.on_data != NULL)
			s->cbs.on_data(s, msg, s->arg);
		if (stream_gone(s)) {
			cbl_msg_free(msg);
			return;
		}
		if ((s->flags & CBL_SF_MANUAL_CREDIT) == 0 && !rx_end)
			(void)cbl_stream_consumed(s, len);
	}
	cbl_msg_free(msg);
	if (rx_end && s->cbs.on_hclose != NULL) {
		s->cbs.on_hclose(s, s->arg);
		if (stream_gone(s))
			return;
	}
	if (end)
		stream_end(s, 0, NULL);
}

/* Receive side: a stream frame from the peer (I/O thread). */
void
cbl_stream_rx(cbl_conn *conn, cbl_msg *msg)
{

	stream_rx(conn, msg);
	cbl_stream_reap(conn);
}

/*
 * Nearest open or close deadline of a live stream, or 0.  Cached: the
 * streams are walked only after one was added or ended, or had its
 * deadline set or cleared.
 */
uint64_t
cbl_stream_next_deadline(cbl_conn *conn)
{
	cbl_stream *s;
	uint64_t next;

	pthread_mutex_lock(&conn->mtx);
	if (conn->strm_dirty) {
		next = 0;
		RB_FOREACH(s, cbl_stream_tree, &conn->streams)
			if (s->deadline != 0 && !s->ending &&
			    (next == 0 || s->deadline < next))
				next = s->deadline;
		conn->strm_next = next;
		conn->strm_dirty = false;
	}
	next = conn->strm_next;
	pthread_mutex_unlock(&conn->mtx);
	return (next);
}

/* Fail streams whose open or close timed out; nearest deadline or 0. */
uint64_t
cbl_stream_expire(cbl_conn *conn, uint64_t now)
{
	cbl_stream *s, *hit;
	uint64_t next;

	for (;;) {
		hit = NULL;
		next = 0;
		pthread_mutex_lock(&conn->mtx);
		RB_FOREACH(s, cbl_stream_tree, &conn->streams) {
			if (s->deadline == 0 || s->ending)
				continue;
			if (now != 0 && s->deadline <= now) {
				hit = s;
				break;
			}
			if (next == 0 || s->deadline < next)
				next = s->deadline;
		}
		pthread_mutex_unlock(&conn->mtx);
		if (hit == NULL) {
			if (now != 0)
				cbl_stream_reap(conn);
			return (next);
		}
		if (hit->state == CBL_SS_OPENING && hit->cbs.on_open != NULL)
			hit->cbs.on_open(hit, NULL, ETIMEDOUT, hit->arg);
		if (hit->state == CBL_SS_CLOSING)
			(void)send_ctl(conn, hit, hit->id, CBL_F_S_RESET,
			    ETIMEDOUT, "close timed out", 0);
		stream_finish(hit, ETIMEDOUT, "timed out");
	}
}

/* The connection is gone: every stream ends with "error". */
void
cbl_stream_conn_closed(cbl_conn *conn, int error)
{
	cbl_stream *s;

	cbl_stream_reap(conn);
	for (;;) {
		pthread_mutex_lock(&conn->mtx);
		s = RB_MIN(cbl_stream_tree, &conn->streams);
		pthread_mutex_unlock(&conn->mtx);
		if (s == NULL)
			return;
		if (s->local && s->state == CBL_SS_OPENING &&
		    s->cbs.on_open != NULL)
			s->cbs.on_open(s, NULL, error, s->arg);
		stream_finish(s, error, "connection closed");
	}
}

/*
 * Window to advertise for the stream this open or accept message starts
 * (0: the CBL_LIM_STREAM_WINDOW default).  Generated code uses it for a
 * spec's "initial-credit".
 */
int
cbl_msg_set_window(cbl_msg *msg, uint32_t window)
{

	if (msg == NULL || window > INT32_MAX)
		return (EINVAL);
	msg->window = window;
	return (0);
}
