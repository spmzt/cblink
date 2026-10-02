/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Dispatch of incoming requests to family handlers, and the server-side
 * request context (cbl_req).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"

#define	CBL_DUMP_BUDGET	64	/* parts per turn */

/* Send an ERROR frame with full extended-ack details. */
static int
send_error_ext(cbl_conn *conn, const struct cbl_hdr *h, int code,
    const char *text, const struct cbl_path_elem *path, size_t pathlen,
    int miss, const void *cookie, size_t cookie_len, uint32_t extra)
{
	cbl_msg *msg;
	int error;

	if ((error = cbl_msg_alloc_empty(&conn->lim, &msg)) != 0)
		return (error);
	msg->hdr.family = h->family;
	msg->hdr.cmd = h->cmd;
	msg->hdr.flags = CBL_F_ERROR | extra;
	msg->hdr.seq = h->seq;
	if ((extra & CBL_F_S_OPEN) != 0)
		msg->hdr.stream = h->stream;
	(void)cbl_msg_put_error(msg, code, text, path,
	    pathlen > CBL_PATH_MAX ? CBL_PATH_MAX : pathlen, miss);
	if (cookie != NULL)
		(void)cbl_msg_put_cookie(msg, cookie, cookie_len);
	return (cbl_conn_enqueue_ctl(conn, msg));
}

static void
reject(cbl_conn *conn, cbl_msg *msg, int code, const char *text)
{

	(void)cbl_conn_send_error(conn, &msg->hdr, code, text);
	cbl_msg_free(msg);
}

static void
req_free(cbl_req *req)
{
	cbl_conn *conn = req->conn;

	if (req->dump.priv_free != NULL)
		req->dump.priv_free(req->dump.priv);
	free(req->err_msg);
	cbl_msg_free(req->msg);
	cbl_family_rele(req->fam);
	atomic_fetch_sub(&conn->inflight, 1);
	free(req);
	cbl_conn_rele(conn);
}

static void
req_rele(cbl_req *req)
{

	if (atomic_fetch_sub(&req->refs, 1) == 1)
		req_free(req);
}

/*
 * Send the terminal frame of a request, once: false if it was sent
 * already.  The caller then drops its reference.
 */
static bool
req_end(cbl_req *req, int error)
{
	bool dump = (req->hdr.flags & CBL_F_DUMP) != 0;
	cbl_conn *conn = req->conn;
	cbl_stream *s;
	cbl_msg *msg;
	int code;

	if (atomic_exchange(&req->completed, true))
		return (false);
	pthread_mutex_lock(&conn->mtx);
	if (req->on_deferred) {
		TAILQ_REMOVE(&conn->deferred, req, defer_link);
		req->on_deferred = false;
	}
	pthread_mutex_unlock(&conn->mtx);
	if ((s = req->stream) != NULL) {
		/* A deferred stream open: the accept frame was its answer. */
		req->stream = NULL;
		if ((code = cbl_stream_settle(s, error)) != 0)
			(void)send_error_ext(conn, &req->hdr, code,
			    req->err_msg != NULL ? req->err_msg :
			    "stream not accepted", req->err_path,
			    req->err_pathlen, req->err_miss, NULL, 0,
			    CBL_F_S_OPEN);
		cbl_stream_rele(s);
		return (true);
	}
	if (error != 0) {
		(void)send_error_ext(req->conn, &req->hdr, error, req->err_msg,
		    req->err_path, req->err_pathlen, req->err_miss,
		    req->has_cookie ? req->cookie : NULL, req->cookie_len,
		    dump ? CBL_F_MULTI | CBL_F_DONE : 0);
	} else if (dump || (req->hdr.flags & CBL_F_ACK) != 0) {
		if (cbl_msg_alloc_empty(&req->conn->lim, &msg) == 0) {
			msg->hdr.family = req->hdr.family;
			msg->hdr.cmd = req->hdr.cmd;
			msg->hdr.seq = req->hdr.seq;
			msg->hdr.flags = dump ? CBL_F_MULTI | CBL_F_DONE :
			    CBL_F_ACK;
			if (req->err_msg != NULL)
				(void)cbl_msg_put_error(msg, 0, req->err_msg,
				    NULL, 0, -1);
			if (req->has_cookie)
				(void)cbl_msg_put_cookie(msg, req->cookie,
				    req->cookie_len);
			(void)cbl_conn_enqueue_ctl(req->conn, msg);
		}
	}
	return (true);
}

/* End a request on behalf of the reference the caller holds. */
static void
req_finish(cbl_req *req, int error)
{

	(void)req_end(req, error);
	req_rele(req);
}

/* Is the send queue too full to produce more dump output? */
static bool
dump_throttled(cbl_conn *conn)
{
	bool full;

	pthread_mutex_lock(&conn->mtx);
	full = conn->txq_bytes >= conn->lim.v[CBL_LIM_SENDQ_BYTES] / 2;
	pthread_mutex_unlock(&conn->mtx);
	return (full);
}

/*
 * Run a dump for at most CBL_DUMP_BUDGET parts: until it finishes, fails,
 * fills the send queue (resumed after a flush), or uses up its turn, so
 * that one large dump to a fast reader does not starve the loop's other
 * connections.  Both of the last two wait on conn->dumps for
 * cbl_server_resume().
 */
static void
dump_step(cbl_req *req)
{
	cbl_conn *conn = req->conn;
	cbl_loop *loop;
	int error;

	for (int n = 0;; n++) {
		if (conn->state != CBL_CS_OPEN) {
			req_finish(req, ECONNRESET);
			return;
		}
		if (dump_throttled(conn)) {
			TAILQ_INSERT_TAIL(&conn->dumps, req, dump_link);
			return;
		}
		if (n == CBL_DUMP_BUDGET) {
			TAILQ_INSERT_TAIL(&conn->dumps, req, dump_link);
			if ((loop = cbl_conn_loop(conn)) != NULL)
				cbl_loop_kick(loop, conn);
			return;
		}
		error = req->op->dumpit(req, req->msg, &req->dump,
		    req->fam->arg);
		if (error != EAGAIN) {
			req_finish(req, error);
			return;
		}
	}
}

/*
 * Called by the connection core: give each waiting dump a turn, if the
 * send queue has room.  Dumps that use up their turn queue up again, for
 * the next call.
 */
void
cbl_server_resume(cbl_conn *conn)
{
	TAILQ_HEAD(, cbl_req) turn;
	cbl_req *req;

	TAILQ_INIT(&turn);
	TAILQ_CONCAT(&turn, &conn->dumps, dump_link);
	while ((req = TAILQ_FIRST(&turn)) != NULL) {
		TAILQ_REMOVE(&turn, req, dump_link);
		if (dump_throttled(conn))
			TAILQ_INSERT_TAIL(&conn->dumps, req, dump_link);
		else
			dump_step(req);
	}
}

/* Is a dump ready for another turn (cbl_conn_interest())? */
bool
cbl_server_dump_ready(cbl_conn *conn)
{

	return (!TAILQ_EMPTY(&conn->dumps) && !dump_throttled(conn));
}

/* The connection is going away: abandon unfinished dumps. */
void
cbl_server_abort(cbl_conn *conn)
{
	void (*fn)(cbl_req *, void *);
	cbl_req *req;

	while ((req = TAILQ_FIRST(&conn->dumps)) != NULL) {
		TAILQ_REMOVE(&conn->dumps, req, dump_link);
		atomic_store(&req->completed, true);
		req_rele(req);
	}
	/*
	 * Deferred requests can no longer be answered: say so, so the work
	 * for them can stop.  They are still finished by cbl_req_complete().
	 */
	for (;;) {
		pthread_mutex_lock(&conn->mtx);
		if ((req = TAILQ_FIRST(&conn->deferred)) != NULL) {
			TAILQ_REMOVE(&conn->deferred, req, defer_link);
			req->on_deferred = false;
			atomic_fetch_add(&req->refs, 1);
			atomic_store(&req->cancelled, true);
			fn = req->cancel_fn;
		}
		pthread_mutex_unlock(&conn->mtx);
		if (req == NULL)
			return;
		if (fn != NULL)
			fn(req, req->cancel_arg);
		req_rele(req);
	}
}

void
cbl_server_dispatch(cbl_conn *conn, cbl_msg *msg)
{
	const struct cbl_op *op;
	struct cbl_verr verr;
	cbl_family *fam;
	cbl_req *req;
	uint32_t f = msg->hdr.flags;
	char text[96];
	int error;

	if ((fam = cbl_family_lookup(conn->ctx, msg->hdr.family)) == NULL) {
		snprintf(text, sizeof(text), "unknown family %u",
		    msg->hdr.family);
		reject(conn, msg, ENOENT, text);
		return;
	}
	op = cbl_family_op(fam, msg->hdr.cmd);
	if (op == NULL) {
		cbl_family_rele(fam);
		reject(conn, msg, EOPNOTSUPP, "unknown command");
		return;
	}
	if ((f & CBL_F_S_OPEN) != 0) {
		if ((op->flags & (CBL_OPF_STREAM | CBL_OPF_PUSH)) == 0) {
			cbl_family_rele(fam);
			reject(conn, msg, EOPNOTSUPP,
			    "command does not open a stream");
			return;
		}
	} else if ((f & CBL_F_DUMP) != 0) {
		if ((op->flags & CBL_OPF_DUMP) == 0) {
			cbl_family_rele(fam);
			reject(conn, msg, EOPNOTSUPP, "dump not supported");
			return;
		}
	} else if ((op->flags & CBL_OPF_DO) == 0) {
		cbl_family_rele(fam);
		reject(conn, msg, EOPNOTSUPP, (op->flags & CBL_OPF_DUMP) != 0 ?
		    "command supports dump only" : "command opens a stream");
		return;
	}
	if ((op->flags & CBL_OPF_AUTH) != 0 &&
	    (conn->peer.flags & CBL_PEER_AUTHENTICATED) == 0) {
		cbl_family_rele(fam);
		reject(conn, msg, EACCES, "authenticated peer required");
		return;
	}
	if (atomic_load(&conn->inflight) >= conn->lim.v[CBL_LIM_MAX_INFLIGHT]) {
		cbl_family_rele(fam);
		reject(conn, msg, EAGAIN, "too many requests in flight");
		return;
	}
	if ((error = cbl_validate(cbl_msg_body(msg), op->policy,
	    &verr)) != 0) {
		(void)send_error_ext(conn, &msg->hdr, error, verr.msg,
		    verr.path, verr.pathlen, verr.miss_type, NULL, 0,
		    (f & CBL_F_S_OPEN) != 0 ? CBL_F_S_OPEN :
		    (f & CBL_F_DUMP) != 0 ? CBL_F_MULTI | CBL_F_DONE : 0);
		cbl_family_rele(fam);
		cbl_msg_free(msg);
		return;
	}
	if ((req = calloc(1, sizeof(*req))) == NULL) {
		cbl_family_rele(fam);
		reject(conn, msg, ENOMEM, "out of memory");
		return;
	}
	cbl_conn_ref(conn);
	atomic_fetch_add(&conn->inflight, 1);
	atomic_init(&req->refs, 1);
	req->conn = conn;
	req->fam = fam;
	req->op = op;
	req->msg = msg;
	req->hdr = msg->hdr;
	req->err_miss = -1;

	if ((f & CBL_F_S_OPEN) != 0) {
		cbl_server_stream_open(req);
		return;
	}
	if ((f & CBL_F_DUMP) != 0) {
		dump_step(req);
		return;
	}
	/*
	 * Our reference keeps "req" valid however soon a deferred request is
	 * completed by another thread.
	 */
	error = op->doit(req, msg, fam->arg);
	if (!req->deferred)
		(void)req_end(req, error);
	req_rele(req);
}

int
cbl_req_reply_new(cbl_req *req, uint16_t cmd, cbl_msg **msgp)
{
	cbl_msg *msg;
	int error;

	if (req == NULL || msgp == NULL)
		return (EINVAL);
	if ((error = cbl_msg_alloc_empty(&req->conn->lim, &msg)) != 0)
		return (error);
	msg->hdr.family = req->hdr.family;
	msg->hdr.cmd = cmd != 0 ? cmd : req->hdr.cmd;
	msg->hdr.seq = req->hdr.seq;
	msg->hdr.flags = (req->hdr.flags & CBL_F_DUMP) != 0 ? CBL_F_MULTI : 0;
	*msgp = msg;
	return (0);
}

int
cbl_req_send(cbl_req *req, cbl_msg *msg)
{

	if (req == NULL || msg == NULL || atomic_load(&req->completed)) {
		cbl_msg_free(msg);
		return (EINVAL);
	}
	msg->hdr.seq = req->hdr.seq;
	msg->hdr.family = req->hdr.family;
	return (cbl_conn_enqueue(req->conn, msg));
}

int
cbl_req_set_err(cbl_req *req, const char *text,
    const struct cbl_path_elem *path, size_t pathlen, int miss_type)
{

	if (req == NULL || pathlen > CBL_PATH_MAX ||
	    (path == NULL && pathlen != 0))
		return (EINVAL);
	free(req->err_msg);
	req->err_msg = NULL;
	if (text != NULL && (req->err_msg = strdup(text)) == NULL)
		return (ENOMEM);
	if (pathlen > 0)
		memcpy(req->err_path, path, pathlen * sizeof(*path));
	req->err_pathlen = pathlen;
	req->err_miss = miss_type;
	return (0);
}

int
cbl_req_set_cookie(cbl_req *req, const void *p, size_t len)
{

	if (req == NULL || len > CBL_COOKIE_MAX || (p == NULL && len != 0))
		return (EINVAL);
	if (len != 0)
		memcpy(req->cookie, p, len);
	req->cookie_len = len;
	req->has_cookie = true;
	return (0);
}

int
cbl_req_defer(cbl_req *req)
{

	if (req == NULL || (req->hdr.flags & CBL_F_DUMP) != 0)
		return (EINVAL);
	if (!req->deferred) {
		req->deferred = true;
		/* A reference for cbl_req_complete(). */
		atomic_fetch_add(&req->refs, 1);
		pthread_mutex_lock(&req->conn->mtx);
		TAILQ_INSERT_TAIL(&req->conn->deferred, req, defer_link);
		req->on_deferred = true;
		pthread_mutex_unlock(&req->conn->mtx);
	}
	return (0);
}

/*
 * Called on the I/O thread when the connection of a deferred request goes
 * away, before or while the work for it runs; cbl_req_complete() is still
 * needed to release it.
 */
int
cbl_req_set_cancel(cbl_req *req, void (*fn)(cbl_req *, void *), void *arg)
{

	if (req == NULL)
		return (EINVAL);
	pthread_mutex_lock(&req->conn->mtx);
	req->cancel_fn = fn;
	req->cancel_arg = arg;
	pthread_mutex_unlock(&req->conn->mtx);
	return (0);
}

/* Has the request's connection gone away?  Any thread. */
bool
cbl_req_cancelled(const cbl_req *req)
{

	return (req != NULL && atomic_load(&req->cancelled));
}

/* Finish a deferred request; may be called from any thread. */
int
cbl_req_complete(cbl_req *req, int error)
{

	if (req == NULL || !req->deferred || !req_end(req, error))
		return (EINVAL);
	req_rele(req);
	return (0);
}

const cbl_peer *
cbl_req_peer(const cbl_req *req)
{

	return (req != NULL ? &req->conn->peer : NULL);
}

cbl_conn *
cbl_req_conn(const cbl_req *req)
{

	return (req != NULL ? req->conn : NULL);
}

cbl_ctx *
cbl_req_ctx(const cbl_req *req)
{

	return (req != NULL ? req->conn->ctx : NULL);
}

/* Builder for one dump part. */
int
cbl_req_dump_item(cbl_req *req, cbl_msg **msgp)
{

	if (req == NULL || (req->hdr.flags & CBL_F_DUMP) == 0)
		return (EINVAL);
	return (cbl_req_reply_new(req, 0, msgp));
}

/*
 * A stream open passed the checks.  The accept frame (sent by
 * cbl_stream_accept()) is the response; a refusal is an ERROR|S_OPEN.
 */
void
cbl_server_stream_open(cbl_req *req)
{
	int error;

	error = cbl_stream_server_open(req, req->conn, req->msg,
	    (req->op->flags & CBL_OPF_PUSH) != 0);
	if (error == EINPROGRESS) {
		/* Deferred: cbl_req_complete() settles it. */
		req_rele(req);
		return;
	}
	if (error != 0)
		(void)send_error_ext(req->conn, &req->hdr, error, req->err_msg,
		    req->err_path, req->err_pathlen, req->err_miss, NULL, 0,
		    CBL_F_S_OPEN);
	atomic_store(&req->completed, true);
	req_rele(req);
}

/* The request message, writable so parsers can use its arena. */
cbl_msg *
cbl_req_msg(const cbl_req *req)
{

	return (req != NULL ? req->msg : NULL);
}
