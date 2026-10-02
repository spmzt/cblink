/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Client-side dump iterator.  Parts are queued by the connection's I/O
 * thread and handed out one at a time.  The queue is bounded by
 * sendq_bytes: when it is full, the connection stops reading until the
 * consumer has taken half of it, so a slow consumer slows the peer down
 * instead of losing the dump.
 */

#include <errno.h>
#include <stdlib.h>

#include "cbl_impl.h"

struct dump_item {
	STAILQ_ENTRY(dump_item)	 link;
	cbl_msg			*msg;
};

struct cbl_dump {
	cbl_conn			*conn;
	atomic_uint			 refs;	/* iterator + pending request */
	STAILQ_HEAD(, dump_item)	 q;
	size_t				 qbytes;
	bool				 done;
	bool				 overflow;
	bool				 held;	/* the connection's reading */
	int				 error;
	cbl_msg				*errmsg;
	cbl_msg				*cur;
};

static void
dump_rele(cbl_dump *d)
{
	struct dump_item *it;

	if (atomic_fetch_sub(&d->refs, 1) != 1)
		return;
	if (d->held)
		cbl_conn_rx_hold(d->conn, false);
	while ((it = STAILQ_FIRST(&d->q)) != NULL) {
		STAILQ_REMOVE_HEAD(&d->q, link);
		cbl_msg_free(it->msg);
		free(it);
	}
	cbl_msg_free(d->cur);
	cbl_msg_free(d->errmsg);
	cbl_conn_rele(d->conn);
	free(d);
}

/* Runs on the connection's I/O thread. */
static void
dump_cb(cbl_conn *conn, cbl_msg *msg, bool final, int error, void *arg)
{
	cbl_dump *d = arg;
	struct dump_item *it;
	bool hold = false, release = false;

	pthread_mutex_lock(&conn->mtx);
	if (final) {
		d->done = true;
		if (d->held) {
			d->held = false;
			release = true;
		}
		if (d->error == 0)
			d->error = error;
		if (msg != NULL && (msg->hdr.flags & CBL_F_ERROR) != 0 &&
		    d->errmsg == NULL && cbl_msg_ref(msg) == 0)
			d->errmsg = msg;
	} else if (!d->overflow && msg != NULL) {
		if ((it = malloc(sizeof(*it))) != NULL &&
		    cbl_msg_ref(msg) == 0) {
			it->msg = msg;
			STAILQ_INSERT_TAIL(&d->q, it, link);
			d->qbytes += msg->len;
			if (!d->held && d->qbytes >=
			    conn->lim.v[CBL_LIM_SENDQ_BYTES]) {
				d->held = true;
				hold = true;
			}
		} else {
			free(it);
			d->overflow = true;
			d->error = ENOMEM;
		}
	}
	pthread_cond_broadcast(&conn->cv);
	pthread_mutex_unlock(&conn->mtx);
	if (hold || release)
		cbl_conn_rx_hold(conn, hold);
	if (final)
		dump_rele(d);
}

int
cbl_dump_start(cbl_conn *conn, cbl_msg *req, cbl_dump **dp)
{
	cbl_dump *d;
	int error;

	if (conn == NULL || req == NULL || dp == NULL) {
		cbl_msg_free(req);
		return (EINVAL);
	}
	if ((d = calloc(1, sizeof(*d))) == NULL) {
		cbl_msg_free(req);
		return (ENOMEM);
	}
	cbl_conn_ref(conn);
	d->conn = conn;
	STAILQ_INIT(&d->q);
	atomic_init(&d->refs, 2);
	req->hdr.flags |= CBL_F_DUMP;
	if ((error = cbl_request_async(conn, req, dump_cb, d)) != 0) {
		atomic_store(&d->refs, 1);
		dump_rele(d);
		return (error);
	}
	*dp = d;
	return (0);
}

static bool
dump_ready(void *arg)
{
	cbl_dump *d = arg;

	return (!STAILQ_EMPTY(&d->q) || d->done || d->overflow);
}

/*
 * Next part, or *itemp == NULL at the end; the return value is the dump's
 * error.  The item stays valid until the next call or cbl_dump_free().
 */
int
cbl_dump_next(cbl_dump *d, cbl_msg **itemp)
{
	struct dump_item *it;
	bool release;
	int error;

	if (d == NULL || itemp == NULL)
		return (EINVAL);
	*itemp = NULL;
	cbl_msg_free(d->cur);
	d->cur = NULL;
	if ((error = cbl_conn_wait(d->conn, dump_ready, d)) != 0)
		return (error);
	pthread_mutex_lock(&d->conn->mtx);
	if (d->overflow) {
		error = d->error;
		pthread_mutex_unlock(&d->conn->mtx);
		return (error);
	}
	if ((it = STAILQ_FIRST(&d->q)) != NULL) {
		STAILQ_REMOVE_HEAD(&d->q, link);
		d->qbytes -= it->msg->len;
		d->cur = it->msg;
		free(it);
		*itemp = d->cur;
		/* Half the queue is free: read again. */
		release = d->held &&
		    d->qbytes <= d->conn->lim.v[CBL_LIM_SENDQ_BYTES] / 2;
		if (release)
			d->held = false;
		pthread_mutex_unlock(&d->conn->mtx);
		if (release)
			cbl_conn_rx_hold(d->conn, false);
		return (0);
	}
	error = d->done ? d->error : (d->conn->error != 0 ?
	    d->conn->error : ECONNRESET);
	pthread_mutex_unlock(&d->conn->mtx);
	return (error);
}

const cbl_msg *
cbl_dump_error(const cbl_dump *d)
{

	return (d != NULL ? d->errmsg : NULL);
}

void
cbl_dump_free(cbl_dump *d)
{

	if (d != NULL)
		dump_rele(d);
}
