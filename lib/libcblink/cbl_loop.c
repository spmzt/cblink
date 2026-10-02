/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Built-in kqueue(2) event loop.  One thread runs a loop at a time.
 * Other threads talk to it through cbl_loop_post()/cbl_loop_kick(),
 * which queue work and trigger an EVFILT_USER event.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cbl_impl.h"

#define	CBL_LOOP_NEV	64
#define	CBL_USER_IDENT	0

uint64_t
cbl_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

int
cbl_loop_new(cbl_ctx *ctx, cbl_loop **loopp)
{
	struct kevent kev;
	cbl_loop *loop;
	int error;

	if (ctx == NULL || loopp == NULL)
		return (EINVAL);
	if ((loop = calloc(1, sizeof(*loop))) == NULL)
		return (ENOMEM);
	loop->ctx = ctx;
	STAILQ_INIT(&loop->posts);
	LIST_INIT(&loop->conns);
	LIST_INIT(&loop->timers);
	LIST_INIT(&loop->sigs);
	TAILQ_INIT(&loop->dead);
	if ((error = pthread_mutex_init(&loop->mtx, NULL)) != 0) {
		free(loop);
		return (error);
	}
	loop->kq = kqueuex(KQUEUE_CLOEXEC);
	if (loop->kq == -1) {
		error = errno;
		pthread_mutex_destroy(&loop->mtx);
		free(loop);
		return (error);
	}
	EV_SET(&kev, CBL_USER_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0,
	    NULL);
	if (kevent(loop->kq, &kev, 1, NULL, 0, NULL) == -1) {
		error = errno;
		close(loop->kq);
		pthread_mutex_destroy(&loop->mtx);
		free(loop);
		return (error);
	}
	atomic_fetch_add(&ctx->nobjs, 1);
	*loopp = loop;
	return (0);
}

static void
loop_trigger(cbl_loop *loop)
{
	struct kevent kev;

	EV_SET(&kev, CBL_USER_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	(void)kevent(loop->kq, &kev, 1, NULL, 0, NULL);
}

bool
cbl_loop_on_thread(const cbl_loop *loop)
{

	return (loop != NULL && atomic_load(&loop->running) &&
	    atomic_load(&loop->thread) == (uintptr_t)pthread_self());
}

int
cbl_loop_post(cbl_loop *loop, void (*fn)(void *), void *arg)
{
	struct cbl_post *p;

	if (loop == NULL || fn == NULL)
		return (EINVAL);
	if ((p = malloc(sizeof(*p))) == NULL)
		return (ENOMEM);
	p->fn = fn;
	p->arg = arg;
	pthread_mutex_lock(&loop->mtx);
	STAILQ_INSERT_TAIL(&loop->posts, p, link);
	pthread_mutex_unlock(&loop->mtx);
	loop_trigger(loop);
	return (0);
}

static void
loop_kick_cb(void *arg)
{
	cbl_conn *conn = arg;

	pthread_mutex_lock(&conn->loop->mtx);
	conn->kicked = false;
	pthread_mutex_unlock(&conn->loop->mtx);
	if (!conn->dead) {
		(void)cbl_conn_process(conn, 0);
		if (!conn->dead)
			cbl_loop_update(conn->loop, conn);
	}
	cbl_conn_rele(conn);
}

/*
 * Ask the loop thread to service "conn" (send queue changed, a deadline
 * moved, a stream ended).  From any thread, the loop thread included: a
 * kick there runs once the current batch of events is done.
 */
void
cbl_loop_kick(cbl_loop *loop, cbl_conn *conn)
{

	pthread_mutex_lock(&loop->mtx);
	if (conn->kicked || conn->dead) {
		pthread_mutex_unlock(&loop->mtx);
		return;
	}
	conn->kicked = true;
	pthread_mutex_unlock(&loop->mtx);
	cbl_conn_ref(conn);
	if (cbl_loop_post(loop, loop_kick_cb, conn) != 0) {
		pthread_mutex_lock(&loop->mtx);
		conn->kicked = false;
		pthread_mutex_unlock(&loop->mtx);
		cbl_conn_rele(conn);
	}
}

/*
 * Is the caller the thread doing this connection's I/O?  Yes when it has
 * no (live) loop, when it is the loop thread, and when the loop is not
 * running at all.
 */
bool
cbl_conn_io_thread(const cbl_conn *conn)
{
	cbl_loop *loop = cbl_conn_loop(conn);

	return (loop == NULL || cbl_loop_on_thread(loop) ||
	    !atomic_load(&loop->running));
}

int
cbl_loop_stop(cbl_loop *loop)
{

	if (loop == NULL)
		return (EINVAL);
	atomic_store(&loop->stop, true);
	loop_trigger(loop);
	return (0);
}

int
cbl_loop_fd(const cbl_loop *loop)
{

	return (loop != NULL ? loop->kq : -1);
}

/*
 * Bring the kqueue registration of "conn" in line with what it wants:
 * read/write filters on its descriptor and a one-shot timer for its
 * nearest deadline.
 */
void
cbl_loop_update(cbl_loop *loop, cbl_conn *conn)
{
	struct kevent kev[3];
	uint64_t next, now;
	int events, n = 0;

	if (conn->dead || conn->fd == -1)
		return;
	next = cbl_conn_wants(conn, &events);
	if ((events & CBL_EV_READ) != (conn->kq_events & CBL_EV_READ)) {
		EV_SET(&kev[n++], conn->fd, EVFILT_READ,
		    (events & CBL_EV_READ) != 0 ? EV_ADD | EV_ENABLE :
		    EV_ADD | EV_DISABLE, 0, 0, &conn->src);
	}
	if ((events & CBL_EV_WRITE) != (conn->kq_events & CBL_EV_WRITE)) {
		EV_SET(&kev[n++], conn->fd, EVFILT_WRITE,
		    (events & CBL_EV_WRITE) != 0 ? EV_ADD | EV_ENABLE :
		    EV_ADD | EV_DISABLE, 0, 0, &conn->src);
	}
	conn->kq_events = events;
	/*
	 * The timer is armed for an absolute deadline, and re-armed only for
	 * an earlier one: deadlines that move later (the idle timer, with
	 * every frame) or go away cost no kevent().  A timer that fires too
	 * early finds nothing due, and the next update arms it again.
	 */
	if (next != 0 && (conn->kq_deadline == 0 || next < conn->kq_deadline)) {
		now = cbl_now_ms();
		EV_SET(&kev[n++], (uintptr_t)conn, EVFILT_TIMER,
		    EV_ADD | EV_ONESHOT, NOTE_MSECONDS,
		    next > now ? (int64_t)(next - now) : 0, &conn->src);
		conn->kq_deadline = next;
	}
	if (n > 0)
		(void)kevent(loop->kq, kev, n, NULL, 0, NULL);
}

int
cbl_conn_attach(cbl_conn *conn, cbl_loop *loop)
{

	if (conn == NULL || loop == NULL || conn->ctx != loop->ctx)
		return (EINVAL);
	if (conn->loop != NULL)
		return (EBUSY);
	if (conn->state == CBL_CS_CLOSED)
		return (ENOTCONN);
	cbl_conn_ref(conn);		/* the loop's reference */
	pthread_mutex_lock(&loop->mtx);
	conn->loop = loop;
	LIST_INSERT_HEAD(&loop->conns, conn, loop_link);
	pthread_mutex_unlock(&loop->mtx);
	conn->kq_events = 0;
	conn->kq_deadline = 0;
	if (cbl_loop_on_thread(loop) || !atomic_load(&loop->running))
		cbl_loop_update(loop, conn);
	else
		cbl_loop_kick(loop, conn);
	return (0);
}

/* Called on the loop thread when a connection is finished. */
void
cbl_loop_detach(cbl_loop *loop, cbl_conn *conn)
{
	struct kevent kev;

	if (conn->dead)
		return;
	/*
	 * Always: a one-shot timer re-armed while a firing was still queued
	 * fires again, and EV_DELETE also drops what is queued.  ENOENT when
	 * there is nothing is fine.
	 */
	EV_SET(&kev, (uintptr_t)conn, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	(void)kevent(loop->kq, &kev, 1, NULL, 0, NULL);
	conn->kq_deadline = 0;
	pthread_mutex_lock(&loop->mtx);
	conn->dead = true;
	LIST_REMOVE(conn, loop_link);
	TAILQ_INSERT_TAIL(&loop->dead, conn, dead_link);
	pthread_mutex_unlock(&loop->mtx);
}

int
cbl_loop_add_listener(cbl_loop *loop, cbl_listener *l)
{
	struct kevent kev;

	EV_SET(&kev, l->fd, EVFILT_READ, EV_ADD, 0, 0, &l->src);
	if (kevent(loop->kq, &kev, 1, NULL, 0, NULL) == -1)
		return (errno);
	return (0);
}

void
cbl_loop_del_listener(cbl_loop *loop, cbl_listener *l)
{
	struct kevent kev[2];

	EV_SET(&kev[0], l->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	EV_SET(&kev[1], (uintptr_t)l, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	(void)kevent(loop->kq, &kev[0], 1, NULL, 0, NULL);
	/* ENOENT if there was no timer. */
	(void)kevent(loop->kq, &kev[1], 1, NULL, 0, NULL);
}

/*
 * Stop watching a listener for "ms": accept(2) keeps failing for want of
 * descriptors or memory, and the socket stays readable.  A one-shot timer
 * on the listener's source brings it back (cbl_loop_resume_listener()).
 */
void
cbl_loop_pause_listener(cbl_loop *loop, cbl_listener *l, int ms)
{
	struct kevent kev[2];

	EV_SET(&kev[0], l->fd, EVFILT_READ, EV_DISABLE, 0, 0, &l->src);
	EV_SET(&kev[1], (uintptr_t)l, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
	    NOTE_MSECONDS, ms, &l->src);
	(void)kevent(loop->kq, kev, 2, NULL, 0, NULL);
}

void
cbl_loop_resume_listener(cbl_loop *loop, cbl_listener *l)
{
	struct kevent kev;

	EV_SET(&kev, l->fd, EVFILT_READ, EV_ENABLE, 0, 0, &l->src);
	(void)kevent(loop->kq, &kev, 1, NULL, 0, NULL);
}

int
cbl_loop_timer(cbl_loop *loop, uint32_t ms, uint32_t flags,
    void (*fn)(cbl_timer *, void *), void *arg, cbl_timer **tp)
{
	struct kevent kev;
	cbl_timer *t;
	int error;

	if (loop == NULL || fn == NULL)
		return (EINVAL);
	if ((t = calloc(1, sizeof(*t))) == NULL)
		return (ENOMEM);
	t->src.type = CBL_SRC_TIMER;
	t->src.obj = t;
	t->loop = loop;
	t->fn = fn;
	t->arg = arg;
	t->repeat = (flags & CBL_TF_REPEAT) != 0;
	t->held = tp != NULL;
	EV_SET(&kev, (uintptr_t)t, EVFILT_TIMER,
	    EV_ADD | (t->repeat ? 0 : EV_ONESHOT), NOTE_MSECONDS, ms, &t->src);
	if (kevent(loop->kq, &kev, 1, NULL, 0, NULL) == -1) {
		error = errno;
		free(t);
		return (error);
	}
	pthread_mutex_lock(&loop->mtx);
	LIST_INSERT_HEAD(&loop->timers, t, link);
	pthread_mutex_unlock(&loop->mtx);
	if (tp != NULL)
		*tp = t;
	return (0);
}

/* Must be called on the loop thread (or while the loop is not running). */
void
cbl_timer_cancel(cbl_timer *t)
{
	struct kevent kev;
	cbl_loop *loop;

	if (t == NULL)
		return;
	loop = t->loop;
	EV_SET(&kev, (uintptr_t)t, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	(void)kevent(loop->kq, &kev, 1, NULL, 0, NULL);
	/*
	 * An event for this timer may still be in the batch being
	 * dispatched; neutralise it here and free it in loop_reap().
	 */
	t->fn = NULL;
}

int
cbl_loop_signal(cbl_loop *loop, int sig, void (*fn)(int, void *), void *arg)
{
	struct kevent kev;
	struct cbl_sig *s;
	struct sigaction ign;
	int error;

	if (loop == NULL || fn == NULL || sig <= 0 || sig >= NSIG)
		return (EINVAL);
	if ((s = calloc(1, sizeof(*s))) == NULL)
		return (ENOMEM);
	s->src.type = CBL_SRC_SIGNAL;
	s->src.obj = s;
	s->sig = sig;
	s->fn = fn;
	s->arg = arg;
	/*
	 * EVFILT_SIGNAL only records; the default action must be off while
	 * the loop has the signal.  cbl_loop_free() puts the old one back.
	 */
	memset(&ign, 0, sizeof(ign));
	ign.sa_handler = SIG_IGN;
	sigemptyset(&ign.sa_mask);
	if (sigaction(sig, &ign, &s->old) == -1) {
		error = errno;
		free(s);
		return (error);
	}
	EV_SET(&kev, sig, EVFILT_SIGNAL, EV_ADD, 0, 0, &s->src);
	if (kevent(loop->kq, &kev, 1, NULL, 0, NULL) == -1) {
		error = errno;
		(void)sigaction(sig, &s->old, NULL);
		free(s);
		return (error);
	}
	pthread_mutex_lock(&loop->mtx);
	LIST_INSERT_HEAD(&loop->sigs, s, link);
	pthread_mutex_unlock(&loop->mtx);
	return (0);
}

static void
loop_run_posts(cbl_loop *loop)
{
	STAILQ_HEAD(, cbl_post) q;
	struct cbl_post *p;

	pthread_mutex_lock(&loop->mtx);
	STAILQ_INIT(&q);
	STAILQ_CONCAT(&q, &loop->posts);
	pthread_mutex_unlock(&loop->mtx);
	while ((p = STAILQ_FIRST(&q)) != NULL) {
		STAILQ_REMOVE_HEAD(&q, link);
		p->fn(p->arg);
		free(p);
	}
}

static void
loop_reap(cbl_loop *loop)
{
	cbl_conn *conn;
	cbl_timer *t, *tt;

	for (;;) {
		pthread_mutex_lock(&loop->mtx);
		conn = TAILQ_FIRST(&loop->dead);
		if (conn != NULL)
			TAILQ_REMOVE(&loop->dead, conn, dead_link);
		pthread_mutex_unlock(&loop->mtx);
		if (conn == NULL)
			break;
		/* conn->loop stays: a kick may still be queued for it. */
		cbl_conn_rele(conn);	/* the loop's reference */
	}
	pthread_mutex_lock(&loop->mtx);
	LIST_FOREACH_SAFE(t, &loop->timers, link, tt) {
		if (t->fn == NULL) {
			LIST_REMOVE(t, link);
			free(t);
		}
	}
	pthread_mutex_unlock(&loop->mtx);
}

/*
 * One batch of events.  The caller has made this thread the loop's owner
 * ("running"), for as long as it keeps calling: other threads decide on
 * that whether they may act on the loop's connections themselves.
 */
static int
loop_once(cbl_loop *loop, int timeout_ms)
{
	struct kevent evs[CBL_LOOP_NEV];
	struct timespec ts, *tsp = NULL;
	struct cbl_src *src;
	cbl_conn *conn;
	cbl_timer *t;
	struct cbl_sig *s;
	int n, rev;

	if (timeout_ms >= 0) {
		ts.tv_sec = timeout_ms / 1000;
		ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000;
		tsp = &ts;
	}
	n = kevent(loop->kq, NULL, 0, evs, CBL_LOOP_NEV, tsp);
	if (n == -1)
		return (errno == EINTR ? 0 : errno);
	for (int i = 0; i < n; i++) {
		if (evs[i].filter == EVFILT_USER) {
			loop_run_posts(loop);
			continue;
		}
		src = evs[i].udata;
		if (src == NULL)
			continue;
		switch (src->type) {
		case CBL_SRC_CONN:
			conn = src->obj;
			if (conn->dead)
				break;
			if (evs[i].filter == EVFILT_READ)
				rev = CBL_EV_READ;
			else if (evs[i].filter == EVFILT_WRITE)
				rev = CBL_EV_WRITE;
			else {
				rev = 0;
				conn->kq_deadline = 0;	/* one-shot fired */
			}
			(void)cbl_conn_process(conn, rev);
			if (!conn->dead)
				cbl_loop_update(loop, conn);
			break;
		case CBL_SRC_LISTENER:
			if (evs[i].filter == EVFILT_TIMER &&
			    cbl_listener_fd(src->obj) != -1)
				cbl_loop_resume_listener(loop, src->obj);
			cbl_listener_on_ready(src->obj);
			break;
		case CBL_SRC_TIMER:
			t = src->obj;
			if (t->fn == NULL || t->fired)
				break;
			t->fn(t, t->arg);
			/*
			 * A one-shot timer is done.  If the caller kept its
			 * handle, the handle stays valid until cancelled.
			 */
			if (!t->repeat && t->fn != NULL) {
				if (t->held)
					t->fired = true;
				else
					cbl_timer_cancel(t);
			}
			break;
		case CBL_SRC_SIGNAL:
			s = src->obj;
			s->fn(s->sig, s->arg);
			break;
		default:
			break;
		}
	}
	loop_reap(loop);
	return (0);
}

static void
loop_own(cbl_loop *loop, bool own)
{

	if (own)
		atomic_store(&loop->thread, (uintptr_t)pthread_self());
	atomic_store(&loop->running, own);
}

/*
 * One batch, for an application that drives the loop itself: the thread
 * owns the loop only while this runs.
 */
int
cbl_loop_run_once(cbl_loop *loop, int timeout_ms)
{
	int error;

	if (loop == NULL)
		return (EINVAL);
	loop_own(loop, true);
	error = loop_once(loop, timeout_ms);
	loop_own(loop, false);
	return (error);
}

/* The thread owns the loop for the whole run, not batch by batch. */
int
cbl_loop_run(cbl_loop *loop)
{
	int error = 0;

	if (loop == NULL)
		return (EINVAL);
	loop_own(loop, true);
	/*
	 * A stop requested before the loop runs (another thread started it
	 * a moment ago) still counts; returning consumes it.
	 */
	while (!atomic_exchange(&loop->stop, false))
		if ((error = loop_once(loop, -1)) != 0)
			break;
	loop_own(loop, false);
	return (error);
}

void
cbl_loop_free(cbl_loop *loop)
{
	cbl_conn *conn;
	cbl_timer *t;
	struct cbl_sig *s;

	if (loop == NULL)
		return;
	/* Close what is still attached; the loop is not running now. */
	while ((conn = LIST_FIRST(&loop->conns)) != NULL) {
		cbl_conn_fail(conn, ECONNABORTED);
		if (!conn->dead)
			cbl_loop_detach(loop, conn);
	}
	loop_run_posts(loop);
	loop_reap(loop);
	while ((t = LIST_FIRST(&loop->timers)) != NULL) {
		LIST_REMOVE(t, link);
		free(t);
	}
	while ((s = LIST_FIRST(&loop->sigs)) != NULL) {
		LIST_REMOVE(s, link);
		(void)sigaction(s->sig, &s->old, NULL);
		free(s);
	}
	close(loop->kq);
	pthread_mutex_destroy(&loop->mtx);
	atomic_fetch_sub(&loop->ctx->nobjs, 1);
	free(loop);
}
