/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Streams: open/accept/reject, data, credit flow control, close, reset. */

#include <stdatomic.h>
#include <time.h>

#include "cbl_net_test.h"

enum { S_CHAT = 1, S_FEED, S_REJECT, S_NOACCEPT, S_SINK, S_RESETDATA,
    S_LASTDATA, S_LATER, S_BADACCEPT };
enum { SA_SEQ = 1, SA_PAD, SA_N };

/* Server side. */
struct srv {
	atomic_int	 opened;
	atomic_int	 closed;
	atomic_int	 close_code;
	char		 close_text[64];
	atomic_int	 received;
	atomic_int	 hclosed;
	cbl_stream	*sink;		/* manual-credit stream */
	atomic_size_t	 sink_bytes;
};

static void
srv_echo_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct srv *sv = arg;
	cbl_msg *m;

	sv->received++;
	if (cbl_stream_msg_new(s, &m) == 0) {
		cbl_put_attr(m, SA_SEQ, cbl_msg_attr(data, SA_SEQ));
		if (cbl_stream_send(s, m) == EAGAIN)
			cbl_msg_free(m);
	}
}

static void
srv_hclose(cbl_stream *s, void *arg __unused)
{

	(void)cbl_stream_half_close(s);
}

static void
srv_close(cbl_stream *s __unused, int code, const char *text, void *arg)
{
	struct srv *sv = arg;

	sv->close_code = code;
	if (text != NULL)
		strlcpy(sv->close_text, text, sizeof(sv->close_text));
	sv->closed++;
}

static const struct cbl_stream_cbs echo_cbs = {
	.on_data = srv_echo_data,
	.on_hclose = srv_hclose,
	.on_close = srv_close,
};

static int
chat_open(cbl_req *req __unused, const cbl_msg *msg __unused, cbl_stream *s,
    void *arg)
{
	struct srv *sv = arg;

	sv->opened++;
	return (cbl_stream_accept(s, NULL, 0, &echo_cbs, sv));
}

/* Push: send N items as credit allows, then half-close. */
struct feed {
	struct srv	*sv;
	uint64_t	 n;
	uint64_t	 next;
};

static void
feed_pump(cbl_stream *s, struct feed *f)
{
	cbl_msg *m;
	int error;

	while (f->next < f->n) {
		if (cbl_stream_msg_new(s, &m) != 0)
			return;
		cbl_put_uint(m, SA_SEQ, f->next);
		cbl_put_bytes(m, SA_PAD, "0123456789abcdef0123456789abcdef",
		    32);
		if ((error = cbl_stream_send(s, m)) == EAGAIN) {
			cbl_msg_free(m);
			return;		/* resumed by on_writable */
		}
		if (error != 0)
			return;
		f->next++;
	}
	(void)cbl_stream_half_close(s);
}

static void
feed_writable(cbl_stream *s, size_t credit __unused, void *arg)
{

	feed_pump(s, arg);
}

static void
feed_close(cbl_stream *s __unused, int code, const char *text, void *arg)
{
	struct feed *f = arg;

	srv_close(s, code, text, f->sv);
	free(f);
}

static const struct cbl_stream_cbs feed_cbs = {
	.on_writable = feed_writable,
	.on_close = feed_close,
};

static int
feed_open(cbl_req *req __unused, const cbl_msg *msg, cbl_stream *s, void *arg)
{
	struct feed *f;
	int error;

	if ((f = calloc(1, sizeof(*f))) == NULL)
		return (ENOMEM);
	f->sv = arg;
	f->n = 100;
	(void)cbl_attr_uint(cbl_msg_attr(msg, SA_N), &f->n);
	f->sv->opened++;
	if ((error = cbl_stream_accept(s, NULL, 0, &feed_cbs, f)) != 0) {
		free(f);
		return (error);
	}
	feed_pump(s, f);
	return (0);
}

static int
reject_open(cbl_req *req, const cbl_msg *msg __unused, cbl_stream *s __unused,
    void *arg __unused)
{

	cbl_req_set_err(req, "go away", NULL, 0, -1);
	return (EACCES);
}

/*
 * An accept whose frame cannot be built: the stream is not accepted, the
 * callbacks given are never called, and the open is refused.
 */
static int
badaccept_open(cbl_req *req __unused, const cbl_msg *msg __unused,
    cbl_stream *s, void *arg)
{
	struct srv *sv = arg;
	cbl_msg *m;
	int error;

	if ((error = cbl_stream_msg_new(s, &m)) != 0)
		return (error);
	(void)cbl_put_uint(m, SA_SEQ, 1);
	(void)cbl_put_uint(m, SA_SEQ, 2);	/* a duplicate: EEXIST */
	error = cbl_stream_accept(s, m, 0, &echo_cbs, sv);
	sv->close_code = error;
	return (error);
}

static int
noaccept_open(cbl_req *req __unused, const cbl_msg *msg __unused,
    cbl_stream *s __unused, void *arg __unused)
{

	return (0);
}

static void
sink_data(cbl_stream *s __unused, cbl_msg *data, void *arg)
{
	struct srv *sv = arg;

	sv->received++;
	sv->sink_bytes += cbl_msg_len(data);
}

static const struct cbl_stream_cbs sink_cbs = {
	.on_data = sink_data,
	.on_close = srv_close,
};

static int
sink_open(cbl_req *req __unused, const cbl_msg *msg __unused, cbl_stream *s,
    void *arg)
{
	struct srv *sv = arg;

	sv->sink = s;
	sv->opened++;
	return (cbl_stream_accept(s, NULL, CBL_SF_MANUAL_CREDIT, &sink_cbs,
	    sv));
}

/*
 * Streams ended from inside their own callbacks (on_data here): the library
 * must not touch them afterwards, and runs no further callback but on_close.
 */
static void
srv_reset_data(cbl_stream *s, cbl_msg *data __unused, void *arg)
{
	struct srv *sv = arg;

	sv->received++;
	(void)cbl_stream_reset(s, EBADMSG);
}

/* Answer the peer's last frame with ours: both halves close in on_data. */
static void
srv_last_data(cbl_stream *s, cbl_msg *data __unused, void *arg)
{
	struct srv *sv = arg;
	cbl_msg *m;

	sv->received++;
	if (cbl_stream_msg_new(s, &m) == 0 &&
	    cbl_msg_set_flags(m, CBL_F_S_DATA | CBL_F_S_HCLOSE) == 0)
		(void)cbl_stream_send(s, m);
}

static void
srv_count_hclose(cbl_stream *s __unused, void *arg)
{
	struct srv *sv = arg;

	sv->hclosed++;
}

static const struct cbl_stream_cbs reset_cbs = {
	.on_data = srv_reset_data,
	.on_hclose = srv_count_hclose,
	.on_close = srv_close,
};

static const struct cbl_stream_cbs last_cbs = {
	.on_data = srv_last_data,
	.on_hclose = srv_count_hclose,
	.on_close = srv_close,
};

static int
resetdata_open(cbl_req *req __unused, const cbl_msg *msg __unused,
    cbl_stream *s, void *arg)
{

	return (cbl_stream_accept(s, NULL, 0, &reset_cbs, arg));
}

static int
lastdata_open(cbl_req *req __unused, const cbl_msg *msg __unused,
    cbl_stream *s, void *arg)
{

	return (cbl_stream_accept(s, NULL, 0, &last_cbs, arg));
}

/*
 * A deferred open, settled 50 ms later by another thread: accepted when
 * the open's SA_N is 1, refused with EACCES otherwise.
 */
struct later {
	cbl_req		*req;
	cbl_stream	*s;
	struct srv	*sv;
	uint64_t	 accept;
};

static void *
later_thread(void *arg)
{
	struct later *lt = arg;

	usleep(50000);
	if (lt->accept == 1) {
		lt->sv->opened++;
		(void)cbl_stream_accept(lt->s, NULL, 0, &echo_cbs, lt->sv);
		(void)cbl_req_complete(lt->req, 0);
	} else
		(void)cbl_req_complete(lt->req, EACCES);
	free(lt);
	return (NULL);
}

static int
later_open(cbl_req *req, const cbl_msg *msg, cbl_stream *s, void *arg)
{
	struct later *lt;
	pthread_t thr;

	if ((lt = calloc(1, sizeof(*lt))) == NULL)
		return (ENOMEM);
	lt->req = req;
	lt->s = s;
	lt->sv = arg;
	(void)cbl_attr_uint(cbl_msg_attr(msg, SA_N), &lt->accept);
	ATF_REQUIRE_EQ(0, cbl_req_defer(req));
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, later_thread, lt));
	pthread_detach(thr);
	return (0);
}

static const struct cbl_op st_ops[] = {
	{ .cmd = S_CHAT, .name = "chat", .flags = CBL_OPF_STREAM,
	  .stream_open = chat_open },
	{ .cmd = S_FEED, .name = "feed", .flags = CBL_OPF_PUSH,
	  .stream_open = feed_open },
	{ .cmd = S_REJECT, .name = "reject", .flags = CBL_OPF_STREAM,
	  .stream_open = reject_open },
	{ .cmd = S_NOACCEPT, .name = "noaccept", .flags = CBL_OPF_STREAM,
	  .stream_open = noaccept_open },
	{ .cmd = S_SINK, .name = "sink", .flags = CBL_OPF_STREAM,
	  .stream_open = sink_open },
	{ .cmd = S_RESETDATA, .name = "resetdata", .flags = CBL_OPF_STREAM,
	  .stream_open = resetdata_open },
	{ .cmd = S_LASTDATA, .name = "lastdata", .flags = CBL_OPF_STREAM,
	  .stream_open = lastdata_open },
	{ .cmd = S_LATER, .name = "later", .flags = CBL_OPF_STREAM,
	  .stream_open = later_open },
	{ .cmd = S_BADACCEPT, .name = "badaccept", .flags = CBL_OPF_STREAM,
	  .stream_open = badaccept_open },
};

static const struct cbl_family_def st_def = {
	.abi = CBL_FAMILY_ABI, .name = "streams", .version = 1,
	.ops = st_ops, .nops = nitems(st_ops),
};

struct fx {
	cbl_ctx			*sctx, *cctx;
	struct test_server	 ts;
	cbl_family		*fam;
	uint16_t		 id;
	cbl_conn		*c;
	struct srv		 sv;
};

static void
fx_setup(struct fx *f, uint64_t srv_window, uint64_t max_streams,
    uint64_t cli_window)
{

	memset(f, 0, sizeof(*f));
	f->sctx = test_ctx();
	f->cctx = test_ctx();
	if (srv_window != 0)
		ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(f->sctx,
		    CBL_LIM_STREAM_WINDOW, srv_window));
	if (max_streams != 0)
		ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(f->sctx,
		    CBL_LIM_MAX_STREAMS, max_streams));
	if (cli_window != 0)
		ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(f->cctx,
		    CBL_LIM_STREAM_WINDOW, cli_window));
	ATF_REQUIRE_EQ(0, cbl_family_register(f->sctx, &st_def, &f->sv,
	    &f->fam));
	f->id = cbl_family_id(f->fam);
	test_server_start(&f->ts, f->sctx, "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	ATF_REQUIRE_EQ(0, cbl_conn_new(f->cctx, f->ts.uri, CBL_PLAINTEXT,
	    &f->c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(f->c));
}

static void
fx_teardown(struct fx *f)
{

	if (f->c != NULL)
		cbl_conn_free(f->c);
	test_server_stop(&f->ts);
	ATF_REQUIRE_EQ(0, cbl_family_unregister(f->fam));
	cbl_ctx_free(f->sctx);
	cbl_ctx_free(f->cctx);
}

static uint64_t
ms_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

/* Drive the loop-less client until *flag >= want (or timeout). */
static void
drive(cbl_conn *c, atomic_int *flag, int want, int ms)
{
	uint64_t end = ms_now() + (uint64_t)ms;
	struct pollfd pfd;
	int events, timeout;

	while (*flag < want && ms_now() < end) {
		if (cbl_conn_interest(c, &events, &timeout) != 0 ||
		    cbl_conn_fd(c) == -1)
			return;
		pfd.fd = cbl_conn_fd(c);
		pfd.events = POLLIN | ((events & CBL_EV_WRITE) ? POLLOUT : 0);
		pfd.revents = 0;
		(void)poll(&pfd, 1,
		    timeout >= 0 && timeout < 10 ? timeout : 10);
		(void)cbl_conn_process(c,
		    ((pfd.revents & (POLLIN | POLLHUP)) ? CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) ? CBL_EV_WRITE : 0));
	}
}

static void
wait_for(atomic_int *flag, int want, int ms)
{

	for (int i = 0; i < ms / 5 && *flag < want; i++)
		usleep(5000);
}

/* Client side. */
enum { RESET_NONE, RESET_ON_OPEN, RESET_ON_WRITABLE };

struct cli {
	atomic_int	 opened;
	atomic_int	 open_error;
	atomic_int	 data;
	atomic_int	 hclosed;
	atomic_int	 closed;
	atomic_int	 close_code;
	atomic_int	 writable;
	atomic_bool	 in_order;
	int		 reset_in;	/* RESET_*: reset from that callback */
	uint64_t	 next;
	char		 text[64];
};

static void
cli_open(cbl_stream *s, cbl_msg *accept __unused, int error, void *arg)
{
	struct cli *c = arg;

	c->open_error = error;
	c->opened++;
	if (c->reset_in == RESET_ON_OPEN)
		(void)cbl_stream_reset(s, 0);
}

static void
cli_data(cbl_stream *s __unused, cbl_msg *data, void *arg)
{
	struct cli *c = arg;
	uint64_t seq = UINT64_MAX;

	(void)cbl_attr_uint(cbl_msg_attr(data, SA_SEQ), &seq);
	if (seq != c->next)
		c->in_order = false;
	c->next++;
	c->data++;
}

static void
cli_hclose(cbl_stream *s __unused, void *arg)
{
	struct cli *c = arg;

	c->hclosed++;
}

static void
cli_close(cbl_stream *s __unused, int code, const char *text, void *arg)
{
	struct cli *c = arg;

	c->close_code = code;
	if (text != NULL)
		strlcpy(c->text, text, sizeof(c->text));
	c->closed++;
}

static void
cli_writable(cbl_stream *s, size_t credit __unused, void *arg)
{
	struct cli *c = arg;

	c->writable++;
	if (c->reset_in == RESET_ON_WRITABLE)
		(void)cbl_stream_reset(s, 0);
}

static const struct cbl_stream_cbs cli_cbs = {
	.on_open = cli_open,
	.on_data = cli_data,
	.on_hclose = cli_hclose,
	.on_close = cli_close,
	.on_writable = cli_writable,
};

static cbl_stream *
open_stream(struct fx *f, uint16_t cmd, uint32_t flags, struct cli *c,
    uint64_t n)
{
	cbl_stream *s;
	cbl_msg *m;

	memset(c, 0, sizeof(*c));
	c->in_order = true;
	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, f->id, cmd, 0, &m));
	if (n != 0)
		cbl_put_uint(m, SA_N, n);
	ATF_REQUIRE_EQ(0, cbl_stream_open(f->c, m, flags, &cli_cbs, c, &s));
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_EQ(1, cbl_stream_id(s) % 2);	/* initiator: odd */
	return (s);
}

ATF_TC_WITHOUT_HEAD(echo);
ATF_TC_BODY(echo, tc)
{
	struct fx f;
	struct cli c;
	cbl_stream *s;
	cbl_msg *m;

	fx_setup(&f, 0, 0, 0);
	s = open_stream(&f, S_CHAT, 0, &c, 0);
	drive(f.c, &c.opened, 1, 3000);
	ATF_REQUIRE_EQ(1, c.opened);
	ATF_REQUIRE_EQ(0, c.open_error);
	for (uint64_t i = 0; i < 200; i++) {
		ATF_REQUIRE_EQ(0, cbl_stream_msg_new(s, &m));
		cbl_put_uint(m, SA_SEQ, i);
		ATF_REQUIRE_EQ(0, cbl_stream_send(s, m));
		if (i % 50 == 0)
			drive(f.c, &c.data, (int)i, 50);
	}
	drive(f.c, &c.data, 200, 5000);
	ATF_REQUIRE_EQ(200, c.data);
	ATF_REQUIRE(c.in_order);
	/* Half-close both ways ends the stream cleanly. */
	ATF_REQUIRE_EQ(0, cbl_stream_half_close(s));
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.hclosed);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_EQ(0, c.close_code);
	wait_for(&f.sv.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, f.sv.closed);
	ATF_REQUIRE_EQ(200, f.sv.received);
	fx_teardown(&f);
}

/* Push stream: 2000 items through the default window. */
ATF_TC_WITHOUT_HEAD(push);
ATF_TC_BODY(push, tc)
{
	struct fx f;
	struct cli c;
	cbl_stream *s;
	cbl_msg *m;

	fx_setup(&f, 0, 0, 4096);
	s = open_stream(&f, S_FEED, CBL_SF_PUSH, &c, 2000);
	drive(f.c, &c.opened, 1, 3000);
	ATF_REQUIRE_EQ(0, c.open_error);
	/* The opener of a push stream cannot send. */
	ATF_REQUIRE_EQ(0, cbl_stream_msg_new(s, &m));
	ATF_REQUIRE_EQ(EPIPE, cbl_stream_send(s, m));
	drive(f.c, &c.closed, 1, 10000);
	ATF_REQUIRE_EQ(2000, c.data);
	ATF_REQUIRE(c.in_order);
	ATF_REQUIRE_EQ(1, c.hclosed);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_EQ(0, c.close_code);
	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(rejected);
ATF_TC_BODY(rejected, tc)
{
	struct fx f;
	struct cli c;

	fx_setup(&f, 0, 0, 0);
	(void)open_stream(&f, S_REJECT, 0, &c, 0);
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.opened);
	ATF_REQUIRE_EQ(EACCES, c.open_error);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_STREQ("go away", c.text);
	(void)open_stream(&f, S_NOACCEPT, 0, &c, 0);
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(ECONNREFUSED, c.open_error);
	/* An accept that fails leaves no stream and no callbacks behind. */
	(void)open_stream(&f, S_BADACCEPT, 0, &c, 0);
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(EEXIST, c.open_error);
	ATF_REQUIRE_EQ(EEXIST, f.sv.close_code);
	ATF_REQUIRE_EQ(0, f.sv.closed);
	/* A plain request to a stream command is refused. */
	{
		cbl_msg *m, *r;

		cbl_msg_new(f.cctx, f.id, S_CHAT, 0, &m);
		ATF_REQUIRE_EQ(EOPNOTSUPP, cbl_request(f.c, m, &r, 2000));
		cbl_msg_free(r);
	}
	fx_teardown(&f);
}

/*
 * Flow control: the server grants credit only when told to, so the client
 * runs out, gets EAGAIN, and resumes on on_writable.
 */
ATF_TC_WITHOUT_HEAD(flow_control);
ATF_TC_BODY(flow_control, tc)
{
	struct fx f;
	struct cli c;
	cbl_stream *s;
	cbl_msg *m;
	int sent = 0, error;

	fx_setup(&f, 1024, 0, 0);
	s = open_stream(&f, S_SINK, 0, &c, 0);
	drive(f.c, &c.opened, 1, 3000);
	ATF_REQUIRE_EQ(0, c.open_error);
	ATF_REQUIRE_EQ(1024, cbl_stream_credit(s));
	for (;;) {
		ATF_REQUIRE_EQ(0, cbl_stream_msg_new(s, &m));
		cbl_put_bytes(m, SA_PAD, "0123456789012345678901234567890123"
		    "4567890123456789", 50);
		if ((error = cbl_stream_send(s, m)) == EAGAIN) {
			cbl_msg_free(m);
			break;
		}
		ATF_REQUIRE_EQ(0, error);
		sent++;
	}
	/* 78-byte frames: 13 fit in 1024 bytes. */
	ATF_REQUIRE_EQ(13, sent);
	wait_for(&f.sv.received, 13, 3000);
	ATF_REQUIRE_EQ(13, f.sv.received);
	drive(f.c, &c.writable, 1, 300);
	ATF_REQUIRE_EQ(0, c.writable);	/* nothing granted yet */
	/* The application consumes: credit flows back. */
	ATF_REQUIRE_EQ(0, cbl_stream_consumed(f.sv.sink, f.sv.sink_bytes));
	drive(f.c, &c.writable, 1, 3000);
	ATF_REQUIRE_EQ(1, c.writable);
	ATF_REQUIRE_EQ(1024, cbl_stream_credit(s));
	/* Reset ends both sides; on_close runs at the next processing. */
	ATF_REQUIRE_EQ(0, cbl_stream_reset(s, 0));
	ATF_REQUIRE_EQ(0, c.closed);
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_EQ(ECANCELED, c.close_code);
	wait_for(&f.sv.closed, 1, 3000);
	ATF_REQUIRE_EQ(ECANCELED, f.sv.close_code);
	fx_teardown(&f);
}

/* Graceful close with a code and a reason, as in WebSocket. */
ATF_TC_WITHOUT_HEAD(close_handshake);
ATF_TC_BODY(close_handshake, tc)
{
	struct fx f;
	struct cli c;
	cbl_stream *s;

	fx_setup(&f, 0, 0, 0);
	s = open_stream(&f, S_CHAT, 0, &c, 0);
	drive(f.c, &c.opened, 1, 3000);
	ATF_REQUIRE_EQ(0, cbl_stream_close(s, 1000, "bye"));
	ATF_REQUIRE_EQ(EPIPE, cbl_stream_close(s, 1000, "again"));
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.closed);
	wait_for(&f.sv.closed, 1, 3000);
	ATF_REQUIRE_EQ(1000, f.sv.close_code);
	ATF_REQUIRE_STREQ("bye", f.sv.close_text);
	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(max_streams);
ATF_TC_BODY(max_streams, tc)
{
	struct fx f;
	struct cli c[3];

	fx_setup(&f, 0, 2, 0);
	(void)open_stream(&f, S_CHAT, 0, &c[0], 0);
	(void)open_stream(&f, S_CHAT, 0, &c[1], 0);
	(void)open_stream(&f, S_CHAT, 0, &c[2], 0);
	drive(f.c, &c[2].opened, 1, 3000);
	ATF_REQUIRE_EQ(0, c[0].open_error);
	ATF_REQUIRE_EQ(0, c[1].open_error);
	ATF_REQUIRE_EQ(ENOSPC, c[2].open_error);
	/* Closing the connection ends the open streams. */
	cbl_conn_close(f.c);
	ATF_REQUIRE_EQ(1, c[0].closed);
	ATF_REQUIRE_EQ(1, c[1].closed);
	cbl_conn_free(f.c);
	f.c = NULL;
	wait_for(&f.sv.closed, 2, 3000);
	ATF_REQUIRE_EQ(2, f.sv.closed);
	fx_teardown(&f);
}

/* A peer that never accepts: the open times out. */
ATF_TC_WITHOUT_HEAD(open_timeout);
ATF_TC_BODY(open_timeout, tc)
{
	cbl_ctx *ctx = test_ctx();
	struct cli c = { .in_order = true };
	cbl_stream *s;
	cbl_conn *conn;
	cbl_msg *m;
	char uri[64];
	uint16_t port;
	int lfd, fd;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_REQUEST_MS, 300));
	lfd = raw_listen(&port);
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", port);
	ATF_REQUIRE_EQ(0, cbl_conn_new(ctx, uri, CBL_PLAINTEXT, &conn));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(conn));
	fd = accept(lfd, NULL, NULL);
	cbl_msg_new(ctx, 5, 1, 0, &m);
	ATF_REQUIRE_EQ(0, cbl_stream_open(conn, m, 0, &cli_cbs, &c, &s));
	m = raw_read_msg(ctx, fd);
	ATF_REQUIRE_EQ(CBL_F_REQUEST | CBL_F_S_OPEN, cbl_msg_flags(m));
	cbl_msg_free(m);
	drive(conn, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(ETIMEDOUT, c.open_error);
	ATF_REQUIRE_EQ(1, c.closed);
	close(fd);
	close(lfd);
	cbl_conn_free(conn);
	cbl_ctx_free(ctx);
}

/* Raw peer violations against a server. */
static void
raw_open(int fd, cbl_ctx *ctx, uint16_t fam, uint16_t cmd, uint32_t seq,
    uint32_t id, uint64_t credit)
{
	unsigned char buf[64];
	char hex[32];
	size_t len;

	snprintf(hex, sizeof(hex), "A1 25 1A %02X %02X %02X %02X",
	    (unsigned)(credit >> 24) & 0xff, (unsigned)(credit >> 16) & 0xff,
	    (unsigned)(credit >> 8) & 0xff, (unsigned)credit & 0xff);
	len = mkframe(buf, sizeof(buf), fam, cmd, CBL_F_REQUEST | CBL_F_S_OPEN,
	    seq, id, hex);
	(void)ctx;
	raw_write(fd, buf, len);
}

ATF_TC_WITHOUT_HEAD(protocol_violations);
ATF_TC_BODY(protocol_violations, tc)
{
	struct fx f;
	unsigned char buf[2048];
	cbl_msg *m;
	size_t len;
	int fd;

	fx_setup(&f, 1024, 0, 0);
	fd = raw_connect(f.ts.uri);
	/* Even id from the connection initiator: refused. */
	raw_open(fd, f.cctx, f.id, S_CHAT, 1, 2, 4096);
	m = raw_read_msg(f.cctx, fd);
	ATF_REQUIRE_EQ(CBL_F_ERROR | CBL_F_S_OPEN, cbl_msg_flags(m));
	ATF_REQUIRE_EQ(EPROTO, cbl_msg_err_code(m));
	cbl_msg_free(m);
	/* A good open, then the same id again. */
	raw_open(fd, f.cctx, f.id, S_CHAT, 2, 5, 4096);
	m = raw_read_msg(f.cctx, fd);
	ATF_REQUIRE_EQ(CBL_F_S_OPEN, cbl_msg_flags(m));
	ATF_REQUIRE_EQ(5, cbl_msg_stream(m));
	cbl_msg_free(m);
	raw_open(fd, f.cctx, f.id, S_CHAT, 3, 5, 4096);
	m = raw_read_msg(f.cctx, fd);
	ATF_REQUIRE_EQ(EPROTO, cbl_msg_err_code(m));
	cbl_msg_free(m);
	/* Data beyond the 1024-byte window: the server resets the stream. */
	memset(buf, 0, sizeof(buf));
	{
		char *hex = malloc(4200), *p = hex;

		p += sprintf(p, "A1 02 59 04 00");
		for (int i = 0; i < 1024; i++)
			p += sprintf(p, " AA");
		len = mkframe(buf, sizeof(buf), f.id, S_CHAT, CBL_F_S_DATA, 0,
		    5, hex);
		free(hex);
	}
	raw_write(fd, buf, len);
	m = raw_read_msg(f.cctx, fd);
	ATF_REQUIRE_EQ(CBL_F_S_RESET, cbl_msg_flags(m));
	ATF_REQUIRE_EQ(5, cbl_msg_stream(m));
	ATF_REQUIRE_STREQ("flow-control window exceeded", cbl_msg_err_str(m));
	cbl_msg_free(m);
	/* Data on an unknown stream is answered with a reset. */
	len = mkframe(buf, sizeof(buf), f.id, S_CHAT, CBL_F_S_DATA, 0, 99,
	    "A0");
	raw_write(fd, buf, len);
	m = raw_read_msg(f.cctx, fd);
	ATF_REQUIRE_EQ(CBL_F_S_RESET, cbl_msg_flags(m));
	ATF_REQUIRE_EQ(99, cbl_msg_stream(m));
	cbl_msg_free(m);
	/* The connection is still fine. */
	raw_open(fd, f.cctx, f.id, S_CHAT, 4, 7, 4096);
	m = raw_read_msg(f.cctx, fd);
	ATF_REQUIRE_EQ(CBL_F_S_OPEN, cbl_msg_flags(m));
	cbl_msg_free(m);
	/*
	 * At most one reset per id: 99 again, and 5, reset earlier, get no
	 * answer.  The ping's reply is the next frame.
	 */
	len = mkframe(buf, sizeof(buf), f.id, S_CHAT, CBL_F_S_DATA, 0, 99,
	    "A0");
	raw_write(fd, buf, len);
	len = mkframe(buf, sizeof(buf), f.id, S_CHAT, CBL_F_S_DATA, 0, 5,
	    "A0");
	raw_write(fd, buf, len);
	len = mkframe(buf, sizeof(buf), 0, 4, CBL_F_REQUEST, 20, 0, "A0");
	raw_write(fd, buf, len);
	m = raw_read_msg(f.cctx, fd);
	ATF_REQUIRE_EQ(20, cbl_msg_seq(m));
	ATF_REQUIRE_EQ(0, cbl_msg_stream(m));
	cbl_msg_free(m);
	/* A data frame that does not decode resets its stream. */
	len = mkframe(buf, sizeof(buf), f.id, S_CHAT, CBL_F_S_DATA, 0, 7,
	    "A1 01 BF");
	raw_write(fd, buf, len);
	m = raw_read_msg(f.cctx, fd);
	ATF_REQUIRE_EQ(CBL_F_S_RESET, cbl_msg_flags(m));
	ATF_REQUIRE_EQ(7, cbl_msg_stream(m));
	ATF_REQUIRE_STREQ("malformed frame", cbl_msg_err_str(m));
	cbl_msg_free(m);
	close(fd);
	fx_teardown(&f);
}

/* Data sent from another thread while a loop runs the connection. */
struct sender {
	cbl_stream	*s;
	int		 n;
};

static void *
sender_thread(void *arg)
{
	struct sender *sd = arg;
	cbl_msg *m;

	for (int i = 0; i < sd->n; i++) {
		if (cbl_stream_msg_new(sd->s, &m) != 0)
			break;
		cbl_put_uint(m, SA_SEQ, (uint64_t)i);
		while (cbl_stream_send(sd->s, m) == EAGAIN)
			usleep(1000);
	}
	return (NULL);
}

static void *
loop_thread(void *arg)
{

	(void)cbl_loop_run(arg);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(cross_thread);
ATF_TC_BODY(cross_thread, tc)
{
	struct sender sd;
	struct fx f;
	struct cli c;
	cbl_loop *loop;
	pthread_t lt, st;

	fx_setup(&f, 0, 0, 0);
	ATF_REQUIRE_EQ(0, cbl_loop_new(f.cctx, &loop));
	ATF_REQUIRE_EQ(0, cbl_conn_attach(f.c, loop));
	ATF_REQUIRE_EQ(0, pthread_create(&lt, NULL, loop_thread, loop));
	sd.s = open_stream(&f, S_CHAT, 0, &c, 0);
	wait_for(&c.opened, 1, 3000);
	ATF_REQUIRE_EQ(0, c.open_error);
	sd.n = 500;
	ATF_REQUIRE_EQ(0, pthread_create(&st, NULL, sender_thread, &sd));
	pthread_join(st, NULL);
	wait_for(&c.data, 500, 10000);
	ATF_REQUIRE_EQ(500, c.data);
	ATF_REQUIRE(c.in_order);
	/* Reset from this thread: on_close still runs on the loop thread. */
	ATF_REQUIRE_EQ(0, cbl_stream_reset(sd.s, 0));
	wait_for(&c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.closed);
	cbl_loop_stop(loop);
	pthread_join(lt, NULL);
	cbl_conn_free(f.c);
	f.c = NULL;
	cbl_loop_free(loop);
	fx_teardown(&f);
}

/* An accept whose seq is not the open's is refused: on_open sees EPROTO. */
ATF_TC_WITHOUT_HEAD(accept_wrong_seq);
ATF_TC_BODY(accept_wrong_seq, tc)
{
	cbl_ctx *cctx = test_ctx();
	unsigned char buf[64];
	struct cli c;
	cbl_stream *s;
	cbl_conn *conn;
	cbl_msg *m;
	uint16_t port;
	char uri[64];
	size_t len;
	int lfd, sfd;

	lfd = raw_listen(&port);
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", port);
	ATF_REQUIRE_EQ(0, cbl_conn_new(cctx, uri, CBL_PLAINTEXT, &conn));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(conn));
	ATF_REQUIRE((sfd = accept(lfd, NULL, NULL)) != -1);
	memset(&c, 0, sizeof(c));
	ATF_REQUIRE_EQ(0, cbl_msg_new(cctx, 9, 1, 0, &m));
	ATF_REQUIRE_EQ(0, cbl_stream_open(conn, m, 0, &cli_cbs, &c, &s));
	ATF_REQUIRE((m = raw_read_msg(cctx, sfd)) != NULL);
	len = mkframe(buf, sizeof(buf), 9, 1, CBL_F_S_OPEN,
	    cbl_msg_seq(m) + 1, cbl_msg_stream(m), "A0");
	cbl_msg_free(m);
	raw_write(sfd, buf, len);
	drive(conn, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.opened);
	ATF_REQUIRE_EQ(EPROTO, c.open_error);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE((m = raw_read_msg(cctx, sfd)) != NULL);
	ATF_REQUIRE_EQ(CBL_F_S_RESET, cbl_msg_flags(m));
	cbl_msg_free(m);
	cbl_conn_free(conn);
	close(sfd);
	close(lfd);
	cbl_ctx_free(cctx);
}

/* An open deferred by its handler is accepted, or refused, later. */
ATF_TC_WITHOUT_HEAD(deferred_open);
ATF_TC_BODY(deferred_open, tc)
{
	struct fx f;
	struct cli c;
	cbl_stream *s;
	cbl_msg *m;

	fx_setup(&f, 0, 0, 0);
	s = open_stream(&f, S_LATER, 0, &c, 1);
	drive(f.c, &c.opened, 1, 3000);
	ATF_REQUIRE_EQ(1, c.opened);
	ATF_REQUIRE_EQ(0, c.open_error);
	ATF_REQUIRE_EQ(0, cbl_stream_msg_new(s, &m));
	cbl_put_uint(m, SA_SEQ, 0);
	ATF_REQUIRE_EQ(0, cbl_stream_send(s, m));
	drive(f.c, &c.data, 1, 3000);
	ATF_REQUIRE_EQ(1, c.data);
	ATF_REQUIRE_EQ(0, cbl_stream_reset(s, 0));
	drive(f.c, &c.closed, 1, 3000);

	(void)open_stream(&f, S_LATER, 0, &c, 2);
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.opened);
	ATF_REQUIRE_EQ(EACCES, c.open_error);
	ATF_REQUIRE_EQ(1, c.closed);
	fx_teardown(&f);
}

/* A stream kept with cbl_stream_ref() answers EPIPE once it ended. */
ATF_TC_WITHOUT_HEAD(stream_ref);
ATF_TC_BODY(stream_ref, tc)
{
	struct fx f;
	struct cli c;
	cbl_stream *s;
	cbl_msg *m;

	fx_setup(&f, 0, 0, 0);
	s = open_stream(&f, S_CHAT, 0, &c, 0);
	cbl_stream_ref(s);
	drive(f.c, &c.opened, 1, 3000);
	ATF_REQUIRE_EQ(0, cbl_stream_reset(s, 0));
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_EQ(0, cbl_stream_msg_new(s, &m));
	ATF_REQUIRE_EQ(EPIPE, cbl_stream_send(s, m));
	ATF_REQUIRE_EQ(EPIPE, cbl_stream_half_close(s));
	ATF_REQUIRE_EQ(EPIPE, cbl_stream_reset(s, 0));
	cbl_stream_rele(s);
	fx_teardown(&f);
}

/* Send one data frame, the last one when "last". */
static void
send_one(cbl_stream *s, bool last)
{
	cbl_msg *m;

	ATF_REQUIRE_EQ(0, cbl_stream_msg_new(s, &m));
	cbl_put_uint(m, SA_SEQ, 0);
	if (last)
		ATF_REQUIRE_EQ(0, cbl_msg_set_flags(m,
		    CBL_F_S_DATA | CBL_F_S_HCLOSE));
	ATF_REQUIRE_EQ(0, cbl_stream_send(s, m));
}

/*
 * The server resets the stream from on_data, for a frame that also
 * half-closes: the stream is not used afterwards, and on_hclose does not
 * run for a stream the application already reset.
 */
ATF_TC_WITHOUT_HEAD(reset_in_on_data);
ATF_TC_BODY(reset_in_on_data, tc)
{
	struct fx f;
	struct cli c;
	cbl_stream *s;

	fx_setup(&f, 0, 0, 0);
	s = open_stream(&f, S_RESETDATA, 0, &c, 0);
	drive(f.c, &c.opened, 1, 3000);
	ATF_REQUIRE_EQ(0, c.open_error);
	send_one(s, true);
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_EQ(EBADMSG, c.close_code);
	wait_for(&f.sv.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, f.sv.closed);
	ATF_REQUIRE_EQ(EBADMSG, f.sv.close_code);
	ATF_REQUIRE_EQ(1, f.sv.received);
	ATF_REQUIRE_EQ(0, f.sv.hclosed);
	fx_teardown(&f);
}

/* The server's last frame, sent from on_data, ends the stream there. */
ATF_TC_WITHOUT_HEAD(last_send_in_on_data);
ATF_TC_BODY(last_send_in_on_data, tc)
{
	struct fx f;
	struct cli c;
	cbl_stream *s;

	fx_setup(&f, 0, 0, 0);
	s = open_stream(&f, S_LASTDATA, 0, &c, 0);
	drive(f.c, &c.opened, 1, 3000);
	ATF_REQUIRE_EQ(0, c.open_error);
	send_one(s, true);
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.data);
	ATF_REQUIRE_EQ(1, c.hclosed);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_EQ(0, c.close_code);
	wait_for(&f.sv.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, f.sv.closed);
	ATF_REQUIRE_EQ(0, f.sv.close_code);
	fx_teardown(&f);
}

/* The client resets from on_open, when its open is refused. */
ATF_TC_WITHOUT_HEAD(reset_in_on_open);
ATF_TC_BODY(reset_in_on_open, tc)
{
	struct fx f;
	struct cli c;

	fx_setup(&f, 0, 0, 0);
	(void)open_stream(&f, S_REJECT, 0, &c, 0);
	c.reset_in = RESET_ON_OPEN;
	drive(f.c, &c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.opened);
	ATF_REQUIRE_EQ(EACCES, c.open_error);
	ATF_REQUIRE_EQ(1, c.closed);
	fx_teardown(&f);
}

/* The client resets from on_writable, when credit comes back. */
ATF_TC_WITHOUT_HEAD(reset_in_on_writable);
ATF_TC_BODY(reset_in_on_writable, tc)
{
	struct fx f;
	struct cli c;
	cbl_stream *s;
	cbl_msg *m;
	int error;

	fx_setup(&f, 1024, 0, 0);
	s = open_stream(&f, S_CHAT, 0, &c, 0);
	drive(f.c, &c.opened, 1, 3000);
	ATF_REQUIRE_EQ(0, c.open_error);
	c.reset_in = RESET_ON_WRITABLE;
	for (int i = 0; i < 100; i++) {
		ATF_REQUIRE_EQ(0, cbl_stream_msg_new(s, &m));
		cbl_put_uint(m, SA_SEQ, (uint64_t)i);
		cbl_put_bytes(m, SA_PAD, "0123456789abcdef0123456789abcdef",
		    32);
		if ((error = cbl_stream_send(s, m)) == EAGAIN) {
			cbl_msg_free(m);
			break;
		}
		ATF_REQUIRE_EQ(0, error);
	}
	drive(f.c, &c.closed, 1, 5000);
	ATF_REQUIRE(c.writable >= 1);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_EQ(ECANCELED, c.close_code);
	wait_for(&f.sv.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, f.sv.closed);
	fx_teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, echo);
	ATF_TP_ADD_TC(tp, push);
	ATF_TP_ADD_TC(tp, rejected);
	ATF_TP_ADD_TC(tp, flow_control);
	ATF_TP_ADD_TC(tp, close_handshake);
	ATF_TP_ADD_TC(tp, max_streams);
	ATF_TP_ADD_TC(tp, open_timeout);
	ATF_TP_ADD_TC(tp, protocol_violations);
	ATF_TP_ADD_TC(tp, cross_thread);
	ATF_TP_ADD_TC(tp, reset_in_on_data);
	ATF_TP_ADD_TC(tp, last_send_in_on_data);
	ATF_TP_ADD_TC(tp, reset_in_on_open);
	ATF_TP_ADD_TC(tp, reset_in_on_writable);
	ATF_TP_ADD_TC(tp, accept_wrong_seq);
	ATF_TP_ADD_TC(tp, deferred_open);
	ATF_TP_ADD_TC(tp, stream_ref);
	return (atf_no_error());
}
