/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Family 1's subscriptions over a connection (cbl_ysub.c): a server of
 * subdemo's tables with ietf-subscribed-notifications, ietf-yang-push
 * and ietf-datastores, its counters read by a handler that counts the
 * reads; a client on a loop of its own that opens SUBSCRIBE streams and
 * keeps what they bring.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cbl_net_test.h"
#include "ysubh.h"

static const struct cbl_ynode *n_counters, *n_other, *n_alert, *n_est,
    *n_est_in, *n_est_out, *n_pu;
static atomic_uint ticks;

static const struct cbl_ynode *
top(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ysubh_schema.nmod; i++) {
		const struct cbl_ymodule *m = ysubh_schema.mod[i];

		if (strcmp(m->name, mod) != 0)
			continue;
		for (uint32_t j = 0; j < m->ntop; j++)
			if (strcmp(m->top[j]->name, name) == 0)
				return (m->top[j]);
	}
	atf_tc_fail("no %s:%s", mod, name);
}

static const struct cbl_ynode *
io(const struct cbl_ynode *rpc, int kind)
{

	for (uint32_t i = 0; i < rpc->nchild; i++)
		if (rpc->child[i]->kind == kind)
			return (rpc->child[i]);
	atf_tc_fail("no input or output under %s", rpc->name);
}

static uint64_t
ident(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ysubh_schema.nident; i++)
		if (strcmp(ysubh_schema.ident[i].name, name) == 0 &&
		    strcmp(ysubh_schema.ident[i].module->name, mod) == 0)
			return (ysubh_schema.ident[i].sid);
	atf_tc_fail("no identity %s:%s", mod, name);
}

/* The ports counters has: em0, em1 where it is there; em0's octets. */
static atomic_bool em1, counters_fail;
static atomic_uint_fast64_t em0_octets;

/* counters: ticks counts the reads. */
static int
counters_get(cbl_req *req, void *data, cbl_yarena *a)
{
	struct subdemo_counters *c;
	struct subdemo_counters_port *p;

	(void)req;
	if (atomic_load(&counters_fail))
		return (EIO);
	if ((c = cbl_yarena_alloc(a, sizeof(*c))) == NULL ||
	    (p = cbl_yarena_alloc(a, 2 * sizeof(*p))) == NULL)
		return (ENOMEM);
	c->has_ticks = true;
	c->ticks = atomic_fetch_add(&ticks, 1) + 1;
	p[0].name = "em0";
	p[0].has_octets = true;
	p[0].octets = atomic_load(&em0_octets);
	p[1].name = "em1";
	p[1].has_octets = true;
	p[1].octets = 0;
	c->port.n = atomic_load(&em1) ? 2 : 1;
	c->port.v = p;
	((struct subdemo *)data)->counters = c;
	return (0);
}

static int
other_get(cbl_req *req, void *data, cbl_yarena *a)
{
	struct subdemo_other *o;

	(void)req;
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	o->note = "left out";
	((struct subdemo *)data)->other = o;
	return (0);
}

/* modify-subscription and resync-subscription, as a program serves
 * them: cblink's. */
static int
modify_rpc(cbl_req *req, const void *in, void *out, cbl_yarena *a)
{

	(void)out;
	(void)a;
	return (cbl_ysub_modify(req, in));
}

static int
resync_rpc(cbl_req *req, const void *in, void *out, cbl_yarena *a)
{

	(void)out;
	(void)a;
	return (cbl_ysub_resync(req,
	    ((const struct ietf_yang_push_resync_subscription_input *)in)->id));
}

/* The alerts kept, two, a minute and a half and a minute old; and,
 * with missed set, one kept just now (a configured subscription's
 * receiver missed it). */
static struct timespec kept_at[2];
static atomic_bool missed;

static int
replay(const struct timespec *from, struct cbl_ysub_replay *r, void *arg)
{
	static const struct subdemo_alert kept[2] = {
		{ .level = "high", .text = "old 1" },
		{ .level = "low", .text = "old 2" },
	};
	static const struct subdemo_alert late = { .level = "high",
	    .text = "missed" };
	struct timespec now;

	(void)from;
	(void)arg;
	cbl_ysub_replay_oldest(r, &kept_at[0]);
	for (int i = 0; i < 2; i++)
		ATF_REQUIRE_EQ(0, cbl_ysub_replay_emit(r, n_alert, &kept[i],
		    &kept_at[i]));
	if (atomic_load(&missed)) {
		clock_gettime(CLOCK_REALTIME, &now);
		ATF_REQUIRE_EQ(0, cbl_ysub_replay_emit(r, n_alert, &late,
		    &now));
	}
	cbl_ysub_replay_live(r);
	return (0);
}

static struct cbl_yhandler handlers[4];
static struct cbl_yserver server = { .schema = &ysubh_schema };

static int
hcmp(const void *a, const void *b)
{
	const struct cbl_yhandler *x = a, *y = b;

	return ((x->sid > y->sid) - (x->sid < y->sid));
}

/* The client's view of one subscription. */
struct cli {
	pthread_mutex_t	 mtx;
	atomic_int	 opened;
	atomic_int	 open_error;
	char		 open_text[128];
	uint32_t	 id;
	atomic_int	 arrived;	/* data frames, decoded or not */
	atomic_int	 records;
	char		*json[16];	/* the records, as RFC 7951 JSON */
	const char	*kind[16];	/* each one's notification */
	char		*when[16];	/* and event-time */
	atomic_int	 closed;
	char		 close_text[64];
};

static void
cli_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{
	struct ietf_subscribed_notifications_establish_subscription_output o;
	struct cli *c = arg;
	cbl_yarena *a;

	(void)s;
	if (error != 0) {
		if (accept != NULL && cbl_msg_err_str(accept) != NULL)
			strlcpy(c->open_text, cbl_msg_err_str(accept),
			    sizeof(c->open_text));
		c->open_error = error;
	} else if ((a = cbl_yarena_new()) != NULL) {
		memset(&o, 0, sizeof(o));
		if (cbl_msg_ydecode(accept, n_est_out, &o, a, CBL_YD_STRICT,
		    NULL, 0) == 0)
			c->id = o.id;
		cbl_yarena_free(a);
	}
	c->opened++;
}

static void
cli_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct cli *c = arg;
	struct cbl_ynotif nt;
	struct cbl_ybuf b = { 0 };
	const struct cbl_ynode *n;
	cbl_yarena *a;
	void *p;

	(void)s;
	c->arrived++;
	if ((a = cbl_yarena_new()) == NULL)
		return;
	if (cbl_msg_ynotif(data, &nt, a) == 0 &&
	    (n = cbl_yschema_node(&ysubh_schema, nt.sid)) != NULL &&
	    (p = cbl_yarena_alloc(a, n->size)) != NULL &&
	    cbl_ydecode(n, nt.content, nt.len, p, a, CBL_YD_STRICT, NULL,
	    0) == 0 && cbl_yjson(n, p, &b) == 0) {
		pthread_mutex_lock(&c->mtx);
		if (c->records < (int)nitems(c->json)) {
			c->json[c->records] = strndup((const char *)b.p,
			    b.len);
			c->kind[c->records] = n->name;
			c->when[c->records] = strdup(nt.event_time);
		}
		c->records++;
		pthread_mutex_unlock(&c->mtx);
	}
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
}

static void
cli_close(cbl_stream *s, int code, const char *text, void *arg)
{
	struct cli *c = arg;

	(void)s;
	(void)code;
	if (text != NULL)
		strlcpy(c->close_text, text, sizeof(c->close_text));
	c->closed++;
}

static const struct cbl_stream_cbs cli_cbs = {
	.on_open = cli_open,
	.on_data = cli_data,
	.on_close = cli_close,
};

struct fixture {
	cbl_ctx			*sctx;
	cbl_ctx			*cctx;
	struct test_server	 ts;
	cbl_conn		*c;
	cbl_loop		*loop;
	pthread_t		 lt;
};

static void *
loop_thread(void *arg)
{

	(void)cbl_loop_run(arg);
	return (NULL);
}

static void
setup(struct fixture *f)
{

	n_counters = top("subdemo", "counters");
	n_other = top("subdemo", "other");
	n_alert = top("subdemo", "alert");
	n_est = top("ietf-subscribed-notifications", "establish-subscription");
	n_est_in = io(n_est, CBL_YN_INPUT);
	n_est_out = io(n_est, CBL_YN_OUTPUT);
	n_pu = top("ietf-yang-push", "push-update");
	handlers[0] = (struct cbl_yhandler){ n_counters->sid, counters_get,
	    NULL, NULL, NULL };
	handlers[1] = (struct cbl_yhandler){ n_other->sid, other_get, NULL,
	    NULL, NULL };
	handlers[2] = (struct cbl_yhandler){ top("ietf-subscribed-notifications",
	    "modify-subscription")->sid, NULL, NULL, modify_rpc, NULL };
	handlers[3] = (struct cbl_yhandler){ top("ietf-yang-push",
	    "resync-subscription")->sid, NULL, NULL, resync_rpc, NULL };
	qsort(handlers, nitems(handlers), sizeof(handlers[0]), hcmp);
	server.nhandler = nitems(handlers);
	server.handler = handlers;
	atomic_store(&ticks, 0);
	atomic_store(&em1, false);
	atomic_store(&counters_fail, false);
	atomic_store(&em0_octets, 1500);

	f->sctx = test_ctx();
	f->cctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_yserver_add(f->sctx, &server, NULL));
	clock_gettime(CLOCK_REALTIME, &kept_at[0]);
	kept_at[0].tv_sec -= 90;
	kept_at[1] = kept_at[0];
	kept_at[1].tv_sec += 30;
	ATF_REQUIRE_EQ(0, cbl_ysub_set_replay(f->sctx, replay, NULL));
	test_server_start(&f->ts, f->sctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT);
	ATF_REQUIRE_EQ(0, cbl_conn_new(f->cctx, f->ts.uri, CBL_PLAINTEXT,
	    &f->c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(f->c));
	ATF_REQUIRE_EQ(0, cbl_loop_new(f->cctx, &f->loop));
	ATF_REQUIRE_EQ(0, cbl_conn_attach(f->c, f->loop));
	ATF_REQUIRE_EQ(0, pthread_create(&f->lt, NULL, loop_thread, f->loop));
}

static void
teardown(struct fixture *f)
{

	cbl_loop_stop(f->loop);
	pthread_join(f->lt, NULL);
	cbl_conn_free(f->c);
	cbl_loop_free(f->loop);
	test_server_stop(&f->ts);
	/* A subscription's thread lets its connection go a moment later. */
	for (int i = 0; i < 200 && cbl_ctx_free(f->sctx) == EBUSY; i++)
		usleep(10000);
	cbl_ctx_free(f->cctx);
}

static void
wait_for(atomic_int *flag, int want, int ms)
{

	for (int i = 0; i < ms / 5 && *flag < want; i++)
		usleep(5000);
}

static void
cli_init(struct cli *c)
{

	memset(c, 0, sizeof(*c));
	pthread_mutex_init(&c->mtx, NULL);
}

static void
cli_fini(struct cli *c)
{

	for (size_t i = 0; i < nitems(c->json); i++) {
		free(c->json[i]);
		free(c->when[i]);
	}
	pthread_mutex_destroy(&c->mtx);
}

typedef struct ietf_subscribed_notifications_establish_subscription_input
    est_in;
typedef struct ietf_subscribed_notifications_establish_subscription_input_yp_periodic
    est_per;
#define	SN(x)	IETF_SUBSCRIBED_NOTIFICATIONS_ESTABLISH_SUBSCRIPTION_INPUT_##x

/* establish-subscription's input: the NETCONF stream, filtered. */
static void
for_stream(est_in *in, const char *stream, const char *xpath)
{

	memset(in, 0, sizeof(*in));
	in->target = SN(TARGET_STREAM);
	in->stream = stream;
	if (xpath != NULL) {
		in->stream_filter = SN(STREAM_FILTER_WITHIN_SUBSCRIPTION);
		in->filter_spec = SN(FILTER_SPEC_STREAM_XPATH_FILTER);
		in->stream_xpath_filter = xpath;
	}
}

/* A datastore's, filtered, periodic where period is not 0. */
static void
for_datastore(est_in *in, const char *ds, const char *xpath, est_per *per,
    uint32_t period)
{

	memset(in, 0, sizeof(*in));
	in->target = SN(TARGET_DATASTORE);
	in->has_yp_datastore = true;
	in->yp_datastore = ident("ietf-datastores", ds);
	if (xpath != NULL) {
		in->yp_selection_filter =
		    SN(YP_SELECTION_FILTER_WITHIN_SUBSCRIPTION);
		in->yp_filter_spec = SN(YP_FILTER_SPEC_DATASTORE_XPATH_FILTER);
		in->yp_datastore_xpath_filter = xpath;
	}
	if (period != 0) {
		memset(per, 0, sizeof(*per));
		per->has_period = true;
		per->period = period;
		in->yp_update_trigger = SN(YP_UPDATE_TRIGGER_PERIODIC);
		in->yp_periodic = per;
	}
}

/* SUBSCRIBE with in: the stream, its open waited for. */
static cbl_stream *
subscribe(struct fixture *f, const est_in *in, struct cli *c)
{
	cbl_stream *s;
	cbl_msg *m;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, CBL_YANG_FAMILY,
	    CBL_YCMD_SUBSCRIBE, 0, &m));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, n_est_in, in));
	ATF_REQUIRE_EQ(0, cbl_stream_open(f->c, m, CBL_SF_PUSH, &cli_cbs, c,
	    &s));
	wait_for(&c->opened, 1, 3000);
	ATF_REQUIRE_EQ(1, c->opened);
	return (s);
}

ATF_TC_WITHOUT_HEAD(periodic);
ATF_TC_BODY(periodic, tc)
{
	struct fixture f;
	struct cli c;
	est_per per;
	est_in in;
	cbl_stream *s;

	setup(&f);
	cli_init(&c);
	for_datastore(&in, "operational", "/subdemo:counters", &per, 10);
	s = subscribe(&f, &in, &c);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	ATF_REQUIRE(c.id >= 1);
	/* A push at once, then every tenth of a second. */
	wait_for(&c.records, 3, 3000);
	ATF_REQUIRE_MSG(c.records >= 3, "%d records of %d frames",
	    (int)c.records, (int)c.arrived);
	pthread_mutex_lock(&c.mtx);
	/* Members in SID order; the id the accept gave. */
	ATF_REQUIRE_MATCH("^\\{\"datastore-contents\":\\{\"subdemo:counters\":"
	    "\\{\"port\":\\[\\{\"name\":\"em0\",\"octets\":\"1500\"\\}\\],"
	    "\"ticks\":1\\}\\},\"id\":[0-9]+\\}$", c.json[0]);
	ATF_REQUIRE_MATCH("\"ticks\":2\\}", c.json[1]);
	/* other is not what the filter asks for: not read, not pushed. */
	ATF_REQUIRE(strstr(c.json[1], "other") == NULL);
	pthread_mutex_unlock(&c.mtx);
	ATF_REQUIRE_EQ(0, cbl_stream_close(s, 0, NULL));
	wait_for(&c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.closed);
	cli_fini(&c);
	teardown(&f);
}

ATF_TC_WITHOUT_HEAD(stream);
ATF_TC_BODY(stream, tc)
{
	struct subdemo_alert low = { .level = "low", .text = "a" };
	struct subdemo_alert high = { .level = "high", .text = "b" };
	struct fixture f;
	struct cli c, all;
	cbl_stream *s, *s2;
	est_in in;

	setup(&f);
	cli_init(&c);
	cli_init(&all);
	for_stream(&in, "NETCONF", "/subdemo:alert[level='high']");
	s = subscribe(&f, &in, &c);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	for_stream(&in, "NETCONF", NULL);
	s2 = subscribe(&f, &in, &all);
	ATF_REQUIRE_EQ_MSG(0, all.open_error, "%s", all.open_text);
	ATF_REQUIRE(all.id != c.id);
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &low));
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &high));
	wait_for(&all.records, 2, 3000);
	wait_for(&c.records, 1, 3000);
	usleep(100000);
	ATF_REQUIRE_EQ(2, all.records);
	ATF_REQUIRE_EQ(1, c.records);
	ATF_REQUIRE_STREQ("{\"level\":\"high\",\"text\":\"b\"}", c.json[0]);
	ATF_REQUIRE_STREQ("{\"level\":\"low\",\"text\":\"a\"}", all.json[0]);
	ATF_REQUIRE_EQ(0, cbl_stream_close(s, 0, NULL));
	ATF_REQUIRE_EQ(0, cbl_stream_close(s2, 0, NULL));
	wait_for(&c.closed, 1, 3000);
	wait_for(&all.closed, 1, 3000);
	cli_fini(&c);
	cli_fini(&all);
	teardown(&f);
}

/*
 * On-change: the first read pushed whole (sync-on-start), then what
 * changed as a YANG Patch: a port made and another's octets changed in
 * one, the port gone in the next.
 */
ATF_TC_WITHOUT_HEAD(on_change);
ATF_TC_BODY(on_change, tc)
{
	struct ietf_subscribed_notifications_establish_subscription_input_yp_on_change
	    oc = { 0 };
	struct fixture f;
	struct cli c;
	est_per per;
	est_in in;
	cbl_stream *s;

	setup(&f);
	cli_init(&c);
	for_datastore(&in, "operational", "/subdemo:counters/port", &per, 0);
	in.yp_update_trigger = SN(YP_UPDATE_TRIGGER_ON_CHANGE);
	in.yp_on_change = &oc;
	s = subscribe(&f, &in, &c);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	wait_for(&c.records, 1, 3000);
	ATF_REQUIRE_EQ(1, c.records);
	ATF_REQUIRE_MATCH("^\\{\"datastore-contents\":\\{\"subdemo:counters\":"
	    "\\{\"port\":\\[\\{\"name\":\"em0\",\"octets\":\"1500\"\\}\\]\\}"
	    "\\},\"id\":[0-9]+\\}$", c.json[0]);
	/* Nothing changes: nothing pushed, though ticks does. */
	usleep(1300000);
	ATF_REQUIRE_EQ(1, c.records);
	atomic_store(&em1, true);
	atomic_store(&em0_octets, 3000);
	wait_for(&c.records, 2, 3000);
	ATF_REQUIRE_EQ(2, c.records);
	pthread_mutex_lock(&c.mtx);
	ATF_REQUIRE_MATCH("\"edit\":\\[", c.json[1]);
	ATF_REQUIRE_MATCH("\\{\"edit-id\":\"[0-9]+\",\"operation\":"
	    "\"replace\",\"target\":\"/subdemo:counters/port=em0/octets\","
	    "\"value\":\\{\"subdemo:octets\":\"3000\"\\}\\}", c.json[1]);
	ATF_REQUIRE_MATCH("\\{\"edit-id\":\"[0-9]+\",\"operation\":"
	    "\"create\",\"target\":\"/subdemo:counters/port=em1\","
	    "\"value\":\\{\"subdemo:port\":\\[\\{\"name\":\"em1\","
	    "\"octets\":\"0\"\\}\\]\\}\\}", c.json[1]);
	pthread_mutex_unlock(&c.mtx);
	atomic_store(&em1, false);
	wait_for(&c.records, 3, 3000);
	ATF_REQUIRE_EQ(3, c.records);
	ATF_REQUIRE_MATCH("\\{\"edit-id\":\"1\",\"operation\":\"delete\","
	    "\"target\":\"/subdemo:counters/port=em1\"\\}\\]", c.json[2]);
	ATF_REQUIRE_EQ(0, cbl_stream_close(s, 0, NULL));
	wait_for(&c.closed, 1, 3000);
	cli_fini(&c);
	teardown(&f);
}

/* Told what changes: read when told, not every period. */
ATF_TC_WITHOUT_HEAD(told);
ATF_TC_BODY(told, tc)
{
	struct ietf_subscribed_notifications_establish_subscription_input_yp_on_change
	    oc = { 0 };
	const struct cbl_ynode *tops[1];
	struct fixture f;
	struct cli c;
	est_per per;
	est_in in;
	unsigned t;

	setup(&f);
	tops[0] = n_counters;
	ATF_REQUIRE_EQ(0, cbl_ysub_told(f.sctx, tops, 1));
	cli_init(&c);
	for_datastore(&in, "operational", "/subdemo:counters/port", &per, 0);
	in.yp_update_trigger = SN(YP_UPDATE_TRIGGER_ON_CHANGE);
	in.yp_on_change = &oc;
	(void)subscribe(&f, &in, &c);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	wait_for(&c.records, 1, 3000);
	ATF_REQUIRE_EQ(1, c.records);
	/* Changed, not told: not read again. */
	t = atomic_load(&ticks);
	atomic_store(&em0_octets, 3000);
	usleep(2300000);
	ATF_REQUIRE_EQ(1, c.records);
	ATF_REQUIRE_EQ(t, atomic_load(&ticks));
	/* Another node's news: nothing still. */
	cbl_ysub_changed(f.sctx, n_other);
	usleep(1300000);
	ATF_REQUIRE_EQ(1, c.records);
	cbl_ysub_changed(f.sctx, n_counters);
	wait_for(&c.records, 2, 3000);
	ATF_REQUIRE_EQ(2, c.records);
	ATF_REQUIRE_MATCH("\"target\":\"/subdemo:counters/port=em0/octets\"",
	    c.json[1]);
	/* Told while its read fails: read again at the next tick, untold,
	 * once it reads. */
	atomic_store(&counters_fail, true);
	atomic_store(&em0_octets, 4500);
	cbl_ysub_changed(f.sctx, n_counters);
	usleep(1300000);
	ATF_REQUIRE_EQ(2, c.records);
	atomic_store(&counters_fail, false);
	wait_for(&c.records, 3, 3000);
	ATF_REQUIRE_EQ(3, c.records);
	ATF_REQUIRE_MATCH("\"subdemo:octets\":\"4500\"", c.json[2]);
	cli_fini(&c);
	teardown(&f);
}

/* What is refused at the open, and why. */
static void
refused_by(struct fixture *f, const est_in *in, const char *why)
{
	struct cli c;

	cli_init(&c);
	(void)subscribe(f, in, &c);
	ATF_CHECK(c.open_error != 0);
	ATF_CHECK_MATCH_MSG(why, c.open_text, "%s, not %s", c.open_text,
	    why);
	cli_fini(&c);
}

ATF_TC_WITHOUT_HEAD(refused);
ATF_TC_BODY(refused, tc)
{
	struct fixture f;
	est_per per;
	est_in in;

	setup(&f);
	for_stream(&in, "other", NULL);
	refused_by(&f, &in, "no such stream");
	for_datastore(&in, "operational", NULL, &per, 0);
	refused_by(&f, &in, "needs a period");
	for_datastore(&in, "operational", NULL, &per, 5);
	refused_by(&f, &in, "10 centiseconds");
	for_datastore(&in, "running", NULL, &per, 100);
	refused_by(&f, &in, "operational");
	for_datastore(&in, "operational", "/subdemo:counters[", &per, 100);
	refused_by(&f, &in, ".");
	for_datastore(&in, "operational", NULL, &per, 100);
	in.stop_time = "2000-01-01T00:00:00Z";
	refused_by(&f, &in, "stop-time has passed");
	for_datastore(&in, "operational", NULL, &per, 100);
	in.has_encoding = true;
	in.encoding = ident("ietf-subscribed-notifications", "encoding");
	refused_by(&f, &in, "encoding: not supported");
	teardown(&f);
}

/* A stop-time ends it: the stream closed, the subscription gone. */
ATF_TC_WITHOUT_HEAD(stop_time);
ATF_TC_BODY(stop_time, tc)
{
	char stop[32];
	struct fixture f;
	struct cli c;
	struct tm tm;
	est_per per;
	est_in in;
	time_t t;

	setup(&f);
	cli_init(&c);
	t = time(NULL) + 2;
	gmtime_r(&t, &tm);
	strftime(stop, sizeof(stop), "%Y-%m-%dT%H:%M:%SZ", &tm);
	for_datastore(&in, "operational", NULL, &per, 10);
	in.stop_time = stop;
	(void)subscribe(&f, &in, &c);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	wait_for(&c.closed, 1, 4000);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_STREQ("stop-time reached", c.close_text);
	ATF_REQUIRE(c.records >= 1);
	cli_fini(&c);
	teardown(&f);
}

/* An rpc of the modules, its input in, over the client's connection. */
static int
call_rpc(struct fixture *f, const char *mod, const char *name, const void *in)
{
	cbl_msg *m, *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, CBL_YANG_FAMILY, CBL_YCMD_RPC,
	    0, &m));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, io(top(mod, name),
	    CBL_YN_INPUT), in));
	error = cbl_request(f->c, m, &r, 5000);
	if (error != 0 && r != NULL && cbl_msg_err_str(r) != NULL)
		fprintf(stderr, "%s: %s\n", name, cbl_msg_err_str(r));
	cbl_msg_free(r);
	return (error);
}

/* Whether record i is notification name; how many records name is. */
static int
kinds(struct cli *c, const char *name)
{
	int n = 0;

	pthread_mutex_lock(&c->mtx);
	for (int i = 0; i < c->records && i < 16; i++)
		n += c->kind[i] != NULL && strcmp(c->kind[i], name) == 0;
	pthread_mutex_unlock(&c->mtx);
	return (n);
}

/*
 * A subscriber that does not read: records left out, the subscription
 * suspended; once it reads, told subscription-suspended and -resumed,
 * and the pushes go on.
 */
static int
info_of(const struct cbl_ysub_info *in, void *arg)
{

	*(struct cbl_ysub_info *)arg = *in;
	((struct cbl_ysub_info *)arg)->stream = NULL;
	((struct cbl_ysub_info *)arg)->xpath = NULL;
	((struct cbl_ysub_info *)arg)->receiver = NULL;
	((struct cbl_ysub_info *)arg)->anchor_time = NULL;
	((struct cbl_ysub_info *)arg)->stop_time = NULL;
	return (0);
}

ATF_TC_WITHOUT_HEAD(suspend);
ATF_TC_BODY(suspend, tc)
{
	static const struct cbl_stream_cbs mcbs = {
		.on_open = cli_open,
		.on_data = cli_data,
		.on_close = cli_close,
	};
	struct cbl_ysub_info inf;
	struct fixture f;
	struct cli c;
	est_per per;
	est_in in;
	cbl_stream *s;
	cbl_msg *m;

	setup(&f);
	cli_init(&c);
	for_datastore(&in, "operational", "/subdemo:counters", &per, 10);
	ATF_REQUIRE_EQ(0, cbl_msg_new(f.cctx, CBL_YANG_FAMILY,
	    CBL_YCMD_SUBSCRIBE, 0, &m));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, n_est_in, &in));
	/* Room for two records, given back by hand alone. */
	ATF_REQUIRE_EQ(0, cbl_msg_set_window(m, 512));
	ATF_REQUIRE_EQ(0, cbl_stream_open(f.c, m, CBL_SF_PUSH |
	    CBL_SF_MANUAL_CREDIT, &mcbs, &c, &s));
	wait_for(&c.opened, 1, 3000);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	usleep(800000);
	memset(&inf, 0, sizeof(inf));
	ATF_REQUIRE_EQ(0, cbl_ysub_each(f.sctx, info_of, &inf));
	ATF_REQUIRE(inf.suspended);
	ATF_REQUIRE(inf.excluded > 0);
	ATF_REQUIRE(c.records < 8);
	/* Read now: the state notifications, then pushes again. */
	ATF_REQUIRE_EQ(0, cbl_stream_consumed(s, 64 * 1024));
	for (int i = 0; i < 300 && kinds(&c, "subscription-resumed") == 0; i++)
		usleep(10000);
	ATF_REQUIRE_EQ(0, cbl_stream_consumed(s, 64 * 1024));
	usleep(300000);
	ATF_REQUIRE_EQ(1, kinds(&c, "subscription-suspended"));
	ATF_REQUIRE_EQ(1, kinds(&c, "subscription-resumed"));
	pthread_mutex_lock(&c.mtx);
	for (int i = 0; i < c.records && i < 16; i++)
		if (strcmp(c.kind[i], "subscription-suspended") == 0) {
			ATF_REQUIRE_MATCH("\"reason\":"
			    "\"ietf-subscribed-notifications:unsupportable-volume\"",
			    c.json[i]);
			ATF_REQUIRE(i + 1 < c.records && strcmp(c.kind[i + 1],
			    "subscription-resumed") == 0);
		}
	pthread_mutex_unlock(&c.mtx);
	memset(&inf, 0, sizeof(inf));
	ATF_REQUIRE_EQ(0, cbl_ysub_each(f.sctx, info_of, &inf));
	ATF_REQUIRE(!inf.suspended);
	ATF_REQUIRE_EQ(0, cbl_stream_close(s, 0, NULL));
	wait_for(&c.closed, 1, 3000);
	cli_fini(&c);
	teardown(&f);
}

/*
 * Replay: the alerts kept since replay-start-time, each at its own
 * time, then replay-completed, then what comes live; the output says
 * where the replay began when the log begins later than asked.
 */
ATF_TC_WITHOUT_HEAD(replay);
ATF_TC_BODY(replay, tc)
{
	struct subdemo_alert live = { .level = "high", .text = "now" };
	struct fixture f;
	struct cli c;
	char from[32], want[32];
	struct tm tm;
	time_t t;
	est_in in;

	setup(&f);
	cli_init(&c);
	t = time(NULL) - 3600;
	gmtime_r(&t, &tm);
	strftime(from, sizeof(from), "%Y-%m-%dT%H:%M:%SZ", &tm);
	for_stream(&in, "NETCONF", NULL);
	in.replay_start_time = from;
	(void)subscribe(&f, &in, &c);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &live));
	wait_for(&c.records, 4, 3000);
	ATF_REQUIRE_EQ(4, c.records);
	pthread_mutex_lock(&c.mtx);
	ATF_REQUIRE_STREQ("alert", c.kind[0]);
	ATF_REQUIRE_STREQ("{\"level\":\"high\",\"text\":\"old 1\"}", c.json[0]);
	gmtime_r(&kept_at[0].tv_sec, &tm);
	strftime(want, sizeof(want), "%Y-%m-%dT%H:%M:%S", &tm);
	ATF_REQUIRE(strncmp(c.when[0], want, strlen(want)) == 0);
	ATF_REQUIRE_STREQ("{\"level\":\"low\",\"text\":\"old 2\"}", c.json[1]);
	ATF_REQUIRE_STREQ("replay-completed", c.kind[2]);
	ATF_REQUIRE_STREQ("{\"level\":\"high\",\"text\":\"now\"}", c.json[3]);
	pthread_mutex_unlock(&c.mtx);
	cli_fini(&c);
	teardown(&f);
}

/* modify-subscription: the filter changed, told subscription-modified. */
ATF_TC_WITHOUT_HEAD(modify);
ATF_TC_BODY(modify, tc)
{
	struct ietf_subscribed_notifications_modify_subscription_input mi;
	struct subdemo_alert low = { .level = "low", .text = "a" };
	struct subdemo_alert high = { .level = "high", .text = "b" };
	struct fixture f;
	struct cli c;
	est_in in;

	setup(&f);
	cli_init(&c);
	for_stream(&in, "NETCONF", "/subdemo:alert[level='high']");
	(void)subscribe(&f, &in, &c);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	memset(&mi, 0, sizeof(mi));
	mi.has_id = true;
	mi.id = c.id;
	mi.target = IETF_SUBSCRIBED_NOTIFICATIONS_MODIFY_SUBSCRIPTION_INPUT_TARGET_STREAM;
	mi.stream_filter =
	    IETF_SUBSCRIBED_NOTIFICATIONS_MODIFY_SUBSCRIPTION_INPUT_STREAM_FILTER_WITHIN_SUBSCRIPTION;
	mi.filter_spec =
	    IETF_SUBSCRIBED_NOTIFICATIONS_MODIFY_SUBSCRIPTION_INPUT_FILTER_SPEC_STREAM_XPATH_FILTER;
	mi.stream_xpath_filter = "/subdemo:alert[level='low']";
	ATF_REQUIRE_EQ(0, call_rpc(&f, "ietf-subscribed-notifications",
	    "modify-subscription", &mi));
	wait_for(&c.records, 1, 3000);
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &high));
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &low));
	wait_for(&c.records, 2, 3000);
	usleep(100000);
	ATF_REQUIRE_EQ(2, c.records);
	pthread_mutex_lock(&c.mtx);
	ATF_REQUIRE_STREQ("subscription-modified", c.kind[0]);
	ATF_REQUIRE_MATCH("\"stream-xpath-filter\":\"/subdemo:alert\\[level='low'\\]\"",
	    c.json[0]);
	ATF_REQUIRE_STREQ("{\"level\":\"low\",\"text\":\"a\"}", c.json[1]);
	pthread_mutex_unlock(&c.mtx);
	/* Another connection's, or none: refused. */
	mi.id = c.id + 100;
	ATF_REQUIRE(call_rpc(&f, "ietf-subscribed-notifications",
	    "modify-subscription", &mi) != 0);
	cli_fini(&c);
	teardown(&f);
}

/* resync-subscription: an on-change subscription pushes it whole again. */
ATF_TC_WITHOUT_HEAD(resync);
ATF_TC_BODY(resync, tc)
{
	struct ietf_yang_push_resync_subscription_input ri;
	struct ietf_subscribed_notifications_establish_subscription_input_yp_on_change
	    oc = { 0 };
	struct fixture f;
	struct cli c;
	est_per per;
	est_in in;

	setup(&f);
	cli_init(&c);
	for_datastore(&in, "operational", "/subdemo:counters/port", &per, 0);
	in.yp_update_trigger = SN(YP_UPDATE_TRIGGER_ON_CHANGE);
	in.yp_on_change = &oc;
	(void)subscribe(&f, &in, &c);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	wait_for(&c.records, 1, 3000);
	ATF_REQUIRE_EQ(1, c.records);
	memset(&ri, 0, sizeof(ri));
	ri.has_id = true;
	ri.id = c.id;
	ATF_REQUIRE_EQ(0, call_rpc(&f, "ietf-yang-push", "resync-subscription",
	    &ri));
	wait_for(&c.records, 2, 3000);
	ATF_REQUIRE_EQ(2, c.records);
	ATF_REQUIRE_EQ(2, kinds(&c, "push-update"));
	cli_fini(&c);
	teardown(&f);
}

/* What cbl_ysub_each() tells, copied: a configured subscription's
 * receivers' into a place that outlives the call. */
static struct cbl_ysub_rcv_info rcvs_kept[4][2];

static int
collect(const struct cbl_ysub_info *in, void *arg)
{
	struct cbl_ysub_info *v = arg;

	for (int i = 0; i < 4; i++)
		if (v[i].id == 0) {
			v[i] = *in;
			v[i].stream = v[i].xpath = v[i].receiver = NULL;
			v[i].nrcvs = in->nrcvs < 2 ? in->nrcvs : 2;
			for (size_t k = 0; k < v[i].nrcvs; k++) {
				rcvs_kept[i][k] = in->rcvs[k];
				rcvs_kept[i][k].name = NULL;
				rcvs_kept[i][k].instance = NULL;
			}
			v[i].rcvs = rcvs_kept[i];
			return (0);
		}
	return (ENOSPC);
}

/* Listed while they run; kill ends one, its stream closed. */
ATF_TC_WITHOUT_HEAD(each_kill);
ATF_TC_BODY(each_kill, tc)
{
	struct cbl_ysub_info v[4];
	struct fixture f;
	struct cli c;
	est_in in;

	setup(&f);
	cli_init(&c);
	for_stream(&in, "NETCONF", NULL);
	(void)subscribe(&f, &in, &c);
	ATF_REQUIRE_EQ_MSG(0, c.open_error, "%s", c.open_text);
	memset(v, 0, sizeof(v));
	ATF_REQUIRE_EQ(0, cbl_ysub_each(f.sctx, collect, v));
	ATF_REQUIRE_EQ(c.id, v[0].id);
	ATF_REQUIRE_EQ(0, v[1].id);
	ATF_REQUIRE_EQ(ENOENT, cbl_ysub_kill(f.sctx, c.id + 100));
	ATF_REQUIRE_EQ(0, cbl_ysub_kill(f.sctx, c.id));
	wait_for(&c.closed, 1, 3000);
	ATF_REQUIRE_EQ(1, c.closed);
	ATF_REQUIRE_STREQ("killed", c.close_text);
	memset(v, 0, sizeof(v));
	ATF_REQUIRE_EQ(0, cbl_ysub_each(f.sctx, collect, v));
	ATF_REQUIRE_EQ(0, v[0].id);
	cli_fini(&c);
	teardown(&f);
}

/*
 * A stand-in transport for the configured subscriptions: what it is
 * told, as the client keeps it; down, it refuses to connect and fails
 * a send.
 */
static struct cli tr_cli;
static atomic_bool tr_down;
static atomic_int tr_connects, tr_disconnects;
static char tr_name[32], tr_instance[32];

static int
tr_connect(struct cbl_ysub_rcv *r, void *arg)
{

	ATF_REQUIRE_EQ(arg, (void *)&tr_cli);
	strlcpy(tr_name, r->name, sizeof(tr_name));
	strlcpy(tr_instance, r->instance != NULL ? r->instance : "",
	    sizeof(tr_instance));
	if (atomic_load(&tr_down))
		return (ECONNREFUSED);
	r->arg = tr_name;
	tr_connects++;
	return (0);
}

static int
tr_send(struct cbl_ysub_rcv *r, uint64_t sid, const uint8_t *content,
    size_t len, const struct timespec *when, void *arg)
{
	struct cli *c = arg;
	struct cbl_ybuf b = { 0 };
	const struct cbl_ynode *n;
	cbl_yarena *a;
	struct tm tm;
	char buf[32];
	void *p;
	ATF_REQUIRE_EQ(r->arg, (void *)tr_name);
	if (atomic_load(&tr_down))
		return (EPIPE);
	c->arrived++;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((n = cbl_yschema_node(&ysubh_schema, sid)) != NULL &&
	    (p = cbl_yarena_alloc(a, n->size)) != NULL &&
	    cbl_ydecode(n, content, len, p, a, CBL_YD_STRICT, NULL, 0) == 0 &&
	    cbl_yjson(n, p, &b) == 0) {
		gmtime_r(&when->tv_sec, &tm);
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
		pthread_mutex_lock(&c->mtx);
		if (c->records < (int)nitems(c->json)) {
			c->json[c->records] = strndup((const char *)b.p,
			    b.len);
			c->kind[c->records] = n->name;
			c->when[c->records] = strdup(buf);
		}
		c->records++;
		pthread_mutex_unlock(&c->mtx);
	}
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
	return (0);
}

static void
tr_disconnect(struct cbl_ysub_rcv *r, void *arg)
{

	(void)arg;
	ATF_REQUIRE_EQ(r->arg, (void *)tr_name);
	tr_disconnects++;
}

static const struct cbl_ysub_transport tr = {
	.connect = tr_connect,
	.send = tr_send,
	.disconnect = tr_disconnect,
};

typedef struct ietf_subscribed_notifications_subscriptions_subscription
    cfg_sub;
#define	CS(x)	IETF_SUBSCRIBED_NOTIFICATIONS_SUBSCRIPTIONS_SUBSCRIPTION_##x

/* running's subscriptions: one of id, the NETCONF stream filtered by
 * xpath, replayed to a receiver connected again, to receiver "console"
 * (no receiver instance: that module is the program's); told to the
 * server. */
static int
configure(struct fixture *f, uint32_t id, const char *xpath, bool replay_it,
    char *why, size_t whylen)
{
	struct ietf_subscribed_notifications data = { 0 };
	struct ietf_subscribed_notifications_subscriptions subs = { 0 };
	struct ietf_subscribed_notifications_subscriptions_subscription_receivers
	    rs = { 0 };
	struct ietf_subscribed_notifications_subscriptions_subscription_receivers_receiver
	    r = { .name = "console" };
	cfg_sub s = { 0 };

	s.id = id;
	s.target = CS(TARGET_STREAM);
	s.stream = "NETCONF";
	if (xpath != NULL) {
		s.stream_filter = CS(STREAM_FILTER_WITHIN_SUBSCRIPTION);
		s.filter_spec = CS(FILTER_SPEC_STREAM_XPATH_FILTER);
		s.stream_xpath_filter = xpath;
	}
	s.configured_replay = replay_it;
	rs.receiver.n = 1;
	rs.receiver.v = &r;
	s.receivers = &rs;
	subs.subscription.n = id != 0 ? 1 : 0;
	subs.subscription.v = &s;
	data.subscriptions = &subs;
	return (cbl_ysub_configure(f->sctx, top("ietf-subscribed-notifications",
	    "subscriptions"), &data, why, whylen));
}

/*
 * A configured subscription made by the configuration: its receiver
 * connected and told subscription-started, the stream's records sent
 * it; down, what it misses is excluded, connected again it is told
 * subscription-started with the time of the last record it had, what
 * was kept since replayed, then replay-completed; a change of the
 * filter told subscription-modified; taken out of the configuration,
 * subscription-terminated and disconnected.
 */
ATF_TC_WITHOUT_HEAD(configured);
ATF_TC_BODY(configured, tc)
{
	struct subdemo_alert live = { .level = "high", .text = "now" };
	struct subdemo_alert lost = { .level = "high", .text = "lost" };
	struct subdemo_alert low = { .level = "low", .text = "quiet" };
	struct cbl_ysub_info v[4];
	struct fixture f;
	char why[160];

	setup(&f);
	cli_init(&tr_cli);
	atomic_store(&tr_down, false);
	atomic_store(&missed, false);
	tr_connects = tr_disconnects = 0;
	ATF_REQUIRE_EQ(0, cbl_ysub_set_transport(f.sctx, &tr, &tr_cli));
	/* Refused: no receiver, a bad filter; nothing is made. */
	{
		struct ietf_subscribed_notifications data = { 0 };
		struct ietf_subscribed_notifications_subscriptions subs = { 0 };
		cfg_sub s = { .id = 3, .target = CS(TARGET_STREAM),
		    .stream = "NETCONF" };

		subs.subscription.n = 1;
		subs.subscription.v = &s;
		data.subscriptions = &subs;
		int error = cbl_ysub_configure(f.sctx,
		    top("ietf-subscribed-notifications", "subscriptions"),
		    &data, why, sizeof(why));

		ATF_REQUIRE_EQ_MSG(EINVAL, error, "%d: %s", error, why);
		ATF_REQUIRE_MATCH("subscription 3: .*receiver", why);
	}
	ATF_REQUIRE_EQ_MSG(EINVAL, configure(&f, 7, "/subdemo:alert[", true,
	    why, sizeof(why)), "%s", why);
	ATF_REQUIRE_MATCH("subscription 7: ", why);
	memset(v, 0, sizeof(v));
	ATF_REQUIRE_EQ(0, cbl_ysub_each(f.sctx, collect, v));
	ATF_REQUIRE_EQ(0, v[0].id);
	/* Made: connected, started; a record of the stream sent. */
	ATF_REQUIRE_EQ_MSG(0, configure(&f, 7, NULL, true, why, sizeof(why)),
	    "%s", why);
	/* A replay from when it was made first: nothing kept since, told
	 * complete. */
	wait_for(&tr_cli.records, 2, 3000);
	ATF_REQUIRE_EQ(2, tr_cli.records);
	ATF_REQUIRE_STREQ("console", tr_name);
	ATF_REQUIRE_STREQ("", tr_instance);
	ATF_REQUIRE_STREQ("subscription-started", tr_cli.kind[0]);
	ATF_REQUIRE_MATCH("\"id\":7,.*\"stream\":\"NETCONF\"", tr_cli.json[0]);
	ATF_REQUIRE_STREQ("replay-completed", tr_cli.kind[1]);
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &live));
	wait_for(&tr_cli.records, 3, 3000);
	ATF_REQUIRE_EQ(3, tr_cli.records);
	ATF_REQUIRE_STREQ("{\"level\":\"high\",\"text\":\"now\"}",
	    tr_cli.json[2]);
	ATF_REQUIRE_EQ(0, cbl_ysub_each(f.sctx, collect, v));
	ATF_REQUIRE_EQ(7, v[0].id);
	ATF_REQUIRE(v[0].configured);
	ATF_REQUIRE_EQ(1, v[0].nrcvs);
	ATF_REQUIRE_EQ(CBL_YSUB_RCV_ACTIVE, v[0].rcvs[0].state);
	ATF_REQUIRE_EQ(3, v[0].rcvs[0].sent);
	/* Down: the send fails, the receiver disconnected; what comes
	 * meanwhile is excluded.  Up again a second on: started, with
	 * the last record's time, what was kept since replayed. */
	atomic_store(&tr_down, true);
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &lost));
	wait_for(&tr_disconnects, 1, 3000);
	ATF_REQUIRE_EQ(1, tr_disconnects);
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &lost));
	usleep(100000);
	memset(v, 0, sizeof(v));
	ATF_REQUIRE_EQ(0, cbl_ysub_each(f.sctx, collect, v));
	ATF_REQUIRE_EQ(CBL_YSUB_RCV_CONNECTING, v[0].rcvs[0].state);
	ATF_REQUIRE(v[0].rcvs[0].excluded >= 1);
	atomic_store(&missed, true);
	atomic_store(&tr_down, false);
	wait_for(&tr_cli.records, 6, 5000);
	ATF_REQUIRE_EQ(6, tr_cli.records);
	ATF_REQUIRE_EQ(2, tr_connects);
	ATF_REQUIRE_STREQ("subscription-started", tr_cli.kind[3]);
	ATF_REQUIRE_MATCH("\"replay-previous-event-time\":\"20", tr_cli.json[3]);
	ATF_REQUIRE_STREQ("{\"level\":\"high\",\"text\":\"missed\"}",
	    tr_cli.json[4]);
	ATF_REQUIRE_STREQ("replay-completed", tr_cli.kind[5]);
	/* The filter changed: told subscription-modified; what the filter
	 * leaves out is not sent. */
	ATF_REQUIRE_EQ_MSG(0, configure(&f, 7, "/subdemo:alert[level='high']",
	    true, why, sizeof(why)), "%s", why);
	wait_for(&tr_cli.records, 7, 3000);
	ATF_REQUIRE_EQ(7, tr_cli.records);
	ATF_REQUIRE_STREQ("subscription-modified", tr_cli.kind[6]);
	ATF_REQUIRE_MATCH("\"stream-xpath-filter\":\"/subdemo:alert",
	    tr_cli.json[6]);
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &low));
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alert, &live));
	wait_for(&tr_cli.records, 8, 3000);
	usleep(100000);
	ATF_REQUIRE_EQ(8, tr_cli.records);
	ATF_REQUIRE_STREQ("{\"level\":\"high\",\"text\":\"now\"}",
	    tr_cli.json[7]);
	/* The same again: nothing happens. */
	ATF_REQUIRE_EQ_MSG(0, configure(&f, 7, "/subdemo:alert[level='high']",
	    true, why, sizeof(why)), "%s", why);
	usleep(100000);
	ATF_REQUIRE_EQ(8, tr_cli.records);
	ATF_REQUIRE_EQ(2, tr_connects);
	/* Taken out: terminated, disconnected, gone from the list. */
	ATF_REQUIRE_EQ_MSG(0, configure(&f, 0, NULL, false, why, sizeof(why)),
	    "%s", why);
	wait_for(&tr_disconnects, 2, 3000);
	ATF_REQUIRE_EQ(2, tr_disconnects);
	ATF_REQUIRE_EQ(9, tr_cli.records);
	ATF_REQUIRE_STREQ("subscription-terminated", tr_cli.kind[8]);
	ATF_REQUIRE_MATCH("no-such-subscription", tr_cli.json[8]);
	memset(v, 0, sizeof(v));
	ATF_REQUIRE_EQ(0, cbl_ysub_each(f.sctx, collect, v));
	ATF_REQUIRE_EQ(0, v[0].id);
	cli_fini(&tr_cli);
	teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, configured);
	ATF_TP_ADD_TC(tp, periodic);
	ATF_TP_ADD_TC(tp, stream);
	ATF_TP_ADD_TC(tp, on_change);
	ATF_TP_ADD_TC(tp, told);
	ATF_TP_ADD_TC(tp, suspend);
	ATF_TP_ADD_TC(tp, replay);
	ATF_TP_ADD_TC(tp, modify);
	ATF_TP_ADD_TC(tp, resync);
	ATF_TP_ADD_TC(tp, refused);
	ATF_TP_ADD_TC(tp, stop_time);
	ATF_TP_ADD_TC(tp, each_kill);
	return (atf_no_error());
}
