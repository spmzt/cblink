/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Family 1's datastores over a connection: a server of dsdemo's cfg,
 * running changed by a confirmed commit alone (CBL_YDS_CONFIRMED), and a
 * client that edits the candidate, reads both, and commits: plainly,
 * confirmed and undone at its timeout, confirmed by a persist-id from
 * another session, undone with its session or by cancel-commit, an undo
 * that fails told; a value its handler warns of first, refused unless
 * accepted, and one it warns of after, in the answer.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cbl_net_test.h"
#include "ydsh.h"

static const struct cbl_ynode *n_cfg, *n_commit, *n_cancel, *n_discard;

/* cfg as the handlers keep it. */
static struct {
	bool	 have;
	int32_t	 a;
	char	 b[32];
	uint32_t hits;
	int	 undo_fails;	/* how often an undo failed */
	int	 edits;		/* how often the handler was asked */
} kept;

static const struct cbl_ynode *
top(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ydsh_schema.nmod; i++) {
		const struct cbl_ymodule *m = ydsh_schema.mod[i];

		if (strcmp(m->name, mod) != 0)
			continue;
		for (uint32_t j = 0; j < m->ntop; j++)
			if (strcmp(m->top[j]->name, name) == 0)
				return (m->top[j]);
	}
	atf_tc_fail("no %s:%s", mod, name);
}

static const struct cbl_ynode *
input_of(const struct cbl_ynode *rpc)
{

	for (uint32_t i = 0; i < rpc->nchild; i++)
		if (rpc->child[i]->kind == CBL_YN_INPUT)
			return (rpc->child[i]);
	atf_tc_fail("%s has no input", rpc->name);
}

static int
cfg_get(cbl_req *req, void *data, cbl_yarena *a)
{
	struct dsdemo *d = data;
	struct dsdemo_cfg *c;
	char *b;

	(void)req;
	kept.hits++;
	if (!kept.have)
		return (0);
	if ((c = cbl_yarena_alloc(a, sizeof(*c))) == NULL ||
	    (b = cbl_yarena_alloc(a, sizeof(kept.b))) == NULL)
		return (ENOMEM);
	memcpy(b, kept.b, sizeof(kept.b));
	c->has_a = true;
	c->a = kept.a;
	c->b = b[0] != '\0' ? b : NULL;
	c->has_hits = true;
	c->hits = kept.hits;
	d->cfg = c;
	return (0);
}

/*
 * a 13: refused unless the request accepts "thirteen"; a 7: done, the
 * requester told so; a 99 put back fails (an undo that fails).
 */
static int
cfg_edit(cbl_req *req, const void *before, const void *after)
{
	const struct dsdemo *b = before, *x = after;

	kept.edits++;
	if (x->cfg != NULL && x->cfg->has_a && x->cfg->a == 13 &&
	    !cbl_req_yaccepts(req, "thirteen")) {
		(void)cbl_req_set_yapptag(req, "thirteen");
		(void)cbl_req_set_err(req, "13 is unlucky: accept it", NULL, 0,
		    -1);
		return (EINVAL);
	}
	if (b->cfg != NULL && b->cfg->has_a && b->cfg->a == 99 &&
	    x->cfg != NULL && x->cfg->a != 99)
		return (EIO);
	kept.have = x->cfg != NULL;
	kept.a = x->cfg != NULL && x->cfg->has_a ? x->cfg->a : 0;
	(void)strlcpy(kept.b, x->cfg != NULL && x->cfg->b != NULL ? x->cfg->b :
	    "", sizeof(kept.b));
	if (kept.a == 7)
		(void)cbl_req_ywarn(req, n_cfg->sid, "seven",
		    "7 takes effect after a reboot");
	return (0);
}

static void
undo_failed(cbl_ctx *ctx, const struct cbl_ynode *n, int error,
    const char *why, void *arg)
{

	(void)ctx;
	(void)n;
	(void)why;
	(void)arg;
	ATF_CHECK_EQ(EIO, error);
	kept.undo_fails++;
}

static struct cbl_yhandler handlers[1];
static struct cbl_yserver server = { .schema = &ydsh_schema };

struct fixture {
	cbl_ctx			*sctx;
	cbl_ctx			*cctx;
	struct test_server	 ts;
	cbl_conn		*c;
};

static cbl_conn *
dial(struct fixture *f)
{
	cbl_conn *c;

	ATF_REQUIRE_EQ(0, cbl_conn_new(f->cctx, f->ts.uri, CBL_PLAINTEXT, &c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(c));
	return (c);
}

static void
setup(struct fixture *f)
{

	n_cfg = top("dsdemo", "cfg");
	n_commit = top("ietf-netconf", "commit");
	n_cancel = top("ietf-netconf", "cancel-commit");
	n_discard = top("ietf-netconf", "discard-changes");
	handlers[0] = (struct cbl_yhandler){ n_cfg->sid, cfg_get, cfg_edit,
	    NULL, NULL };
	server.nhandler = nitems(handlers);
	server.handler = handlers;
	memset(&kept, 0, sizeof(kept));
	kept.have = true;
	kept.a = 1;

	f->sctx = test_ctx();
	f->cctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_yserver_add(f->sctx, &server, NULL));
	ATF_REQUIRE_EQ(0, cbl_ydatastores(f->sctx, CBL_YDS_CONFIRMED,
	    undo_failed, NULL));
	ATF_REQUIRE_EQ(EEXIST, cbl_ydatastores(f->sctx, 0, NULL, NULL));
	test_server_start(&f->ts, f->sctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT);
	f->c = dial(f);
}

static void
teardown(struct fixture *f)
{

	cbl_conn_free(f->c);
	test_server_stop(&f->ts);
	cbl_ctx_free(f->sctx);
	cbl_ctx_free(f->cctx);
}

/* EDIT cfg's a (and b) in datastore ds (-1: none said). */
static int
edit(struct fixture *f, cbl_conn *c, int ds, int32_t a)
{
	struct dsdemo_cfg cfg = { .has_a = true, .a = a, .b = "x" };
	struct dsdemo d = { .cfg = &cfg };
	cbl_msg *m, *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, CBL_YANG_FAMILY, CBL_YCMD_EDIT,
	    0, &m));
	if (ds >= 0)
		ATF_REQUIRE_EQ(0, cbl_msg_set_datastore(m,
		    (enum cbl_yds_name)ds));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_cfg, &d));
	error = cbl_request(c, m, &r, 5000);
	cbl_msg_free(r);
	return (error);
}

/* cfg's a as datastore ds has it; -1: none; and whether hits is there. */
static int32_t
get_a(struct fixture *f, enum cbl_yds_name ds, bool *hits)
{
	struct dsdemo d = { 0 };
	cbl_msg *m, *r;
	cbl_yarena *a;
	int32_t v = -1;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, CBL_YANG_FAMILY, CBL_YCMD_GET,
	    0, &m));
	ATF_REQUIRE_EQ(0, cbl_msg_set_datastore(m, ds));
	ATF_REQUIRE_EQ(0, cbl_msg_put_yget(m, &n_cfg->sid, 1));
	ATF_REQUIRE_EQ(0, cbl_request(f->c, m, &r, 5000));
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	if (cbl_msg_ydecode_member(r, n_cfg, &d, a, CBL_YD_STRICT, NULL,
	    0) == 0 && d.cfg != NULL && d.cfg->has_a)
		v = d.cfg->a;
	if (hits != NULL)
		*hits = d.cfg != NULL && d.cfg->has_hits;
	cbl_yarena_free(a);
	cbl_msg_free(r);
	return (v);
}

/* A commit over c: confirmed with timeout secs (0: not), persist and
 * persist-id as given; accepting tag (NULL: none); its reply into rp. */
static int
commit(struct fixture *f, cbl_conn *c, uint32_t secs, const char *persist,
    const char *pid, const char *tag, cbl_msg **rp)
{
	struct ietf_netconf_commit_input in = { .confirmed = secs > 0,
	    .has_confirm_timeout = secs > 0, .confirm_timeout = secs,
	    .persist = persist, .persist_id = pid };
	cbl_msg *m, *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, CBL_YANG_FAMILY, CBL_YCMD_RPC,
	    0, &m));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, input_of(n_commit), &in));
	if (tag != NULL)
		ATF_REQUIRE_EQ(0, cbl_msg_set_accept(m, &tag, 1));
	error = cbl_request(c, m, &r, 5000);
	if (rp != NULL)
		*rp = r;
	else
		cbl_msg_free(r);
	return (error);
}

static int
rpc0(struct fixture *f, const struct cbl_ynode *n, const char *pid)
{
	struct ietf_netconf_cancel_commit_input in = { .persist_id = pid };
	cbl_msg *m, *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, CBL_YANG_FAMILY, CBL_YCMD_RPC,
	    0, &m));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, input_of(n), &in));
	error = cbl_request(f->c, m, &r, 5000);
	cbl_msg_free(r);
	return (error);
}

/* Until the server has put cfg back to a, 5 s at most. */
static void
await_a(struct fixture *f, int32_t a)
{

	for (int i = 0; i < 100 && get_a(f, CBL_YDS_RUNNING, NULL) != a; i++)
		usleep(50000);
	ATF_CHECK_EQ(a, get_a(f, CBL_YDS_RUNNING, NULL));
}

/* The candidate edited and read, running as it was; committed; the
 * candidate forgotten by discard-changes; running not edited itself. */
ATF_TC_WITHOUT_HEAD(candidate);
ATF_TC_BODY(candidate, tc)
{
	struct fixture f;
	bool hits;

	setup(&f);
	ATF_CHECK_EQ(EACCES, edit(&f, f.c, -1, 5));
	ATF_CHECK_EQ(EACCES, edit(&f, f.c, CBL_YDS_RUNNING, 5));
	ATF_CHECK_EQ(EOPNOTSUPP, edit(&f, f.c, CBL_YDS_OPERATIONAL, 5));
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 5));
	ATF_CHECK_EQ(5, get_a(&f, CBL_YDS_CANDIDATE, &hits));
	ATF_CHECK(!hits);	/* configuration alone */
	ATF_CHECK_EQ(1, get_a(&f, CBL_YDS_RUNNING, &hits));
	ATF_CHECK(!hits);
	ATF_CHECK_EQ(1, get_a(&f, CBL_YDS_OPERATIONAL, &hits));
	ATF_CHECK(hits);
	ATF_REQUIRE_EQ(0, commit(&f, f.c, 0, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(5, kept.a);
	ATF_CHECK_EQ(5, get_a(&f, CBL_YDS_CANDIDATE, NULL));
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 6));
	ATF_REQUIRE_EQ(0, rpc0(&f, n_discard, NULL));
	ATF_CHECK_EQ(5, get_a(&f, CBL_YDS_CANDIDATE, NULL));
	ATF_CHECK_EQ(5, kept.a);
	teardown(&f);
}

/* Confirmed and let be: undone at its timeout. */
ATF_TC_WITHOUT_HEAD(timeout);
ATF_TC_BODY(timeout, tc)
{
	struct timespec until;
	struct fixture f;

	setup(&f);
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 8));
	ATF_REQUIRE_EQ(0, commit(&f, f.c, 1, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(8, kept.a);
	ATF_CHECK(cbl_ydatastore_pending(f.sctx, &until));
	await_a(&f, 1);
	ATF_CHECK(!cbl_ydatastore_pending(f.sctx, NULL));
	teardown(&f);
}

/* With persist: confirmed from another session by its persist-id, which
 * another commit without it may not do; it stays past the timeout. */
ATF_TC_WITHOUT_HEAD(persist);
ATF_TC_BODY(persist, tc)
{
	struct fixture f;
	cbl_conn *c2;

	setup(&f);
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 8));
	ATF_REQUIRE_EQ(0, commit(&f, f.c, 2, "p1", NULL, NULL, NULL));
	c2 = dial(&f);
	ATF_CHECK_EQ(EBUSY, commit(&f, c2, 0, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(0, commit(&f, c2, 0, NULL, "p1", NULL, NULL));
	ATF_CHECK(!cbl_ydatastore_pending(f.sctx, NULL));
	sleep(3);
	ATF_CHECK_EQ(8, get_a(&f, CBL_YDS_RUNNING, NULL));
	cbl_conn_free(c2);
	teardown(&f);
}

/* Without persist, its session gone: undone; cancel-commit undoes one at
 * once, by its persist-id. */
ATF_TC_WITHOUT_HEAD(cancel);
ATF_TC_BODY(cancel, tc)
{
	struct fixture f;
	cbl_conn *c2;

	setup(&f);
	c2 = dial(&f);
	ATF_REQUIRE_EQ(0, edit(&f, c2, CBL_YDS_CANDIDATE, 8));
	ATF_REQUIRE_EQ(0, commit(&f, c2, 600, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(8, kept.a);
	cbl_conn_free(c2);
	await_a(&f, 1);
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 9));
	ATF_REQUIRE_EQ(0, commit(&f, f.c, 600, "p2", NULL, NULL, NULL));
	ATF_CHECK_EQ(EACCES, rpc0(&f, n_cancel, "nope"));
	ATF_CHECK_EQ(0, rpc0(&f, n_cancel, "p2"));
	ATF_CHECK_EQ(1, get_a(&f, CBL_YDS_RUNNING, NULL));
	ATF_CHECK_EQ(ENOENT, rpc0(&f, n_cancel, "p2"));
	teardown(&f);
}

/* An undo the handler fails: told, the program's to deal with. */
ATF_TC_WITHOUT_HEAD(undo_fails);
ATF_TC_BODY(undo_fails, tc)
{
	struct fixture f;

	setup(&f);
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 99));
	ATF_REQUIRE_EQ(0, commit(&f, f.c, 1, NULL, NULL, NULL, NULL));
	for (int i = 0; i < 100 && kept.undo_fails == 0; i++)
		usleep(50000);
	ATF_CHECK_EQ(1, kept.undo_fails);
	ATF_CHECK_EQ(99, kept.a);
	ATF_CHECK(!cbl_ydatastore_pending(f.sctx, NULL));
	teardown(&f);
}

/* A warning first: refused with its app-tag, done when accepted; one
 * after: in the answer. */
ATF_TC_WITHOUT_HEAD(warnings);
ATF_TC_BODY(warnings, tc)
{
	const struct cbl_ywarning *w;
	struct fixture f;
	cbl_yarena *a;
	cbl_msg *r;
	size_t n;

	setup(&f);
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 13));
	r = NULL;
	ATF_CHECK_EQ(EINVAL, commit(&f, f.c, 0, NULL, NULL, NULL, &r));
	ATF_REQUIRE(r != NULL);
	ATF_CHECK_STREQ("thirteen", cbl_msg_err_apptag(r));
	cbl_msg_free(r);
	ATF_CHECK_EQ(1, kept.a);
	ATF_CHECK_EQ(0, commit(&f, f.c, 0, NULL, NULL, "thirteen", NULL));
	ATF_CHECK_EQ(13, kept.a);
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 7));
	r = NULL;
	ATF_REQUIRE_EQ(0, commit(&f, f.c, 0, NULL, NULL, NULL, &r));
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ(0, cbl_msg_ywarnings(r, a, &w, &n));
	ATF_REQUIRE_EQ(1u, n);
	ATF_CHECK_EQ(n_cfg->sid, w[0].sid);
	ATF_CHECK_STREQ("seven", w[0].tag);
	ATF_CHECK(strstr(w[0].text, "reboot") != NULL);
	cbl_yarena_free(a);
	cbl_msg_free(r);
	teardown(&f);
}

/* EDIT cfg as given into the candidate; the reply's text into msg. */
static int
edit_cfg(struct fixture *f, struct dsdemo_cfg *cfg, char *msg, size_t len)
{
	struct dsdemo d = { .cfg = cfg };
	cbl_msg *m, *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, CBL_YANG_FAMILY, CBL_YCMD_EDIT,
	    0, &m));
	ATF_REQUIRE_EQ(0, cbl_msg_set_datastore(m, CBL_YDS_CANDIDATE));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_cfg, &d));
	error = cbl_request(f->c, m, &r, 5000);
	(void)snprintf(msg, len, "%s", r != NULL && cbl_msg_err_str(r) !=
	    NULL ? cbl_msg_err_str(r) : "");
	cbl_msg_free(r);
	return (error);
}

/*
 * when and must of what is edited (RFC 7950 7.21.5, 7.5.3): a mandatory
 * leaf a when brings needed where it holds alone; a must's message; an
 * absent container's case not asked for.
 */
ATF_TC_WITHOUT_HEAD(conditions);
ATF_TC_BODY(conditions, tc)
{
	struct dsdemo_cfg cfg;
	struct fixture f;
	char msg[256];

	setup(&f);
	memset(&cfg, 0, sizeof(cfg));
	cfg.has_a = true;
	cfg.a = 2;
	cfg.has_kind = true;
	cfg.kind = DSDEMO_CFG_KIND_PLAIN;
	ATF_CHECK_EQ_MSG(0, edit_cfg(&f, &cfg, msg, sizeof(msg)), "%s", msg);
	cfg.kind = DSDEMO_CFG_KIND_TAGGED;
	ATF_CHECK_EQ(EINVAL, edit_cfg(&f, &cfg, msg, sizeof(msg)));
	ATF_CHECK_MSG(strstr(msg, "tag-id: mandatory, missing") != NULL, "%s",
	    msg);
	cfg.has_tag_id = true;
	cfg.tag_id = 100;
	ATF_CHECK_EQ_MSG(0, edit_cfg(&f, &cfg, msg, sizeof(msg)), "%s", msg);
	cfg.c = "nine char";
	ATF_CHECK_EQ(EINVAL, edit_cfg(&f, &cfg, msg, sizeof(msg)));
	ATF_CHECK_STREQ("c is 8 characters at most", msg);
	cfg.c = "eight ch";
	ATF_CHECK_EQ_MSG(0, edit_cfg(&f, &cfg, msg, sizeof(msg)), "%s", msg);
	teardown(&f);
}

/* A commit whose change fails: the handler asked once, the change
 * that failed not undone (RFC 6241 section 7.2 undoes the others). */
ATF_TC_WITHOUT_HEAD(failed_alone);
ATF_TC_BODY(failed_alone, tc)
{
	struct fixture f;

	setup(&f);
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 13));
	kept.edits = 0;
	ATF_CHECK_EQ(EINVAL, commit(&f, f.c, 0, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(1, kept.edits);
	ATF_CHECK_EQ(1, kept.a);
	teardown(&f);
}

/* An undo puts back what its commit's consent allowed: 13, accepted
 * once, is put back at the timeout without being asked again. */
ATF_TC_WITHOUT_HEAD(undo_accepts);
ATF_TC_BODY(undo_accepts, tc)
{
	struct fixture f;

	setup(&f);
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 13));
	ATF_REQUIRE_EQ(0, commit(&f, f.c, 0, NULL, NULL, "thirteen", NULL));
	ATF_REQUIRE_EQ(13, kept.a);
	ATF_REQUIRE_EQ(0, edit(&f, f.c, CBL_YDS_CANDIDATE, 5));
	ATF_REQUIRE_EQ(0, commit(&f, f.c, 1, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(5, kept.a);
	await_a(&f, 13);
	ATF_CHECK_EQ(0, kept.undo_fails);
	teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, candidate);
	ATF_TP_ADD_TC(tp, timeout);
	ATF_TP_ADD_TC(tp, persist);
	ATF_TP_ADD_TC(tp, cancel);
	ATF_TP_ADD_TC(tp, undo_fails);
	ATF_TP_ADD_TC(tp, warnings);
	ATF_TP_ADD_TC(tp, conditions);
	ATF_TP_ADD_TC(tp, undo_accepts);
	ATF_TP_ADD_TC(tp, failed_alone);
	return (atf_no_error());
}
