/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Schema mount (RFC 8528): mntdemo's hosts, each with a mount point,
 * dsdemo's cfg mounted below one.  The structs round-trip through
 * YANG-CBOR, the mounted keyed by absolute SIDs (tag 47); JSON names
 * them as at the top; the instance tree reads and writes them; the
 * validator looks inside.  A tag-47 key in an ordinary map is taken.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_data.h>
#include <cbl_schema.h>

#include "ymnth.h"

static const struct cbl_ymodule *
module(const char *name)
{

	for (uint32_t i = 0; i < ymnth_schema.nmod; i++)
		if (strcmp(ymnth_schema.mod[i]->name, name) == 0)
			return (ymnth_schema.mod[i]);
	atf_tc_fail("no module %s", name);
}

static const struct cbl_ynode *
top(const char *mod)
{

	return (module(mod)->top[0]);
}

/* host "a", its data dsdemo's cfg { a = 5, b = "x" }, kind given. */
static void
build(struct mntdemo *m, cbl_yarena *a, int kind)
{
	struct mntdemo_hosts *h;
	struct mntdemo_hosts_host *e;
	struct mntdemo_hosts_host_data *d;
	struct dsdemo_cfg *c;
	struct dsdemo *ds;
	const struct cbl_ynode *n_data;

	ATF_REQUIRE((h = cbl_yarena_alloc(a, sizeof(*h))) != NULL);
	ATF_REQUIRE((e = cbl_yarena_alloc(a, sizeof(*e))) != NULL);
	ATF_REQUIRE((d = cbl_yarena_alloc(a, sizeof(*d))) != NULL);
	ATF_REQUIRE((c = cbl_yarena_alloc(a, sizeof(*c))) != NULL);
	memset(h, 0, sizeof(*h));
	memset(e, 0, sizeof(*e));
	memset(d, 0, sizeof(*d));
	memset(c, 0, sizeof(*c));
	c->has_a = true;
	c->a = 5;
	c->b = "x";
	c->has_kind = true;
	c->kind = (enum dsdemo_cfg_kind)kind;
	n_data = top("mntdemo")->child[0]->child[0];
	ATF_REQUIRE_STREQ("data", n_data->name);
	ATF_REQUIRE((n_data->flags & CBL_YNF_MOUNT) != 0);
	ATF_REQUIRE((ds = cbl_ymount_data(n_data, d, module("dsdemo"),
	    a)) != NULL);
	ds->cfg = c;
	ATF_CHECK(cbl_ymount_data(n_data, d, module("dsdemo"), a) == ds);
	e->name = "a";
	e->data = d;
	h->host.n = 1;
	h->host.v = e;
	memset(m, 0, sizeof(*m));
	m->hosts = h;
}

ATF_TC_WITHOUT_HEAD(codec);
ATF_TC_BODY(codec, tc)
{
	const struct cbl_ynode *n_hosts = top("mntdemo");
	const struct cbl_ynode *n_data = n_hosts->child[0]->child[0];
	struct cbl_ybuf b = { NULL, 0, 0 }, b2 = { NULL, 0, 0 };
	struct mntdemo m, back;
	const struct dsdemo *ds;
	cbl_yarena *a;
	char why[160];

	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	build(&m, a, DSDEMO_CFG_KIND_PLAIN);
	ATF_REQUIRE_EQ(0, cbl_yencode_member(n_hosts, &m, &b));
	/* The mounted key: tag 47 (0xd8 0x2f), then dsdemo:cfg's SID. */
	ATF_CHECK(memmem(b.p, b.len, "\xd8\x2f", 2) != NULL);
	memset(&back, 0, sizeof(back));
	ATF_REQUIRE_EQ_MSG(0, cbl_ydecode_member(n_hosts, b.p, b.len, &back, a,
	    CBL_YD_STRICT, why, sizeof(why)), "%s", why);
	ATF_REQUIRE(back.hosts != NULL && back.hosts->host.n == 1);
	ATF_CHECK_STREQ("a", back.hosts->host.v[0].name);
	ATF_REQUIRE((ds = cbl_ymount_find(n_data, back.hosts->host.v[0].data,
	    module("dsdemo"))) != NULL);
	ATF_REQUIRE(ds->cfg != NULL);
	ATF_CHECK_EQ(5, ds->cfg->a);
	ATF_CHECK_STREQ("x", ds->cfg->b);
	ATF_REQUIRE_EQ(0, cbl_yencode_member(n_hosts, &back, &b2));
	ATF_CHECK(b.len == b2.len && memcmp(b.p, b2.p, b.len) == 0);
	cbl_ybuf_free(&b);
	cbl_ybuf_free(&b2);
	cbl_yarena_free(a);
}

ATF_TC_WITHOUT_HEAD(json);
ATF_TC_BODY(json, tc)
{
	struct cbl_ybuf b = { NULL, 0, 0 };
	struct mntdemo m;
	cbl_yarena *a;
	char *s;

	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	build(&m, a, DSDEMO_CFG_KIND_PLAIN);
	ATF_REQUIRE_EQ(0, cbl_yjson_module(module("mntdemo"), &m, &b));
	ATF_REQUIRE((s = strndup((const char *)b.p, b.len)) != NULL);
	ATF_CHECK_MSG(strstr(s, "\"data\":{\"dsdemo:cfg\":{\"a\":5,\"b\":\"x\"")
	    != NULL, "%s", s);
	free(s);
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
}

ATF_TC_WITHOUT_HEAD(tree);
ATF_TC_BODY(tree, tc)
{
	const struct cbl_ynode *n_hosts = top("mntdemo");
	struct cbl_ybuf in = { NULL, 0, 0 }, out = { NULL, 0, 0 };
	struct mntdemo m;
	const cbl_dnode *x;
	cbl_dtree *t;
	cbl_yarena *a;
	char why[160];

	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	build(&m, a, DSDEMO_CFG_KIND_PLAIN);
	ATF_REQUIRE_EQ(0, cbl_yencode_member(n_hosts, &m, &in));
	ATF_REQUIRE((t = cbl_dtree_new(&ymnth_schema)) != NULL);
	ATF_REQUIRE_EQ_MSG(0, cbl_dnode_decode(cbl_dtree_root(t), n_hosts,
	    in.p, in.len, CBL_YD_STRICT, why, sizeof(why), NULL), "%s", why);
	/* hosts/host/data/dsdemo:cfg, a node of the tree. */
	x = cbl_dnode_first(cbl_dtree_root(t));
	ATF_REQUIRE(x != NULL);
	x = cbl_dnode_first(x);			/* host a */
	ATF_REQUIRE(x != NULL);
	for (x = cbl_dnode_first(x); x != NULL &&
	    strcmp(cbl_dnode_schema(x)->name, "data") != 0;
	    x = cbl_dnode_next(x))
		;
	ATF_REQUIRE(x != NULL);
	x = cbl_dnode_first(x);
	ATF_REQUIRE(x != NULL);
	ATF_CHECK_STREQ("cfg", cbl_dnode_schema(x)->name);
	ATF_CHECK_STREQ("dsdemo", cbl_dnode_schema(x)->module->name);
	ATF_REQUIRE_EQ(0, cbl_dtree_encode(t, &out));
	ATF_CHECK(out.len > 0 && memmem(out.p, out.len, in.p + 1,
	    in.len - 1) != NULL);
	cbl_dtree_free(t);
	cbl_ybuf_free(&in);
	cbl_ybuf_free(&out);
	cbl_yarena_free(a);
}

ATF_TC_WITHOUT_HEAD(validate);
ATF_TC_BODY(validate, tc)
{
	struct cbl_yverr err;
	struct mntdemo m;
	cbl_yarena *a;

	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	build(&m, a, DSDEMO_CFG_KIND_PLAIN);
	ATF_CHECK_EQ(0, cbl_yvalidate_member(top("mntdemo"), &m, 0, &err));
	/* An enum of no value, mounted: found. */
	build(&m, a, 99);
	ATF_CHECK_EQ(EINVAL, cbl_yvalidate_member(top("mntdemo"), &m, 0,
	    &err));
	ATF_CHECK_MSG(strstr(err.msg, "kind") != NULL, "%s", err.msg);
	cbl_yarena_free(a);
}

/* A container's child keyed by its absolute SID, tag 47: taken. */
ATF_TC_WITHOUT_HEAD(absolute_key);
ATF_TC_BODY(absolute_key, tc)
{
	const struct cbl_ynode *n_cfg = top("dsdemo");
	const struct cbl_ynode *n_a = NULL;
	struct dsdemo_cfg c;
	uint8_t buf[16];
	size_t len = 0;
	cbl_yarena *a;
	char why[160];

	for (uint32_t i = 0; i < n_cfg->nchild; i++)
		if (strcmp(n_cfg->child[i]->name, "a") == 0)
			n_a = n_cfg->child[i];
	ATF_REQUIRE(n_a != NULL && n_a->sid <= UINT32_MAX);
	buf[len++] = 0xa1;			/* a map of one */
	buf[len++] = 0xd8;			/* tag 47 */
	buf[len++] = 0x2f;
	buf[len++] = 0x1a;			/* the SID, four bytes */
	buf[len++] = (uint8_t)(n_a->sid >> 24);
	buf[len++] = (uint8_t)(n_a->sid >> 16);
	buf[len++] = (uint8_t)(n_a->sid >> 8);
	buf[len++] = (uint8_t)n_a->sid;
	buf[len++] = 0x07;			/* 7 */
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ_MSG(0, cbl_ydecode(n_cfg, buf, len, &c, a,
	    CBL_YD_STRICT, why, sizeof(why)), "%s", why);
	ATF_CHECK(c.has_a && c.a == 7);
	cbl_yarena_free(a);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, codec);
	ATF_TP_ADD_TC(tp, json);
	ATF_TP_ADD_TC(tp, tree);
	ATF_TP_ADD_TC(tp, validate);
	ATF_TP_ADD_TC(tp, absolute_key);
	return (atf_no_error());
}
