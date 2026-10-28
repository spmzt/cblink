/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The instance tree (cbl_data.h) on the tables of shapes, edits,
 * ietf-system and ietf-sid-file (yang_h_test's): built, walked and freed;
 * list entries by their keys, many of them; the order of what is added,
 * a configuration leaf-list's values once; a choice's cases never two;
 * defaults on demand and made; every struct through the tree and back to
 * the same bytes, and a module's data struct.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "cbl_data.h"
#include "yangh.h"
#include "yfill.h"

/* A schema node by its path of names: "ietf-system:system/ntp/server". */
static const struct cbl_ynode *
sn(const char *path)
{
	const struct cbl_ynode *const *k = NULL;
	const struct cbl_ynode *n = NULL;
	char buf[256], *p, *name;
	uint32_t nk = 0;

	strlcpy(buf, path, sizeof(buf));
	p = buf;
	name = strsep(&p, ":");
	for (uint32_t i = 0; i < yangh_schema.nmod; i++)
		if (strcmp(yangh_schema.mod[i]->name, name) == 0) {
			k = yangh_schema.mod[i]->top;
			nk = yangh_schema.mod[i]->ntop;
		}
	ATF_REQUIRE_MSG(k != NULL, "no module %s", name);
	while ((name = strsep(&p, "/")) != NULL) {
		n = NULL;
		for (uint32_t i = 0; i < nk; i++)
			if (strcmp(k[i]->name, name) == 0)
				n = k[i];
		ATF_REQUIRE_MSG(n != NULL, "%s: no %s", path, name);
		k = n->child;
		nk = n->nchild;
	}
	return (n);
}

static const char *
str(const cbl_dnode *n)
{

	return (*(const char *const *)cbl_dnode_value(n));
}

/* An ntp server entry, its name the key, with a udp address. */
static cbl_dnode *
ntp_server(cbl_dnode *ntp, const char *name)
{
	const struct cbl_ynode *server = sn("ietf-system:system/ntp/server");
	const void *keys[1] = { &name };
	/* inet:host, a union: its first member, an IPv4 address. */
	struct ietf_system_system_ntp_server_udp_address addr = {
		.which = 0, .v.m0 = "192.0.2.1"
	};
	cbl_dnode *e, *udp;

	ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(ntp, server, keys, &e));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(e,
	    sn("ietf-system:system/ntp/server/udp"), NULL, &udp));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(udp,
	    sn("ietf-system:system/ntp/server/udp/address"), &addr, NULL));
	return (e);
}

ATF_TC_WITHOUT_HEAD(build);
ATF_TC_BODY(build, tc)
{
	static const char *const abc[] = { "a", "b", "c" };
	const struct cbl_ynode *server = sn("ietf-system:system/ntp/server");
	const char *host = "edge1", *name;
	const void *keys[1] = { &name };
	cbl_dnode *root, *sys, *ntp, *x;
	bool off = false;
	cbl_dtree *t;
	int i;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	root = cbl_dtree_root(t);
	ATF_CHECK(cbl_dnode_schema(root) == NULL);
	ATF_CHECK(cbl_dnode_first(root) == NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(root, sn("ietf-system:system"), NULL,
	    &sys));
	ATF_CHECK_EQ(EEXIST, cbl_dnode_add(root, sn("ietf-system:system"),
	    NULL, NULL));
	/* Only where the schema has it, and a value for a leaf. */
	ATF_CHECK_EQ(EINVAL, cbl_dnode_add(root,
	    sn("ietf-system:system/hostname"), &host, NULL));
	ATF_CHECK_EQ(EINVAL, cbl_dnode_add(sys,
	    sn("ietf-system:system/hostname"), NULL, NULL));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(sys,
	    sn("ietf-system:system/hostname"), &host, &x));
	host = "changed";	/* the tree has its own copy */
	ATF_CHECK_STREQ("edge1", str(x));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(sys, sn("ietf-system:system/ntp"),
	    NULL, &ntp));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(ntp,
	    sn("ietf-system:system/ntp/enabled"), &off, NULL));

	/* Three servers, by their keys; a second "b" is refused. */
	ntp_server(ntp, "a");
	ntp_server(ntp, "b");
	ntp_server(ntp, "c");
	name = "b";
	ATF_CHECK_EQ(EEXIST, cbl_dnode_add_entry(ntp, server, keys, NULL));
	ATF_CHECK_EQ(EINVAL, cbl_dnode_add(ntp, server, NULL, NULL));
	ATF_REQUIRE((x = cbl_dnode_entry(ntp, server, keys)) != NULL);
	ATF_CHECK_STREQ("b", str(cbl_dnode_first(x)));
	/* A key is the entry's: not set, not taken away alone. */
	ATF_CHECK_EQ(EPERM, cbl_dnode_set(cbl_dnode_first(x), &host));
	ATF_CHECK_EQ(EPERM, cbl_dnode_remove(cbl_dnode_first(x)));
	ATF_CHECK_EQ(EPERM, cbl_dnode_remove(root));

	/* Walked: the children in schema order, the entries as added. */
	i = 0;
	for (x = cbl_dnode_first(ntp); x != NULL; x = cbl_dnode_next(x), i++)
		if (i == 0)
			ATF_CHECK_STREQ("enabled", cbl_dnode_schema(x)->name);
		else
			ATF_CHECK_STREQ(abc[i - 1], str(cbl_dnode_first(x)));
	ATF_CHECK_EQ(4, i);
	ATF_CHECK(cbl_dnode_parent(cbl_dnode_last(ntp)) == ntp);
	/* system, hostname, ntp, enabled, and three servers of 4 each. */
	ATF_CHECK_EQ(4 + 3 * 4, cbl_dtree_count(t));

	/* One taken away, with all below it. */
	name = "b";
	ATF_REQUIRE_EQ(0, cbl_dnode_remove(cbl_dnode_entry(ntp, server,
	    keys)));
	ATF_CHECK(cbl_dnode_entry(ntp, server, keys) == NULL);
	ATF_CHECK_EQ(4 + 2 * 4, cbl_dtree_count(t));
	name = "c";
	ATF_REQUIRE((x = cbl_dnode_entry(ntp, server, keys)) != NULL);
	ATF_CHECK_STREQ("a", str(cbl_dnode_first(cbl_dnode_prev(x))));
	/* And again under the same key. */
	ntp_server(ntp, "b");
	name = "b";
	ATF_CHECK(cbl_dnode_entry(ntp, server, keys) == cbl_dnode_last(ntp));
	cbl_dtree_free(t);
}

ATF_TC_WITHOUT_HEAD(many);
ATF_TC_BODY(many, tc)
{
	const struct cbl_ynode *server =
	    sn("ietf-system:system/dns-resolver/server");
	char names[5000][8];
	const char *name;
	const void *keys[1] = { &name };
	cbl_dnode *dns, *e;
	cbl_dtree *t;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t),
	    sn("ietf-system:system"), NULL, &e));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(e,
	    sn("ietf-system:system/dns-resolver"), NULL, &dns));
	for (int i = 0; i < 5000; i++) {
		snprintf(names[i], sizeof(names[i]), "s%d", i);
		name = names[i];
		ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(dns, server, keys, NULL));
	}
	for (int i = 0; i < 5000; i++) {
		name = names[i];
		ATF_REQUIRE((e = cbl_dnode_entry(dns, server, keys)) != NULL);
		ATF_CHECK_STREQ(names[i], str(cbl_dnode_first(e)));
		if (i % 2 == 0)
			ATF_REQUIRE_EQ(0, cbl_dnode_remove(e));
	}
	for (int i = 0; i < 5000; i++) {
		name = names[i];
		ATF_CHECK((cbl_dnode_entry(dns, server, keys) == NULL) ==
		    (i % 2 == 0));
	}
	/* system, dns-resolver, and 2500 entries with their keys. */
	ATF_CHECK_EQ(2 + 2500 * 2, cbl_dtree_count(t));
	cbl_dtree_free(t);
}

ATF_TC_WITHOUT_HEAD(leaflists);
ATF_TC_BODY(leaflists, tc)
{
	const struct cbl_ynode *search =
	    sn("ietf-system:system/dns-resolver/search");
	const char *v[] = { "x.example", "y.example", "z.example" }, *w;
	cbl_dnode *dns, *x;
	cbl_dtree *t;
	int i;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t),
	    sn("ietf-system:system"), NULL, &x));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(x,
	    sn("ietf-system:system/dns-resolver"), NULL, &dns));
	for (i = 0; i < 3; i++)
		ATF_REQUIRE_EQ(0, cbl_dnode_add(dns, search, &v[i], NULL));
	/* A configuration leaf-list's values once each. */
	ATF_CHECK_EQ(EEXIST, cbl_dnode_add(dns, search, &v[1], NULL));
	ATF_REQUIRE((x = cbl_dnode_llentry(dns, search, &v[1])) != NULL);
	ATF_CHECK_EQ(EEXIST, cbl_dnode_set(x, &v[2]));
	w = "w.example";
	ATF_REQUIRE_EQ(0, cbl_dnode_set(x, &w));
	ATF_CHECK(cbl_dnode_llentry(dns, search, &v[1]) == NULL);
	/* In the order added, the one set where it was. */
	i = 0;
	for (x = cbl_dnode_child(dns, search); x != NULL;
	    x = cbl_dnode_next(x), i++)
		ATF_CHECK_STREQ(i == 1 ? "w.example" : v[i], str(x));
	ATF_CHECK_EQ(3, i);
	cbl_dtree_free(t);
}

ATF_TC_WITHOUT_HEAD(choices);
ATF_TC_BODY(choices, tc)
{
	const char *tzname = "Europe/Paris";
	int16_t offset = 60;
	cbl_dnode *sys, *clock, *x;
	cbl_dtree *t;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t),
	    sn("ietf-system:system"), NULL, &sys));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(sys, sn("ietf-system:system/clock"),
	    NULL, &clock));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(clock,
	    sn("ietf-system:system/clock/timezone-name"), &tzname, &x));
	/* One case of a choice: the other's is refused while it has one. */
	ATF_CHECK_EQ(EINVAL, cbl_dnode_add(clock,
	    sn("ietf-system:system/clock/timezone-utc-offset"), &offset,
	    NULL));
	ATF_REQUIRE_EQ(0, cbl_dnode_remove(x));
	ATF_CHECK_EQ(0, cbl_dnode_add(clock,
	    sn("ietf-system:system/clock/timezone-utc-offset"), &offset,
	    NULL));
	cbl_dtree_free(t);
}

ATF_TC_WITHOUT_HEAD(defaults);
ATF_TC_BODY(defaults, tc)
{
	const struct cbl_ynode *enabled = sn("ietf-system:system/ntp/enabled");
	cbl_dnode *root, *sys, *ntp, *e, *x;
	const void *v;
	bool isdflt;
	ssize_t made;
	cbl_dtree *t;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	root = cbl_dtree_root(t);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(root, sn("ietf-system:system"), NULL,
	    &sys));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(sys, sn("ietf-system:system/ntp"),
	    NULL, &ntp));
	/* On demand: true, ntp's default, with no node for it. */
	ATF_REQUIRE((v = cbl_dnode_leaf(ntp, enabled, &isdflt)) != NULL);
	ATF_CHECK(isdflt && *(const bool *)v);
	ATF_CHECK(cbl_dnode_child(ntp, enabled) == NULL);
	/* A leaf with no default: none. */
	ATF_CHECK(cbl_dnode_leaf(sys, sn("ietf-system:system/hostname"),
	    &isdflt) == NULL);
	e = ntp_server(ntp, "a");

	/* Made: ntp's enabled, the server's port (in its case, which it
	 * has), association-type, iburst and prefer; the resolver's and
	 * radius's timeout and attempts, each in two non-presence
	 * containers made for them; clock, holding none, is not kept. */
	ATF_REQUIRE((made = cbl_dtree_defaults(sys)) >= 0);
	ATF_CHECK_EQ(1 + 4 + 2 + 2, made);
	ATF_REQUIRE((x = cbl_dnode_child(ntp, enabled)) != NULL);
	ATF_CHECK(cbl_dnode_flags(x) & CBL_DN_DEFAULT);
	ATF_REQUIRE((x = cbl_dnode_child(cbl_dnode_child(e,
	    sn("ietf-system:system/ntp/server/udp")),
	    sn("ietf-system:system/ntp/server/udp/port"))) != NULL);
	ATF_CHECK_EQ(123, *(const uint16_t *)cbl_dnode_value(x));
	ATF_REQUIRE((x = cbl_dnode_child(sys,
	    sn("ietf-system:system/dns-resolver"))) != NULL);
	ATF_CHECK(cbl_dnode_flags(x) & CBL_DN_DEFAULT);
	ATF_REQUIRE((x = cbl_dnode_child(x,
	    sn("ietf-system:system/dns-resolver/options"))) != NULL);
	ATF_CHECK_EQ(5, *(const uint8_t *)cbl_dnode_leaf(x,
	    sn("ietf-system:system/dns-resolver/options/timeout"), &isdflt));
	ATF_CHECK(isdflt);
	ATF_CHECK(cbl_dnode_child(sys, sn("ietf-system:system/radius")) !=
	    NULL);
	ATF_CHECK(cbl_dnode_child(sys, sn("ietf-system:system/clock")) ==
	    NULL);
	/* Again: nothing more to make. */
	ATF_CHECK_EQ(0, cbl_dtree_defaults(sys));
	/* A default set is a value of its own. */
	x = cbl_dnode_child(ntp, enabled);
	ATF_REQUIRE_EQ(0, cbl_dnode_set(x, &(bool){ false }));
	ATF_CHECK((cbl_dnode_flags(x) & CBL_DN_DEFAULT) == 0);
	cbl_dtree_free(t);

	/* A presence container is not made: without ntp, only the
	 * resolver's and radius's. */
	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t),
	    sn("ietf-system:system"), NULL, &sys));
	ATF_CHECK_EQ(4, cbl_dtree_defaults(sys));
	ATF_CHECK(cbl_dnode_child(sys, sn("ietf-system:system/ntp")) == NULL);
	cbl_dtree_free(t);
}

/*
 * Every top-level struct node, filled three ways by the tables (yfill),
 * every optional leaf and only what must be: through the tree and back
 * to the same bytes.  An rpc's input and output under the rpc.
 */
static size_t
roundtrip_node(cbl_dnode *parent, const struct cbl_ynode *n)
{
	size_t done = 0;

	for (int pass = 0; pass < 3; pass++)
		for (int all = 0; all < 2; all++) {
			struct cbl_ybuf in = { 0 }, out = { 0 };
			char why[256];
			cbl_dnode *x;

			ATF_REQUIRE_EQ(0, yencoded(n, pass, all, &in));
			ATF_REQUIRE_EQ_MSG(0, cbl_dnode_decode(parent, n, in.p,
			    in.len, CBL_YD_STRICT, why, sizeof(why), &x),
			    "%s: %s", n->name, why);
			ATF_REQUIRE_EQ(0, cbl_dnode_encode(x, &out));
			ATF_CHECK_MSG(in.len == out.len && memcmp(in.p, out.p,
			    in.len) == 0, "%s pass %d%s: not the same bytes",
			    n->name, pass, all ? " all" : "");
			ATF_REQUIRE_EQ(0, cbl_dnode_remove(x));
			cbl_ybuf_free(&in);
			cbl_ybuf_free(&out);
			done++;
		}
	return (done);
}

ATF_TC_WITHOUT_HEAD(roundtrip);
ATF_TC_BODY(roundtrip, tc)
{
	cbl_dnode *root, *rpc;
	size_t done = 0;
	cbl_dtree *t;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	root = cbl_dtree_root(t);
	for (uint32_t i = 0; i < yangh_schema.nmod; i++) {
		const struct cbl_ymodule *m = yangh_schema.mod[i];

		for (uint32_t j = 0; j < m->ntop; j++) {
			const struct cbl_ynode *n = m->top[j];

			if (n->kind == CBL_YN_RPC) {
				ATF_REQUIRE_EQ(0, cbl_dnode_add(root, n, NULL,
				    &rpc));
				for (uint32_t k = 0; k < n->nchild; k++)
					if (n->child[k]->size > 0)
						done += roundtrip_node(rpc,
						    n->child[k]);
				ATF_REQUIRE_EQ(0, cbl_dnode_remove(rpc));
			} else if (n->size > 0)
				done += roundtrip_node(root, n);
		}
	}
	ATF_CHECK(done >= 60);
	ATF_CHECK_EQ(0, cbl_dtree_count(t));
	cbl_dtree_free(t);
}

ATF_TC_WITHOUT_HEAD(module);
ATF_TC_BODY(module, tc)
{
	const struct cbl_ynode *shapes = sn("shapes:shapes");
	const struct cbl_ymodule *m = shapes->module;
	struct cbl_ybuf in = { 0 }, out = { 0 };
	struct shapes data, back;
	cbl_yarena *a;
	cbl_dtree *t;
	void *p;

	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ(0, yencoded(shapes, 1, true, &in));
	ATF_REQUIRE((p = cbl_yarena_alloc(a, shapes->size)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_ydecode(shapes, in.p, in.len, p, a,
	    CBL_YD_STRICT, NULL, 0));
	memset(&data, 0, sizeof(data));
	data.shapes = p;
	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dtree_from_module(t, m, &data));
	ATF_CHECK(cbl_dnode_child(cbl_dtree_root(t), shapes) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dtree_to_module(t, m, &back, a));
	ATF_REQUIRE(back.shapes != NULL);
	ATF_REQUIRE_EQ(0, cbl_yencode(shapes, back.shapes, &out));
	ATF_CHECK(in.len == out.len && memcmp(in.p, out.p, in.len) == 0);
	/* A module the tree has nothing of: its struct all zero. */
	ATF_REQUIRE_EQ(0, cbl_dtree_to_module(t, sn("ietf-system:system")->
	    module, &(struct ietf_system){ 0 }, a));
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	cbl_ybuf_free(&in);
	cbl_ybuf_free(&out);
}

/*
 * A union of strings told apart by their patterns (inet:host: an IPv4
 * or IPv6 address, or a domain name) comes back from CBOR as the member
 * it was, the first whose restrictions it meets (RFC 7950 9.12), not
 * the first string.
 */
ATF_TC_WITHOUT_HEAD(union_member);
ATF_TC_BODY(union_member, tc)
{
	static const char *const hosts[] = { "192.0.2.1", "2001:db8::1",
	    "ntp.example.org" };
	const struct cbl_ynode *server = sn("ietf-system:system/ntp/server");
	const struct cbl_ynode *udp = sn("ietf-system:system/ntp/server/udp");
	const struct cbl_ynode *addr =
	    sn("ietf-system:system/ntp/server/udp/address");
	const char *name = "a";
	const void *keys[1] = { &name };
	struct cbl_ybuf b = { NULL, 0, 0 };
	cbl_dnode *sys, *ntp, *e, *u, *x;
	cbl_dtree *t, *back;
	cbl_yarena *a;
	unsigned seen[3];
	char why[160];
	void *v;

	for (int i = 0; i < 3; i++) {
		ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
		ATF_REQUIRE((v = cbl_yarena_alloc(a, addr->type->csize)) !=
		    NULL);
		memset(v, 0, addr->type->csize);
		ATF_REQUIRE_EQ(0, cbl_yvalue_parse(addr, addr->type,
		    hosts[i], v, a));
		seen[i] = *(const unsigned *)v;
		ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
		ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t),
		    sn("ietf-system:system"), NULL, &sys));
		ATF_REQUIRE_EQ(0, cbl_dnode_add(sys,
		    sn("ietf-system:system/ntp"), NULL, &ntp));
		ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(ntp, server, keys, &e));
		ATF_REQUIRE_EQ(0, cbl_dnode_add(e, udp, NULL, &u));
		ATF_REQUIRE_EQ(0, cbl_dnode_add(u, addr, v, NULL));
		ATF_REQUIRE_EQ(0, cbl_dtree_encode(t, &b));
		ATF_REQUIRE((back = cbl_dtree_new(&yangh_schema)) != NULL);
		ATF_REQUIRE_EQ_MSG(0, cbl_dtree_decode(back, b.p, b.len, 0,
		    why, sizeof(why)), "%s", why);
		x = cbl_dnode_child(cbl_dtree_root(back),
		    sn("ietf-system:system"));
		x = x != NULL ? cbl_dnode_child(x,
		    sn("ietf-system:system/ntp")) : NULL;
		x = x != NULL ? cbl_dnode_entry(x, server, keys) : NULL;
		x = x != NULL ? cbl_dnode_child(x, udp) : NULL;
		x = x != NULL ? cbl_dnode_child(x, addr) : NULL;
		ATF_REQUIRE(x != NULL);
		ATF_CHECK_EQ_MSG(seen[i], *(const unsigned *)cbl_dnode_value(x),
		    "%s", hosts[i]);
		cbl_dtree_free(back);
		cbl_dtree_free(t);
		cbl_ybuf_free(&b);
		memset(&b, 0, sizeof(b));
		cbl_yarena_free(a);
	}
	/* Three values, and not all of one member. */
	ATF_CHECK(seen[0] != seen[2] && seen[1] != seen[2]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, build);
	ATF_TP_ADD_TC(tp, many);
	ATF_TP_ADD_TC(tp, leaflists);
	ATF_TP_ADD_TC(tp, choices);
	ATF_TP_ADD_TC(tp, defaults);
	ATF_TP_ADD_TC(tp, roundtrip);
	ATF_TP_ADD_TC(tp, union_member);
	ATF_TP_ADD_TC(tp, module);
	return (atf_no_error());
}
