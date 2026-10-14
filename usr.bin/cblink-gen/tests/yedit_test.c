/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Edits of the instance tree (cbl_dtree_edit()) on the module edits: RFC
 * 6241 section 7.2's examples (an interface's MTU set, an interface
 * replaced, one deleted, an OSPF area's interface deleted, by merge and by
 * none); create where there is one, delete where there is none, remove
 * either way; none through what is not there; a choice's case taking the
 * other's place; leaf-lists and an ordered list; and an edit that fails
 * halfway leaving the target as it was.  A tree's state is compared by
 * its YANG-CBOR.
 */

#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include "cbl_data.h"
#include "yangh.h"

static const struct cbl_ynode *
sn(const char *path)
{
	const struct cbl_ymodule *m = NULL;
	const struct cbl_ynode *const *k;
	const struct cbl_ynode *n = NULL;
	char buf[256], *p, *name;
	uint32_t nk;

	for (uint32_t i = 0; i < yangh_schema.nmod; i++)
		if (strcmp(yangh_schema.mod[i]->name, "edits") == 0)
			m = yangh_schema.mod[i];
	ATF_REQUIRE(m != NULL);
	k = m->top;
	nk = m->ntop;
	strlcpy(buf, path, sizeof(buf));
	p = buf;
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

static cbl_dnode *
top(cbl_dtree *t)
{
	cbl_dnode *x = cbl_dnode_child(cbl_dtree_root(t), sn("top"));

	if (x == NULL)
		ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t), sn("top"),
		    NULL, &x));
	return (x);
}

static cbl_dnode *
entry(cbl_dnode *parent, const char *list, const char *key)
{
	const void *keys[1] = { &key };
	cbl_dnode *e;

	if ((e = cbl_dnode_entry(parent, sn(list), keys)) == NULL)
		ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(parent, sn(list), keys,
		    &e));
	return (e);
}

static cbl_dnode *
iface(cbl_dtree *t, const char *name, uint32_t mtu)
{
	cbl_dnode *e = entry(top(t), "top/interface", name);

	if (mtu != 0)
		ATF_REQUIRE_EQ(0, cbl_dnode_add(e, sn("top/interface/mtu"), &mtu,
		    NULL));
	return (e);
}

static cbl_dnode *
address(cbl_dnode *ifc, const char *name, uint8_t len)
{
	cbl_dnode *e = entry(ifc, "top/interface/address", name);

	ATF_REQUIRE_EQ(0, cbl_dnode_add(e,
	    sn("top/interface/address/prefix-length"), &len, NULL));
	return (e);
}

static cbl_dnode *
ospf_iface(cbl_dtree *t, const char *area, const char *name)
{
	cbl_dnode *x = top(t), *y;

	if ((y = cbl_dnode_child(x, sn("top/protocols"))) == NULL)
		ATF_REQUIRE_EQ(0, cbl_dnode_add(x, sn("top/protocols"), NULL,
		    &y));
	x = y;
	if ((y = cbl_dnode_child(x, sn("top/protocols/ospf"))) == NULL)
		ATF_REQUIRE_EQ(0, cbl_dnode_add(x, sn("top/protocols/ospf"),
		    NULL, &y));
	x = entry(y, "top/protocols/ospf/area", area);
	if ((y = cbl_dnode_child(x,
	    sn("top/protocols/ospf/area/interfaces"))) == NULL)
		ATF_REQUIRE_EQ(0, cbl_dnode_add(x,
		    sn("top/protocols/ospf/area/interfaces"), NULL, &y));
	return (entry(y, "top/protocols/ospf/area/interfaces/interface",
	    name));
}

/* Whether two trees have the same top, by their bytes. */
static bool
same(cbl_dtree *a, cbl_dtree *b)
{
	struct cbl_ybuf x = { 0 }, y = { 0 };
	cbl_dnode *ta = cbl_dnode_child(cbl_dtree_root(a), sn("top"));
	cbl_dnode *tb = cbl_dnode_child(cbl_dtree_root(b), sn("top"));
	bool eq;

	if (ta == NULL || tb == NULL)
		return (ta == tb);
	ATF_REQUIRE_EQ(0, cbl_dnode_encode(ta, &x));
	ATF_REQUIRE_EQ(0, cbl_dnode_encode(tb, &y));
	eq = x.len == y.len && memcmp(x.p, y.p, x.len) == 0;
	cbl_ybuf_free(&x);
	cbl_ybuf_free(&y);
	return (eq);
}

static cbl_dtree *
tree(void)
{
	cbl_dtree *t;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	return (t);
}

/* The running configuration RFC 6241 section 7.2's examples start from. */
static cbl_dtree *
running(void)
{
	cbl_dtree *t = tree();

	address(iface(t, "Ethernet0/0", 1400), "192.0.2.1", 24);
	address(iface(t, "Ethernet0/1", 1500), "192.0.2.9", 24);
	ospf_iface(t, "0.0.0.0", "192.0.2.4");
	ospf_iface(t, "0.0.0.0", "192.0.2.1");
	return (t);
}

ATF_TC_WITHOUT_HEAD(rfc6241);
ATF_TC_BODY(rfc6241, tc)
{
	struct cbl_dederr err;
	cbl_dtree *t, *e, *want;
	cbl_dnode *x;

	/* Set the MTU to 1500 on Ethernet0/0: a merge. */
	t = running();
	e = tree();
	iface(e, "Ethernet0/0", 1500);
	ATF_REQUIRE_EQ(0, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	want = tree();
	address(iface(want, "Ethernet0/0", 1500), "192.0.2.1", 24);
	address(iface(want, "Ethernet0/1", 1500), "192.0.2.9", 24);
	ospf_iface(want, "0.0.0.0", "192.0.2.4");
	ospf_iface(want, "0.0.0.0", "192.0.2.1");
	ATF_CHECK(same(t, want));
	cbl_dtree_free(e);
	cbl_dtree_free(want);
	cbl_dtree_free(t);

	/* Add Ethernet0/0, replacing any interface of that name: its old
	 * address goes, the new one comes. */
	t = running();
	e = tree();
	x = iface(e, "Ethernet0/0", 1500);
	address(x, "192.0.2.4", 24);
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, CBL_DOP_REPLACE));
	ATF_REQUIRE_EQ(0, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	want = tree();
	address(iface(want, "Ethernet0/0", 1500), "192.0.2.4", 24);
	address(iface(want, "Ethernet0/1", 1500), "192.0.2.9", 24);
	ospf_iface(want, "0.0.0.0", "192.0.2.4");
	ospf_iface(want, "0.0.0.0", "192.0.2.1");
	ATF_CHECK(same(t, want));
	cbl_dtree_free(e);
	cbl_dtree_free(want);
	cbl_dtree_free(t);

	/* Delete the configuration of Ethernet0/0. */
	t = running();
	e = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(iface(e, "Ethernet0/0", 0),
	    CBL_DOP_DELETE));
	ATF_REQUIRE_EQ(0, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	want = tree();
	address(iface(want, "Ethernet0/1", 1500), "192.0.2.9", 24);
	ospf_iface(want, "0.0.0.0", "192.0.2.4");
	ospf_iface(want, "0.0.0.0", "192.0.2.1");
	ATF_CHECK(same(t, want));
	cbl_dtree_free(e);
	cbl_dtree_free(t);

	/* Delete interface 192.0.2.4 from an OSPF area, the area's others
	 * unaffected: by merge, and by none, which makes nothing on its
	 * way. */
	for (int dflt = CBL_DOP_MERGE; dflt <= CBL_DOP_NONE;
	    dflt += CBL_DOP_NONE - CBL_DOP_MERGE) {
		t = running();
		e = tree();
		ATF_REQUIRE_EQ(0, cbl_dnode_set_op(ospf_iface(e, "0.0.0.0",
		    "192.0.2.4"), CBL_DOP_DELETE));
		ATF_REQUIRE_EQ(0, cbl_dtree_edit(t, e, dflt, &err));
		cbl_dtree_free(want);
		want = tree();
		address(iface(want, "Ethernet0/0", 1400), "192.0.2.1", 24);
		address(iface(want, "Ethernet0/1", 1500), "192.0.2.9", 24);
		ospf_iface(want, "0.0.0.0", "192.0.2.1");
		ATF_CHECK_MSG(same(t, want), "default operation %d", dflt);
		cbl_dtree_free(e);
		cbl_dtree_free(t);
	}
	cbl_dtree_free(want);
}

ATF_TC_WITHOUT_HEAD(errors);
ATF_TC_BODY(errors, tc)
{
	struct cbl_dederr err;
	cbl_dtree *t, *e, *was;
	cbl_dnode *x;

	t = running();
	was = running();
	/* create where there is one: data-exists, and it names the node. */
	e = tree();
	x = iface(e, "Ethernet0/0", 9000);
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, CBL_DOP_CREATE));
	ATF_CHECK_EQ(EEXIST, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	ATF_CHECK_STREQ("data-exists", err.tag);
	ATF_CHECK(err.node == x);
	ATF_CHECK(same(t, was));
	cbl_dtree_free(e);

	/* delete where there is none: data-missing; remove: nothing. */
	e = tree();
	x = iface(e, "Ethernet9/9", 0);
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, CBL_DOP_DELETE));
	ATF_CHECK_EQ(ENOENT, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	ATF_CHECK_STREQ("data-missing", err.tag);
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, CBL_DOP_REMOVE));
	ATF_CHECK_EQ(0, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	ATF_CHECK(same(t, was));
	cbl_dtree_free(e);

	/* none through an interface that is not there: data-missing. */
	e = tree();
	x = address(iface(e, "Ethernet9/9", 0), "192.0.2.77", 24);
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, CBL_DOP_CREATE));
	ATF_CHECK_EQ(ENOENT, cbl_dtree_edit(t, e, CBL_DOP_NONE, &err));
	ATF_CHECK_STREQ("data-missing", err.tag);
	/* With merge it is made on the way. */
	ATF_CHECK_EQ(0, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	ATF_CHECK(!same(t, was));
	cbl_dtree_free(e);
	cbl_dtree_free(t);
	cbl_dtree_free(was);
}

/* An edit that fails after it changed much: the target as it was. */
ATF_TC_WITHOUT_HEAD(atomic);
ATF_TC_BODY(atomic, tc)
{
	struct cbl_dederr err;
	cbl_dtree *t, *e, *was;
	cbl_dnode *x;

	t = running();
	was = running();
	e = tree();
	/* A merge of a new MTU, a new interface, a replace of Ethernet0/1
	 * and a delete in OSPF, then a create of what is there. */
	iface(e, "Ethernet0/0", 9000);
	address(iface(e, "Ethernet0/2", 1500), "192.0.2.17", 28);
	x = iface(e, "Ethernet0/1", 1280);
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, CBL_DOP_REPLACE));
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(ospf_iface(e, "0.0.0.0",
	    "192.0.2.4"), CBL_DOP_DELETE));
	x = ospf_iface(e, "0.0.0.0", "192.0.2.1");
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, CBL_DOP_CREATE));
	ATF_CHECK_EQ(EEXIST, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	ATF_CHECK(err.node == x);
	ATF_CHECK(same(t, was));
	ATF_CHECK_EQ(cbl_dtree_count(was), cbl_dtree_count(t));
	/* Without the create, it all holds. */
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, 0));
	ATF_CHECK_EQ(0, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	ATF_CHECK(!same(t, was));
	cbl_dtree_free(e);
	cbl_dtree_free(t);
	cbl_dtree_free(was);
}

ATF_TC_WITHOUT_HEAD(choice);
ATF_TC_BODY(choice, tc)
{
	struct cbl_dederr err;
	const char *addr = "192.0.2.50";
	cbl_dtree *t, *e, *was;
	cbl_dnode *x;
	bool yes = true;

	t = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(t), sn("top/static-address"),
	    &addr, NULL));
	was = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(was), sn("top/static-address"),
	    &addr, NULL));
	/* dhcp, of the other case: static-address goes. */
	e = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(e), sn("top/dhcp"), &yes, NULL));
	ATF_REQUIRE_EQ(0, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	ATF_CHECK(cbl_dnode_child(top(t), sn("top/static-address")) == NULL);
	ATF_CHECK(cbl_dnode_child(top(t), sn("top/dhcp")) != NULL);
	cbl_dtree_free(e);
	/* Back, and that undone by a later error: static-address again. */
	cbl_dtree_free(t);
	t = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(t), sn("top/static-address"),
	    &addr, NULL));
	e = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(e), sn("top/dhcp"), &yes, NULL));
	x = iface(e, "Ethernet9/9", 0);
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, CBL_DOP_DELETE));
	ATF_CHECK_EQ(ENOENT, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	ATF_CHECK(same(t, was));
	cbl_dtree_free(e);
	cbl_dtree_free(t);
	cbl_dtree_free(was);
}

ATF_TC_WITHOUT_HEAD(lists);
ATF_TC_BODY(lists, tc)
{
	static const char *const order[] = { "10.0.0.0/8", "192.168.0.0/16",
	    "172.16.0.0/12" };
	struct cbl_dederr err;
	const char *tag;
	cbl_dtree *t, *e;
	cbl_dnode *x;
	int i;

	t = tree();
	tag = "blue";
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(t), sn("top/tags"), &tag, NULL));
	entry(top(t), "top/route", order[0]);
	entry(top(t), "top/route", order[1]);
	/* A leaf-list's value merged: added once; one there: nothing. */
	e = tree();
	tag = "red";
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(e), sn("top/tags"), &tag, NULL));
	tag = "blue";
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(e), sn("top/tags"), &tag, NULL));
	/* An ordered-by user list's new entry: after its last. */
	entry(top(e), "top/route", order[2]);
	ATF_REQUIRE_EQ(0, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	i = 0;
	for (x = cbl_dnode_child(top(t), sn("top/tags")); x != NULL &&
	    cbl_dnode_schema(x) == sn("top/tags"); x = cbl_dnode_next(x))
		i++;
	ATF_CHECK_EQ(2, i);
	i = 0;
	for (x = cbl_dnode_child(top(t), sn("top/route")); x != NULL &&
	    cbl_dnode_schema(x) == sn("top/route"); x = cbl_dnode_next(x), i++)
		ATF_CHECK_STREQ(order[i],
		    *(const char *const *)cbl_dnode_value(cbl_dnode_first(x)));
	ATF_CHECK_EQ(3, i);
	cbl_dtree_free(e);
	/* A value deleted by its value. */
	e = tree();
	tag = "red";
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(e), sn("top/tags"), &tag, &x));
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, CBL_DOP_DELETE));
	ATF_REQUIRE_EQ(0, cbl_dtree_edit(t, e, CBL_DOP_MERGE, &err));
	ATF_CHECK(cbl_dnode_llentry(top(t), sn("top/tags"), &tag) == NULL);
	tag = "blue";
	ATF_CHECK(cbl_dnode_llentry(top(t), sn("top/tags"), &tag) != NULL);
	cbl_dtree_free(e);
	cbl_dtree_free(t);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rfc6241);
	ATF_TP_ADD_TC(tp, errors);
	ATF_TP_ADD_TC(tp, atomic);
	ATF_TP_ADD_TC(tp, choice);
	ATF_TP_ADD_TC(tp, lists);
	return (atf_no_error());
}
