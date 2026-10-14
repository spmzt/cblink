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
 * halfway leaving the target as it was.  RFC 8072's (YANG Patch): songs
 * of a playlist ordered by the user inserted and moved, first, last,
 * before and after another.  And the difference of two trees, applied to
 * the first, makes it the second: trees of every struct filled three
 * ways, a playlist reordered, a choice's case changed.  A tree's state is
 * compared by its YANG-CBOR.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <atf-c.h>

#include "cbl_data.h"
#include "yangh.h"
#include "yfill.h"

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

/* A playlist's song, its index the key. */
static cbl_dnode *
song(cbl_dnode *pl, uint32_t index)
{
	const void *keys[1] = { &index };
	cbl_dnode *e;

	if ((e = cbl_dnode_entry(pl, sn("top/playlist/song"), keys)) == NULL)
		ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(pl,
		    sn("top/playlist/song"), keys, &e));
	return (e);
}

static cbl_dnode *
playlist(cbl_dtree *t, const char *name)
{

	return (entry(top(t), "top/playlist", name));
}

/* The songs' indexes, in order, as "1 2 3". */
static const char *
songs(cbl_dtree *t)
{
	static char buf[128];
	cbl_dnode *pl = playlist(t, "Foo-One"), *x;
	size_t n = 0;

	buf[0] = '\0';
	for (x = cbl_dnode_child(pl, sn("top/playlist/song")); x != NULL &&
	    cbl_dnode_schema(x) == sn("top/playlist/song");
	    x = cbl_dnode_next(x))
		n += (size_t)snprintf(buf + n, sizeof(buf) - n, "%s%u",
		    n > 0 ? " " : "", *(const uint32_t *)cbl_dnode_value(
		    cbl_dnode_child(x, sn("top/playlist/song/index"))));
	return (buf);
}

/* A one-node edit: a song of Foo-One with op and where. */
static cbl_dtree *
song_edit(uint32_t index, int op, int where, const uint32_t *point)
{
	const void *pt[1] = { point };
	cbl_dtree *e = tree();
	cbl_dnode *x = song(playlist(e, "Foo-One"), index);

	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(x, op));
	if (where != 0)
		ATF_REQUIRE_EQ(0, cbl_dnode_set_where(x, where,
		    point != NULL ? pt : NULL));
	return (e);
}

static int
apply1(cbl_dtree *t, cbl_dtree *e, struct cbl_dederr *err)
{
	int error = cbl_dtree_edit(t, e, CBL_DOP_MERGE, err);

	cbl_dtree_free(e);
	return (error);
}

ATF_TC_WITHOUT_HEAD(rfc8072);
ATF_TC_BODY(rfc8072, tc)
{
	struct cbl_dederr err;
	uint32_t one = 1, two = 2, three = 3, nine = 9;
	cbl_dtree *t, *e;
	cbl_dnode *pl;

	t = tree();
	pl = playlist(t, "Foo-One");
	song(pl, 1);
	song(pl, 2);
	song(pl, 3);
	ATF_CHECK_STREQ("1 2 3", songs(t));
	/* Insert a song after another (A.1.3's), and move one after
	 * another (A.1.4's). */
	ATF_REQUIRE_EQ(0, apply1(t, song_edit(5, CBL_DOP_INSERT,
	    CBL_DWHERE_AFTER, &two), &err));
	ATF_CHECK_STREQ("1 2 5 3", songs(t));
	ATF_REQUIRE_EQ(0, apply1(t, song_edit(1, CBL_DOP_MOVE,
	    CBL_DWHERE_AFTER, &three), &err));
	ATF_CHECK_STREQ("2 5 3 1", songs(t));
	/* First, last, before; a merge that says where moves what is
	 * there; a move where it already is changes nothing. */
	ATF_REQUIRE_EQ(0, apply1(t, song_edit(6, CBL_DOP_INSERT,
	    CBL_DWHERE_FIRST, NULL), &err));
	ATF_CHECK_STREQ("6 2 5 3 1", songs(t));
	ATF_REQUIRE_EQ(0, apply1(t, song_edit(6, CBL_DOP_MOVE,
	    CBL_DWHERE_LAST, NULL), &err));
	ATF_CHECK_STREQ("2 5 3 1 6", songs(t));
	ATF_REQUIRE_EQ(0, apply1(t, song_edit(3, CBL_DOP_MERGE,
	    CBL_DWHERE_BEFORE, &two), &err));
	ATF_CHECK_STREQ("3 2 5 1 6", songs(t));
	ATF_REQUIRE_EQ(0, apply1(t, song_edit(2, CBL_DOP_MOVE,
	    CBL_DWHERE_BEFORE, &one), &err));
	ATF_CHECK_STREQ("3 5 2 1 6", songs(t));
	ATF_REQUIRE_EQ(0, apply1(t, song_edit(2, CBL_DOP_MOVE,
	    CBL_DWHERE_BEFORE, &one), &err));
	ATF_CHECK_STREQ("3 5 2 1 6", songs(t));

	/* Refused: insert of one there (A.1.1's data-exists); before one
	 * not there; a move of one not there; where on a list the system
	 * orders. */
	ATF_CHECK_EQ(EEXIST, apply1(t, song_edit(5, CBL_DOP_INSERT,
	    CBL_DWHERE_LAST, NULL), &err));
	ATF_CHECK_STREQ("data-exists", err.tag);
	ATF_CHECK_EQ(ENOENT, apply1(t, song_edit(7, CBL_DOP_INSERT,
	    CBL_DWHERE_BEFORE, &nine), &err));
	ATF_CHECK_STREQ("bad-attribute", err.tag);
	ATF_CHECK(strstr(err.msg, "missing-instance") != NULL);
	ATF_CHECK_EQ(ENOENT, apply1(t, song_edit(9, CBL_DOP_MOVE,
	    CBL_DWHERE_FIRST, NULL), &err));
	ATF_CHECK_STREQ("data-missing", err.tag);
	e = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(playlist(e, "Bar"),
	    CBL_DOP_CREATE));
	ATF_CHECK_EQ(EINVAL, cbl_dnode_set_where(playlist(e, "Bar"),
	    CBL_DWHERE_AFTER, NULL));
	ATF_REQUIRE_EQ(0, cbl_dnode_set_where(playlist(e, "Bar"),
	    CBL_DWHERE_FIRST, NULL));
	ATF_CHECK_EQ(EINVAL, apply1(t, e, &err));
	ATF_CHECK_STREQ("bad-attribute", err.tag);
	ATF_CHECK_STREQ("3 5 2 1 6", songs(t));

	/* Moves undone with the rest when a later change fails. */
	e = song_edit(6, CBL_DOP_MOVE, CBL_DWHERE_FIRST, NULL);
	song(playlist(e, "Foo-One"), 1);
	ATF_REQUIRE_EQ(0, cbl_dnode_set_where(song(playlist(e, "Foo-One"), 1),
	    CBL_DWHERE_AFTER, (const void *[]){ &three }));
	ATF_REQUIRE_EQ(0, cbl_dnode_set_op(iface(e, "Ethernet9/9", 0),
	    CBL_DOP_DELETE));
	ATF_CHECK_EQ(ENOENT, apply1(t, e, &err));
	ATF_CHECK_STREQ("3 5 2 1 6", songs(t));
	cbl_dtree_free(t);
}

/* The node of y's parent q that x of p's is: by keys, value, or kind. */
static const cbl_dnode *
counterpart(const cbl_dnode *q, const cbl_dnode *x)
{
	const struct cbl_ynode *s = cbl_dnode_schema(x);
	const void *keys[8];

	if (s->kind == CBL_YN_LEAFLIST)
		return (cbl_dnode_llentry(q, s, cbl_dnode_value(x)));
	if (s->kind != CBL_YN_LIST)
		return (cbl_dnode_child(q, s));
	for (uint16_t k = 0; k < s->nkeys; k++)
		keys[k] = cbl_dnode_value(cbl_dnode_child(x,
		    s->child[s->keys[k]]));
	return (cbl_dnode_entry(q, s, keys));
}

/*
 * Whether two nodes are the same data, as YANG has it: the same
 * children with the same values, a system-ordered list's entries in any
 * order, a user-ordered one's in the same.
 */
static bool
equal(const cbl_dnode *p, const cbl_dnode *q)
{
	const struct cbl_ynode *s = cbl_dnode_schema(p);
	const cbl_dnode *x, *y;
	size_t np = 0, nq = 0;

	if (s != NULL && s->type != NULL &&
	    !cbl_dvalue_equal(s->type, cbl_dnode_value(p), cbl_dnode_value(q)))
		return (false);
	for (x = cbl_dnode_first(p); x != NULL; x = cbl_dnode_next(x))
		np++;
	for (y = cbl_dnode_first(q); y != NULL; y = cbl_dnode_next(y))
		nq++;
	if (np != nq)
		return (false);
	for (x = cbl_dnode_first(p), y = cbl_dnode_first(q); x != NULL;
	    x = cbl_dnode_next(x), y = cbl_dnode_next(y)) {
		const struct cbl_ynode *xs = cbl_dnode_schema(x);
		const cbl_dnode *m;

		if (xs != cbl_dnode_schema(y))
			return (false);
		if ((xs->flags & CBL_YNF_USERORDER) || (xs->kind ==
		    CBL_YN_LIST && xs->nkeys == 0))
			m = y;
		else
			m = counterpart(q, x);
		if (m == NULL || !equal(x, m))
			return (false);
	}
	return (true);
}

static bool
same_all(cbl_dtree *a, cbl_dtree *b)
{

	return (cbl_dtree_count(a) == cbl_dtree_count(b) &&
	    equal(cbl_dtree_root(a), cbl_dtree_root(b)));
}

/* diff(a, b) applied to a: a is b; and a diff of the same, empty. */
static void
roundtrip(cbl_dtree *a, cbl_dtree *b, const char *what)
{
	struct cbl_dederr err;
	cbl_dtree *d;

	ATF_REQUIRE_MSG((d = cbl_dtree_diff(a, b)) != NULL, "%s: %s", what,
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(0, cbl_dtree_edit(a, d, CBL_DOP_NONE, &err),
	    "%s: %s %s", what, err.tag != NULL ? err.tag : "", err.msg);
	ATF_CHECK_MSG(same_all(a, b), "%s: not the same", what);
	cbl_dtree_free(d);
	ATF_REQUIRE((d = cbl_dtree_diff(a, b)) != NULL);
	ATF_CHECK_EQ_MSG(0, cbl_dtree_count(d), "%s: a difference left",
	    what);
	cbl_dtree_free(d);
}

/* A tree of top-level node n, filled by yfill (pass, all). */
static cbl_dtree *
filled(const struct cbl_ynode *n, int pass, bool all)
{
	struct cbl_ybuf b = { 0 };
	cbl_dtree *t = tree();

	ATF_REQUIRE_EQ(0, yencoded(n, pass, all, &b));
	ATF_REQUIRE_EQ(0, cbl_dnode_decode(cbl_dtree_root(t), n, b.p, b.len,
	    CBL_YD_STRICT, NULL, 0, NULL));
	cbl_ybuf_free(&b);
	return (t);
}

ATF_TC_WITHOUT_HEAD(diff_filled);
ATF_TC_BODY(diff_filled, tc)
{
	char what[128];
	size_t done = 0;

	for (uint32_t i = 0; i < yangh_schema.nmod; i++) {
		const struct cbl_ymodule *m = yangh_schema.mod[i];

		for (uint32_t j = 0; j < m->ntop; j++) {
			const struct cbl_ynode *n = m->top[j];

			if (n->size == 0 || n->kind == CBL_YN_RPC ||
			    n->kind == CBL_YN_NOTIF ||
			    n->kind == CBL_YN_STRUCTURE)
				continue;
			for (int p = 0; p < 6; p++)
				for (int q = 0; q < 6; q++) {
					cbl_dtree *a = filled(n, p / 2, p % 2);
					cbl_dtree *b = filled(n, q / 2, q % 2);

					snprintf(what, sizeof(what),
					    "%s %d to %d", n->name, p, q);
					roundtrip(a, b, what);
					cbl_dtree_free(a);
					cbl_dtree_free(b);
					done++;
				}
			/* From nothing, and to nothing. */
			{
				cbl_dtree *a = tree(), *b = filled(n, 1, true);

				roundtrip(a, b, n->name);
				cbl_dtree_free(b);
				b = tree();
				roundtrip(a, b, n->name);
				cbl_dtree_free(a);
				cbl_dtree_free(b);
			}
		}
	}
	ATF_CHECK(done >= 36 * 3);
}

ATF_TC_WITHOUT_HEAD(diff_cases);
ATF_TC_BODY(diff_cases, tc)
{
	const char *addr = "192.0.2.50", *tag;
	bool yes = true;
	cbl_dtree *a, *b;
	cbl_dnode *pl;

	/* A playlist reordered, a song gone, one come, one changed. */
	a = tree();
	pl = playlist(a, "Foo-One");
	for (uint32_t i = 1; i <= 4; i++)
		song(pl, i);
	tag = "x";
	ATF_REQUIRE_EQ(0, cbl_dnode_add(song(pl, 2), sn("top/playlist/song/id"),
	    &tag, NULL));
	b = tree();
	pl = playlist(b, "Foo-One");
	song(pl, 3);
	song(pl, 5);
	song(pl, 1);
	tag = "y";
	ATF_REQUIRE_EQ(0, cbl_dnode_add(song(pl, 2), sn("top/playlist/song/id"),
	    &tag, NULL));
	roundtrip(a, b, "playlist");
	ATF_CHECK_STREQ("3 5 1 2", songs(a));
	cbl_dtree_free(a);
	cbl_dtree_free(b);

	/* A choice's case changed, both ways; a leaf-list's values. */
	a = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(a), sn("top/static-address"),
	    &addr, NULL));
	tag = "blue";
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(a), sn("top/tags"), &tag, NULL));
	b = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(b), sn("top/dhcp"), &yes, NULL));
	tag = "red";
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(b), sn("top/tags"), &tag, NULL));
	roundtrip(a, b, "case");
	cbl_dtree_free(a);
	a = tree();
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top(a), sn("top/static-address"),
	    &addr, NULL));
	roundtrip(b, a, "case back");
	cbl_dtree_free(a);
	cbl_dtree_free(b);

	/* RFC 6241's running configuration, Ethernet0/0's address changed
	 * and an OSPF interface gone. */
	a = running();
	b = tree();
	address(iface(b, "Ethernet0/0", 1400), "192.0.2.2", 24);
	address(iface(b, "Ethernet0/1", 1500), "192.0.2.9", 24);
	ospf_iface(b, "0.0.0.0", "192.0.2.1");
	roundtrip(a, b, "rfc6241");
	cbl_dtree_free(a);
	cbl_dtree_free(b);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rfc6241);
	ATF_TP_ADD_TC(tp, errors);
	ATF_TP_ADD_TC(tp, atomic);
	ATF_TP_ADD_TC(tp, choice);
	ATF_TP_ADD_TC(tp, lists);
	ATF_TP_ADD_TC(tp, rfc8072);
	ATF_TP_ADD_TC(tp, diff_filled);
	ATF_TP_ADD_TC(tp, diff_cases);
	return (atf_no_error());
}
