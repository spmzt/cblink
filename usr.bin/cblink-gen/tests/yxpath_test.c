/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * XPath-lite over the instance tree (cbl_xp_eval()), on RFC 6241's
 * running configuration in the test module edits: paths absolute and
 * relative, the four axes, predicates, current(); comparisons with node
 * sets (XPath 1.0 section 3.4), arithmetic, and, or, union, count();
 * leaves' string values (a decimal64's canonical form, an instance-
 * identifier's path); every function XPath-lite has, one test each at
 * least; and what is not XPath-lite refused.  The expressions are written as the tables hold
 * them, every name with its module.
 */

#include <errno.h>
#include <math.h>
#include <string.h>

#include <atf-c.h>

#include "cbl_data.h"
#include "yangh.h"

static const struct cbl_ynode *
sn(const char *mod, const char *path)
{
	const struct cbl_ymodule *m = NULL;
	const struct cbl_ynode *const *k;
	const struct cbl_ynode *n = NULL;
	char buf[256], *p, *name;
	uint32_t nk;

	for (uint32_t i = 0; i < yangh_schema.nmod; i++)
		if (strcmp(yangh_schema.mod[i]->name, mod) == 0)
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
entry(cbl_dnode *parent, const struct cbl_ynode *list, const char *key)
{
	const void *keys[1] = { &key };
	cbl_dnode *e;

	if ((e = cbl_dnode_entry(parent, list, keys)) == NULL)
		ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(parent, list, keys, &e));
	return (e);
}

static cbl_dtree *
running(cbl_dnode **topp)
{
	cbl_dtree *t;
	cbl_dnode *top, *ifc, *a;
	uint32_t mtu[] = { 1400, 1500 };
	uint8_t len = 24;
	const char *names[] = { "Ethernet0/0", "Ethernet0/1" };
	const char *addrs[] = { "192.0.2.1", "192.0.2.9" };

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t),
	    sn("edits", "top"), NULL, &top));
	for (int i = 0; i < 2; i++) {
		ifc = entry(top, sn("edits", "top/interface"), names[i]);
		ATF_REQUIRE_EQ(0, cbl_dnode_add(ifc,
		    sn("edits", "top/interface/mtu"), &mtu[i], NULL));
		a = entry(ifc, sn("edits", "top/interface/address"), addrs[i]);
		ATF_REQUIRE_EQ(0, cbl_dnode_add(a,
		    sn("edits", "top/interface/address/prefix-length"), &len,
		    NULL));
	}
	*topp = top;
	return (t);
}

/* expr's value from ctx, as a number, a boolean, a string, a count. */
static double
num(cbl_dtree *t, const char *expr, const cbl_dnode *ctx)
{
	struct cbl_xval v;
	char why[128];
	double d;

	ATF_REQUIRE_EQ_MSG(0, cbl_xp_eval(t, expr, ctx, NULL, &v, why,
	    sizeof(why)), "%s: %s", expr, why);
	ATF_REQUIRE_EQ_MSG(CBL_XV_NUMBER, v.kind, "%s", expr);
	d = v.num;
	cbl_xval_free(&v);
	return (d);
}

static bool
truth(cbl_dtree *t, const char *expr, const cbl_dnode *ctx,
    const cbl_dnode *cur)
{
	struct cbl_xval v;
	char why[128];
	bool b;

	ATF_REQUIRE_EQ_MSG(0, cbl_xp_eval(t, expr, ctx, cur, &v, why,
	    sizeof(why)), "%s: %s", expr, why);
	ATF_REQUIRE_EQ_MSG(CBL_XV_BOOL, v.kind, "%s", expr);
	b = v.b;
	cbl_xval_free(&v);
	return (b);
}

static size_t
count(cbl_dtree *t, const char *expr, const cbl_dnode *ctx,
    const cbl_dnode *cur)
{
	struct cbl_xval v;
	char why[128];
	size_t n;

	ATF_REQUIRE_EQ_MSG(0, cbl_xp_eval(t, expr, ctx, cur, &v, why,
	    sizeof(why)), "%s: %s", expr, why);
	ATF_REQUIRE_EQ_MSG(CBL_XV_NODES, v.kind, "%s", expr);
	n = v.n;
	cbl_xval_free(&v);
	return (n);
}

static void
check_str(cbl_dtree *t, const char *expr, const cbl_dnode *ctx,
    const char *want)
{
	struct cbl_xval v;
	char why[128];

	ATF_REQUIRE_EQ_MSG(0, cbl_xp_eval(t, expr, ctx, NULL, &v, why,
	    sizeof(why)), "%s: %s", expr, why);
	ATF_REQUIRE_EQ(CBL_XV_STRING, v.kind);
	ATF_CHECK_STREQ_MSG(want, v.s, "%s", expr);
	cbl_xval_free(&v);
}

ATF_TC_WITHOUT_HEAD(paths);
ATF_TC_BODY(paths, tc)
{
	cbl_dnode *top, *mtu, *primary;
	const char *name = "Ethernet0/1";
	cbl_dtree *t = running(&top);

	/* Absolute and relative; the axes; "//". */
	ATF_CHECK_EQ(2, count(t, "/edits:top/edits:interface", NULL, NULL));
	ATF_CHECK_EQ(2, count(t, "edits:interface", top, NULL));
	ATF_CHECK_EQ(1, count(t, "..", top, NULL));
	ATF_CHECK_EQ(1, count(t, ".", top, NULL));
	ATF_CHECK_EQ(4, count(t, "//edits:name", NULL, NULL));
	ATF_CHECK_EQ(2, count(t, "/edits:top/edits:interface/*", NULL,
	    NULL) / 3);
	ATF_CHECK_EQ(0, count(t, "/edits:top/edits:nothing", NULL, NULL));
	/* Another module's name of the same name: not these. */
	ATF_CHECK_EQ(0, count(t, "/shapes:top", NULL, NULL));

	/* Predicates, and current(): from primary, its interface's MTU. */
	ATF_CHECK_EQ(1500, num(t, "number(/edits:top/edits:interface"
	    "[edits:name = 'Ethernet0/1']/edits:mtu)", NULL));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top, sn("edits", "top/primary"),
	    &name, &primary));
	ATF_CHECK_EQ(1, count(t, "../edits:interface[edits:name = "
	    "current()]/edits:mtu", primary, primary));
	ATF_CHECK_EQ(1500, num(t, "number(../edits:interface[edits:name = "
	    "current()]/edits:mtu)", primary));
	/* current() is the current node wherever the context is. */
	ATF_CHECK_EQ(1, count(t, "/edits:top/edits:interface[edits:name = "
	    "current()/../edits:primary]", NULL, primary));
	mtu = (cbl_dnode *)(uintptr_t)cbl_dnode_child(cbl_dnode_first(top),
	    sn("edits", "top/interface/mtu"));
	ATF_CHECK_EQ(1, count(t, "../edits:address", mtu, NULL));
	cbl_dtree_free(t);
}

ATF_TC_WITHOUT_HEAD(values);
ATF_TC_BODY(values, tc)
{
	cbl_dnode *top, *sh;
	cbl_dtree *t = running(&top);
	int64_t ratio;

	/* Node sets against numbers, strings and each other. */
	ATF_CHECK(truth(t, "/edits:top/edits:interface/edits:mtu > 1450",
	    NULL, NULL));
	ATF_CHECK(truth(t, "/edits:top/edits:interface/edits:mtu = 1400",
	    NULL, NULL));
	ATF_CHECK(truth(t, "/edits:top/edits:interface/edits:mtu != 1400",
	    NULL, NULL));
	ATF_CHECK(!truth(t, "/edits:top/edits:interface/edits:mtu > 1500",
	    NULL, NULL));
	ATF_CHECK(truth(t, "//edits:name = 'Ethernet0/0'", NULL, NULL));
	ATF_CHECK(truth(t, "/edits:top/edits:interface/edits:name = "
	    "/edits:top/edits:interface/edits:address/edits:name or "
	    "true()", NULL, NULL));
	ATF_CHECK(!truth(t, "/edits:top/edits:interface/edits:name = "
	    "/edits:top/edits:interface/edits:address/edits:name", NULL,
	    NULL));
	ATF_CHECK(!truth(t, "/edits:top/edits:nothing = 'x'", NULL, NULL));
	ATF_CHECK(truth(t, "/edits:top/edits:nothing != 'x' or "
	    "not(/edits:top/edits:nothing)", NULL, NULL));
	/* Arithmetic, and, or, union, count. */
	ATF_CHECK_EQ(7, num(t, "1 + 2 * 3", NULL));
	ATF_CHECK_EQ(2, num(t, "10 mod 4", NULL));
	ATF_CHECK(isnan(num(t, "number('x')", NULL)));
	ATF_CHECK_EQ(-3, num(t, "-(1 + 2)", NULL));
	ATF_CHECK(truth(t, "1 < 2 and 'a' = 'a'", NULL, NULL));
	ATF_CHECK(!truth(t, "false() and boolean(1 div 0)", NULL, NULL));
	ATF_CHECK_EQ(4, num(t, "count(//edits:mtu | //edits:prefix-length)",
	    NULL));
	ATF_CHECK_EQ(2, num(t, "count(//edits:mtu | //edits:mtu)", NULL));
	/* String values: a uint32, and decimal64's canonical forms. */
	check_str(t, "string(/edits:top/edits:interface/edits:mtu)", NULL,
	    "1400");
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t),
	    sn("shapes", "shapes"), NULL, &sh));
	ratio = 257;
	ATF_REQUIRE_EQ(0, cbl_dnode_add(sh, sn("shapes", "shapes/ratio"),
	    &ratio, NULL));
	check_str(t, "string(/shapes:shapes/shapes:ratio)", NULL, "2.57");
	ratio = -250;
	ATF_REQUIRE_EQ(0, cbl_dnode_set(cbl_dnode_child(sh,
	    sn("shapes", "shapes/ratio")), &ratio));
	check_str(t, "string(/shapes:shapes/shapes:ratio)", NULL, "-2.5");
	ratio = 200;
	ATF_REQUIRE_EQ(0, cbl_dnode_set(cbl_dnode_child(sh,
	    sn("shapes", "shapes/ratio")), &ratio));
	check_str(t, "string(/shapes:shapes/shapes:ratio)", NULL, "2.0");
	ATF_CHECK_EQ(2, num(t, "number(/shapes:shapes/shapes:ratio)", NULL));
	check_str(t, "string(1 div 0)", NULL, "Infinity");
	check_str(t, "string(0.5)", NULL, "0.5");
	cbl_dtree_free(t);
}

/* An identity of shapes by its name, its SID. */
static uint64_t
ident(const char *name)
{

	for (uint32_t i = 0; i < yangh_schema.nident; i++)
		if (strcmp(yangh_schema.ident[i].name, name) == 0 &&
		    strcmp(yangh_schema.ident[i].module->name, "shapes") == 0)
			return (yangh_schema.ident[i].sid);
	ATF_REQUIRE_MSG(false, "no identity %s", name);
	return (0);
}

ATF_TC_WITHOUT_HEAD(functions);
ATF_TC_BODY(functions, tc)
{
	static const uint8_t perms[] = { 0x10 };	/* write, position 4 */
	struct cbl_bytes pb = { perms, sizeof(perms) }, iidv;
	const char *name = "Ethernet0/1";
	cbl_dnode *top, *sh, *primary, *mark;
	cbl_dtree *t = running(&top);
	uint64_t red = ident("red");
	uint8_t iid[32];
	size_t n = 0;
	int level = 7;

	/* deref(): a leafref to its target's node; an instance-identifier
	 * to the node it names. */
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top, sn("edits", "top/primary"),
	    &name, &primary));
	ATF_CHECK_EQ(1500, num(t, "number(deref(.)/../edits:mtu)", primary));
	ATF_CHECK_EQ(1, count(t, "deref(.)", primary, NULL));
	iid[n++] = 0x82;	/* [SID of mtu, "Ethernet0/0"] */
	iid[n++] = 0x1b;
	for (int i = 7; i >= 0; i--)
		iid[n++] = (uint8_t)(sn("edits", "top/interface/mtu")->sid >>
		    (8 * i));
	iid[n++] = 0x6b;
	memcpy(iid + n, "Ethernet0/0", 11);
	n += 11;
	iidv = (struct cbl_bytes){ iid, n };
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top, sn("edits", "top/mark"), &iidv,
	    &mark));
	ATF_CHECK_EQ(1400, num(t, "number(deref(/edits:top/edits:mark))",
	    NULL));
	check_str(t, "string(/edits:top/edits:mark)", NULL,
	    "/edits:top/edits:interface[edits:name='Ethernet0/0']/edits:mtu");

	/* derived-from(), -or-self(); enum-value(); bit-is-set(). */
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t),
	    sn("shapes", "shapes"), NULL, &sh));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(sh, sn("shapes", "shapes/colour"),
	    &red, NULL));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(sh, sn("shapes", "shapes/level"),
	    &level, NULL));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(sh, sn("shapes", "shapes/perms"),
	    &pb, NULL));
	ATF_CHECK(truth(t, "derived-from(/shapes:shapes/shapes:colour, "
	    "'shapes:colour')", NULL, NULL));
	ATF_CHECK(!truth(t, "derived-from(/shapes:shapes/shapes:colour, "
	    "'shapes:red')", NULL, NULL));
	ATF_CHECK(truth(t, "derived-from-or-self(/shapes:shapes/"
	    "shapes:colour, 'shapes:red')", NULL, NULL));
	ATF_CHECK(truth(t, "/shapes:shapes/shapes:colour = 'shapes:red'",
	    NULL, NULL));
	ATF_CHECK_EQ(7, num(t, "enum-value(/shapes:shapes/shapes:level)",
	    NULL));
	check_str(t, "string(/shapes:shapes/shapes:level)", NULL,
	    "very high");
	ATF_CHECK(truth(t, "bit-is-set(/shapes:shapes/shapes:perms, 'write')",
	    NULL, NULL));
	ATF_CHECK(!truth(t, "bit-is-set(/shapes:shapes/shapes:perms, 'read')",
	    NULL, NULL));

	/* re-match(): an XSD pattern, the whole string. */
	ATF_CHECK(truth(t, "re-match('abc', '[a-c]+')", NULL, NULL));
	ATF_CHECK(!truth(t, "re-match('abcd', '[a-c]+')", NULL, NULL));
	ATF_CHECK(truth(t, "re-match('Ethernet0/0', '\\p{L}+\\d/\\d')",
	    NULL, NULL));

	/* count(), not(), boolean(). */
	ATF_CHECK_EQ(2, num(t, "count(/edits:top/edits:interface)", NULL));
	ATF_CHECK(truth(t, "not(/edits:top/edits:nothing)", NULL, NULL));
	ATF_CHECK(!truth(t, "boolean('')", NULL, NULL));

	/* The string functions, characters counted, not bytes. */
	check_str(t, "concat('a', 1, true())", NULL, "a1true");
	ATF_CHECK(truth(t, "contains('Ethernet0/0', 'net')", NULL, NULL));
	ATF_CHECK(truth(t, "starts-with('Ethernet0/0', 'Eth')", NULL, NULL));
	ATF_CHECK_EQ(5, num(t, "string-length('h\xc3\xa9llo')", NULL));
	check_str(t, "substring('12345', 1.5, 2.6)", NULL, "234");
	check_str(t, "substring('12345', 0, 3)", NULL, "12");
	check_str(t, "substring('h\xc3\xa9llo', 2)", NULL,
	    "\xc3\xa9llo");
	check_str(t, "substring('12345', 0 div 0, 3)", NULL, "");
	check_str(t, "substring-before('192.0.2.1/24', '/')", NULL,
	    "192.0.2.1");
	check_str(t, "substring-after('192.0.2.1/24', '/')", NULL, "24");
	check_str(t, "normalize-space('  a \t b  ')", NULL, "a b");
	check_str(t, "translate('bar', 'abc', 'ABC')", NULL, "BAr");
	check_str(t, "translate('--aaa--', 'abc-', 'ABC')", NULL, "AAA");
	/* With no argument, the context node's string. */
	ATF_CHECK_EQ(11, num(t, "string-length()", primary));
	cbl_dtree_free(t);
}

ATF_TC_WITHOUT_HEAD(refused);
ATF_TC_BODY(refused, tc)
{
	struct cbl_xval v;
	cbl_dnode *top;
	cbl_dtree *t = running(&top);
	char why[128];

	/* A position, an axis beyond the four, a variable; and what does
	 * not parse. */
	ATF_CHECK_EQ(EINVAL, cbl_xp_eval(t, "/edits:top/edits:interface[1]",
	    NULL, NULL, &v, why, sizeof(why)));
	ATF_CHECK(strstr(why, "position") != NULL);
	ATF_CHECK_EQ(EINVAL, cbl_xp_eval(t, "ancestor::edits:top", top, NULL,
	    &v, why, sizeof(why)));
	ATF_CHECK(strstr(why, "ancestor") != NULL);
	ATF_CHECK_EQ(EINVAL, cbl_xp_eval(t, "$x", NULL, NULL, &v, why,
	    sizeof(why)));
	ATF_CHECK_EQ(EINVAL, cbl_xp_eval(t, "/edits:top[", NULL, NULL, &v,
	    why, sizeof(why)));
	cbl_dtree_free(t);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, paths);
	ATF_TP_ADD_TC(tp, values);
	ATF_TP_ADD_TC(tp, functions);
	ATF_TP_ADD_TC(tp, refused);
	return (atf_no_error());
}
