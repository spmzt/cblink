/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Filters over the instance tree (cbl_data.h): RFC 6241 section 6.4's
 * subtree filter examples on its configuration (the test module
 * filters), each output as the RFC has it; XPath filters (section 8.9)
 * selecting the same; and what a filter may not be refused.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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

#define	T(path)	sn("filters", "top" path)

static void
user(cbl_dnode *users, const char *name, const char *type,
    const char *full, uint32_t dept, uint32_t id)
{
	const void *keys[1] = { &name };
	cbl_dnode *e, *ci;

	ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(users, T("/users/user"), keys,
	    &e));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(e, T("/users/user/type"), &type,
	    NULL));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(e, T("/users/user/full-name"), &full,
	    NULL));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(e, T("/users/user/company-info"),
	    NULL, &ci));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(ci,
	    T("/users/user/company-info/dept"), &dept, NULL));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(ci, T("/users/user/company-info/id"),
	    &id, NULL));
}

/* RFC 6241 section 6.4's configuration. */
static cbl_dtree *
config(void)
{
	const char *ifs[] = { "eth0", "eth1" };
	uint32_t in[] = { 45621, 1 }, out[] = { 774344, 2 };
	cbl_dnode *top, *users, *ifc, *e;
	cbl_dtree *t;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t), T(""), NULL,
	    &top));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top, T("/users"), NULL, &users));
	user(users, "root", "superuser", "Charlie Root", 1, 1);
	user(users, "fred", "admin", "Fred Flintstone", 2, 2);
	user(users, "barney", "admin", "Barney Rubble", 2, 3);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(top, T("/interfaces"), NULL, &ifc));
	for (int i = 0; i < 2; i++) {
		const void *keys[1] = { &ifs[i] };

		ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(ifc,
		    T("/interfaces/interface"), keys, &e));
		ATF_REQUIRE_EQ(0, cbl_dnode_add(e,
		    T("/interfaces/interface/ifInOctets"), &in[i], NULL));
		ATF_REQUIRE_EQ(0, cbl_dnode_add(e,
		    T("/interfaces/interface/ifOutOctets"), &out[i], NULL));
	}
	return (t);
}

/*
 * A tree as lines, a leaf's each: its path, an entry by its first key's
 * value, and its value.
 */
static void
dump(const cbl_dtree *t, const cbl_dnode *n, const char *path, FILE *f)
{
	struct cbl_xval v;
	char p[512], why[128];

	for (const cbl_dnode *c = cbl_dnode_first(n); c != NULL;
	    c = cbl_dnode_next(c)) {
		const struct cbl_ynode *s = cbl_dnode_schema(c);

		if (s->kind == CBL_YN_LIST) {
			const cbl_dnode *k = cbl_dnode_child(c,
			    s->child[s->keys[0]]);

			ATF_REQUIRE_EQ(0, cbl_xp_eval(t, "string(.)", k, NULL,
			    &v, why, sizeof(why)));
			snprintf(p, sizeof(p), "%s/%s[%s]", path, s->name,
			    v.s);
			cbl_xval_free(&v);
		} else
			snprintf(p, sizeof(p), "%s/%s", path, s->name);
		if (s->type != NULL) {
			ATF_REQUIRE_EQ(0, cbl_xp_eval(t, "string(.)", c, NULL,
			    &v, why, sizeof(why)));
			fprintf(f, "%s %s\n", p, v.s);
			cbl_xval_free(&v);
		} else if (cbl_dnode_first(c) == NULL)
			fprintf(f, "%s\n", p);
		dump(t, c, p, f);
	}
}

static int
by_line(const void *a, const void *b)
{

	return (strcmp(*(char *const *)a, *(char *const *)b));
}

/* Lines s sorted (a node's children are in SID order), in place. */
static char *
sorted(char *s)
{
	char *lines[256], *p = s, *out, *o;
	size_t n = 0, len = strlen(s);

	while (*p != '\0' && n < nitems(lines)) {
		lines[n++] = p;
		if ((p = strchr(p, '\n')) == NULL)
			break;
		*p++ = '\0';
	}
	qsort(lines, n, sizeof(lines[0]), by_line);
	ATF_REQUIRE((o = out = malloc(len + 1)) != NULL);
	for (size_t i = 0; i < n; i++)
		o += sprintf(o, "%s\n", lines[i]);
	*o = '\0';
	return (out);
}

/* Tree out as want's lines, in any order; and freed. */
static void
check_out(cbl_dtree *out, const char *want)
{
	char *buf = NULL, *w, *g, *ws, *gs;
	size_t len = 0;
	FILE *f;

	ATF_REQUIRE(out != NULL);
	ATF_REQUIRE((f = open_memstream(&buf, &len)) != NULL);
	dump(out, cbl_dtree_root(out), "", f);
	fclose(f);
	ATF_REQUIRE((w = strdup(want)) != NULL);
	g = buf;
	ws = sorted(w);
	gs = sorted(g);
	ATF_CHECK_STREQ(ws, gs);
	free(ws);
	free(gs);
	free(w);
	free(buf);
	cbl_dtree_free(out);
}

static cbl_dfnode *
fadd(cbl_dfnode *parent, const struct cbl_ynode *s, const void *v)
{
	cbl_dfnode *n;

	ATF_REQUIRE_EQ(0, cbl_dfilter_add(parent, s, v, &n));
	return (n);
}

/* top/users or top/interfaces, in filter f. */
static cbl_dfnode *
under_top(cbl_dfilter *f, const char *what)
{

	return (fadd(fadd(cbl_dfilter_root(f), T(""), NULL), what[0] == 'u' ?
	    T("/users") : T("/interfaces"), NULL));
}

#define	USERS_ALL							\
    "/top/users/user[root]/name root\n"					\
    "/top/users/user[root]/type superuser\n"				\
    "/top/users/user[root]/full-name Charlie Root\n"			\
    "/top/users/user[root]/company-info/dept 1\n"			\
    "/top/users/user[root]/company-info/id 1\n"				\
    FRED_ALL								\
    "/top/users/user[barney]/name barney\n"				\
    "/top/users/user[barney]/type admin\n"				\
    "/top/users/user[barney]/full-name Barney Rubble\n"			\
    "/top/users/user[barney]/company-info/dept 2\n"			\
    "/top/users/user[barney]/company-info/id 3\n"

#define	FRED_ALL							\
    "/top/users/user[fred]/name fred\n"					\
    "/top/users/user[fred]/type admin\n"					\
    "/top/users/user[fred]/full-name Fred Flintstone\n"			\
    "/top/users/user[fred]/company-info/dept 2\n"			\
    "/top/users/user[fred]/company-info/id 2\n"

static const char users_all[] = USERS_ALL;
static const char fred_all[] = FRED_ALL;

/* 6.4.1, 6.4.2: no filter, all; an empty one, nothing. */
ATF_TC_WITHOUT_HEAD(rfc6241_none_empty);
ATF_TC_BODY(rfc6241_none_empty, tc)
{
	cbl_dtree *t = config();
	cbl_dfilter *f;
	const cbl_dnode *root = cbl_dtree_root(t);

	check_out(cbl_dtree_select(t, &root, 1), USERS_ALL
	    "/top/interfaces/interface[eth0]/ifName eth0\n"
	    "/top/interfaces/interface[eth0]/ifInOctets 45621\n"
	    "/top/interfaces/interface[eth0]/ifOutOctets 774344\n"
	    "/top/interfaces/interface[eth1]/ifName eth1\n"
	    "/top/interfaces/interface[eth1]/ifInOctets 1\n"
	    "/top/interfaces/interface[eth1]/ifOutOctets 2\n");
	ATF_REQUIRE((f = cbl_dfilter_new(&yangh_schema)) != NULL);
	check_out(cbl_dtree_filter_subtree(t, f), "");
	cbl_dfilter_free(f);
	cbl_dtree_free(t);
}

/* 6.4.3: the users subtree, <top><users/></top>. */
ATF_TC_WITHOUT_HEAD(rfc6241_users);
ATF_TC_BODY(rfc6241_users, tc)
{
	cbl_dtree *t = config();
	cbl_dfilter *f = cbl_dfilter_new(&yangh_schema);

	under_top(f, "users");
	check_out(cbl_dtree_filter_subtree(t, f), users_all);
	cbl_dfilter_free(f);
	cbl_dtree_free(t);
}

/* 6.4.4: every user's name, <user><name/></user>. */
ATF_TC_WITHOUT_HEAD(rfc6241_names);
ATF_TC_BODY(rfc6241_names, tc)
{
	cbl_dtree *t = config();
	cbl_dfilter *f = cbl_dfilter_new(&yangh_schema);

	fadd(fadd(under_top(f, "users"), T("/users/user"), NULL),
	    T("/users/user/name"), NULL);
	check_out(cbl_dtree_filter_subtree(t, f),
	    "/top/users/user[root]/name root\n"
	    "/top/users/user[fred]/name fred\n"
	    "/top/users/user[barney]/name barney\n");
	cbl_dfilter_free(f);
	cbl_dtree_free(t);
}

/* 6.4.5: one user, <user><name>fred</name></user>: all of fred. */
ATF_TC_WITHOUT_HEAD(rfc6241_one_user);
ATF_TC_BODY(rfc6241_one_user, tc)
{
	const char *fred = "fred";
	cbl_dtree *t = config();
	cbl_dfilter *f = cbl_dfilter_new(&yangh_schema);

	fadd(fadd(under_top(f, "users"), T("/users/user"), NULL),
	    T("/users/user/name"), &fred);
	check_out(cbl_dtree_filter_subtree(t, f), fred_all);
	cbl_dfilter_free(f);
	cbl_dtree_free(t);
}

/* 6.4.6: fred's name, type and full name. */
ATF_TC_WITHOUT_HEAD(rfc6241_user_fields);
ATF_TC_BODY(rfc6241_user_fields, tc)
{
	const char *fred = "fred";
	cbl_dtree *t = config();
	cbl_dfilter *f = cbl_dfilter_new(&yangh_schema);
	cbl_dfnode *u = fadd(under_top(f, "users"), T("/users/user"), NULL);

	fadd(u, T("/users/user/name"), &fred);
	fadd(u, T("/users/user/type"), NULL);
	fadd(u, T("/users/user/full-name"), NULL);
	check_out(cbl_dtree_filter_subtree(t, f),
	    "/top/users/user[fred]/name fred\n"
	    "/top/users/user[fred]/type admin\n"
	    "/top/users/user[fred]/full-name Fred Flintstone\n");
	cbl_dfilter_free(f);
	cbl_dtree_free(t);
}

/*
 * 6.4.7: several subtrees: root's name and company-info, fred's name and
 * id, barney's name, type and dept if he is a superuser (he is not).
 */
ATF_TC_WITHOUT_HEAD(rfc6241_subtrees);
ATF_TC_BODY(rfc6241_subtrees, tc)
{
	const char *root = "root", *fred = "fred", *barney = "barney";
	const char *su = "superuser";
	cbl_dtree *t = config();
	cbl_dfilter *f = cbl_dfilter_new(&yangh_schema);
	cbl_dfnode *us = under_top(f, "users"), *u;

	u = fadd(us, T("/users/user"), NULL);
	fadd(u, T("/users/user/name"), &root);
	fadd(u, T("/users/user/company-info"), NULL);
	u = fadd(us, T("/users/user"), NULL);
	fadd(u, T("/users/user/name"), &fred);
	fadd(fadd(u, T("/users/user/company-info"), NULL),
	    T("/users/user/company-info/id"), NULL);
	u = fadd(us, T("/users/user"), NULL);
	fadd(u, T("/users/user/name"), &barney);
	fadd(u, T("/users/user/type"), &su);
	fadd(fadd(u, T("/users/user/company-info"), NULL),
	    T("/users/user/company-info/dept"), NULL);
	check_out(cbl_dtree_filter_subtree(t, f),
	    "/top/users/user[root]/name root\n"
	    "/top/users/user[root]/company-info/dept 1\n"
	    "/top/users/user[root]/company-info/id 1\n"
	    "/top/users/user[fred]/name fred\n"
	    "/top/users/user[fred]/company-info/id 2\n");
	cbl_dfilter_free(f);
	cbl_dtree_free(t);
}

/* 6.4.8: one interface, by its ifName. */
ATF_TC_WITHOUT_HEAD(rfc6241_interface);
ATF_TC_BODY(rfc6241_interface, tc)
{
	const char *eth0 = "eth0";
	cbl_dtree *t = config();
	cbl_dfilter *f = cbl_dfilter_new(&yangh_schema);

	fadd(fadd(under_top(f, "interfaces"), T("/interfaces/interface"),
	    NULL), T("/interfaces/interface/ifName"), &eth0);
	check_out(cbl_dtree_filter_subtree(t, f),
	    "/top/interfaces/interface[eth0]/ifName eth0\n"
	    "/top/interfaces/interface[eth0]/ifInOctets 45621\n"
	    "/top/interfaces/interface[eth0]/ifOutOctets 774344\n");
	cbl_dfilter_free(f);
	cbl_dtree_free(t);
}

/*
 * A content match on a leaf other than a key, a number: the users of
 * dept 2, whole; on two, AND: of dept 2 and id 3.
 */
ATF_TC_WITHOUT_HEAD(content_match);
ATF_TC_BODY(content_match, tc)
{
	uint32_t two = 2, three = 3;
	cbl_dtree *t = config();
	cbl_dfilter *f = cbl_dfilter_new(&yangh_schema);
	cbl_dfnode *ci;

	ci = fadd(fadd(under_top(f, "users"), T("/users/user"), NULL),
	    T("/users/user/company-info"), NULL);
	fadd(ci, T("/users/user/company-info/dept"), &two);
	check_out(cbl_dtree_filter_subtree(t, f),
	    "/top/users/user[fred]/name fred\n"
	    "/top/users/user[fred]/company-info/dept 2\n"
	    "/top/users/user[fred]/company-info/id 2\n"
	    "/top/users/user[barney]/name barney\n"
	    "/top/users/user[barney]/company-info/dept 2\n"
	    "/top/users/user[barney]/company-info/id 3\n");
	fadd(ci, T("/users/user/company-info/id"), &three);
	check_out(cbl_dtree_filter_subtree(t, f),
	    "/top/users/user[barney]/name barney\n"
	    "/top/users/user[barney]/company-info/dept 2\n"
	    "/top/users/user[barney]/company-info/id 3\n");
	cbl_dfilter_free(f);
	cbl_dtree_free(t);
}

/* XPath filters (section 8.9): what the subtree filters above select. */
ATF_TC_WITHOUT_HEAD(xpath);
ATF_TC_BODY(xpath, tc)
{
	cbl_dtree *t = config();
	char why[128];

	check_out(cbl_dtree_filter_xpath(t, "/filters:top/filters:users",
	    why, sizeof(why)), users_all);
	check_out(cbl_dtree_filter_xpath(t, "/filters:top/filters:users/"
	    "filters:user[filters:name = 'fred']", why, sizeof(why)),
	    fred_all);
	check_out(cbl_dtree_filter_xpath(t, "//filters:user/filters:name",
	    why, sizeof(why)),
	    "/top/users/user[root]/name root\n"
	    "/top/users/user[fred]/name fred\n"
	    "/top/users/user[barney]/name barney\n");
	/* Without the key: the entry has it all the same. */
	check_out(cbl_dtree_filter_xpath(t, "//filters:user[filters:type = "
	    "'superuser']/filters:company-info/filters:id | "
	    "//filters:interface[filters:ifInOctets > 100]/"
	    "filters:ifOutOctets", why, sizeof(why)),
	    "/top/users/user[root]/name root\n"
	    "/top/users/user[root]/company-info/id 1\n"
	    "/top/interfaces/interface[eth0]/ifName eth0\n"
	    "/top/interfaces/interface[eth0]/ifOutOctets 774344\n");
	check_out(cbl_dtree_filter_xpath(t, "/filters:top/filters:nothing",
	    why, sizeof(why)), "");
	/* Not a node set. */
	ATF_CHECK(cbl_dtree_filter_xpath(t, "count(//filters:user)", why,
	    sizeof(why)) == NULL);
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_STREQ("not a node set", why);
	cbl_dtree_free(t);
}

static cbl_dnacm_path *
npath(const char *path)
{
	cbl_dnacm_path *p;
	char why[128];

	p = cbl_dnacm_path_new(&yangh_schema, path, why, sizeof(why));
	ATF_REQUIRE_MSG(p != NULL, "%s: %s", path, why);
	return (p);
}

static void
nrefused(const char *path, const char *msg)
{
	char why[128];

	ATF_CHECK(cbl_dnacm_path_new(&yangh_schema, path, why,
	    sizeof(why)) == NULL);
	ATF_CHECK_MSG(strstr(why, msg) != NULL, "%s: %s", path, why);
}

/* The node of tree t expr finds, the one. */
static const cbl_dnode *
node(cbl_dtree *t, const char *expr)
{
	struct cbl_xval v;
	const cbl_dnode *n;
	char why[128];

	ATF_REQUIRE_EQ_MSG(0, cbl_xp_eval(t, expr, NULL, NULL, &v, why,
	    sizeof(why)), "%s", why);
	ATF_REQUIRE_EQ_MSG(1u, v.n, "%s", expr);
	n = v.nodes[0];
	cbl_xval_free(&v);
	return (n);
}

/*
 * NACM's paths (RFC 8341 section 3.4.5): a node and all below it, a
 * list's entries by keys or all of them, $USER; a key not a string, a
 * leaf-list's value; schema nodes; and what is not a
 * node-instance-identifier refused.
 */
ATF_TC_WITHOUT_HEAD(nacm);
ATF_TC_BODY(nacm, tc)
{
	cbl_dtree *t = config();
	const cbl_dnode *users = node(t, "/filters:top/filters:users");
	const cbl_dnode *ifs = node(t, "/filters:top/filters:interfaces");
	const cbl_dnode *fred = node(t, "//filters:user[filters:name = "
	    "'fred']");
	const cbl_dnode *fid = node(t, "//filters:user[filters:name = "
	    "'fred']/filters:company-info/filters:id");
	const cbl_dnode *rdept = node(t, "//filters:user[filters:name = "
	    "'root']/filters:company-info/filters:dept");
	const cbl_dnode *barney = node(t, "//filters:user[filters:name = "
	    "'barney']");
	cbl_dnacm_path *p;

	p = npath("/");
	ATF_CHECK(cbl_dnacm_path_match(p, ifs, NULL));
	ATF_CHECK(cbl_dnacm_path_match(p, fid, NULL));
	cbl_dnacm_path_free(p);
	/* Its module the previous step's. */
	p = npath("/filters:top/users");
	ATF_CHECK(cbl_dnacm_path_match(p, users, NULL));
	ATF_CHECK(cbl_dnacm_path_match(p, fid, NULL));
	ATF_CHECK(!cbl_dnacm_path_match(p, ifs, NULL));
	ATF_CHECK(!cbl_dnacm_path_match(p, cbl_dnode_parent(users), NULL));
	cbl_dnacm_path_free(p);
	p = npath("/filters:top/filters:users/filters:user[filters:name = "
	    "'fred']");
	ATF_CHECK(cbl_dnacm_path_match(p, fred, NULL));
	ATF_CHECK(cbl_dnacm_path_match(p, fid, NULL));
	ATF_CHECK(!cbl_dnacm_path_match(p, rdept, NULL));
	ATF_CHECK(!cbl_dnacm_path_match(p, users, NULL));
	cbl_dnacm_path_free(p);
	/* Every entry: the key left out. */
	p = npath("/filters:top/users/user/company-info/id");
	ATF_CHECK(cbl_dnacm_path_match(p, fid, NULL));
	ATF_CHECK(!cbl_dnacm_path_match(p, rdept, NULL));
	cbl_dnacm_path_free(p);
	/* $USER: the session's user. */
	p = npath("/filters:top/users/user[name=$USER]");
	ATF_CHECK(cbl_dnacm_path_match(p, fid, "fred"));
	ATF_CHECK(!cbl_dnacm_path_match(p, fid, "barney"));
	ATF_CHECK(cbl_dnacm_path_match(p, barney, "barney"));
	ATF_CHECK(!cbl_dnacm_path_match(p, fid, NULL));
	cbl_dnacm_path_free(p);
	/* Schema nodes: a path with predicates names none. */
	p = npath("/filters:top/users");
	ATF_CHECK(cbl_dnacm_path_match_schema(p, T("/users/user/name")));
	ATF_CHECK(!cbl_dnacm_path_match_schema(p, T("/interfaces")));
	cbl_dnacm_path_free(p);
	p = npath("/filters:top/users/user[name='fred']");
	ATF_CHECK(!cbl_dnacm_path_match_schema(p, T("/users/user/name")));
	cbl_dnacm_path_free(p);
	cbl_dtree_free(t);

	/* A key of uint32, by its value; a leaf-list's value. */
	{
		const char *pl = "mix", *tags[] = { "a", "b" };
		const void *k[1] = { &pl };
		uint32_t idx[] = { 1, 2 };
		cbl_dnode *top, *e;

		ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
		ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t),
		    sn("edits", "top"), NULL, &top));
		ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(top,
		    sn("edits", "top/playlist"), k, &e));
		for (int i = 0; i < 2; i++) {
			const void *ki[1] = { &idx[i] };

			ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(e,
			    sn("edits", "top/playlist/song"), ki, NULL));
			ATF_REQUIRE_EQ(0, cbl_dnode_add(top,
			    sn("edits", "top/tags"), &tags[i], NULL));
		}
		p = npath("/edits:top/playlist[name='mix']/song[index='2']");
		ATF_CHECK(cbl_dnacm_path_match(p, node(t,
		    "//edits:song[edits:index = 2]/edits:index"), NULL));
		ATF_CHECK(!cbl_dnacm_path_match(p, node(t,
		    "//edits:song[edits:index = 1]"), NULL));
		cbl_dnacm_path_free(p);
		p = npath("/edits:top/playlist/song[index=2]");
		ATF_CHECK(cbl_dnacm_path_match(p, node(t,
		    "//edits:song[edits:index = 2]"), NULL));
		cbl_dnacm_path_free(p);
		p = npath("/edits:top/tags[.='b']");
		ATF_CHECK(cbl_dnacm_path_match(p, node(t,
		    "//edits:tags[. = 'b']"), NULL));
		ATF_CHECK(!cbl_dnacm_path_match(p, node(t,
		    "//edits:tags[. = 'a']"), NULL));
		cbl_dnacm_path_free(p);
		cbl_dtree_free(t);
	}

	nrefused("filters:top", "absolute");
	nrefused("/top", "no module");
	nrefused("/filters:top/nothing", "no such node");
	nrefused("/filters:top/users/user[1]", "key = value");
	nrefused("/filters:top/users/user[type='x']", "not a key");
	nrefused("/filters:top/users/user[name=$OTHER]", "variable");
	nrefused("/edits:top/playlist/song[index='two']", "not a value");
	nrefused("/filters:top/users/user[", "at ");
}

/* A filter node is a child of its parent's; a value, a leaf's. */
ATF_TC_WITHOUT_HEAD(refused);
ATF_TC_BODY(refused, tc)
{
	cbl_dfilter *f = cbl_dfilter_new(&yangh_schema);
	cbl_dfnode *top = fadd(cbl_dfilter_root(f), T(""), NULL);
	const char *x = "x";

	ATF_CHECK_EQ(EINVAL, cbl_dfilter_add(cbl_dfilter_root(f),
	    T("/users"), NULL, NULL));
	ATF_CHECK_EQ(EINVAL, cbl_dfilter_add(top, T("/users/user"), NULL,
	    NULL));
	ATF_CHECK_EQ(EINVAL, cbl_dfilter_add(top, T("/users"), &x, NULL));
	cbl_dfilter_free(f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rfc6241_none_empty);
	ATF_TP_ADD_TC(tp, rfc6241_users);
	ATF_TP_ADD_TC(tp, rfc6241_names);
	ATF_TP_ADD_TC(tp, rfc6241_one_user);
	ATF_TP_ADD_TC(tp, rfc6241_user_fields);
	ATF_TP_ADD_TC(tp, rfc6241_subtrees);
	ATF_TP_ADD_TC(tp, rfc6241_interface);
	ATF_TP_ADD_TC(tp, content_match);
	ATF_TP_ADD_TC(tp, xpath);
	ATF_TP_ADD_TC(tp, nacm);
	ATF_TP_ADD_TC(tp, refused);
	return (atf_no_error());
}
