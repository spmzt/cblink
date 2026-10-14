/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cblink's XPath-lite evaluator against libyang's (PLAN-SDN-YANG 2.2.6),
 * a developer's tool the corpus case runs.  The corpus's tables
 * (corpus.h) and a libyang context of its modules, every feature on in
 * both; data filled by yfill, a tree of each (a node libyang will not
 * take left out of both); and expressions evaluated over both from the
 * same node: every when, must and leafref path of the corpus at each
 * node it is on, as written (the tree as it is, not as a when sees it),
 * and expressions made of the data, seeded.  A node set is compared as
 * the set of its nodes, the rest as values.  Made-up expressions never
 * depend on the order of siblings, which YANG does not define: libyang
 * keeps the schema's, cblink the SIDs'.
 *
 * Where libyang departs from the specifications, the tool says so and
 * does not count it: deref() of a leafref with no target fails in
 * libyang (RFC 7950 section 10.3.1: the nodes it refers to, none), and
 * substring() from a start below 0 takes too many characters there
 * (XPath 1.0 section 4.2), so none is made; and libyang reads as numbers
 * strings XPath does not, "infinity" or "1e3" (section 4.4: NaN), so a
 * number made of such a value is not compared.
 *
 * usage: xpdiff dir [seed [count]]
 */

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "cbl_data.h"
#include "corpus.h"
#include "yfill.h"

/* Pointer maps: cblink's nodes to libyang's and back. */
struct map {
	const void	**k, **v;
	size_t		 n, cap;
};

static size_t
hash(const void *p, size_t cap)
{

	return (((uintptr_t)p >> 4) * 0x9e3779b97f4a7c15ULL & (cap - 1));
}

static void
map_put(struct map *m, const void *k, const void *v)
{
	size_t i;

	if ((m->n + 1) * 2 > m->cap) {
		struct map o = *m;

		m->cap = o.cap > 0 ? o.cap * 2 : 1024;
		m->n = 0;
		if ((m->k = calloc(m->cap, sizeof(*m->k))) == NULL ||
		    (m->v = calloc(m->cap, sizeof(*m->v))) == NULL)
			err(1, "calloc");
		for (size_t j = 0; j < o.cap; j++)
			if (o.k[j] != NULL)
				map_put(m, o.k[j], o.v[j]);
		free(o.k);
		free(o.v);
	}
	for (i = hash(k, m->cap); m->k[i] != NULL && m->k[i] != k;
	    i = (i + 1) & (m->cap - 1))
		;
	if (m->k[i] == NULL)
		m->n++;
	m->k[i] = k;
	m->v[i] = v;
}

static const void *
map_get(const struct map *m, const void *k)
{

	if (m->cap == 0)
		return (NULL);
	for (size_t i = hash(k, m->cap); m->k[i] != NULL;
	    i = (i + 1) & (m->cap - 1))
		if (m->k[i] == k)
			return (m->v[i]);
	return (NULL);
}

static struct ly_ctx *ly;
static cbl_dtree *t;
static struct lyd_node *ltree;
static struct map c2l, l2c;
static const cbl_dnode **nodes, **leaves;
static size_t nnodes, nleaves, maxnodes, maxleaves;
static size_t nexpr, ndiff, ndrop, nboth, ndangling, nrepoint, nnum;
static uint64_t rng;
static bool verbose;		/* $XPDIFF_VERBOSE: what is left out */

static uint32_t
rnd(uint32_t n)
{

	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (n > 0 ? (uint32_t)(rng % n) : 0);
}

/* A node's string value, cblink's (malloc'd), or NULL. */
static char *
sval(const cbl_dnode *n)
{
	struct cbl_xval v;
	char why[256], *s;

	if (cbl_xp_eval(t, "string(.)", n, NULL, &v, why, sizeof(why)) != 0)
		return (NULL);
	s = v.s;
	v.s = NULL;
	cbl_xval_free(&v);
	return (s);
}

/*
 * yfill's identityrefs are any SID: each leaf's made an identity derived
 * from its bases, as libyang takes, and derived-from() needs, them.
 */
static void
fix_idents(cbl_dnode *n, int depth)
{
	uint64_t cand[256];

	if (depth > 64)
		return;
	for (cbl_dnode *c = cbl_dnode_first(n); c != NULL;
	    c = cbl_dnode_next(c)) {
		const struct cbl_ynode *s = cbl_dnode_schema(c);
		const struct cbl_ytype *ty = s->type;
		size_t nc = 0;

		fix_idents(c, depth + 1);
		if (ty == NULL || ty->kind != CBL_YT_IDENTITYREF ||
		    s->kind != CBL_YN_LEAF || (s->flags & CBL_YNF_KEY))
			continue;
		for (uint32_t i = 0; i < corpus_schema.nident && nc < 256;
		    i++) {
			bool all = ty->nbases > 0;

			for (uint16_t b = 0; b < ty->nbases && all; b++)
				all = cbl_yderived_from(&corpus_schema,
				    corpus_schema.ident[i].sid, ty->bases[b],
				    false);
			if (all)
				cand[nc++] = corpus_schema.ident[i].sid;
		}
		if (nc > 0)
			(void)cbl_dnode_set(c, &cand[rnd((uint32_t)nc)]);
	}
}

/*
 * The implicit nodes libyang made under a node it was given; not one
 * made of cblink's, an empty non-presence container, which it flags so
 * too.
 */
static void
strip(struct lyd_node *first)
{
	struct lyd_node *n, *next;

	for (n = first; n != NULL; n = next) {
		next = n->next;
		if ((n->flags & LYD_DEFAULT) && map_get(&l2c, n) == NULL) {
			lyd_free_tree(n);
			continue;
		}
		strip(lyd_child(n));
	}
}

/* Tree c's children made libyang's under lp; those it will not take
 * left out of both. */
static void
convert(cbl_dnode *c, struct lyd_node *lp, int depth)
{
	cbl_dnode *x, *next;

	if (depth > 64)
		return;
	for (x = cbl_dnode_first(c); x != NULL; x = next) {
		const struct cbl_ynode *s = cbl_dnode_schema(x);
		const struct cbl_ynode *ps = cbl_dnode_schema(c);
		const struct lys_module *mod;
		struct lyd_node *l = NULL;
		LY_ERR e = LY_EINVAL;
		char *v;

		next = cbl_dnode_next(x);
		/* A key: made with its entry. */
		if ((s->flags & CBL_YNF_KEY) && ps != NULL &&
		    ps->kind == CBL_YN_LIST) {
			for (struct lyd_node *k = lyd_child(lp); k != NULL;
			    k = k->next)
				if (k->schema != NULL &&
				    strcmp(k->schema->name, s->name) == 0 &&
				    strcmp(k->schema->module->name,
				    s->module->name) == 0) {
					map_put(&c2l, x, k);
					map_put(&l2c, k, x);
				}
			continue;
		}
		mod = ly_ctx_get_module_implemented(ly, s->module->name);
		if (mod != NULL)
			switch (s->kind) {
			case CBL_YN_CONTAINER:
				e = lyd_new_inner(lp, mod, s->name, 0, &l);
				break;
			case CBL_YN_LIST: {
				const char *keys[16];
				char *kv[16] = { 0 };
				bool ok = s->nkeys <= 16;

				for (uint16_t k = 0; ok && k < s->nkeys; k++) {
					kv[k] = sval(cbl_dnode_child(x,
					    s->child[s->keys[k]]));
					keys[k] = kv[k];
					ok = kv[k] != NULL;
				}
				if (ok)
					e = lyd_new_list3(lp, mod, s->name,
					    keys, NULL, 0, &l);
				for (uint16_t k = 0; k < s->nkeys && k < 16;
				    k++)
					free(kv[k]);
				break;
			}
			case CBL_YN_LEAF:
			case CBL_YN_LEAFLIST:
				if ((v = sval(x)) != NULL)
					e = lyd_new_term(lp, mod, s->name, v, 0,
					    &l);
				free(v);
				break;
			default:
				break;
			}
		if (e != LY_SUCCESS) {
			if (verbose)
				fprintf(stderr, "left out: %s:%s: %s\n",
				    s->module->name, s->name,
				    ly_last_logmsg() != NULL ?
				    ly_last_logmsg() : "?");
			ndrop++;
			if (l != NULL)
				lyd_free_tree(l);
			(void)cbl_dnode_remove(x);
			continue;
		}
		if (lp == NULL)
			lyd_insert_sibling(ltree, l, &ltree);
		strip(lyd_child(l));
		map_put(&c2l, x, l);
		map_put(&l2c, l, x);
		if (s->kind == CBL_YN_CONTAINER || s->kind == CBL_YN_LIST)
			convert(x, l, depth + 1);
	}
}

static void
collect(const cbl_dnode *n)
{

	for (const cbl_dnode *c = cbl_dnode_first(n); c != NULL;
	    c = cbl_dnode_next(c)) {
		if (nnodes == maxnodes) {
			maxnodes = maxnodes > 0 ? maxnodes * 2 : 1024;
			if ((nodes = reallocarray(nodes, maxnodes,
			    sizeof(*nodes))) == NULL)
				err(1, "reallocarray");
		}
		nodes[nnodes++] = c;
		if (cbl_dnode_schema(c)->type != NULL) {
			if (nleaves == maxleaves) {
				maxleaves = maxleaves > 0 ? maxleaves * 2 :
				    1024;
				if ((leaves = reallocarray(leaves, maxleaves,
				    sizeof(*leaves))) == NULL)
					err(1, "reallocarray");
			}
			leaves[nleaves++] = c;
		}
		collect(c);
	}
}

struct buf {
	char	*p;
	size_t	 n, max;
};

static void
add(struct buf *b, const char *s)
{
	size_t len = strlen(s);

	if (b->n + len + 1 > b->max) {
		b->max = (b->n + len + 1) * 2;
		if ((b->p = realloc(b->p, b->max)) == NULL)
			err(1, "realloc");
	}
	memcpy(b->p + b->n, s, len + 1);
	b->n += len;
}

static char	*path_of(const cbl_dnode *, bool, bool *);

/*
 * Results.
 */

enum { R_ERR, R_NODES, R_BOOL, R_NUM, R_STR };

struct res {
	int		 kind;
	bool		 b;
	long double	 num;
	char		*s;
	const void	**nodes;
	size_t		 n;
	char		 err[256];
	char		*shown;		/* the nodes' paths, for a report */
};

static int
by_ptr(const void *a, const void *b)
{
	uintptr_t x = (uintptr_t)*(const void *const *)a;
	uintptr_t y = (uintptr_t)*(const void *const *)b;

	return (x < y ? -1 : x > y);
}

static void
res_free(struct res *r)
{

	free(r->s);
	free(r->nodes);
	free(r->shown);
	memset(r, 0, sizeof(*r));
}

static void
c_eval(const char *expr, const cbl_dnode *ctx, struct res *r)
{
	struct cbl_xval v;

	memset(r, 0, sizeof(*r));
	if (cbl_xp_eval(t, expr, ctx, ctx, &v, r->err, sizeof(r->err)) != 0)
		return;
	switch (v.kind) {
	case CBL_XV_NODES:
		r->kind = R_NODES;
		if ((r->nodes = calloc(v.n + 1, sizeof(*r->nodes))) == NULL)
			err(1, "calloc");
		for (size_t i = 0; i < v.n; i++)
			r->nodes[i] = v.nodes[i];
		r->n = v.n;
		qsort(r->nodes, r->n, sizeof(*r->nodes), by_ptr);
		{
			struct buf b = { 0 };
			bool u;

			add(&b, "");
			for (size_t i = 0; i < v.n && i < 12; i++) {
				char *p = v.nodes[i] == cbl_dtree_root(t) ?
				    NULL : path_of(v.nodes[i], true, &u);

				add(&b, "\n    ");
				add(&b, p != NULL ? p : "/");
				free(p);
			}
			r->shown = b.p;
		}
		break;
	case CBL_XV_BOOL:
		r->kind = R_BOOL;
		r->b = v.b;
		break;
	case CBL_XV_NUMBER:
		r->kind = R_NUM;
		r->num = v.num;
		break;
	case CBL_XV_STRING:
		r->kind = R_STR;
		r->s = v.s;
		v.s = NULL;
		break;
	}
	cbl_xval_free(&v);
}

static void
l_eval(const char *expr, const cbl_dnode *ctx, struct res *r)
{
	const struct lyd_node *lctx = NULL;
	struct ly_set *set = NULL;
	LY_XPATH_TYPE type;
	char *str = NULL;
	long double num = 0;
	ly_bool b = 0;

	memset(r, 0, sizeof(*r));
	if (ctx != cbl_dtree_root(t) && (lctx = map_get(&c2l, ctx)) == NULL) {
		snprintf(r->err, sizeof(r->err), "no libyang node");
		return;
	}
	if (lyd_eval_xpath4(lctx, ltree, NULL, expr, LY_VALUE_JSON, NULL,
	    NULL, &type, &set, &str, &num, &b) != LY_SUCCESS) {
		snprintf(r->err, sizeof(r->err), "%s",
		    ly_last_logmsg() != NULL ? ly_last_logmsg() : "?");
		return;
	}
	switch (type) {
	case LY_XPATH_NODE_SET:
		r->kind = R_NODES;
		if ((r->nodes = calloc(set->count + 1,
		    sizeof(*r->nodes))) == NULL)
			err(1, "calloc");
		for (uint32_t i = 0; i < set->count; i++) {
			const void *c = map_get(&l2c, set->dnodes[i]);

			/* Not one of cblink's: itself, never equal. */
			r->nodes[r->n++] = c != NULL ? c : set->dnodes[i];
		}
		qsort(r->nodes, r->n, sizeof(*r->nodes), by_ptr);
		{
			struct buf sb = { 0 };

			add(&sb, "");
			for (uint32_t i = 0; i < set->count && i < 12; i++) {
				char *p = lyd_path(set->dnodes[i], LYD_PATH_STD,
				    NULL, 0);

				add(&sb, "\n    ");
				add(&sb, p != NULL ? p : "?");
				if (map_get(&l2c, set->dnodes[i]) == NULL)
					add(&sb, " (not cblink's)");
				free(p);
			}
			r->shown = sb.p;
		}
		break;
	case LY_XPATH_STRING:
		r->kind = R_STR;
		r->s = str;
		str = NULL;
		break;
	case LY_XPATH_NUMBER:
		r->kind = R_NUM;
		r->num = num;
		break;
	case LY_XPATH_BOOLEAN:
		r->kind = R_BOOL;
		r->b = b;
		break;
	}
	ly_set_free(set, NULL);
	free(str);
}

static bool
same(const struct res *a, const struct res *b)
{

	if (a->kind != b->kind)
		return (false);
	switch (a->kind) {
	case R_NODES:
		return (a->n == b->n && (a->n == 0 || memcmp(a->nodes,
		    b->nodes, a->n * sizeof(*a->nodes)) == 0));
	case R_BOOL:
		return (a->b == b->b);
	case R_NUM:
		if (isnan(a->num) || isnan(b->num))
			return (isnan(a->num) && isnan(b->num));
		if (isinf(a->num) || isinf(b->num))
			return (a->num == b->num);
		return (fabsl(a->num - b->num) <= 1e-9L *
		    fmaxl(1, fabsl(a->num)));
	case R_STR:
		return (strcmp(a->s, b->s) == 0);
	default:
		return (true);
	}
}

static void
show(const char *who, const struct res *r)
{

	switch (r->kind) {
	case R_ERR:
		fprintf(stderr, "  %s: error: %s\n", who, r->err);
		break;
	case R_NODES:
		fprintf(stderr, "  %s: %zu nodes%s\n", who, r->n,
		    r->shown != NULL ? r->shown : "");
		break;
	case R_BOOL:
		fprintf(stderr, "  %s: %s\n", who, r->b ? "true" : "false");
		break;
	case R_NUM:
		fprintf(stderr, "  %s: %.17Lg\n", who, r->num);
		break;
	case R_STR:
		fprintf(stderr, "  %s: \"%s\"\n", who, r->s);
		break;
	}
}

/* expr from ctx in both: the same? */
static void
both(const char *expr, const cbl_dnode *ctx, const char *what)
{
	struct res c, l;
	char *at;
	bool uniq;

	nexpr++;
	c_eval(expr, ctx, &c);
	l_eval(expr, ctx, &l);
	if (c.kind == R_ERR && l.kind == R_ERR && verbose && nboth < 40)
		fprintf(stderr, "both fail: %s\n  cblink: %s\n  libyang: %s\n",
		    expr, c.err, l.err);
	if (c.kind == R_ERR && l.kind == R_ERR)
		nboth++;
	/* libyang's deref() of a dangling leafref: not counted. */
	if (c.kind != R_ERR && l.kind == R_ERR && strstr(expr, "deref(") !=
	    NULL && strstr(l.err, "no target instance") != NULL)
		ndangling++;
	else if (!same(&c, &l)) {
		if (ndiff++ < 30) {
			at = ctx == cbl_dtree_root(t) ? NULL :
			    path_of(ctx, true, &uniq);
			fprintf(stderr, "%s: %s\n  from %s\n", what, expr,
			    at != NULL ? at : "/");
			free(at);
			show("cblink", &c);
			show("libyang", &l);
		}
	}
	res_free(&c);
	res_free(&l);
}

/*
 * Expressions made of the data.
 */

/* s quoted, into b; false if it has both quotes. */
static bool
quote(struct buf *b, const char *s)
{
	const char *q = strchr(s, '\'') == NULL ? "'" :
	    strchr(s, '"') == NULL ? "\"" : NULL;

	if (q == NULL)
		return (false);
	add(b, q);
	add(b, s);
	add(b, q);
	return (true);
}

/*
 * Node n's absolute path, malloc'd: each step by its module, an entry
 * by its keys and a leaf-list's value if keys; *uniq if it names n alone
 * (a keyless list's entries it cannot tell apart).  NULL: a value no
 * literal can hold.
 */
static char *
path_of(const cbl_dnode *n, bool keys, bool *uniq)
{
	const cbl_dnode *chain[80];
	struct buf b = { 0 };
	size_t nc = 0;
	char *v;

	*uniq = true;
	for (const cbl_dnode *a = n; a != NULL && cbl_dnode_schema(a) != NULL;
	    a = cbl_dnode_parent(a))
		if (nc < 80)
			chain[nc++] = a;
	add(&b, "");
	while (nc-- > 0) {
		const cbl_dnode *a = chain[nc];
		const struct cbl_ynode *s = cbl_dnode_schema(a);

		add(&b, "/");
		add(&b, s->module->name);
		add(&b, ":");
		add(&b, s->name);
		if (s->kind == CBL_YN_LIST && s->nkeys == 0)
			*uniq = false;
		if (!keys) {
			if (s->kind == CBL_YN_LIST || s->kind == CBL_YN_LEAFLIST)
				*uniq = false;
			continue;
		}
		for (uint16_t k = 0; s->kind == CBL_YN_LIST && k < s->nkeys;
		    k++) {
			const struct cbl_ynode *ks = s->child[s->keys[k]];

			if ((v = sval(cbl_dnode_child(a, ks))) == NULL)
				goto bad;
			add(&b, "[");
			add(&b, ks->module->name);
			add(&b, ":");
			add(&b, ks->name);
			add(&b, "=");
			if (!quote(&b, v)) {
				free(v);
				goto bad;
			}
			free(v);
			add(&b, "]");
		}
		if (s->kind == CBL_YN_LEAFLIST) {
			if ((v = sval(a)) == NULL)
				goto bad;
			add(&b, "[.=");
			if (!quote(&b, v)) {
				free(v);
				goto bad;
			}
			free(v);
			add(&b, "]");
		}
	}
	return (b.p);
bad:
	free(b.p);
	return (NULL);
}

static int
kind_of(const cbl_dnode *n)
{
	const struct cbl_ytype *ty = cbl_dnode_schema(n)->type;

	return (ty != NULL ? ty->kind : -1);
}

static bool
numeric(int k)
{

	return (k == CBL_YT_INT8 || k == CBL_YT_INT16 || k == CBL_YT_INT32 ||
	    k == CBL_YT_INT64 || k == CBL_YT_UINT8 || k == CBL_YT_UINT16 ||
	    k == CBL_YT_UINT32 || k == CBL_YT_UINT64 ||
	    k == CBL_YT_DECIMAL64);
}

/* Whether s is a number to strtold(3), not to XPath (section 3.7). */
static bool
c_only_number(const char *s)
{
	const char *p = s + strspn(s, " \t\r\n");
	char *end;
	bool digits = false;

	errno = 0;
	(void)strtold(s, &end);
	if (end == s || end[strspn(end, " \t\r\n")] != '\0')
		return (false);
	if (*p == '-')
		p++;
	for (; *p >= '0' && *p <= '9'; p++)
		digits = true;
	if (*p == '.')
		for (p++; *p >= '0' && *p <= '9'; p++)
			digits = true;
	return (!digits || p[strspn(p, " \t\r\n")] != '\0');
}

/* Whether a node expr finds has a value only strtold(3) reads. */
static bool
num_trap(const char *expr)
{
	struct cbl_xval v;
	char why[256], *sv;
	bool trap = false;

	if (cbl_xp_eval(t, expr, NULL, NULL, &v, why, sizeof(why)) != 0)
		return (true);
	for (size_t i = 0; v.kind == CBL_XV_NODES && i < v.n && !trap; i++)
		if ((sv = sval(v.nodes[i])) != NULL) {
			trap = c_only_number(sv);
			free(sv);
		}
	cbl_xval_free(&v);
	if (trap)
		nnum++;
	return (trap);
}

/* A leaf picked at random, its path and value; false: none fit. */
struct pick {
	const cbl_dnode	*n;
	char		*path;		/* with keys */
	char		*gen;		/* without: all of its kind */
	char		*v;
	int		 kind;
	bool		 uniq;
};

static bool
pick(struct pick *p)
{
	bool u;

	memset(p, 0, sizeof(*p));
	if (nleaves == 0)
		return (false);
	p->n = leaves[rnd((uint32_t)nleaves)];
	p->kind = kind_of(p->n);
	if ((p->path = path_of(p->n, true, &p->uniq)) == NULL ||
	    (p->gen = path_of(p->n, false, &u)) == NULL ||
	    (p->v = sval(p->n)) == NULL) {
		free(p->path);
		free(p->gen);
		free(p->v);
		return (false);
	}
	return (true);
}

static void
unpick(struct pick *p)
{

	free(p->path);
	free(p->gen);
	free(p->v);
}

/* A value's string, for functions of strings: one with a string, the
 * same in both; an instance-identifier's is written two ways. */
static bool
strfit(const struct pick *p)
{

	return (p->uniq && p->kind != CBL_YT_INSTANCEID &&
	    p->kind != CBL_YT_UNION);
}

/* Leafref leaf n given the value of a node its path finds, if one. */
static void
repoint(const cbl_dnode *n, char **v)
{
	const struct cbl_ynode *s = cbl_dnode_schema(n);
	struct lyd_node *ln = (struct lyd_node *)(uintptr_t)map_get(&c2l, n);
	struct cbl_xval tv;
	const cbl_dnode *tg;
	char why[256], *nv;

	if (ln == NULL || cbl_xp_eval(t, corpus_schema.xpath[s->type->path],
	    n, n, &tv, why, sizeof(why)) != 0)
		return;
	if (tv.kind != CBL_XV_NODES || tv.n == 0) {
		cbl_xval_free(&tv);
		return;
	}
	tg = tv.nodes[rnd((uint32_t)tv.n)];
	cbl_xval_free(&tv);
	if ((nv = sval(tg)) == NULL)
		return;
	if (lyd_change_term(ln, nv) == LY_SUCCESS) {
		if (cbl_dnode_set((cbl_dnode *)(uintptr_t)n,
		    cbl_dnode_value(tg)) == 0) {
			nrepoint++;
			free(*v);
			*v = nv;
			return;
		}
		(void)lyd_change_term(ln, *v);
	}
	free(nv);
}

static void
made_up(void)
{
	static const char *const pats[] = { "[a-z]+", ".*", "\\d+",
	    "[A-Za-z0-9 ._-]*", "\\p{L}+" };
	static const char *const arith[] = { " * 2 - 1", " mod 7", " div 3",
	    " + 0.5" };
	struct pick a, b;
	struct buf e = { 0 };
	const cbl_dnode *ctx = cbl_dtree_root(t);
	char tmp[8192], frag[64];
	const struct cbl_ynode *s;

	if (!pick(&a))
		return;
	if (!pick(&b)) {
		unpick(&a);
		return;
	}
	s = cbl_dnode_schema(a.n);
	add(&e, "");
	switch (rnd(25)) {
	case 0:
		add(&e, a.path);
		break;
	case 1:
	case 2:
		add(&e, a.path);
		add(&e, rnd(2) ? " = " : " != ");
		if (!quote(&e, a.v))
			goto out;
		break;
	case 3:
		if (!strfit(&a))
			goto out;
		snprintf(tmp, sizeof(tmp), "string(%s)", a.path);
		add(&e, tmp);
		break;
	case 4:
	case 5:
		if (!strfit(&a))
			goto out;
		snprintf(tmp, sizeof(tmp), "%s(%s)", rnd(2) ? "string-length" :
		    "normalize-space", a.path);
		add(&e, tmp);
		break;
	case 6:
		if (!strfit(&a))
			goto out;
		snprintf(tmp, sizeof(tmp), "translate(%s, 'aeiou-:', 'AE_')",
		    a.path);
		add(&e, tmp);
		break;
	case 7: {
		static const char *const st[] = { "0", "1", "1.5", "2", "0.4",
		    "0 div 0" };
		static const char *const ln[] = { "1", "2.5", "3", "100" };

		if (!strfit(&a))
			goto out;
		snprintf(tmp, sizeof(tmp), "substring(%s, %s, %s)", a.path,
		    st[rnd(6)], ln[rnd(4)]);
		add(&e, tmp);
		break;
	}
	case 8:
	case 9: {
		size_t len = strlen(a.v), from = len > 0 ? rnd(
		    (uint32_t)len) : 0, n = len - from > 3 ? 3 : len - from;
		bool ascii = true;

		if (!strfit(&a))
			goto out;
		for (size_t i = 0; i < len; i++)
			ascii = ascii && (unsigned char)a.v[i] < 0x80;
		snprintf(frag, sizeof(frag), "%.*s", ascii ? (int)n : 0,
		    a.v + from);
		snprintf(tmp, sizeof(tmp), "%s(%s, ", rnd(2) ? "contains" :
		    "starts-with", a.path);
		add(&e, tmp);
		if (!quote(&e, frag))
			goto out;
		add(&e, ")");
		break;
	}
	case 10:
		snprintf(tmp, sizeof(tmp), "count(%s)", a.gen);
		add(&e, tmp);
		break;
	case 11:
		if (!numeric(a.kind) || !a.uniq || num_trap(a.path))
			goto out;
		snprintf(tmp, sizeof(tmp), "%snumber(%s)%s", rnd(2) ? "-" : "",
		    a.path, arith[rnd(4)]);
		add(&e, tmp);
		break;
	case 12: {
		static const char *const ops[] = { "<", "<=", ">", ">=", "=",
		    "!=" };
		bool self = rnd(3) == 0;	/* on the boundary */
		const char *l = rnd(2) ? a.path : a.gen;
		const char *rt = self ? a.path : rnd(2) ? b.path : b.gen;
		int op = rnd(6);

		/* An order compares numbers. */
		if (op < 4 && (num_trap(l) || num_trap(rt)))
			goto out;
		snprintf(tmp, sizeof(tmp), "%s %s %s", l, ops[op], rt);
		add(&e, tmp);
		break;
	}
	case 13: {
		const cbl_dnode *p = cbl_dnode_parent(a.n);
		int k = rnd(5);

		if (p == NULL || p == cbl_dtree_root(t) ||
		    (k == 3 && cbl_dnode_parent(p) == cbl_dtree_root(t)))
			goto out;
		ctx = p;
		if (k == 0)
			snprintf(tmp, sizeof(tmp), "child::%s:%s",
			    s->module->name, s->name);
		else if (k == 4)
			snprintf(tmp, sizeof(tmp), "%s:%s = ../%s:%s",
			    s->module->name, s->name, s->module->name,
			    s->name);
		else
			snprintf(tmp, sizeof(tmp), "%s", k == 1 ? "count(*)" :
			    k == 2 ? "." : "count(../*)");
		add(&e, tmp);
		break;
	}
	case 14: {
		const struct cbl_yident *id;

		if (a.kind != CBL_YT_IDENTITYREF || corpus_schema.nident == 0)
			goto out;
		id = &corpus_schema.ident[rnd(corpus_schema.nident)];
		if (rnd(3) == 0)
			snprintf(tmp, sizeof(tmp), "derived-from-or-self(%s, "
			    "'%s')", a.gen, a.v);
		else
			snprintf(tmp, sizeof(tmp), "derived-from%s(%s, "
			    "'%s:%s')", rnd(2) ? "" : "-or-self", a.gen,
			    id->module->name, id->name);
		add(&e, tmp);
		break;
	}
	case 15:
		if (a.kind != CBL_YT_ENUMERATION || !a.uniq)
			goto out;
		snprintf(tmp, sizeof(tmp), "enum-value(%s)", a.path);
		add(&e, tmp);
		break;
	case 16:
		if (a.kind != CBL_YT_BITS || s->type->nitems == 0 || !a.uniq)
			goto out;
		snprintf(tmp, sizeof(tmp), "bit-is-set(%s, '%s')", a.path,
		    s->type->items[rnd(s->type->nitems)].name);
		add(&e, tmp);
		break;
	case 17:
		if (!(s->type->flags & CBL_YTF_LEAFREF) || s->lref == NULL)
			goto out;
		/* Mostly pointed at a target first, in both trees. */
		if (s->kind == CBL_YN_LEAF && !(s->flags & CBL_YNF_KEY) &&
		    s->type->path >= 0 && rnd(4) != 0)
			repoint(a.n, &a.v);
		snprintf(tmp, sizeof(tmp), "deref(%s)", a.path);
		add(&e, tmp);
		break;
	case 18:
		snprintf(tmp, sizeof(tmp), "%s | %s", a.path, b.gen);
		add(&e, tmp);
		break;
	case 19:
		snprintf(tmp, sizeof(tmp), "//%s:%s", s->module->name, s->name);
		add(&e, tmp);
		break;
	case 20:
		add(&e, "not(");
		add(&e, a.path);
		add(&e, " = ");
		if (!quote(&e, a.v))
			goto out;
		add(&e, rnd(2) ? ") and " : ") or ");
		add(&e, b.gen);
		break;
	case 21:
		if (a.kind != CBL_YT_STRING || !a.uniq)
			goto out;
		snprintf(tmp, sizeof(tmp), "re-match(%s, '%s')", a.path,
		    pats[rnd(5)]);
		add(&e, tmp);
		break;
	case 22: {
		const cbl_dnode *p = cbl_dnode_parent(a.n);
		char *pg;
		bool u;

		if (p == NULL || p == cbl_dtree_root(t) ||
		    (pg = path_of(p, false, &u)) == NULL)
			goto out;
		snprintf(tmp, sizeof(tmp), "%s[%s:%s = ", pg, s->module->name,
		    s->name);
		free(pg);
		add(&e, tmp);
		if (!quote(&e, a.v))
			goto out;
		add(&e, "]");
		break;
	}
	case 23:
		if (!strfit(&a) || !strfit(&b))
			goto out;
		snprintf(tmp, sizeof(tmp), "concat(%s, '-', %s)", a.path,
		    b.path);
		add(&e, tmp);
		break;
	default:
		snprintf(tmp, sizeof(tmp), "%s(%s)", rnd(2) ? "boolean" :
		    "not", a.gen);
		add(&e, tmp);
		break;
	}
	/* One snprintf() cut short: tmp's size, a path's length at most. */
	if (strlen(e.p) < sizeof(tmp) - 1)
		both(e.p, ctx, "made up");
out:
	free(e.p);
	unpick(&a);
	unpick(&b);
}

/* The corpus's own: each when, must and leafref path where it is. */
static void
corpus_exprs(void)
{
	const struct cbl_yschema *sc = &corpus_schema;

	for (size_t i = 0; i < nnodes; i++) {
		const cbl_dnode *n = nodes[i], *p = cbl_dnode_parent(n);
		const struct cbl_ynode *s = cbl_dnode_schema(n);
		uint16_t k = s->ccase;

		for (uint16_t j = 0; j < s->nwhen; j++)
			both(sc->xpath[s->when[j].expr], s->when[j].ctx ==
			    CBL_YWC_SELF ? n : s->when[j].ctx ==
			    CBL_YWC_ROOT ? cbl_dtree_root(t) : p, "when");
		for (const struct cbl_ychoice *ch = s->choice; ch != NULL;
		    k = ch->parent_case, ch = ch->parent) {
			for (uint16_t j = 0; j < ch->nwhen; j++)
				both(sc->xpath[ch->when[j].expr], p,
				    "choice's when");
			for (uint16_t j = 0; j < ch->cases[k].nwhen; j++)
				both(sc->xpath[ch->cases[k].when[j].expr], p,
				    "case's when");
		}
		for (uint16_t j = 0; j < s->nmust; j++)
			both(sc->xpath[s->must[j].expr], n, "must");
		if (s->type != NULL && (s->type->flags & CBL_YTF_LEAFREF) &&
		    s->type->path >= 0)
			both(sc->xpath[s->type->path], n, "path");
	}
}

int
main(int argc, char *argv[])
{
	const char *feats[] = { "*", NULL };
	unsigned long count;
	size_t nmod = 0;

	if (argc < 2 || argc > 4) {
		fprintf(stderr, "usage: xpdiff dir [seed [count]]\n");
		return (2);
	}
	rng = argc > 2 ? strtoull(argv[2], NULL, 0) : 1;
	rng = rng != 0 ? rng : 1;
	count = argc > 3 ? strtoul(argv[3], NULL, 0) : 20000;
	ly_log_options(LY_LOSTORE_LAST);
	verbose = getenv("XPDIFF_VERBOSE") != NULL;
	if (ly_ctx_new(argv[1], LY_CTX_ENABLE_IMP_FEATURES |
	    LY_CTX_NO_YANGLIBRARY, &ly) != LY_SUCCESS)
		errx(1, "ly_ctx_new");
	/* Again what failed, until no more loads: a module's default may
	 * be an identity of one implemented after it. */
	for (size_t was = SIZE_MAX; nmod != was;) {
		was = nmod;
		nmod = 0;
		for (uint32_t i = 0; i < corpus_schema.nmod; i++)
			if (ly_ctx_get_module_implemented(ly,
			    corpus_schema.mod[i]->name) != NULL ||
			    ly_ctx_load_module(ly, corpus_schema.mod[i]->name,
			    NULL, feats) != NULL)
				nmod++;
			else if (verbose)
				fprintf(stderr, "not loaded: %s: %s\n",
				    corpus_schema.mod[i]->name,
				    ly_last_logmsg() != NULL ?
				    ly_last_logmsg() : "?");
	}
	for (int pass = 0; pass < 2; pass++) {
		if ((t = cbl_dtree_new(&corpus_schema)) == NULL)
			err(1, "cbl_dtree_new");
		for (uint32_t i = 0; i < corpus_schema.nmod; i++)
			for (uint32_t j = 0; j < corpus_schema.mod[i]->ntop;
			    j++) {
				const struct cbl_ynode *n =
				    corpus_schema.mod[i]->top[j];
				struct cbl_ybuf b = { 0 };

				if (n->size == 0 || (n->kind !=
				    CBL_YN_CONTAINER && n->kind != CBL_YN_LIST))
					continue;
				if (yencoded(n, pass, true, &b) == 0)
					(void)cbl_dnode_decode(cbl_dtree_root(t),
					    n, b.p, b.len, CBL_YD_STRICT, NULL, 0,
					    NULL);
				cbl_ybuf_free(&b);
			}
		ltree = NULL;
		fix_idents(cbl_dtree_root(t), 0);
		convert(cbl_dtree_root(t), NULL, 0);
		strip(ltree);
		nnodes = nleaves = 0;
		collect(cbl_dtree_root(t));
		corpus_exprs();
		for (unsigned long i = 0; i < count; i++)
			made_up();
		lyd_free_all(ltree);
		cbl_dtree_free(t);
		free(c2l.k);
		free(c2l.v);
		free(l2c.k);
		free(l2c.v);
		memset(&c2l, 0, sizeof(c2l));
		memset(&l2c, 0, sizeof(l2c));
	}
	free(nodes);
	free(leaves);
	ly_ctx_destroy(ly);
	printf("%zu modules, %zu expressions (%zu errors in both; %zu "
	    "derefs re-pointed, %zu of dangling ones libyang's errors; %zu "
	    "of numbers only libyang's not made), %zu nodes left out, %zu "
	    "differ\n", nmod, nexpr, nboth, nrepoint, ndangling, nnum, ndrop,
	    ndiff);
	return (ndiff != 0);
}
