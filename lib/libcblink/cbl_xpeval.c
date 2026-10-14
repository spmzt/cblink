/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * XPath-lite (YANG.md section 5) over an instance tree (cbl_data.h,
 * PLAN-SDN-YANG 2.2): an expression as the tables hold it, its names by
 * module (cblink-gen writes every step's prefix as its module's name),
 * evaluated with a context node and a current node (RFC 7950 section
 * 6.4.1).
 *
 * A value is a node set, a boolean, a number or a string (XPath 1.0
 * section 1).  A path goes from the root or the context node, or from
 * what its base gives, step by step over the axes child, parent, self
 * and descendant-or-self; a step's name test is its module and name,
 * "*" any child (of one module, with a prefix), node() any node.  A
 * predicate is a condition, never a position.  Comparisons are XPath's,
 * with node sets compared by their nodes' string values (section 3.4).
 * A leaf's string value is its value's canonical form (RFC 7950 section
 * 9), an identityref's "module:name", as the tables write an identity a
 * literal names.  The root is the document's: the parent of the modules'
 * top-level nodes.
 */

#include <sys/types.h>

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"
#include "cbl_pattern.h"
#include "cbl_xpath.h"
#include "cbl_yimpl.h"

struct ev {
	const cbl_dtree		*t;
	const cbl_dnode		*cur;
	const struct cbl_d_view	*view;
	char			*why;
	size_t			 whylen;
	int			 depth;
	size_t			 work;		/* nodes visited, and calls */
	bool			 over;		/* more than CBL_XP_WORK_MAX */
};

static int
fail(struct ev *e, int error, const char *fmt, ...)
{
	va_list ap;

	if (e->why != NULL && e->whylen > 0 && e->why[0] == '\0') {
		va_start(ap, fmt);
		vsnprintf(e->why, e->whylen, fmt, ap);
		va_end(ap);
	}
	return (error);
}

void
cbl_xval_free(struct cbl_xval *v)
{

	if (v == NULL)
		return;
	free(v->nodes);
	free(v->s);
	memset(v, 0, sizeof(*v));
}

/*
 * Node sets: an array, each node once (a set of the pointers seen while
 * one is made, for that).
 */
struct nset {
	const cbl_dnode	**v;
	size_t		 n, max;
	const cbl_dnode	**seen;		/* open addressing, cap a power of 2 */
	size_t		 cap;
};

static int
ns_add(struct nset *s, const cbl_dnode *x)
{
	const cbl_dnode **v;
	size_t i;

	if ((s->n + 1) * 2 > s->cap) {
		size_t cap = s->cap > 0 ? s->cap * 2 : 64;
		const cbl_dnode **seen;

		if ((seen = calloc(cap, sizeof(*seen))) == NULL)
			return (ENOMEM);
		for (size_t j = 0; j < s->cap; j++)
			if (s->seen[j] != NULL) {
				for (i = ((uintptr_t)s->seen[j] >> 4) &
				    (cap - 1); seen[i] != NULL;
				    i = (i + 1) & (cap - 1))
					;
				seen[i] = s->seen[j];
			}
		free(s->seen);
		s->seen = seen;
		s->cap = cap;
	}
	for (i = ((uintptr_t)x >> 4) & (s->cap - 1); s->seen[i] != NULL;
	    i = (i + 1) & (s->cap - 1))
		if (s->seen[i] == x)
			return (0);
	s->seen[i] = x;
	if (s->n == s->max) {
		size_t max = s->max > 0 ? s->max * 2 : 16;

		if ((v = reallocarray(s->v, max, sizeof(*v))) == NULL)
			return (ENOMEM);
		s->v = v;
		s->max = max;
	}
	s->v[s->n++] = x;
	return (0);
}

/* The set made a value, its own array taken. */
static void
ns_value(struct nset *s, struct cbl_xval *v)
{

	memset(v, 0, sizeof(*v));
	v->kind = CBL_XV_NODES;
	v->nodes = s->v;
	v->n = s->n;
	free(s->seen);
	memset(s, 0, sizeof(*s));
}

static void
ns_free(struct nset *s)
{

	free(s->v);
	free(s->seen);
	memset(s, 0, sizeof(*s));
}

/*
 * String values.
 */

struct sbuf {
	char	*p;
	size_t	 n, max;
};

static int
sb_add(struct sbuf *b, const char *s, size_t len)
{
	char *p;

	if (b->n + len + 1 > b->max) {
		size_t max = b->max > 0 ? b->max : 32;

		while (b->n + len + 1 > max)
			max *= 2;
		if ((p = realloc(b->p, max)) == NULL)
			return (ENOMEM);
		b->p = p;
		b->max = max;
	}
	memcpy(b->p + b->n, s, len);
	b->n += len;
	b->p[b->n] = '\0';
	return (0);
}

static int
sb_printf(struct sbuf *b, const char *fmt, ...)
{
	char tmp[64];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(tmp))
		return (EINVAL);
	return (sb_add(b, tmp, (size_t)n));
}

static int64_t
read_int(const void *v, uint32_t size)
{

	switch (size) {
	case 1:
		return (*(const int8_t *)v);
	case 2:
		return (*(const int16_t *)v);
	case 4:
		return (*(const int32_t *)v);
	default:
		return (*(const int64_t *)v);
	}
}

static uint64_t
read_uint(const void *v, uint32_t size)
{

	switch (size) {
	case 1:
		return (*(const uint8_t *)v);
	case 2:
		return (*(const uint16_t *)v);
	case 4:
		return (*(const uint32_t *)v);
	default:
		return (*(const uint64_t *)v);
	}
}

static int
base64(struct sbuf *b, const struct cbl_bytes *by)
{
	static const char al[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const uint8_t *p = by->p;
	char q[4];
	int error;

	for (size_t i = 0; i < by->len; i += 3) {
		uint32_t w = (uint32_t)p[i] << 16;

		if (i + 1 < by->len)
			w |= (uint32_t)p[i + 1] << 8;
		if (i + 2 < by->len)
			w |= p[i + 2];
		q[0] = al[w >> 18 & 63];
		q[1] = al[w >> 12 & 63];
		q[2] = i + 1 < by->len ? al[w >> 6 & 63] : '=';
		q[3] = i + 2 < by->len ? al[w & 63] : '=';
		if ((error = sb_add(b, q, 4)) != 0)
			return (error);
	}
	return (0);
}

static int	value_string(struct sbuf *, const struct cbl_yschema *,
		    const struct cbl_ytype *, const void *);

/* A literal of value v: in quotes it has none of. */
static int
quoted(struct sbuf *b, const struct cbl_yschema *s, const struct cbl_ytype *t,
    const void *v)
{
	struct sbuf in = { 0 };
	const char *q;
	int error;

	if ((error = sb_add(&in, "", 0)) != 0 ||
	    (error = value_string(&in, s, t, v)) != 0) {
		free(in.p);
		return (error);
	}
	q = strchr(in.p, '\'') != NULL ? "\"" : "'";
	if ((error = sb_add(b, q, 1)) == 0 &&
	    (error = sb_add(b, in.p, in.n)) == 0)
		error = sb_add(b, q, 1);
	free(in.p);
	return (error);
}

/*
 * An instance-identifier's string (RFC 7950 section 9.13): from its
 * YANG-CBOR, each node by its module, a list's keys and a leaf-list
 * entry's value as predicates.
 */
static int
iid_string(struct sbuf *b, const struct cbl_yschema *s, const void *v)
{
	const struct cbl_ynode *n, *chain[CBL_D_DEPTH_MAX + 1];
	const void **vals;
	cbl_yarena *a;
	size_t nvals, nc = 0, j = 0;
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if (cbl_yiid_read(s, v, &n, &vals, &nvals, a) != 0) {
		cbl_yarena_free(a);
		return (0);
	}
	for (const struct cbl_ynode *x = n; x != NULL && nc < CBL_D_DEPTH_MAX;
	    x = x->parent)
		chain[nc++] = x;
	error = 0;
	while (nc-- > 0 && error == 0) {
		const struct cbl_ynode *x = chain[nc];

		if ((error = sb_add(b, "/", 1)) != 0 ||
		    (error = sb_add(b, x->module->name,
		    strlen(x->module->name))) != 0 ||
		    (error = sb_add(b, ":", 1)) != 0 ||
		    (error = sb_add(b, x->name, strlen(x->name))) != 0)
			break;
		for (uint16_t k = 0; x->kind == CBL_YN_LIST && k < x->nkeys &&
		    error == 0; k++) {
			const struct cbl_ynode *kn = x->child[x->keys[k]];

			if ((error = sb_add(b, "[", 1)) != 0 ||
			    (error = sb_add(b, kn->module->name,
			    strlen(kn->module->name))) != 0 ||
			    (error = sb_add(b, ":", 1)) != 0 ||
			    (error = sb_add(b, kn->name, strlen(kn->name))) !=
			    0 || (error = sb_add(b, "=", 1)) != 0 ||
			    (error = quoted(b, s, kn->type, vals[j++])) != 0)
				break;
			error = sb_add(b, "]", 1);
		}
		if (error == 0 && x->kind == CBL_YN_LEAFLIST && x == n &&
		    (error = sb_add(b, "[.=", 3)) == 0 &&
		    (error = quoted(b, s, x->type, vals[j++])) == 0)
			error = sb_add(b, "]", 1);
	}
	cbl_yarena_free(a);
	return (error);
}

/* A value of type t, in its canonical form (RFC 7950 section 9). */
static int
value_string(struct sbuf *b, const struct cbl_yschema *s,
    const struct cbl_ytype *t, const void *v)
{
	const struct cbl_bytes *by;
	const struct cbl_yident *id;
	const char *str;
	int64_t i;
	uint64_t u, scale;
	int error;

	switch (t->kind) {
	case CBL_YT_INT8:
	case CBL_YT_INT16:
	case CBL_YT_INT32:
	case CBL_YT_INT64:
		return (sb_printf(b, "%jd", (intmax_t)read_int(v, t->csize)));
	case CBL_YT_UINT8:
	case CBL_YT_UINT16:
	case CBL_YT_UINT32:
	case CBL_YT_UINT64:
		return (sb_printf(b, "%ju", (uintmax_t)read_uint(v,
		    t->csize)));
	case CBL_YT_DECIMAL64: {
		char frac[24];
		size_t n;

		/* At least one digit after the point, no zero after it. */
		i = *(const int64_t *)v;
		scale = 1;
		for (unsigned k = 0; k < t->fdigits; k++)
			scale *= 10;
		u = i < 0 ? (uint64_t)-(i + 1) + 1 : (uint64_t)i;
		snprintf(frac, sizeof(frac), "%0*ju", (int)t->fdigits,
		    (uintmax_t)(u % scale));
		for (n = strlen(frac); n > 1 && frac[n - 1] == '0'; n--)
			frac[n - 1] = '\0';
		return (sb_printf(b, "%s%ju.%s", i < 0 ? "-" : "",
		    (uintmax_t)(u / scale), t->fdigits > 0 ? frac : "0"));
	}
	case CBL_YT_BOOLEAN:
		return (sb_printf(b, "%s", *(const bool *)v ? "true" :
		    "false"));
	case CBL_YT_EMPTY:
		return (0);
	case CBL_YT_STRING:
		str = *(const char *const *)v;
		return (str != NULL ? sb_add(b, str, strlen(str)) : 0);
	case CBL_YT_ENUMERATION:
		i = read_int(v, t->csize);
		for (uint32_t k = 0; k < t->nitems; k++)
			if (t->items[k].value == i)
				return (sb_add(b, t->items[k].name,
				    strlen(t->items[k].name)));
		return (EINVAL);
	case CBL_YT_BITS: {
		bool first = true;

		by = v;
		/* The bits set, by position. */
		for (int64_t pos = 0; (size_t)pos < by->len * 8; pos++) {
			if ((((const uint8_t *)by->p)[pos / 8] &
			    (1u << (pos % 8))) == 0)
				continue;
			for (uint32_t k = 0; k < t->nitems; k++)
				if (t->items[k].value == pos) {
					if ((!first && (error = sb_add(b, " ",
					    1)) != 0) || (error = sb_add(b,
					    t->items[k].name,
					    strlen(t->items[k].name))) != 0)
						return (error);
					first = false;
				}
		}
		return (0);
	}
	case CBL_YT_BINARY:
		return (base64(b, v));
	case CBL_YT_IDENTITYREF:
		if ((id = cbl_yschema_ident(s, *(const uint64_t *)v)) == NULL)
			return (sb_printf(b, "%ju", (uintmax_t)*(const uint64_t *)
			    v));
		if ((error = sb_add(b, id->module->name,
		    strlen(id->module->name))) != 0 ||
		    (error = sb_add(b, ":", 1)) != 0)
			return (error);
		return (sb_add(b, id->name, strlen(id->name)));
	case CBL_YT_INSTANCEID:
		return (iid_string(b, s, v));
	case CBL_YT_UNION: {
		unsigned w = *(const unsigned *)v;

		if (w >= t->nmembers)
			return (EINVAL);
		return (value_string(b, s, t->members[w], (const char *)v +
		    t->voff));
	}
	}
	return (EINVAL);
}

/* Whether the expression sees node c, a child (cbl_d_view). */
static bool
seen(struct ev *e, const cbl_dnode *c)
{
	const struct cbl_d_view *w = e->view;

	/* Each node visited counts: an expression's work is bounded. */
	if (++e->work > CBL_XP_WORK_MAX) {
		e->over = true;
		return (false);
	}
	if (w == NULL)
		return (true);
	if (w->dummy != NULL && c->parent == w->dummy)
		return (false);
	return (w->hide == NULL || c->parent != w->hpar ||
	    !w->hide(w->harg, c->sn));
}

/*
 * A node's first child as the expression sees it, and the next: the
 * root's, the tree's own, then its parent references' (RFC 8528 section
 * 4, cbl_dtree_set_refs()); and its parent, theirs the tree's root.
 */
static const cbl_dnode *
kid1(const struct ev *e, const cbl_dnode *n)
{

	if (n->first == NULL && n == &e->t->root && e->t->refs != NULL)
		return (e->t->refs->root.first);
	return (n->first);
}

static const cbl_dnode *
kidn(const struct ev *e, const cbl_dnode *c)
{

	if (c->next == NULL && c->parent == &e->t->root && e->t->refs != NULL)
		return (e->t->refs->root.first);
	return (c->next);
}

static const cbl_dnode *
up(const struct ev *e, const cbl_dnode *n)
{

	if (e->t->refs != NULL && n->parent == &e->t->refs->root)
		return (&e->t->root);
	return (n->parent);
}

/* Node n's value as the expression sees it: none, the dummy's. */
static const void *
value(const struct ev *e, const cbl_dnode *n)
{

	return (e->view != NULL && n == e->view->dummy ? NULL : n->value);
}

int
cbl_d_vstring(const struct cbl_yschema *s, const struct cbl_ytype *t,
    const void *v, char **out)
{
	struct sbuf b = { 0 };
	int error;

	if ((error = sb_add(&b, "", 0)) != 0 ||
	    (error = value_string(&b, s, t, v)) != 0) {
		free(b.p);
		return (error);
	}
	*out = b.p;
	return (0);
}

/* A node's string value: a leaf's value; else its leaves', in order. */
static int
node_string(struct sbuf *b, struct ev *e, const cbl_dnode *n,
    int depth)
{
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	if (n->sn != NULL && n->sn->type != NULL) {
		if (value(e, n) == NULL)
			return (0);
		return (value_string(b, n->tree->schema, n->sn->type,
		    n->value));
	}
	for (const cbl_dnode *c = kid1(e, n); c != NULL; c = kidn(e, c))
		if (seen(e, c) && (error = node_string(b, e, c, depth + 1)) !=
		    0)
			return (error);
	return (0);
}

static int
str_of_node(struct ev *e, const cbl_dnode *n, char **out)
{
	struct sbuf b = { 0 };
	int error;

	if ((error = sb_add(&b, "", 0)) != 0 ||
	    (error = node_string(&b, e, n, 0)) != 0) {
		free(b.p);
		return (error);
	}
	*out = b.p;
	return (0);
}

/*
 * Conversions (XPath 1.0 sections 4.2, 4.3, 4.4).
 */

static double
str_number(const char *s)
{
	char *end;
	double d;

	s += strspn(s, " \t\n\r");
	if (*s == '\0')
		return (NAN);
	d = strtod(s, &end);
	end += strspn(end, " \t\n\r");
	/* XPath's numbers: digits, a point, a minus; no exponent, no hex. */
	if (*end != '\0' || strpbrk(s, "eExXiInN") != NULL)
		return (NAN);
	return (d);
}

static int
to_string(struct ev *e, const struct cbl_xval *v, char **out)
{
	char buf[64];

	switch (v->kind) {
	case CBL_XV_NODES:
		if (v->n == 0)
			break;
		return (str_of_node(e, v->nodes[0], out));
	case CBL_XV_BOOL:
		*out = strdup(v->b ? "true" : "false");
		return (*out != NULL ? 0 : ENOMEM);
	case CBL_XV_NUMBER:
		if (isnan(v->num))
			snprintf(buf, sizeof(buf), "NaN");
		else if (isinf(v->num))
			snprintf(buf, sizeof(buf), "%sInfinity",
			    v->num < 0 ? "-" : "");
		else if (v->num == floor(v->num) && fabs(v->num) < 1e15)
			snprintf(buf, sizeof(buf), "%.0f", v->num);
		else
			snprintf(buf, sizeof(buf), "%.15g", v->num);
		*out = strdup(buf);
		return (*out != NULL ? 0 : ENOMEM);
	case CBL_XV_STRING:
		*out = strdup(v->s != NULL ? v->s : "");
		return (*out != NULL ? 0 : ENOMEM);
	}
	*out = strdup("");
	return (*out != NULL ? 0 : ENOMEM);
}

static int
to_number(struct ev *e, const struct cbl_xval *v, double *out)
{
	char *s;
	int error;

	switch (v->kind) {
	case CBL_XV_BOOL:
		*out = v->b ? 1 : 0;
		return (0);
	case CBL_XV_NUMBER:
		*out = v->num;
		return (0);
	default:
		if ((error = to_string(e, v, &s)) != 0)
			return (error);
		*out = str_number(s);
		free(s);
		return (0);
	}
}

static bool
to_bool(const struct cbl_xval *v)
{

	switch (v->kind) {
	case CBL_XV_NODES:
		return (v->n > 0);
	case CBL_XV_BOOL:
		return (v->b);
	case CBL_XV_NUMBER:
		return (v->num != 0 && !isnan(v->num));
	case CBL_XV_STRING:
		return (v->s != NULL && v->s[0] != '\0');
	}
	return (false);
}

static void
set_bool(struct cbl_xval *v, bool b)
{

	memset(v, 0, sizeof(*v));
	v->kind = CBL_XV_BOOL;
	v->b = b;
}

static void
set_number(struct cbl_xval *v, double d)
{

	memset(v, 0, sizeof(*v));
	v->kind = CBL_XV_NUMBER;
	v->num = d;
}

static int
set_string(struct cbl_xval *v, char *s)
{

	memset(v, 0, sizeof(*v));
	if (s == NULL)
		return (ENOMEM);
	v->kind = CBL_XV_STRING;
	v->s = s;
	return (0);
}

/*
 * Comparisons (XPath 1.0 section 3.4).
 */

static bool
cmp_num(enum cbl_xp_kind op, double a, double b)
{

	switch (op) {
	case CBL_XP_EQ:
		return (a == b);
	case CBL_XP_NE:
		return (a != b);
	case CBL_XP_LT:
		return (a < b);
	case CBL_XP_LE:
		return (a <= b);
	case CBL_XP_GT:
		return (a > b);
	default:
		return (a >= b);
	}
}

/* Two values none of which is a node set. */
static int
cmp_atoms(struct ev *e, enum cbl_xp_kind op, const struct cbl_xval *a,
    const struct cbl_xval *b, bool *out)
{
	char *sa, *sb;
	double na, nb;
	int error;

	if (op == CBL_XP_EQ || op == CBL_XP_NE) {
		if (a->kind == CBL_XV_BOOL || b->kind == CBL_XV_BOOL) {
			*out = (to_bool(a) == to_bool(b)) == (op == CBL_XP_EQ);
			return (0);
		}
		if (a->kind == CBL_XV_STRING && b->kind == CBL_XV_STRING) {
			*out = (strcmp(a->s, b->s) == 0) == (op == CBL_XP_EQ);
			return (0);
		}
		if (a->kind != CBL_XV_NUMBER && b->kind != CBL_XV_NUMBER) {
			if ((error = to_string(e, a, &sa)) != 0)
				return (error);
			if ((error = to_string(e, b, &sb)) != 0) {
				free(sa);
				return (error);
			}
			*out = (strcmp(sa, sb) == 0) == (op == CBL_XP_EQ);
			free(sa);
			free(sb);
			return (0);
		}
	}
	if ((error = to_number(e, a, &na)) != 0 ||
	    (error = to_number(e, b, &nb)) != 0)
		return (error);
	*out = cmp_num(op, na, nb);
	return (0);
}

/* A node's value as a value of the kind of the other side's. */
static int
node_atom(struct ev *e, const cbl_dnode *n, struct cbl_xval *v)
{
	char *s;
	int error;

	if ((error = str_of_node(e, n, &s)) != 0)
		return (error);
	return (set_string(v, s));
}

static int
compare(struct ev *e, enum cbl_xp_kind op, const struct cbl_xval *a,
    const struct cbl_xval *b, bool *out)
{
	struct cbl_xval x, y;
	int error;

	*out = false;
	/* A node set and a boolean: the set's boolean. */
	if ((a->kind == CBL_XV_NODES && b->kind == CBL_XV_BOOL) ||
	    (b->kind == CBL_XV_NODES && a->kind == CBL_XV_BOOL)) {
		struct cbl_xval ba, bb;

		set_bool(&ba, to_bool(a));
		set_bool(&bb, to_bool(b));
		return (cmp_atoms(e, op, &ba, &bb, out));
	}
	/* Two node sets: some pair whose strings compare so (numbers, for
	 * an order: cmp_atoms() takes two strings so). */
	if (a->kind == CBL_XV_NODES && b->kind == CBL_XV_NODES) {
		for (size_t i = 0; i < a->n && !*out; i++) {
			if ((error = node_atom(e, a->nodes[i], &x)) != 0)
				return (error);
			for (size_t j = 0; j < b->n && !*out; j++) {
				if ((error = node_atom(e, b->nodes[j],
				    &y)) != 0) {
					cbl_xval_free(&x);
					return (error);
				}
				error = cmp_atoms(e, op, &x, &y, out);
				cbl_xval_free(&y);
				if (error != 0) {
					cbl_xval_free(&x);
					return (error);
				}
			}
			cbl_xval_free(&x);
		}
		return (0);
	}
	if (a->kind == CBL_XV_NODES || b->kind == CBL_XV_NODES) {
		const struct cbl_xval *set = a->kind == CBL_XV_NODES ? a : b;
		const struct cbl_xval *other = set == a ? b : a;

		for (size_t i = 0; i < set->n && !*out; i++) {
			if ((error = node_atom(e, set->nodes[i], &x)) != 0)
				return (error);
			/* Against a number, the node's as a number. */
			if (other->kind == CBL_XV_NUMBER) {
				double nx;

				if ((error = to_number(e, &x, &nx)) == 0) {
					cbl_xval_free(&x);
					set_number(&x, nx);
				}
			}
			error = error != 0 ? error : set == a ?
			    cmp_atoms(e, op, &x, other, out) :
			    cmp_atoms(e, op, other, &x, out);
			cbl_xval_free(&x);
			if (error != 0)
				return (error);
		}
		return (0);
	}
	return (cmp_atoms(e, op, a, b, out));
}

/*
 * Paths.
 */

/* Whether node n passes step x's test. */
static bool
test_ok(const struct cbl_xp *x, const cbl_dnode *n)
{

	if (n->sn == NULL)
		return (x->test == CBL_XT_NODE);
	switch (x->test) {
	case CBL_XT_NODE:
		return (true);
	case CBL_XT_ANY:
		return (x->prefix == NULL ||
		    strcmp(x->prefix, n->sn->module->name) == 0);
	case CBL_XT_NAME:
		return (strcmp(x->s, n->sn->name) == 0 && (x->prefix == NULL ||
		    strcmp(x->prefix, n->sn->module->name) == 0));
	default:
		return (false);
	}
}

static int	eval(struct ev *, const struct cbl_xp *, const cbl_dnode *,
		    struct cbl_xval *);
static int	eval_expr(struct ev *, const char *, const cbl_dnode *,
		    const cbl_dnode *, struct cbl_xval *);

/* The nodes of out that pass each predicate, as conditions. */
static int
filter(struct ev *e, struct cbl_xp *const *preds, size_t npreds,
    struct nset *in)
{
	struct cbl_xval v;
	size_t k;
	int error;

	for (size_t p = 0; p < npreds; p++) {
		for (size_t i = k = 0; i < in->n; i++) {
			if ((error = eval(e, preds[p], in->v[i], &v)) != 0)
				return (error);
			if (v.kind == CBL_XV_NUMBER) {
				cbl_xval_free(&v);
				return (fail(e, EINVAL, "a predicate of a "
				    "position: not XPath-lite"));
			}
			if (to_bool(&v))
				in->v[k++] = in->v[i];
			cbl_xval_free(&v);
		}
		in->n = k;
	}
	return (0);
}

static int
descend(struct ev *e, struct nset *out, const struct cbl_xp *x,
    const cbl_dnode *n, int depth)
{
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	if (test_ok(x, n) && (error = ns_add(out, n)) != 0)
		return (error);
	for (const cbl_dnode *c = kid1(e, n); c != NULL; c = kidn(e, c))
		if (seen(e, c) && (error = descend(e, out, x, c, depth + 1)) !=
		    0)
			return (error);
	return (0);
}

/* Step x from each node of in, into out. */
static int
step(struct ev *e, const struct cbl_xp *x, const struct nset *in,
    struct nset *out)
{
	int error = 0;

	for (size_t i = 0; i < in->n && error == 0; i++) {
		const cbl_dnode *n = in->v[i];

		switch (x->axis) {
		case CBL_XA_CHILD:
			for (const cbl_dnode *c = kid1(e, n); c != NULL &&
			    error == 0; c = kidn(e, c))
				if (seen(e, c) && test_ok(x, c))
					error = ns_add(out, c);
			break;
		case CBL_XA_PARENT:
			if (up(e, n) != NULL && test_ok(x, up(e, n)))
				error = ns_add(out, up(e, n));
			break;
		case CBL_XA_SELF:
			if (test_ok(x, n))
				error = ns_add(out, n);
			break;
		case CBL_XA_DESCENDANT_OR_SELF:
			error = descend(e, out, x, n, 0);
			break;
		default:
			return (fail(e, EINVAL, "the %s axis: not XPath-lite",
			    cbl_xp_axis_name(x->axis)));
		}
	}
	if (error != 0)
		return (error);
	return (filter(e, x->preds, x->npreds, out));
}

static int
eval_path(struct ev *e, const struct cbl_xp *x, const cbl_dnode *ctx,
    struct cbl_xval *out)
{
	struct nset cur = { 0 }, next;
	struct cbl_xval base;
	int error;

	if (x->base != NULL) {
		if ((error = eval(e, x->base, ctx, &base)) != 0)
			return (error);
		if (base.kind != CBL_XV_NODES) {
			cbl_xval_free(&base);
			return (fail(e, EINVAL, "a path from what is not a "
			    "node set"));
		}
		for (size_t i = 0; i < base.n && error == 0; i++)
			error = ns_add(&cur, base.nodes[i]);
		cbl_xval_free(&base);
	} else
		error = ns_add(&cur, x->absolute ? &e->t->root : ctx);
	for (size_t i = 0; i < x->nargs && error == 0; i++) {
		memset(&next, 0, sizeof(next));
		error = step(e, x->args[i], &cur, &next);
		ns_free(&cur);
		cur = next;
	}
	if (error != 0) {
		ns_free(&cur);
		return (error);
	}
	ns_value(&cur, out);
	return (0);
}

/*
 * Functions: XPath 1.0's that XPath-lite has (section 4: count(), not(),
 * true(), false(), boolean(), number(), string() and the string
 * functions) and YANG's (RFC 7950 section 10: current(), deref(),
 * derived-from(), derived-from-or-self(), enum-value(), bit-is-set(),
 * re-match()).
 */

/* The length of the UTF-8 character at s, 1 for what is not one. */
static size_t
u8len(const char *s)
{
	unsigned char c = (unsigned char)*s;
	size_t n = c < 0x80 ? 1 : c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : c >= 0xc0 ?
	    2 : 1;

	for (size_t i = 1; i < n; i++)
		if (((unsigned char)s[i] & 0xc0) != 0x80)
			return (1);
	return (n);
}

static size_t
u8count(const char *s)
{
	size_t n = 0;

	for (; *s != '\0'; s += u8len(s))
		n++;
	return (n);
}

/* The character of s at index i (from 0), and its length; NULL: none. */
static const char *
u8at(const char *s, size_t i, size_t *len)
{

	for (; *s != '\0'; s += u8len(s))
		if (i-- == 0) {
			*len = u8len(s);
			return (s);
		}
	return (NULL);
}

/* XPath's round(): to the nearest, halves up (section 4.4). */
static double
xround(double d)
{

	if (isnan(d) || isinf(d))
		return (d);
	return (floor(d + 0.5));
}

static int
str_arg(struct ev *e, const struct cbl_xval *v, char **out)
{

	return (to_string(e, v, out));
}

/* An identity by its "module:name", as the tables write one; 0: none. */
static uint64_t
ident_sid(const cbl_dtree *t, const char *qname)
{
	const char *colon = strchr(qname, ':'), *name;
	size_t ml;

	if (colon == NULL)
		return (0);
	ml = (size_t)(colon - qname);
	name = colon + 1;
	for (uint32_t i = 0; i < t->schema->nident; i++) {
		const struct cbl_yident *id = &t->schema->ident[i];

		if (strcmp(id->name, name) == 0 &&
		    strlen(id->module->name) == ml &&
		    strncmp(id->module->name, qname, ml) == 0)
			return (id->sid);
	}
	return (0);
}

/* The member of a union, or the type, of kind k a node's value is. */
static const struct cbl_ytype *
value_of(const struct ev *e, const cbl_dnode *n, int kind, const void **v)
{
	const struct cbl_ytype *t;

	if (n->sn == NULL || (t = n->sn->type) == NULL || value(e, n) == NULL)
		return (NULL);
	*v = n->value;
	if (t->kind == CBL_YT_UNION) {
		unsigned w = *(const unsigned *)n->value;

		if (w >= t->nmembers)
			return (NULL);
		*v = (const char *)n->value + t->voff;
		t = t->members[w];
	}
	return (t->kind == kind ? t : NULL);
}

static int
func_deref(struct ev *e, const struct cbl_xval *a, struct cbl_xval *out)
{
	const cbl_dnode *n, *x;
	struct cbl_xval tv;
	struct nset s = { 0 };
	cbl_yarena *ar;
	int error = 0;

	if (a->kind != CBL_XV_NODES)
		return (fail(e, EINVAL, "deref() of what is not a node set"));
	if (a->n > 0 && (n = a->nodes[0])->sn != NULL &&
	    n->sn->type != NULL && value(e, n) != NULL) {
		const struct cbl_ytype *t = n->sn->type;

		if ((t->flags & CBL_YTF_LEAFREF) != 0 && t->path >= 0) {
			/* Its path's nodes, those of its value. */
			if ((error = eval_expr(e, n->tree->schema->xpath[t->path],
			    n, n, &tv)) != 0)
				return (error);
			for (size_t i = 0; i < tv.n && error == 0; i++)
				if (tv.nodes[i]->value != NULL &&
				    cbl_dvalue_equal(t, tv.nodes[i]->value,
				    n->value))
					error = ns_add(&s, tv.nodes[i]);
			cbl_xval_free(&tv);
		} else if (t->kind == CBL_YT_INSTANCEID) {
			if ((ar = cbl_yarena_new()) == NULL)
				return (ENOMEM);
			if ((x = cbl_d_iid_node(e->t, n->value, ar)) != NULL)
				error = ns_add(&s, x);
			cbl_yarena_free(ar);
		}
	}
	if (error != 0) {
		ns_free(&s);
		return (error);
	}
	ns_value(&s, out);
	return (0);
}

static int
func_strings(struct ev *e, const char *f, struct cbl_xval *a, size_t n,
    struct cbl_xval *out, bool *done)
{
	struct sbuf b = { 0 };
	char *s1 = NULL, *s2 = NULL, *s3 = NULL, *p;
	const char *c;
	double start, len;
	size_t cl;
	int error;

	*done = true;
	if ((error = sb_add(&b, "", 0)) != 0)
		return (error);
	if (strcmp(f, "concat") == 0 && n >= 2) {
		for (size_t i = 0; i < n && error == 0; i++)
			if ((error = str_arg(e, &a[i], &s1)) == 0) {
				error = sb_add(&b, s1, strlen(s1));
				free(s1);
				s1 = NULL;
			}
		if (error == 0)
			return (set_string(out, b.p));
		free(b.p);
		return (error);
	}
	free(b.p);
	memset(&b, 0, sizeof(b));
	if (n >= 1 && (error = str_arg(e, &a[0], &s1)) != 0)
		return (error);
	if (n >= 2 && (error = str_arg(e, &a[1], &s2)) != 0)
		goto out;
	if (strcmp(f, "contains") == 0 && n == 2)
		set_bool(out, strstr(s1, s2) != NULL);
	else if (strcmp(f, "starts-with") == 0 && n == 2)
		set_bool(out, strncmp(s1, s2, strlen(s2)) == 0);
	else if (strcmp(f, "string-length") == 0 && n <= 1)
		set_number(out, (double)u8count(n == 1 ? s1 : ""));
	else if (strcmp(f, "substring-before") == 0 && n == 2) {
		p = strstr(s1, s2);
		error = set_string(out, p != NULL ? strndup(s1,
		    (size_t)(p - s1)) : strdup(""));
	} else if (strcmp(f, "substring-after") == 0 && n == 2) {
		p = strstr(s1, s2);
		error = set_string(out, strdup(p != NULL ? p + strlen(s2) :
		    ""));
	} else if (strcmp(f, "substring") == 0 && (n == 2 || n == 3)) {
		/* Characters at positions p, start <= p < start + len,
		 * both rounded (section 4.2). */
		if ((error = to_number(e, &a[1], &start)) != 0)
			goto out;
		len = INFINITY;
		if (n == 3 && (error = to_number(e, &a[2], &len)) != 0)
			goto out;
		start = xround(start);
		len = xround(len);
		if ((error = sb_add(&b, "", 0)) != 0)
			goto out;
		for (size_t i = 0; (c = u8at(s1, i, &cl)) != NULL && error == 0;
		    i++) {
			double pos = (double)(i + 1);

			if (pos >= start && pos < start + len)
				error = sb_add(&b, c, cl);
		}
		if (error == 0) {
			error = set_string(out, b.p);
			b.p = NULL;
		}
	} else if (strcmp(f, "normalize-space") == 0 && n <= 1) {
		const char *q = n == 1 ? s1 : "";
		bool space = false;

		if ((error = sb_add(&b, "", 0)) != 0)
			goto out;
		q += strspn(q, " \t\r\n");
		for (; *q != '\0' && error == 0; q++) {
			if (strchr(" \t\r\n", *q) != NULL) {
				space = true;
				continue;
			}
			if (space)
				error = sb_add(&b, " ", 1);
			space = false;
			if (error == 0)
				error = sb_add(&b, q, 1);
		}
		if (error == 0) {
			error = set_string(out, b.p);
			b.p = NULL;
		}
	} else if (strcmp(f, "translate") == 0 && n == 3) {
		if ((error = str_arg(e, &a[2], &s3)) != 0 ||
		    (error = sb_add(&b, "", 0)) != 0)
			goto out;
		/* Each character of s1: as at the same place in s3, where it
		 * is in s2; else itself; none, s3 being shorter. */
		for (size_t i = 0; (c = u8at(s1, i, &cl)) != NULL && error == 0;
		    i++) {
			const char *fc, *tc;
			size_t fl, tl, k;

			for (k = 0; (fc = u8at(s2, k, &fl)) != NULL; k++)
				if (fl == cl && memcmp(fc, c, cl) == 0)
					break;
			if (fc == NULL)
				error = sb_add(&b, c, cl);
			else if ((tc = u8at(s3, k, &tl)) != NULL)
				error = sb_add(&b, tc, tl);
		}
		if (error == 0) {
			error = set_string(out, b.p);
			b.p = NULL;
		}
	} else
		*done = false;
out:
	free(b.p);
	free(s1);
	free(s2);
	free(s3);
	return (error);
}

static int
eval_func(struct ev *e, const struct cbl_xp *x, const cbl_dnode *ctx,
    struct cbl_xval *out)
{
	const char *f = x->s;
	struct cbl_xval *a = NULL;
	struct nset s = { 0 };
	size_t n = x->nargs;
	const void *v;
	char *str, *str2;
	double d;
	bool done;
	int error = 0;

	if (strcmp(f, "current") == 0 && n == 0) {
		if ((error = ns_add(&s, e->cur)) != 0)
			return (error);
		ns_value(&s, out);
		return (0);
	}
	if ((strcmp(f, "true") == 0 || strcmp(f, "false") == 0) && n == 0) {
		set_bool(out, f[0] == 't');
		return (0);
	}
	/* The arguments; the context node for one that may go without. */
	if ((a = calloc(n > 0 ? n : 1, sizeof(*a))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < n && error == 0; i++)
		error = eval(e, x->args[i], ctx, &a[i]);
	if (error == 0 && n == 0 && (strcmp(f, "string") == 0 ||
	    strcmp(f, "number") == 0 || strcmp(f, "string-length") == 0 ||
	    strcmp(f, "normalize-space") == 0)) {
		if ((error = ns_add(&s, ctx)) == 0) {
			ns_value(&s, &a[0]);
			n = 1;
		}
	}
	if (error != 0)
		goto out;
	if (strcmp(f, "not") == 0 && n == 1)
		set_bool(out, !to_bool(&a[0]));
	else if (strcmp(f, "boolean") == 0 && n == 1)
		set_bool(out, to_bool(&a[0]));
	else if (strcmp(f, "number") == 0 && n == 1) {
		if ((error = to_number(e, &a[0], &d)) == 0)
			set_number(out, d);
	} else if (strcmp(f, "string") == 0 && n == 1) {
		if ((error = to_string(e, &a[0], &str)) == 0)
			error = set_string(out, str);
	} else if (strcmp(f, "count") == 0 && n == 1 &&
	    a[0].kind == CBL_XV_NODES)
		set_number(out, (double)a[0].n);
	else if (strcmp(f, "deref") == 0 && n == 1)
		error = func_deref(e, &a[0], out);
	else if ((strcmp(f, "derived-from") == 0 ||
	    strcmp(f, "derived-from-or-self") == 0) && n == 2 &&
	    a[0].kind == CBL_XV_NODES) {
		uint64_t base;
		bool any = false;

		if ((error = to_string(e, &a[1], &str)) != 0)
			goto out;
		/* By the schema of each node's tree. */
		for (size_t i = 0; i < a[0].n && !any; i++) {
			const cbl_dtree *nt = a[0].nodes[i]->tree;

			if (value_of(e, a[0].nodes[i], CBL_YT_IDENTITYREF, &v) !=
			    NULL && (base = ident_sid(nt, str)) != 0)
				any = cbl_yderived_from(nt->schema,
				    *(const uint64_t *)v, base, f[12] == '-');
		}
		free(str);
		set_bool(out, any);
	} else if (strcmp(f, "enum-value") == 0 && n == 1 &&
	    a[0].kind == CBL_XV_NODES) {
		const struct cbl_ytype *t = a[0].n > 0 ?
		    value_of(e, a[0].nodes[0], CBL_YT_ENUMERATION, &v) : NULL;

		set_number(out, t != NULL ? (double)read_int(v, t->csize) :
		    NAN);
	} else if (strcmp(f, "bit-is-set") == 0 && n == 2 &&
	    a[0].kind == CBL_XV_NODES) {
		const struct cbl_ytype *t = a[0].n > 0 ?
		    value_of(e, a[0].nodes[0], CBL_YT_BITS, &v) : NULL;
		bool set = false;

		if ((error = to_string(e, &a[1], &str)) != 0)
			goto out;
		for (uint32_t k = 0; t != NULL && k < t->nitems; k++) {
			const struct cbl_bytes *by = v;
			int64_t pos = t->items[k].value;

			if (strcmp(t->items[k].name, str) == 0)
				set = (size_t)(pos / 8) < by->len &&
				    (((const uint8_t *)by->p)[pos / 8] &
				    (1u << (pos % 8))) != 0;
		}
		free(str);
		set_bool(out, set);
	} else if (strcmp(f, "re-match") == 0 && n == 2) {
		regex_t re;
		char why[128];
		size_t pos;

		if ((error = to_string(e, &a[0], &str)) != 0)
			goto out;
		if ((error = to_string(e, &a[1], &str2)) != 0) {
			free(str);
			goto out;
		}
		if (cbl_pattern_compile(str2, &re, why, sizeof(why), &pos) !=
		    0)
			error = fail(e, EINVAL, "re-match(): %s", why);
		else {
			set_bool(out, cbl_pattern_match(&re, str));
			cbl_pattern_free(&re);
		}
		free(str);
		free(str2);
	} else if ((error = func_strings(e, f, a, n, out, &done)) == 0 &&
	    !done)
		error = fail(e, EINVAL, "%s() with %zu arguments: not "
		    "XPath-lite", f, x->nargs);
out:
	for (size_t i = 0; i < (n > x->nargs ? n : x->nargs); i++)
		cbl_xval_free(&a[i]);
	free(a);
	return (error);
}

static int
eval(struct ev *e, const struct cbl_xp *x, const cbl_dnode *ctx,
    struct cbl_xval *out)
{
	struct cbl_xval a, b;
	struct nset s;
	double na, nb;
	bool r;
	int error;

	memset(out, 0, sizeof(*out));
	if (e->over || ++e->work > CBL_XP_WORK_MAX) {
		e->over = true;
		return (fail(e, EFBIG, "too much to evaluate"));
	}
	if (++e->depth > CBL_XP_MAX_HEIGHT) {
		e->depth--;
		return (fail(e, ELOOP, "nested too deep"));
	}
	switch (x->kind) {
	case CBL_XP_OR:
	case CBL_XP_AND:
		/* Left first; the right only where it decides. */
		if ((error = eval(e, x->args[0], ctx, &a)) != 0)
			break;
		r = to_bool(&a);
		cbl_xval_free(&a);
		if (r == (x->kind == CBL_XP_OR)) {
			set_bool(out, r);
			break;
		}
		if ((error = eval(e, x->args[1], ctx, &b)) != 0)
			break;
		set_bool(out, to_bool(&b));
		cbl_xval_free(&b);
		break;
	case CBL_XP_EQ:
	case CBL_XP_NE:
	case CBL_XP_LT:
	case CBL_XP_LE:
	case CBL_XP_GT:
	case CBL_XP_GE:
		if ((error = eval(e, x->args[0], ctx, &a)) != 0)
			break;
		if ((error = eval(e, x->args[1], ctx, &b)) != 0) {
			cbl_xval_free(&a);
			break;
		}
		if ((error = compare(e, x->kind, &a, &b, &r)) == 0)
			set_bool(out, r);
		cbl_xval_free(&a);
		cbl_xval_free(&b);
		break;
	case CBL_XP_ADD:
	case CBL_XP_SUB:
	case CBL_XP_MUL:
	case CBL_XP_DIV:
	case CBL_XP_MOD:
		if ((error = eval(e, x->args[0], ctx, &a)) != 0)
			break;
		if ((error = eval(e, x->args[1], ctx, &b)) != 0) {
			cbl_xval_free(&a);
			break;
		}
		if ((error = to_number(e, &a, &na)) == 0 &&
		    (error = to_number(e, &b, &nb)) == 0)
			set_number(out, x->kind == CBL_XP_ADD ? na + nb :
			    x->kind == CBL_XP_SUB ? na - nb :
			    x->kind == CBL_XP_MUL ? na * nb :
			    x->kind == CBL_XP_DIV ? na / nb : fmod(na, nb));
		cbl_xval_free(&a);
		cbl_xval_free(&b);
		break;
	case CBL_XP_NEG:
		if ((error = eval(e, x->args[0], ctx, &a)) != 0)
			break;
		if ((error = to_number(e, &a, &na)) == 0)
			set_number(out, -na);
		cbl_xval_free(&a);
		break;
	case CBL_XP_UNION:
		if ((error = eval(e, x->args[0], ctx, &a)) != 0)
			break;
		if ((error = eval(e, x->args[1], ctx, &b)) != 0) {
			cbl_xval_free(&a);
			break;
		}
		if (a.kind != CBL_XV_NODES || b.kind != CBL_XV_NODES)
			error = fail(e, EINVAL, "| of what is not a node set");
		memset(&s, 0, sizeof(s));
		for (size_t i = 0; error == 0 && i < a.n; i++)
			error = ns_add(&s, a.nodes[i]);
		for (size_t i = 0; error == 0 && i < b.n; i++)
			error = ns_add(&s, b.nodes[i]);
		cbl_xval_free(&a);
		cbl_xval_free(&b);
		if (error == 0)
			ns_value(&s, out);
		else
			ns_free(&s);
		break;
	case CBL_XP_LITERAL:
		error = set_string(out, strdup(x->s));
		break;
	case CBL_XP_NUMBER:
		set_number(out, x->num);
		error = 0;
		break;
	case CBL_XP_FUNC:
		error = eval_func(e, x, ctx, out);
		break;
	case CBL_XP_FILTER:
		if ((error = eval(e, x->args[0], ctx, &a)) != 0)
			break;
		if (x->npreds == 0) {
			*out = a;
			break;
		}
		if (a.kind != CBL_XV_NODES) {
			cbl_xval_free(&a);
			error = fail(e, EINVAL, "a predicate of what is not a "
			    "node set");
			break;
		}
		memset(&s, 0, sizeof(s));
		for (size_t i = 0; error == 0 && i < a.n; i++)
			error = ns_add(&s, a.nodes[i]);
		cbl_xval_free(&a);
		if (error == 0)
			error = filter(e, x->preds, x->npreds, &s);
		if (error == 0)
			ns_value(&s, out);
		else
			ns_free(&s);
		break;
	case CBL_XP_PATH:
		error = eval_path(e, x, ctx, out);
		break;
	case CBL_XP_STEP: {
		struct nset in = { 0 }, o = { 0 };

		if ((error = ns_add(&in, ctx)) == 0)
			error = step(e, x, &in, &o);
		ns_free(&in);
		if (error == 0)
			ns_value(&o, out);
		else
			ns_free(&o);
		break;
	}
	default:
		error = fail(e, EINVAL, "variables: not XPath-lite");
		break;
	}
	e->depth--;
	/* Over the budget, nodes were left unseen: the value is wrong. */
	if (error == 0 && e->over) {
		cbl_xval_free(out);
		error = fail(e, EFBIG, "too much to evaluate");
	}
	return (error);
}

/* Another expression of the tables, with its own current node. */
static int
eval_expr(struct ev *e, const char *expr, const cbl_dnode *ctx,
    const cbl_dnode *cur, struct cbl_xval *out)
{
	const cbl_dnode *was = e->cur;
	struct cbl_xp *x;
	char perr[128];
	size_t pos;
	int error;

	if ((x = cbl_xp_parse(expr, perr, sizeof(perr), &pos)) == NULL)
		return (fail(e, EINVAL, "at %zu: %s", pos, perr));
	e->cur = cur;
	error = eval(e, x, ctx, out);
	e->cur = was;
	cbl_xp_free(x);
	return (error);
}

int
cbl_xp_eval(const cbl_dtree *t, const char *expr, const cbl_dnode *ctx,
    const cbl_dnode *cur, struct cbl_xval *out, char *why, size_t whylen)
{

	return (cbl_d_xp_eval(t, expr, ctx, cur, NULL, out, why, whylen));
}

int
cbl_d_xp_eval(const cbl_dtree *t, const char *expr, const cbl_dnode *ctx,
    const cbl_dnode *cur, const struct cbl_d_view *view, struct cbl_xval *out,
    char *why, size_t whylen)
{
	struct ev e = { .t = t, .cur = cur != NULL ? cur : ctx, .view = view,
	    .why = why, .whylen = whylen };
	struct cbl_xp *x;
	char perr[128];
	size_t pos;
	int error;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (t == NULL || expr == NULL || out == NULL)
		return (EINVAL);
	if (ctx == NULL)
		ctx = &t->root;
	if (e.cur == NULL)
		e.cur = ctx;
	if ((x = cbl_xp_parse(expr, perr, sizeof(perr), &pos)) == NULL)
		return (fail(&e, EINVAL, "at %zu: %s", pos, perr));
	error = eval(&e, x, ctx, out);
	cbl_xp_free(x);
	return (error);
}
