/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Filters over an instance tree (cbl_data.h, PLAN-SDN-YANG 2.2.5).  What
 * a filter selects is a set of nodes, made a tree of its own: each node
 * selected with all below it, the nodes above it with their keys (an
 * entry is not without them).  An XPath filter selects the nodes its
 * expression finds (RFC 6241 section 8.9).  A subtree filter (section 6)
 * is a tree of the schema's nodes: one with a value is a content match
 * node, one with children a containment node, one with neither a
 * selection node; it selects as section 6.2 says.  A mount point's
 * parent references (RFC 8528 section 4) are the nodes their expressions
 * select of the parent tree, made a tree likewise, which the mounted
 * tree's expressions see.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"
#include "cbl_yimpl.h"

struct cbl_dfnode {
	const struct cbl_ynode	*sn;
	void			*value;		/* a content match node's */
	struct cbl_dfnode	*parent;
	struct cbl_dfnode	*first, *last, *next;
};

struct cbl_dfilter {
	const struct cbl_yschema *schema;
	struct cbl_dfnode	 root;
};

/*
 * Sets of nodes: an array, each once (a table of the pointers, for that).
 */
struct pset {
	const cbl_dnode	**v;
	size_t		 n, max;
	const void	**seen;		/* open addressing, cap a power of 2 */
	size_t		 cap;
};

static size_t
slot(const struct pset *s, const void *x)
{
	size_t i;

	for (i = ((uintptr_t)x >> 4) & (s->cap - 1); s->seen[i] != NULL &&
	    s->seen[i] != x; i = (i + 1) & (s->cap - 1))
		;
	return (i);
}

static bool
ps_has(const struct pset *s, const void *x)
{

	return (s->cap > 0 && s->seen[slot(s, x)] == x);
}

/* x in s: once, and in its array if v (else only in its table). */
static int
ps_put(struct pset *s, const cbl_dnode *x, bool v)
{
	const cbl_dnode **nv;
	const void **seen, **old;
	size_t i, oldcap;

	if (ps_has(s, x))
		return (0);
	if ((s->n + 1) * 2 > s->cap || s->cap == 0) {
		oldcap = s->cap;
		old = s->seen;
		s->cap = oldcap > 0 ? oldcap * 2 : 64;
		if ((seen = calloc(s->cap, sizeof(*seen))) == NULL) {
			s->cap = oldcap;
			return (ENOMEM);
		}
		s->seen = seen;
		for (size_t j = 0; j < oldcap; j++)
			if (old[j] != NULL)
				s->seen[slot(s, old[j])] = old[j];
		free(old);
	}
	i = slot(s, x);
	s->seen[i] = x;
	if (!v) {
		s->n++;
		return (0);
	}
	if (s->n == s->max) {
		size_t max = s->max > 0 ? s->max * 2 : 16;

		if ((nv = reallocarray(s->v, max, sizeof(*nv))) == NULL)
			return (ENOMEM);
		s->v = nv;
		s->max = max;
	}
	s->v[s->n++] = x;
	return (0);
}

static void
ps_free(struct pset *s)
{

	free(s->v);
	free(s->seen);
	memset(s, 0, sizeof(*s));
}

/*
 * The tree of a selection.
 */

struct sel {
	struct pset	 picked;	/* selected: with all below them */
	struct pset	 above;		/* their ancestors */
};

static int
build(const struct sel *s, cbl_dnode *o, const cbl_dnode *d, int depth)
{
	cbl_dnode *x;
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	for (const cbl_dnode *c = d->first; c != NULL; c = c->next) {
		if (ps_has(&s->picked, c))
			error = cbl_d_copy(o, c, NULL, 0);
		else if (ps_has(&s->above, c)) {
			if ((error = cbl_d_mirror(o, c, &x)) == 0)
				error = build(s, x, c, depth + 1);
		} else
			continue;
		if (error != 0)
			return (error);
	}
	return (0);
}

cbl_dtree *
cbl_dtree_select(const cbl_dtree *t, const cbl_dnode *const *nodes, size_t n)
{
	struct sel s = { 0 };
	cbl_dtree *out;
	int error = 0;

	if (t == NULL || (nodes == NULL && n > 0)) {
		errno = EINVAL;
		return (NULL);
	}
	if ((out = cbl_dtree_new(t->schema)) == NULL)
		return (NULL);
	for (size_t i = 0; i < n && error == 0; i++) {
		if (nodes[i] == NULL || nodes[i]->tree != t) {
			error = EINVAL;
			break;
		}
		error = ps_put(&s.picked, nodes[i], false);
		for (const cbl_dnode *a = nodes[i]->parent; a != NULL &&
		    error == 0; a = a->parent)
			error = ps_put(&s.above, a, false);
	}
	if (error == 0) {
		/* The root itself: all of the tree. */
		if (ps_has(&s.picked, &t->root))
			for (const cbl_dnode *c = t->root.first; c != NULL &&
			    error == 0; c = c->next)
				error = cbl_d_copy(&out->root, c, NULL, 0);
		else
			error = build(&s, &out->root, &t->root, 0);
	}
	ps_free(&s.picked);
	ps_free(&s.above);
	if (error != 0) {
		cbl_dtree_free(out);
		errno = error;
		return (NULL);
	}
	return (out);
}

cbl_dtree *
cbl_dtree_filter_xpath(const cbl_dtree *t, const char *expr, char *why,
    size_t whylen)
{
	struct cbl_xval v;
	cbl_dtree *out;
	int error;

	if ((error = cbl_xp_eval(t, expr, NULL, NULL, &v, why, whylen)) != 0) {
		errno = error;
		return (NULL);
	}
	if (v.kind != CBL_XV_NODES) {
		cbl_xval_free(&v);
		if (why != NULL && whylen > 0)
			strlcpy(why, "not a node set", whylen);
		errno = EINVAL;
		return (NULL);
	}
	out = cbl_dtree_select(t, v.nodes, v.n);
	cbl_xval_free(&v);
	return (out);
}

/*
 * Parent references (RFC 8528 section 4).
 */

cbl_dtree *
cbl_dtree_parent_refs(const cbl_dtree *t, const cbl_dnode *mp,
    const char *const *exprs, size_t n, char *why, size_t whylen)
{
	struct pset s = { 0 };
	struct cbl_xval v;
	cbl_dtree *out;
	int error = 0;

	if (t == NULL || mp == NULL || mp->tree != t ||
	    (exprs == NULL && n > 0)) {
		errno = EINVAL;
		return (NULL);
	}
	for (size_t i = 0; i < n && error == 0; i++) {
		if ((error = cbl_xp_eval(t, exprs[i], mp, mp, &v, why,
		    whylen)) != 0)
			break;
		if (v.kind != CBL_XV_NODES) {
			if (why != NULL && whylen > 0)
				snprintf(why, whylen, "parent-reference %zu: "
				    "not a node set", i + 1);
			error = EINVAL;
		}
		for (size_t j = 0; error == 0 && j < v.n; j++)
			error = ps_put(&s, v.nodes[j], true);
		cbl_xval_free(&v);
	}
	if (error != 0) {
		ps_free(&s);
		errno = error;
		return (NULL);
	}
	out = cbl_dtree_select(t, s.v, s.n);
	ps_free(&s);
	return (out);
}

int
cbl_dtree_set_refs(cbl_dtree *t, const cbl_dtree *refs)
{

	if (t == NULL || refs == t)
		return (EINVAL);
	t->refs = refs;
	return (0);
}

/*
 * Subtree filters.
 */

cbl_dfilter *
cbl_dfilter_new(const struct cbl_yschema *s)
{
	cbl_dfilter *f;

	if (s == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	if ((f = calloc(1, sizeof(*f))) == NULL)
		return (NULL);
	f->schema = s;
	return (f);
}

static void
fnode_free(cbl_dfnode *n, int depth)
{
	cbl_dfnode *c, *next;

	for (c = n->first; c != NULL; c = next) {
		next = c->next;
		if (depth < CBL_D_DEPTH_MAX)
			fnode_free(c, depth + 1);
		if (c->value != NULL)
			cbl_d_vdel(c->sn->type, c->value);
		free(c);
	}
}

void
cbl_dfilter_free(cbl_dfilter *f)
{

	if (f == NULL)
		return;
	fnode_free(&f->root, 0);
	free(f);
}

cbl_dfnode *
cbl_dfilter_root(cbl_dfilter *f)
{

	return (f != NULL ? &f->root : NULL);
}

int
cbl_dfilter_add(cbl_dfnode *parent, const struct cbl_ynode *sn,
    const void *value, cbl_dfnode **out)
{
	cbl_dfnode *n;
	int depth = 0;

	if (parent == NULL || sn == NULL || sn->parent != parent->sn)
		return (EINVAL);
	for (const cbl_dfnode *a = parent; a != NULL; a = a->parent)
		if (++depth > CBL_D_DEPTH_MAX)
			return (ELOOP);
	/* A value: a leaf's or a leaf-list's, but an empty one's, which
	 * only a selection node can be. */
	if (value != NULL && (sn->type == NULL || (sn->kind != CBL_YN_LEAF &&
	    sn->kind != CBL_YN_LEAFLIST)))
		return (EINVAL);
	if ((n = calloc(1, sizeof(*n))) == NULL)
		return (ENOMEM);
	n->sn = sn;
	if (value != NULL && sn->type->kind != CBL_YT_EMPTY &&
	    (n->value = cbl_d_vdup(sn->type, value)) == NULL) {
		free(n);
		return (errno != 0 ? errno : ENOMEM);
	}
	n->parent = parent;
	if (parent->last != NULL)
		parent->last->next = n;
	else
		parent->first = n;
	parent->last = n;
	if (out != NULL)
		*out = n;
	return (0);
}

/* The node of d content match node g matches, or NULL. */
static const cbl_dnode *
matched(const cbl_dnode *d, const cbl_dfnode *g)
{
	const cbl_dnode *c;

	if (g->sn->kind == CBL_YN_LEAFLIST)
		return (cbl_dnode_llentry(d, g->sn, g->value));
	c = cbl_dnode_child(d, g->sn);
	return (c != NULL && c->value != NULL &&
	    cbl_dvalue_equal(g->sn->type, c->value, g->value) ? c : NULL);
}

/*
 * What filter node f selects of node d, the data node it is matched to,
 * into out (section 6.2): d with all below it, f having no children or
 * content match nodes alone, all matching; else, they all matching, the
 * nodes they match, those of its selection nodes, and what its
 * containment nodes select of theirs.
 */
static int
fsel(struct pset *out, const cbl_dnode *d, const cbl_dfnode *f, int depth)
{
	struct pset tmp = { 0 };
	const cbl_dnode *m;
	bool cm_only = true;
	int error = 0;

	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	if (f->first == NULL)
		return (ps_put(out, d, true));
	for (const cbl_dfnode *g = f->first; g != NULL && error == 0;
	    g = g->next) {
		if (g->value == NULL) {
			cm_only = false;
			continue;
		}
		if ((m = matched(d, g)) == NULL) {
			ps_free(&tmp);
			return (0);
		}
		error = ps_put(&tmp, m, true);
	}
	if (error == 0 && cm_only) {
		ps_free(&tmp);
		return (ps_put(out, d, true));
	}
	for (const cbl_dfnode *g = f->first; g != NULL && error == 0;
	    g = g->next) {
		if (g->value != NULL)
			continue;
		for (const cbl_dnode *c = d->first; c != NULL && error == 0;
		    c = c->next)
			if (c->sn == g->sn)
				error = g->first == NULL ?
				    ps_put(&tmp, c, true) :
				    fsel(&tmp, c, g, depth + 1);
	}
	for (size_t i = 0; i < tmp.n && error == 0; i++)
		error = ps_put(out, tmp.v[i], true);
	ps_free(&tmp);
	return (error);
}

cbl_dtree *
cbl_dtree_filter_subtree(const cbl_dtree *t, const cbl_dfilter *f)
{
	struct pset s = { 0 };
	cbl_dtree *out;
	int error;

	if (t == NULL || f == NULL || f->schema != t->schema) {
		errno = EINVAL;
		return (NULL);
	}
	/* An empty filter selects nothing (section 6.4.2). */
	if (f->root.first == NULL)
		return (cbl_dtree_new(t->schema));
	if ((error = fsel(&s, &t->root, &f->root, 0)) != 0) {
		ps_free(&s);
		errno = error;
		return (NULL);
	}
	out = cbl_dtree_select(t, s.v, s.n);
	ps_free(&s);
	return (out);
}

/*
 * A subtree filter as YANG-CBOR (WIRE-FORMAT.md section 7): anydata's
 * content, a map whose keys are SID deltas from the anydata's own, each
 * a node of the filter keyed as RFC 9254 keys a container's children.
 * null is a selection node, of any kind; a container's map a
 * containment node (an empty one, a selection node); a list's array of
 * maps, a filter node each; a leaf's value a content match node; a
 * leaf-list's array of values, a content match node each.  At the top,
 * the schema's top-level data nodes and notifications.
 */

const struct cbl_ynode *
cbl_dfilter_top(const cbl_dfilter *f, size_t i)
{
	const cbl_dfnode *n;

	if (f == NULL)
		return (NULL);
	for (n = f->root.first; n != NULL && i > 0; n = n->next)
		i--;
	return (n != NULL ? n->sn : NULL);
}

struct frd {
	const struct cbl_yschema *s;
	const uint8_t	*p, *end;
	cbl_yarena	*a;
	char		*why;
	size_t		 whylen;
};

static int
frd_fail(struct frd *r, int error, const char *what,
    const struct cbl_ynode *sn)
{

	if (r->why != NULL && r->whylen > 0 && r->why[0] == '\0')
		(void)snprintf(r->why, r->whylen, "subtree filter: %s%s%s",
		    sn != NULL ? sn->name : "", sn != NULL ? ": " : "", what);
	return (error);
}

/* A head of major type major at r->p, its argument in *v. */
static bool
fhead(struct frd *r, int major, uint64_t *v)
{
	const uint8_t *p = r->p;
	size_t k;

	if (p >= r->end || *p >> 5 != major)
		return (false);
	*v = *p++ & 0x1f;
	if (*v >= 24) {
		if (*v > 27)
			return (false);
		k = (size_t)1 << (*v - 24);
		if ((size_t)(r->end - p) < k)
			return (false);
		for (*v = 0; k > 0; k--)
			*v = *v << 8 | *p++;
	}
	r->p = p;
	return (true);
}

/* A value of sn's at r->p, a content match node of parent's. */
static int
fvalue(struct frd *r, cbl_dfnode *parent, const struct cbl_ynode *sn)
{
	size_t len;
	void *v;
	int error;

	if ((len = cbl_ycbor_skip(r->p, r->end)) == 0)
		return (frd_fail(r, EINVAL, "not CBOR", sn));
	if ((v = cbl_yarena_alloc(r->a, sn->type->csize)) == NULL)
		return (ENOMEM);
	memset(v, 0, sn->type->csize);
	if ((error = cbl_ydecode_value(sn, r->p, len, v, r->a, NULL, 0)) != 0)
		return (frd_fail(r, error, "not one of its values", sn));
	r->p += len;
	if ((error = cbl_dfilter_add(parent, sn, v, NULL)) != 0)
		return (frd_fail(r, error, "no content match node", sn));
	return (0);
}

static int	fmap(struct frd *, cbl_dfnode *, uint64_t, int);

/* Node sn of the filter, a child of parent: its encoding at r->p. */
static int
fnode(struct frd *r, cbl_dfnode *parent, const struct cbl_ynode *sn,
    int depth)
{
	cbl_dfnode *n;
	uint64_t k;
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (frd_fail(r, ELOOP, "too deep", sn));
	if (r->p < r->end && *r->p == 0xf6) {
		r->p++;
		return (cbl_dfilter_add(parent, sn, NULL, NULL));
	}
	switch (sn->kind) {
	case CBL_YN_CONTAINER:
	case CBL_YN_NOTIF:
		if ((error = cbl_dfilter_add(parent, sn, NULL, &n)) != 0)
			return (error);
		return (fmap(r, n, sn->sid, depth + 1));
	case CBL_YN_LIST:
		if (!fhead(r, 4, &k))
			return (frd_fail(r, EINVAL, "a list is an array", sn));
		for (uint64_t i = 0; i < k; i++)
			if ((error = cbl_dfilter_add(parent, sn, NULL,
			    &n)) != 0 ||
			    (error = fmap(r, n, sn->sid, depth + 1)) != 0)
				return (error);
		return (0);
	case CBL_YN_LEAF:
		return (fvalue(r, parent, sn));
	case CBL_YN_LEAFLIST:
		if (!fhead(r, 4, &k))
			return (frd_fail(r, EINVAL, "a leaf-list is an array",
			    sn));
		for (uint64_t i = 0; i < k; i++)
			if ((error = fvalue(r, parent, sn)) != 0)
				return (error);
		return (0);
	default:
		return (frd_fail(r, EINVAL, "null alone selects it", sn));
	}
}

/* The map at r->p: parent's children, keyed by deltas from base. */
static int
fmap(struct frd *r, cbl_dfnode *parent, uint64_t base, int depth)
{
	const struct cbl_ynode *sn;
	uint64_t k, d;
	int64_t delta;
	int error;

	if (!fhead(r, 5, &k))
		return (frd_fail(r, EINVAL, "a map was expected",
		    parent->sn));
	for (uint64_t i = 0; i < k; i++) {
		if (fhead(r, 0, &d) && d <= INT64_MAX)
			delta = (int64_t)d;
		else if (fhead(r, 1, &d) && d < INT64_MAX)
			delta = -1 - (int64_t)d;
		else
			return (frd_fail(r, EINVAL, "a key is a SID delta",
			    parent->sn));
		sn = cbl_yschema_node(r->s, (uint64_t)((int64_t)base + delta));
		if (sn == NULL || sn->parent != parent->sn ||
		    (parent->sn == NULL && sn->kind != CBL_YN_NOTIF &&
		    !cbl_yis_top_data(sn)) || (parent->sn != NULL &&
		    sn->kind != CBL_YN_CONTAINER && sn->kind != CBL_YN_LIST &&
		    sn->kind != CBL_YN_LEAF && sn->kind != CBL_YN_LEAFLIST &&
		    sn->kind != CBL_YN_ANYDATA && sn->kind != CBL_YN_ANYXML))
			return (frd_fail(r, EINVAL, "a SID of no node there",
			    parent->sn));
		if ((error = fnode(r, parent, sn, depth)) != 0)
			return (error);
	}
	return (0);
}

cbl_dfilter *
cbl_dfilter_decode(const struct cbl_yschema *s, uint64_t base,
    const void *data, size_t len, char *why, size_t whylen)
{
	struct frd r = { s, data, (const uint8_t *)data + len, NULL, why,
	    whylen };
	cbl_dfilter *f;
	int error;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (s == NULL || data == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	if ((f = cbl_dfilter_new(s)) == NULL)
		return (NULL);
	if ((r.a = cbl_yarena_new()) == NULL)
		error = ENOMEM;
	else if ((error = fmap(&r, &f->root, base, 0)) == 0 && r.p != r.end)
		error = frd_fail(&r, EINVAL, "bytes after it", NULL);
	cbl_yarena_free(r.a);
	if (error != 0) {
		cbl_dfilter_free(f);
		errno = error;
		return (NULL);
	}
	return (f);
}

/* The children of filter node n, each schema node's in one member. */
static int
fenc(const cbl_dfnode *n, uint64_t base, struct cbl_ybuf *b, int depth)
{
	const cbl_dfnode *c, *g;
	uint64_t k = 0, m;
	bool sel;
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	/* A member each schema node, at its first filter node. */
	for (c = n->first; c != NULL; c = c->next) {
		for (g = n->first; g != c && g->sn != c->sn; g = g->next)
			;
		if (g == c)
			k++;
	}
	if ((error = cbl_ycbor_head(b, 5, k)) != 0)
		return (error);
	for (c = n->first; c != NULL; c = c->next) {
		for (g = n->first; g != c && g->sn != c->sn; g = g->next)
			;
		if (g != c)
			continue;
		error = c->sn->sid >= base ?
		    cbl_ycbor_head(b, 0, c->sn->sid - base) :
		    cbl_ycbor_head(b, 1, base - c->sn->sid - 1);
		if (error != 0)
			return (error);
		/* Those of its schema node: how many, a selection node
		 * among them. */
		for (g = c, m = 0, sel = false; g != NULL; g = g->next)
			if (g->sn == c->sn) {
				m++;
				if (g->first == NULL && g->value == NULL)
					sel = true;
			}
		switch (c->sn->kind) {
		case CBL_YN_LIST:
			if (m == 1 && sel) {
				error = cbl_ycbor_head(b, 7, 22);
				break;
			}
			error = cbl_ycbor_head(b, 4, m);
			for (g = c; error == 0 && g != NULL; g = g->next)
				if (g->sn == c->sn)
					error = fenc(g, c->sn->sid, b,
					    depth + 1);
			break;
		case CBL_YN_LEAFLIST:
			/* Its values, or the selection node alone. */
			if (sel && m > 1)
				return (EINVAL);
			if (sel) {
				error = cbl_ycbor_head(b, 7, 22);
				break;
			}
			error = cbl_ycbor_head(b, 4, m);
			for (g = c; error == 0 && g != NULL; g = g->next)
				if (g->sn == c->sn)
					error = cbl_yencode_value(b,
					    g->sn->type, g->value);
			break;
		default:
			if (m > 1)
				return (EINVAL);
			if (c->value != NULL)
				error = cbl_yencode_value(b, c->sn->type,
				    c->value);
			else if (c->first == NULL)
				error = cbl_ycbor_head(b, 7, 22);
			else
				error = fenc(c, c->sn->sid, b, depth + 1);
			break;
		}
		if (error != 0)
			return (error);
	}
	return (0);
}

int
cbl_dfilter_encode(const cbl_dfilter *f, uint64_t base, struct cbl_ybuf *b)
{

	if (f == NULL || b == NULL)
		return (EINVAL);
	return (fenc(&f->root, base, b, 0));
}
