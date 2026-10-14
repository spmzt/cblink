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
