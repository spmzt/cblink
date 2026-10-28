/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The difference of two instance trees (cbl_data.h, PLAN-SDN-YANG
 * 2.1.4): an edit that makes the first the second when applied to it
 * with the default operation none, what a YANG Patch says (RFC 8072;
 * YANG-Push's push-change-update, RFC 8641).
 *
 * What only the second has is a create of its subtree; a leaf whose value
 * differs, a merge; anydata that differs, a replace; what only the first
 * has, a remove, but where the second has another case of a choice it is
 * in, whose create takes its place (RFC 7950 section 7.9.2).  A node both have is in the
 * edit, with no operation of its own, where something below it changed:
 * made as the walk goes down, dropped again where nothing did.  An
 * ordered-by user list, or leaf-list, whose order would not be the
 * second's has each of the second's entries said where: the first, or
 * after the one before it; one only the second has is an insert, one
 * both have a move, or a merge where something below it changed too.  A
 * list without keys cannot be named entry by entry: where its entries
 * differ, the node it is in is replaced whole.
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"

/* The keys of entry n, as cbl_dnode_add_entry() takes them. */
static void
keys_of(const cbl_dnode *n, const void **keys)
{

	for (uint16_t k = 0; k < n->sn->nkeys; k++)
		keys[k] = cbl_d_key_value(n, k);
}

static bool
is_key(const cbl_dnode *n)
{

	return ((n->sn->flags & CBL_YNF_KEY) && n->parent != NULL &&
	    n->parent->sn != NULL && n->parent->sn->kind == CBL_YN_LIST);
}

/* Node n made in the edit, under op: its kind, its keys, its value. */
int
cbl_d_mirror(cbl_dnode *op, const cbl_dnode *n, cbl_dnode **made)
{
	const void *keys[UINT8_MAX];
	cbl_dnode *x;

	if (n->sn->kind == CBL_YN_LIST) {
		if (n->sn->nkeys > nitems(keys))
			return (EINVAL);
		keys_of(n, keys);
		if (n->sn->nkeys > 0 &&
		    (x = cbl_dnode_entry(op, n->sn, keys)) != NULL) {
			*made = x;
			return (0);
		}
		return (cbl_dnode_add_entry(op, n->sn, keys, made));
	}
	if (n->sn->kind == CBL_YN_LEAFLIST) {
		if ((x = cbl_dnode_llentry(op, n->sn, n->value)) != NULL) {
			*made = x;
			return (0);
		}
	} else if ((x = cbl_dnode_child(op, n->sn)) != NULL) {
		*made = x;
		return (0);
	}
	return (cbl_dnode_add(op, n->sn, n->value, made));
}

/* n and all below it copied under op. */
int
cbl_d_copy(cbl_dnode *op, const cbl_dnode *n, cbl_dnode **made, int depth)
{
	cbl_dnode *x;
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	if ((error = cbl_d_mirror(op, n, &x)) != 0)
		return (error);
	for (const cbl_dnode *c = n->first; c != NULL; c = c->next)
		if (!is_key(c) && (error = cbl_d_copy(x, c, NULL,
		    depth + 1)) != 0)
			return (error);
	if (made != NULL)
		*made = x;
	return (0);
}

/* The node of parent a that b's node n is: by keys, value, or kind. */
static cbl_dnode *
match(const cbl_dnode *a, const cbl_dnode *n)
{
	const void *keys[UINT8_MAX];

	switch (n->sn->kind) {
	case CBL_YN_LIST:
		if (n->sn->nkeys == 0 || n->sn->nkeys > nitems(keys))
			return (NULL);
		keys_of(n, keys);
		return (cbl_dnode_entry(a, n->sn, keys));
	case CBL_YN_LEAFLIST:
		return (cbl_dnode_llentry(a, n->sn, n->value));
	default:
		return (cbl_dnode_child(a, n->sn));
	}
}

static bool
same_bytes(const struct cbl_bytes *x, const struct cbl_bytes *y)
{

	return (x->len == y->len && (x->len == 0 ||
	    memcmp(x->p, y->p, x->len) == 0));
}

/* Whether the two nodes' subtrees encode alike. */
static bool
same_tree(const cbl_dnode *x, const cbl_dnode *y)
{
	struct cbl_ybuf bx = { 0 }, by = { 0 };
	bool eq;

	eq = cbl_dnode_encode(x, &bx) == 0 && cbl_dnode_encode(y, &by) == 0 &&
	    bx.len == by.len && memcmp(bx.p, by.p, bx.len) == 0;
	cbl_ybuf_free(&bx);
	cbl_ybuf_free(&by);
	return (eq);
}

/* Whether a and b's entries of a keyless list sn differ. */
static bool
keyless_differ(const cbl_dnode *a, const cbl_dnode *b,
    const struct cbl_ynode *sn)
{
	const cbl_dnode *x = cbl_dnode_child(a, sn), *y = cbl_dnode_child(b,
	    sn);

	for (; x != NULL && x->sn == sn && y != NULL && y->sn == sn;
	    x = x->next, y = y->next)
		if (!same_tree(x, y))
			return (true);
	return ((x != NULL && x->sn == sn) != (y != NULL && y->sn == sn));
}

/* Whether b has a node of a case of a choice sn is in other than sn's. */
static bool
case_taken(const cbl_dnode *b, const struct cbl_ynode *sn)
{

	if (sn->choice == NULL)
		return (false);
	for (const cbl_dnode *c = b->first; c != NULL; c = c->next)
		if (c->sn->choice != NULL && !cbl_d_same_case(sn, c->sn))
			return (true);
	return (false);
}

/* Whether n has a child in the edit other than its keys. */
static bool
changed(const cbl_dnode *n)
{

	for (const cbl_dnode *c = n->first; c != NULL; c = c->next)
		if (!is_key(c))
			return (true);
	return (n->op != 0);
}

/*
 * Whether a's entries of kind sn that b has, then b's new ones after
 * them (where a create puts them), are in b's order: b's entries those
 * of a in a's order, then only new ones.
 */
static bool
in_order(const cbl_dnode *a, const cbl_dnode *b, const struct cbl_ynode *sn)
{
	const cbl_dnode *x, *y, *m;

	y = cbl_dnode_child(b, sn);
	for (x = cbl_dnode_child(a, sn); x != NULL && x->sn == sn;
	    x = x->next) {
		if ((m = match(b, x)) == NULL)
			continue;
		/* A new one before it would go after it. */
		if (y != m)
			return (false);
		y = y->next;
	}
	for (; y != NULL && y->sn == sn; y = y->next)
		if (match(a, y) != NULL)
			return (false);
	return (true);
}

static int	diff_node(cbl_dnode *, const cbl_dnode *, const cbl_dnode *,
		    cbl_dnode **, int);

/* Each of b's entries of kind sn said where, in b's order. */
static int
order(cbl_dnode *op, const cbl_dnode *a, const cbl_dnode *b,
    const struct cbl_ynode *sn, int depth)
{
	const void *keys[UINT8_MAX];
	const cbl_dnode *y, *m, *prev = NULL;
	cbl_dnode *x;
	int error;

	for (y = cbl_dnode_child(b, sn); y != NULL && y->sn == sn;
	    prev = y, y = y->next) {
		if ((m = match(a, y)) == NULL) {
			if ((error = cbl_d_copy(op, y, &x, depth + 1)) == 0)
				error = cbl_dnode_set_op(x, CBL_DOP_INSERT);
		} else if ((error = diff_node(op, m, y, &x, depth + 1)) == 0) {
			/* Changed below: a merge; else only a move. */
			if (x != NULL)
				error = cbl_dnode_set_op(x, CBL_DOP_MERGE);
			else if ((error = cbl_d_mirror(op, y, &x)) == 0)
				error = cbl_dnode_set_op(x, CBL_DOP_MOVE);
		}
		if (error != 0)
			return (error);
		if (prev == NULL)
			error = cbl_dnode_set_where(x, CBL_DWHERE_FIRST, NULL);
		else {
			if (sn->kind == CBL_YN_LIST)
				keys_of(prev, keys);
			else
				keys[0] = prev->value;
			error = cbl_dnode_set_where(x, CBL_DWHERE_AFTER, keys);
		}
		if (error != 0)
			return (error);
	}
	return (0);
}

/* What changed between a's and b's children, made under x. */
static int
diff_children(cbl_dnode *x, const cbl_dnode *a, const cbl_dnode *b,
    int depth)
{
	const struct cbl_ynode *const *k;
	const cbl_dnode *y, *m;
	cbl_dnode *z;
	uint32_t nk;
	int error;

	k = cbl_d_kids(b->tree, b->sn, &nk);
	for (uint32_t i = 0; i < nk; i++) {
		const struct cbl_ynode *sn = k[i];

		if ((sn->flags & CBL_YNF_KEY) && b->sn != NULL &&
		    b->sn->kind == CBL_YN_LIST)
			continue;
		if (sn->kind == CBL_YN_LIST && sn->nkeys == 0) {
			if (keyless_differ(a, b, sn))
				return (ENOTSUP);	/* the caller's */
			continue;
		}
		if ((sn->flags & CBL_YNF_USERORDER) &&
		    (sn->kind == CBL_YN_LIST || sn->kind == CBL_YN_LEAFLIST) &&
		    !in_order(a, b, sn)) {
			if ((error = order(x, a, b, sn, depth)) != 0)
				return (error);
		} else
			for (y = cbl_dnode_child(b, sn);
			    y != NULL && y->sn == sn; y = y->next) {
				if ((m = match(a, y)) != NULL)
					error = diff_node(x, m, y, &z,
					    depth + 1);
				else if ((error = cbl_d_copy(x, y, &z,
				    depth + 1)) == 0)
					error = cbl_dnode_set_op(z,
					    CBL_DOP_CREATE);
				if (error != 0)
					return (error);
			}
		/* What only a has: removed, unless another case's create
		 * takes its place. */
		if (case_taken(b, sn))
			continue;
		for (y = cbl_dnode_child(a, sn); y != NULL && y->sn == sn;
		    y = y->next)
			if (match(b, y) == NULL &&
			    ((error = cbl_d_mirror(x, y, &z)) != 0 ||
			    (error = cbl_dnode_set_op(z, CBL_DOP_REMOVE)) !=
			    0))
				return (error);
	}
	return (0);
}

/*
 * a and b, the same node of the two trees: its change made under op,
 * *out the edit's node for it, or NULL where nothing changed.
 */
static int
diff_node(cbl_dnode *op, const cbl_dnode *a, const cbl_dnode *b,
    cbl_dnode **out, int depth)
{
	cbl_dnode *x;
	int error;

	*out = NULL;
	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	switch (b->sn->kind) {
	case CBL_YN_LEAF:
		if (cbl_dvalue_equal(b->sn->type, a->value, b->value))
			return (0);
		if ((error = cbl_d_mirror(op, b, &x)) != 0)
			return (error);
		*out = x;
		return (cbl_dnode_set_op(x, CBL_DOP_MERGE));
	case CBL_YN_LEAFLIST:
		/* Matched by value: the same. */
		return (0);
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		if (same_bytes(a->value, b->value))
			return (0);
		if ((error = cbl_d_mirror(op, b, &x)) != 0)
			return (error);
		*out = x;
		return (cbl_dnode_set_op(x, CBL_DOP_REPLACE));
	default:
		break;
	}
	if ((error = cbl_d_mirror(op, b, &x)) != 0)
		return (error);
	error = diff_children(x, a, b, depth);
	if (error == ENOTSUP) {
		/* A keyless list below: this node replaced, whole. */
		(void)cbl_dnode_remove(x);
		if ((error = cbl_d_copy(op, b, &x, depth)) != 0)
			return (error);
		*out = x;
		return (cbl_dnode_set_op(x, CBL_DOP_REPLACE));
	}
	if (error != 0)
		return (error);
	if (!changed(x)) {
		(void)cbl_dnode_remove(x);
		return (0);
	}
	*out = x;
	return (0);
}

cbl_dtree *
cbl_dtree_diff(const cbl_dtree *a, const cbl_dtree *b)
{
	cbl_dtree *d;
	int error;

	if (a == NULL || b == NULL || a->schema != b->schema) {
		errno = EINVAL;
		return (NULL);
	}
	if ((d = cbl_dtree_new(a->schema)) == NULL)
		return (NULL);
	if ((error = diff_children(&d->root, &a->root, &b->root, 0)) != 0) {
		cbl_dtree_free(d);
		/* A keyless list at the top cannot be replaced. */
		errno = error;
		return (NULL);
	}
	return (d);
}
