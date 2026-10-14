/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: YANG-CBOR as a peer sends it, decoded into each struct of
 * the module shapes (cblink-gen's tests: every kind of node and type, so
 * every tag RFC 9254 has, deltas from a node's own SID and from an rpc's,
 * unions, choices, lists and leaf-lists), strictly and not.  What
 * decodes is validated; encoded, decoded again and encoded to the same
 * bytes; and given its defaults, likewise.  A top-level node's, an rpc's
 * input's and output's also into the instance tree (cbl_data.h), its
 * defaults made, and out to bytes as stable.  The tables are committed
 * (yshapes.h, yshapes_schema.c: make regen).
 */

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_schema.h"
#include "yshapes.h"

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* What a decode may allocate: enough for a seed, not for a bomb. */
#define	ARENA_LIMIT	(1 << 20)

static alignas(max_align_t) char tree[4096], again[4096];

static bool
has_struct(const struct cbl_ynode *n)
{

	switch (n->kind) {
	case CBL_YN_CONTAINER:
	case CBL_YN_LIST:
	case CBL_YN_NOTIF:
	case CBL_YN_INPUT:
	case CBL_YN_OUTPUT:
	case CBL_YN_STRUCTURE:
		return (n->size > 0);
	default:
		return (false);
	}
}

/* p, of n's struct, encoded, decoded and encoded again: the same bytes. */
static void
stable(const struct cbl_ynode *n, const void *p)
{
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	cbl_yarena *a;

	if (cbl_yencode(n, p, &b1) != 0) {
		cbl_ybuf_free(&b1);
		return;
	}
	if ((a = cbl_yarena_new()) == NULL)
		abort();
	/* What it wrote it must read, strictly too. */
	if (cbl_ydecode(n, b1.p, b1.len, again, a, CBL_YD_STRICT, NULL,
	    0) != 0)
		abort();
	if (cbl_yencode(n, again, &b2) != 0 || b1.len != b2.len ||
	    memcmp(b1.p, b2.p, b1.len) != 0)
		abort();
	cbl_yarena_free(a);
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
}

/* The tree's bytes, decoded into a second tree, encode the same. */
static void
tree_stable(const struct cbl_ynode *n, cbl_dnode *x)
{
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	cbl_dtree *t2;
	cbl_dnode *y, *at;

	if (cbl_dnode_encode(x, &b1) != 0)
		abort();
	if ((t2 = cbl_dtree_new(&yshapes_schema)) == NULL)
		abort();
	at = cbl_dtree_root(t2);
	if (cbl_dnode_schema(cbl_dnode_parent(x)) != NULL &&
	    cbl_dnode_add(at, cbl_dnode_schema(cbl_dnode_parent(x)), NULL,
	    &at) != 0)
		abort();
	if (cbl_dnode_decode(at, n, b1.p, b1.len, CBL_YD_STRICT, NULL, 0,
	    &y) != 0 || cbl_dnode_encode(y, &b2) != 0 || b1.len != b2.len ||
	    memcmp(b1.p, b2.p, b1.len) != 0)
		abort();
	cbl_dtree_free(t2);
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
}

/* Into a tree, under the root or under its rpc. */
static void
in_tree(const struct cbl_ynode *n, const struct cbl_ynode *rpc,
    const uint8_t *data, size_t size)
{
	cbl_dtree *t;
	cbl_dnode *at, *x;

	if ((t = cbl_dtree_new(&yshapes_schema)) == NULL)
		abort();
	at = cbl_dtree_root(t);
	if (rpc != NULL && cbl_dnode_add(at, rpc, NULL, &at) != 0)
		abort();
	/* What the struct decoder takes, the tree may yet refuse: a
	 * configuration leaf-list's value twice, a key twice. */
	if (cbl_dnode_decode(at, n, data, size, 0, NULL, 0, &x) == 0) {
		tree_stable(n, x);
		if (cbl_dtree_defaults(cbl_dtree_root(t)) < 0)
			abort();
		tree_stable(n, x);
		if (cbl_dnode_remove(x) != 0 || (rpc == NULL &&
		    cbl_dtree_count(t) != 0))
			abort();
	}
	cbl_dtree_free(t);
}

static void
one(const struct cbl_ynode *n, const uint8_t *data, size_t size, int flags)
{
	struct cbl_yverr err;
	cbl_yarena *a;

	if (n->size > sizeof(tree))
		abort();
	if ((a = cbl_yarena_new()) == NULL)
		abort();
	cbl_yarena_set_limit(a, ARENA_LIMIT);
	if (cbl_ydecode(n, data, size, tree, a, flags, NULL, 0) == 0) {
		(void)cbl_yvalidate(n, tree, 0, &err);
		(void)cbl_yvalidate(n, tree, CBL_YV_EDIT, &err);
		stable(n, tree);
		if (cbl_ydefaults(n, tree, a) == 0)
			stable(n, tree);
	}
	cbl_yarena_free(a);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

	for (uint32_t i = 0; i < yshapes_schema.nnode; i++) {
		const struct cbl_ynode *n = yshapes_schema.node[i];

		if (!has_struct(n))
			continue;
		one(n, data, size, 0);
		one(n, data, size, CBL_YD_STRICT);
	}
	for (uint32_t i = 0; i < yshapes_schema.nmod; i++) {
		const struct cbl_ymodule *m = yshapes_schema.mod[i];

		for (uint32_t j = 0; j < m->ntop; j++) {
			const struct cbl_ynode *n = m->top[j];

			if (n->kind != CBL_YN_RPC) {
				if (has_struct(n))
					in_tree(n, NULL, data, size);
				continue;
			}
			for (uint32_t k = 0; k < n->nchild; k++)
				if (has_struct(n->child[k]))
					in_tree(n->child[k], n, data, size);
		}
	}
	return (0);
}
