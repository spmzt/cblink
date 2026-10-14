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
 * bytes; and given its defaults, likewise.  The tables are committed
 * (yshapes.h, yshapes_schema.c: make regen).
 */

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
	return (0);
}
