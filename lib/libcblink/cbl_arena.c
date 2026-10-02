/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Per-message linear arena.  Allocations are never freed individually;
 * the whole chain is released with the message, like snl(3)'s
 * struct linear_buffer.
 */

#include <stdckdint.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"

#define	CBL_CHUNK_MIN	2048
#define	CBL_CHUNK_MAX	(64 * 1024)
#define	CBL_ALIGN	alignof(max_align_t)

void
cbl_arena_init(struct cbl_arena *ar)
{

	ar->head = NULL;
	ar->total = 0;
}

void *
cbl_arena_alloc(struct cbl_arena *ar, size_t len)
{
	struct cbl_chunk *c;
	size_t need, size;
	void *p;

	if (len == 0)
		len = 1;
	if (ckd_add(&need, len, CBL_ALIGN - 1))
		return (NULL);
	need &= ~(CBL_ALIGN - 1);

	c = ar->head;
	if (c == NULL || c->size - c->off < need) {
		/* Grow geometrically, but oversized requests get their own. */
		size = ar->total < CBL_CHUNK_MIN ? CBL_CHUNK_MIN : ar->total;
		if (size > CBL_CHUNK_MAX)
			size = CBL_CHUNK_MAX;
		if (size < need)
			size = need;
		if (ckd_add(&size, size, sizeof(*c)))
			return (NULL);
		c = malloc(size);
		if (c == NULL)
			return (NULL);
		c->size = size - sizeof(*c);
		c->off = 0;
		c->next = ar->head;
		ar->head = c;
		ar->total += c->size;
	}
	p = c->data + c->off;
	c->off += need;
	memset(p, 0, len);
	return (p);
}

void
cbl_arena_free(struct cbl_arena *ar)
{
	struct cbl_chunk *c, *next;

	for (c = ar->head; c != NULL; c = next) {
		next = c->next;
		free(c);
	}
	ar->head = NULL;
	ar->total = 0;
}
