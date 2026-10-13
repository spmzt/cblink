/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Lookups in the YANG schema tables cblink-gen writes (cbl_schema.h):
 * a child by its delta, a node or an identity by its SID, whether one
 * identity is derived from another.
 */

#include <stddef.h>
#include <stdint.h>

#include "cbl_schema.h"

/* The child of SID sid among v[lo..hi), by a binary search. */
static const struct cbl_ynode *
search(const struct cbl_ynode *const *v, uint32_t lo, uint32_t hi,
    uint64_t sid)
{

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;

		if (v[mid]->sid == sid)
			return (v[mid]);
		if (v[mid]->sid < sid)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (NULL);
}

const struct cbl_ynode *
cbl_ynode_child(const struct cbl_ynode *n, int64_t delta)
{
	uint64_t sid, off;

	if (n == NULL || n->nchild == 0)
		return (NULL);
	/* Modulo 2^64, as SIDs and their deltas are. */
	sid = cbl_ynode_base(n) + (uint64_t)delta;
	off = sid - n->child[0]->sid;
	if (sid >= n->child[0]->sid && off < n->nmap) {
		if (n->map == NULL)
			return (n->child[off]);
		return (n->map[off] != 0 ? n->child[n->map[off] - 1] : NULL);
	}
	return (search(n->child, 0, n->nchild, sid));
}

const struct cbl_ynode *
cbl_yschema_node(const struct cbl_yschema *s, uint64_t sid)
{

	return (s != NULL ? search(s->node, 0, s->nnode, sid) : NULL);
}

const struct cbl_yident *
cbl_yschema_ident(const struct cbl_yschema *s, uint64_t sid)
{
	uint32_t lo = 0, hi;

	if (s == NULL)
		return (NULL);
	hi = s->nident;
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;

		if (s->ident[mid].sid == sid)
			return (&s->ident[mid]);
		if (s->ident[mid].sid < sid)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (NULL);
}

bool
cbl_yderived_from(const struct cbl_yschema *s, uint64_t x, uint64_t base,
    bool self)
{
	const struct cbl_yident *b;
	uint32_t lo = 0, hi;

	if (self && x == base)
		return (true);
	if ((b = cbl_yschema_ident(s, base)) == NULL)
		return (false);
	hi = b->nderived;
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;

		if (b->derived[mid] == x)
			return (true);
		if (b->derived[mid] < x)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (false);
}
