/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Read access to decoded messages. */

#include <errno.h>
#include <string.h>

#include "cbl_impl.h"

static bool
is_family_key(int64_t key)
{

	return (key >= CBL_ATTR_MIN && key <= CBL_ATTR_MAX);
}

uint16_t
cbl_msg_family(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.family : 0);
}

uint16_t
cbl_msg_cmd(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.cmd : 0);
}

uint32_t
cbl_msg_flags(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.flags : 0);
}

uint32_t
cbl_msg_seq(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.seq : 0);
}

uint32_t
cbl_msg_stream(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.stream : 0);
}

size_t
cbl_msg_len(const cbl_msg *msg)
{

	if (msg == NULL)
		return (0);
	return (msg->finalized ? msg->len : 0);
}

const cbl_attr *
cbl_msg_body(const cbl_msg *msg)
{

	if (msg == NULL || !msg->decoded)
		return (NULL);
	return (msg->nodes != NULL ? &msg->nodes[0] : &msg->empty);
}

/* Binary search: map children are sorted by key. */
const cbl_attr *
cbl_map_lookup(const cbl_attr *map, int64_t key)
{
	uint32_t lo, hi, mid;

	if (map == NULL || map->kind != CBL_K_NEST)
		return (NULL);
	lo = 0;
	hi = map->count;
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if (map->child[mid].key == key)
			return (&map->child[mid]);
		if (map->child[mid].key < key)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (NULL);
}

const cbl_attr *
cbl_msg_attr(const cbl_msg *msg, uint16_t type)
{

	if (type == 0)
		return (NULL);
	return (cbl_map_lookup(cbl_msg_body(msg), type));
}

const cbl_attr *
cbl_attr_get(const cbl_attr *nest, uint16_t type)
{

	if (type == 0)
		return (NULL);
	return (cbl_map_lookup(nest, type));
}

/* Iteration skips framework and out-of-range keys in maps. */
static const cbl_attr *
skip_hidden(const cbl_attr *a, const cbl_attr *end)
{

	for (; a < end; a++)
		if (!a->inmap || is_family_key(a->key))
			return (a);
	return (NULL);
}

const cbl_attr *
cbl_attr_first(const cbl_attr *c)
{

	if (c == NULL || (c->kind != CBL_K_NEST && c->kind != CBL_K_ARRAY) ||
	    c->count == 0)
		return (NULL);
	return (skip_hidden(c->child, c->child + c->count));
}

const cbl_attr *
cbl_attr_next(const cbl_attr *a)
{
	const cbl_attr *p;

	if (a == NULL || (p = a->parent) == NULL)
		return (NULL);
	return (skip_hidden(a + 1, p->child + p->count));
}

const cbl_attr *
cbl_attr_index(const cbl_attr *array, size_t i)
{

	if (array == NULL || array->kind != CBL_K_ARRAY || i >= array->count)
		return (NULL);
	return (&array->child[i]);
}

uint16_t
cbl_attr_type(const cbl_attr *a)
{

	if (a == NULL || !a->inmap || !is_family_key(a->key))
		return (0);
	return ((uint16_t)a->key);
}

enum cbl_kind
cbl_attr_kind(const cbl_attr *a)
{

	return (a != NULL ? (enum cbl_kind)a->kind : CBL_K_ANY);
}

size_t
cbl_attr_count(const cbl_attr *a)
{

	if (a == NULL || (a->kind != CBL_K_NEST && a->kind != CBL_K_ARRAY))
		return (0);
	return (a->count);
}

int
cbl_attr_uint(const cbl_attr *a, uint64_t *vp)
{

	if (a == NULL || vp == NULL)
		return (EINVAL);
	if (a->kind == CBL_K_INT)
		return (ERANGE);
	if (a->kind != CBL_K_UINT)
		return (EINVAL);
	*vp = a->v.u;
	return (0);
}

int
cbl_attr_int(const cbl_attr *a, int64_t *vp)
{

	if (a == NULL || vp == NULL)
		return (EINVAL);
	if (a->kind == CBL_K_UINT) {
		if (a->v.u > INT64_MAX)
			return (ERANGE);
		*vp = (int64_t)a->v.u;
		return (0);
	}
	if (a->kind != CBL_K_INT)
		return (EINVAL);
	if ((a->nflags & CBL_NF_NEGBIG) != 0)
		return (ERANGE);
	*vp = a->v.i;
	return (0);
}

int
cbl_attr_bool(const cbl_attr *a, bool *vp)
{

	if (a == NULL || vp == NULL || a->kind != CBL_K_BOOL)
		return (EINVAL);
	*vp = a->v.b;
	return (0);
}

int
cbl_attr_double(const cbl_attr *a, double *vp)
{

	if (a == NULL || vp == NULL || a->kind != CBL_K_FLOAT)
		return (EINVAL);
	*vp = a->v.d;
	return (0);
}

int
cbl_attr_bytes(const cbl_attr *a, const void **pp, size_t *lenp)
{

	if (a == NULL || pp == NULL || lenp == NULL ||
	    (a->kind != CBL_K_BYTES && a->kind != CBL_K_TEXT))
		return (EINVAL);
	*pp = a->v.s.p;
	*lenp = a->v.s.len;
	return (0);
}

int
cbl_attr_str(cbl_msg *msg, const cbl_attr *a, const char **sp)
{
	char *s;

	if (msg == NULL || a == NULL || sp == NULL || a->kind != CBL_K_TEXT)
		return (EINVAL);
	if (memchr(a->v.s.p, '\0', a->v.s.len) != NULL)
		return (EINVAL);
	if ((s = cbl_arena_alloc(&msg->arena, a->v.s.len + 1)) == NULL)
		return (ENOMEM);
	memcpy(s, a->v.s.p, a->v.s.len);
	*sp = s;
	return (0);
}

int
cbl_msg_err_code(const cbl_msg *msg)
{

	/* Frames that carry an outcome: errors, resets and closes. */
	if (msg == NULL || (msg->hdr.flags & (CBL_F_ERROR | CBL_F_NOTIFY |
	    CBL_F_S_RESET | CBL_F_S_CLOSE)) == 0)
		return (0);
	return (msg->err_code);
}

const char *
cbl_msg_err_str(const cbl_msg *msg)
{

	return (msg != NULL ? msg->err_str : NULL);
}

size_t
cbl_msg_err_path(const cbl_msg *msg, struct cbl_path_elem *path, size_t max)
{
	const cbl_attr *e;
	size_t n;

	if (msg == NULL || msg->err_path == NULL)
		return (0);
	for (n = 0; n < msg->err_path->count; n++) {
		e = &msg->err_path->child[n];
		if (e->kind == CBL_K_ARRAY && e->count == 1)
			e = &e->child[0];
		if (e->kind != CBL_K_UINT || e->v.u > UINT32_MAX)
			return (0);	/* malformed path: report none */
	}
	for (n = 0; n < msg->err_path->count && n < max; n++) {
		e = &msg->err_path->child[n];
		path[n].index = e->kind == CBL_K_ARRAY;
		if (path[n].index)
			e = &e->child[0];
		path[n].v = (uint32_t)e->v.u;
	}
	return (msg->err_path->count);
}

int
cbl_msg_err_miss_type(const cbl_msg *msg)
{

	return (msg != NULL ? msg->err_miss : -1);
}

int
cbl_msg_err_cookie(const cbl_msg *msg, const void **pp, size_t *lenp)
{

	if (msg == NULL || pp == NULL || lenp == NULL)
		return (EINVAL);
	if (msg->err_cookie == NULL)
		return (ENOENT);
	*pp = msg->err_cookie->v.s.p;
	*lenp = msg->err_cookie->v.s.len;
	return (0);
}
