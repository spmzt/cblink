/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Declarative parsers in the style of snl(3): a sorted table maps
 * attribute types to struct offsets and callbacks, and one call fills a
 * user struct.  Memory for strings and nested objects comes from the
 * message arena.
 */

#include <errno.h>
#include <string.h>

#include "cbl_impl.h"

int
cbl_parse_nest(cbl_msg *msg, const cbl_attr *nest, const struct cbl_parser *p,
    void *target)
{
	const struct cbl_attr_parser *ap;
	const cbl_attr *a;
	int error;

	if (msg == NULL || p == NULL || target == NULL)
		return (EINVAL);
	if (nest == NULL || nest->kind != CBL_K_NEST)
		return (EINVAL);
	for (uint32_t i = 0; i < p->np_size; i++) {
		ap = &p->np[i];
		if ((a = cbl_map_lookup(nest, ap->type)) == NULL)
			continue;
		error = ap->cb(msg, a, ap->arg, (char *)target + ap->off);
		if (error != 0)
			return (error);
	}
	if (p->post != NULL)
		return (p->post(msg, target));
	return (0);
}

int
cbl_parse(cbl_msg *msg, const struct cbl_parser *p, void *target)
{

	return (cbl_parse_nest(msg, cbl_msg_body(msg), p, target));
}

int
cbl_parser_check(const struct cbl_parser *p)
{

	if (p == NULL)
		return (EINVAL);
	for (uint32_t i = 0; i < p->np_size; i++) {
		if (p->np[i].cb == NULL || p->np[i].type < CBL_ATTR_MIN)
			return (EINVAL);
		if (i > 0 && p->np[i].type <= p->np[i - 1].type)
			return (EINVAL);
		if (p->out_size != 0 && p->np[i].off >= p->out_size)
			return (EINVAL);
	}
	return (0);
}

static int
get_unsigned(const cbl_attr *a, uint64_t max, uint64_t *vp)
{
	int error;

	if ((error = cbl_attr_uint(a, vp)) != 0)
		return (error);
	return (*vp > max ? ERANGE : 0);
}

static int
get_signed(const cbl_attr *a, int64_t min, int64_t max, int64_t *vp)
{
	int error;

	if ((error = cbl_attr_int(a, vp)) != 0)
		return (error);
	return (*vp < min || *vp > max ? ERANGE : 0);
}

#define	GET_U(name, type, max)						\
int									\
name(cbl_msg *msg __unused, const cbl_attr *a,				\
    const void *arg __unused, void *target)				\
{									\
	uint64_t v;							\
	int error;							\
									\
	if ((error = get_unsigned(a, (max), &v)) != 0)			\
		return (error);						\
	*(type *)target = (type)v;					\
	return (0);							\
}

#define	GET_S(name, type, min, max)					\
int									\
name(cbl_msg *msg __unused, const cbl_attr *a,				\
    const void *arg __unused, void *target)				\
{									\
	int64_t v;							\
	int error;							\
									\
	if ((error = get_signed(a, (min), (max), &v)) != 0)		\
		return (error);						\
	*(type *)target = (type)v;					\
	return (0);							\
}

GET_U(cbl_get_u8, uint8_t, UINT8_MAX)
GET_U(cbl_get_u16, uint16_t, UINT16_MAX)
GET_U(cbl_get_u32, uint32_t, UINT32_MAX)
GET_U(cbl_get_u64, uint64_t, UINT64_MAX)
GET_S(cbl_get_s8, int8_t, INT8_MIN, INT8_MAX)
GET_S(cbl_get_s16, int16_t, INT16_MIN, INT16_MAX)
GET_S(cbl_get_s32, int32_t, INT32_MIN, INT32_MAX)
GET_S(cbl_get_s64, int64_t, INT64_MIN, INT64_MAX)

int
cbl_get_bool(cbl_msg *msg __unused, const cbl_attr *a,
    const void *arg __unused, void *target)
{

	return (cbl_attr_bool(a, target));
}

int
cbl_get_flag(cbl_msg *msg __unused, const cbl_attr *a,
    const void *arg __unused, void *target)
{

	if (a->kind != CBL_K_BOOL || !a->v.b)
		return (EINVAL);
	*(bool *)target = true;
	return (0);
}

int
cbl_get_double(cbl_msg *msg __unused, const cbl_attr *a,
    const void *arg __unused, void *target)
{

	return (cbl_attr_double(a, target));
}

int
cbl_get_str(cbl_msg *msg, const cbl_attr *a, const void *arg __unused,
    void *target)
{

	return (cbl_attr_str(msg, a, target));
}

int
cbl_get_bytes(cbl_msg *msg __unused, const cbl_attr *a,
    const void *arg __unused, void *target)
{
	struct cbl_bytes *b = target;

	if (a->kind != CBL_K_BYTES)
		return (EINVAL);
	b->p = a->v.s.p;
	b->len = a->v.s.len;
	return (0);
}

int
cbl_get_attr(cbl_msg *msg __unused, const cbl_attr *a,
    const void *arg __unused, void *target)
{

	*(const cbl_attr **)target = a;
	return (0);
}

int
cbl_get_nested(cbl_msg *msg, const cbl_attr *a, const void *arg,
    void *target)
{

	return (cbl_parse_nest(msg, a, arg, target));
}

int
cbl_get_nested_ptr(cbl_msg *msg, const cbl_attr *a, const void *arg,
    void *target)
{
	const struct cbl_parser *p = arg;
	void *obj;
	int error;

	if ((obj = cbl_arena_alloc(&msg->arena, p->out_size)) == NULL)
		return (ENOMEM);
	if ((error = cbl_parse_nest(msg, a, p, obj)) != 0)
		return (error);
	*(void **)target = obj;
	return (0);
}

int
cbl_get_array(cbl_msg *msg, const cbl_attr *a, const void *arg,
    void *target)
{
	const struct cbl_array_desc *d = arg;
	struct cbl_array *arr = target;
	char *v;
	int error;

	if (a->kind != CBL_K_ARRAY || d == NULL || d->elem_size == 0)
		return (EINVAL);
	arr->n = 0;
	arr->v = NULL;
	if (a->count == 0)
		return (0);
	/* count <= max_attrs, so this is bounded by the decoder limits. */
	v = cbl_arena_alloc(&msg->arena, (size_t)a->count * d->elem_size);
	if (v == NULL)
		return (ENOMEM);
	for (uint32_t i = 0; i < a->count; i++) {
		error = d->cb(msg, &a->child[i], d->arg,
		    v + (size_t)i * d->elem_size);
		if (error != 0)
			return (error);
	}
	arr->n = a->count;
	arr->v = v;
	return (0);
}
