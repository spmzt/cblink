/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Declarative attribute policies (docs/API.md section 7).  The framework
 * validates a request against its command's policy before the handler
 * runs.  Attributes that are not in the policy are ignored.
 */

#include <errno.h>
#include <string.h>

#include "cbl_impl.h"

struct vctx {
	struct cbl_verr	*err;
	size_t		 depth;
};

static int
vfail(struct vctx *v, int error, const char *msg)
{

	if (v->err != NULL) {
		v->err->msg = msg;
		v->err->pathlen = v->depth < CBL_PATH_MAX ? v->depth :
		    CBL_PATH_MAX;	/* only that much was recorded */
	}
	return (error);
}

static void
vpush(struct vctx *v, uint32_t val, bool index)
{

	if (v->err != NULL && v->depth < CBL_PATH_MAX) {
		v->err->path[v->depth].v = val;
		v->err->path[v->depth].index = index;
	}
	v->depth++;
}

static int validate_map(struct vctx *v, const cbl_attr *map,
    const struct cbl_policy_set *ps);

static bool
enum_has(const struct cbl_enum *e, uint64_t val)
{

	for (uint32_t i = 0; i < e->n; i++)
		if (e->v[i] == val)
			return (true);
	return (false);
}

static int
validate_value(struct vctx *v, const cbl_attr *a, const struct cbl_policy *p)
{
	bool range = (p->flags & CBL_PF_RANGE) != 0;
	int64_t iv;
	int error;

	switch (p->kind) {
	case CBL_K_ANY:
		break;
	case CBL_K_UINT:
		if (a->kind != CBL_K_UINT)
			return (vfail(v, EINVAL,
			    "expected an unsigned integer"));
		if ((p->flags & CBL_PF_MASK) != 0 && (a->v.u & ~p->u.max) != 0)
			return (vfail(v, EINVAL, "unknown flag bits"));
		if ((p->flags & CBL_PF_MASK) == 0 && range &&
		    (a->v.u < p->u.min || a->v.u > p->u.max))
			return (vfail(v, ERANGE, "value out of range"));
		if (p->values != NULL && !enum_has(p->values, a->v.u))
			return (vfail(v, EINVAL, "value not in enumeration"));
		break;
	case CBL_K_INT:
		if (cbl_attr_int(a, &iv) != 0)
			return (vfail(v, a->kind == CBL_K_INT ||
			    a->kind == CBL_K_UINT ? ERANGE : EINVAL,
			    "expected a signed integer"));
		if (range && (iv < p->i.min || iv > p->i.max))
			return (vfail(v, ERANGE, "value out of range"));
		break;
	case CBL_K_BOOL:
		if (a->kind != CBL_K_BOOL)
			return (vfail(v, EINVAL, "expected a boolean"));
		break;
	case CBL_K_FLAG:
		if (a->kind != CBL_K_BOOL || !a->v.b)
			return (vfail(v, EINVAL, "flag must be true"));
		break;
	case CBL_K_TEXT:
		if (a->kind != CBL_K_TEXT)
			return (vfail(v, EINVAL, "expected a text string"));
		if (memchr(a->v.s.p, '\0', a->v.s.len) != NULL)
			return (vfail(v, EINVAL, "text contains NUL"));
		if (range && (a->v.s.len < p->len.min ||
		    a->v.s.len > p->len.max))
			return (vfail(v, ERANGE, "length out of range"));
		break;
	case CBL_K_BYTES:
		if (a->kind != CBL_K_BYTES)
			return (vfail(v, EINVAL, "expected a byte string"));
		if (range && (a->v.s.len < p->len.min ||
		    a->v.s.len > p->len.max))
			return (vfail(v, ERANGE, "length out of range"));
		break;
	case CBL_K_FLOAT:
		if (a->kind != CBL_K_FLOAT)
			return (vfail(v, EINVAL, "expected a float"));
		break;
	case CBL_K_NULL:
		if (a->kind != CBL_K_NULL)
			return (vfail(v, EINVAL, "expected null"));
		break;
	case CBL_K_NEST:
		if (a->kind != CBL_K_NEST)
			return (vfail(v, EINVAL, "expected a nested set"));
		if (p->nested != NULL &&
		    (error = validate_map(v, a, p->nested)) != 0)
			return (error);
		break;
	default:
		return (vfail(v, EINVAL, "bad policy kind"));
	}
	if (p->validate != NULL && (error = p->validate(a, p->arg)) != 0)
		return (vfail(v, error, "rejected by validator"));
	return (0);
}

static int
validate_attr(struct vctx *v, const cbl_attr *a, const struct cbl_policy *p)
{
	uint32_t n;
	int error;

	if ((p->flags & CBL_PF_MULTI) == 0)
		return (validate_value(v, a, p));
	if (a->kind != CBL_K_ARRAY)
		return (vfail(v, EINVAL, "expected an array"));
	n = a->count;
	if (n < p->min_count || (p->max_count != 0 && n > p->max_count))
		return (vfail(v, ERANGE, "element count out of range"));
	for (uint32_t i = 0; i < n; i++) {
		vpush(v, i, true);
		if ((error = validate_value(v, &a->child[i], p)) != 0)
			return (error);
		v->depth--;
	}
	return (0);
}

static int
validate_map(struct vctx *v, const cbl_attr *map,
    const struct cbl_policy_set *ps)
{
	const struct cbl_policy *p;
	const cbl_attr *a;
	int error;

	for (uint32_t i = 0; i < ps->n; i++) {
		p = &ps->p[i];
		a = cbl_map_lookup(map, p->type);
		if (a == NULL) {
			if ((p->flags & CBL_PF_REQUIRED) == 0)
				continue;
			if (v->err != NULL)
				v->err->miss_type = p->type;
			return (vfail(v, EINVAL,
			    "missing required attribute"));
		}
		vpush(v, p->type, false);
		if ((error = validate_attr(v, a, p)) != 0)
			return (error);
		v->depth--;
	}
	return (0);
}

int
cbl_validate(const cbl_attr *map, const struct cbl_policy_set *ps,
    struct cbl_verr *err)
{
	struct vctx v = { .err = err };

	if (err != NULL) {
		memset(err, 0, sizeof(*err));
		err->miss_type = -1;
	}
	if (map == NULL || map->kind != CBL_K_NEST)
		return (EINVAL);
	if (ps == NULL)
		return (0);
	return (validate_map(&v, map, ps));
}

/* Sanity-check a policy table: sorted, unique, sensible ranges. */
int
cbl_policy_set_check(const struct cbl_policy_set *ps)
{
	const struct cbl_policy *p;

	if (ps == NULL)
		return (0);
	for (uint32_t i = 0; i < ps->n; i++) {
		p = &ps->p[i];
		if (p->type < CBL_ATTR_MIN)
			return (EINVAL);
		if (i > 0 && p->type <= ps->p[i - 1].type)
			return (EINVAL);
		if (p->kind > CBL_K_ARRAY || p->kind == CBL_K_ARRAY)
			return (EINVAL);
		if ((p->flags & CBL_PF_RANGE) != 0) {
			if (p->kind == CBL_K_UINT && p->u.min > p->u.max)
				return (EINVAL);
			if (p->kind == CBL_K_INT && p->i.min > p->i.max)
				return (EINVAL);
			if ((p->kind == CBL_K_TEXT || p->kind == CBL_K_BYTES) &&
			    p->len.min > p->len.max)
				return (EINVAL);
		}
		if (p->max_count != 0 && p->min_count > p->max_count)
			return (EINVAL);
	}
	return (0);
}
