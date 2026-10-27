/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A YANG value as RFC 7951's JSON, from its struct by the schema
 * tables, as the YANG-CBOR encoder (cbl_ycodec.c) walks it: for a
 * program to show or hand on what a GET brought, and for those that
 * speak JSON.
 *
 * - A member is named "module:name" at the top and where its module is
 *   not its parent's (an augment), else "name" (section 4).
 * - Containers are objects, lists arrays of objects, leaf-lists arrays.
 * - int8 to int32 and uint8 to uint32 are numbers; int64, uint64 and
 *   decimal64 strings, decimal64 with its fraction digits (6.1).
 * - An enumeration is its name, bits the names of those set, a space
 *   between (6.3, 6.5); binary is base64 (6.6); empty [null] (6.9);
 *   an identityref "module:identity" (6.8), the module always said.
 * - A union is its member's value, as that member's type says.
 * - Anydata is an object of its content's members, each "module:name"
 *   (7.7): its YANG-CBOR's keys deltas from its own SID, top-level
 *   nodes of the tables.  Where it holds one the tables do not have,
 *   it is null, as anyxml and an instance-identifier are: left out of
 *   this version.
 */

#include <sys/types.h>

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cblink.h"
#include "cbl_schema.h"
#include "cbl_yimpl.h"

#define	AT(p, off)	((const void *)((const char *)(p) + (off)))
#define	JDEPTH_MAX	64

struct yarr {
	size_t		 n;
	const void	*v;
};

static int	json_map(struct cbl_ybuf *, const struct cbl_ynode *,
		    const void *, int);
static int	json_child(struct cbl_ybuf *, const struct cbl_ynode *,
		    const void *, int);
static int	json_name(struct cbl_ybuf *, const struct cbl_ynode *,
		    const struct cbl_ynode *);

static int
jput(struct cbl_ybuf *b, const void *d, size_t len)
{
	size_t	 cap;
	uint8_t	*p;

	if (b->len + len > b->cap) {
		cap = b->cap > 0 ? b->cap : 256;
		while (cap < b->len + len)
			cap *= 2;
		if ((p = realloc(b->p, cap)) == NULL)
			return (ENOMEM);
		b->p = p;
		b->cap = cap;
	}
	memcpy(b->p + b->len, d, len);
	b->len += len;
	return (0);
}

static int
jputs(struct cbl_ybuf *b, const char *s)
{

	return (jput(b, s, strlen(s)));
}

static int
jprintf(struct cbl_ybuf *b, const char *fmt, ...)
{
	char	 buf[96];
	va_list	 ap;
	int	 n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(buf))
		return (EINVAL);
	return (jput(b, buf, (size_t)n));
}

/* A JSON string: its quotes, the escapes RFC 8259 asks for. */
static int
jstr(struct cbl_ybuf *b, const char *s, size_t len)
{
	const unsigned char	*p = (const unsigned char *)s;
	char			 esc[8];
	size_t			 i;
	int			 error;

	if ((error = jputs(b, "\"")) != 0)
		return (error);
	for (i = 0; i < len; i++) {
		if (p[i] == '"' || p[i] == '\\') {
			esc[0] = '\\';
			esc[1] = (char)p[i];
			error = jput(b, esc, 2);
		} else if (p[i] < 0x20) {
			snprintf(esc, sizeof(esc), "\\u%04x", p[i]);
			error = jputs(b, esc);
		} else
			error = jput(b, &p[i], 1);
		if (error != 0)
			return (error);
	}
	return (jputs(b, "\""));
}

static int
jstrz(struct cbl_ybuf *b, const char *s)
{

	return (jstr(b, s != NULL ? s : "", s != NULL ? strlen(s) : 0));
}

static int
jbase64(struct cbl_ybuf *b, const uint8_t *p, size_t len)
{
	static const char	 tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				    "abcdefghijklmnopqrstuvwxyz0123456789+/";
	char			 q[4];
	size_t			 i;
	uint32_t		 v;
	int			 error;

	if ((error = jputs(b, "\"")) != 0)
		return (error);
	for (i = 0; i < len; i += 3) {
		v = (uint32_t)p[i] << 16;
		if (i + 1 < len)
			v |= (uint32_t)p[i + 1] << 8;
		if (i + 2 < len)
			v |= p[i + 2];
		q[0] = tab[(v >> 18) & 63];
		q[1] = tab[(v >> 12) & 63];
		q[2] = i + 1 < len ? tab[(v >> 6) & 63] : '=';
		q[3] = i + 2 < len ? tab[v & 63] : '=';
		if ((error = jput(b, q, 4)) != 0)
			return (error);
	}
	return (jputs(b, "\""));
}

static int
read_enum(const void *p, uint32_t size)
{

	switch (size) {
	case 1:
		return (*(const int8_t *)p);
	case 2:
		return (*(const int16_t *)p);
	case 8:
		return ((int)*(const int64_t *)p);
	default:
		return (*(const int *)p);
	}
}

/* An identity by its SID, among those the schema knows; NULL else. */
static const struct cbl_yident *
ident_of(const struct cbl_yschema *s, uint64_t sid)
{
	uint32_t	lo, hi, mid;

	if (s == NULL || s->nident == 0)
		return (NULL);
	lo = 0;
	hi = s->nident;
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if (s->ident[mid].sid == sid)
			return (&s->ident[mid]);
		if (s->ident[mid].sid < sid)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (NULL);
}

/* decimal64: its digits, the point fdigits from the right. */
static int
jdec64(struct cbl_ybuf *b, int64_t v, uint8_t fdigits)
{
	char		 digits[32], out[40];
	uint64_t	 u;
	size_t		 n, i, o;

	u = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
	n = (size_t)snprintf(digits, sizeof(digits), "%0*" PRIu64,
	    fdigits + 1, u);
	o = 0;
	if (v < 0)
		out[o++] = '-';
	for (i = 0; i < n; i++) {
		if (fdigits > 0 && i == n - fdigits)
			out[o++] = '.';
		out[o++] = digits[i];
	}
	out[o] = '\0';
	return (jstrz(b, out));
}

static int
json_value(struct cbl_ybuf *b, const struct cbl_ynode *n,
    const struct cbl_ytype *t, const void *v)
{
	const struct cbl_bytes	*by;
	const struct cbl_yident	*id;
	int			 e, error;
	bool			 first;

	switch (t->kind) {
	case CBL_YT_INT8:
		return (jprintf(b, "%d", *(const int8_t *)v));
	case CBL_YT_INT16:
		return (jprintf(b, "%d", *(const int16_t *)v));
	case CBL_YT_INT32:
		return (jprintf(b, "%" PRId32, *(const int32_t *)v));
	case CBL_YT_INT64:
		return (jprintf(b, "\"%" PRId64 "\"", *(const int64_t *)v));
	case CBL_YT_UINT8:
		return (jprintf(b, "%u", *(const uint8_t *)v));
	case CBL_YT_UINT16:
		return (jprintf(b, "%u", *(const uint16_t *)v));
	case CBL_YT_UINT32:
		return (jprintf(b, "%" PRIu32, *(const uint32_t *)v));
	case CBL_YT_UINT64:
		return (jprintf(b, "\"%" PRIu64 "\"", *(const uint64_t *)v));
	case CBL_YT_DECIMAL64:
		return (jdec64(b, *(const int64_t *)v, t->fdigits));
	case CBL_YT_BOOLEAN:
		return (jputs(b, *(const bool *)v ? "true" : "false"));
	case CBL_YT_EMPTY:
		return (jputs(b, "[null]"));
	case CBL_YT_STRING:
		return (jstrz(b, *(const char *const *)v));
	case CBL_YT_BINARY:
		by = v;
		return (jbase64(b, by->p, by->len));
	case CBL_YT_BITS:
		by = v;
		if ((error = jputs(b, "\"")) != 0)
			return (error);
		first = true;
		for (int64_t pos = 0; (size_t)pos < by->len * 8; pos++) {
			if ((((const uint8_t *)by->p)[pos / 8] &
			    (1u << (pos % 8))) == 0)
				continue;
			for (uint32_t i = 0; i < t->nitems; i++)
				if (t->items[i].value == pos) {
					if ((!first && (error = jputs(b,
					    " ")) != 0) || (error = jputs(b,
					    t->items[i].name)) != 0)
						return (error);
					first = false;
				}
		}
		return (jputs(b, "\""));
	case CBL_YT_ENUMERATION:
		e = read_enum(v, t->csize);
		for (uint32_t i = 0; i < t->nitems; i++)
			if (t->items[i].value == e)
				return (jstrz(b, t->items[i].name));
		return (EINVAL);
	case CBL_YT_IDENTITYREF:
		id = ident_of(n->module != NULL ? n->module->schema : NULL,
		    *(const uint64_t *)v);
		if (id == NULL)
			return (jprintf(b, "\"%" PRIu64 "\"",
			    *(const uint64_t *)v));
		if ((error = jputs(b, "\"")) != 0 || (error = jputs(b,
		    id->module != NULL ? id->module->name : "")) != 0 ||
		    (error = jputs(b, ":")) != 0 ||
		    (error = jputs(b, id->name)) != 0)
			return (error);
		return (jputs(b, "\""));
	case CBL_YT_INSTANCEID:
		return (jputs(b, "null"));
	case CBL_YT_UNION: {
		unsigned which = *(const unsigned *)v;

		if (which >= t->nmembers)
			return (EINVAL);
		return (json_value(b, n, t->members[which], AT(v, t->voff)));
	}
	}
	return (EINVAL);
}

/* A CBOR head at *pp: its major type and value; false: none. */
static bool
cbor_head(const uint8_t **pp, const uint8_t *end, int *major, uint64_t *v)
{
	const uint8_t *p = *pp;
	size_t k;

	if (p >= end)
		return (false);
	*major = p[0] >> 5;
	*v = p[0] & 0x1f;
	p++;
	if (*v >= 24) {
		if (*v > 27)
			return (false);
		k = (size_t)1 << (*v - 24);
		if ((size_t)(end - p) < k)
			return (false);
		for (*v = 0; k > 0; k--)
			*v = *v << 8 | *p++;
	}
	*pp = p;
	return (true);
}

/*
 * Anydata's YANG-CBOR, {delta: value}, as an object of its members,
 * each a top-level node of the tables, decoded and said as one; null
 * where it is not so.
 */
static int
json_anydata(struct cbl_ybuf *b, const struct cbl_ynode *n,
    const struct cbl_bytes *v, int depth)
{
	const struct cbl_yschema *s = n->module != NULL ? n->module->schema :
	    NULL;
	const uint8_t *p, *end;
	const struct cbl_ynode *c;
	struct cbl_ybuf out = { 0 };
	cbl_yarena *a;
	uint64_t count, d;
	int64_t delta;
	void *data;
	size_t len;
	int major, error = 0;
	bool ok;

	if (v->p == NULL || s == NULL || depth > JDEPTH_MAX)
		return (jputs(b, "null"));
	p = v->p;
	end = p + v->len;
	if (!cbor_head(&p, end, &major, &count) || major != 5)
		return (jputs(b, "null"));
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	ok = (error = jputs(&out, "{")) == 0;
	for (uint64_t i = 0; ok && i < count; i++) {
		if (!cbor_head(&p, end, &major, &d) || major > 1 ||
		    d > INT64_MAX) {
			ok = false;
			break;
		}
		delta = major == 0 ? (int64_t)d : -1 - (int64_t)d;
		c = cbl_yschema_node(s, (uint64_t)((int64_t)n->sid + delta));
		if (c == NULL || c->module == NULL || c->module->size == 0 ||
		    (len = cbl_ycbor_skip(p, end)) == 0 ||
		    (data = cbl_yarena_alloc(a, c->module->size)) == NULL ||
		    cbl_ydecode_member(c, p, len, data, a, 0, NULL, 0) != 0) {
			ok = false;
			break;
		}
		p += len;
		if ((i > 0 && (error = jputs(&out, ",")) != 0) ||
		    (error = json_name(&out, c, NULL)) != 0 ||
		    (error = json_child(&out, c, data, depth + 1)) != 0)
			ok = false;
	}
	if (ok)
		error = jputs(&out, "}");
	cbl_yarena_free(a);
	if (ok && error == 0)
		error = jput(b, out.p, out.len);
	else if (error == 0 || error == EINVAL)
		error = jputs(b, "null");
	cbl_ybuf_free(&out);
	return (error);
}

/* A member's name: "module:name" at the top or across modules. */
static int
json_name(struct cbl_ybuf *b, const struct cbl_ynode *c,
    const struct cbl_ynode *parent)
{
	int	error;

	if ((error = jputs(b, "\"")) != 0)
		return (error);
	if (parent == NULL || parent->module != c->module) {
		if ((error = jputs(b, c->module != NULL ? c->module->name :
		    "")) != 0 || (error = jputs(b, ":")) != 0)
			return (error);
	}
	if ((error = jputs(b, c->name)) != 0)
		return (error);
	return (jputs(b, "\":"));
}

static int
json_child(struct cbl_ybuf *b, const struct cbl_ynode *n, const void *p,
    int depth)
{
	const struct yarr	*a;
	int			 error;

	switch (n->kind) {
	case CBL_YN_CONTAINER:
		return (json_map(b, n, *(const void *const *)AT(p, n->off),
		    depth + 1));
	case CBL_YN_LIST:
		a = (const struct yarr *)AT(p, n->off);
		if ((error = jputs(b, "[")) != 0)
			return (error);
		for (size_t i = 0; i < a->n; i++)
			if ((i > 0 && (error = jputs(b, ",")) != 0) ||
			    (error = json_map(b, n, AT(a->v, i * n->size),
			    depth + 1)) != 0)
				return (error);
		return (jputs(b, "]"));
	case CBL_YN_LEAFLIST:
		a = (const struct yarr *)AT(p, n->off);
		if ((error = jputs(b, "[")) != 0)
			return (error);
		for (size_t i = 0; i < a->n; i++)
			if ((i > 0 && (error = jputs(b, ",")) != 0) ||
			    (error = json_value(b, n, n->type, AT(a->v, i *
			    n->type->csize))) != 0)
				return (error);
		return (jputs(b, "]"));
	case CBL_YN_LEAF:
		return (json_value(b, n, n->type, AT(p, n->off)));
	case CBL_YN_ANYDATA:
		return (json_anydata(b, n, (const struct cbl_bytes *)AT(p,
		    n->off), depth));
	case CBL_YN_ANYXML:
		return (jputs(b, "null"));
	}
	return (EINVAL);
}

/* n's children in struct p, an object. */
static int
json_map(struct cbl_ybuf *b, const struct cbl_ynode *n, const void *p,
    int depth)
{
	bool	first = true;
	int	error;

	if (depth > JDEPTH_MAX)
		return (ELOOP);
	if ((error = jputs(b, "{")) != 0)
		return (error);
	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ynode *c = n->child[i];

		if (!cbl_ypresent(c, p))
			continue;
		if ((!first && (error = jputs(b, ",")) != 0) ||
		    (error = json_name(b, c, n)) != 0 ||
		    (error = json_child(b, c, p, depth)) != 0)
			return (error);
		first = false;
	}
	return (jputs(b, "}"));
}

int
cbl_yjson(const struct cbl_ynode *n, const void *p, struct cbl_ybuf *b)
{

	if (n == NULL || p == NULL || b == NULL)
		return (EINVAL);
	return (json_map(b, n, p, 0));
}

int
cbl_yjson_members(const struct cbl_ymodule *m, const void *data,
    struct cbl_ybuf *b, bool *first)
{
	const struct cbl_ynode	*c;
	int			 error;

	if (m == NULL || data == NULL || b == NULL || first == NULL)
		return (EINVAL);
	for (uint32_t i = 0; i < m->ntop; i++) {
		c = m->top[i];
		if (c->kind != CBL_YN_CONTAINER && c->kind != CBL_YN_LIST &&
		    c->kind != CBL_YN_LEAF && c->kind != CBL_YN_LEAFLIST &&
		    c->kind != CBL_YN_ANYDATA && c->kind != CBL_YN_ANYXML)
			continue;
		if (!cbl_ypresent(c, data))
			continue;
		if ((!*first && (error = jputs(b, ",")) != 0) ||
		    (error = json_name(b, c, NULL)) != 0 ||
		    (error = json_child(b, c, data, 0)) != 0)
			return (error);
		*first = false;
	}
	return (0);
}

int
cbl_yjson_module(const struct cbl_ymodule *m, const void *data,
    struct cbl_ybuf *b)
{
	bool	first = true;
	int	error;

	if ((error = jputs(b, "{")) != 0 ||
	    (error = cbl_yjson_members(m, data, b, &first)) != 0)
		return (error);
	return (jputs(b, "}"));
}
