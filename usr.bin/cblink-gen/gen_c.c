/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * C code generation (docs/GENERATOR.md).  Output is a pure function of
 * the spec: no timestamps, no paths, spec order everywhere except tables
 * that must be sorted by id.
 */

#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "spec.h"

/*
 * A struct-like object: a whole attribute set, or the attribute list of
 * one request, reply, dump item or notification.
 */
struct obj {
	char			 *tag;		/* struct P_<tag> */
	const struct sset	 *set;
	size_t			  n;
	const struct sattr	**a;		/* list order */
	bool			 *req;		/* CBL_PF_REQUIRED per attr */
	bool			  has_msg;	/* owns its reply message */
};

struct gctx {
	const struct spec	*s;
	const char		*P;		/* prefix */
	const char		*PU;		/* PREFIX */
	char			*famc;		/* mangled family name */
	struct obj		*objs;
	size_t			 nobjs;
};

/* Names. */
static bool
is_family_set(const struct gctx *g, const struct sset *set)
{

	return (strcmp(set->cname, g->famc) == 0);
}

/* "PU_A_KEY" or "PU_SET_A_KEY". */
static char *
attr_id(const struct gctx *g, const struct sset *set, const struct sattr *a)
{
	char *su, *au, *id;

	au = upper(a->cname);
	if (is_family_set(g, set))
		id = xasprintf("%s_A_%s", g->PU, au);
	else {
		su = upper(set->cname);
		id = xasprintf("%s_%s_A_%s", g->PU, su, au);
		free(su);
	}
	free(au);
	return (id);
}

/* "P_put_key" or "P_set_put_key". */
static char *
attr_put(const struct gctx *g, const struct sset *set, const struct sattr *a)
{

	if (is_family_set(g, set))
		return (xasprintf("%s_put_%s", g->P, a->cname));
	return (xasprintf("%s_%s_put_%s", g->P, set->cname, a->cname));
}

static char *
cmd_id(const struct gctx *g, const struct sop *op)
{
	char *u = upper(op->cname), *id;

	id = xasprintf("%s_CMD_%s", g->PU, u);
	free(u);
	return (id);
}

static char *
grp_id(const struct gctx *g, const struct sgrp *gr)
{
	char *u = upper(gr->cname), *id;

	id = xasprintf("%s_MCGRP_%s", g->PU, u);
	free(u);
	return (id);
}

static void
emit_doc(struct buf *b, const char *doc, const char *indent)
{
	const char *p, *e;

	if (doc == NULL || *doc == '\0')
		return;
	buf_printf(b, "%s/*\n", indent);
	for (p = doc; *p != '\0'; p = *e == '\0' ? e : e + 1) {
		e = strchr(p, '\n');
		if (e == NULL)
			e = p + strlen(p);
		if (e == p)
			buf_printf(b, "%s *\n", indent);
		else {
			buf_printf(b, "%s * ", indent);
			/*
			 * Never let a doc string close the comment, or
			 * open one (-Wcomment, an error at WARNS=6).
			 */
			for (const char *q = p; q < e; q++) {
				if (q[0] == '*' && q + 1 < e && q[1] == '/')
					buf_puts(b, "* /"), q++;
				else if (q[0] == '/' && q + 1 < e &&
				    q[1] == '*')
					buf_puts(b, "/ *"), q++;
				else
					buf_add(b, q, 1);
			}
			buf_puts(b, "\n");
		}
	}
	buf_printf(b, "%s */\n", indent);
}

static const char *
elem_ctype(const struct gctx *g, const struct sattr *a, char *tmp, size_t len)
{

	switch (a->type) {
	case T_TEXT:
		return ("const char *");
	case T_FLAG:
		return ("bool");
	case T_NEST:
		snprintf(tmp, len, "struct %s_%s", g->P, a->nested->cname);
		return (tmp);
	default:
		return (stype_ctype(a->type));
	}
}

static const char *
getter(enum stype t)
{

	switch (t) {
	case T_U8: return ("cbl_get_u8");
	case T_U16: return ("cbl_get_u16");
	case T_U32: return ("cbl_get_u32");
	case T_U64: return ("cbl_get_u64");
	case T_S8: return ("cbl_get_s8");
	case T_S16: return ("cbl_get_s16");
	case T_S32: return ("cbl_get_s32");
	case T_S64: return ("cbl_get_s64");
	case T_BOOL: return ("cbl_get_bool");
	case T_FLAG: return ("cbl_get_flag");
	case T_FLOAT: return ("cbl_get_double");
	case T_TEXT: return ("cbl_get_str");
	case T_BYTES: return ("cbl_get_bytes");
	default: return (NULL);
	}
}

static const char *
kind(enum stype t)
{

	if (stype_unsigned(t))
		return ("CBL_K_UINT");
	if (stype_signed(t))
		return ("CBL_K_INT");
	switch (t) {
	case T_BOOL: return ("CBL_K_BOOL");
	case T_FLAG: return ("CBL_K_FLAG");
	case T_TEXT: return ("CBL_K_TEXT");
	case T_BYTES: return ("CBL_K_BYTES");
	case T_FLOAT: return ("CBL_K_FLOAT");
	default: return ("CBL_K_NEST");
	}
}

static char *
fmt_u64(uint64_t v)
{

	if (v == UINT64_MAX)
		return (xstrdup("UINT64_MAX"));
	return (xasprintf("UINT64_C(%" PRIu64 ")", v));
}

static char *
fmt_s64(int64_t v)
{

	if (v == INT64_MIN)
		return (xstrdup("INT64_MIN"));
	if (v == INT64_MAX)
		return (xstrdup("INT64_MAX"));
	return (xasprintf("INT64_C(%" PRId64 ")", v));
}

/* Put one value; "val" is a C expression, "key" an id or CBL_ELEM. */
static void
emit_put_value(struct buf *b, const struct gctx *g, const struct sattr *a,
    const char *key, const char *val, bool elem, const char *ind)
{

	if (stype_unsigned(a->type))
		buf_printf(b, "%s(void)cbl_put_uint(msg, %s, (uint64_t)%s);\n",
		    ind, key, val);
	else if (stype_signed(a->type))
		buf_printf(b, "%s(void)cbl_put_int(msg, %s, (int64_t)%s);\n",
		    ind, key, val);
	else if (a->type == T_BOOL || (a->type == T_FLAG && elem))
		buf_printf(b, "%s(void)cbl_put_bool(msg, %s, %s);\n", ind, key,
		    val);
	else if (a->type == T_FLAG)
		buf_printf(b, "%s(void)cbl_put_flag(msg, %s);\n", ind, key);
	else if (a->type == T_FLOAT)
		buf_printf(b, "%s(void)cbl_put_double(msg, %s, %s);\n", ind,
		    key, val);
	else if (a->type == T_TEXT)
		buf_printf(b, "%s(void)cbl_put_str(msg, %s, %s);\n", ind, key,
		    val);
	else if (a->type == T_BYTES)
		buf_printf(b, "%s(void)cbl_put_bytes(msg, %s, %s.p, %s.len);\n",
		    ind, key, val, val);
	else {
		buf_printf(b, "%s(void)cbl_nest_start(msg, %s);\n", ind, key);
		buf_printf(b, "%s(void)%s_%s_put_fields(msg, %s%s);\n", ind,
		    g->P, a->nested->cname, elem ? "&" : "", val);
		buf_printf(b, "%s(void)cbl_nest_end(msg);\n", ind);
	}
}

/* Struct field declaration. */
static void
emit_field(struct buf *b, const struct gctx *g, const struct sattr *a)
{
	char tmp[160];

	emit_doc(b, a->doc, "\t");
	if (a->multi) {
		buf_printf(b, "\tstruct {\n\t\tsize_t\t\t n;\n");
		if (a->type == T_TEXT)
			buf_puts(b, "\t\tconst char *const\t*v;\n");
		else
			buf_printf(b, "\t\tconst %s\t*v;\n", elem_ctype(g, a,
			    tmp, sizeof(tmp)));
		buf_printf(b, "\t}\t\t\t %s;\n", a->cname);
		return;
	}
	switch (a->type) {
	case T_NEST:
		buf_printf(b, "\tconst struct %s_%s\t*%s;\n", g->P,
		    a->nested->cname, a->cname);
		break;
	case T_TEXT:
		buf_printf(b, "\tconst char\t\t*%s;\n", a->cname);
		break;
	case T_BYTES:
		buf_printf(b, "\tstruct cbl_bytes\t %s;\n", a->cname);
		break;
	case T_FLAG:
		buf_printf(b, "\tbool\t\t\t %s;\n", a->cname);
		break;
	default:
		buf_printf(b, "\tbool\t\t\t has_%s;\n", a->cname);
		buf_printf(b, "\t%s\t\t %s;\n", stype_ctype(a->type),
		    a->cname);
		break;
	}
}

static void
emit_struct(struct buf *b, const struct gctx *g, const struct obj *o)
{

	buf_printf(b, "struct %s_%s {\n", g->P, o->tag);
	for (size_t i = 0; i < o->n; i++)
		emit_field(b, g, o->a[i]);
	if (o->has_msg)
		buf_printf(b, "\tcbl_msg\t\t\t*_msg;\t/* owns the memory */\n");
	buf_puts(b, "};\n\n");
}

static void
emit_obj_protos(struct buf *b, const struct gctx *g, const struct obj *o)
{

	buf_printf(b, "extern const struct cbl_policy_set %s_%s_policy;\n",
	    g->P, o->tag);
	buf_printf(b, "extern const struct cbl_parser %s_%s_parser;\n", g->P,
	    o->tag);
	buf_printf(b, "int\t%s_%s_parse(cbl_msg *msg, const cbl_attr *map,\n"
	    "\t    struct %s_%s *out);\n", g->P, o->tag, g->P, o->tag);
	buf_printf(b, "int\t%s_%s_put_fields(cbl_msg *msg,\n"
	    "\t    const struct %s_%s *in);\n", g->P, o->tag, g->P, o->tag);
}

/* Sorted-by-id view of an object's attributes. */
static size_t *
sorted(const struct obj *o)
{
	size_t *ix = xcalloc(o->n, sizeof(*ix)), t;

	for (size_t i = 0; i < o->n; i++)
		ix[i] = i;
	for (size_t i = 1; i < o->n; i++)
		for (size_t j = i; j > 0 &&
		    o->a[ix[j - 1]]->value > o->a[ix[j]]->value; j--) {
			t = ix[j];
			ix[j] = ix[j - 1];
			ix[j - 1] = t;
		}
	return (ix);
}

static void
emit_policy_entry(struct buf *b, const struct gctx *g, const struct sattr *a,
    bool required)
{
	char *lo, *hi;
	bool range = false, mask = false;

	buf_printf(b, "\t{ .type = %u, .kind = %s", (unsigned)a->value,
	    kind(a->type));
	if (stype_unsigned(a->type) && a->en != NULL &&
	    a->en->type == D_FLAGS)
		mask = true;
	else if (stype_unsigned(a->type) || stype_signed(a->type))
		range = true;
	else if ((a->type == T_TEXT || a->type == T_BYTES) &&
	    (a->min_len.set || a->max_len.set || a->exact_len.set))
		range = true;
	buf_printf(b, ", .flags = 0%s%s%s%s",
	    required ? " | CBL_PF_REQUIRED" : "",
	    a->multi ? " | CBL_PF_MULTI" : "",
	    range ? " | CBL_PF_RANGE" : "",
	    mask ? " | CBL_PF_MASK" : "");
	if (a->multi && (a->min_count.set || a->max_count.set))
		buf_printf(b, ",\n\t  .min_count = %" PRIu64
		    ", .max_count = %" PRIu64, a->min_count.set ?
		    a->min_count.mag : 0, a->max_count.set ? a->max_count.mag :
		    0);
	if (mask) {
		uint64_t m = 0;

		for (size_t i = 0; i < a->en->nentries; i++)
			m |= UINT64_C(1) << a->en->entries[i].value;
		hi = fmt_u64(m);
		buf_printf(b, ",\n\t  .u = { 0, %s }", hi);
		free(hi);
	} else if (stype_unsigned(a->type)) {
		lo = fmt_u64(a->min.set ? snum_u(&a->min) : 0);
		hi = fmt_u64(a->max.set ? snum_u(&a->max) :
		    stype_umax(a->type));
		buf_printf(b, ",\n\t  .u = { %s, %s }", lo, hi);
		free(lo);
		free(hi);
	} else if (stype_signed(a->type)) {
		lo = fmt_s64(a->min.set ? snum_s(&a->min) :
		    stype_smin(a->type));
		hi = fmt_s64(a->max.set ? snum_s(&a->max) :
		    stype_smax(a->type));
		buf_printf(b, ",\n\t  .i = { %s, %s }", lo, hi);
		free(lo);
		free(hi);
	} else if (range) {
		uint64_t l = 0, h = UINT32_MAX;

		if (a->exact_len.set)
			l = h = a->exact_len.mag;
		if (a->min_len.set)
			l = a->min_len.mag;
		if (a->max_len.set)
			h = a->max_len.mag;
		buf_printf(b, ",\n\t  .len = { %" PRIu64 ", %" PRIu64 " }", l,
		    h);
	}
	if (a->type == T_NEST)
		buf_printf(b, ",\n\t  .nested = &%s_%s_policy", g->P,
		    a->nested->cname);
	if (a->en != NULL && a->en->type == D_ENUM)
		buf_printf(b, ",\n\t  .values = &%s_%s_values", g->P,
		    a->en->cname);
	buf_puts(b, " },\n");
}

/* Callbacks, tables and functions of one object. */
static void
emit_obj_impl(struct buf *b, const struct gctx *g, const struct obj *o)
{
	size_t *ix = sorted(o);
	char tmp[160], *v;

	/* Parser callbacks for fields that need more than a stock one. */
	for (size_t i = 0; i < o->n; i++) {
		const struct sattr *a = o->a[i];

		if (!a->multi && (a->type == T_TEXT || a->type == T_BYTES ||
		    a->type == T_FLAG))
			continue;	/* stock callback + offsetof */
		buf_printf(b, "static int\n%s_%s_cb_%s(cbl_msg *msg, "
		    "const cbl_attr *a,\n    const void *arg __unused, "
		    "void *target)\n{\n", g->P, o->tag, a->cname);
		buf_printf(b, "\tstruct %s_%s *s = target;\n", g->P, o->tag);
		if (a->multi) {
			buf_printf(b, "\t%s%s*v = NULL;\n",
			    elem_ctype(g, a, tmp, sizeof(tmp)),
			    a->type == T_TEXT ? "" : " ");
			buf_puts(b, "\tsize_t n;\n\tint error;\n\n");
			buf_puts(b, "\tif (cbl_attr_kind(a) != CBL_K_ARRAY)\n"
			    "\t\treturn (EINVAL);\n");
			buf_puts(b, "\tif ((n = cbl_attr_count(a)) > 0 &&\n"
			    "\t    (v = cbl_msg_alloc(msg, n * sizeof(*v))) == "
			    "NULL)\n\t\treturn (ENOMEM);\n");
			buf_puts(b, "\tfor (size_t i = 0; i < n; i++) {\n");
			if (a->type == T_NEST)
				buf_printf(b, "\t\terror = %s_%s_parse(msg, "
				    "cbl_attr_index(a, i), &v[i]);\n", g->P,
				    a->nested->cname);
			else
				buf_printf(b, "\t\terror = %s(msg, "
				    "cbl_attr_index(a, i), NULL, &v[i]);\n",
				    a->type == T_FLAG ? "cbl_get_bool" :
				    getter(a->type));
			buf_puts(b, "\t\tif (error != 0)\n\t\t\treturn (error);"
			    "\n\t}\n");
			buf_printf(b, "\ts->%s.n = n;\n\ts->%s.v = v;\n"
			    "\treturn (0);\n}\n\n", a->cname, a->cname);
			continue;
		}
		if (a->type == T_NEST) {
			buf_printf(b, "\tstruct %s_%s *p;\n\tint error;\n\n",
			    g->P, a->nested->cname);
			buf_puts(b, "\tif ((p = cbl_msg_alloc(msg, "
			    "sizeof(*p))) == NULL)\n\t\treturn (ENOMEM);\n");
			buf_printf(b, "\tif ((error = %s_%s_parse(msg, a, p)) "
			    "!= 0)\n\t\treturn (error);\n", g->P,
			    a->nested->cname);
			buf_printf(b, "\ts->%s = p;\n\treturn (0);\n}\n\n",
			    a->cname);
			continue;
		}
		buf_puts(b, "\tint error;\n\n");
		buf_printf(b, "\tif ((error = %s(msg, a, NULL, &s->%s)) != 0)\n"
		    "\t\treturn (error);\n", getter(a->type), a->cname);
		buf_printf(b, "\ts->has_%s = true;\n\treturn (0);\n}\n\n",
		    a->cname);
	}

	/* Parser table, sorted by type. */
	buf_printf(b, "static const struct cbl_attr_parser %s_%s_np[] = {\n",
	    g->P, o->tag);
	for (size_t k = 0; k < o->n; k++) {
		const struct sattr *a = o->a[ix[k]];

		if (!a->multi && (a->type == T_TEXT || a->type == T_BYTES ||
		    a->type == T_FLAG))
			buf_printf(b, "\t{ .type = %u, .off = offsetof(struct "
			    "%s_%s, %s),\n\t  .cb = %s },\n",
			    (unsigned)a->value, g->P, o->tag, a->cname,
			    getter(a->type));
		else
			buf_printf(b, "\t{ .type = %u, .off = 0, .cb = "
			    "%s_%s_cb_%s },\n", (unsigned)a->value, g->P,
			    o->tag, a->cname);
	}
	buf_puts(b, "};\n\n");
	buf_printf(b, "const struct cbl_parser %s_%s_parser = {\n"
	    "\t.out_size = sizeof(struct %s_%s),\n"
	    "\t.np_size = nitems(%s_%s_np),\n\t.np = %s_%s_np,\n};\n\n",
	    g->P, o->tag, g->P, o->tag, g->P, o->tag, g->P, o->tag);

	/* Policy table. */
	buf_printf(b, "static const struct cbl_policy %s_%s_pol[] = {\n", g->P,
	    o->tag);
	for (size_t k = 0; k < o->n; k++)
		emit_policy_entry(b, g, o->a[ix[k]], o->req[ix[k]]);
	buf_puts(b, "};\n\n");
	buf_printf(b, "const struct cbl_policy_set %s_%s_policy = {\n"
	    "\t.p = %s_%s_pol,\n\t.n = nitems(%s_%s_pol),\n};\n\n", g->P,
	    o->tag, g->P, o->tag, g->P, o->tag);

	/* Parse. */
	buf_printf(b, "int\n%s_%s_parse(cbl_msg *msg, const cbl_attr *map,\n"
	    "    struct %s_%s *out)\n{\n\n\tmemset(out, 0, sizeof(*out));\n"
	    "\treturn (cbl_parse_nest(msg, map, &%s_%s_parser, out));\n}\n\n",
	    g->P, o->tag, g->P, o->tag, g->P, o->tag);

	/* Encode. */
	buf_printf(b, "int\n%s_%s_put_fields(cbl_msg *msg, "
	    "const struct %s_%s *in)\n{\n\n", g->P, o->tag, g->P, o->tag);
	for (size_t i = 0; i < o->n; i++) {
		const struct sattr *a = o->a[i];
		char *key = xasprintf("%u", (unsigned)a->value);

		if (a->multi) {
			buf_printf(b, "\tif (in->%s.n > 0) {\n", a->cname);
			buf_printf(b, "\t\t(void)cbl_array_start(msg, %s);\n",
			    key);
			buf_printf(b, "\t\tfor (size_t i = 0; i < in->%s.n; "
			    "i++) {\n", a->cname);
			v = xasprintf("in->%s.v[i]", a->cname);
			emit_put_value(b, g, a, "CBL_ELEM", v, true, "\t\t\t");
			free(v);
			buf_puts(b, "\t\t}\n\t\t(void)cbl_array_end(msg);\n"
			    "\t}\n");
		} else {
			if (stype_scalar(a->type))
				buf_printf(b, "\tif (in->has_%s)\n", a->cname);
			else if (a->type == T_FLAG)
				buf_printf(b, "\tif (in->%s)\n", a->cname);
			else if (a->type == T_BYTES)
				buf_printf(b, "\tif (in->%s.p != NULL)\n",
				    a->cname);
			else
				buf_printf(b, "\tif (in->%s != NULL)%s\n",
				    a->cname, a->type == T_NEST ? " {" : "");
			v = xasprintf("in->%s", a->cname);
			emit_put_value(b, g, a, key, v, false, "\t\t");
			free(v);
			if (a->type == T_NEST)
				buf_puts(b, "\t}\n");
		}
		free(key);
	}
	buf_puts(b, "\treturn (cbl_msg_error(msg));\n}\n\n");
	free(ix);
}

/* Build the object list: every set, then each op's lists. */
static void
add_obj(struct gctx *g, char *tag, const struct sset *set, size_t n,
    const struct sattr **a, bool *req, bool has_msg)
{

	g->objs = xreallocarray(g->objs, g->nobjs + 1, sizeof(*g->objs));
	g->objs[g->nobjs].tag = tag;
	g->objs[g->nobjs].set = set;
	g->objs[g->nobjs].n = n;
	g->objs[g->nobjs].a = a;
	g->objs[g->nobjs].req = req;
	g->objs[g->nobjs].has_msg = has_msg;
	g->nobjs++;
}

static void
add_list(struct gctx *g, const struct sop *op, const struct slist *l,
    const char *sfx, bool has_msg)
{
	const struct sattr **a;
	bool *req;

	if (!l->present)
		return;
	a = xcalloc(l->n, sizeof(*a));
	req = xcalloc(l->n, sizeof(*req));
	for (size_t i = 0; i < l->n; i++) {
		a[i] = l->attrs[i];
		req[i] = l->required[i];
	}
	add_obj(g, xasprintf("%s_%s", op->cname, sfx), op->set, l->n, a, req,
	    has_msg);
}

static void
build_objs(struct gctx *g)
{
	const struct spec *s = g->s;

	for (size_t i = 0; i < s->nsets; i++) {
		const struct sset *set = &s->sets[i];
		const struct sattr **a = xcalloc(set->nattrs, sizeof(*a));
		bool *req = xcalloc(set->nattrs, sizeof(*req));

		for (size_t k = 0; k < set->nattrs; k++) {
			a[k] = &set->attrs[k];
			req[k] = set->attrs[k].required;
		}
		add_obj(g, xstrdup(set->cname), set, set->nattrs, a, req,
		    false);
	}
	for (size_t i = 0; i < s->nops; i++) {
		const struct sop *op = &s->ops[i];

		add_list(g, op, &op->do_req, "req", false);
		add_list(g, op, &op->do_rsp, "rsp", true);
		add_list(g, op, &op->dump_req, "dump_req", false);
		add_list(g, op, &op->dump_rsp, "dump_rsp", false);
		add_list(g, op, &op->event, "ntf", false);
	}
}

static void
free_objs(struct gctx *g)
{

	for (size_t i = 0; i < g->nobjs; i++) {
		free(g->objs[i].tag);
		free(g->objs[i].a);
		free(g->objs[i].req);
	}
	free(g->objs);
}

static void
banner(struct buf *b, const struct gctx *g)
{

	buf_printf(b, "/*\n * Generated by cblink-gen %s from %s.  "
	    "Do not edit.\n */\n\n", CBLGEN_VERSION, g->s->file);
}

/* Per-attribute builder signature (without the return type). */
static void
builder_sig(struct buf *b, const struct gctx *g, const struct sset *set,
    const struct sattr *a, bool proto)
{
	char *fn = attr_put(g, set, a), tmp[160];

	buf_printf(b, proto ? "int\t%s(cbl_msg *msg" : "int\n%s(cbl_msg *msg",
	    fn);
	free(fn);
	if (a->multi && a->type == T_TEXT)
		buf_puts(b, ", const char *const *v, size_t n)");
	else if (a->multi)
		buf_printf(b, ", const %s *v, size_t n)",
		    elem_ctype(g, a, tmp, sizeof(tmp)));
	else if (a->type == T_FLAG)
		buf_puts(b, ")");
	else if (a->type == T_BYTES)
		buf_puts(b, ", const void *p, size_t len)");
	else if (a->type == T_TEXT)
		buf_puts(b, ", const char *v)");
	else if (a->type == T_NEST)
		buf_printf(b, ", const struct %s_%s *v)", g->P,
		    a->nested->cname);
	else
		buf_printf(b, ", %s v)", stype_ctype(a->type));
}

static bool
grp_has_events(const struct spec *s, const struct sgrp *gr)
{

	for (size_t i = 0; i < s->nops; i++)
		if (s->ops[i].mcgrp == gr)
			return (true);
	return (false);
}

static bool
op_is_cmd(const struct sop *op)
{

	return (op->has_do || op->has_dump || op->stream != NULL);
}

static const struct sop *
stream_op(const struct sstream *st)
{

	return (st->open);
}

/* Header. */
static void
gen_header(struct buf *b, struct gctx *g, const char *base)
{
	const struct spec *s = g->s;
	char *guard = upper(base);

	for (char *p = guard; *p != '\0'; p++)
		if (!((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')))
			*p = '_';
	banner(b, g);
	buf_printf(b, "#ifndef _%s_H_\n#define\t_%s_H_\n\n", guard, guard);
	buf_puts(b, "#include <cblink.h>\n\n");
	emit_doc(b, s->doc, "");
	if (s->doc != NULL)
		buf_puts(b, "\n");
	buf_printf(b, "#define\t%s_FAMILY_NAME\t\"%s\"\n", g->PU, s->name);
	buf_printf(b, "#define\t%s_FAMILY_VERSION\t%" PRIu32 "\n", g->PU,
	    s->version);
	if (s->has_fixed_id)
		buf_printf(b, "#define\t%s_FAMILY_ID\t%" PRIu32 "\n", g->PU,
		    s->fixed_id);
	buf_puts(b, "\n");

	/* Definitions. */
	for (size_t i = 0; i < s->ndefs; i++) {
		const struct sdef *d = &s->defs[i];
		char *du = upper(d->cname);

		emit_doc(b, d->doc, "");
		if (d->type == D_CONST) {
			if (d->value.neg)
				buf_printf(b, "#define\t%s_%s\t(-%" PRIu64
				    ")\n\n", g->PU, du, d->value.mag);
			else
				buf_printf(b, "#define\t%s_%s\t%" PRIu64 "\n\n",
				    g->PU, du, d->value.mag);
		} else {
			for (size_t k = 0; k < d->nentries; k++) {
				char *eu = upper(d->entries[k].cname);

				emit_doc(b, d->entries[k].doc, "");
				if (d->type == D_ENUM)
					buf_printf(b, "#define\t%s_%s_%s\t%"
					    PRIu64 "\n", g->PU, du, eu,
					    d->entries[k].value);
				else
					buf_printf(b, "#define\t%s_%s_%s\t"
					    "(UINT64_C(1) << %" PRIu64 ")\n",
					    g->PU, du, eu,
					    d->entries[k].value);
				free(eu);
			}
			buf_printf(b, "extern const struct cbl_enum %s_%s_"
			    "values;\n\n", g->P, d->cname);
		}
		free(du);
	}

	/* Attribute ids. */
	for (size_t i = 0; i < s->nsets; i++) {
		const struct sset *set = &s->sets[i];
		uint32_t max = 0;
		char *mx, *su = upper(set->cname);

		emit_doc(b, set->doc, "");
		buf_printf(b, "enum %s_%s_attrs {\n", g->P, set->cname);
		for (size_t k = 0; k < set->nattrs; k++) {
			char *id = attr_id(g, set, &set->attrs[k]);

			buf_printf(b, "\t%s = %" PRIu32 ",\n", id,
			    set->attrs[k].value);
			if (set->attrs[k].value > max)
				max = set->attrs[k].value;
			free(id);
		}
		mx = is_family_set(g, set) ? xasprintf("%s_A_MAX", g->PU) :
		    xasprintf("%s_%s_A_MAX", g->PU, su);
		buf_printf(b, "\t%s = %" PRIu32 ",\n};\n\n", mx, max);
		free(mx);
		free(su);
	}

	/* Commands and groups. */
	buf_printf(b, "enum %s_cmds {\n", g->P);
	for (size_t i = 0; i < s->nops; i++) {
		char *id = cmd_id(g, &s->ops[i]);

		buf_printf(b, "\t%s = %" PRIu32 ",\n", id, s->ops[i].value);
		free(id);
	}
	buf_puts(b, "};\n\n");
	if (s->ngrps > 0) {
		buf_printf(b, "enum %s_mcgrps {\n", g->P);
		for (size_t i = 0; i < s->ngrps; i++) {
			char *id = grp_id(g, &s->grps[i]);

			buf_printf(b, "\t%s = %zu,\n", id, i);
			free(id);
		}
		buf_puts(b, "};\n\n");
	}
	buf_printf(b, "#define\t%s_MCGRP_COUNT\t%zu\n\n", g->PU, s->ngrps);

	/* Structs. */
	for (size_t i = 0; i < s->nsets; i++)
		buf_printf(b, "struct %s_%s;\n", g->P, s->sets[i].cname);
	buf_puts(b, "\n");
	for (size_t i = 0; i < g->nobjs; i++)
		emit_struct(b, g, &g->objs[i]);

	/* Tables, parse and encode functions. */
	for (size_t i = 0; i < g->nobjs; i++)
		emit_obj_protos(b, g, &g->objs[i]);
	buf_puts(b, "\n/* Per-attribute builders. */\n");
	for (size_t i = 0; i < s->nsets; i++)
		for (size_t k = 0; k < s->sets[i].nattrs; k++) {
			builder_sig(b, g, &s->sets[i], &s->sets[i].attrs[k],
			    true);
			buf_puts(b, ";\n");
		}

	/* Client. */
	buf_puts(b, "\n/* Client side (generated into *_client.c). */\n");
	buf_printf(b, "struct %s_client {\n\tcbl_conn\t*conn;\n"
	    "\tuint16_t\t family;\n\tuint32_t\t version;\n"
	    "\tuint32_t\t groups[%s_MCGRP_COUNT > 0 ? %s_MCGRP_COUNT : 1];\n"
	    "\tcbl_msg\t\t*err;\t/* ERROR of the last failed call */\n};\n\n",
	    g->P, g->PU, g->PU);
	buf_printf(b, "int\t%s_client_init(struct %s_client *cl, "
	    "cbl_conn *conn);\nvoid\t%s_client_fini(struct %s_client *cl);\n",
	    g->P, g->P, g->P, g->P);
	if (!s->has_fixed_id)
		buf_printf(b, "int\t%s_client_init_info(struct %s_client *cl, "
		    "cbl_conn *conn,\n\t    const cbl_family_info *info);\n",
		    g->P, g->P);
	for (size_t i = 0; i < s->nops; i++) {
		const struct sop *op = &s->ops[i];

		if (op->has_do && op->stream == NULL) {
			buf_printf(b, "int\t%s_%s(struct %s_client *cl", g->P,
			    op->cname, g->P);
			if (op->do_req.present)
				buf_printf(b, ",\n\t    const struct %s_%s_req "
				    "*req", g->P, op->cname);
			if (op->do_rsp.present)
				buf_printf(b, ",\n\t    struct %s_%s_rsp "
				    "**rspp", g->P, op->cname);
			buf_puts(b, ");\n");
			if (op->do_rsp.present)
				buf_printf(b, "void\t%s_%s_rsp_free(struct "
				    "%s_%s_rsp *rsp);\n", g->P, op->cname, g->P,
				    op->cname);
			/* The same request from a loop callback. */
			buf_printf(b, "typedef void\t%s_%s_cb(struct %s_client "
			    "*cl, int error,", g->P, op->cname, g->P);
			if (op->do_rsp.present)
				buf_printf(b, "\n\t    struct %s_%s_rsp *rsp,",
				    g->P, op->cname);
			buf_puts(b, " void *arg);\n");
			buf_printf(b, "int\t%s_%s_async(struct %s_client *cl",
			    g->P, op->cname, g->P);
			if (op->do_req.present)
				buf_printf(b, ",\n\t    const struct %s_%s_req "
				    "*req", g->P, op->cname);
			buf_printf(b, ",\n\t    %s_%s_cb *cb, void *arg);\n",
			    g->P, op->cname);
		}
		if (op->has_dump) {
			buf_printf(b, "int\t%s_%s_dump(struct %s_client *cl",
			    g->P, op->cname, g->P);
			if (op->dump_req.present)
				buf_printf(b, ",\n\t    const struct %s_%s_"
				    "dump_req *req", g->P, op->cname);
			buf_puts(b, ", cbl_dump **dp);\n");
			if (op->dump_rsp.present)
				buf_printf(b, "int\t%s_%s_dump_next(cbl_dump *d"
				    ",\n\t    struct %s_%s_dump_rsp "
				    "**itemp);\n", g->P, op->cname, g->P,
				    op->cname);
		}
	}
	for (size_t i = 0; i < s->ngrps; i++) {
		const struct sgrp *gr = &s->grps[i];

		buf_printf(b, "\nstruct %s_%s_handlers {\n", g->P, gr->cname);
		for (size_t k = 0; k < s->nops; k++)
			if (s->ops[k].mcgrp == gr)
				buf_printf(b, "\tvoid\t(*%s)(const struct "
				    "%s_%s_ntf *ntf, void *arg);\n",
				    s->ops[k].cname, g->P, s->ops[k].cname);
		if (!grp_has_events(s, gr))
			buf_puts(b,
			    "\tint\t_reserved;\t\t/* no notifications */\n");
		buf_puts(b, "};\n\n");
		buf_printf(b, "int\t%s_%s_subscribe(struct %s_client *cl,\n"
		    "\t    const struct %s_%s_handlers *h, void *arg, "
		    "cbl_sub **subp);\n", g->P, gr->cname, g->P, g->P,
		    gr->cname);
		buf_printf(b, "int\t%s_%s_unsubscribe(cbl_sub *sub);\n", g->P,
		    gr->cname);
	}
	for (size_t i = 0; i < s->nstreams; i++) {
		const struct sstream *st = &s->streams[i];
		const struct sop *op = stream_op(st);

		buf_printf(b, "\nstruct %s_%s_cbs {\n", g->P, st->cname);
		if (op->do_rsp.present)
			buf_printf(b, "\tvoid\t(*on_open)(cbl_stream *s, "
			    "const struct %s_%s_rsp *accept,\n\t\t    int "
			    "error, void *arg);\n", g->P, op->cname);
		else
			buf_puts(b, "\tvoid\t(*on_open)(cbl_stream *s, int "
			    "error, void *arg);\n");
		if (st->dir != DIR_UP)
			buf_printf(b, "\tvoid\t(*on_data)(cbl_stream *s, "
			    "const struct %s_%s *data,\n\t\t    void *arg);\n",
			    g->P, st->down->cname);
		buf_puts(b, "\tvoid\t(*on_hclose)(cbl_stream *s, void *arg);\n"
		    "\tvoid\t(*on_close)(cbl_stream *s, int code, const char "
		    "*text,\n\t\t    void *arg);\n\tvoid\t(*on_writable)"
		    "(cbl_stream *s, size_t credit, void *arg);\n};\n\n");
		buf_printf(b, "int\t%s_%s_open(struct %s_client *cl", g->P,
		    st->cname, g->P);
		if (op->do_req.present)
			buf_printf(b, ",\n\t    const struct %s_%s_req *req",
			    g->P, op->cname);
		buf_printf(b, ",\n\t    const struct %s_%s_cbs *cbs, void *arg"
		    ", cbl_stream **sp);\n", g->P, st->cname);
		if (st->dir != DIR_DOWN)
			buf_printf(b, "int\t%s_%s_send(cbl_stream *s, "
			    "const struct %s_%s *data);\n", g->P, st->cname,
			    g->P, st->up->cname);
	}

	/* Server. */
	buf_puts(b, "\n/* Server side (generated into *_server.c). */\n");
	buf_printf(b, "extern const struct cbl_family_def %s_family_def;\n",
	    g->P);
	if (!s->has_fixed_id)
		buf_printf(b, "int\t%s_register(cbl_ctx *ctx, void *arg, "
		    "cbl_family **famp);\n", g->P);
	buf_puts(b, "\n/* Handlers the server implements. */\n");
	for (size_t i = 0; i < s->nops; i++) {
		const struct sop *op = &s->ops[i];

		if (op->has_do && op->stream == NULL) {
			buf_printf(b, "int\t%s_%s_doit(cbl_req *req", g->P,
			    op->cname);
			if (op->do_req.present)
				buf_printf(b, ",\n\t    const struct %s_%s_req "
				    "*rq", g->P, op->cname);
			buf_puts(b, ", void *arg);\n");
		}
		if (op->has_dump) {
			buf_printf(b, "int\t%s_%s_dumpit(cbl_req *req", g->P,
			    op->cname);
			if (op->dump_req.present)
				buf_printf(b, ",\n\t    const struct %s_%s_"
				    "dump_req *rq", g->P, op->cname);
			buf_puts(b, ",\n\t    struct cbl_dump_state *st, "
			    "void *arg);\n");
		}
	}
	for (size_t i = 0; i < s->nstreams; i++) {
		const struct sstream *st = &s->streams[i];
		const struct sop *op = stream_op(st);

		buf_printf(b, "int\t%s_%s_stream_open(cbl_req *req", g->P,
		    st->cname);
		if (op->do_req.present)
			buf_printf(b, ",\n\t    const struct %s_%s_req *rq",
			    g->P, op->cname);
		buf_puts(b, ", cbl_stream *s, void *arg);\n");
	}
	buf_puts(b, "\n/* Server helpers. */\n");
	for (size_t i = 0; i < s->nops; i++) {
		const struct sop *op = &s->ops[i];

		if (op->do_rsp.present && op->stream == NULL)
			buf_printf(b, "int\t%s_%s_reply(cbl_req *req, "
			    "const struct %s_%s_rsp *rsp);\n", g->P, op->cname,
			    g->P, op->cname);
		if (op->dump_rsp.present)
			buf_printf(b, "int\t%s_%s_dump_reply(cbl_req *req,\n"
			    "\t    const struct %s_%s_dump_rsp *rsp);\n", g->P,
			    op->cname, g->P, op->cname);
		if (op->has_event)
			buf_printf(b, "int\t%s_%s_notify(cbl_family *fam, "
			    "const struct %s_%s_ntf *ntf);\n", g->P, op->cname,
			    g->P, op->cname);
	}
	for (size_t i = 0; i < s->nstreams; i++) {
		const struct sstream *st = &s->streams[i];
		const struct sop *op = stream_op(st);

		buf_printf(b, "\nstruct %s_%s_server_cbs {\n", g->P, st->cname);
		if (st->dir != DIR_DOWN)
			buf_printf(b, "\tvoid\t(*on_data)(cbl_stream *s, "
			    "const struct %s_%s *data,\n\t\t    void *arg);\n",
			    g->P, st->up->cname);
		buf_puts(b, "\tvoid\t(*on_hclose)(cbl_stream *s, void *arg);\n"
		    "\tvoid\t(*on_close)(cbl_stream *s, int code, const char "
		    "*text,\n\t\t    void *arg);\n\tvoid\t(*on_writable)"
		    "(cbl_stream *s, size_t credit, void *arg);\n};\n\n");
		buf_printf(b, "int\t%s_%s_accept(cbl_stream *s", g->P,
		    st->cname);
		if (op->do_rsp.present)
			buf_printf(b, ",\n\t    const struct %s_%s_rsp *accept",
			    g->P, op->cname);
		buf_printf(b, ",\n\t    const struct %s_%s_server_cbs *cbs, "
		    "void *arg);\n", g->P, st->cname);
		if (st->dir != DIR_UP)
			buf_printf(b, "int\t%s_%s_server_send(cbl_stream *s,\n"
			    "\t    const struct %s_%s *data);\n", g->P,
			    st->cname, g->P, st->down->cname);
	}
	buf_printf(b, "\n#endif /* !_%s_H_ */\n", guard);
	free(guard);
}

/* Common part: tables, parse/encode, builders. */
static void
gen_common(struct buf *b, struct gctx *g, const char *base)
{
	const struct spec *s = g->s;

	banner(b, g);
	buf_puts(b, "#include <sys/param.h>\n\n#include <errno.h>\n"
	    "#include <stddef.h>\n#include <string.h>\n\n");
	buf_printf(b, "#include \"%s.h\"\n\n", base);
	buf_printf(b, "_Static_assert(CBLINK_VERSION_MAJOR == %d,\n"
	    "    \"generated by cblink-gen %s for libcblink %d.x\");\n\n",
	    CBLGEN_LIB_MAJOR, CBLGEN_VERSION, CBLGEN_LIB_MAJOR);
	for (size_t i = 0; i < s->ndefs; i++) {
		const struct sdef *d = &s->defs[i];

		if (d->type == D_CONST)
			continue;
		buf_printf(b, "static const uint64_t %s_%s_vals[] = {\n",
		    g->P, d->cname);
		for (size_t k = 0; k < d->nentries; k++)
			buf_printf(b, "\tUINT64_C(%" PRIu64 "),\n", d->type ==
			    D_ENUM ? d->entries[k].value : UINT64_C(1) <<
			    d->entries[k].value);
		buf_printf(b, "};\n\nconst struct cbl_enum %s_%s_values = {\n"
		    "\t.v = %s_%s_vals,\n\t.n = nitems(%s_%s_vals),\n};\n\n",
		    g->P, d->cname, g->P, d->cname, g->P, d->cname);
	}
	for (size_t i = 0; i < g->nobjs; i++)
		emit_obj_impl(b, g, &g->objs[i]);

	/* Per-attribute builders. */
	for (size_t i = 0; i < s->nsets; i++) {
		const struct sset *set = &s->sets[i];

		for (size_t k = 0; k < set->nattrs; k++) {
			const struct sattr *a = &set->attrs[k];
			char *key = attr_id(g, set, a);

			builder_sig(b, g, set, a, false);
			buf_puts(b, "\n{\n\n");
			if (a->multi) {
				buf_printf(b, "\t(void)cbl_array_start(msg, "
				    "%s);\n\tfor (size_t i = 0; i < n; i++)"
				    "%s\n", key, a->type == T_NEST ? " {" : "");
				emit_put_value(b, g, a, "CBL_ELEM", "v[i]",
				    true, "\t\t");
				if (a->type == T_NEST)
					buf_puts(b, "\t}\n");
				buf_puts(b, "\t(void)cbl_array_end(msg);\n");
			} else if (a->type == T_BYTES)
				buf_printf(b, "\t(void)cbl_put_bytes(msg, %s, "
				    "p, len);\n", key);
			else
				emit_put_value(b, g, a, key, "v", false, "\t");
			buf_puts(b, "\treturn (cbl_msg_error(msg));\n}\n\n");
			free(key);
		}
	}
}

/*
 * P_op_async(): the request of P_op() without waiting, for a client on a
 * loop.  The reply is kept (cbl_msg_ref()) until the final frame, then
 * parsed and handed to the callback, which owns it.
 */
static void
gen_client_async(struct buf *b, struct gctx *g, const struct sop *op,
    const char *cmd)
{
	const char *P = g->P, *on = op->cname;
	bool rsp = op->do_rsp.present;

	buf_printf(b, "struct %s__%s_call {\n\tstruct %s_client\t*cl;\n"
	    "\t%s_%s_cb\t\t*cb;\n\tvoid\t\t\t*arg;\n"
	    "\tcbl_msg\t\t\t*rsp;\t/* the reply, until the end */\n};\n\n",
	    P, on, P, P, on);
	buf_printf(b, "static void\n%s__%s_done(cbl_conn *conn __unused, "
	    "cbl_msg *m, bool final,\n    int error, void *arg)\n{\n"
	    "\tstruct %s__%s_call *c = arg;\n", P, on, P, on);
	if (rsp)
		buf_printf(b, "\tstruct %s_%s_rsp *out = NULL;\n", P, on);
	buf_puts(b, "\n\tif (!final) {\n\t\tif (c->rsp == NULL && m != NULL && "
	    "cbl_msg_ref(m) == 0)\n\t\t\tc->rsp = m;\n\t\treturn;\n\t}\n");
	buf_printf(b, "\t%s__err(c->cl, error != 0 && m != NULL && "
	    "cbl_msg_ref(m) == 0 ?\n\t    m : NULL);\n", P);
	if (rsp) {
		buf_puts(b, "\tif (error == 0 && c->rsp == NULL)\n"
		    "\t\terror = EPROTO;\n");
		buf_puts(b, "\tif (error == 0 && (out = cbl_msg_alloc(c->rsp, "
		    "sizeof(*out))) == NULL)\n\t\terror = ENOMEM;\n");
		buf_printf(b, "\tif (error == 0 && (error = %s_%s_rsp_parse("
		    "c->rsp,\n\t    cbl_msg_body(c->rsp), out)) == 0) {\n"
		    "\t\tout->_msg = c->rsp;\n\t\tc->rsp = NULL;\n\t}\n",
		    P, on);
		buf_puts(b, "\tcbl_msg_free(c->rsp);\n\tc->cb(c->cl, error, "
		    "error == 0 ? out : NULL, c->arg);\n");
	} else
		buf_puts(b, "\tcbl_msg_free(c->rsp);\n"
		    "\tc->cb(c->cl, error, c->arg);\n");
	buf_puts(b, "\tfree(c);\n}\n\n");

	buf_printf(b, "int\n%s_%s_async(struct %s_client *cl", P, on, P);
	if (op->do_req.present)
		buf_printf(b, ",\n    const struct %s_%s_req *req", P, on);
	buf_printf(b, ", %s_%s_cb *cb,\n    void *arg)\n{\n"
	    "\tstruct %s__%s_call *c;\n\tcbl_msg *msg;\n\tint error;\n\n",
	    P, on, P, on);
	buf_puts(b, "\tif (cb == NULL)\n\t\treturn (EINVAL);\n");
	buf_printf(b, "\tif ((error = cbl_msg_new(cbl_conn_ctx(cl->conn), "
	    "cl->family,\n\t    %s, 0, &msg)) != 0)\n\t\treturn (error);\n",
	    cmd);
	if (op->do_req.present)
		buf_printf(b, "\tif (req != NULL && (error = %s_%s_req_put_"
		    "fields(msg, req)) != 0) {\n\t\tcbl_msg_free(msg);\n"
		    "\t\treturn (error);\n\t}\n", P, on);
	buf_puts(b, "\tif ((c = calloc(1, sizeof(*c))) == NULL) {\n"
	    "\t\tcbl_msg_free(msg);\n\t\treturn (ENOMEM);\n\t}\n"
	    "\tc->cl = cl;\n\tc->cb = cb;\n\tc->arg = arg;\n");
	buf_printf(b, "\tif ((error = cbl_request_async(cl->conn, msg, "
	    "%s__%s_done, c)) != 0)\n\t\tfree(c);\n\treturn (error);\n}\n\n",
	    P, on);
}

/*
 * The body of a stream's on_data trampoline.  A payload that breaks its
 * set's policy or does not parse ends the stream: dropping it would leave
 * the two ends disagreeing about what was said.
 */
static void
emit_on_data(struct buf *b, const char *P, const char *set)
{

	buf_printf(b, "\tif (cbl_validate(cbl_msg_body(data), &%s_%s_policy, "
	    "NULL) != 0 ||\n\t    %s_%s_parse(data, cbl_msg_body(data), &d) "
	    "!= 0) {\n\t\t(void)cbl_stream_reset(s, EBADMSG);\n"
	    "\t\treturn;\n\t}\n\tif (c->cbs.on_data != NULL)\n"
	    "\t\tc->cbs.on_data(s, &d, c->arg);\n}\n\n", P, set, P, set);
}

static void
gen_client(struct buf *b, struct gctx *g, const char *base)
{
	const struct spec *s = g->s;
	bool calls = false;

	/* Only plain request wrappers keep the last error. */
	for (size_t i = 0; i < s->nops; i++)
		if (s->ops[i].has_do && s->ops[i].stream == NULL)
			calls = true;
	banner(b, g);
	buf_puts(b, "#include <errno.h>\n#include <stdlib.h>\n"
	    "#include <string.h>\n\n");
	buf_printf(b, "#include \"%s.h\"\n\n", base);
	if (calls)
		buf_printf(b, "static void\n%s__err(struct %s_client *cl, "
		    "cbl_msg *m)\n{\n\n\tcbl_msg_free(cl->err);\n\tcl->err = "
		    "m;\n}\n\n", g->P, g->P);

	/* init/fini. */
	buf_printf(b, "int\n%s_client_init(struct %s_client *cl, cbl_conn "
	    "*conn)\n{\n", g->P, g->P);
	if (s->has_fixed_id) {
		buf_printf(b, "\n\tmemset(cl, 0, sizeof(*cl));\n\tcl->conn = "
		    "conn;\n\tcl->family = %s_FAMILY_ID;\n\tcl->version = %s_"
		    "FAMILY_VERSION;\n", g->PU, g->PU);
		buf_printf(b, "\tfor (size_t i = 0; i < %s_MCGRP_COUNT; i++)\n"
		    "\t\tcl->groups[i] = (uint32_t)i + 1;\n"
		    "\treturn (0);\n}\n\n", g->PU);
	} else {
		buf_puts(b, "\tcbl_family_info *info;\n\tint error;\n\n");
		buf_printf(b, "\tif ((error = cbl_resolve(conn, %s_FAMILY_NAME,"
		    " &info)) != 0)\n\t\treturn (error);\n", g->PU);
		buf_printf(b, "\terror = %s_client_init_info(cl, conn, info);\n"
		    "\tcbl_family_info_free(info);\n\treturn (error);\n}\n\n",
		    g->P);
		/* From cbl_resolve_async(), for clients on a loop. */
		buf_printf(b, "int\n%s_client_init_info(struct %s_client *cl, "
		    "cbl_conn *conn,\n    const cbl_family_info *info)\n{\n\n",
		    g->P, g->P);
		buf_puts(b, "\tmemset(cl, 0, sizeof(*cl));\n"
		    "\tcl->conn = conn;\n");
		buf_puts(b, "\tcl->family = cbl_family_info_id(info);\n"
		    "\tcl->version = cbl_family_info_version(info);\n");
		for (size_t i = 0; i < s->ngrps; i++) {
			char *id = grp_id(g, &s->grps[i]);

			buf_printf(b, "\t(void)cbl_family_info_group(info, "
			    "\"%s\", &cl->groups[%s]);\n", s->grps[i].name, id);
			free(id);
		}
		buf_puts(b, "\treturn (0);\n}\n\n");
	}
	buf_printf(b, "void\n%s_client_fini(struct %s_client *cl)\n{\n\n"
	    "\tcbl_msg_free(cl->err);\n\tcl->err = NULL;\n}\n\n", g->P, g->P);

	for (size_t i = 0; i < s->nops; i++) {
		const struct sop *op = &s->ops[i];
		char *cmd = cmd_id(g, op);

		if (op->has_do && op->stream == NULL) {
			buf_printf(b, "int\n%s_%s(struct %s_client *cl", g->P,
			    op->cname, g->P);
			if (op->do_req.present)
				buf_printf(b, ",\n    const struct %s_%s_req "
				    "*req", g->P, op->cname);
			if (op->do_rsp.present)
				buf_printf(b, ",\n    struct %s_%s_rsp **rspp",
				    g->P, op->cname);
			buf_puts(b, ")\n{\n");
			if (op->do_rsp.present)
				buf_printf(b, "\tstruct %s_%s_rsp *out;\n",
				    g->P, op->cname);
			buf_puts(b, "\tcbl_msg *msg, *rsp = NULL;\n\tint error;"
			    "\n\n");
			if (op->do_rsp.present)
				buf_puts(b, "\t*rspp = NULL;\n");
			buf_printf(b, "\tif ((error = cbl_msg_new(cbl_conn_ctx("
			    "cl->conn), cl->family,\n\t    %s, 0, &msg)) "
			    "!= 0)\n\t\treturn (error);\n", cmd);
			if (op->do_req.present)
				buf_printf(b, "\tif (req != NULL && (error = "
				    "%s_%s_req_put_fields(msg, req)) != 0) {\n"
				    "\t\tcbl_msg_free(msg);\n\t\treturn "
				    "(error);\n\t}\n", g->P, op->cname);
			buf_puts(b, "\terror = cbl_request(cl->conn, msg, "
			    "&rsp, -1);\n");
			buf_printf(b, "\tif (error != 0) {\n\t\t%s__err(cl, "
			    "rsp);\n\t\treturn (error);\n\t}\n\t%s__err(cl, "
			    "NULL);\n", g->P, g->P);
			if (op->do_rsp.present) {
				buf_puts(b, "\tif (rsp == NULL)\n\t\treturn "
				    "(EPROTO);\n");
				buf_puts(b, "\tif ((out = cbl_msg_alloc(rsp, "
				    "sizeof(*out))) == NULL) {\n"
				    "\t\tcbl_msg_free(rsp);\n\t\treturn "
				    "(ENOMEM);\n\t}\n");
				buf_printf(b, "\tif ((error = %s_%s_rsp_parse("
				    "rsp, cbl_msg_body(rsp), out)) != 0) {\n"
				    "\t\tcbl_msg_free(rsp);\n\t\treturn "
				    "(error);\n\t}\n\tout->_msg = rsp;\n"
				    "\t*rspp = out;\n\treturn (0);\n}\n\n",
				    g->P, op->cname);
				buf_printf(b, "void\n%s_%s_rsp_free(struct "
				    "%s_%s_rsp *rsp)\n{\n\n\tif (rsp != NULL)\n"
				    "\t\tcbl_msg_free(rsp->_msg);\n}\n\n", g->P,
				    op->cname, g->P, op->cname);
			} else
				buf_puts(b, "\tcbl_msg_free(rsp);\n"
				    "\treturn (0);\n}\n\n");
			gen_client_async(b, g, op, cmd);
		}
		if (op->has_dump) {
			buf_printf(b, "int\n%s_%s_dump(struct %s_client *cl",
			    g->P, op->cname, g->P);
			if (op->dump_req.present)
				buf_printf(b, ",\n    const struct %s_%s_"
				    "dump_req *req", g->P, op->cname);
			buf_puts(b, ", cbl_dump **dp)\n{\n\tcbl_msg *msg;\n"
			    "\tint error;\n\n");
			buf_printf(b, "\tif ((error = cbl_msg_new(cbl_conn_ctx("
			    "cl->conn), cl->family,\n\t    %s, CBL_F_DUMP, "
			    "&msg)) != 0)\n\t\treturn (error);\n", cmd);
			if (op->dump_req.present)
				buf_printf(b, "\tif (req != NULL && (error = "
				    "%s_%s_dump_req_put_fields(msg, req)) "
				    "!= 0) {\n\t\tcbl_msg_free(msg);\n"
				    "\t\treturn (error);\n\t}\n", g->P,
				    op->cname);
			buf_puts(b, "\treturn (cbl_dump_start(cl->conn, msg, "
			    "dp));\n}\n\n");
			if (op->dump_rsp.present) {
				buf_printf(b, "int\n%s_%s_dump_next(cbl_dump "
				    "*d, struct %s_%s_dump_rsp **itemp)\n{\n",
				    g->P, op->cname, g->P, op->cname);
				buf_printf(b, "\tstruct %s_%s_dump_rsp *out;\n"
				    "\tcbl_msg *m;\n\tint error;\n\n\t*itemp = "
				    "NULL;\n", g->P, op->cname);
				buf_puts(b, "\tif ((error = cbl_dump_next(d, "
				    "&m)) != 0 || m == NULL)\n\t\treturn "
				    "(error);\n");
				buf_puts(b, "\tif ((out = cbl_msg_alloc(m, "
				    "sizeof(*out))) == NULL)\n\t\treturn "
				    "(ENOMEM);\n");
				buf_printf(b, "\tif ((error = %s_%s_dump_rsp_"
				    "parse(m, cbl_msg_body(m), out)) != 0)\n"
				    "\t\treturn (error);\n\t*itemp = out;\n"
				    "\treturn (0);\n}\n\n", g->P, op->cname);
			}
		}
		free(cmd);
	}

	/* Subscriptions. */
	for (size_t i = 0; i < s->ngrps; i++) {
		const struct sgrp *gr = &s->grps[i];
		char *gid = grp_id(g, gr);

		buf_printf(b, "struct %s_%s_sub {\n\tstruct %s_%s_handlers h;\n"
		    "\tvoid\t*arg;\n};\n\n", g->P, gr->cname, g->P, gr->cname);
		buf_printf(b, "static void\n%s_%s_ntf_cb(cbl_conn *conn "
		    "__unused, cbl_msg *msg, void *arg)\n{\n", g->P, gr->cname);
		if (!grp_has_events(s, gr)) {
			buf_puts(b, "\n\t(void)msg;\n\t(void)arg;\n}\n\n");
			goto subscribe;
		}
		buf_printf(b, "\tstruct %s_%s_sub *ctx = arg;\n\n", g->P,
		    gr->cname);
		buf_puts(b, "\tswitch (cbl_msg_cmd(msg)) {\n");
		for (size_t k = 0; k < s->nops; k++) {
			const struct sop *op = &s->ops[k];
			char *cmd;

			if (op->mcgrp != gr)
				continue;
			cmd = cmd_id(g, op);
			buf_printf(b, "\tcase %s: {\n"
			    "\t\tstruct %s_%s_ntf n;\n\n"
			    "\t\tif (ctx->h.%s != NULL &&\n\t\t    %s_%s_ntf_"
			    "parse(msg, cbl_msg_body(msg), &n) == 0)\n\t\t\t"
			    "ctx->h.%s(&n, ctx->arg);\n\t\tbreak;\n\t}\n", cmd,
			    g->P, op->cname, op->cname, g->P, op->cname,
			    op->cname);
			free(cmd);
		}
		buf_puts(b, "\tdefault:\n\t\tbreak;\n\t}\n}\n\n");
subscribe:
		buf_printf(b, "int\n%s_%s_subscribe(struct %s_client *cl,\n"
		    "    const struct %s_%s_handlers *h, void *arg, cbl_sub "
		    "**subp)\n{\n\tstruct %s_%s_sub *ctx;\n\tint error;\n\n",
		    g->P, gr->cname, g->P, g->P, gr->cname, g->P, gr->cname);
		buf_puts(b, "\tif ((ctx = calloc(1, sizeof(*ctx))) == NULL)\n"
		    "\t\treturn (ENOMEM);\n\tctx->h = *h;\n"
		    "\tctx->arg = arg;\n");
		buf_printf(b, "\terror = cbl_subscribe_id(cl->conn, cl->family,"
		    "\n\t    cl->groups[%s], %s_%s_ntf_cb, ctx, subp);\n", gid,
		    g->P, gr->cname);
		buf_puts(b, "\tif (error != 0)\n\t\tfree(ctx);\n"
		    "\treturn (error);\n}\n\n");
		buf_printf(b, "int\n%s_%s_unsubscribe(cbl_sub *sub)\n{\n"
		    "\tvoid *ctx = cbl_sub_arg(sub);\n\tint error;\n\n"
		    "\terror = cbl_unsubscribe(sub);\n\tfree(ctx);\n"
		    "\treturn (error);\n}\n\n", g->P, gr->cname);
		free(gid);
	}

	/* Streams. */
	for (size_t i = 0; i < s->nstreams; i++) {
		const struct sstream *st = &s->streams[i];
		const struct sop *op = stream_op(st);
		const char *P = g->P, *sn = st->cname;
		char *cmd = cmd_id(g, op);

		buf_printf(b, "struct %s_%s_ctx {\n\tstruct %s_%s_cbs cbs;\n"
		    "\tvoid\t*arg;\n};\n\n", P, sn, P, sn);
		buf_printf(b, "static void\n%s_%s_on_open(cbl_stream *s, "
		    "cbl_msg *accept, int error,\n    void *arg)\n{\n"
		    "\tstruct %s_%s_ctx *c = arg;\n", P, sn, P, sn);
		if (op->do_rsp.present) {
			buf_printf(b, "\tstruct %s_%s_rsp r, *rp = NULL;\n\n",
			    P, op->cname);
			buf_puts(b, "\tif (c->cbs.on_open == NULL)\n"
			    "\t\treturn;\n");
			buf_printf(b, "\tif (error == 0 && accept != NULL &&\n"
			    "\t    %s_%s_rsp_parse(accept, "
			    "cbl_msg_body(accept), &r) == 0)\n\t\trp = &r;\n"
			    "\tc->cbs.on_open(s, rp, error, c->arg);\n}\n\n",
			    P, op->cname);
		} else
			buf_puts(b, "\n\t(void)accept;\n"
			    "\tif (c->cbs.on_open != NULL)\n"
			    "\t\tc->cbs.on_open(s, error, c->arg);\n}\n\n");
		if (st->dir != DIR_UP) {
			buf_printf(b, "static void\n%s_%s_on_data(cbl_stream "
			    "*s, cbl_msg *data, void *arg)\n{\n"
			    "\tstruct %s_%s_ctx *c = arg;\n"
			    "\tstruct %s_%s d;\n\n", P, sn, P, sn, P,
			    st->down->cname);
			emit_on_data(b, P, st->down->cname);
		}
		buf_printf(b, "static void\n%s_%s_on_hclose(cbl_stream *s, "
		    "void *arg)\n{\n\tstruct %s_%s_ctx *c = arg;\n\n"
		    "\tif (c->cbs.on_hclose != NULL)\n\t\tc->cbs.on_hclose(s, "
		    "c->arg);\n}\n\n", P, sn, P, sn);
		buf_printf(b, "static void\n%s_%s_on_close(cbl_stream *s, int "
		    "code, const char *text,\n    void *arg)\n{\n"
		    "\tstruct %s_%s_ctx *c = arg;\n\n\tif (c->cbs.on_close != "
		    "NULL)\n\t\tc->cbs.on_close(s, code, text, c->arg);\n"
		    "\tfree(c);\n}\n\n", P, sn, P, sn);
		buf_printf(b, "static void\n%s_%s_on_writable(cbl_stream *s, "
		    "size_t credit, void *arg)\n{\n\tstruct %s_%s_ctx *c = "
		    "arg;\n\n\tif (c->cbs.on_writable != NULL)\n"
		    "\t\tc->cbs.on_writable(s, credit, c->arg);\n}\n\n", P, sn,
		    P, sn);
		buf_printf(b, "static const struct cbl_stream_cbs %s_%s_tramp "
		    "= {\n\t.on_open = %s_%s_on_open,\n", P, sn, P, sn);
		if (st->dir != DIR_UP)
			buf_printf(b, "\t.on_data = %s_%s_on_data,\n", P, sn);
		buf_printf(b, "\t.on_hclose = %s_%s_on_hclose,\n\t.on_close = "
		    "%s_%s_on_close,\n\t.on_writable = %s_%s_on_writable,\n"
		    "};\n\n", P, sn, P, sn, P, sn);
		buf_printf(b, "int\n%s_%s_open(struct %s_client *cl", P, sn, P);
		if (op->do_req.present)
			buf_printf(b, ",\n    const struct %s_%s_req *req", P,
			    op->cname);
		buf_printf(b, ",\n    const struct %s_%s_cbs *cbs, void *arg, "
		    "cbl_stream **sp)\n{\n\tstruct %s_%s_ctx *c;\n"
		    "\tcbl_msg *msg;\n\tint error;\n\n", P, sn, P, sn);
		buf_printf(b, "\tif ((error = cbl_msg_new(cbl_conn_ctx("
		    "cl->conn), cl->family,\n\t    %s, CBL_F_REQUEST | "
		    "CBL_F_S_OPEN, &msg)) != 0)\n\t\treturn (error);\n",
		    cmd);
		if (op->do_req.present)
			buf_printf(b, "\tif (req != NULL && (error = %s_%s_req_"
			    "put_fields(msg, req)) != 0) {\n\t\tcbl_msg_free"
			    "(msg);\n\t\treturn (error);\n\t}\n", P, op->cname);
		buf_puts(b, "\tif ((c = calloc(1, sizeof(*c))) == NULL) {\n"
		    "\t\tcbl_msg_free(msg);\n\t\treturn (ENOMEM);\n\t}\n"
		    "\tc->cbs = *cbs;\n\tc->arg = arg;\n");
		if (st->credit.set)
			buf_printf(b, "\t(void)cbl_msg_set_window(msg, %" PRIu64
			    ");\n", st->credit.mag);
		buf_printf(b, "\tif ((error = cbl_stream_open(cl->conn, msg, "
		    "%s, &%s_%s_tramp, c,\n\t    sp)) != 0)\n\t\tfree(c);\n"
		    "\treturn (error);\n}\n\n",
		    st->dir == DIR_DOWN ? "CBL_SF_PUSH" : "0", P, sn);
		if (st->dir != DIR_DOWN) {
			buf_printf(b, "int\n%s_%s_send(cbl_stream *s, const "
			    "struct %s_%s *data)\n{\n\tcbl_msg *msg;\n\tint "
			    "error;\n\n\tif ((error = cbl_stream_msg_new(s, "
			    "&msg)) != 0)\n\t\treturn (error);\n", P, sn, P,
			    st->up->cname);
			buf_printf(b, "\tif ((error = %s_%s_put_fields(msg, "
			    "data)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn"
			    " (error);\n\t}\n\treturn (cbl_stream_send(s, msg))"
			    ";\n}\n\n", P, st->up->cname);
		}
		free(cmd);
	}
}

static void
gen_server(struct buf *b, struct gctx *g, const char *base)
{
	const struct spec *s = g->s;
	const char *P = g->P;
	size_t nops = 0, *ix;
	bool check = false;

	/* Ops with both do and dump validate before choosing a parser. */
	for (size_t i = 0; i < s->nops; i++) {
		const struct sop *op = &s->ops[i];

		if (op->has_do && op->has_dump && op->stream == NULL &&
		    (op->do_req.present || op->dump_req.present))
			check = true;
	}
	banner(b, g);
	buf_puts(b, "#include <sys/param.h>\n\n#include <errno.h>\n"
	    "#include <stdlib.h>\n\n");
	buf_printf(b, "#include \"%s.h\"\n\n", base);
	if (check)
		buf_printf(b, "static int\n%s__check(cbl_req *req, const "
		    "struct cbl_policy_set *ps)\n{\n\tstruct cbl_verr ve;\n"
		    "\tint error;\n\n\terror = cbl_validate(cbl_msg_body("
		    "cbl_req_msg(req)), ps, &ve);\n\tif (error != 0)\n"
		    "\t\t(void)cbl_req_set_err(req, ve.msg, ve.path, "
		    "ve.pathlen,\n\t\t    ve.miss_type);\n\treturn (error);"
		    "\n}\n\n", P);

	for (size_t i = 0; i < s->nops; i++) {
		const struct sop *op = &s->ops[i];
		bool both = op->has_do && op->has_dump && op->stream == NULL;

		if (op->has_do && op->stream == NULL) {
			buf_printf(b, "static int\n%s_%s_doit_t(cbl_req *req, "
			    "const cbl_msg *msg __unused,\n    void *arg)\n{\n",
			    P, op->cname);
			if (op->do_req.present) {
				buf_printf(b, "\tstruct %s_%s_req rq;\n\tint "
				    "error;\n\n", P, op->cname);
				if (both)
					buf_printf(b, "\tif ((error = %s__check"
					    "(req, &%s_%s_req_policy)) != 0)\n"
					    "\t\treturn (error);\n", P, P,
					    op->cname);
				buf_printf(b, "\tif ((error = %s_%s_req_parse("
				    "cbl_req_msg(req),\n\t    cbl_msg_body("
				    "cbl_req_msg(req)), &rq)) != 0)\n"
				    "\t\treturn (error);\n\treturn "
				    "(%s_%s_doit(req, &rq, arg));\n}\n\n", P,
				    op->cname, P, op->cname);
			} else
				buf_printf(b, "\n\treturn (%s_%s_doit(req, "
				    "arg));\n}\n\n", P, op->cname);
		}
		if (op->has_dump) {
			buf_printf(b, "static int\n%s_%s_dumpit_t(cbl_req "
			    "*req, const cbl_msg *msg __unused,\n    struct "
			    "cbl_dump_state *st, void *arg)\n{\n", P,
			    op->cname);
			if (op->dump_req.present) {
				buf_printf(b, "\tstruct %s_%s_dump_req rq;\n"
				    "\tint error;\n\n", P, op->cname);
				if (both)
					buf_printf(b, "\tif ((error = %s__check"
					    "(req, &%s_%s_dump_req_policy))"
					    " != 0)\n\t\treturn (error);\n",
					    P, P, op->cname);
				buf_printf(b, "\tif ((error = %s_%s_dump_req_"
				    "parse(cbl_req_msg(req),\n\t    "
				    "cbl_msg_body(cbl_req_msg(req)), &rq)) "
				    "!= 0)\n\t\treturn (error);\n\treturn "
				    "(%s_%s_dumpit(req, &rq, st, arg));\n}\n\n",
				    P, op->cname, P, op->cname);
			} else
				buf_printf(b, "\n\treturn (%s_%s_dumpit(req, "
				    "st, arg));\n}\n\n", P, op->cname);
		}
		if (op->stream != NULL) {
			const struct sstream *st = op->stream;

			buf_printf(b, "static int\n%s_%s_stream_open_t(cbl_req "
			    "*req, const cbl_msg *msg __unused,\n    "
			    "cbl_stream *s, void *arg)\n{\n", P, st->cname);
			if (op->do_req.present)
				buf_printf(b, "\tstruct %s_%s_req rq;\n\tint "
				    "error;\n\n\tif ((error = %s_%s_req_parse("
				    "cbl_req_msg(req),\n\t    cbl_msg_body("
				    "cbl_req_msg(req)), &rq)) != 0)\n"
				    "\t\treturn (error);\n\treturn "
				    "(%s_%s_stream_open(req, &rq, s, arg));"
				    "\n}\n\n", P, op->cname, P, op->cname, P,
				    st->cname);
			else
				buf_printf(b, "\n\treturn (%s_%s_stream_open("
				    "req, s, arg));\n}\n\n", P, st->cname);
		}
		if (op_is_cmd(op))
			nops++;
	}

	/* Ops table, sorted by command id. */
	ix = xcalloc(s->nops, sizeof(*ix));
	for (size_t i = 0, n = 0; i < s->nops; i++)
		if (op_is_cmd(&s->ops[i]))
			ix[n++] = i;
	for (size_t i = 1; i < nops; i++)
		for (size_t j = i; j > 0 &&
		    s->ops[ix[j - 1]].value > s->ops[ix[j]].value; j--) {
			size_t t = ix[j];

			ix[j] = ix[j - 1];
			ix[j - 1] = t;
		}
	if (nops > 0) {
		buf_printf(b, "static const struct cbl_op %s__ops[] = {\n", P);
		for (size_t k = 0; k < nops; k++) {
			const struct sop *op = &s->ops[ix[k]];
			char *cmd = cmd_id(g, op);
			const char *pol = NULL;
			char *polname = NULL;

			buf_printf(b, "\t{\n\t\t.cmd = %s,\n\t\t.name = \"%s\","
			    "\n\t\t.flags = 0", cmd, op->name);
			if (op->stream != NULL)
				buf_puts(b, op->stream->dir == DIR_DOWN ?
				    " | CBL_OPF_PUSH" : " | CBL_OPF_STREAM");
			else {
				if (op->has_do)
					buf_puts(b, " | CBL_OPF_DO");
				if (op->has_dump)
					buf_puts(b, " | CBL_OPF_DUMP");
			}
			if (op->auth)
				buf_puts(b, " | CBL_OPF_AUTH");
			buf_puts(b, ",\n");
			if (op->stream != NULL || (op->has_do && !op->has_dump))
				pol = op->do_req.present ? "req" : NULL;
			else if (op->has_dump && !op->has_do)
				pol = op->dump_req.present ? "dump_req" : NULL;
			if (pol != NULL) {
				polname = xasprintf("&%s_%s_%s_policy", P,
				    op->cname, pol);
				buf_printf(b, "\t\t.policy = %s,\n", polname);
				free(polname);
			}
			if (op->stream != NULL)
				buf_printf(b, "\t\t.stream_open = %s_%s_stream_"
				    "open_t,\n", P, op->stream->cname);
			else {
				if (op->has_do)
					buf_printf(b, "\t\t.doit = %s_%s_"
					    "doit_t,\n", P, op->cname);
				if (op->has_dump)
					buf_printf(b, "\t\t.dumpit = %s_%s_"
					    "dumpit_t,\n", P, op->cname);
			}
			buf_puts(b, "\t},\n");
			free(cmd);
		}
		buf_puts(b, "};\n\n");
	}
	free(ix);
	if (s->ngrps > 0) {
		buf_printf(b,
		    "static const struct cbl_mcgrp %s__mcgrps[] = {\n", P);
		for (size_t i = 0; i < s->ngrps; i++)
			buf_printf(b, "\t{ .name = \"%s\", .flags = %s },\n",
			    s->grps[i].name, s->grps[i].auth ? "CBL_MCF_AUTH" :
			    "0");
		buf_puts(b, "};\n\n");
	}
	buf_printf(b, "const struct cbl_family_def %s_family_def = {\n"
	    "\t.abi = CBL_FAMILY_ABI,\n\t.name = %s_FAMILY_NAME,\n"
	    "\t.version = %s_FAMILY_VERSION,\n", P, g->PU, g->PU);
	if (nops > 0)
		buf_printf(b, "\t.ops = %s__ops,\n\t.nops = nitems(%s__ops),\n",
		    P, P);
	if (s->ngrps > 0)
		buf_printf(b, "\t.mcgrps = %s__mcgrps,\n\t.nmcgrps = "
		    "nitems(%s__mcgrps),\n", P, P);
	buf_puts(b, "};\n\n");
	if (!s->has_fixed_id)
		buf_printf(b, "int\n%s_register(cbl_ctx *ctx, void *arg, "
		    "cbl_family **famp)\n{\n\n\treturn (cbl_family_register("
		    "ctx, &%s_family_def, arg, famp));\n}\n\n", P, P);

	/* Reply, notify and stream helpers. */
	for (size_t i = 0; i < s->nops; i++) {
		const struct sop *op = &s->ops[i];
		char *cmd = cmd_id(g, op);

		if (op->do_rsp.present && op->stream == NULL)
			buf_printf(b, "int\n%s_%s_reply(cbl_req *req, const "
			    "struct %s_%s_rsp *rsp)\n{\n\tcbl_msg *msg;\n"
			    "\tint error;\n\n\tif ((error = cbl_req_reply_new"
			    "(req, %s, &msg)) != 0)\n\t\treturn (error);\n"
			    "\tif ((error = %s_%s_rsp_put_fields(msg, rsp)) != "
			    "0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);"
			    "\n\t}\n\treturn (cbl_req_send(req, msg));\n}\n\n",
			    P, op->cname, P, op->cname, cmd, P, op->cname);
		if (op->dump_rsp.present)
			buf_printf(b, "int\n%s_%s_dump_reply(cbl_req *req,\n"
			    "    const struct %s_%s_dump_rsp *rsp)\n{\n"
			    "\tcbl_msg *msg;\n\tint error;\n\n\tif ((error = "
			    "cbl_req_dump_item(req, &msg)) != 0)\n"
			    "\t\treturn (error);\n"
			    "\tif ((error = %s_%s_dump_rsp_put_fields(msg, "
			    "rsp)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn "
			    "(error);\n\t}\n\treturn (cbl_req_send(req, msg));"
			    "\n}\n\n", P, op->cname, P, op->cname, P,
			    op->cname);
		if (op->has_event) {
			char *gid = grp_id(g, op->mcgrp);

			buf_printf(b, "int\n%s_%s_notify(cbl_family *fam, "
			    "const struct %s_%s_ntf *ntf)\n{\n"
			    "\tcbl_msg *msg;\n"
			    "\tint error;\n\n\tif ((error = cbl_notify_msg_new("
			    "fam, %s, &msg)) != 0)\n\t\treturn (error);\n"
			    "\tif ((error = %s_%s_ntf_put_fields(msg, ntf)) != "
			    "0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);"
			    "\n\t}\n\treturn (cbl_notify(fam, %s, msg));\n"
			    "}\n\n", P, op->cname, P, op->cname, cmd, P,
			    op->cname, gid);
			free(gid);
		}
		free(cmd);
	}
	for (size_t i = 0; i < s->nstreams; i++) {
		const struct sstream *st = &s->streams[i];
		const struct sop *op = stream_op(st);
		const char *sn = st->cname;

		buf_printf(b, "struct %s_%s_sctx {\n\tstruct %s_%s_server_cbs "
		    "cbs;\n\tvoid\t*arg;\n};\n\n", P, sn, P, sn);
		if (st->dir != DIR_DOWN) {
			buf_printf(b, "static void\n%s_%s_s_on_data(cbl_stream "
			    "*s, cbl_msg *data, void *arg)\n{\n\tstruct %s_%s_"
			    "sctx *c = arg;\n\tstruct %s_%s d;\n\n", P, sn, P,
			    sn, P, st->up->cname);
			emit_on_data(b, P, st->up->cname);
		}
		buf_printf(b, "static void\n%s_%s_s_on_hclose(cbl_stream *s, "
		    "void *arg)\n{\n\tstruct %s_%s_sctx *c = arg;\n\n"
		    "\tif (c->cbs.on_hclose != NULL)\n\t\tc->cbs.on_hclose(s, "
		    "c->arg);\n}\n\n", P, sn, P, sn);
		buf_printf(b, "static void\n%s_%s_s_on_close(cbl_stream *s, "
		    "int code, const char *text,\n    void *arg)\n{\n"
		    "\tstruct %s_%s_sctx *c = arg;\n\n\tif (c->cbs.on_close != "
		    "NULL)\n\t\tc->cbs.on_close(s, code, text, c->arg);\n"
		    "\tfree(c);\n}\n\n", P, sn, P, sn);
		buf_printf(b, "static void\n%s_%s_s_on_writable(cbl_stream *s, "
		    "size_t credit, void *arg)\n{\n\tstruct %s_%s_sctx *c = "
		    "arg;\n\n\tif (c->cbs.on_writable != NULL)\n"
		    "\t\tc->cbs.on_writable(s, credit, c->arg);\n}\n\n", P, sn,
		    P, sn);
		buf_printf(b, "static const struct cbl_stream_cbs %s_%s_stramp "
		    "= {\n", P, sn);
		if (st->dir != DIR_DOWN)
			buf_printf(b, "\t.on_data = %s_%s_s_on_data,\n", P, sn);
		buf_printf(b, "\t.on_hclose = %s_%s_s_on_hclose,\n"
		    "\t.on_close = %s_%s_s_on_close,\n"
		    "\t.on_writable = %s_%s_s_on_writable,\n};\n\n",
		    P, sn, P, sn, P, sn);
		buf_printf(b, "int\n%s_%s_accept(cbl_stream *s", P, sn);
		if (op->do_rsp.present)
			buf_printf(b, ",\n    const struct %s_%s_rsp *accept",
			    P, op->cname);
		buf_printf(b, ",\n    const struct %s_%s_server_cbs *cbs, void "
		    "*arg)\n{\n\tstruct %s_%s_sctx *c;\n"
		    "\tcbl_msg *msg = NULL;\n\tint error;\n\n", P, sn, P, sn);
		if (op->do_rsp.present)
			buf_printf(b, "\tif (accept != NULL) {\n"
			    "\t\tif ((error = cbl_stream_msg_new(s, &msg)) "
			    "!= 0)\n\t\t\treturn (error);\n"
			    "\t\tif ((error = %s_%s_rsp_put_fields("
			    "msg, accept)) != 0) {\n\t\t\tcbl_msg_free(msg);\n"
			    "\t\t\treturn (error);\n\t\t}\n\t}\n", P,
			    op->cname);
		if (st->credit.set) {
			buf_puts(b, "\tif (msg == NULL && (error = "
			    "cbl_stream_msg_new(s, &msg)) != 0)\n\t\treturn "
			    "(error);\n");
			buf_printf(b, "\t(void)cbl_msg_set_window(msg, %" PRIu64
			    ");\n", st->credit.mag);
		}
		buf_puts(b, "\tif ((c = calloc(1, sizeof(*c))) == NULL) {\n"
		    "\t\tcbl_msg_free(msg);\n\t\treturn (ENOMEM);\n\t}\n"
		    "\tc->cbs = *cbs;\n\tc->arg = arg;\n");
		buf_printf(b, "\tif ((error = cbl_stream_accept(s, msg, 0, "
		    "&%s_%s_stramp, c)) != 0)\n\t\tfree(c);\n\treturn (error);"
		    "\n}\n\n", P, sn);
		if (st->dir != DIR_UP) {
			buf_printf(b, "int\n%s_%s_server_send(cbl_stream *s, "
			    "const struct %s_%s *data)\n{\n\tcbl_msg *msg;\n"
			    "\tint error;\n\n\tif ((error = cbl_stream_msg_new("
			    "s, &msg)) != 0)\n\t\treturn (error);\n", P, sn, P,
			    st->down->cname);
			buf_printf(b, "\tif ((error = %s_%s_put_fields(msg, "
			    "data)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn"
			    " (error);\n\t}\n\treturn (cbl_stream_send(s, msg))"
			    ";\n}\n\n", P, st->down->cname);
		}
	}
}

/* Write "b" to dirfd/name, replacing it atomically. */
static int
write_file(int dirfd, const char *name, const struct buf *b)
{
	char *tmp;
	int fd, error = 0;

	tmp = xasprintf(".%s.XXXXXX", name);
	if ((fd = mkostempsat(dirfd, tmp, 0, O_CLOEXEC)) == -1) {
		warn("%s", tmp);
		error = 1;
		goto out;
	}
	if ((b->len > 0 && write(fd, b->p, b->len) != (ssize_t)b->len) ||
	    fchmod(fd, 0644) != 0 || close(fd) != 0) {
		warn("%s", tmp);
		(void)unlinkat(dirfd, tmp, 0);
		error = 1;
		goto out;
	}
	if (renameat(dirfd, tmp, dirfd, name) != 0) {
		warn("%s", name);
		(void)unlinkat(dirfd, tmp, 0);
		error = 1;
	}
out:
	free(tmp);
	return (error);
}

static bool
want(const char *parts, const char *part)
{
	size_t n = strlen(part);

	for (const char *p = parts; p != NULL && *p != '\0';) {
		if (strncmp(p, part, n) == 0 && (p[n] == ',' || p[n] == '\0'))
			return (true);
		if ((p = strchr(p, ',')) != NULL)
			p++;
	}
	return (false);
}

int
gen_c(const struct spec *s, const char *base, int dirfd,
    const char *parts)
{
	struct gctx g = { .s = s, .P = s->prefix, .PU = s->uprefix };
	struct buf b;
	char *name;
	int error = 0;

	g.famc = mangle(s->name);
	build_objs(&g);
	if (want(parts, "h")) {
		buf_init(&b);
		gen_header(&b, &g, base);
		name = xasprintf("%s.h", base);
		error |= write_file(dirfd, name, &b);
		free(name);
		buf_free(&b);
	}
	if (want(parts, "c")) {
		buf_init(&b);
		gen_common(&b, &g, base);
		name = xasprintf("%s.c", base);
		error |= write_file(dirfd, name, &b);
		free(name);
		buf_free(&b);
	}
	if (want(parts, "client")) {
		buf_init(&b);
		gen_client(&b, &g, base);
		name = xasprintf("%s_client.c", base);
		error |= write_file(dirfd, name, &b);
		free(name);
		buf_free(&b);
	}
	if (want(parts, "server")) {
		buf_init(&b);
		gen_server(&b, &g, base);
		name = xasprintf("%s_server.c", base);
		error |= write_file(dirfd, name, &b);
		free(name);
		buf_free(&b);
	}
	if (want(parts, "md")) {
		buf_init(&b);
		error |= gen_md(s, &b);
		name = xasprintf("%s.md", base);
		error |= write_file(dirfd, name, &b);
		free(name);
		buf_free(&b);
	}
	free_objs(&g);
	free(g.famc);
	return (error);
}
