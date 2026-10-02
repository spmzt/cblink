/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Spec loading and validation (docs/SPEC-FORMAT.md parts 2 and 3).
 * All semantic errors are collected; the caller prints them sorted by
 * location.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "spec.h"

struct ld {
	struct diags	*d;
	bool		 builtin;
	struct spec	*s;
};

#define	ERRN(ld, n, ...)	\
	diag_add((ld)->d, (n)->line, (n)->col, __VA_ARGS__)
#define	ERRL(ld, l, ...)	\
	diag_add((ld)->d, (l).line, (l).col, __VA_ARGS__)

static struct loc
nloc(const struct ynode *n)
{

	return ((struct loc){ n->line, n->col });
}

/* Location of "key" inside a mapping (falls back to the mapping). */
static struct loc
kloc(const struct ynode *map, const char *key)
{

	for (size_t i = 0; i < map->npairs; i++)
		if (strcmp(map->pairs[i].key, key) == 0)
			return ((struct loc){ map->pairs[i].line,
			    map->pairs[i].col });
	return (nloc(map));
}

const char *
stype_name(enum stype t)
{
	static const char *names[] = { "u8", "u16", "u32", "u64", "s8", "s16",
	    "s32", "s64", "bool", "flag", "text", "bytes", "float", "nest" };

	return (names[t]);
}

const char *
stype_ctype(enum stype t)
{
	static const char *names[] = { "uint8_t", "uint16_t", "uint32_t",
	    "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "bool",
	    "bool", "const char *", "struct cbl_bytes", "double", NULL };

	return (names[t]);
}

bool
stype_unsigned(enum stype t)
{

	return (t >= T_U8 && t <= T_U64);
}

bool
stype_signed(enum stype t)
{

	return (t >= T_S8 && t <= T_S64);
}

bool
stype_scalar(enum stype t)
{

	return (stype_unsigned(t) || stype_signed(t) || t == T_BOOL ||
	    t == T_FLOAT);
}

uint64_t
stype_umax(enum stype t)
{

	switch (t) {
	case T_U8: return (UINT8_MAX);
	case T_U16: return (UINT16_MAX);
	case T_U32: return (UINT32_MAX);
	default: return (UINT64_MAX);
	}
}

int64_t
stype_smin(enum stype t)
{

	switch (t) {
	case T_S8: return (INT8_MIN);
	case T_S16: return (INT16_MIN);
	case T_S32: return (INT32_MIN);
	default: return (INT64_MIN);
	}
}

int64_t
stype_smax(enum stype t)
{

	switch (t) {
	case T_S8: return (INT8_MAX);
	case T_S16: return (INT16_MAX);
	case T_S32: return (INT32_MAX);
	default: return (INT64_MAX);
	}
}

uint64_t
snum_u(const struct snum *n)
{

	return (n->neg ? 0 : n->mag);
}

int64_t
snum_s(const struct snum *n)
{

	if (n->neg)
		return (n->mag == (uint64_t)INT64_MAX + 1 ? INT64_MIN :
		    -(int64_t)n->mag);
	return (n->mag > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)n->mag);
}

char *
mangle(const char *name)
{
	char *s = xstrdup(name);

	for (char *p = s; *p != '\0'; p++)
		if (*p == '-' || *p == '.')
			*p = '_';
	return (s);
}

char *
upper(const char *s)
{
	char *u = xstrdup(s);

	for (char *p = u; *p != '\0'; p++)
		if (*p >= 'a' && *p <= 'z')
			*p = (char)(*p - 'a' + 'A');
	return (u);
}

/* Schema helpers. */
static bool
want_type(struct ld *ld, const struct ynode *n, enum ytype t, const char *what)
{
	static const char *tn[] = { "a scalar", "a mapping", "a sequence" };

	if (n->type == t)
		return (true);
	ERRN(ld, n, "%s must be %s", what, tn[t]);
	return (false);
}

static void
check_keys(struct ld *ld, const struct ynode *map, const char *const *ok)
{

	for (size_t i = 0; i < map->npairs; i++) {
		bool found = false;

		for (size_t j = 0; ok[j] != NULL; j++)
			if (strcmp(map->pairs[i].key, ok[j]) == 0)
				found = true;
		if (!found)
			diag_add(ld->d, map->pairs[i].line, map->pairs[i].col,
			    "unknown key '%s'", map->pairs[i].key);
	}
}

static const struct ynode *
need(struct ld *ld, const struct ynode *map, const char *key)
{
	const struct ynode *v = ymap_get(map, key);

	if (v == NULL)
		ERRN(ld, map, "missing required key '%s'", key);
	return (v);
}

static char *
get_str(struct ld *ld, const struct ynode *n, const char *what)
{

	if (n == NULL || !want_type(ld, n, Y_SCALAR, what))
		return (NULL);
	return (xstrdup(n->str));
}

/* Names: [a-z][a-z0-9-]*, at most 63 characters. */
static char *
get_name(struct ld *ld, const struct ynode *n, const char *what)
{
	const char *s;
	size_t len;

	if (n == NULL || !want_type(ld, n, Y_SCALAR, what))
		return (NULL);
	s = n->str;
	len = strlen(s);
	if (len == 0 || len > 63 || s[0] < 'a' || s[0] > 'z')
		goto bad;
	for (size_t i = 1; i < len; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') ||
		    (s[i] >= '0' && s[i] <= '9') || s[i] == '-'))
			goto bad;
	if (s[len - 1] == '-' || strstr(s, "--") != NULL)
		goto bad;
	return (xstrdup(s));
bad:
	ERRN(ld, n, "invalid %s '%s' (expected [a-z][a-z0-9-]*, at most 63 "
	    "characters)", what, s);
	return (NULL);
}

static bool
get_bool(struct ld *ld, const struct ynode *n, bool *out)
{

	if (!want_type(ld, n, Y_SCALAR, "value"))
		return (false);
	if (strcmp(n->str, "true") == 0)
		*out = true;
	else if (strcmp(n->str, "false") == 0)
		*out = false;
	else {
		ERRN(ld, n, "expected 'true' or 'false', got '%s'", n->str);
		return (false);
	}
	return (true);
}

/* Decimal, 0x hex, optional '-'; or a const name if "refs". */
static bool
get_num(struct ld *ld, const struct ynode *n, bool refs, struct snum *out)
{
	const char *s;
	uint64_t v = 0, d;
	int base = 10;

	memset(out, 0, sizeof(*out));
	out->loc = nloc(n);
	if (!want_type(ld, n, Y_SCALAR, "number"))
		return (false);
	s = n->str;
	if (refs && s[0] >= 'a' && s[0] <= 'z') {
		out->set = true;
		out->ref = xstrdup(s);
		return (true);
	}
	if (n->quoted)
		goto bad;
	if (*s == '-') {
		out->neg = true;
		s++;
	}
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		base = 16;
		s += 2;
	}
	if (*s == '\0')
		goto bad;
	for (; *s != '\0'; s++) {
		if (*s >= '0' && *s <= '9')
			d = (uint64_t)(*s - '0');
		else if (base == 16 && *s >= 'a' && *s <= 'f')
			d = (uint64_t)(*s - 'a' + 10);
		else if (base == 16 && *s >= 'A' && *s <= 'F')
			d = (uint64_t)(*s - 'A' + 10);
		else
			goto bad;
		if (v > (UINT64_MAX - d) / (uint64_t)base) {
			ERRN(ld, n, "number '%s' out of range", n->str);
			return (false);
		}
		v = v * (uint64_t)base + d;
	}
	if (out->neg && v > (uint64_t)INT64_MAX + 1) {
		ERRN(ld, n, "number '%s' out of range", n->str);
		return (false);
	}
	if (out->neg && v == 0)
		out->neg = false;
	out->set = true;
	out->mag = v;
	return (true);
bad:
	ERRN(ld, n, "expected a number%s, got '%s'",
	    refs ? " or a const name" : "", n->str);
	return (false);
}

static bool
get_u32(struct ld *ld, const struct ynode *n, uint32_t min, uint32_t max,
    uint32_t *out)
{
	struct snum v;

	if (!get_num(ld, n, false, &v))
		return (false);
	if (v.neg || v.mag < min || v.mag > max) {
		ERRN(ld, n, "value %s out of range %" PRIu32 "..%" PRIu32,
		    n->str, min, max);
		return (false);
	}
	*out = (uint32_t)v.mag;
	return (true);
}

/* Definitions. */
static void
load_def(struct ld *ld, const struct ynode *n, struct sdef *def)
{
	static const char *const ck_const[] = { "name", "type", "value", "doc",
	    NULL };
	static const char *const ck_enum[] = { "name", "type", "entries",
	    "doc", NULL };
	static const char *const ck_entry[] = { "name", "value", "doc", NULL };
	const struct ynode *v, *ents, *e;
	char *type;
	uint64_t next = 0;

	def->loc = nloc(n);
	if (!want_type(ld, n, Y_MAP, "definition"))
		return;
	def->name = get_name(ld, need(ld, n, "name"), "definition name");
	def->doc = (v = ymap_get(n, "doc")) != NULL ? get_str(ld, v, "doc") :
	    NULL;
	if ((type = get_str(ld, need(ld, n, "type"), "type")) == NULL)
		return;
	if (strcmp(type, "const") == 0) {
		def->type = D_CONST;
		check_keys(ld, n, ck_const);
		if ((v = need(ld, n, "value")) != NULL)
			(void)get_num(ld, v, false, &def->value);
	} else if (strcmp(type, "enum") == 0 || strcmp(type, "flags") == 0) {
		def->type = type[0] == 'e' ? D_ENUM : D_FLAGS;
		check_keys(ld, n, ck_enum);
		if ((ents = need(ld, n, "entries")) == NULL ||
		    !want_type(ld, ents, Y_SEQ, "entries"))
			goto out;
		def->entries = xcalloc(ents->nitems, sizeof(*def->entries));
		def->nentries = ents->nitems;
		for (size_t i = 0; i < ents->nitems; i++) {
			struct sentry *en = &def->entries[i];

			e = ents->items[i];
			en->loc = nloc(e);
			/* Enum values and flag bits count on from the last. */
			en->value = next;
			if (e->type == Y_SCALAR) {
				en->name = get_name(ld, e, "entry name");
			} else if (want_type(ld, e, Y_MAP, "entry")) {
				check_keys(ld, e, ck_entry);
				en->name = get_name(ld, need(ld, e, "name"),
				    "entry name");
				if ((v = ymap_get(e, "doc")) != NULL)
					en->doc = get_str(ld, v, "doc");
				if ((v = ymap_get(e, "value")) != NULL) {
					struct snum sv;

					if (get_num(ld, v, false, &sv)) {
						if (sv.neg || (def->type ==
						    D_FLAGS && sv.mag > 63))
							ERRN(ld, v, "%s %s out "
							    "of range",
							    def->type == D_FLAGS
							    ? "flag bit" :
							    "enum value",
							    v->str);
						else
							en->value = sv.mag;
					}
				}
			}
			if (def->type == D_FLAGS && en->value > 63)
				ERRL(ld, en->loc, "flag bit %" PRIu64
				    " out of range 0..63", en->value);
			next = en->value + 1;
		}
	} else
		ERRN(ld, ymap_get(n, "type"), "unknown definition type '%s' "
		    "(expected const, enum or flags)", type);
out:
	free(type);
}

static const struct {
	const char	*name;
	enum stype	 type;
} type_names[] = {
	{ "u8", T_U8 }, { "u16", T_U16 }, { "u32", T_U32 }, { "u64", T_U64 },
	{ "s8", T_S8 }, { "s16", T_S16 }, { "s32", T_S32 }, { "s64", T_S64 },
	{ "bool", T_BOOL }, { "flag", T_FLAG }, { "text", T_TEXT },
	{ "string", T_TEXT }, { "bytes", T_BYTES }, { "binary", T_BYTES },
	{ "float", T_FLOAT }, { "nest", T_NEST },
};

static void
load_attr(struct ld *ld, const struct ynode *n, struct sattr *a,
    uint32_t *next)
{
	static const char *const ck[] = { "name", "value", "type", "doc",
	    "nested-attributes", "multi-attr", "enum", "required", "checks",
	    NULL };
	static const char *const ck_checks[] = { "min", "max", "min-len",
	    "max-len", "exact-len", "min-count", "max-count", NULL };
	const struct ynode *v, *c;
	char *t;
	size_t i;

	a->loc = nloc(n);
	a->value = *next;
	if (!want_type(ld, n, Y_MAP, "attribute"))
		return;
	check_keys(ld, n, ck);
	a->name = get_name(ld, need(ld, n, "name"), "attribute name");
	if ((v = ymap_get(n, "value")) != NULL) {
		a->value_loc = nloc(v);
		(void)get_u32(ld, v, 1, 65535, &a->value);
	} else
		a->value_loc = a->loc;
	if (a->value > 65535)
		ERRL(ld, a->loc, "attribute id %" PRIu32 " out of range "
		    "1..65535", a->value);
	*next = a->value + 1;
	if ((v = need(ld, n, "type")) != NULL) {
		a->type_loc = nloc(v);
		if ((t = get_str(ld, v, "type")) != NULL) {
			for (i = 0; i < nitems(type_names); i++)
				if (strcmp(t, type_names[i].name) == 0)
					break;
			if (i == nitems(type_names))
				ERRN(ld, v, "unknown type '%s'", t);
			else
				a->type = type_names[i].type;
			free(t);
		}
	}
	if ((v = ymap_get(n, "doc")) != NULL)
		a->doc = get_str(ld, v, "doc");
	if ((v = ymap_get(n, "nested-attributes")) != NULL) {
		a->nested_loc = nloc(v);
		a->nested_name = get_str(ld, v, "nested-attributes");
	}
	if ((v = ymap_get(n, "multi-attr")) != NULL)
		(void)get_bool(ld, v, &a->multi);
	if ((v = ymap_get(n, "enum")) != NULL) {
		a->enum_loc = nloc(v);
		a->enum_name = get_str(ld, v, "enum");
	}
	if ((v = ymap_get(n, "required")) != NULL)
		(void)get_bool(ld, v, &a->required);
	if ((c = ymap_get(n, "checks")) != NULL &&
	    want_type(ld, c, Y_MAP, "checks")) {
		a->checks_loc = nloc(c);
		check_keys(ld, c, ck_checks);
		if ((v = ymap_get(c, "min")) != NULL)
			(void)get_num(ld, v, true, &a->min);
		if ((v = ymap_get(c, "max")) != NULL)
			(void)get_num(ld, v, true, &a->max);
		if ((v = ymap_get(c, "min-len")) != NULL)
			(void)get_num(ld, v, true, &a->min_len);
		if ((v = ymap_get(c, "max-len")) != NULL)
			(void)get_num(ld, v, true, &a->max_len);
		if ((v = ymap_get(c, "exact-len")) != NULL)
			(void)get_num(ld, v, true, &a->exact_len);
		if ((v = ymap_get(c, "min-count")) != NULL)
			(void)get_num(ld, v, true, &a->min_count);
		if ((v = ymap_get(c, "max-count")) != NULL)
			(void)get_num(ld, v, true, &a->max_count);
	}
}

static void
load_set(struct ld *ld, const struct ynode *n, struct sset *set)
{
	static const char *const ck[] = { "name", "doc", "attributes", NULL };
	const struct ynode *v, *attrs;
	uint32_t next = 1;

	set->loc = nloc(n);
	if (!want_type(ld, n, Y_MAP, "attribute set"))
		return;
	check_keys(ld, n, ck);
	set->name = get_name(ld, need(ld, n, "name"), "attribute-set name");
	if ((v = ymap_get(n, "doc")) != NULL)
		set->doc = get_str(ld, v, "doc");
	if ((attrs = need(ld, n, "attributes")) == NULL ||
	    !want_type(ld, attrs, Y_SEQ, "attributes"))
		return;
	set->attrs = xcalloc(attrs->nitems, sizeof(*set->attrs));
	set->nattrs = attrs->nitems;
	for (size_t i = 0; i < attrs->nitems; i++)
		load_attr(ld, attrs->items[i], &set->attrs[i], &next);
}

static void
load_list(struct ld *ld, const struct ynode *n, struct slist *l, bool req)
{
	static const char *const ck_req[] = { "attributes", "required", NULL };
	static const char *const ck[] = { "attributes", NULL };
	const struct ynode *v;

	l->present = true;
	l->loc = nloc(n);
	if (!want_type(ld, n, Y_MAP, "attribute list"))
		return;
	check_keys(ld, n, req ? ck_req : ck);
	if ((v = need(ld, n, "attributes")) != NULL &&
	    want_type(ld, v, Y_SEQ, "attributes")) {
		l->n = v->nitems;
		l->names = xcalloc(l->n, sizeof(*l->names));
		l->locs = xcalloc(l->n, sizeof(*l->locs));
		for (size_t i = 0; i < l->n; i++) {
			l->locs[i] = nloc(v->items[i]);
			l->names[i] = get_str(ld, v->items[i],
			    "attribute name");
		}
	}
	if ((v = ymap_get(n, "required")) != NULL &&
	    want_type(ld, v, Y_SEQ, "required")) {
		l->nreq = v->nitems;
		l->req_names = xcalloc(l->nreq, sizeof(*l->req_names));
		l->req_locs = xcalloc(l->nreq, sizeof(*l->req_locs));
		for (size_t i = 0; i < l->nreq; i++) {
			l->req_locs[i] = nloc(v->items[i]);
			l->req_names[i] = get_str(ld, v->items[i],
			    "attribute name");
		}
	}
}

static void
load_dodump(struct ld *ld, const struct ynode *n, struct slist *rq,
    struct slist *rs)
{
	static const char *const ck[] = { "request", "reply", NULL };
	const struct ynode *v;

	if (!want_type(ld, n, Y_MAP, "do/dump"))
		return;
	check_keys(ld, n, ck);
	if ((v = ymap_get(n, "request")) != NULL)
		load_list(ld, v, rq, true);
	if ((v = ymap_get(n, "reply")) != NULL)
		load_list(ld, v, rs, false);
}

static void
load_op(struct ld *ld, const struct ynode *n, struct sop *op, uint32_t *next)
{
	static const char *const ck[] = { "name", "value", "doc",
	    "attribute-set", "auth", "do", "dump", "event", "mcgrp", NULL };
	const struct ynode *v;

	op->loc = nloc(n);
	op->value = *next;
	op->value_loc = op->loc;
	if (!want_type(ld, n, Y_MAP, "operation"))
		return;
	check_keys(ld, n, ck);
	op->name = get_name(ld, need(ld, n, "name"), "operation name");
	if ((v = ymap_get(n, "value")) != NULL) {
		op->value_loc = nloc(v);
		(void)get_u32(ld, v, 1, 65535, &op->value);
	}
	if (op->value > 65535)
		ERRL(ld, op->loc, "command id %" PRIu32 " out of range "
		    "1..65535", op->value);
	*next = op->value + 1;
	if ((v = ymap_get(n, "doc")) != NULL)
		op->doc = get_str(ld, v, "doc");
	if ((v = need(ld, n, "attribute-set")) != NULL) {
		op->set_loc = nloc(v);
		op->set_name = get_str(ld, v, "attribute-set");
	}
	if ((v = ymap_get(n, "auth")) != NULL)
		(void)get_bool(ld, v, &op->auth);
	if ((v = ymap_get(n, "do")) != NULL) {
		op->has_do = true;
		load_dodump(ld, v, &op->do_req, &op->do_rsp);
	}
	if ((v = ymap_get(n, "dump")) != NULL) {
		op->has_dump = true;
		load_dodump(ld, v, &op->dump_req, &op->dump_rsp);
	}
	if ((v = ymap_get(n, "event")) != NULL) {
		op->has_event = true;
		load_list(ld, v, &op->event, false);
	}
	if ((v = ymap_get(n, "mcgrp")) != NULL) {
		op->mcgrp_loc = nloc(v);
		op->mcgrp_name = get_str(ld, v, "mcgrp");
	}
}

static void
load_grp(struct ld *ld, const struct ynode *n, struct sgrp *g)
{
	static const char *const ck[] = { "name", "doc", "auth", NULL };
	const struct ynode *v;

	g->loc = nloc(n);
	if (!want_type(ld, n, Y_MAP, "multicast group"))
		return;
	check_keys(ld, n, ck);
	g->name = get_name(ld, need(ld, n, "name"), "group name");
	if ((v = ymap_get(n, "doc")) != NULL)
		g->doc = get_str(ld, v, "doc");
	if ((v = ymap_get(n, "auth")) != NULL)
		(void)get_bool(ld, v, &g->auth);
}

static void
load_stream(struct ld *ld, const struct ynode *n, struct sstream *st)
{
	static const char *const ck[] = { "name", "doc", "open", "direction",
	    "payload", "payload-up", "payload-down", "initial-credit", NULL };
	const struct ynode *v;
	char *dir;

	st->loc = nloc(n);
	if (!want_type(ld, n, Y_MAP, "stream"))
		return;
	check_keys(ld, n, ck);
	st->name = get_name(ld, need(ld, n, "name"), "stream name");
	if ((v = ymap_get(n, "doc")) != NULL)
		st->doc = get_str(ld, v, "doc");
	if ((v = need(ld, n, "open")) != NULL) {
		st->open_loc = nloc(v);
		st->open_name = get_str(ld, v, "open");
	}
	if ((v = need(ld, n, "direction")) != NULL &&
	    (dir = get_str(ld, v, "direction")) != NULL) {
		if (strcmp(dir, "bidirectional") == 0)
			st->dir = DIR_BIDI;
		else if (strcmp(dir, "client-to-server") == 0)
			st->dir = DIR_UP;
		else if (strcmp(dir, "server-to-client") == 0)
			st->dir = DIR_DOWN;
		else
			ERRN(ld, v, "unknown direction '%s' (expected "
			    "bidirectional, client-to-server or "
			    "server-to-client)", dir);
		free(dir);
	}
	if ((v = ymap_get(n, "payload")) != NULL) {
		st->payload_loc = nloc(v);
		st->payload_name = get_str(ld, v, "payload");
	}
	if ((v = ymap_get(n, "payload-up")) != NULL) {
		st->up_loc = nloc(v);
		st->up_name = get_str(ld, v, "payload-up");
	}
	if ((v = ymap_get(n, "payload-down")) != NULL) {
		st->down_loc = nloc(v);
		st->down_name = get_str(ld, v, "payload-down");
	}
	if (st->payload_name == NULL && st->up_name == NULL &&
	    st->down_name == NULL)
		ERRN(ld, n, "stream needs 'payload' or 'payload-up'/"
		    "'payload-down'%s", "");
	if (st->payload_name != NULL && (st->up_name != NULL ||
	    st->down_name != NULL))
		ERRL(ld, st->payload_loc, "'payload' cannot be combined with "
		    "'payload-up'/'payload-down'%s", "");
	if ((v = ymap_get(n, "initial-credit")) != NULL &&
	    get_num(ld, v, true, &st->credit) && !st->credit.ref &&
	    (st->credit.neg || st->credit.mag > INT32_MAX))
		ERRN(ld, v, "initial-credit out of range 0..%d", INT32_MAX);
}

/* Validation. */
static struct sset *
find_set(struct spec *s, const char *name)
{

	for (size_t i = 0; name != NULL && i < s->nsets; i++)
		if (s->sets[i].name != NULL &&
		    strcmp(s->sets[i].name, name) == 0)
			return (&s->sets[i]);
	return (NULL);
}

static struct sdef *
find_def(struct spec *s, const char *name)
{

	for (size_t i = 0; name != NULL && i < s->ndefs; i++)
		if (s->defs[i].name != NULL &&
		    strcmp(s->defs[i].name, name) == 0)
			return (&s->defs[i]);
	return (NULL);
}

static struct sattr *
find_attr(struct sset *set, const char *name)
{

	for (size_t i = 0; set != NULL && name != NULL && i < set->nattrs; i++)
		if (set->attrs[i].name != NULL &&
		    strcmp(set->attrs[i].name, name) == 0)
			return (&set->attrs[i]);
	return (NULL);
}

static void
resolve_num(struct ld *ld, struct snum *n)
{
	struct sdef *def;

	if (!n->set || n->ref == NULL)
		return;
	def = find_def(ld->s, n->ref);
	if (def == NULL) {
		ERRL(ld, n->loc, "undefined const '%s'", n->ref);
		n->set = false;
	} else if (def->type != D_CONST) {
		ERRL(ld, n->loc, "'%s' is not a const", n->ref);
		n->set = false;
	} else {
		n->neg = def->value.neg;
		n->mag = def->value.mag;
	}
}

static void
dupname(struct ld *ld, const char *what, const char *name, struct loc l,
    const char *prev, struct loc pl)
{

	if (name != NULL && prev != NULL && strcmp(name, prev) == 0)
		ERRL(ld, l, "duplicate %s '%s' (first defined at %d:%d)", what,
		    name, pl.line, pl.col);
}

static bool
is_c_keyword(const char *s)
{
	static const char *const kw[] = { "alignas", "alignof", "auto", "bool",
	    "break", "case", "char", "const", "constexpr", "continue",
	    "default", "do", "double", "else", "enum", "extern", "false",
	    "float", "for", "goto", "if", "inline", "int", "long", "nullptr",
	    "register", "restrict", "return", "short", "signed", "sizeof",
	    "static", "static_assert", "struct", "switch", "thread_local",
	    "true", "typedef", "typeof", "typeof_unqual", "union", "unsigned",
	    "void", "volatile", "while", NULL };

	for (size_t i = 0; kw[i] != NULL; i++)
		if (strcmp(s, kw[i]) == 0)
			return (true);
	return (false);
}

static void
check_attr(struct ld *ld, struct sattr *a)
{
	bool isint = stype_unsigned(a->type) || stype_signed(a->type);
	bool islen = a->type == T_TEXT || a->type == T_BYTES;
	struct snum *nums[] = { &a->min, &a->max, &a->min_len, &a->max_len,
	    &a->exact_len, &a->min_count, &a->max_count };

	for (size_t i = 0; i < nitems(nums); i++)
		resolve_num(ld, nums[i]);
	if (a->type == T_NEST) {
		if (a->nested_name == NULL)
			ERRL(ld, a->type_loc, "type 'nest' requires "
			    "'nested-attributes'%s", "");
		else if ((a->nested = find_set(ld->s, a->nested_name)) == NULL)
			ERRL(ld, a->nested_loc, "undefined attribute-set '%s'",
			    a->nested_name);
	} else if (a->nested_name != NULL)
		ERRL(ld, a->nested_loc, "'nested-attributes' requires type "
		    "'nest'%s", "");
	if (a->enum_name != NULL) {
		if (!stype_unsigned(a->type))
			ERRL(ld, a->enum_loc, "'enum' requires an unsigned "
			    "type%s", "");
		else if ((a->en = find_def(ld->s, a->enum_name)) == NULL)
			ERRL(ld, a->enum_loc, "undefined enum '%s'",
			    a->enum_name);
		else if (a->en->type == D_CONST) {
			ERRL(ld, a->enum_loc, "'%s' is a const, not an enum "
			    "or flags", a->enum_name);
			a->en = NULL;
		}
		for (size_t i = 0; a->en != NULL && i < a->en->nentries; i++) {
			const struct sentry *e = &a->en->entries[i];
			uint64_t max = stype_umax(a->type);

			if (a->en->type == D_FLAGS ? e->value < 64 &&
			    (UINT64_C(1) << e->value) > max : e->value > max) {
				ERRL(ld, a->enum_loc, "'%s' has values that do "
				    "not fit type '%s'", a->enum_name,
				    stype_name(a->type));
				break;
			}
		}
	}
	if ((a->min.set || a->max.set) && !isint)
		ERRL(ld, (a->min.set ? a->min : a->max).loc, "'min'/'max' "
		    "apply only to integer types, not '%s'",
		    stype_name(a->type));
	if ((a->min_len.set || a->max_len.set) && !islen)
		ERRL(ld, (a->min_len.set ? a->min_len : a->max_len).loc,
		    "'min-len'/'max-len' apply only to text and bytes, not "
		    "'%s'", stype_name(a->type));
	if (a->exact_len.set && a->type != T_BYTES)
		ERRL(ld, a->exact_len.loc, "'exact-len' applies only to "
		    "bytes%s", "");
	if (a->exact_len.set && (a->min_len.set || a->max_len.set))
		ERRL(ld, a->exact_len.loc, "'exact-len' cannot be combined "
		    "with 'min-len'/'max-len'%s", "");
	if ((a->min_count.set || a->max_count.set) && !a->multi)
		ERRL(ld, (a->min_count.set ? a->min_count : a->max_count).loc,
		    "'min-count'/'max-count' require 'multi-attr: true'%s",
		    "");

	/* Ranges. */
	if (isint && stype_unsigned(a->type)) {
		if (a->min.set && a->min.neg)
			ERRL(ld, a->min.loc, "invalid range: min (%s%" PRIu64
			    ") below 0 for '%s'", "-", a->min.mag,
			    stype_name(a->type));
		if (a->max.set && a->max.neg)
			ERRL(ld, a->max.loc, "invalid range: max (%s%" PRIu64
			    ") below 0 for '%s'", "-", a->max.mag,
			    stype_name(a->type));
		if (a->min.set && !a->min.neg && a->min.mag >
		    stype_umax(a->type))
			ERRL(ld, a->min.loc, "invalid range: min (%" PRIu64
			    ") exceeds %s maximum", a->min.mag,
			    stype_name(a->type));
		if (a->max.set && !a->max.neg && a->max.mag >
		    stype_umax(a->type))
			ERRL(ld, a->max.loc, "invalid range: max (%" PRIu64
			    ") exceeds %s maximum", a->max.mag,
			    stype_name(a->type));
		if (a->min.set && a->max.set && !a->min.neg && !a->max.neg &&
		    a->min.mag > a->max.mag)
			ERRL(ld, a->min.loc, "invalid range: min (%" PRIu64
			    ") > max (%" PRIu64 ")", a->min.mag, a->max.mag);
	} else if (isint) {
		int64_t lo = stype_smin(a->type), hi = stype_smax(a->type);

		if (a->min.set && (a->min.neg ? a->min.mag >
		    (uint64_t)INT64_MAX + 1 || snum_s(&a->min) < lo :
		    a->min.mag > (uint64_t)hi))
			ERRL(ld, a->min.loc, "invalid range: min outside %s "
			    "range", stype_name(a->type));
		if (a->max.set && (a->max.neg ? snum_s(&a->max) < lo :
		    a->max.mag > (uint64_t)hi))
			ERRL(ld, a->max.loc, "invalid range: max outside %s "
			    "range", stype_name(a->type));
		if (a->min.set && a->max.set &&
		    snum_s(&a->min) > snum_s(&a->max))
			ERRL(ld, a->min.loc, "invalid range: min (%" PRId64
			    ") > max (%" PRId64 ")", snum_s(&a->min),
			    snum_s(&a->max));
	}
	struct snum *lens[] = { &a->min_len, &a->max_len, &a->exact_len,
	    &a->min_count, &a->max_count };
	for (size_t i = 0; i < nitems(lens); i++)
		if (lens[i]->set && (lens[i]->neg || lens[i]->mag > UINT32_MAX))
			ERRL(ld, lens[i]->loc, "invalid range: value out of "
			    "range 0..4294967295%s", "");
	if (a->min_len.set && a->max_len.set && a->min_len.mag > a->max_len.mag)
		ERRL(ld, a->min_len.loc, "invalid range: min-len (%" PRIu64
		    ") > max-len (%" PRIu64 ")", a->min_len.mag,
		    a->max_len.mag);
	if (a->min_count.set && a->max_count.set &&
	    a->min_count.mag > a->max_count.mag)
		ERRL(ld, a->min_count.loc, "invalid range: min-count (%" PRIu64
		    ") > max-count (%" PRIu64 ")", a->min_count.mag,
		    a->max_count.mag);
	if (a->max_count.set && a->max_count.mag == 0)
		ERRL(ld, a->max_count.loc, "invalid range: max-count must be "
		    "at least 1%s", "");
}

static void
check_list(struct ld *ld, struct sop *op, struct slist *l, const char *what)
{

	if (!l->present)
		return;
	l->attrs = xcalloc(l->n, sizeof(*l->attrs));
	l->required = xcalloc(l->n, sizeof(*l->required));
	for (size_t i = 0; i < l->n; i++) {
		if (l->names[i] == NULL)
			continue;
		for (size_t j = 0; j < i; j++)
			dupname(ld, "attribute in list", l->names[i],
			    l->locs[i], l->names[j], l->locs[j]);
		if (op->set == NULL)
			continue;
		l->attrs[i] = find_attr(op->set, l->names[i]);
		if (l->attrs[i] == NULL)
			ERRL(ld, l->locs[i], "undefined attribute '%s' in "
			    "attribute-set '%s' (%s)", l->names[i],
			    op->set->name, what);
		else
			l->required[i] = l->attrs[i]->required;
	}
	if (l->nreq > 0) {
		for (size_t i = 0; i < l->n; i++)
			l->required[i] = false;
		for (size_t j = 0; j < l->nreq; j++) {
			size_t i;

			if (l->req_names[j] == NULL)
				continue;
			for (i = 0; i < l->n; i++)
				if (l->names[i] != NULL &&
				    strcmp(l->names[i], l->req_names[j]) == 0)
					break;
			if (i == l->n)
				ERRL(ld, l->req_locs[j], "required attribute "
				    "'%s' is not listed in 'attributes'",
				    l->req_names[j]);
			else
				l->required[i] = true;
		}
	}
}

/*
 * Generated identifiers that could collide.  C keeps struct and enum tags,
 * ordinary identifiers (functions, objects, typedefs) and macros apart, so
 * each is checked within its own name space: a set and an operation may
 * share a name, but an operation "put-key" and the builder of attribute
 * "key" may not.  Everything gen_c.c names is listed here.
 */
enum { NS_TAG, NS_ORD, NS_MACRO };

struct ident {
	int		 ns;
	char		*id;
	struct loc	 loc;
	const char	*what;
	const char	*owner;		/* the spec name it comes from */
};

struct idents {
	struct ident	*v;
	size_t		 n;
	const char	*owner;		/* of the identifiers being added */
};

static void __printflike(5, 6)
ident_add(struct idents *is, int ns, struct loc l, const char *what,
    const char *fmt, ...)
{
	va_list ap;
	char *id;

	va_start(ap, fmt);
	if (vasprintf(&id, fmt, ap) == -1)
		id = xstrdup("");
	va_end(ap);
	if (ns == NS_MACRO)
		for (char *c = id; *c != '\0'; c++)
			if (*c >= 'a' && *c <= 'z')
				*c = (char)(*c - 'a' + 'A');
	is->v = xreallocarray(is->v, is->n + 1, sizeof(*is->v));
	is->v[is->n].ns = ns;
	is->v[is->n].id = id;
	is->v[is->n].loc = l;
	is->v[is->n].what = what;
	is->v[is->n].owner = is->owner;
	is->n++;
}

/* A struct with its tables and functions: a set, or an op's list. */
static void
ident_obj(struct idents *is, struct loc l, const char *what, const char *tag,
    const char *sfx)
{
	static const char *const fn[] = { "policy", "parser", "parse",
	    "put_fields", "np", "pol" };

	ident_add(is, NS_TAG, l, what, "%s%s", tag, sfx);
	for (size_t i = 0; i < nitems(fn); i++)
		ident_add(is, NS_ORD, l, what, "%s%s_%s", tag, sfx, fn[i]);
}

static void
check_idents(struct ld *ld)
{
	static const char *const fam_tag[] = { "client", "cmds", "mcgrps" };
	static const char *const fam_ord[] = { "client_init", "client_fini",
	    "client_init_info", "register", "family_def" };
	static const char *const fam_mac[] = { "family_name", "family_version",
	    "family_id", "mcgrp_count" };
	static const char *const st_tag[] = { "cbs", "server_cbs", "ctx",
	    "sctx" };
	static const char *const st_ord[] = { "open", "send", "accept",
	    "server_send", "stream_open", "on_open", "on_data", "on_hclose",
	    "on_close", "on_writable", "tramp", "stramp", "s_on_data",
	    "s_on_hclose", "s_on_close", "s_on_writable" };
	struct spec *s = ld->s;
	struct idents is = { 0 };
	struct loc top = { 1, 1 };
	struct { struct loc a, b; } *seenv = NULL;
	size_t nseen = 0;

	is.owner = "";
	for (size_t i = 0; i < nitems(fam_tag); i++)
		ident_add(&is, NS_TAG, top, "family", "%s", fam_tag[i]);
	for (size_t i = 0; i < nitems(fam_ord); i++)
		ident_add(&is, NS_ORD, top, "family", "%s", fam_ord[i]);
	for (size_t i = 0; i < nitems(fam_mac); i++)
		ident_add(&is, NS_MACRO, top, "family", "%s", fam_mac[i]);
	for (size_t i = 0; i < s->ndefs; i++) {
		struct sdef *d = &s->defs[i];

		if (d->cname == NULL)
			continue;
		is.owner = d->name;
		if (d->type == D_CONST) {
			ident_add(&is, NS_MACRO, d->loc, "definition", "%s",
			    d->cname);
			continue;
		}
		ident_add(&is, NS_ORD, d->loc, "definition", "%s_values",
		    d->cname);
		ident_add(&is, NS_ORD, d->loc, "definition", "%s_vals",
		    d->cname);
		for (size_t k = 0; k < d->nentries; k++)
			if (d->entries[k].cname != NULL) {
				is.owner = d->entries[k].name;
				ident_add(&is, NS_MACRO, d->entries[k].loc,
				    "entry", "%s_%s", d->cname,
				    d->entries[k].cname);
			}
	}
	for (size_t i = 0; i < s->nsets; i++) {
		struct sset *set = &s->sets[i];
		bool fam;

		if (set->cname == NULL)
			continue;
		/* The family-named set drops its name from attribute ids. */
		fam = s->name != NULL && strcmp(set->name, s->name) == 0;
		is.owner = set->name;
		ident_obj(&is, set->loc, "attribute-set", set->cname, "");
		ident_add(&is, NS_TAG, set->loc, "attribute-set", "%s_attrs",
		    set->cname);
		if (fam)
			ident_add(&is, NS_MACRO, set->loc, "attribute-set",
			    "a_max");
		else
			ident_add(&is, NS_MACRO, set->loc, "attribute-set",
			    "%s_a_max", set->cname);
		for (size_t k = 0; k < set->nattrs; k++) {
			struct sattr *a = &set->attrs[k];

			if (a->cname == NULL)
				continue;
			is.owner = a->name;
			if (fam) {
				ident_add(&is, NS_ORD, a->loc, "attribute",
				    "put_%s", a->cname);
				ident_add(&is, NS_MACRO, a->loc, "attribute",
				    "a_%s", a->cname);
			} else {
				ident_add(&is, NS_ORD, a->loc, "attribute",
				    "%s_put_%s", set->cname, a->cname);
				ident_add(&is, NS_MACRO, a->loc, "attribute",
				    "%s_a_%s", set->cname, a->cname);
			}
		}
	}
	for (size_t i = 0; i < s->nops; i++) {
		struct sop *op = &s->ops[i];
		const char *c = op->cname, *w = "operation";
		bool call = op->has_do && op->stream == NULL;

		if (c == NULL)
			continue;
		is.owner = op->name;
		ident_add(&is, NS_MACRO, op->loc, w, "cmd_%s", c);
		if (op->do_req.present)
			ident_obj(&is, op->loc, w, c, "_req");
		if (op->do_rsp.present)
			ident_obj(&is, op->loc, w, c, "_rsp");
		if (op->dump_req.present)
			ident_obj(&is, op->loc, w, c, "_dump_req");
		if (op->dump_rsp.present)
			ident_obj(&is, op->loc, w, c, "_dump_rsp");
		if (op->event.present)
			ident_obj(&is, op->loc, w, c, "_ntf");
		if (call) {
			ident_add(&is, NS_ORD, op->loc, w, "%s", c);
			ident_add(&is, NS_ORD, op->loc, w, "%s_async", c);
			ident_add(&is, NS_ORD, op->loc, w, "%s_cb", c);
			ident_add(&is, NS_ORD, op->loc, w, "%s_doit", c);
			ident_add(&is, NS_ORD, op->loc, w, "%s_doit_t", c);
		}
		if (call && op->do_rsp.present) {
			ident_add(&is, NS_ORD, op->loc, w, "%s_rsp_free", c);
			ident_add(&is, NS_ORD, op->loc, w, "%s_reply", c);
		}
		if (op->has_dump) {
			ident_add(&is, NS_ORD, op->loc, w, "%s_dump", c);
			ident_add(&is, NS_ORD, op->loc, w, "%s_dumpit", c);
			ident_add(&is, NS_ORD, op->loc, w, "%s_dumpit_t", c);
		}
		if (op->dump_rsp.present) {
			ident_add(&is, NS_ORD, op->loc, w, "%s_dump_next", c);
			ident_add(&is, NS_ORD, op->loc, w, "%s_dump_reply", c);
		}
		if (op->has_event)
			ident_add(&is, NS_ORD, op->loc, w, "%s_notify", c);
	}
	for (size_t i = 0; i < s->ngrps; i++) {
		struct sgrp *g = &s->grps[i];

		if (g->cname == NULL)
			continue;
		is.owner = g->name;
		ident_add(&is, NS_MACRO, g->loc, "group", "mcgrp_%s", g->cname);
		ident_add(&is, NS_TAG, g->loc, "group", "%s_handlers", g->cname);
		ident_add(&is, NS_TAG, g->loc, "group", "%s_sub", g->cname);
		ident_add(&is, NS_ORD, g->loc, "group", "%s_subscribe",
		    g->cname);
		ident_add(&is, NS_ORD, g->loc, "group", "%s_unsubscribe",
		    g->cname);
		ident_add(&is, NS_ORD, g->loc, "group", "%s_ntf_cb", g->cname);
	}
	for (size_t i = 0; i < s->nstreams; i++) {
		struct sstream *st = &s->streams[i];

		if (st->cname == NULL)
			continue;
		is.owner = st->name;
		for (size_t k = 0; k < nitems(st_tag); k++)
			ident_add(&is, NS_TAG, st->loc, "stream", "%s_%s",
			    st->cname, st_tag[k]);
		for (size_t k = 0; k < nitems(st_ord); k++)
			ident_add(&is, NS_ORD, st->loc, "stream", "%s_%s",
			    st->cname, st_ord[k]);
	}
	/*
	 * The same identifier from two places.  Two things of one kind and
	 * one name are duplicates, reported as such already; and a pair of
	 * places is reported once, for its first identifier.
	 */
	for (size_t i = 0; i < is.n; i++)
		for (size_t j = 0; j < i; j++) {
			const struct ident *x = &is.v[i], *y = &is.v[j];
			bool seen = false;

			if (x->ns != y->ns || strcmp(x->id, y->id) != 0 ||
			    (strcmp(x->what, y->what) == 0 &&
			    strcmp(x->owner, y->owner) == 0) ||
			    (x->loc.line == y->loc.line &&
			    x->loc.col == y->loc.col))
				continue;
			for (size_t k = 0; k < nseen && !seen; k++)
				seen = memcmp(&seenv[k].a, &x->loc,
				    sizeof(x->loc)) == 0 && memcmp(&seenv[k].b,
				    &y->loc, sizeof(y->loc)) == 0;
			if (seen)
				continue;
			seenv = xreallocarray(seenv, nseen + 1, sizeof(*seenv));
			seenv[nseen].a = x->loc;
			seenv[nseen++].b = y->loc;
			/* Report at the later of the two places. */
			if (x->loc.line < y->loc.line ||
			    (x->loc.line == y->loc.line &&
			    x->loc.col < y->loc.col)) {
				const struct ident *t = x;

				x = y;
				y = t;
			}
			ERRL(ld, x->loc, "%s generates C identifier '%s_%s', "
			    "which collides with the %s at %d:%d", x->what,
			    x->ns == NS_MACRO ? s->uprefix : s->prefix, x->id,
			    y->what, y->loc.line, y->loc.col);
		}
	for (size_t i = 0; i < is.n; i++)
		free(is.v[i].id);
	free(is.v);
	free(seenv);
}

static void
validate(struct ld *ld)
{
	struct spec *s = ld->s;

	/* Definitions. */
	for (size_t i = 0; i < s->ndefs; i++) {
		struct sdef *d = &s->defs[i];

		for (size_t j = 0; j < i; j++)
			dupname(ld, "definition", d->name, d->loc,
			    s->defs[j].name, s->defs[j].loc);
		for (size_t k = 0; k < d->nentries; k++) {
			for (size_t j = 0; j < k; j++) {
				dupname(ld, "entry", d->entries[k].name,
				    d->entries[k].loc, d->entries[j].name,
				    d->entries[j].loc);
				if (d->entries[k].value == d->entries[j].value)
					ERRL(ld, d->entries[k].loc,
					    "%s %" PRIu64
					    " already used by '%s' (%d:%d)",
					    d->type == D_FLAGS ? "flag bit" :
					    "enum value", d->entries[k].value,
					    d->entries[j].name != NULL ?
					    d->entries[j].name : "?",
					    d->entries[j].loc.line,
					    d->entries[j].loc.col);
			}
		}
		if (d->type == D_CONST && d->value.set && d->value.neg &&
		    d->value.mag > (uint64_t)INT64_MAX + 1)
			ERRL(ld, d->value.loc, "const out of range%s", "");
	}
	/* Attribute sets. */
	for (size_t i = 0; i < s->nsets; i++) {
		struct sset *set = &s->sets[i];

		for (size_t j = 0; j < i; j++)
			dupname(ld, "attribute-set", set->name, set->loc,
			    s->sets[j].name, s->sets[j].loc);
		for (size_t k = 0; k < set->nattrs; k++) {
			struct sattr *a = &set->attrs[k];

			if (a->cname != NULL && is_c_keyword(a->cname))
				ERRL(ld, a->loc, "attribute name '%s' is a C "
				    "keyword", a->name);
			if (a->name != NULL && strncmp(a->name, "has-", 4) == 0)
				for (size_t j = 0; j < set->nattrs; j++)
					if (set->attrs[j].name != NULL &&
					    strcmp(set->attrs[j].name,
					    a->name + 4) == 0)
						ERRL(ld, a->loc, "attribute "
						    "'%s' collides with the "
						    "presence flag of '%s'",
						    a->name, a->name + 4);
			for (size_t j = 0; j < k; j++) {
				dupname(ld, "attribute", a->name, a->loc,
				    set->attrs[j].name, set->attrs[j].loc);
				if (a->value == set->attrs[j].value)
					ERRL(ld, a->value_loc, "attribute id %"
					    PRIu32 " already used by '%s' "
					    "(%d:%d)", a->value,
					    set->attrs[j].name != NULL ?
					    set->attrs[j].name : "?",
					    set->attrs[j].loc.line,
					    set->attrs[j].loc.col);
			}
			check_attr(ld, a);
		}
	}
	/* Groups. */
	for (size_t i = 0; i < s->ngrps; i++)
		for (size_t j = 0; j < i; j++)
			dupname(ld, "multicast group", s->grps[i].name,
			    s->grps[i].loc, s->grps[j].name, s->grps[j].loc);
	/* Operations. */
	for (size_t i = 0; i < s->nops; i++) {
		struct sop *op = &s->ops[i];

		for (size_t j = 0; j < i; j++) {
			dupname(ld, "operation", op->name, op->loc,
			    s->ops[j].name, s->ops[j].loc);
			if (op->value == s->ops[j].value)
				ERRL(ld, op->value_loc, "command id %" PRIu32
				    " already used by '%s' (%d:%d)", op->value,
				    s->ops[j].name != NULL ? s->ops[j].name :
				    "?", s->ops[j].loc.line, s->ops[j].loc.col);
		}
		if (op->set_name != NULL &&
		    (op->set = find_set(s, op->set_name)) == NULL)
			ERRL(ld, op->set_loc, "undefined attribute-set '%s'",
			    op->set_name);
		check_list(ld, op, &op->do_req, "do request");
		check_list(ld, op, &op->do_rsp, "do reply");
		check_list(ld, op, &op->dump_req, "dump request");
		check_list(ld, op, &op->dump_rsp, "dump reply");
		check_list(ld, op, &op->event, "event");
		if (op->has_event && (op->has_do || op->has_dump))
			ERRL(ld, op->loc, "operation '%s': 'event' cannot be "
			    "combined with 'do' or 'dump'",
			    op->name != NULL ? op->name : "?");
		if (op->has_event && op->mcgrp_name == NULL)
			ERRL(ld, op->loc, "event '%s' requires 'mcgrp'",
			    op->name != NULL ? op->name : "?");
		if (op->mcgrp_name != NULL) {
			if (!op->has_event)
				ERRL(ld, op->mcgrp_loc, "'mcgrp' requires "
				    "'event'%s", "");
			for (size_t g = 0; g < s->ngrps; g++)
				if (s->grps[g].name != NULL && strcmp(
				    s->grps[g].name, op->mcgrp_name) == 0)
					op->mcgrp = &s->grps[g];
			if (op->mcgrp == NULL)
				ERRL(ld, op->mcgrp_loc, "undefined multicast "
				    "group '%s'", op->mcgrp_name);
		}
	}
	/* Streams. */
	for (size_t i = 0; i < s->nstreams; i++) {
		struct sstream *st = &s->streams[i];

		for (size_t j = 0; j < i; j++)
			dupname(ld, "stream", st->name, st->loc,
			    s->streams[j].name, s->streams[j].loc);
		for (size_t k = 0; st->open_name != NULL && k < s->nops; k++)
			if (s->ops[k].name != NULL &&
			    strcmp(s->ops[k].name, st->open_name) == 0)
				st->open = &s->ops[k];
		if (st->open_name != NULL && st->open == NULL)
			ERRL(ld, st->open_loc, "undefined operation '%s'",
			    st->open_name);
		else if (st->open != NULL) {
			if (st->open->stream != NULL)
				ERRL(ld, st->open_loc, "operation '%s' already "
				    "opens stream '%s'", st->open_name,
				    st->open->stream->name);
			else
				st->open->stream = st;
			if (st->open->has_dump || st->open->has_event)
				ERRL(ld, st->open_loc, "operation '%s' opens a "
				    "stream and must not have 'dump' or "
				    "'event'", st->open_name);
		}
		if (st->payload_name != NULL) {
			st->up = st->down = find_set(s, st->payload_name);
			if (st->up == NULL)
				ERRL(ld, st->payload_loc, "undefined "
				    "attribute-set '%s'", st->payload_name);
		}
		if (st->up_name != NULL &&
		    (st->up = find_set(s, st->up_name)) == NULL)
			ERRL(ld, st->up_loc, "undefined attribute-set '%s'",
			    st->up_name);
		if (st->down_name != NULL &&
		    (st->down = find_set(s, st->down_name)) == NULL)
			ERRL(ld, st->down_loc, "undefined attribute-set '%s'",
			    st->down_name);
		if (st->dir == DIR_UP && st->down_name != NULL)
			ERRL(ld, st->down_loc, "client-to-server stream has no "
			    "'payload-down'%s", "");
		if (st->dir == DIR_DOWN && st->up_name != NULL)
			ERRL(ld, st->up_loc, "server-to-client stream has no "
			    "'payload-up'%s", "");
		resolve_num(ld, &st->credit);
		if (st->credit.set && st->credit.ref != NULL &&
		    (st->credit.neg || st->credit.mag > INT32_MAX))
			ERRL(ld, st->credit.loc, "initial-credit out of range "
			    "0..%d", INT32_MAX);
	}
	for (size_t i = 0; i < s->nops; i++) {
		struct sop *op = &s->ops[i];

		if (!op->has_do && !op->has_dump && !op->has_event &&
		    op->stream == NULL)
			ERRL(ld, op->loc, "operation '%s' has no 'do', 'dump', "
			    "'event' or stream", op->name != NULL ? op->name :
			    "?");
	}
	check_idents(ld);
}

static void
set_cnames(struct spec *s)
{

	for (size_t i = 0; i < s->ndefs; i++) {
		if (s->defs[i].name != NULL)
			s->defs[i].cname = mangle(s->defs[i].name);
		for (size_t k = 0; k < s->defs[i].nentries; k++)
			if (s->defs[i].entries[k].name != NULL)
				s->defs[i].entries[k].cname =
				    mangle(s->defs[i].entries[k].name);
	}
	for (size_t i = 0; i < s->nsets; i++) {
		if (s->sets[i].name != NULL)
			s->sets[i].cname = mangle(s->sets[i].name);
		for (size_t k = 0; k < s->sets[i].nattrs; k++)
			if (s->sets[i].attrs[k].name != NULL)
				s->sets[i].attrs[k].cname =
				    mangle(s->sets[i].attrs[k].name);
	}
	for (size_t i = 0; i < s->nops; i++)
		if (s->ops[i].name != NULL)
			s->ops[i].cname = mangle(s->ops[i].name);
	for (size_t i = 0; i < s->ngrps; i++)
		if (s->grps[i].name != NULL)
			s->grps[i].cname = mangle(s->grps[i].name);
	for (size_t i = 0; i < s->nstreams; i++)
		if (s->streams[i].name != NULL)
			s->streams[i].cname = mangle(s->streams[i].name);
}

static bool
family_name_ok(const char *n, bool builtin)
{
	size_t len = strlen(n);

	if (len == 0 || len > 63 || n[0] < 'a' || n[0] > 'z')
		return (false);
	for (size_t i = 1; i < len; i++)
		if (!((n[i] >= 'a' && n[i] <= 'z') ||
		    (n[i] >= '0' && n[i] <= '9') || n[i] == '_' ||
		    n[i] == '.' || n[i] == '-'))
			return (false);
	if (!builtin && (strcmp(n, "ctrl") == 0 ||
	    strncmp(n, "cblink.", 7) == 0))
		return (false);
	return (true);
}

static bool
cident_ok(const char *n)
{

	if (!((n[0] >= 'a' && n[0] <= 'z') || n[0] == '_'))
		return (false);
	for (const char *p = n + 1; *p != '\0'; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
		    *p == '_'))
			return (false);
	return (strlen(n) <= 32);
}

#define	LOAD_SEQ(key, arr, count, fn) do {				\
	if ((v = ymap_get(root, key)) != NULL &&			\
	    want_type(&ld, v, Y_SEQ, key)) {				\
		s->arr = xcalloc(v->nitems, sizeof(*s->arr));		\
		s->count = v->nitems;					\
		for (size_t i = 0; i < v->nitems; i++)			\
			fn;						\
	}								\
} while (0)

struct spec *
spec_load(const struct ynode *root, const char *file, bool builtin,
    struct diags *d)
{
	static const char *const ck[] = { "name", "version", "doc", "c-prefix",
	    "definitions", "attribute-sets", "operations", "mcast-groups",
	    "streams", "fixed-id", NULL };
	struct ld ld = { .d = d, .builtin = builtin };
	const struct ynode *v;
	struct spec *s;
	uint32_t next = 1;

	s = xcalloc(1, sizeof(*s));
	s->file = file;
	ld.s = s;
	if (!want_type(&ld, root, Y_MAP, "a spec")) {
		spec_free(s);
		return (NULL);
	}
	check_keys(&ld, root, ck);
	if ((v = need(&ld, root, "name")) != NULL &&
	    (s->name = get_str(&ld, v, "family name")) != NULL &&
	    !family_name_ok(s->name, builtin))
		ERRN(&ld, v, "invalid family name '%s' (expected "
		    "[a-z][a-z0-9_.-]*, at most 63 characters; 'ctrl' and "
		    "'cblink.*' are reserved)", s->name);
	if ((v = need(&ld, root, "version")) != NULL)
		(void)get_u32(&ld, v, 1, UINT32_MAX, &s->version);
	if ((v = ymap_get(root, "doc")) != NULL)
		s->doc = get_str(&ld, v, "doc");
	if ((v = ymap_get(root, "c-prefix")) != NULL) {
		if ((s->prefix = get_str(&ld, v, "c-prefix")) != NULL &&
		    !cident_ok(s->prefix))
			ERRN(&ld, v, "invalid c-prefix '%s' (expected a "
			    "lowercase C identifier)", s->prefix);
	} else if (s->name != NULL)
		s->prefix = mangle(s->name);
	if ((v = ymap_get(root, "fixed-id")) != NULL) {
		if (!builtin)
			ERRL(&ld, kloc(root, "fixed-id"), "'fixed-id' is "
			    "reserved for built-in families (cblink-gen -B)%s",
			    "");
		else if (get_u32(&ld, v, 0, 65535, &s->fixed_id))
			s->has_fixed_id = true;
	}
	LOAD_SEQ("definitions", defs, ndefs,
	    load_def(&ld, v->items[i], &s->defs[i]));
	if (need(&ld, root, "attribute-sets") != NULL)
		LOAD_SEQ("attribute-sets", sets, nsets,
		    load_set(&ld, v->items[i], &s->sets[i]));
	if (need(&ld, root, "operations") != NULL)
		LOAD_SEQ("operations", ops, nops,
		    load_op(&ld, v->items[i], &s->ops[i], &next));
	LOAD_SEQ("mcast-groups", grps, ngrps,
	    load_grp(&ld, v->items[i], &s->grps[i]));
	LOAD_SEQ("streams", streams, nstreams,
	    load_stream(&ld, v->items[i], &s->streams[i]));
	if (s->prefix != NULL)
		s->uprefix = upper(s->prefix);
	set_cnames(s);
	validate(&ld);
	if (d->n > 0) {
		spec_free(s);
		return (NULL);
	}
	return (s);
}

static void
list_free(struct slist *l)
{

	for (size_t i = 0; i < l->n; i++)
		free(l->names[i]);
	for (size_t i = 0; i < l->nreq; i++)
		free(l->req_names[i]);
	free(l->names);
	free(l->locs);
	free(l->attrs);
	free(l->req_names);
	free(l->req_locs);
	free(l->required);
}

static void
num_free(struct snum *n)
{

	free(n->ref);
}

void
spec_free(struct spec *s)
{

	if (s == NULL)
		return;
	for (size_t i = 0; i < s->ndefs; i++) {
		struct sdef *d = &s->defs[i];

		for (size_t k = 0; k < d->nentries; k++) {
			free(d->entries[k].name);
			free(d->entries[k].cname);
			free(d->entries[k].doc);
		}
		free(d->entries);
		free(d->name);
		free(d->cname);
		free(d->doc);
		num_free(&d->value);
	}
	for (size_t i = 0; i < s->nsets; i++) {
		struct sset *set = &s->sets[i];

		for (size_t k = 0; k < set->nattrs; k++) {
			struct sattr *a = &set->attrs[k];

			free(a->name);
			free(a->cname);
			free(a->doc);
			free(a->nested_name);
			free(a->enum_name);
			num_free(&a->min);
			num_free(&a->max);
			num_free(&a->min_len);
			num_free(&a->max_len);
			num_free(&a->exact_len);
			num_free(&a->min_count);
			num_free(&a->max_count);
		}
		free(set->attrs);
		free(set->name);
		free(set->cname);
		free(set->doc);
	}
	for (size_t i = 0; i < s->nops; i++) {
		struct sop *op = &s->ops[i];

		free(op->name);
		free(op->cname);
		free(op->doc);
		free(op->set_name);
		free(op->mcgrp_name);
		list_free(&op->do_req);
		list_free(&op->do_rsp);
		list_free(&op->dump_req);
		list_free(&op->dump_rsp);
		list_free(&op->event);
	}
	for (size_t i = 0; i < s->ngrps; i++) {
		free(s->grps[i].name);
		free(s->grps[i].cname);
		free(s->grps[i].doc);
	}
	for (size_t i = 0; i < s->nstreams; i++) {
		struct sstream *st = &s->streams[i];

		free(st->name);
		free(st->cname);
		free(st->doc);
		free(st->open_name);
		free(st->payload_name);
		free(st->up_name);
		free(st->down_name);
		num_free(&st->credit);
	}
	free(s->defs);
	free(s->sets);
	free(s->ops);
	free(s->grps);
	free(s->streams);
	free(s->name);
	free(s->prefix);
	free(s->uprefix);
	free(s->doc);
	free(s);
}
