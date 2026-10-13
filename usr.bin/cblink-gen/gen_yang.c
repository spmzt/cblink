/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * C from a YANG schema: the header of structs, one a container, list
 * entry, rpc or action input and output, notification and structure,
 * and one a module for its top-level data (PLAN-SDN-YANG 1.6.1), for
 * the modules named and those whose trees they add to.  The shape is
 * the YAML generator's: a container is a pointer, NULL when absent; a
 * list or leaf-list is { n, v }; a scalar leaf other than a key has a
 * has_ flag, a string or bytes is absent when NULL; a
 * choice is an enum saying its case, the members of every case beside
 * it.  Names are the module's, then the path, '-' and '.' made '_'; a
 * node another module adds takes that module's prefix.
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "gen.h"
#include "schema.h"

struct yg {
	struct schema	*s;
	struct diags	*d;
	struct buf	 enums;		/* enums and bit positions */
	struct buf	 unions;	/* union types, inner ones first */
	struct buf	 fwd;		/* struct declarations */
	struct buf	 structs;	/* struct bodies */
	struct buf	 codec;		/* their encoders and decoders */
	char		**names;	/* every global name, for collisions */
	size_t		 nnames;
};

/* Members are named per struct; these may not be. */
static const char *const keywords[] = {
	"alignas", "alignof", "auto", "bool", "break", "case", "char",
	"const", "constexpr", "continue", "default", "do", "double", "else",
	"enum", "extern", "false", "float", "for", "goto", "if", "inline",
	"int", "long", "nullptr", "register", "restrict", "return", "short",
	"signed", "sizeof", "static", "static_assert", "struct", "switch",
	"thread_local", "true", "typedef", "typeof", "typeof_unqual",
	"union", "unsigned", "void", "volatile", "while",
};

static void
mangle(struct buf *b, const char *s, bool upper)
{

	for (; *s != '\0'; s++) {
		char c = *s;

		if (!isalnum((unsigned char)c))
			c = '_';
		else if (upper)
			c = (char)toupper((unsigned char)c);
		buf_add(b, &c, 1);
	}
}

static void
name_add(struct yg *g, const char *name)
{

	g->names = xreallocarray(g->names, g->nnames + 1, sizeof(*g->names));
	g->names[g->nnames++] = xstrdup(name);
}

/* The data node above n, past choices and cases; NULL at the top. */
static const struct snode *
data_parent(const struct snode *n)
{
	const struct snode *p = n->parent;

	while (p != NULL && (p->kind == SN_CHOICE || p->kind == SN_CASE))
		p = p->parent;
	return (p);
}

/* The module whose tree n is in, and that of its parent's step. */
static const struct smodule *
parent_module(const struct snode *n)
{
	const struct snode *p = data_parent(n);

	if (p != NULL)
		return (p->module);
	return (n->in != NULL ? n->in->module : n->module);
}

/* n's step: its name, after its module's prefix if its parent's differs. */
static void
step(struct buf *b, const struct snode *n, bool upper)
{

	if (n->module != parent_module(n)) {
		mangle(b, n->module->prefix, upper);
		buf_puts(b, "_");
	}
	mangle(b, n->name, upper);
}

/* The C name of the struct for n, or the prefix of names under it. */
static void
cname(struct buf *b, const struct snode *n, bool upper)
{
	const struct snode *p = data_parent(n);

	if (p != NULL)
		cname(b, p, upper);
	else if (n->in != NULL) {
		mangle(b, n->in->module->name, upper);
		buf_puts(b, "_");
		mangle(b, n->in->arg, upper);
	} else
		mangle(b, n->module->name, upper);
	buf_puts(b, "_");
	step(b, n, upper);
}

/* A member's name within its struct. */
static void
member(struct buf *b, const struct snode *n)
{
	size_t start = b->len;

	step(b, n, false);
	for (size_t i = 0; i < nitems(keywords); i++)
		if (strcmp(b->p + start, keywords[i]) == 0) {
			buf_puts(b, "_");
			break;
		}
}

static bool
scalar(const struct sntype *t)
{

	switch (t->base) {
	case ST_BINARY:
	case ST_BITS:
	case ST_EMPTY:
	case ST_INSTANCEID:
	case ST_STRING:
		return (false);
	case ST_LEAFREF:
		return (t->real != NULL && scalar(t->real));
	default:
		return (true);
	}
}

static void	ctype(struct yg *g, struct buf *b, const struct sntype *t,
		    const char *name, const char *uname);

/* An enumeration's enum, or a bits' positions, named name/uname. */
static void
items(struct yg *g, const struct sntype *t, const char *name,
    const char *uname)
{
	struct buf c;

	if (t->base == ST_ENUMERATION)
		buf_printf(&g->enums, "enum %s {\n", name);
	name_add(g, name);
	for (size_t i = 0; i < t->nitems; i++) {
		buf_init(&c);
		buf_printf(&c, "%s_", uname);
		mangle(&c, t->items[i].name, true);
		if (t->base == ST_ENUMERATION)
			buf_printf(&g->enums, "\t%s = %" PRId64 ",\n", c.p,
			    t->items[i].value);
		else
			buf_printf(&g->enums, "#define\t%s\t%" PRId64 "u\n",
			    c.p, t->items[i].value);
		name_add(g, c.p);
		buf_free(&c);
	}
	buf_puts(&g->enums, t->base == ST_ENUMERATION ? "};\n\n" : "\n");
}

/* A union's struct: which member is set, and the members. */
static void
union_type(struct yg *g, const struct sntype *t, const char *name,
    const char *uname)
{
	struct buf body, mn, mu;

	buf_init(&body);
	for (size_t i = 0; i < t->nmembers; i++) {
		buf_init(&mn);
		buf_init(&mu);
		buf_printf(&mn, "%s_m%zu", name, i);
		buf_printf(&mu, "%s_M%zu", uname, i);
		buf_puts(&body, "\t\t");
		ctype(g, &body, t->members[i], mn.p, mu.p);
		buf_printf(&body, "m%zu;\n", i);
		buf_free(&mn);
		buf_free(&mu);
	}
	buf_printf(&g->unions, "struct %s {\n\tunsigned\t which;\t/* the "
	    "member set, from 0 */\n\tunion {\n%s\t} v;\n};\n\n", name, body.p);
	name_add(g, name);
	buf_free(&body);
}

/*
 * The C type of a value of t, then a space or a tab as the column
 * wants; name and uname name what it needs declared (an enum, a union).
 */
static void
ctype(struct yg *g, struct buf *b, const struct sntype *t, const char *name,
    const char *uname)
{

	switch (t->base) {
	case ST_BINARY:
	case ST_BITS:
	case ST_INSTANCEID:
		if (t->base == ST_BITS)
			items(g, t, name, uname);
		buf_puts(b, "struct cbl_bytes\t ");
		break;
	case ST_BOOLEAN:
	case ST_EMPTY:
		buf_puts(b, "bool\t\t ");
		break;
	case ST_DECIMAL64:
	case ST_INT64:
		buf_puts(b, "int64_t\t\t ");
		break;
	case ST_ENUMERATION:
		items(g, t, name, uname);
		buf_printf(b, "enum %s\t ", name);
		break;
	case ST_IDENTITYREF:
	case ST_UINT64:
		buf_puts(b, "uint64_t\t ");
		break;
	case ST_INT8:
		buf_puts(b, "int8_t\t\t ");
		break;
	case ST_INT16:
		buf_puts(b, "int16_t\t\t ");
		break;
	case ST_INT32:
		buf_puts(b, "int32_t\t\t ");
		break;
	case ST_LEAFREF:
		if (t->real == NULL) {
			diag_add(g->d, 0, 0, "%s: a leafref without its "
			    "target's type", name);
			buf_puts(b, "int\t\t ");
		} else
			ctype(g, b, t->real, name, uname);
		break;
	case ST_STRING:
		buf_puts(b, "const char\t*");
		break;
	case ST_UINT8:
		buf_puts(b, "uint8_t\t\t ");
		break;
	case ST_UINT16:
		buf_puts(b, "uint16_t\t ");
		break;
	case ST_UINT32:
		buf_puts(b, "uint32_t\t ");
		break;
	case ST_UNION:
		union_type(g, t, name, uname);
		buf_printf(b, "struct %s\t ", name);
		break;
	}
}

/* What a value's comment says, if anything. */
static void
type_note(struct buf *b, const struct sntype *t)
{

	if (t->base == ST_LEAFREF && t->real != NULL)
		t = t->real;
	switch (t->base) {
	case ST_DECIMAL64:
		buf_printf(b, "\t/* decimal64, %u fraction digits */",
		    t->fdigits);
		break;
	case ST_IDENTITYREF:
		buf_puts(b, "\t/* identityref: a SID */");
		break;
	case ST_INSTANCEID:
		buf_puts(b, "\t/* instance-identifier, in CBOR */");
		break;
	default:
		break;
	}
}

struct mset {
	char	**v;
	size_t	 n;
};

static void
mset_add(struct yg *g, struct mset *ms, const char *sname, const char *m)
{

	for (size_t i = 0; i < ms->n; i++)
		if (strcmp(ms->v[i], m) == 0) {
			diag_add(g->d, 0, 0, "struct %s: two members named "
			    "%s", sname, m);
			return;
		}
	ms->v = xreallocarray(ms->v, ms->n + 1, sizeof(*ms->v));
	ms->v[ms->n++] = xstrdup(m);
}

static void	emit_struct(struct yg *g, const struct snode *n,
		    const struct snode *first, const char *sname,
		    const char *what);

/* The struct's members for the nodes from first, choices flattened. */
static void
members(struct yg *g, struct buf *b, struct mset *ms, const char *sname,
    const struct snode *first)
{
	struct buf m, tn, tu, cn;
	const struct snode *c;

	for (const struct snode *n = first; n != NULL; n = n->next) {
		buf_init(&m);
		buf_init(&tn);
		buf_init(&tu);
		member(&m, n);
		switch (n->kind) {
		case SN_CONTAINER:
			cname(&tn, n, false);
			buf_printf(b, "\tconst struct %s\t*%s;\n", tn.p, m.p);
			mset_add(g, ms, sname, m.p);
			emit_struct(g, n, n->child, tn.p, NULL);
			break;
		case SN_LIST:
			cname(&tn, n, false);
			buf_printf(b, "\tstruct {\n\t\tsize_t\t\t n;\n\t\tconst "
			    "struct %s\t*v;\n\t}\t\t\t %s;\n", tn.p, m.p);
			mset_add(g, ms, sname, m.p);
			emit_struct(g, n, n->child, tn.p, NULL);
			break;
		case SN_LEAF:
			cname(&tn, n, false);
			cname(&tu, n, true);
			/* A mandatory one too: a filtered read leaves it out. */
			if (scalar(n->type) && !(n->flags & SNF_KEY)) {
				buf_printf(b, "\tbool\t\t\t has_%s;\n", m.p);
				buf_init(&cn);
				buf_printf(&cn, "has_%s", m.p);
				mset_add(g, ms, sname, cn.p);
				buf_free(&cn);
			}
			buf_puts(b, "\t");
			ctype(g, b, n->type, tn.p, tu.p);
			buf_printf(b, "%s;", m.p);
			type_note(b, n->type);
			buf_puts(b, "\n");
			mset_add(g, ms, sname, m.p);
			break;
		case SN_LEAFLIST:
			cname(&tn, n, false);
			cname(&tu, n, true);
			buf_init(&cn);
			ctype(g, &cn, n->type, tn.p, tu.p);
			/* A string's "const char\t*" wants a const pointer. */
			if (cn.p[cn.len - 1] == '*')
				buf_printf(b, "\tstruct {\n\t\tsize_t\t\t n;\n"
				    "\t\t%sconst\t*v;\n", cn.p);
			else
				buf_printf(b, "\tstruct {\n\t\tsize_t\t\t n;\n"
				    "\t\tconst %s*v;\n", cn.p);
			buf_free(&cn);
			buf_printf(b, "\t}\t\t\t %s;", m.p);
			type_note(b, n->type);
			buf_puts(b, "\n");
			mset_add(g, ms, sname, m.p);
			break;
		case SN_CHOICE:
			cname(&tn, n, false);
			cname(&tu, n, true);
			buf_printf(&g->enums, "enum %s {\n\t%s_NONE = 0,\n",
			    tn.p, tu.p);
			name_add(g, tn.p);
			buf_init(&cn);
			buf_printf(&cn, "%s_NONE", tu.p);
			name_add(g, cn.p);
			buf_free(&cn);
			for (c = n->child; c != NULL; c = c->next) {
				buf_init(&cn);
				buf_printf(&cn, "%s_", tu.p);
				mangle(&cn, c->name, true);
				buf_printf(&g->enums, "\t%s,\n", cn.p);
				name_add(g, cn.p);
				buf_free(&cn);
			}
			buf_puts(&g->enums, "};\n\n");
			buf_printf(b, "\tenum %s\t %s;\t/* the case given */\n",
			    tn.p, m.p);
			mset_add(g, ms, sname, m.p);
			for (c = n->child; c != NULL; c = c->next)
				members(g, b, ms, sname, c->child);
			break;
		case SN_ANYDATA:
		case SN_ANYXML:
			buf_printf(b, "\tstruct cbl_bytes\t %s;\t/* %s, in "
			    "CBOR */\n", m.p, snode_kind_name(n->kind));
			mset_add(g, ms, sname, m.p);
			break;
		case SN_ACTION:
		case SN_RPC:
			for (c = n->child; c != NULL; c = c->next) {
				buf_init(&cn);
				cname(&cn, c, false);
				emit_struct(g, c, c->child, cn.p, NULL);
				buf_free(&cn);
			}
			break;
		case SN_NOTIF:
			cname(&tn, n, false);
			emit_struct(g, n, n->child, tn.p, NULL);
			break;
		case SN_CASE:
		case SN_INPUT:
		case SN_OUTPUT:
			break;
		}
		buf_free(&m);
		buf_free(&tn);
		buf_free(&tu);
	}
}

/*
 * The struct sname of n's children from first; n NULL for a module's
 * top-level data or a structure, what saying which.
 */
static void
emit_struct(struct yg *g, const struct snode *n, const struct snode *first,
    const char *sname, const char *what)
{
	struct mset ms = { 0 };
	struct buf b;

	buf_init(&b);
	members(g, &b, &ms, sname, first);
	if (n != NULL)
		what = snode_kind_name(n->kind);
	buf_printf(&g->fwd, "struct %s;\n", sname);
	buf_printf(&g->structs, "/* %s%s%s */\nstruct %s {\n%s%s};\n\n",
	    what, n != NULL && n->kind == SN_LIST ? " entry" : "",
	    n != NULL && (n->flags & SNF_PRESENCE) ? ", presence" : "",
	    sname, b.p != NULL && b.len > 0 ? b.p : "",
	    ms.n == 0 ? "\tchar\t\t\t _empty;\t/* nothing in it */\n" : "");
	name_add(g, sname);
	/* Its value in YANG-CBOR and back, by the schema tables. */
	if (n != NULL || strcmp(what, "structure") == 0)
		buf_printf(&g->codec, "int\t%s_encode(const struct %s *,\n"
		    "\t    struct cbl_ybuf *);\nint\t%s_decode(const void *, "
		    "size_t, struct %s *,\n\t    cbl_yarena *, int, char *, "
		    "size_t);\n", sname, sname, sname, sname);
	for (size_t i = 0; i < ms.n; i++)
		free(ms.v[i]);
	free(ms.v);
	buf_free(&b);
}

static int
strpcmp(const void *a, const void *b)
{

	return (strcmp(*(char *const *)a, *(char *const *)b));
}

int
gen_yang_h(struct schema *s, const char *base, const char *from,
    struct buf *out, struct diags *d)
{
	struct yg g = { .s = s, .d = d };
	struct mset ms = { 0 };
	struct buf nm, guard, gname, scratch;
	size_t errs = d->n;

	buf_init(&g.enums);
	buf_init(&g.unions);
	buf_init(&g.fwd);
	buf_init(&g.structs);
	buf_init(&g.codec);
	for (size_t i = 0; i < s->nmods; i++) {
		struct smodule *m = s->mods[i];

		if (!smodule_emitted(m))
			continue;
		buf_init(&nm);
		mangle(&nm, m->name, false);
		if (m->data != NULL)
			emit_struct(&g, NULL, m->data, nm.p, "data");
		/* Their inputs, outputs and notifications: structs only. */
		buf_init(&scratch);
		members(&g, &scratch, &ms, nm.p, m->rpcs);
		members(&g, &scratch, &ms, nm.p, m->notifs);
		buf_free(&scratch);
		for (size_t j = 0; j < m->nexts; j++) {
			const struct sext *e = &m->exts[j];
			struct buf sn;

			if (e->inherited || e->module != m || e->arg == NULL ||
			    (strcmp(e->ext, "ietf-yang-structure-ext:"
			    "structure") != 0 && strcmp(e->ext,
			    "ietf-restconf:yang-data") != 0))
				continue;
			buf_init(&sn);
			buf_printf(&sn, "%s_", nm.p);
			mangle(&sn, e->arg, false);
			emit_struct(&g, NULL, e->data, sn.p, "structure");
			buf_free(&sn);
		}
		buf_free(&nm);
	}

	/* A name twice: two paths that mangle alike. */
	qsort(g.names, g.nnames, sizeof(*g.names), strpcmp);
	for (size_t i = 1; i < g.nnames; i++)
		if (strcmp(g.names[i], g.names[i - 1]) == 0 &&
		    (i < 2 || strcmp(g.names[i], g.names[i - 2]) != 0))
			diag_add(d, 0, 0, "%s: two schema nodes or values "
			    "with this C name", g.names[i]);

	buf_init(&guard);
	buf_puts(&guard, "_");
	mangle(&guard, base, true);
	buf_puts(&guard, "_H_");
	buf_init(&gname);
	mangle(&gname, base, false);
	buf_printf(out, "/*\n * Generated by cblink-gen %s from %s.  "
	    "Do not edit.\n */\n\n#ifndef %s\n#define\t%s\n\n"
	    "#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n"
	    "#include <cbl_schema.h>\n#include <cblink.h>\n\n"
	    "/* The schema tables, base_schema.c (-m schema). */\n"
	    "extern const struct cbl_yschema %s_schema;\n\n", CBLGEN_VERSION,
	    from, guard.p, guard.p, gname.p);
	if (g.fwd.len > 0)
		buf_printf(out, "%s\n", g.fwd.p);
	if (g.enums.len > 0)
		buf_puts(out, g.enums.p);
	if (g.unions.len > 0)
		buf_puts(out, g.unions.p);
	if (g.structs.len > 0)
		buf_puts(out, g.structs.p);
	if (g.codec.len > 0)
		buf_printf(out, "/*\n * Each struct's value in YANG-CBOR (RFC 9254) "
		    "and back: cbl_yencode(),\n * cbl_ydecode() with its node "
		    "(base_schema.c).\n */\n%s\n", g.codec.p);
	buf_printf(out, "#endif /* !%s */\n", guard.p);

	for (size_t i = 0; i < g.nnames; i++)
		free(g.names[i]);
	free(g.names);
	buf_free(&guard);
	buf_free(&gname);
	buf_free(&g.enums);
	buf_free(&g.unions);
	buf_free(&g.fwd);
	buf_free(&g.structs);
	buf_free(&g.codec);
	return (d->n > errs ? -1 : 0);
}

/*
 * The names above, for the layout the schema tables give of these structs
 * (gen_yschema.c): one rule for both.
 */
void
yc_mangle(struct buf *b, const char *s)
{

	mangle(b, s, false);
}

void
yc_struct(struct buf *b, const struct snode *n)
{

	cname(b, n, false);
}

void
yc_member(struct buf *b, const struct snode *n)
{

	member(b, n);
}

bool
yc_has_flag(const struct snode *n)
{

	return (n->kind == SN_LEAF && scalar(n->type) &&
	    !(n->flags & SNF_KEY));
}
