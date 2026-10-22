/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Tree diagrams (RFC 8340) of YANG modules, from the generator's schema
 * model, as yanglint -f tree prints them, so that the two can be compared
 * line for line.  libyang's printer shows a module's own tree, its rpcs
 * and its notifications compiled: a feature turned off leaves its nodes
 * out, another module's nodes augmented into them carry that module's
 * prefix, and a node's type and if-features are those its statement
 * writes.  The module's augments of other modules' trees it shows as
 * written, a uses as one "-u" line; then its structures, augments of
 * structures and yang-data.  Where the printer's rules for a written node
 * differ from those for a compiled one (the flags of a notification's
 * nodes; a case shown for a choice's shorthand), they are kept, since the
 * point is to print what yanglint prints.  Lines are never wrapped, as
 * yanglint wraps them only when asked.
 */

#include <stdlib.h>
#include <string.h>

#include "gen.h"
#include "schema.h"

#define	MOUNT_POINT	"ietf-yang-schema-mount:mount-point"
#define	STRUCTURE	"ietf-yang-structure-ext:structure"
#define	AUG_STRUCTURE	"ietf-yang-structure-ext:augment-structure"
#define	YANG_DATA	"ietf-restconf:yang-data"

/* The least gap between a node's name and its type, its opts included. */
#define	TYPE_GAP	4

/* A node as one line of the diagram, and the lines under it. */
struct tline {
	const char	*status;	/* "+", "x" deprecated, "o" obsolete */
	const char	*flags;		/* "rw", "ro", "-w", "-x", "-n", ... */
	enum {
		TL_NODE,
		TL_CHOICE,		/* (name) */
		TL_CASE,		/* :(name), without flags */
	}		 shape;
	const char	*prefix;	/* another module's node: its prefix */
	const char	*name;
	const char	*opts;		/* "?", "!", "*" or "" */
	char		*keys;		/* a list's, as its key statement */
	char		*type;
	char		*iff;		/* the if-features, comma separated */
	bool		 icase;		/* a shorthand, shown in a case */
	struct tline	*child;
	struct tline	*next;
};

/*
 * Where a line starts: two spaces in the module's tree, four in the other
 * sections, then three columns a level, with a bar for each level whose
 * node has a sibling still to come.
 */
struct wrap {
	int		 indent;
	unsigned	 depth;
	uint64_t	 bars;
};

static void
tl_free(struct tline *t)
{
	struct tline *next;

	for (; t != NULL; t = next) {
		next = t->next;
		tl_free(t->child);
		free(t->keys);
		free(t->type);
		free(t->iff);
		free(t);
	}
}

static char *
join(char **v, size_t n, const char *sep)
{
	struct buf b;

	if (n == 0)
		return (NULL);
	buf_init(&b);
	for (size_t i = 0; i < n; i++)
		buf_printf(&b, "%s%s", i > 0 ? sep : "", v[i]);
	return (b.p);
}

static char *
type_text(const char *type, const char *path)
{

	if (path != NULL)
		return (xasprintf("-> %s", path));
	return (type != NULL ? xstrdup(type) : NULL);
}

static const char *
status_of(uint32_t flags)
{

	return ((flags & SNF_OBSOLETE) != 0 ? "o" :
	    (flags & SNF_DEPRECATED) != 0 ? "x" : "+");
}

/*
 * A compiled node.  In a structure or yang-data, its extension's plugin
 * gives the flags (override); a mount point shows "mp" wherever it is,
 * found, as the printer finds it, by the node's first extension.
 */
static const char *
cflags(const struct snode *n, const char *override)
{

	if (n->nexts > 0 && strcmp(n->exts[0].ext, MOUNT_POINT) == 0)
		return ("mp");
	if (override != NULL)
		return (override);
	switch (n->kind) {
	case SN_RPC:
	case SN_ACTION:
		return ("-x");
	case SN_NOTIF:
		return ("-n");
	case SN_INPUT:
		return ("-w");
	case SN_OUTPUT:
		return ("ro");
	default:
		break;
	}
	/* An input's nodes are written, an output's read, and the nodes of
	 * a notification, which have no config, are "--". */
	for (const struct snode *p = n->parent; p != NULL; p = p->parent)
		if (p->kind == SN_INPUT)
			return ("-w");
		else if (p->kind == SN_OUTPUT)
			return ("ro");
		else if (p->kind == SN_NOTIF)
			return ("--");
	return ((n->flags & SNF_CONFIG) != 0 ? "rw" : "ro");
}

static const char *
copts(const struct snode *n)
{
	bool optional = (n->flags & SNF_MANDATORY) == 0;

	switch (n->kind) {
	case SN_CHOICE:
	case SN_ANYDATA:
	case SN_ANYXML:
		return (optional ? "?" : "");
	case SN_CONTAINER:
		return ((n->flags & SNF_PRESENCE) != 0 ? "!" : "");
	case SN_LIST:
	case SN_LEAFLIST:
		return ("*");
	case SN_LEAF:
		return (optional && (n->flags & SNF_KEY) == 0 ? "?" : "");
	default:
		return ("");
	}
}

/* libyang's own nodes and an empty input or output are not shown. */
static bool
shown(const struct snode *n)
{

	if ((n->flags & SNF_INTERNAL) != 0)
		return (false);
	return (!((n->kind == SN_INPUT || n->kind == SN_OUTPUT) &&
	    n->child == NULL));
}

/* The lines of compiled nodes, those of module cur without a prefix. */
static struct tline *
from_compiled(const struct snode *n, const struct smodule *cur,
    const char *override)
{
	struct tline *first = NULL, **tail = &first, *t;

	for (; n != NULL; n = n->next) {
		if (!shown(n))
			continue;
		t = *tail = xcalloc(1, sizeof(*t));
		tail = &t->next;
		t->status = status_of(n->flags);
		t->flags = cflags(n, override);
		t->shape = n->kind == SN_CHOICE ? TL_CHOICE :
		    n->kind == SN_CASE ? TL_CASE : TL_NODE;
		if (cur != NULL && n->module != cur)
			t->prefix = n->module->prefix;
		t->name = n->name;
		t->opts = copts(n);
		if (n->kind == SN_LIST && n->nkeys > 0) {
			struct buf b;

			buf_init(&b);
			for (size_t i = 0; i < n->nkeys; i++)
				buf_printf(&b, "%s%s", i > 0 ? " " : "",
				    n->keys[i]->name);
			t->keys = b.p;
		}
		if (n->kind == SN_LEAF || n->kind == SN_LEAFLIST)
			t->type = type_text(n->wtype, n->wpath);
		else if (n->kind == SN_ANYDATA || n->kind == SN_ANYXML)
			t->type = xstrdup(snode_kind_name(n->kind));
		t->iff = join(n->iffeatures, n->niffeatures, ",");
		t->child = from_compiled(n->child, cur, override);
	}
	return (first);
}

/*
 * What a written node inherits, as the printer keeps it: the kind of
 * operation it is in, a status and a config not written on the node
 * itself, and the list whose keys its leaves may be.
 */
struct wcache {
	enum snode_kind	 in;		/* SN_INPUT, SN_OUTPUT, SN_NOTIF, or
					   SN_CONTAINER for none */
	uint32_t	 status;	/* SNF_DEPRECATED, SNF_OBSOLETE or 0 */
	uint32_t	 config;	/* SNF_CONFIG, SNF_STATE or 0: none */
	const struct swnode *list;
};

#define	WSTATUS		(SNF_CURRENT | SNF_DEPRECATED | SNF_OBSOLETE)
#define	WCONFIG		(SNF_CONFIG | SNF_STATE)

static bool
is_key(const struct swnode *list, const char *name)
{
	const char *k;
	size_t len = strlen(name);

	if (list == NULL || list->key == NULL)
		return (false);
	for (k = list->key; (k = strstr(k, name)) != NULL; k += len)
		if ((k == list->key || k[-1] == ' ') &&
		    (k[len] == '\0' || k[len] == ' '))
			return (true);
	return (false);
}

static const char *
wflags(const struct swnode *n, const struct wcache *ca, const char *override)
{
	uint32_t config;

	if (override != NULL)
		return (override);
	if ((!n->uses && n->kind == SN_INPUT) || ca->in == SN_INPUT)
		return ("-w");
	/* A notification's nodes, written, are read as an output's. */
	if ((!n->uses && n->kind == SN_OUTPUT) || ca->in == SN_OUTPUT ||
	    ca->in == SN_NOTIF)
		return ("ro");
	if (n->uses)
		return ("-u");
	if (n->kind == SN_NOTIF)
		return ("-n");
	if (n->kind == SN_RPC || n->kind == SN_ACTION)
		return ("-x");
	config = (n->flags & WCONFIG) != 0 ? n->flags : ca->config;
	return ((config & SNF_CONFIG) != 0 ? "rw" :
	    (config & SNF_STATE) != 0 ? "ro" : "--");
}

static const char *
wopts(const struct swnode *n, const struct wcache *ca)
{
	bool optional = (n->flags & SNF_MANDATORY) == 0;

	if (n->uses)
		return ("");
	switch (n->kind) {
	case SN_CHOICE:
	case SN_ANYDATA:
	case SN_ANYXML:
		return (optional ? "?" : "");
	case SN_CONTAINER:
		return ((n->flags & SNF_PRESENCE) != 0 ? "!" : "");
	case SN_LIST:
	case SN_LEAFLIST:
		return ("*");
	case SN_LEAF:
		return (optional && !is_key(ca->list, n->name) ? "?" : "");
	default:
		return ("");
	}
}

/* A choice's shorthand: what the printer shows in a case of its own. */
static bool
shorthand(const struct swnode *n)
{

	if (n->uses || n->parent == NULL || n->parent->uses ||
	    n->parent->kind != SN_CHOICE)
		return (false);
	switch (n->kind) {
	case SN_ANYDATA:
	case SN_ANYXML:
	case SN_CHOICE:
	case SN_CONTAINER:
	case SN_LEAF:
	case SN_LEAFLIST:
		return (true);
	default:
		return (false);
	}
}

static struct tline *
from_written(const struct swnode *n, const struct wcache *ca,
    const char *override)
{
	struct tline *first = NULL, **tail = &first, *t;
	struct wcache cc;

	for (; n != NULL; n = n->next) {
		if (!n->uses && (n->kind == SN_INPUT ||
		    n->kind == SN_OUTPUT) && n->child == NULL)
			continue;
		t = *tail = xcalloc(1, sizeof(*t));
		tail = &t->next;
		if (!n->uses && (n->kind == SN_INPUT || n->kind == SN_OUTPUT))
			t->status = status_of(ca->status);
		else if ((ca->status & (SNF_DEPRECATED | SNF_OBSOLETE)) != 0 &&
		    (n->flags & WSTATUS) == 0)
			t->status = status_of(ca->status);
		else
			t->status = status_of(n->flags);
		t->flags = wflags(n, ca, override);
		t->shape = n->uses ? TL_NODE : n->kind == SN_CHOICE ?
		    TL_CHOICE : n->kind == SN_CASE ? TL_CASE : TL_NODE;
		t->name = n->name;
		t->opts = wopts(n, ca);
		if (!n->uses && n->kind == SN_LIST && n->key != NULL &&
		    n->key[0] != '\0')
			t->keys = xstrdup(n->key);
		if (!n->uses && (n->kind == SN_LEAF || n->kind == SN_LEAFLIST))
			t->type = type_text(n->type, n->path);
		else if (!n->uses && (n->kind == SN_ANYDATA ||
		    n->kind == SN_ANYXML))
			t->type = xstrdup(snode_kind_name(n->kind));
		t->iff = join(n->iffeatures, n->niffeatures, ",");
		t->icase = shorthand(n);

		/* As the printer passes it on: from the parent's cache. */
		cc = *ca;
		if (!n->uses && (n->kind == SN_INPUT || n->kind == SN_OUTPUT ||
		    n->kind == SN_NOTIF))
			cc.in = n->kind;
		if ((n->flags & WSTATUS) != 0)
			cc.status = n->flags & (SNF_DEPRECATED | SNF_OBSOLETE);
		if (ca->in == SN_INPUT)
			cc.config = 0;
		else if (ca->in == SN_OUTPUT)
			cc.config = SNF_STATE;
		else if ((n->flags & WCONFIG) != 0)
			cc.config = n->flags & WCONFIG;
		if (!n->uses && n->kind == SN_LIST)
			cc.list = n;
		t->child = from_written(n->child, &cc, override);
	}
	return (first);
}

static size_t
gap_to_opts(const struct tline *t)
{
	size_t len;

	if (t->keys != NULL)
		return (0);
	len = strlen(t->flags) + 1 + strlen(t->name) + strlen(t->opts);
	if (t->shape != TL_NODE)
		len += 2;		/* the parentheses */
	if (t->prefix != NULL)
		len += strlen(t->prefix) + 1;
	return (len);
}

/* The column the siblings' types start at, counted from the flags. */
static size_t
type_column(const struct tline *t)
{
	size_t col = 0, len, opts;

	for (; t != NULL; t = t->next) {
		if (t->keys != NULL)
			continue;
		opts = strlen(t->opts);
		len = gap_to_opts(t) + (opts >= TYPE_GAP ? 1 : TYPE_GAP - opts);
		if (len > col)
			col = len;
	}
	return (col);
}

static struct wrap
descend(struct wrap w, bool more)
{

	if (more && w.depth < 64)
		w.bars |= (uint64_t)1 << w.depth;
	w.depth++;
	return (w);
}

static void
print_line(struct buf *b, const struct tline *t, size_t col, struct wrap w)
{

	buf_printf(b, "%*s", w.indent, "");
	for (unsigned i = 0; i < w.depth; i++)
		buf_puts(b, i < 64 && (w.bars >> i & 1) != 0 ? "|  " : "   ");
	buf_printf(b, "%s--", t->status);
	if (t->shape != TL_CASE)
		buf_printf(b, "%s ", t->flags);
	buf_printf(b, "%s%s%s%s%s%s", t->shape == TL_CASE ? ":(" :
	    t->shape == TL_CHOICE ? "(" : "", t->prefix != NULL ? t->prefix :
	    "", t->prefix != NULL ? ":" : "", t->name,
	    t->shape != TL_NODE ? ")" : "", t->opts);
	if (t->keys != NULL)
		buf_printf(b, " [%s]", t->keys);
	if (t->type != NULL)
		buf_printf(b, "%*s%s", (int)(col - gap_to_opts(t)), "",
		    t->type);
	if (t->iff != NULL)
		buf_printf(b, " {%s}?", t->iff);
}

static void
print_subtree(struct buf *b, const struct tline *t, size_t col,
    struct wrap w)
{
	struct wrap cw;
	size_t ccol;

	print_line(b, t, col, w);
	if (t->child == NULL)
		return;
	cw = descend(w, t->next != NULL);
	ccol = type_column(t->child);
	for (const struct tline *c = t->child; c != NULL; c = c->next) {
		buf_puts(b, "\n");
		if (c->icase) {
			struct tline cs = {
				.status = c->status,
				.flags = "",
				.shape = TL_CASE,
				.name = c->name,
				.opts = c->opts,
			};

			print_line(b, &cs, 0, cw);
			buf_puts(b, "\n");
			print_subtree(b, c, ccol, descend(cw, c->next != NULL));
		} else
			print_subtree(b, c, ccol, cw);
	}
}

/* The lines of a section, each after a newline; then they are freed. */
static void
print_section(struct buf *b, struct tline *t, int indent)
{
	struct wrap w = { .indent = indent };
	size_t col = type_column(t);

	for (const struct tline *s = t; s != NULL; s = s->next) {
		buf_puts(b, "\n");
		print_subtree(b, s, col, w);
	}
	tl_free(t);
}

void
gen_yang_tree_module(const struct smodule *m, struct buf *b)
{
	const struct wcache top = { .in = SN_CONTAINER, .config = SNF_CONFIG };
	const char *prev = NULL, *sect;
	struct tline *t;

	buf_printf(b, "module: %s", m->name);
	print_section(b, from_compiled(m->data, m, NULL), 2);
	for (size_t i = 0; i < m->naugments; i++) {
		buf_printf(b, "%s  augment %s:", i == 0 ? "\n\n" : "\n",
		    m->augments[i].target);
		print_section(b, from_written(m->augments[i].nodes, &top,
		    NULL), 4);
	}
	if (m->rpcs != NULL) {
		buf_puts(b, "\n\n  rpcs:");
		print_section(b, from_compiled(m->rpcs, m, NULL), 4);
	}
	if (m->notifs != NULL) {
		buf_puts(b, "\n\n  notifications:");
		print_section(b, from_compiled(m->notifs, m, NULL), 4);
	}

	/*
	 * Structures and yang-data, the flags their plugins give, without
	 * prefixes; a run of sections of one kind without blank lines.
	 */
	for (size_t i = 0; i < m->nexts; i++) {
		const struct sext *e = &m->exts[i];

		if (strcmp(e->ext, STRUCTURE) == 0)
			t = from_compiled(e->data, NULL, "");
		else if (strcmp(e->ext, YANG_DATA) == 0)
			t = from_compiled(e->data, NULL, "--");
		else if (strcmp(e->ext, AUG_STRUCTURE) == 0)
			t = from_written(e->written, &top, "");
		else
			continue;
		if (t == NULL)
			continue;
		sect = strchr(e->ext, ':') + 1;
		buf_printf(b, "%s  %s %s:", prev == NULL ||
		    strcmp(prev, sect) != 0 ? "\n\n" : "\n", sect,
		    e->arg != NULL ? e->arg : "");
		print_section(b, t, 4);
		prev = sect;
	}
	buf_puts(b, "\n");
}

void
gen_yang_tree(const struct schema *s, struct buf *b)
{
	bool first = true;

	for (size_t i = 0; i < s->nmods; i++) {
		if (!s->mods[i]->given || !s->mods[i]->implemented)
			continue;
		if (!first)
			buf_puts(b, "\n");
		gen_yang_tree_module(s->mods[i], b);
		first = false;
	}
}
