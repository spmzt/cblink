/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The generator's schema model (schema.h): lookups, the walk, and a
 * dump that tools/yangwalk/treecheck.sh can compare with yanglint.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_pattern.h"
#include "cbl_xpath.h"
#include "gen.h"
#include "schema.h"

struct schema *
schema_new(void)
{

	return (xcalloc(1, sizeof(struct schema)));
}

static void
range_free(struct srange *r)
{

	if (r == NULL)
		return;
	free(r->parts);
	free(r->emsg);
	free(r->eapptag);
	free(r);
}

static void
type_free(struct sntype *t)
{

	if (t == NULL)
		return;
	free(t->name);
	range_free(t->range);
	range_free(t->length);
	for (size_t i = 0; i < t->npatterns; i++) {
		free(t->patterns[i].expr);
		free(t->patterns[i].emsg);
		free(t->patterns[i].eapptag);
	}
	free(t->patterns);
	for (size_t i = 0; i < t->nitems; i++)
		free(t->items[i].name);
	free(t->items);
	free(t->bases);
	free(t->path);
	type_free(t->real);
	for (size_t i = 0; i < t->nmembers; i++)
		type_free(t->members[i]);
	free(t->members);
	free(t);
}

static void	snode_free(struct snode *n);

static void
strings_free(char **v, size_t n)
{

	for (size_t i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

static void
swnode_free(struct swnode *n)
{
	struct swnode *next;

	for (; n != NULL; n = next) {
		next = n->next;
		swnode_free(n->child);
		free(n->name);
		free(n->type);
		free(n->path);
		free(n->key);
		strings_free(n->iffeatures, n->niffeatures);
		free(n);
	}
}

static void
exts_free(struct sext *e, size_t n)
{

	for (size_t i = 0; i < n; i++) {
		free(e[i].ext);
		free(e[i].arg);
		snode_free(e[i].data);
		swnode_free(e[i].written);
	}
	free(e);
}

static void
snode_free(struct snode *n)
{
	struct snode *next;

	for (; n != NULL; n = next) {
		next = n->next;
		snode_free(n->child);
		free(n->name);
		free(n->keys);
		type_free(n->type);
		free(n->wtype);
		free(n->wpath);
		free(n->units);
		for (size_t i = 0; i < n->ndflts; i++)
			free(n->dflts[i]);
		free(n->dflts);
		for (size_t i = 0; i < n->nwhen; i++)
			free(n->when[i]);
		free(n->when);
		for (size_t i = 0; i < n->nmusts; i++) {
			free(n->musts[i].expr);
			free(n->musts[i].emsg);
			free(n->musts[i].eapptag);
		}
		free(n->musts);
		strings_free(n->iffeatures, n->niffeatures);
		exts_free(n->exts, n->nexts);
		free(n);
	}
}

void
schema_free(struct schema *s)
{
	struct smodule *m;

	if (s == NULL)
		return;
	for (size_t i = 0; i < s->nmods; i++) {
		m = s->mods[i];
		for (size_t j = 0; j < m->nfeatures; j++)
			free(m->features[j].name);
		free(m->features);
		for (size_t j = 0; j < m->nidents; j++) {
			free(m->idents[j].name);
			free(m->idents[j].derived);
		}
		free(m->idents);
		for (size_t j = 0; j < m->ndeviated_by; j++)
			free(m->deviated_by[j]);
		free(m->deviated_by);
		for (size_t j = 0; j < m->nimports; j++) {
			free(m->imports[j].name);
			free(m->imports[j].revision);
		}
		free(m->imports);
		snode_free(m->data);
		snode_free(m->rpcs);
		snode_free(m->notifs);
		exts_free(m->exts, m->nexts);
		for (size_t j = 0; j < m->naugments; j++) {
			free(m->augments[j].target);
			swnode_free(m->augments[j].nodes);
		}
		free(m->augments);
		free(m->name);
		free(m->revision);
		free(m->ns);
		free(m->prefix);
		free(m);
	}
	free(s->mods);
	free(s);
}

struct smodule *
schema_module(struct schema *s, const char *name, const char *revision)
{

	for (size_t i = 0; i < s->nmods; i++)
		if (strcmp(s->mods[i]->name, name) == 0 &&
		    (revision == NULL || (s->mods[i]->revision != NULL &&
		    strcmp(s->mods[i]->revision, revision) == 0)))
			return (s->mods[i]);
	return (NULL);
}

struct sident *
schema_ident_in(struct smodule *m, const char *name)
{

	for (size_t i = 0; i < m->nidents; i++)
		if (strcmp(m->idents[i].name, name) == 0)
			return (&m->idents[i]);
	return (NULL);
}

struct sident *
schema_ident(struct schema *s, const char *module, const char *name)
{
	struct smodule *m;

	if ((m = schema_module(s, module, NULL)) == NULL)
		return (NULL);
	return (schema_ident_in(m, name));
}

const struct sext *
snode_ext(const struct snode *n, const char *ext)
{

	for (size_t i = 0; i < n->nexts; i++)
		if (strcmp(n->exts[i].ext, ext) == 0)
			return (&n->exts[i]);
	return (NULL);
}

const char *
snode_kind_name(enum snode_kind kind)
{

	switch (kind) {
	case SN_CONTAINER:	return ("container");
	case SN_LEAF:		return ("leaf");
	case SN_LEAFLIST:	return ("leaf-list");
	case SN_LIST:		return ("list");
	case SN_CHOICE:		return ("choice");
	case SN_CASE:		return ("case");
	case SN_ANYDATA:	return ("anydata");
	case SN_ANYXML:		return ("anyxml");
	case SN_RPC:		return ("rpc");
	case SN_ACTION:		return ("action");
	case SN_NOTIF:		return ("notification");
	case SN_INPUT:		return ("input");
	case SN_OUTPUT:		return ("output");
	}
	return ("?");
}

const char *
sntype_base_name(enum sntype_base base)
{

	switch (base) {
	case ST_BINARY:		return ("binary");
	case ST_BITS:		return ("bits");
	case ST_BOOLEAN:	return ("boolean");
	case ST_DECIMAL64:	return ("decimal64");
	case ST_EMPTY:		return ("empty");
	case ST_ENUMERATION:	return ("enumeration");
	case ST_IDENTITYREF:	return ("identityref");
	case ST_INSTANCEID:	return ("instance-identifier");
	case ST_INT8:		return ("int8");
	case ST_INT16:		return ("int16");
	case ST_INT32:		return ("int32");
	case ST_INT64:		return ("int64");
	case ST_LEAFREF:	return ("leafref");
	case ST_STRING:		return ("string");
	case ST_UINT8:		return ("uint8");
	case ST_UINT16:		return ("uint16");
	case ST_UINT32:		return ("uint32");
	case ST_UINT64:		return ("uint64");
	case ST_UNION:		return ("union");
	}
	return ("?");
}

/* Signed bounds: the signed integers and decimal64. */
bool
sntype_signed(enum sntype_base base)
{

	return (base == ST_INT8 || base == ST_INT16 || base == ST_INT32 ||
	    base == ST_INT64 || base == ST_DECIMAL64);
}

static void
walk(struct snode *n, snode_visit_t *visit, void *arg)
{

	for (; n != NULL; n = n->next) {
		visit(n, arg);
		walk(n->child, visit, arg);
	}
}

void
schema_walk(struct schema *s, snode_visit_t *visit, void *arg)
{

	for (size_t i = 0; i < s->nmods; i++) {
		walk(s->mods[i]->data, visit, arg);
		walk(s->mods[i]->rpcs, visit, arg);
		walk(s->mods[i]->notifs, visit, arg);
	}
}

/* The schema path: a step names its module where it differs from its
 * parent's, as libyang's LYSC_PATH_LOG does. */
static void
path_add(struct buf *b, const struct snode *n)
{

	if (n->parent != NULL)
		path_add(b, n->parent);
	else if (n->in != NULL)
		buf_printf(b, "{%s %s}", n->in->ext, n->in->arg != NULL ?
		    n->in->arg : "");
	buf_puts(b, "/");
	if (n->parent == NULL || n->parent->module != n->module)
		buf_printf(b, "%s:", n->module->name);
	buf_puts(b, n->name);
}

/* An expression on one line, its runs of white space as one space. */
static void
sid_path_add(struct buf *b, const struct snode *n, const struct smodule *pm)
{
	const struct snode *p = n->parent;

	/* Choices and cases are not steps. */
	while (p != NULL && (p->kind == SN_CHOICE || p->kind == SN_CASE))
		p = p->parent;
	if (p != NULL) {
		sid_path_add(b, p, NULL);
		pm = p->module;
	} else if (n->in != NULL) {
		/* The structure: /module:name, its module the instance's. */
		pm = n->in->module;
		buf_printf(b, "/%s:%s", pm->name, n->in->arg);
	}
	buf_puts(b, "/");
	if (pm == NULL || pm != n->module)
		buf_printf(b, "%s:", n->module->name);
	buf_puts(b, n->name);
}

bool
snode_sid_path(const struct snode *n, struct buf *b)
{

	if (n->kind == SN_CHOICE || n->kind == SN_CASE)
		return (false);
	sid_path_add(b, n, NULL);
	return (true);
}

static void
dump_expr(const char *what, const char *x)
{
	bool space = false;

	printf(" %s \"", what);
	for (; *x != '\0'; x++) {
		if (*x == ' ' || *x == '\t' || *x == '\n' || *x == '\r') {
			space = true;
			continue;
		}
		if (space)
			putchar(' ');
		space = false;
		putchar(*x);
	}
	printf("\"");
}

static void
dump_range(const char *what, const struct srange *r, bool sgn)
{

	if (r == NULL)
		return;
	printf(" %s ", what);
	for (size_t i = 0; i < r->nparts; i++) {
		if (i > 0)
			printf("|");
		if (sgn)
			printf("%" PRId64 "..%" PRId64, r->parts[i].min.i,
			    r->parts[i].max.i);
		else
			printf("%" PRIu64 "..%" PRIu64, r->parts[i].min.u,
			    r->parts[i].max.u);
	}
}

static void
dump_type(const struct sntype *t)
{

	printf("%s", sntype_base_name(t->base));
	if (t->name != NULL)
		printf("(%s)", t->name);
	switch (t->base) {
	case ST_DECIMAL64:
		printf(" fraction-digits %u", t->fdigits);
		dump_range("range", t->range, true);
		break;
	case ST_STRING:
		dump_range("length", t->length, false);
		for (size_t i = 0; i < t->npatterns; i++)
			printf(" pattern%s '%s'", t->patterns[i].invert ?
			    "(invert)" : "", t->patterns[i].expr);
		break;
	case ST_BINARY:
		dump_range("length", t->length, false);
		break;
	case ST_ENUMERATION:
	case ST_BITS:
		printf(" {");
		for (size_t i = 0; i < t->nitems; i++)
			printf("%s%s%s%" PRId64, i > 0 ? " " : "",
			    t->items[i].name, t->base == ST_BITS ? "@" : "=",
			    t->items[i].value);
		printf("}");
		break;
	case ST_IDENTITYREF:
		printf(" base");
		for (size_t i = 0; i < t->nbases; i++)
			printf(" %s:%s", t->bases[i]->module->name,
			    t->bases[i]->name);
		break;
	case ST_LEAFREF:
		dump_expr("path", t->path);
		printf("%s -> ", t->require_instance ? "" :
		    " (no instance required)");
		dump_type(t->real);
		break;
	case ST_INSTANCEID:
		if (!t->require_instance)
			printf(" (no instance required)");
		break;
	case ST_UNION:
		printf(" [");
		for (size_t i = 0; i < t->nmembers; i++) {
			if (i > 0)
				printf(" | ");
			dump_type(t->members[i]);
		}
		printf("]");
		break;
	default:
		dump_range("range", t->range, sntype_signed(t->base));
		break;
	}
}

static void	dump_node(struct snode *n, void *arg);

/* Extension instances as tools/yangwalk prints them, and their nodes. */
static void
dump_exts(const struct sext *e, size_t n, const char *owner,
    const char *where)
{

	for (size_t i = 0; i < n; i++) {
		printf("%s extension %s %s%s%s%s\n", e[i].inherited ? owner :
		    e[i].module->name, where, e[i].ext,
		    e[i].arg != NULL ? " " : "", e[i].arg != NULL ? e[i].arg :
		    "", e[i].inherited ? " inherited" : "");
		walk(e[i].data, dump_node, NULL);
	}
}

static void
dump_node(struct snode *n, void *arg __unused)
{
	struct buf b;

	buf_init(&b);
	path_add(&b, n);
	printf("%s %s %s", n->module->name, snode_kind_name(n->kind), b.p);
	switch (n->kind) {
	case SN_RPC: case SN_ACTION: case SN_NOTIF:
		break;
	case SN_INPUT: case SN_OUTPUT:
		if (n->child == NULL)
			printf(" empty");
		break;
	default:
		printf(" %s", (n->flags & SNF_CONFIG) != 0 ? "rw" : "ro");
	}
	if ((n->flags & SNF_MANDATORY) != 0)
		printf(" mandatory");
	if ((n->flags & SNF_KEY) != 0)
		printf(" key");
	if ((n->flags & SNF_PRESENCE) != 0)
		printf(" presence");
	if ((n->flags & SNF_USERORDER) != 0)
		printf(" user-ordered");
	if ((n->flags & SNF_DEPRECATED) != 0)
		printf(" deprecated");
	if ((n->flags & SNF_OBSOLETE) != 0)
		printf(" obsolete");
	if (n->kind == SN_LIST)
		printf(" min %" PRIu32 " max %" PRIu32, n->min, n->max);
	if (n->type != NULL) {
		printf(" ");
		dump_type(n->type);
	}
	if (n->units != NULL)
		printf(" units \"%s\"", n->units);
	for (size_t i = 0; i < n->ndflts; i++)
		printf(" default \"%s\"", n->dflts[i]);
	if (n->dflt_case != NULL)
		printf(" default-case %s", n->dflt_case->name);
	for (size_t i = 0; i < n->nwhen; i++)
		dump_expr("when", n->when[i]);
	for (size_t i = 0; i < n->nmusts; i++)
		dump_expr("must", n->musts[i].expr);
	printf("\n");
	dump_exts(n->exts, n->nexts, n->module->name, b.p);
	buf_free(&b);
}

/*
 * The profile cblink keeps to: every XPath expression of the model
 * (when, must, a leafref's path) parsed and held to XPath-lite, and
 * every pattern translated to an ERE and compiled, which is what cblink
 * evaluates and matches; one that cannot be is a diagnostic at its node.
 */
struct xpcheck {
	struct diags	*d;
	size_t		 n;
	size_t		 npat;
};

static void
pat_one(struct xpcheck *c, const struct snode *n, const char *pat)
{
	regex_t re;
	struct buf b;
	char err[256];
	size_t pos;

	c->npat++;
	if (cbl_pattern_compile(pat, &re, err, sizeof(err), &pos) == 0) {
		cbl_pattern_free(&re);
		return;
	}
	buf_init(&b);
	path_add(&b, n);
	diag_add(c->d, 0, 0, "%s: pattern '%s': outside what cblink matches: "
	    "%s at offset %zu", b.p, pat, err, pos);
	buf_free(&b);
}

static void
xp_one(struct xpcheck *c, const struct snode *n, const char *what,
    const char *expr)
{
	struct cbl_xp *x;
	struct buf b;
	char err[256];
	size_t pos;

	c->n++;
	if ((x = cbl_xp_parse(expr, err, sizeof(err), &pos)) != NULL) {
		if (cbl_xp_lite(x, err, sizeof(err), &pos)) {
			cbl_xp_free(x);
			return;
		}
		cbl_xp_free(x);
		buf_init(&b);
		path_add(&b, n);
		diag_add(c->d, 0, 0, "%s: %s \"%s\": outside XPath-lite: %s "
		    "at offset %zu", b.p, what, expr, err, pos);
		buf_free(&b);
		return;
	}
	buf_init(&b);
	path_add(&b, n);
	diag_add(c->d, 0, 0, "%s: %s \"%s\": %s at offset %zu", b.p, what,
	    expr, err, pos);
	buf_free(&b);
}

static void
xp_type(struct xpcheck *c, const struct snode *n, const struct sntype *t)
{

	if (t == NULL)
		return;
	if (t->path != NULL)
		xp_one(c, n, "path", t->path);
	for (size_t i = 0; i < t->npatterns; i++)
		pat_one(c, n, t->patterns[i].expr);
	xp_type(c, n, t->real);
	for (size_t i = 0; i < t->nmembers; i++)
		xp_type(c, n, t->members[i]);
}

static void
xp_node(struct snode *n, void *arg)
{
	struct xpcheck *c = arg;

	for (size_t i = 0; i < n->nwhen; i++)
		xp_one(c, n, "when", n->when[i]);
	for (size_t i = 0; i < n->nmusts; i++)
		xp_one(c, n, "must", n->musts[i].expr);
	xp_type(c, n, n->type);
	for (size_t i = 0; i < n->nexts; i++)
		walk(n->exts[i].data, xp_node, arg);
}

size_t
schema_check_profile(struct schema *s, struct diags *d, size_t *npatterns)
{
	struct xpcheck c = { .d = d };

	schema_walk(s, xp_node, &c);
	for (size_t i = 0; i < s->nmods; i++)
		for (size_t j = 0; j < s->mods[i]->nexts; j++)
			walk(s->mods[i]->exts[j].data, xp_node, &c);
	*npatterns = c.npat;
	return (c.n);
}

void
schema_dump(struct schema *s)
{
	struct smodule *m;

	for (size_t i = 0; i < s->nmods; i++) {
		m = s->mods[i];
		if (!m->implemented)
			continue;	/* imported only: no nodes */
		printf("module %s@%s\n", m->name, m->revision != NULL ?
		    m->revision : "-");
		for (size_t j = 0; j < m->nfeatures; j++)
			printf("feature %s %s\n", m->features[j].name,
			    m->features[j].enabled ? "on" : "off");
		for (size_t j = 0; j < m->ndeviated_by; j++)
			printf("deviated-by %s\n", m->deviated_by[j]);
		walk(m->data, dump_node, NULL);
		walk(m->rpcs, dump_node, NULL);
		walk(m->notifs, dump_node, NULL);
		dump_exts(m->exts, m->nexts, m->name, m->name);
	}
}
