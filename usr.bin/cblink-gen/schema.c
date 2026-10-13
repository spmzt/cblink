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

#include "gen.h"
#include "schema.h"

struct schema *
schema_new(void)
{

	return (xcalloc(1, sizeof(struct schema)));
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
		snode_free(m->data);
		snode_free(m->rpcs);
		snode_free(m->notifs);
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
schema_ident(struct schema *s, const char *module, const char *name)
{
	struct smodule *m;

	if ((m = schema_module(s, module, NULL)) == NULL)
		return (NULL);
	for (size_t i = 0; i < m->nidents; i++)
		if (strcmp(m->idents[i].name, name) == 0)
			return (&m->idents[i]);
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
	buf_puts(b, "/");
	if (n->parent == NULL || n->parent->module != n->module)
		buf_printf(b, "%s:", n->module->name);
	buf_puts(b, n->name);
}

static void
dump_node(struct snode *n, void *arg __unused)
{
	struct buf b;

	buf_init(&b);
	path_add(&b, n);
	printf("%s %s %s", n->module->name, snode_kind_name(n->kind), b.p);
	buf_free(&b);
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
	printf("\n");
}

void
schema_dump(struct schema *s)
{
	struct smodule *m;

	for (size_t i = 0; i < s->nmods; i++) {
		m = s->mods[i];
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
	}
}
