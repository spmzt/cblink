/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: an XPath expression, as a subscription's filter brings one
 * from the network.  Parse it; what parses is printed, and the print
 * must parse again to the same print.  Then evaluate it (cbl_xp_eval())
 * over a tree of the shapes tables, every kind of leaf in it, from a
 * node the first byte picks: its work bounded, whatever it is.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_xpath.h"
#include "yshapes.h"

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static char *
printed(const struct cbl_xp *x)
{
	char *s = NULL;
	size_t len;
	FILE *fp;

	if ((fp = open_memstream(&s, &len)) == NULL)
		abort();
	cbl_xp_print(x, fp);
	if (fclose(fp) != 0)
		abort();
	return (s);
}

static cbl_dtree *tree;
static const cbl_dnode *ctxs[4];

/* The tree, once: a shapes container with every kind of leaf. */
static void
make_tree(void)
{
	static const char *const names[] = { "a", "b'c" };
	static const enum shapes_shapes_levels levels[] = {
	    SHAPES_SHAPES_LEVELS_LOW, SHAPES_SHAPES_LEVELS_VERY_HIGH };
	static const struct shapes_shapes_eithers eithers[] = {
	    { .which = 0, .v.m0 = 7 }, { .which = 1, .v.m1 = "z" } };
	static const struct shapes_shapes_item items[] = {
	    { .id = 1, .has_peer = true, .peer = 2 },
	    { .id = 2, .has_peer = true, .peer = 1 } };
	static const struct shapes_shapes_tuned tuned = { true, 9 };
	static const uint8_t perms[] = { 0x11 }, blob[] = { 0xde, 0xad };
	const struct cbl_ynode *top = NULL;
	struct shapes_shapes sh = { 0 };
	struct cbl_xval v;
	cbl_dnode *n;
	char why[128];

	for (uint32_t i = 0; i < yshapes_schema.nmod; i++)
		for (uint32_t j = 0; j < yshapes_schema.mod[i]->ntop; j++)
			if (strcmp(yshapes_schema.mod[i]->top[j]->name,
			    "shapes") == 0)
				top = yshapes_schema.mod[i]->top[j];
	sh.default_ = "x y";
	sh.has_ratio = true;
	sh.ratio = -257;
	sh.flag = true;
	sh.blob = (struct cbl_bytes){ blob, sizeof(blob) };
	sh.perms = (struct cbl_bytes){ perms, sizeof(perms) };
	sh.has_level = true;
	sh.level = SHAPES_SHAPES_LEVEL_VERY_HIGH;
	for (uint32_t i = 0; i < yshapes_schema.nident; i++)
		if (strcmp(yshapes_schema.ident[i].name, "red") == 0) {
			sh.has_colour = true;
			sh.colour = yshapes_schema.ident[i].sid;
		}
	sh.has_either = true;
	sh.either.which = 2;
	sh.either.v.m2 = "e";
	sh.names.n = 2;
	sh.names.v = names;
	sh.levels.n = 2;
	sh.levels.v = levels;
	sh.eithers.n = 2;
	sh.eithers.v = eithers;
	sh.tuned = &tuned;
	sh.how = SHAPES_SHAPES_HOW_FAST;
	sh.has_speed = true;
	sh.speed = 100;
	sh.item.n = 2;
	sh.item.v = items;
	if (top == NULL || (tree = cbl_dtree_new(&yshapes_schema)) == NULL ||
	    cbl_dnode_from_struct(cbl_dtree_root(tree), top, &sh, &n) != 0)
		abort();
	ctxs[0] = cbl_dtree_root(tree);
	ctxs[1] = n;
	if (cbl_xp_eval(tree, "//item[id = 2]/peer", NULL, NULL, &v, why,
	    sizeof(why)) != 0 || v.kind != CBL_XV_NODES || v.n != 1)
		abort();
	ctxs[2] = v.nodes[0];
	ctxs[3] = cbl_dnode_parent(v.nodes[0]);
	cbl_xval_free(&v);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct cbl_xp *x, *y;
	struct cbl_xval v;
	const cbl_dnode *ctx;
	char *e, *a, *b, err[128];

	if ((e = malloc(size + 1)) == NULL)
		return (0);
	memcpy(e, data, size);
	e[size] = '\0';
	if ((x = cbl_xp_parse(e, err, sizeof(err), NULL)) != NULL) {
		a = printed(x);
		if ((y = cbl_xp_parse(a, err, sizeof(err), NULL)) == NULL)
			abort();
		b = printed(y);
		if (strcmp(a, b) != 0)
			abort();
		cbl_xp_free(y);
		free(a);
		free(b);
		cbl_xp_free(x);
		if (tree == NULL)
			make_tree();
		ctx = ctxs[size > 0 ? data[0] % 4 : 0];
		if (cbl_xp_eval(tree, e, ctx, ctx, &v, err, sizeof(err)) == 0)
			cbl_xval_free(&v);
	}
	free(e);
	return (0);
}
