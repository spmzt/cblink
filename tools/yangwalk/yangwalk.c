/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yangwalk: what libyang 3's compiled schema gives the generator
 * (Arcana's PLAN-SDN-YANG, step 0.2.2).  The modules named are compiled
 * with every feature on and their imports implemented; then, for every
 * schema node of every implemented module, one line:
 *
 *	owner kind path flags type [constraints] [when "..."] [must "..."]
 *
 * owner is the module that defines the node (an augment's, not its
 * target's), path the schema path with prefixes, flags any of config
 * (rw), state (ro), empty (an input or output without children, which
 * a compiled rpc or action always has), mandatory, key, presence,
 * user-ordered, deprecated, obsolete.  A node defined in a grouping is
 * listed wherever the grouping is used.  Each module is preceded by its features and the modules
 * that deviate it.
 *
 *	yangwalk -p dir module.yang ...
 */

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

static void	type_print(const struct lysc_type *);

/* The names of LY_DATA_TYPE, which libyang keeps unexported. */
static const char *const type_names[] = {
	[LY_TYPE_UNKNOWN] = "unknown", [LY_TYPE_BINARY] = "binary",
	[LY_TYPE_UINT8] = "uint8", [LY_TYPE_UINT16] = "uint16",
	[LY_TYPE_UINT32] = "uint32", [LY_TYPE_UINT64] = "uint64",
	[LY_TYPE_STRING] = "string", [LY_TYPE_BITS] = "bits",
	[LY_TYPE_BOOL] = "boolean", [LY_TYPE_DEC64] = "decimal64",
	[LY_TYPE_EMPTY] = "empty", [LY_TYPE_ENUM] = "enumeration",
	[LY_TYPE_IDENT] = "identityref", [LY_TYPE_INST] = "instance-identifier",
	[LY_TYPE_LEAFREF] = "leafref", [LY_TYPE_UNION] = "union",
	[LY_TYPE_INT8] = "int8", [LY_TYPE_INT16] = "int16",
	[LY_TYPE_INT32] = "int32", [LY_TYPE_INT64] = "int64",
};

static void
range_print(const char *what, const struct lysc_range *r, bool sgn)
{
	LY_ARRAY_COUNT_TYPE u;

	if (r == NULL)
		return;
	printf(" %s ", what);
	LY_ARRAY_FOR(r->parts, u) {
		if (u > 0)
			printf("|");
		if (sgn)
			printf("%" PRId64 "..%" PRId64, r->parts[u].min_64,
			    r->parts[u].max_64);
		else
			printf("%" PRIu64 "..%" PRIu64, r->parts[u].min_u64,
			    r->parts[u].max_u64);
	}
}

static void
type_print(const struct lysc_type *t)
{
	const struct lysc_type_num *num = (const void *)t;
	const struct lysc_type_dec *dec = (const void *)t;
	const struct lysc_type_str *str = (const void *)t;
	const struct lysc_type_bin *bin = (const void *)t;
	const struct lysc_type_enum *en = (const void *)t;
	const struct lysc_type_bits *bits = (const void *)t;
	const struct lysc_type_identityref *idr = (const void *)t;
	const struct lysc_type_leafref *lr = (const void *)t;
	const struct lysc_type_union *un = (const void *)t;
	const struct lysc_type_instanceid *ii = (const void *)t;
	LY_ARRAY_COUNT_TYPE u;

	printf("%s", type_names[t->basetype]);
	if (t->name != NULL)
		printf("(%s)", t->name);
	switch (t->basetype) {
	case LY_TYPE_INT8: case LY_TYPE_INT16:
	case LY_TYPE_INT32: case LY_TYPE_INT64:
		range_print("range", num->range, true);
		break;
	case LY_TYPE_UINT8: case LY_TYPE_UINT16:
	case LY_TYPE_UINT32: case LY_TYPE_UINT64:
		range_print("range", num->range, false);
		break;
	case LY_TYPE_DEC64:
		printf(" fraction-digits %u", dec->fraction_digits);
		range_print("range", dec->range, true);
		break;
	case LY_TYPE_STRING:
		range_print("length", str->length, false);
		LY_ARRAY_FOR(str->patterns, u)
			printf(" pattern%s '%s'", str->patterns[u]->inverted ?
			    "(invert)" : "", str->patterns[u]->expr);
		break;
	case LY_TYPE_BINARY:
		range_print("length", bin->length, false);
		break;
	case LY_TYPE_ENUM:
		printf(" {");
		LY_ARRAY_FOR(en->enums, u)
			printf("%s%s=%" PRId32, u > 0 ? " " : "",
			    en->enums[u].name, en->enums[u].value);
		printf("}");
		break;
	case LY_TYPE_BITS:
		printf(" {");
		LY_ARRAY_FOR(bits->bits, u)
			printf("%s%s@%" PRIu32, u > 0 ? " " : "",
			    bits->bits[u].name, bits->bits[u].position);
		printf("}");
		break;
	case LY_TYPE_IDENT:
		printf(" base");
		LY_ARRAY_FOR(idr->bases, u)
			printf(" %s:%s", idr->bases[u]->module->name,
			    idr->bases[u]->name);
		break;
	case LY_TYPE_LEAFREF:
		printf(" path '%s'%s -> ", lyxp_get_expr(lr->path),
		    lr->require_instance ? "" : " (no instance required)");
		type_print(lr->realtype);
		break;
	case LY_TYPE_INST:
		if (!ii->require_instance)
			printf(" (no instance required)");
		break;
	case LY_TYPE_UNION:
		printf(" [");
		LY_ARRAY_FOR(un->types, u) {
			if (u > 0)
				printf(" | ");
			type_print(un->types[u]);
		}
		printf("]");
		break;
	default:
		break;
	}
}

/* The keyword of a node kind, as YANG writes it. */
static const char *
kind_name(uint16_t nodetype)
{

	switch (nodetype) {
	case LYS_CONTAINER:	return ("container");
	case LYS_CHOICE:	return ("choice");
	case LYS_LEAF:		return ("leaf");
	case LYS_LEAFLIST:	return ("leaf-list");
	case LYS_LIST:		return ("list");
	case LYS_ANYXML:	return ("anyxml");
	case LYS_ANYDATA:	return ("anydata");
	case LYS_CASE:		return ("case");
	case LYS_RPC:		return ("rpc");
	case LYS_ACTION:	return ("action");
	case LYS_NOTIF:		return ("notification");
	case LYS_INPUT:		return ("input");
	case LYS_OUTPUT:	return ("output");
	}
	return ("unknown");
}

static LY_ERR
node_print(struct lysc_node *n, void *arg __unused, ly_bool *cont __unused)
{
	struct lysc_when **when;
	struct lysc_must *must;
	const struct lysc_type *t = NULL;
	char *path;
	LY_ARRAY_COUNT_TYPE u;

	if ((path = lysc_path(n, LYSC_PATH_LOG, NULL, 0)) == NULL)
		err(1, "lysc_path");
	printf("%s %s %s", n->module->name, kind_name(n->nodetype),
	    path);
	free(path);
	if ((n->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF | LYS_INPUT |
	    LYS_OUTPUT)) == 0)
		printf(" %s", (n->flags & LYS_CONFIG_W) != 0 ? "rw" : "ro");
	if ((n->nodetype & (LYS_INPUT | LYS_OUTPUT)) != 0 &&
	    lysc_node_child(n) == NULL)
		printf(" empty");
	if ((n->flags & LYS_MAND_TRUE) != 0)
		printf(" mandatory");
	if (n->nodetype == LYS_LEAF && (n->flags & LYS_KEY) != 0)
		printf(" key");
	if (n->nodetype == LYS_CONTAINER && (n->flags & LYS_PRESENCE) != 0)
		printf(" presence");
	if (lysc_is_userordered(n))
		printf(" user-ordered");
	if ((n->flags & LYS_STATUS_DEPRC) != 0)
		printf(" deprecated");
	if ((n->flags & LYS_STATUS_OBSLT) != 0)
		printf(" obsolete");
	if (n->nodetype == LYS_LIST) {
		const struct lysc_node_list *l = (const void *)n;

		printf(" min %" PRIu32 " max %" PRIu32, l->min, l->max);
	}
	if (n->nodetype == LYS_LEAF)
		t = ((const struct lysc_node_leaf *)(const void *)n)->type;
	else if (n->nodetype == LYS_LEAFLIST)
		t = ((const struct lysc_node_leaflist *)(const void *)n)->type;
	if (t != NULL) {
		printf(" ");
		type_print(t);
	}
	when = lysc_node_when(n);
	LY_ARRAY_FOR(when, u)
		printf(" when \"%s\"", lyxp_get_expr(when[u]->cond));
	must = lysc_node_musts(n);
	LY_ARRAY_FOR(must, u)
		printf(" must \"%s\"", lyxp_get_expr(must[u].cond));
	printf("\n");
	return (LY_SUCCESS);
}

static void
module_print(const struct lys_module *m)
{
	const struct lysp_feature *f = NULL;
	LY_ARRAY_COUNT_TYPE u;
	uint32_t i = 0;

	printf("module %s@%s\n", m->name, m->revision != NULL ? m->revision :
	    "-");
	while ((f = lysp_feature_next(f, m->parsed, &i)) != NULL)
		printf("feature %s %s\n", f->name,
		    (f->flags & LYS_FENABLED) != 0 ? "on" : "off");
	LY_ARRAY_FOR(m->deviated_by, u)
		printf("deviated-by %s\n", m->deviated_by[u]->name);
	if (lysc_module_dfs_full(m, node_print, NULL) != LY_SUCCESS)
		errx(1, "%s: walk failed", m->name);
}

int
main(int argc, char *argv[])
{
	const char *features[] = { "*", NULL };
	const struct lys_module *m;
	struct ly_ctx *ctx;
	struct ly_in *in;
	const char *dir = ".";
	uint32_t idx = 0;
	int ch;

	while ((ch = getopt(argc, argv, "p:")) != -1)
		switch (ch) {
		case 'p':
			dir = optarg;
			break;
		default:
			fprintf(stderr, "usage: yangwalk [-p dir] module ...\n");
			return (2);
		}
	argc -= optind;
	argv += optind;
	if (ly_ctx_new(dir, LY_CTX_REF_IMPLEMENTED, &ctx) != LY_SUCCESS)
		errx(1, "ly_ctx_new");
	for (int i = 0; i < argc; i++) {
		if (ly_in_new_filepath(argv[i], 0, &in) != LY_SUCCESS)
			errx(1, "%s: cannot open", argv[i]);
		if (lys_parse(ctx, in, LYS_IN_YANG, features, NULL) !=
		    LY_SUCCESS)
			errx(1, "%s: does not compile", argv[i]);
		ly_in_free(in, 0);
	}
	while ((m = ly_ctx_get_module_iter(ctx, &idx)) != NULL)
		if (m->implemented && m->compiled != NULL)
			module_print(m);
	ly_ctx_destroy(ctx);
	return (0);
}
