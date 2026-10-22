/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The references of an instance tree (cbl_data.h, PLAN-SDN-YANG 2.1.5):
 * a leafref's value must be one of its target node's instances', an
 * instance-identifier must name a node of the tree, where the schema
 * requires an instance (RFC 7950 sections 9.9.2, 9.13.2).  A leafref's
 * target is the tables' (lref, which the generator had libyang resolve),
 * the nodes its path finds if it has predicates (cbl_xp_eval());
 * an instance-identifier is read from its YANG-CBOR (cbl_yiid_read())
 * and found down from the root by its lists' keys.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"
#include "cbl_yimpl.h"

struct refs {
	const cbl_dtree		*t;
	struct cbl_dederr	*err;
	cbl_yarena		*a;
};

static int
missing(struct refs *r, const cbl_dnode *at, const char *fmt, ...)
{
	va_list ap;

	if (r->err != NULL) {
		r->err->node = at;
		r->err->tag = "data-missing";
		r->err->apptag = "instance-required";
		va_start(ap, fmt);
		vsnprintf(r->err->msg, sizeof(r->err->msg), fmt, ap);
		va_end(ap);
	}
	return (ENOENT);
}

/*
 * Whether a node of target in n's subtree has the value v: by its SID,
 * the same in a parent references' tree of another schema.
 */
static bool
has_value(const cbl_dnode *n, const struct cbl_ynode *target, const void *v,
    int depth)
{

	if (depth > CBL_D_DEPTH_MAX)
		return (false);
	for (const cbl_dnode *c = n->first; c != NULL; c = c->next) {
		if (c->sn->sid == target->sid && c->value != NULL &&
		    cbl_dvalue_equal(target->type, c->value, v))
			return (true);
		if (c->first != NULL && has_value(c, target, v, depth + 1))
			return (true);
	}
	return (false);
}

/*
 * Whether leafref c's path, its predicates looked at, finds a node of its
 * value: 0 and *found, or the evaluator's errno and why.
 */
static int
path_has(const cbl_dtree *t, const cbl_dnode *c, bool *found, char *why,
    size_t whylen)
{
	const struct cbl_ytype *ty = c->sn->type;
	struct cbl_xval v;
	int error;

	*found = false;
	if ((error = cbl_xp_eval(t, t->schema->xpath[ty->path], c, c, &v,
	    why, whylen)) != 0)
		return (error);
	for (size_t i = 0; v.kind == CBL_XV_NODES && i < v.n && !*found; i++)
		*found = v.nodes[i]->value != NULL &&
		    cbl_dvalue_equal(ty, v.nodes[i]->value, c->value);
	cbl_xval_free(&v);
	return (0);
}

/* The node of tree t an instance-identifier names, or NULL: none. */
static const cbl_dnode *
named(const cbl_dtree *t, const struct cbl_ynode *n, const void **vals)
{
	const struct cbl_ynode *chain[CBL_D_DEPTH_MAX + 1];
	const cbl_dnode *x = &t->root;
	size_t nc = 0, j = 0;

	for (const struct cbl_ynode *s = n; s != NULL; s = s->parent) {
		if (nc == sizeof(chain) / sizeof(chain[0]))
			return (NULL);
		chain[nc++] = s;
	}
	while (nc-- > 0 && x != NULL) {
		const struct cbl_ynode *s = chain[nc];

		if (s->kind == CBL_YN_LIST) {
			x = cbl_dnode_entry(x, s, vals + j);
			j += s->nkeys;
		} else if (s->kind == CBL_YN_LEAFLIST)
			x = cbl_dnode_llentry(x, s, vals[j++]);
		else
			x = cbl_dnode_child(x, s);
	}
	return (x);
}

const cbl_dnode *
cbl_d_iid_node(const cbl_dtree *t, const struct cbl_bytes *v, cbl_yarena *a)
{
	const struct cbl_ynode *target;
	const void **vals;
	size_t nvals;

	if (cbl_yiid_read(t->schema, v, &target, &vals, &nvals, a) != 0)
		return (NULL);
	return (named(t, target, vals));
}

static int
check(struct refs *r, const cbl_dnode *n, int depth)
{
	const struct cbl_ynode *target;
	const void **vals;
	size_t nvals;
	char why[128];
	bool found;
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	for (const cbl_dnode *c = n->first; c != NULL; c = c->next) {
		const struct cbl_ytype *t = c->sn->type;

		if (t != NULL && (t->flags & CBL_YTF_REQUIRE) != 0) {
			/* With predicates, the path's nodes; else any of
			 * its target. */
			if ((t->flags & CBL_YTF_LEAFREF) != 0 &&
			    (target = c->sn->lref) != NULL && t->path >= 0 &&
			    strchr(r->t->schema->xpath[t->path], '[') !=
			    NULL) {
				if ((error = path_has(r->t, c, &found, why,
				    sizeof(why))) != 0) {
					if (r->err != NULL) {
						r->err->node = c;
						r->err->tag = "operation-failed";
						snprintf(r->err->msg,
						    sizeof(r->err->msg), "%s: %s",
						    c->sn->name, why);
					}
					return (error);
				}
				if (!found)
					return (missing(r, c, "%s: no %s of its "
					    "value its path finds",
					    c->sn->name, target->name));
			} else if ((t->flags & CBL_YTF_LEAFREF) != 0 &&
			    (target = c->sn->lref) != NULL &&
			    !has_value(&r->t->root, target, c->value, 0) &&
			    (r->t->refs == NULL || !has_value(&r->t->refs->root,
			    target, c->value, 0)))
				return (missing(r, c, "%s: no %s of its value",
				    c->sn->name, target->name));
			if (t->kind == CBL_YT_INSTANCEID) {
				error = cbl_yiid_read(r->t->schema, c->value,
				    &target, &vals, &nvals, r->a);
				if (error != 0 || named(r->t, target, vals) ==
				    NULL)
					return (missing(r, c, "%s: %s",
					    c->sn->name, error != 0 ?
					    "not an instance-identifier of the "
					    "schema" : "no node it names"));
			}
		}
		if (c->first != NULL && (error = check(r, c, depth + 1)) != 0)
			return (error);
	}
	return (0);
}

int
cbl_dtree_check_refs(const cbl_dtree *t, struct cbl_dederr *err)
{
	struct refs r = { .t = t, .err = err };
	int error;

	if (err != NULL)
		memset(err, 0, sizeof(*err));
	if (t == NULL)
		return (EINVAL);
	if ((r.a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	error = check(&r, &t->root, 0);
	cbl_yarena_free(r.a);
	return (error);
}
