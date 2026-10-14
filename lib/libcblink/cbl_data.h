/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The instance tree: YANG data as nodes of the schema tables
 * (cbl_schema.h), for what keeps data and works on it as YANG does (a
 * datastore, an edit, a diff, XPath), where the generated structs are
 * for what one handler fills or reads.
 *
 * A tree has a root, which is no schema node: under it the modules'
 * top-level nodes, and their rpcs', actions', notifications' and
 * structures' trees where one is kept.  Below, a node is a container, a
 * list entry, a leaf, a leaf-list entry, anydata or anyxml, an rpc or an
 * action, its input or output, a notification or a structure: the data
 * nodes, never a choice or a case.  A node's children are in the order of
 * their schema nodes (by SID); a list's entries and a leaf-list's values
 * in the order they were added, which an ordered-by user list keeps.
 *
 * A leaf's or a leaf-list entry's value is held as its member in the
 * generated struct is, of its type's csize bytes: an integer, a bool, an
 * enumeration's value, an identity's SID, a string's const char *, the
 * struct cbl_bytes of binary, bits and an instance-identifier, a union's
 * struct.  The tree keeps its own copy of what a value points to.
 * Anydata and anyxml hold their YANG-CBOR as struct cbl_bytes.
 *
 * Nothing here checks what the schema says beyond a tree's shape: a node
 * where its schema node has it, one entry a list's keys, a configuration
 * leaf-list's values once, the cases of a choice never two.  Values,
 * counts, when, must and references are the validator's and the
 * evaluator's.  A tree is not safe to share between threads.
 */

#ifndef _CBL_DATA_H_
#define	_CBL_DATA_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cbl_schema.h"

typedef struct cbl_dtree	cbl_dtree;
typedef struct cbl_dnode	cbl_dnode;

/* A default in use, made by cbl_dtree_defaults(). */
#define	CBL_DN_DEFAULT		0x0001

/* A tree of schema s's data, empty but for its root. */
cbl_dtree	*cbl_dtree_new(const struct cbl_yschema *s);
void		 cbl_dtree_free(cbl_dtree *t);
cbl_dnode	*cbl_dtree_root(const cbl_dtree *t);
const struct cbl_yschema *cbl_dtree_schema(const cbl_dtree *t);
/* How many nodes it has, the root not counted. */
size_t		 cbl_dtree_count(const cbl_dtree *t);

/* A node's schema node (NULL: the root), its place, its value. */
const struct cbl_ynode *cbl_dnode_schema(const cbl_dnode *n);
cbl_dnode	*cbl_dnode_parent(const cbl_dnode *n);
cbl_dnode	*cbl_dnode_first(const cbl_dnode *n);
cbl_dnode	*cbl_dnode_last(const cbl_dnode *n);
cbl_dnode	*cbl_dnode_next(const cbl_dnode *n);
cbl_dnode	*cbl_dnode_prev(const cbl_dnode *n);
/* A leaf's or leaf-list entry's value, anydata's bytes; else NULL. */
const void	*cbl_dnode_value(const cbl_dnode *n);
uint16_t	 cbl_dnode_flags(const cbl_dnode *n);

/*
 * A child sn of parent: a container (value NULL), a leaf, a leaf-list
 * entry (after the others), anydata, an rpc, an action, an input, an
 * output, a notification, a structure.  A list entry is made with its
 * keys by cbl_dnode_add_entry(), keys[k] the value of the list's k-th
 * key.  *out, if given, is the node made.  0, or EINVAL (sn is not a
 * child of parent's schema node, is a key, or is of a case of a choice
 * another case of which parent has), EEXIST (a second container, leaf,
 * entry of those keys, configuration leaf-list value), ENOMEM.
 */
int		 cbl_dnode_add(cbl_dnode *parent, const struct cbl_ynode *sn,
		    const void *value, cbl_dnode **out);
int		 cbl_dnode_add_entry(cbl_dnode *parent,
		    const struct cbl_ynode *list, const void *const *keys,
		    cbl_dnode **out);
/* A leaf's value replaced, or a leaf-list entry's; EPERM: a key's. */
int		 cbl_dnode_set(cbl_dnode *n, const void *value);
/* n and all below it removed; EPERM: the root, a list entry's key. */
int		 cbl_dnode_remove(cbl_dnode *n);

/*
 * The first child of n that is sn's; the entry of list whose keys are
 * these; the entry of leaf-list ll whose value is this.  NULL: none.
 */
cbl_dnode	*cbl_dnode_child(const cbl_dnode *n,
		    const struct cbl_ynode *sn);
cbl_dnode	*cbl_dnode_entry(const cbl_dnode *parent,
		    const struct cbl_ynode *list, const void *const *keys);
cbl_dnode	*cbl_dnode_llentry(const cbl_dnode *parent,
		    const struct cbl_ynode *ll, const void *value);
/* Whether two values of type t are the same value. */
bool		 cbl_dvalue_equal(const struct cbl_ytype *t, const void *a,
		    const void *b);

/*
 * Defaults (RFC 7950 sections 7.6.1, 7.7.2, 7.9.3).  cbl_dnode_leaf():
 * leaf's value in n, or the default in use where n has none (*isdflt
 * then true): the leaf's, where it is in no choice or in the case n has,
 * or in the choice's default case where n has none of its cases.  NULL:
 * neither.  cbl_dtree_defaults() makes every default in use in n and
 * below a node of its own, flagged CBL_DN_DEFAULT, a non-presence
 * container that holds one too; it returns how many it made, or -1 and
 * errno.  when is not looked at: it is the evaluator's.
 */
const void	*cbl_dnode_leaf(const cbl_dnode *n,
		    const struct cbl_ynode *leaf, bool *isdflt);
ssize_t		 cbl_dtree_defaults(cbl_dnode *n);

/*
 * The structs: struct p of node sn (a container, a list entry, an rpc's
 * input or output, a notification, a structure) made a child of parent,
 * and all it has under it (*out the node made); a node's subtree into
 * its struct p of its schema node's size, zeroed first, pointing into the
 * tree and to what a allocates.  A module's data struct likewise: its
 * top-level nodes, children of the root.
 */
int		 cbl_dnode_from_struct(cbl_dnode *parent,
		    const struct cbl_ynode *sn, const void *p, cbl_dnode **out);
int		 cbl_dnode_to_struct(const cbl_dnode *n, void *p,
		    cbl_yarena *a);
int		 cbl_dtree_from_module(cbl_dtree *t,
		    const struct cbl_ymodule *m, const void *p);
int		 cbl_dtree_to_module(const cbl_dtree *t,
		    const struct cbl_ymodule *m, void *p, cbl_yarena *a);

/*
 * Edits (RFC 6241 section 7.2): a tree of the same schema whose nodes
 * each carry an operation, or their parent's (0), applied to a target.
 * merge makes what is not there and sets the leaves given; replace puts
 * the node given in the place of the one there; create is merge where
 * none is there, data-exists where one is; delete takes away the one
 * there, data-missing where none is; remove takes it away if it is
 * there.  The operation of the edit's top, its default, is merge,
 * replace or none, which changes nothing not asked for and is
 * data-missing where a node the edit goes through is not there.  A node
 * of a choice's case takes the others' place (RFC 7950 section 7.9.2).
 * The edit is all or nothing: on an error the target is as it was, and
 * err, if given, says where (the edit's node), why (RFC 8040's
 * error-tag) and what.  An entry's keys and a leaf-list entry's value
 * say which; an ordered-by user list's new entries go after its last.
 * What the schema says beyond the tree's shape is not checked: the
 * validator's, on the result.
 */
#define	CBL_DOP_MERGE		1
#define	CBL_DOP_REPLACE		2
#define	CBL_DOP_CREATE		3
#define	CBL_DOP_DELETE		4
#define	CBL_DOP_REMOVE		5
#define	CBL_DOP_NONE		6	/* a default only */
#define	CBL_DOP_INSERT		7	/* YANG Patch: a create, where said */
#define	CBL_DOP_MOVE		8	/* YANG Patch: one there, moved */

/*
 * Where an ordered-by user list's entry or leaf-list's value goes (RFC
 * 7950 section 7.8.6, RFC 8072 section 2.5): first, last, or before or
 * after the one whose keys, or value, point gives (point[k] a key's
 * value, point[0] a leaf-list's), copied.  A merge, replace or create
 * puts its node there, an insert or a move must have one.  An entry not
 * there to be put before or after is bad-attribute, missing-instance.
 */
#define	CBL_DWHERE_FIRST	1
#define	CBL_DWHERE_LAST		2
#define	CBL_DWHERE_BEFORE	3
#define	CBL_DWHERE_AFTER	4

struct cbl_dederr {
	const cbl_dnode	*node;
	const char	*tag;
	const char	*apptag;	/* RFC 7950's error-app-tag, or NULL */
	char		 msg[160];
};

int		 cbl_dnode_set_op(cbl_dnode *n, int op);
int		 cbl_dnode_op(const cbl_dnode *n);
int		 cbl_dnode_set_where(cbl_dnode *n, int where,
		    const void *const *point);
int		 cbl_dtree_edit(cbl_dtree *target, const cbl_dtree *edit,
		    int dflt, struct cbl_dederr *err);

/*
 * References (RFC 7950 sections 9.9.2, 9.13.2): every leafref of tree t
 * with require-instance whose value no instance of its target node has,
 * every instance-identifier with require-instance that names no node of
 * t.  0, or ENOENT and err, if given, says the first: data-missing,
 * instance-required.  A leafref's target is the node its path names, any
 * instance of it: a path's predicates, which may narrow that, are the
 * evaluator's; one in a union is not looked at.
 */
int		 cbl_dtree_check_refs(const cbl_dtree *t,
		    struct cbl_dederr *err);

/*
 * XPath-lite (YANG.md section 5) over a tree: expr, as the tables hold
 * one (its names by module), evaluated with context node ctx (NULL: the
 * root) and current node cur (NULL: ctx), current()'s.  The value is a
 * node set (its nodes each once, the array the value's), a boolean, a
 * number or a string (the value's); cbl_xval_free() frees it.  0, or an
 * errno and why (of whylen bytes).
 */
enum cbl_xv_kind {
	CBL_XV_NODES = 1,
	CBL_XV_BOOL,
	CBL_XV_NUMBER,
	CBL_XV_STRING,
};

struct cbl_xval {
	enum cbl_xv_kind	 kind;
	bool			 b;
	double			 num;
	char			*s;
	const cbl_dnode		**nodes;
	size_t			 n;
};

int		 cbl_xp_eval(const cbl_dtree *t, const char *expr,
		    const cbl_dnode *ctx, const cbl_dnode *cur,
		    struct cbl_xval *out, char *why, size_t whylen);
void		 cbl_xval_free(struct cbl_xval *v);

/*
 * The edit that makes tree a tree b, applied to a with the default
 * operation none (a YANG Patch's changes, RFC 8072): creates of what only
 * b has, merges of leaves that differ, removes of what only a has, an
 * ordered-by user list's entries said where when its order is not b's.
 * NULL and errno: ENOTSUP where a list without keys at the top differs.
 */
cbl_dtree	*cbl_dtree_diff(const cbl_dtree *a, const cbl_dtree *b);

/*
 * YANG-CBOR: sn's value (as cbl_ydecode() reads it) made a child of
 * parent; a node's value written, as cbl_yencode() writes it.
 */
int		 cbl_dnode_decode(cbl_dnode *parent,
		    const struct cbl_ynode *sn, const void *data, size_t len,
		    int flags, char *why, size_t whylen, cbl_dnode **out);
int		 cbl_dnode_encode(const cbl_dnode *n, struct cbl_ybuf *b);

#endif /* !_CBL_DATA_H_ */
