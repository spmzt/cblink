/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The instance tree's insides (cbl_data.c), for its edits (cbl_dedit.c):
 * not exported.
 */

#ifndef _CBL_DIMPL_H_
#define	_CBL_DIMPL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cbl_data.h"

#define	CBL_D_DEPTH_MAX	64

struct cbl_dnode {
	const struct cbl_ynode	*sn;
	cbl_dtree		*tree;
	cbl_dnode		*parent, *next, *prev, *first, *last;
	/* By schema child: its first and last instance here, or NULL. */
	cbl_dnode		**head, **tail;
	cbl_dnode		*hnext;		/* an entry, in the index */
	uint64_t		 hash;
	uint16_t		 flags;
	uint8_t			 op;		/* an edit's, CBL_DOP_*; 0: its parent's */
	uint8_t			 where;		/* and its CBL_DWHERE_*, or 0 */
	void			**point;	/* before or after: its keys, or value */
	void			*value;
};

/* A default, parsed once for the tree. */
struct cbl_ddflt {
	const struct cbl_ynode	*sn;
	uint16_t		 k;
	const void		*v;
	struct cbl_ddflt	*next;
};

#define	CBL_D_NDFLT	64

struct cbl_dtree {
	const struct cbl_yschema *schema;
	cbl_dnode		 root;
	/* The root's children: every module's top-level nodes, in turn. */
	const struct cbl_ynode	**tops;
	uint32_t		 ntops;
	size_t			 count;
	cbl_dnode		**slot;		/* the index, nslot a power of 2 */
	size_t			 nslot, nentries;
	struct cbl_ddflt	*dflt[CBL_D_NDFLT];
	cbl_yarena		*arena;		/* the defaults' */
};

/*
 * n and all below it taken out of the tree, kept as they are, to be put
 * back after prev (NULL: first of its kind) under parent, or freed.
 */
void	cbl_d_detach(cbl_dnode *n);
void	cbl_d_reattach(cbl_dnode *parent, cbl_dnode *n, cbl_dnode *prev);
void	cbl_d_free(cbl_dnode *n);
/* n moved among its siblings, after prev (NULL: first of all). */
void	cbl_d_move_after(cbl_dnode *n, cbl_dnode *prev);
/* Whether two schema nodes are in no different cases of one choice. */
bool	cbl_d_same_case(const struct cbl_ynode *a, const struct cbl_ynode *b);
/* An entry's k-th key's value. */
const void *cbl_d_key_value(const cbl_dnode *e, uint16_t k);
/*
 * What a when's expression sees (RFC 7950 section 7.21.5): dummy, if not
 * NULL, a node with no value and no children; none of the children of
 * hpar that hide(harg, their schema node) says.
 */
struct cbl_d_view {
	const cbl_dnode	*dummy;
	const cbl_dnode	*hpar;
	bool		(*hide)(const void *, const struct cbl_ynode *);
	const void	*harg;
};

/* cbl_xp_eval() with a view, or NULL: the tree as it is. */
struct cbl_xval;
int		 cbl_d_xp_eval(const cbl_dtree *t, const char *expr,
		    const cbl_dnode *ctx, const cbl_dnode *cur,
		    const struct cbl_d_view *view, struct cbl_xval *out,
		    char *why, size_t whylen);

/* Defaults under n whose whens are false removed (cbl_dcond.c). */
ssize_t		 cbl_d_prune_defaults(cbl_dnode *n);

/* The node an instance-identifier's YANG-CBOR names in t, or NULL. */
const cbl_dnode *cbl_d_iid_node(const cbl_dtree *t,
	    const struct cbl_bytes *v, cbl_yarena *a);
/* n's value set to a copy of value, the one it had freed; and freed. */
int	cbl_d_set_value(cbl_dnode *n, const void *value);
void	cbl_d_free_value(cbl_dnode *n);

#endif /* !_CBL_DIMPL_H_ */
