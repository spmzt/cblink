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

/* A node's annotation (RFC 7952) and its value, the tree's copy. */
struct cbl_dmeta {
	const struct cbl_yannot	*an;
	void			*value;
	struct cbl_dmeta	*next;		/* by SID */
};

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
	struct cbl_dmeta	*meta;
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
	/* A mounted tree's parent references (cbl_dtree_set_refs()). */
	const struct cbl_dtree	*refs;
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

/*
 * Node n made under op, of another tree maybe: an entry by its keys (one
 * there already if it has keys), a value; and with all below it.
 */
int		 cbl_d_mirror(cbl_dnode *op, const cbl_dnode *n, cbl_dnode **made);
int		 cbl_d_copy(cbl_dnode *op, const cbl_dnode *n, cbl_dnode **made,
		    int depth);
/* A copy of a value of type t, malloc'd; and freed. */
void		*cbl_d_vdup(const struct cbl_ytype *t, const void *value);
void		 cbl_d_vdel(const struct cbl_ytype *t, void *v);
/* A value's canonical string (RFC 7950 section 9), malloc'd, in *out. */
int		 cbl_d_vstring(const struct cbl_yschema *s,
		    const struct cbl_ytype *t, const void *v, char **out);

/* Defaults under n whose whens are false removed (cbl_dcond.c). */
ssize_t		 cbl_d_prune_defaults(cbl_dnode *n);

/* The node an instance-identifier's YANG-CBOR names in t, or NULL. */
const cbl_dnode *cbl_d_iid_node(const cbl_dtree *t,
	    const struct cbl_bytes *v, cbl_yarena *a);
/* n's value set to a copy of value, the one it had freed; and freed. */
int	cbl_d_set_value(cbl_dnode *n, const void *value);
/* The nodes a node of sn may have as children in tree t: sn's, or the
 * top-level ones at the root or a mount point (RFC 8528). */
const struct cbl_ynode *const *cbl_d_kids(const cbl_dtree *t,
	    const struct cbl_ynode *sn, uint32_t *nk);
/* Value p of type t within t's restrictions (cbl_yvalid.c): the
 * decoder's choice of a union's member, RFC 7950 9.12. */
bool	cbl_ytype_admits(const struct cbl_yschema *s,
	    const struct cbl_ytype *t, const void *p);
void	cbl_d_meta_free(cbl_dnode *n);
/* YANG-CBOR of the tree, in cbl_ycodec.c: parent the root and sn NULL,
 * the top-level map. */
int	cbl_d_decode(cbl_dnode *parent, const struct cbl_ynode *sn,
	    const void *data, size_t len, int flags, char *why, size_t whylen,
	    cbl_dnode **out);
int	cbl_d_encode(const cbl_dnode *n, struct cbl_ybuf *b);
void	cbl_d_free_value(cbl_dnode *n);

#endif /* !_CBL_DIMPL_H_ */
