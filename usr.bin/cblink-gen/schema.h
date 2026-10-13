/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBLINK_GEN_SCHEMA_H_
#define	_CBLINK_GEN_SCHEMA_H_

/*
 * The generator's own model of a compiled YANG schema: what the emitter
 * reads, made from libyang's compiled tree by the YANG front end
 * (yang.c), so that nothing after the front end depends on libyang.
 * Every string and array is owned by the schema and freed with it.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct smodule;
struct sntype;

enum snode_kind {
	SN_CONTAINER,
	SN_LEAF,
	SN_LEAFLIST,
	SN_LIST,
	SN_CHOICE,
	SN_CASE,
	SN_ANYDATA,
	SN_ANYXML,
	SN_RPC,
	SN_ACTION,
	SN_NOTIF,
	SN_INPUT,
	SN_OUTPUT,
};

/* snode flags. */
#define	SNF_CONFIG	0x0001	/* config true (else state) */
#define	SNF_MANDATORY	0x0002
#define	SNF_KEY		0x0004	/* a list's key leaf */
#define	SNF_PRESENCE	0x0008	/* a presence container */
#define	SNF_USERORDER	0x0010	/* ordered-by user */
#define	SNF_DEPRECATED	0x0020
#define	SNF_OBSOLETE	0x0040

/*
 * A schema node.  Children are in schema order: data nodes, then the
 * node's actions, then its notifications; an rpc's or action's are its
 * input and its output, always both.
 */
struct snode {
	enum snode_kind	 kind;
	char		*name;
	struct smodule	*module;	/* the module that defines it */
	struct snode	*parent;	/* NULL at the top */
	struct snode	*child;		/* first child */
	struct snode	*next;		/* next sibling */
	uint32_t	 flags;		/* SNF_* */
	struct sntype	*type;		/* leaf, leaf-list */
	uint32_t	 min;		/* list, leaf-list: min-elements */
	uint32_t	 max;		/* list, leaf-list: max-elements */
	struct snode	**keys;		/* list: its key leaves, in order */
	size_t		 nkeys;
};

/* An identity, and those derived from it directly. */
struct sident {
	struct smodule	*module;
	char		*name;
	struct sident	**derived;
	size_t		 nderived;
	uint32_t	 flags;		/* SNF_DEPRECATED, SNF_OBSOLETE */
};

struct sfeature {
	char		*name;
	bool		 enabled;
};

struct smodule {
	char		*name;
	char		*revision;	/* NULL: none */
	char		*ns;
	char		*prefix;
	bool		 implemented;
	struct sfeature	*features;
	size_t		 nfeatures;
	struct sident	*idents;
	size_t		 nidents;
	char		**deviated_by;	/* module names */
	size_t		 ndeviated_by;
	struct snode	*data;		/* top-level data nodes */
	struct snode	*rpcs;
	struct snode	*notifs;
};

struct schema {
	struct smodule	**mods;
	size_t		 nmods;
};

struct schema	*schema_new(void);
void		 schema_free(struct schema *s);
struct smodule	*schema_module(struct schema *s, const char *name,
		    const char *revision);
struct sident	*schema_ident(struct schema *s, const char *module,
		    const char *name);
const char	*snode_kind_name(enum snode_kind kind);

/*
 * Walk every node, depth first, parents before children: data, then rpcs,
 * then notifications of each module, in the order the modules were added.
 */
typedef void	snode_visit_t(struct snode *n, void *arg);
void		 schema_walk(struct schema *s, snode_visit_t *visit, void *arg);

/* One line a node, as tools/yangwalk prints them, for cross-checks. */
void		 schema_dump(struct schema *s);

#endif /* !_CBLINK_GEN_SCHEMA_H_ */
