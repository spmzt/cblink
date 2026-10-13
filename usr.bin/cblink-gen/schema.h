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
struct sident;
struct snode;

/*
 * An extension instance on a node or a module: the extension (its
 * module's name and its own), its argument, the module whose text
 * carries the instance, and, for one that holds data nodes
 * (sx:structure, rc:yang-data; an sx:augment-structure's nodes are put
 * into the structure they augment), those nodes.  libyang copies some
 * down from an ancestor (NACM's default-deny-*): a copy is inherited.
 */
struct sext {
	char		*ext;		/* "module:name" */
	char		*arg;		/* NULL: none */
	struct smodule	*module;	/* where it is written */
	bool		 inherited;
	struct snode	*data;		/* the nodes it holds */
	uint64_t	 sid;		/* a structure's; 0: none */
};

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

/* Built-in types, after RFC 7950 section 4.2.4. */
enum sntype_base {
	ST_BINARY,
	ST_BITS,
	ST_BOOLEAN,
	ST_DECIMAL64,
	ST_EMPTY,
	ST_ENUMERATION,
	ST_IDENTITYREF,
	ST_INSTANCEID,
	ST_INT8,
	ST_INT16,
	ST_INT32,
	ST_INT64,
	ST_LEAFREF,
	ST_STRING,
	ST_UINT8,
	ST_UINT16,
	ST_UINT32,
	ST_UINT64,
	ST_UNION,
};

/*
 * A range or length: its parts, each min..max, signed for the signed
 * integers and decimal64 (whose bounds are scaled by its fraction
 * digits), unsigned otherwise.
 */
struct srange {
	struct srange_part {
		union {
			int64_t		 i;
			uint64_t	 u;
		} min, max;
	}		*parts;
	size_t		 nparts;
	char		*emsg;		/* error-message, or NULL */
	char		*eapptag;	/* error-app-tag, or NULL */
};

struct spattern {
	char		*expr;		/* XSD regular expression, as written */
	bool		 invert;	/* modifier invert-match */
	char		*emsg;
	char		*eapptag;
};

/* An enum with its value, or a bit with its position. */
struct sitem {
	char		*name;
	int64_t		 value;
	uint32_t	 flags;		/* SNF_DEPRECATED, SNF_OBSOLETE */
};

/*
 * A type as compiled: the built-in it comes to, every restriction its
 * typedef chain adds (a string's patterns accumulate), and what its kind
 * needs.
 */
struct sntype {
	enum sntype_base base;
	char		*name;		/* the typedef, NULL for a built-in */
	struct srange	*range;		/* integers, decimal64 */
	struct srange	*length;	/* string, binary */
	struct spattern	*patterns;	/* string */
	size_t		 npatterns;
	struct sitem	*items;		/* enumeration, bits */
	size_t		 nitems;
	uint8_t		 fdigits;	/* decimal64 */
	struct sident	**bases;	/* identityref */
	size_t		 nbases;
	char		*path;		/* leafref */
	struct sntype	*real;		/* leafref: the target's type */
	bool		 require_instance; /* leafref, instance-identifier */
	struct sntype	**members;	/* union */
	size_t		 nmembers;
};

/* A must statement. */
struct smust {
	char		*expr;		/* XPath, as written */
	char		*emsg;
	char		*eapptag;
};

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
	char		*units;		/* leaf, leaf-list */
	char		**dflts;	/* leaf (one), leaf-list: canonical */
	size_t		 ndflts;
	struct snode	*dflt_case;	/* choice: its default case */
	char		**when;		/* when expressions, as written */
	size_t		 nwhen;
	struct smust	*musts;
	size_t		 nmusts;
	struct sext	*exts;		/* its extension instances */
	size_t		 nexts;
	struct sext	*in;		/* the instance holding it, or NULL */
	uint64_t	 sid;		/* 0: none (choice, case, or unassigned) */
};

/* An identity, and those derived from it directly. */
struct sident {
	struct smodule	*module;
	char		*name;
	struct sident	**derived;
	size_t		 nderived;
	uint32_t	 flags;		/* SNF_DEPRECATED, SNF_OBSOLETE */
	uint64_t	 sid;
};

struct sfeature {
	char		*name;
	bool		 enabled;
	uint64_t	 sid;
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
	struct simport {
		char	*name;
		char	*revision;	/* the one bound, NULL: none */
	}		*imports;
	size_t		 nimports;
	struct snode	*data;		/* top-level data nodes */
	struct snode	*rpcs;
	struct snode	*notifs;
	struct sext	*exts;		/* instances at the top of the module */
	size_t		 nexts;
	uint64_t	 sid;
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
struct sident	*schema_ident_in(struct smodule *m, const char *name);
const char	*snode_kind_name(enum snode_kind kind);
/* The node's instance of the extension "module:name", or NULL. */
const struct sext *snode_ext(const struct snode *n, const char *ext);
const char	*sntype_base_name(enum sntype_base base);
bool		 sntype_signed(enum sntype_base base);

/*
 * Walk every node, depth first, parents before children: data, then rpcs,
 * then notifications of each module, in the order the modules were added.
 */
typedef void	snode_visit_t(struct snode *n, void *arg);
void		 schema_walk(struct schema *s, snode_visit_t *visit, void *arg);

struct diags;
/* Every XPath expression parsed; the count, problems added to d. */
size_t		 schema_check_xpath(struct schema *s, struct diags *d);

struct buf;
/*
 * A node's identifier in a .sid file (RFC 9595): its schema node path
 * with choices and cases left out, a step naming its module where it
 * differs from its parent's; a node in a structure starts from
 * /module:structure.  False for a choice or a case, which have none.
 */
bool		 snode_sid_path(const struct snode *n, struct buf *b);

/* One line a node, as tools/yangwalk prints them, for cross-checks. */
void		 schema_dump(struct schema *s);

#endif /* !_CBLINK_GEN_SCHEMA_H_ */
