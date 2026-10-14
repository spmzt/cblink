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
#include <stdio.h>

struct smodule;
struct sident;
struct snode;
struct swnode;

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
	struct swnode	*written;	/* sx:augment-structure: as written */
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

/*
 * A when's context node (RFC 7950 section 7.21.5): the node itself, its
 * closest ancestor that is a data node (a when of a uses, an augment, a
 * choice or a case), or the root.
 */
#define	SWC_SELF	0
#define	SWC_PARENT	1
#define	SWC_ROOT	2

/* snode flags. */
#define	SNF_CONFIG	0x0001	/* config true (else state) */
#define	SNF_MANDATORY	0x0002
#define	SNF_KEY		0x0004	/* a list's key leaf */
#define	SNF_PRESENCE	0x0008	/* a presence container */
#define	SNF_USERORDER	0x0010	/* ordered-by user */
#define	SNF_DEPRECATED	0x0020
#define	SNF_OBSOLETE	0x0040
#define	SNF_INTERNAL	0x0080	/* libyang's, not the module's */
/* A written node's (struct swnode), with SNF_CONFIG for config true. */
#define	SNF_STATE	0x0100	/* config false */
#define	SNF_CURRENT	0x0200	/* status current */

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
/* A list's unique statement: the leaves, descendants of the list. */
struct sunique {
	struct snode	**leaf;
	size_t		 n;
};

struct snode {
	enum snode_kind	 kind;
	char		*name;
	struct smodule	*module;	/* the module that defines it */
	struct snode	*parent;	/* NULL at the top */
	struct snode	*child;		/* first child */
	struct snode	*next;		/* next sibling */
	uint32_t	 flags;		/* SNF_* */
	struct sntype	*type;		/* leaf, leaf-list */
	char		*wtype;		/* ... its type, as written */
	char		*wpath;		/* ... a leafref's path written there */
	uint32_t	 min;		/* list, leaf-list: min-elements */
	uint32_t	 max;		/* list, leaf-list: max-elements */
	struct snode	**keys;		/* list: its key leaves, in order */
	size_t		 nkeys;
	struct sunique	*uniques;	/* list: its unique statements */
	size_t		 nuniques;
	char		*units;		/* leaf, leaf-list */
	char		**dflts;	/* leaf (one), leaf-list: canonical */
	size_t		 ndflts;
	struct snode	*dflt_case;	/* choice: its default case */
	char		**when;		/* when expressions, as written */
	uint8_t		*whenctx;	/* each one's context node: SWC_* */
	size_t		 nwhen;
	struct smust	*musts;
	size_t		 nmusts;
	char		**iffeatures;	/* its if-features, as written */
	size_t		 niffeatures;
	struct sext	*exts;		/* its extension instances */
	size_t		 nexts;
	struct sext	*in;		/* the instance holding it, or NULL */
	uint64_t	 sid;		/* 0: none (choice, case, or unassigned) */
};

/*
 * A node as its module writes it, before groupings are expanded and
 * augments applied, for what a tree diagram (RFC 8340) shows that way:
 * the module's augments of other modules' trees and the nodes of its
 * sx:augment-structure.  It says only what its statement says: config
 * and status where they are written, a uses as itself.
 */
struct swnode {
	enum snode_kind	 kind;		/* SN_CONTAINER for a uses */
	bool		 uses;		/* a uses: name is the grouping's */
	char		*name;
	struct swnode	*parent;
	struct swnode	*child;		/* data nodes, actions, notifications */
	struct swnode	*next;
	uint32_t	 flags;		/* SNF_*, as written */
	char		*type;		/* leaf, leaf-list: as written */
	char		*path;		/* ... a leafref's path written there */
	char		*key;		/* list: its key statement */
	char		**iffeatures;
	size_t		 niffeatures;
};

/* An augment of another module's tree, as written. */
struct saugment {
	char		*target;	/* its schema node identifier */
	struct swnode	*nodes;
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
	bool		 given;		/* named on the command line */
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
	struct saugment	*augments;	/* of other modules' trees */
	size_t		 naugments;
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
/*
 * Whether what is generated has the module's trees: those of the modules
 * named, and those they add to (ietf-ip's nodes are in ietf-interfaces'
 * tree); not what libyang implements of its own (yang-library).
 */
bool		 smodule_emitted(const struct smodule *m);
/*
 * Whether e is a structure of m's own, written in it: an sx:structure
 * (RFC 8791) or an rc:yang-data (RFC 8040), which RFC 9595 numbers
 * alike, a SID for the structure, its nodes from /m:structure.
 */
bool		 sext_is_structure(const struct sext *e,
		    const struct smodule *m);
bool		 sntype_signed(enum sntype_base base);

/*
 * Walk every node, depth first, parents before children: data, then rpcs,
 * then notifications of each module, in the order the modules were added.
 */
typedef void	snode_visit_t(struct snode *n, void *arg);
void		 schema_walk(struct schema *s, snode_visit_t *visit, void *arg);

struct diags;
/*
 * The profile: every XPath expression parsed and within XPath-lite, every
 * pattern translated and compiled.  The count of expressions, that of
 * patterns in *npatterns, problems added to d.
 */
size_t		 schema_check_profile(struct schema *s, struct diags *d,
		    size_t *npatterns);

struct buf;
/*
 * A node's identifier in a .sid file (RFC 9595): its schema node path
 * with choices and cases left out, a step naming its module where it
 * differs from its parent's; a node in a structure starts from
 * /module:structure.  False for a choice or a case, which have none.
 */
bool		 snode_sid_path(const struct snode *n, struct buf *b);

/*
 * The C header of the schema's structs (gen_yang.c), base naming its
 * guard, from the inputs it says it was generated from; -1 and
 * diagnostics when two names collide.
 */
int		 gen_yang_h(struct schema *s, const char *base,
		    const char *from, struct buf *out, struct diags *d);

/*
 * The C names gen_yang_h() gives: a name made C's, a node's struct (and
 * the enum or union struct of its type), its member in its parent's,
 * and whether a leaf has a has_ flag beside it.
 */
/*
 * The nodes a server has handlers for (-m server): a top-level data
 * node's get and edit, an rpc's, an action's, a notification's encoder;
 * m the module whose data struct a top-level node is a member of.
 */
enum yc_handler {
	YH_DATA,
	YH_RPC,
	YH_ACTION,
	YH_NOTIF,
};
typedef void	 yc_handler_f(void *arg, enum yc_handler kind,
		    const struct snode *n, const struct smodule *m);
void		 yc_handlers(const struct schema *s, yc_handler_f *cb,
		    void *arg);
void		 yc_mangle(struct buf *b, const char *s);
void		 yc_struct(struct buf *b, const struct snode *n);
void		 yc_member(struct buf *b, const struct snode *n);
bool		 yc_has_flag(const struct snode *n);

/*
 * The schema tables (cbl_schema.h) of the modules gen_yang_h() makes
 * structs of, as base_schema.c (gen_yschema.c); what each module's
 * come to said on report too.  -1 and diagnostics for a node or an
 * identityref base without a SID.
 */
int		 gen_yang_schema(struct schema *s, const char *base,
		    const char *from, struct buf *out, FILE *report,
		    struct diags *d);

/*
 * A .sid file given (-s), as the server's GET-SID sends it: its module,
 * and the value of its ietf-sid-file structure in YANG-CBOR.
 */
struct ysidcbor {
	char		*module;
	char		*revision;	/* NULL: none */
	struct buf	 cbor;
};

/*
 * The server's handler table (cbl_schema.h) of the same modules, as
 * base_server.c (gen_yserver.c), with the .sid files given.  -1 and
 * diagnostics for a node without a SID.
 */
int		 gen_yang_server(struct schema *s, const char *base,
		    const char *from, const struct ysidcbor *sids,
		    size_t nsids, struct buf *out, struct diags *d);

/* One line a node, as tools/yangwalk prints them, for cross-checks. */
void		 schema_dump(struct schema *s);

/*
 * The tree diagrams (RFC 8340) of the modules named on the command line,
 * as yanglint -f tree prints them (gen_ytree.c); one module's.
 */
void		 gen_yang_tree(const struct schema *s, struct buf *b);
void		 gen_yang_tree_module(const struct smodule *m, struct buf *b);

/*
 * Markdown, a page for each module named on the command line: its tree
 * diagram and its nodes, wherever they are, with their SIDs when the
 * module's .sid file is attached (gen_ymd.c); from names the inputs.
 */
void		 gen_yang_md(const struct schema *s, const char *from,
		    struct buf *b);

#endif /* !_CBLINK_GEN_SCHEMA_H_ */
