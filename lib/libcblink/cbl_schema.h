/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBL_SCHEMA_H_
#define	_CBL_SCHEMA_H_

/*
 * YANG schema tables: what cblink-gen writes of a set of modules (-m
 * schema, PLAN-SDN-YANG 1.6.2) for the library to decode, encode and
 * validate YANG-CBOR by (RFC 9254).  Everything is const and made at
 * compile time.
 *
 * A node is keyed by its SID (RFC 9595); its children, choices and cases
 * passed through, are sorted by SID, so that the delta a map key gives
 * finds the child by a binary search, and a run of children whose deltas
 * follow one another is a dense array.  Types are shared between the
 * nodes that have the same one.  XPath expressions (when, must, a
 * leafref's path) are the schema's, by number, as written: cbl_xpath
 * parses them where they are used.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Built-in types, RFC 7950 section 4.2.4; a leafref has its target's. */
enum cbl_ytype_kind {
	CBL_YT_BINARY = 1,
	CBL_YT_BITS,
	CBL_YT_BOOLEAN,
	CBL_YT_DECIMAL64,
	CBL_YT_EMPTY,
	CBL_YT_ENUMERATION,
	CBL_YT_IDENTITYREF,
	CBL_YT_INSTANCEID,
	CBL_YT_INT8,
	CBL_YT_INT16,
	CBL_YT_INT32,
	CBL_YT_INT64,
	CBL_YT_STRING,
	CBL_YT_UINT8,
	CBL_YT_UINT16,
	CBL_YT_UINT32,
	CBL_YT_UINT64,
	CBL_YT_UNION,
};

/* A range's or a length's part: signed for intN and decimal64 (scaled). */
struct cbl_yrange {
	union {
		int64_t		 i;
		uint64_t	 u;
	} min, max;
};

/* A range or a length, its error-message and error-app-tag. */
struct cbl_yrestrict {
	const struct cbl_yrange	*v;		/* NULL: none */
	uint16_t		 n;
	const char		*emsg;
	const char		*eapptag;
};

/* A pattern: as written, and as the POSIX ERE it was translated to. */
struct cbl_ypattern {
	const char	*xsd;
	const char	*ere;		/* anchored, for regcomp(REG_EXTENDED) */
	bool		 invert;	/* modifier invert-match */
	const char	*emsg;
	const char	*eapptag;
};

/* An enum and its value, or a bit and its position. */
struct cbl_yitem {
	const char	*name;
	int64_t		 value;
};

#define	CBL_YTF_LEAFREF		0x01	/* a leafref: path is its own */
#define	CBL_YTF_REQUIRE		0x02	/* require-instance */

struct cbl_ytype {
	uint8_t			 kind;		/* enum cbl_ytype_kind */
	uint8_t			 flags;		/* CBL_YTF_* */
	uint8_t			 fdigits;	/* decimal64 */
	uint16_t		 npatterns;
	uint16_t		 nmembers;
	uint16_t		 nbases;
	uint32_t		 nitems;
	int32_t			 path;		/* leafref: an expression, or -1 */
	struct cbl_yrestrict	 range;		/* integers, decimal64 */
	struct cbl_yrestrict	 length;	/* string, binary */
	const struct cbl_ypattern *patterns;	/* string: all must match */
	const struct cbl_yitem	*items;		/* enumeration, bits */
	const struct cbl_ytype	*const *members; /* union, in order */
	const uint64_t		*bases;		/* identityref: SIDs */
};

enum cbl_ynode_kind {
	CBL_YN_CONTAINER = 1,
	CBL_YN_LEAF,
	CBL_YN_LEAFLIST,
	CBL_YN_LIST,
	CBL_YN_ANYDATA,
	CBL_YN_ANYXML,
	CBL_YN_RPC,
	CBL_YN_ACTION,
	CBL_YN_NOTIF,
	CBL_YN_INPUT,
	CBL_YN_OUTPUT,
	CBL_YN_STRUCTURE,	/* sx:structure (RFC 8791) */
};

#define	CBL_YNF_CONFIG		0x0001	/* config true */
#define	CBL_YNF_MANDATORY	0x0002
#define	CBL_YNF_KEY		0x0004	/* a list's key leaf */
#define	CBL_YNF_PRESENCE	0x0008	/* a presence container */
#define	CBL_YNF_USERORDER	0x0010	/* ordered-by user */
#define	CBL_YNF_DEPRECATED	0x0020
#define	CBL_YNF_OBSOLETE	0x0040

/*
 * A when statement, and its context node (RFC 7950 section 7.21.5): the
 * node itself, its closest ancestor that is a data node (the when of a
 * uses, an augment, a choice or a case), or the root.
 */
#define	CBL_YWC_SELF		0
#define	CBL_YWC_PARENT		1
#define	CBL_YWC_ROOT		2

struct cbl_ywhen {
	int32_t		 expr;
	uint8_t		 ctx;		/* CBL_YWC_* */
};

/* A must statement: its context is the node. */
struct cbl_ymust {
	int32_t		 expr;
	const char	*emsg;
	const char	*eapptag;
};

struct cbl_ycase {
	const char		*name;
	const struct cbl_ywhen	*when;
	uint16_t		 nwhen;
};

/*
 * A choice, for its cases to be exclusive: a node in one says which case
 * of which choice.  A choice in a case has that case's choice above it.
 */
struct cbl_ychoice {
	const char		*name;
	const struct cbl_ychoice *parent;	/* NULL: right under the node */
	uint16_t		 parent_case;
	uint16_t		 ncases;
	const struct cbl_ycase	*cases;
	int32_t			 dflt;		/* the default case, or -1 */
	bool			 mandatory;
	const struct cbl_ywhen	*when;		/* the choice's own */
	uint16_t		 nwhen;
};

struct cbl_ymodule;

struct cbl_ynode {
	uint64_t		 sid;
	const char		*name;
	const struct cbl_ymodule *module;	/* the one that defines it */
	uint8_t			 kind;		/* enum cbl_ynode_kind */
	uint16_t		 flags;		/* CBL_YNF_* */
	uint16_t		 nkeys;
	uint16_t		 nwhen;
	uint16_t		 nmust;
	uint16_t		 ndflt;
	uint16_t		 ccase;		/* in choice: which case */
	uint32_t		 nchild;
	uint32_t		 min;		/* list, leaf-list: min-elements */
	uint32_t		 max;		/* and max-elements; 0: none */
	const struct cbl_ytype	*type;		/* leaf, leaf-list */
	const struct cbl_ynode	*const *child;	/* by SID */
	const uint32_t		*keys;		/* list: indices in child */
	const struct cbl_ywhen	*when;
	const struct cbl_ymust	*must;
	const char		*const *dflt;	/* canonical */
	const char		*units;
	const struct cbl_ychoice *choice;	/* the one it is in, or NULL */
};

struct cbl_ymodule {
	const char		*name;
	const char		*revision;	/* NULL: none */
	const char		*ns;
	const char		*prefix;
	uint64_t		 sid;
	uint32_t		 ntop;
	/* Its data at the top, rpcs, notifications, structures: by SID. */
	const struct cbl_ynode	*const *top;
};

struct cbl_yschema {
	uint32_t		 nmod;
	uint32_t		 nxpath;
	const struct cbl_ymodule *const *mod;
	const char		*const *xpath;	/* when, must, path: as written */
};

#endif /* !_CBL_SCHEMA_H_ */
