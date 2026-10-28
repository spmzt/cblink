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
 * finds the child (cbl_ynode_child()): at once when their SIDs follow
 * one another (dense), by a small table when they lie close (RFC 9595's
 * numbering puts a child's own children between it and the next), by a
 * binary search otherwise, as for what another module augments in from
 * its own range.  Types are shared between the nodes that have the same
 * one.  XPath expressions (when, must, a
 * leafref's path) are the schema's, by number, as written: cbl_xpath
 * parses them where they are used.
 *
 * And where each node is in the C structs cblink-gen writes of the same
 * modules (-m h): its member's offset in its parent's struct, its has_
 * flag's, its own struct's size; a choice's enum member; a value's C
 * size; so that one codec (cbl_yencode(), cbl_ydecode()) does every
 * struct.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cblink.h>

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

/* No member: a node that is not in its parent's struct, or no flag. */
#define	CBL_YOFF_NONE		UINT32_MAX

struct cbl_ytype {
	uint8_t			 kind;		/* enum cbl_ytype_kind */
	uint8_t			 flags;		/* CBL_YTF_* */
	uint8_t			 fdigits;	/* decimal64 */
	uint32_t		 csize;		/* a value's C size */
	uint32_t		 voff;		/* union: where v is in its struct */
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
/* NACM's (RFC 8341 section 3.5): written only by a rule that permits it;
 * read, written and run only so. */
#define	CBL_YNF_DENY_WRITE	0x0080	/* nacm:default-deny-write */
#define	CBL_YNF_DENY_ALL	0x0100	/* nacm:default-deny-all */
/* A schema mount point (RFC 8528, yangmnt:mount-point): below it, the
 * schema's own top-level nodes (a shared schema), in YANG-CBOR keyed by
 * their absolute SIDs (tag 47), in its struct as struct cbl_ymounts. */
#define	CBL_YNF_MOUNT		0x0200

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
	uint32_t		 off;		/* its enum member: case + 1, 0 none */
};

/*
 * A list's unique statement (RFC 7950 section 7.8.3): for each leaf, the
 * data nodes from a list entry down to it, NULL after the leaf.
 */
struct cbl_yunique {
	uint16_t			 n;
	const struct cbl_ynode *const *const *leaf;
};

struct cbl_ymodule;

/*
 * What a mount point has mounted (CBL_YNF_MOUNT): a module's data struct
 * each, as a module's top-level nodes are filled; NULL data, none.
 */
struct cbl_ymounted {
	const struct cbl_ymodule	*module;
	void				*data;
};

struct cbl_ymounts {
	size_t				 n;
	const struct cbl_ymounted	*v;
};

struct cbl_ynode {
	uint64_t		 sid;
	/*
	 * What its children's SID deltas are from: an rpc's or an
	 * action's input and output, the rpc's or the action's SID (RFC
	 * 9254 section 3.2); 0, every other node, its own.
	 */
	uint64_t		 base;
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
	/*
	 * The children from the first, by SID - child[0]->sid below nmap:
	 * child[that] itself when map is NULL (dense), else child[map[that]
	 * - 1] when not 0; the others by a binary search.
	 */
	uint32_t		 nmap;
	uint32_t		 min;		/* list, leaf-list: min-elements */
	uint32_t		 max;		/* and max-elements; 0: none */
	uint32_t		 off;		/* its member in its parent's struct */
	uint32_t		 hoff;		/* its has_ flag's, or NONE */
	uint32_t		 moff;		/* a mount point's mounted */
	uint32_t		 size;		/* its own struct's: container, ... */
	const struct cbl_ytype	*type;		/* leaf, leaf-list */
	const struct cbl_ynode	*const *child;	/* by SID */
	const uint16_t		*map;
	const uint32_t		*keys;		/* list: indices in child */
	uint16_t		 nunique;	/* list: unique statements */
	const struct cbl_yunique *unique;
	const struct cbl_ywhen	*when;
	const struct cbl_ymust	*must;
	const char		*const *dflt;	/* canonical */
	const char		*units;
	const struct cbl_ychoice *choice;	/* the one it is in, or NULL */
	/* The data node it is a child of (choices and cases passed over,
	 * an rpc's for its input): NULL at the top of its module. */
	const struct cbl_ynode	*parent;
	/* A leaf or leaf-list of type leafref: the node its path names. */
	const struct cbl_ynode	*lref;
};

/*
 * An identity, and every identity derived from it, directly or not, by
 * SID: derived-from(x, base) is x in base's derived, derived-from-or-
 * self also x the base.
 */
struct cbl_yident {
	uint64_t		 sid;
	const char		*name;
	const struct cbl_ymodule *module;
	uint16_t		 flags;		/* CBL_YNF_DEPRECATED, _OBSOLETE */
	uint32_t		 nderived;
	const uint64_t		*derived;
};

/* A feature, and whether the schema was compiled with it. */
struct cbl_yfeature {
	uint64_t		 sid;
	const char		*name;
	bool			 enabled;
};

struct cbl_yschema;
struct cbl_ymodule;

/*
 * A metadata annotation (RFC 7952's md:annotation): its name, its SID
 * (a .sid file's namespace "annotation", draft-ietf-core-yang-metadata)
 * and its value's type.
 */
struct cbl_yannot {
	const struct cbl_ymodule *module;
	const char		*name;
	uint64_t		 sid;
	const struct cbl_ytype	*type;
};

struct cbl_ymodule {
	const struct cbl_yschema *schema;	/* the tables it is in */
	const char		*name;
	const char		*revision;	/* NULL: none */
	const char		*ns;
	const char		*prefix;
	uint64_t		 sid;
	uint32_t		 ntop;
	uint32_t		 nfeature;
	uint32_t		 size;		/* its data's struct, 0: none */
	/* Its data at the top, rpcs, notifications, structures: by SID. */
	const struct cbl_ynode	*const *top;
	const struct cbl_yfeature *feature;	/* by name, as the module */
	uint32_t		 nannot;
	const struct cbl_yannot	*annot;		/* by name */
};

struct cbl_yschema {
	uint32_t		 nmod;
	uint32_t		 nxpath;
	uint32_t		 nident;
	uint32_t		 nnode;
	const struct cbl_ymodule *const *mod;
	const struct cbl_ynode	*const *node;	/* every node, by SID */
	const char		*const *xpath;	/* when, must, path: as written */
	/*
	 * The identities a value may name: the modules', and every one
	 * derived from a base an identityref has, wherever it is
	 * defined; by SID.
	 */
	const struct cbl_yident	*ident;
	uint32_t		 nannot;
	const struct cbl_yannot	*const *annot;	/* every module's, by SID */
};

/* The child of n a map key's delta names (RFC 9254), or NULL. */
/* The SID n's children's deltas are from. */
static inline uint64_t
cbl_ynode_base(const struct cbl_ynode *n)
{

	return (n->base != 0 ? n->base : n->sid);
}

const struct cbl_ynode *cbl_ynode_child(const struct cbl_ynode *n,
		    int64_t delta);
/* The node, the structure, of a SID, or NULL. */
const struct cbl_ynode *cbl_yschema_node(const struct cbl_yschema *s,
		    uint64_t sid);
/* The identity of a SID, or NULL. */
const struct cbl_yident *cbl_yschema_ident(const struct cbl_yschema *s,
		    uint64_t sid);
/* The annotation of a SID; module m's named name.  NULL: none. */
const struct cbl_yannot *cbl_yschema_annot(const struct cbl_yschema *s,
		    uint64_t sid);
const struct cbl_yannot *cbl_ymodule_annot(const struct cbl_ymodule *m,
		    const char *name);
/*
 * Whether identity x is derived from base (XPath derived-from()), or is
 * it with self (derived-from-or-self()).
 */
bool		 cbl_yderived_from(const struct cbl_yschema *s, uint64_t x,
		    uint64_t base, bool self);

/*
 * YANG-CBOR (RFC 9254) of the structs cblink-gen writes, by the tables
 * (cbl_ycodec.c).  A node's value is a map of its children keyed by
 * their deltas from it: n is a container, a list entry, an input, an
 * output, a notification or a structure, p its struct.
 */
struct cbl_ybuf {
	uint8_t		*p;		/* realloc(3)ed */
	size_t		 len;
	size_t		 cap;
};

void		 cbl_ybuf_free(struct cbl_ybuf *b);

/* What a decode allocates, freed in one. */
typedef struct cbl_yarena cbl_yarena;

cbl_yarena	*cbl_yarena_new(void);
void		 cbl_yarena_free(cbl_yarena *a);
/*
 * len bytes, zeroed, a's until it is freed: for a handler's answer; NULL
 * past the arena's limit, 64 MiB unless set: a decode fails with ENOMEM
 * rather than allocate more for what a peer sent.
 */
void		*cbl_yarena_alloc(cbl_yarena *a, size_t len);
void		 cbl_yarena_set_limit(cbl_yarena *a, size_t limit);
/*
 * fn(arg) when a is freed, the last given first: what an answer points
 * to and the arena does not hold (a handler's own buffers) lives until
 * it is encoded.  ENOMEM, and fn is not called.
 */
int		 cbl_yarena_atfree(cbl_yarena *a, void (*fn)(void *),
		    void *arg);
/*
 * A value of type t, leaf or leaf-list n's, from its canonical string s
 * into out, as its member is (what it points to in a; a string's, s
 * itself): what a program reads from a person, a list's key or an
 * rpc's input.  EOPNOTSUPP: a type not read from a string.
 */
int		 cbl_yvalue_parse(const struct cbl_ynode *n,
		    const struct cbl_ytype *t, const char *s, void *out,
		    cbl_yarena *a);
/*
 * An instance-identifier's YANG-CBOR (RFC 9254 section 6.13.1): a SID,
 * or [SID, values...]: *node, the node of schema s it names, and *vals,
 * the keys of the lists from the top down to it, then a leaf-list
 * entry's value, each as its member is, allocated in a (an action's
 * handler reads its target's keys so).
 */
int		 cbl_yiid_read(const struct cbl_yschema *s,
		    const struct cbl_bytes *v, const struct cbl_ynode **node,
		    const void ***vals, size_t *nvals, cbl_yarena *a);
/*
 * n's instance-identifier (RFC 9254 section 6.13.1) into b: the SID, or
 * [SID, values...], the keys of every list from the top down to n, then
 * a leaf-list entry's value, nvals of them, each pointing at a value as
 * its member is (a string key's const char *, an integer's).
 */
int		 cbl_yiid_write(const struct cbl_ynode *n,
		    const void *const *vals, size_t nvals, struct cbl_ybuf *b);

/* n's value from its struct p, appended to b.  0, or an errno. */
int		 cbl_yencode(const struct cbl_ynode *n, const void *p,
		    struct cbl_ybuf *b);

/* {n's SID: its value}: a top-level node, a notification, on its own. */
int		 cbl_yencode_sid(const struct cbl_ynode *n, const void *p,
		    struct cbl_ybuf *b);

#define	CBL_YD_STRICT		0x01	/* a key of no child is an error */

/*
 * n's value from len bytes of data into p, zeroed, of n->size bytes;
 * what it points to is a's.  0, or an errno and why (a's bytes then
 * hold what was made so far, for cbl_yarena_free()).  It checks what
 * the CBOR is; what the schema further says is the validator's.
 */
int		 cbl_ydecode(const struct cbl_ynode *n, const void *data,
		    size_t len, void *p, cbl_yarena *a, int flags, char *why,
		    size_t whylen);

/*
 * A node as a member of its parent's struct: a module's top-level node
 * in the module's data struct (a container's pointer, a list's array, a
 * leaf's value), its value alone.  ENOENT from the encoder: not there
 * (cbl_ymember_present()).
 */
int		 cbl_yencode_member(const struct cbl_ynode *n,
		    const void *parent, struct cbl_ybuf *b);
bool		 cbl_ymember_present(const struct cbl_ynode *n,
		    const void *parent);
/*
 * A mount point's mounted (CBL_YNF_MOUNT): cbl_ymount_data(), mod's data
 * struct in mount point n's struct p, made zeroed in a when there is none
 * (NULL, out of memory); cbl_ymount_find(), it, NULL if none.
 */
void		*cbl_ymount_data(const struct cbl_ynode *n, void *p,
		    const struct cbl_ymodule *mod, cbl_yarena *a);
const void	*cbl_ymount_find(const struct cbl_ynode *n, const void *p,
		    const struct cbl_ymodule *mod);

/*
 * A value as RFC 7951's JSON (cbl_yjson.c says how), appended to b:
 * cbl_yjson() n's children in struct p, an object; cbl_yjson_module() a
 * module's data at the top, its data struct's, an object;
 * cbl_yjson_members() the same members alone, a comma before each but
 * the first of all (*first), so that several modules' make one object.
 */
int		 cbl_yjson(const struct cbl_ynode *n, const void *p,
		    struct cbl_ybuf *b);
int		 cbl_yjson_module(const struct cbl_ymodule *m,
		    const void *data, struct cbl_ybuf *b);
int		 cbl_yjson_members(const struct cbl_ymodule *m,
		    const void *data, struct cbl_ybuf *b, bool *first);
int		 cbl_ydecode_member(const struct cbl_ynode *n,
		    const void *data, size_t len, void *parent, cbl_yarena *a,
		    int flags, char *why, size_t whylen);

/*
 * The static validator (RFC 7950): what holds within the tree of node
 * n's struct p, by the tables.  Each value against its type (ranges,
 * lengths in characters, patterns, enums, bits, identities derived from
 * the bases, a union's member); each node: mandatory leaves and choices,
 * counts, keys there and each entry's own, unique, a configuration
 * leaf-list's values each once, one case of a choice; with CBL_YV_EDIT,
 * no config false node.  EINVAL and err says where and why, as the
 * cblink:error structure would: the node, RFC 8040's error-tag, RFC
 * 7950's error-app-tag, the message (a restriction's own, if it has
 * one).  cbl_yvalidate_member() does a module's top-level node in the
 * module's data struct.  when, must and the targets of leafrefs and
 * instance-identifiers are the evaluator's.
 */
#define	CBL_YV_EDIT		0x0001

struct cbl_yverr {
	const struct cbl_ynode	*node;
	const char		*tag;
	const char		*apptag;	/* NULL: none */
	char			 msg[160];
};

int		 cbl_yvalidate(const struct cbl_ynode *n, const void *p,
		    int flags, struct cbl_yverr *err);
int		 cbl_yvalidate_member(const struct cbl_ynode *n,
		    const void *parent, int flags, struct cbl_yverr *err);

/*
 * Defaults (RFC 7950 sections 7.6.1, 7.7.2, 7.9.3): what node n's struct
 * p has not set, set to the module's default: a leaf's, a leaf-list's
 * values, a choice's default case and the defaults in it; in p and every
 * struct below it that is there (an absent container stays absent).
 * The tree must be writable, as cbl_ydecode() makes it; what is
 * allocated is a's.  An instance-identifier's default is left unset.
 */
int		 cbl_ydefaults(const struct cbl_ynode *n, void *p,
		    cbl_yarena *a);

/*
 * A version 2 body: one map whose top-level keys are SIDs (RFC 9254
 * section 3.2), each a node's value.  cbl_msg_put_ynode() adds {n's
 * SID: the value of its struct p}, cbl_msg_put_sid_raw() one already
 * encoded; cbl_msg_ydecode() reads the value under n's SID of a
 * received body into p (ENOENT: none), cbl_msg_sid_raw() gives its
 * bytes.  An rpc's or an action's input and output are under the rpc's
 * or the action's SID, and null is an empty one (CORECONF); a
 * notification is read from family 1's envelope (cbl_msg_ynotif()), and
 * one of another SID is ENOENT.
 * cbl_msg_put_ymember() and cbl_msg_ydecode_member() do a top-level
 * node in its module's data struct (cbl_yencode_member()); not there,
 * the encoder adds nothing.  cbl_msg_put_ynull() adds {sid: null}: in
 * an EDIT, the node deleted.
 */
int		 cbl_msg_put_ynode(cbl_msg *msg, const struct cbl_ynode *n,
		    const void *p);
int		 cbl_msg_put_ymember(cbl_msg *msg, const struct cbl_ynode *n,
		    const void *parent);
int		 cbl_msg_put_ynull(cbl_msg *msg, uint64_t sid);
int		 cbl_msg_ydecode_member(const cbl_msg *msg,
		    const struct cbl_ynode *n, void *parent, cbl_yarena *a,
		    int flags, char *why, size_t whylen);
int		 cbl_msg_put_sid_raw(cbl_msg *msg, uint64_t sid,
		    const void *cbor, size_t len);
int		 cbl_msg_ydecode(const cbl_msg *msg, const struct cbl_ynode *n,
		    void *p, cbl_yarena *a, int flags, char *why,
		    size_t whylen);
int		 cbl_msg_sid_raw(const cbl_msg *msg, uint64_t sid,
		    const void **pp, size_t *lenp);

/*
 * A server's handlers for the nodes of its modules, by SID: cblink-gen
 * -m server writes the table, the program the handlers, the library
 * calls them.  data is the module's data struct; get fills its member
 * for its node, edit makes the change from before to after of it (for
 * config nodes); an rpc's or an action's in and out are its input's
 * and output's structs, an action's target the instance-identifier, as
 * YANG-CBOR, of the node it is on.  What they allocate is a's.  0, or an
 * errno.
 */
typedef int	 cbl_yget_f(cbl_req *, void *data, cbl_yarena *a);
typedef int	 cbl_yedit_f(cbl_req *, const void *before, const void *after);
typedef int	 cbl_yrpc_f(cbl_req *, const void *in, void *out, cbl_yarena *a);
typedef int	 cbl_yaction_f(cbl_req *, const struct cbl_bytes *target,
		    const void *in, void *out, cbl_yarena *a);

struct cbl_yhandler {
	uint64_t		 sid;		/* its node's */
	cbl_yget_f		*get;
	cbl_yedit_f		*edit;
	cbl_yrpc_f		*rpc;
	cbl_yaction_f		*action;
};

/*
 * A module's .sid file as GET-SID sends it: the value of RFC 9595's
 * ietf-sid-file structure (SID 1301), in YANG-CBOR.
 */
#define	CBL_YSID_FILE		1301

struct cbl_ysidfile {
	const char		*module;
	const char		*revision;	/* NULL: none */
	const uint8_t		*cbor;
	size_t			 len;
};

struct cbl_yserver {
	const struct cbl_yschema *schema;
	uint32_t		 nhandler;
	const struct cbl_yhandler *handler;	/* by SID */
	uint32_t		 nsidfile;
	const struct cbl_ysidfile *sidfile;	/* the -s files given */
};

/*
 * Family 1, "cblink.yang": the handlers of the servers added served by
 * SID, as CORECONF (draft-ietf-core-comi) has its methods.  GET reads
 * {cblink:get: {target: [SID...]}}, or the whole datastore, as {SID:
 * value}, a dump one frame a node; EDIT is {SID: value or null}, the
 * node created or replaced, or deleted, all or nothing; RPC {SID(rpc):
 * input} gives {SID(rpc): output}, null when it has none.
 *
 * cbl_yserver_add() serves srv's modules, arg its handlers'
 * (cbl_req_yarg()).  The handlers run on the loop that read the request
 * and answer on return; with cbl_yserver_threads() each GET, EDIT and
 * RPC runs on a thread of its own instead, the request deferred, so a
 * slow read holds no other request: its handlers must then be safe to
 * run at once.  cbl_msg_put_yget() puts a GET's targets.  A handler
 * names the node at fault with
 * cbl_req_set_yerr(), the error's error-path; a client reads it with
 * cbl_msg_err_sid().
 */
#define	CBL_YANG_FAMILY		1

enum cbl_ycmd {
	CBL_YCMD_GET = 1,
	CBL_YCMD_EDIT = 2,
	CBL_YCMD_RPC = 3,
	CBL_YCMD_NOTIFY = 4,	/* NOTIFY frames, group "notify" */
	CBL_YCMD_GET_SID = 5,	/* dump: {1301: sid-file}, a module each */
	CBL_YCMD_SUBSCRIBE = 6,	/* a push stream: a subscription's records */
};

/*
 * A YANG notification: cbl_ynotify() sends n's, its struct p, to the
 * subscribers of family 1's group "notify", the time now.  A receiver
 * gets its SID, time and content (cbl_ydecode() with the node of that
 * SID) from cbl_msg_ynotif(), what it points to a's or msg's.
 */
struct cbl_ynotif {
	uint64_t	 sid;
	const char	*event_time;	/* RFC 3339, UTC */
	const void	*content;
	size_t		 len;
};

int		 cbl_ynotify(cbl_ctx *ctx, const struct cbl_ynode *n,
		    const void *p);
int		 cbl_msg_ynotif(const cbl_msg *msg, struct cbl_ynotif *nt,
		    cbl_yarena *a);

/*
 * NACM (RFC 8341), where a server's modules have ietf-netconf-acm and a
 * get handler for its nacm container: its rules, read through that
 * handler, are checked for every request to family 1 (an rpc's or an
 * action's exec; a read, what is denied left out; an EDIT, all or
 * nothing) and for every op of another family with CBL_OPF_NACM, as the
 * user cbl_req_user() names; a notification is sent only where it may
 * be read.  nacm:default-deny-write and -all are kept, as the tables
 * have them.  The program tells a change of the rules it made itself
 * with cbl_ynacm_changed(); an EDIT through family 1 is told by itself.
 * cbl_ynacm_counters() has the state leaves' counts.  Rules that cannot
 * be read deny everything but the recovery session.
 */
/*
 * Datastores (RFC 8342) for family 1, where a program asks for them with
 * cbl_ydatastores(): running, the configuration its handlers keep, read
 * as their config true nodes; and candidate, one configuration being
 * made, shared by every session (RFC 6241 section 8.3), changed by an
 * EDIT of it, put in use by ietf-netconf's commit, forgotten by its
 * discard-changes.  The server's modules have ietf-netconf with its
 * features candidate and confirmed-commit; cblink answers those rpcs
 * itself.  A confirmed commit (section 8.4) is undone at its
 * confirm-timeout unless another commit confirms it, from its session
 * or, with persist, from any by its persist-id; cancel-commit undoes it
 * at once, and so does its session going without persist.  An undo a
 * handler fails is told to undo_failed, which may raise an alarm and
 * write a report; the undo stops there, what is left as committed.  With CBL_YDS_CONFIRMED running changes by a
 * confirmed commit alone: an EDIT of it is refused.  A client names the
 * datastore beside a GET or an EDIT with cbl_msg_set_datastore().
 *
 * A handler that would do what its requester should be warned of first
 * refuses with cbl_req_set_yapptag()'s app-tag, unless the request
 * accepts it (cbl_req_yaccepts(); a client's cbl_msg_set_accept()); one
 * that did it tells the requester with cbl_req_ywarn(), the answer's
 * warnings (cbl_msg_ywarnings()).
 */
#define	CBL_YDS_CONFIRMED	0x0001

enum cbl_yds_name {
	CBL_YDS_RUNNING,
	CBL_YDS_CANDIDATE,
	CBL_YDS_OPERATIONAL,
};

typedef void	 cbl_yundo_f(cbl_ctx *ctx, const struct cbl_ynode *n, int error,
		    const char *why, void *arg);

struct cbl_ywarning {
	uint64_t	 sid;		/* the node it is about; 0: none */
	const char	*tag;		/* error-app-tag */
	const char	*text;
};

int		 cbl_ydatastores(cbl_ctx *ctx, unsigned flags,
		    cbl_yundo_f *undo_failed, void *arg);
int		 cbl_msg_set_datastore(cbl_msg *msg, enum cbl_yds_name ds);
int		 cbl_msg_set_accept(cbl_msg *msg, const char *const *tags,
		    size_t n);
int		 cbl_msg_ywarnings(const cbl_msg *msg, cbl_yarena *a,
		    const struct cbl_ywarning **vp, size_t *np);
bool		 cbl_req_yaccepts(cbl_req *req, const char *tag);
int		 cbl_req_set_yapptag(cbl_req *req, const char *tag);
int		 cbl_req_ywarn(cbl_req *req, uint64_t sid, const char *tag,
		    const char *text);
/* The datastore a get handler reads for: running's reads leave out what
 * is no configuration (an address a protocol gave, RFC 8342 section
 * 5.3), the operational state's do not. */
enum cbl_yds_name cbl_req_ydatastore(const cbl_req *req);
/* The edit undoes a commit (one not confirmed in time, cancelled, or
 * the others of one that failed): what it would need accepted is. */
bool		 cbl_req_yundo(const cbl_req *req);
/* Whether a confirmed commit waits, and until when (CLOCK_REALTIME). */
struct timespec;
bool		 cbl_ydatastore_pending(cbl_ctx *ctx, struct timespec *until);

struct cbl_ynacm_counts {
	uint32_t	 denied_operations;
	uint32_t	 denied_data_writes;
	uint32_t	 denied_notifications;
};

void		 cbl_ynacm_changed(cbl_ctx *ctx);
void		 cbl_ynacm_counters(cbl_ctx *ctx, struct cbl_ynacm_counts *c);

int		 cbl_yserver_add(cbl_ctx *ctx, const struct cbl_yserver *srv,
		    void *arg);
int		 cbl_yserver_threads(cbl_ctx *ctx, bool on);
/*
 * An action: its input put as an rpc's (cbl_msg_put_ynode() of its
 * input node), and what it acts on beside it, target an instance of
 * the action's parent (cbl_yiid_write()).
 */
int		 cbl_msg_put_yaction(cbl_msg *msg, const void *target,
		    size_t len);
int		 cbl_msg_put_yget(cbl_msg *msg, const uint64_t *sids,
		    size_t n);
/* A GET's targets and an XPath filter over them (RFC 6241 section 8.9):
 * what it selects comes back, the nodes above it and keys with it. */
int		 cbl_msg_put_yget_xpath(cbl_msg *msg, const uint64_t *sids,
		    size_t n, const char *xpath);
/* The same with RFC 6243's retrieval mode: explicit (what the server
 * has), report-all (the defaults in use too), trim (leaves at their
 * default left out), report-all-tagged (report-all, a leaf at its
 * default annotated so).  _opts: with origin, each configuration node
 * of the operational datastore annotated with its origin (RFC 8342
 * section 5.3.4) where it is not its parent's. */
enum cbl_ywd {
	CBL_YWD_EXPLICIT,
	CBL_YWD_REPORT_ALL,
	CBL_YWD_TRIM,
	CBL_YWD_REPORT_ALL_TAGGED,
};
int		 cbl_msg_put_yget_wd(cbl_msg *msg, const uint64_t *sids,
		    size_t n, const char *xpath, enum cbl_ywd wd);
int		 cbl_msg_put_yget_opts(cbl_msg *msg, const uint64_t *sids,
		    size_t n, const char *xpath, enum cbl_ywd wd, bool origin);
void		*cbl_req_yarg(const cbl_req *req);
int		 cbl_req_set_yerr(cbl_req *req, const char *text,
		    uint64_t sid);
uint64_t	 cbl_msg_err_sid(const cbl_msg *msg);

/*
 * Subscriptions (RFC 8639) and YANG-Push (RFC 8641), dynamic, where a
 * server's modules have ietf-subscribed-notifications (and, for a
 * datastore's, ietf-yang-push and ietf-datastores): SUBSCRIBE opens a
 * push stream with establish-subscription's input, put as an rpc's
 * (cbl_msg_put_ynode() of its input node); the stream is accepted with
 * its output, the id, and carries the subscription's records, each a
 * cblink:notification as group "notify" has them (cbl_msg_ynotif()).
 * The NETCONF stream: every notification cbl_ynotify() sends, what
 * stream-xpath-filter selects of it.  The operational datastore,
 * periodic (period, anchor-time): a push-update every period of what
 * datastore-xpath-filter selects, read by the get handlers on the
 * stream's connection; or on-change, where ietf-yang-push's on-change
 * is on: read every dampening-period (a second at least) and compared
 * with the last read, its changes a push-change-update's YANG Patch,
 * the first read a push-update (sync-on-start).  A stop-time ends it, the stream closed.  A
 * record that does not fit in the stream's credit is left out, and
 * counted.  The subscription ends with its stream (the subscriber's
 * close), cbl_ysub_delete() (the subscriber's, from the request of a
 * delete-subscription rpc on its connection) or cbl_ysub_kill() (any).
 * cbl_ysub_each() calls fn for each subscription, under a lock: fn
 * copies what it keeps and calls no cbl_ysub_* function; it stops at
 * fn's first error, which it returns.
 */
struct cbl_ysub_info {
	uint32_t	 id;
	const char	*stream;	/* or NULL: a datastore's */
	uint64_t	 datastore;	/* its identity's SID */
	const char	*xpath;		/* the filter, or NULL */
	uint32_t	 period;	/* centiseconds; 0: on-change */
	bool		 on_change;
	uint32_t	 dampening;	/* centiseconds */
	const char	*anchor_time;	/* or NULL */
	const char	*stop_time;	/* or NULL */
	uint64_t	 sent;		/* records */
	uint64_t	 excluded;
	bool		 suspended;
	const char	*receiver;	/* the peer's certificate subject */
};

/*
 * Replay (RFC 8639 section 2.4.2.1, the replay feature): fn, given to
 * cbl_ysub_set_replay(), gives the notifications kept since from, the
 * oldest first, to cbl_ysub_replay_emit() with the time each happened,
 * and says the oldest it keeps (cbl_ysub_replay_oldest()).  So that none
 * is lost or sent twice, it calls cbl_ysub_replay_live() while what
 * orders its notifications still holds: from then on the subscription
 * takes them live.  It runs on the loop.
 */
struct cbl_ysub_replay;
typedef int	 cbl_ysub_replay_f(const struct timespec *from,
		    struct cbl_ysub_replay *r, void *arg);
int		 cbl_ysub_set_replay(cbl_ctx *ctx, cbl_ysub_replay_f *fn,
		    void *arg);
int		 cbl_ysub_replay_emit(struct cbl_ysub_replay *r,
		    const struct cbl_ynode *n, const void *p,
		    const struct timespec *when);
void		 cbl_ysub_replay_oldest(struct cbl_ysub_replay *r,
		    const struct timespec *oldest);
void		 cbl_ysub_replay_live(struct cbl_ysub_replay *r);
/*
 * modify-subscription (in, the program's struct of its input) and
 * resync-subscription, for the subscriber's own subscription, from the
 * program's rpc handlers: 0, or an errno, said for the request.
 */
int		 cbl_ysub_modify(cbl_req *req, const void *in);
int		 cbl_ysub_resync(cbl_req *req, uint32_t id);
int		 cbl_ysub_delete(cbl_req *req, uint32_t id);
int		 cbl_ysub_kill(cbl_ctx *ctx, uint32_t id);
/*
 * On-change from the program's own news: cbl_ysub_told() names the
 * top-level data nodes each of whose changes the program tells by
 * cbl_ysub_changed(top) (NULL: any of them).  An on-change
 * subscription that reads only those is read again when told, a
 * dampening period after its last read at the soonest, not every
 * period.  An EDIT, a commit and a commit's undo tell of the nodes
 * they change themselves.
 */
int		 cbl_ysub_told(cbl_ctx *ctx, const struct cbl_ynode *const *tops,
		    size_t n);
void		 cbl_ysub_changed(cbl_ctx *ctx, const struct cbl_ynode *top);
int		 cbl_ysub_each(cbl_ctx *ctx,
		    int (*fn)(const struct cbl_ysub_info *, void *), void *arg);

#endif /* !_CBL_SCHEMA_H_ */
