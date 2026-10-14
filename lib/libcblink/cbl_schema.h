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
 * (cbl_req_yarg()).  cbl_msg_put_yget() puts a GET's targets.  A handler names the node at fault with
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

int		 cbl_yserver_add(cbl_ctx *ctx, const struct cbl_yserver *srv,
		    void *arg);
int		 cbl_msg_put_yget(cbl_msg *msg, const uint64_t *sids,
		    size_t n);
void		*cbl_req_yarg(const cbl_req *req);
int		 cbl_req_set_yerr(cbl_req *req, const char *text,
		    uint64_t sid);
uint64_t	 cbl_msg_err_sid(const cbl_msg *msg);

#endif /* !_CBL_SCHEMA_H_ */
