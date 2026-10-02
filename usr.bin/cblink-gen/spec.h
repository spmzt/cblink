/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Family spec model (docs/SPEC-FORMAT.md part 2). */

#ifndef _CBLINK_GEN_SPEC_H_
#define	_CBLINK_GEN_SPEC_H_

#include "gen.h"

struct loc {
	int	line;
	int	col;
};

/* A number from the spec, possibly a reference to a "const". */
struct snum {
	bool		 set;
	bool		 neg;		/* value is -(mag) */
	uint64_t	 mag;
	char		*ref;		/* const name, resolved later */
	struct loc	 loc;
};

enum sdef_type { D_CONST, D_ENUM, D_FLAGS };

struct sentry {
	char		*name;
	char		*cname;		/* mangled */
	uint64_t	 value;		/* enum value or flag bit */
	char		*doc;
	struct loc	 loc;
};

struct sdef {
	char		*name;
	char		*cname;
	enum sdef_type	 type;
	struct snum	 value;		/* const */
	struct sentry	*entries;
	size_t		 nentries;
	char		*doc;
	struct loc	 loc;
};

enum stype {
	T_U8, T_U16, T_U32, T_U64, T_S8, T_S16, T_S32, T_S64,
	T_BOOL, T_FLAG, T_TEXT, T_BYTES, T_FLOAT, T_NEST,
};

struct sset;

struct sattr {
	char		*name;
	char		*cname;
	uint32_t	 value;
	struct loc	 loc;
	struct loc	 value_loc;
	enum stype	 type;
	struct loc	 type_loc;
	char		*doc;
	char		*nested_name;
	struct loc	 nested_loc;
	struct sset	*nested;
	bool		 multi;
	char		*enum_name;
	struct loc	 enum_loc;
	struct sdef	*en;
	bool		 required;
	struct snum	 min, max, min_len, max_len, exact_len;
	struct snum	 min_count, max_count;
	struct loc	 checks_loc;
};

struct sset {
	char		*name;
	char		*cname;
	char		*doc;
	struct sattr	*attrs;
	size_t		 nattrs;
	struct loc	 loc;
};

/* "attributes:" list of a request, reply or event. */
struct slist {
	bool		 present;
	char		**names;
	struct loc	*locs;
	struct sattr	**attrs;	/* resolved */
	size_t		 n;
	char		**req_names;	/* "required:" */
	struct loc	*req_locs;
	size_t		 nreq;
	bool		*required;	/* per attrs[i], resolved */
	struct loc	 loc;
};

struct sgrp;
struct sstream;

struct sop {
	char		*name;
	char		*cname;
	uint32_t	 value;
	struct loc	 loc;
	struct loc	 value_loc;
	char		*doc;
	char		*set_name;
	struct loc	 set_loc;
	struct sset	*set;
	bool		 auth;
	bool		 has_do;
	struct slist	 do_req, do_rsp;
	bool		 has_dump;
	struct slist	 dump_req, dump_rsp;
	bool		 has_event;
	struct slist	 event;
	char		*mcgrp_name;
	struct loc	 mcgrp_loc;
	struct sgrp	*mcgrp;
	struct sstream	*stream;	/* set when a stream opens with it */
};

struct sgrp {
	char		*name;
	char		*cname;
	char		*doc;
	bool		 auth;
	struct loc	 loc;
};

enum sdir { DIR_BIDI, DIR_UP, DIR_DOWN };	/* DOWN: server-to-client */

struct sstream {
	char		*name;
	char		*cname;
	char		*doc;
	char		*open_name;
	struct loc	 open_loc;
	struct sop	*open;
	enum sdir	 dir;
	char		*payload_name, *up_name, *down_name;
	struct loc	 payload_loc, up_loc, down_loc;
	struct sset	*up;		/* client-to-server payload */
	struct sset	*down;		/* server-to-client payload */
	struct snum	 credit;
	struct loc	 loc;
};

struct spec {
	const char	*file;		/* basename, for output comments */
	char		*name;
	char		*prefix;	/* C prefix, lowercase */
	char		*uprefix;	/* uppercase */
	uint32_t	 version;
	char		*doc;
	bool		 has_fixed_id;
	uint32_t	 fixed_id;
	struct sdef	*defs;
	size_t		 ndefs;
	struct sset	*sets;
	size_t		 nsets;
	struct sop	*ops;
	size_t		 nops;
	struct sgrp	*grps;
	size_t		 ngrps;
	struct sstream	*streams;
	size_t		 nstreams;
};

struct spec	*spec_load(const struct ynode *root, const char *file,
		    bool builtin, struct diags *d);
void		 spec_free(struct spec *s);

const char	*stype_name(enum stype t);
const char	*stype_ctype(enum stype t);
bool		 stype_unsigned(enum stype t);
bool		 stype_signed(enum stype t);
bool		 stype_scalar(enum stype t);	/* has a has_ flag */
uint64_t	 stype_umax(enum stype t);
int64_t		 stype_smin(enum stype t);
int64_t		 stype_smax(enum stype t);

/* Resolved numeric value of a check, after spec_load() succeeded. */
uint64_t	 snum_u(const struct snum *n);
int64_t		 snum_s(const struct snum *n);

int		 gen_c(const struct spec *s, const char *base, int dirfd,
		    const char *parts);
int		 gen_md(const struct spec *s, struct buf *out);
char		*mangle(const char *name);
char		*upper(const char *s);

#endif /* !_CBLINK_GEN_SPEC_H_ */
