/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBLINK_GEN_SID_H_
#define	_CBLINK_GEN_SID_H_

/*
 * ".sid" files (RFC 9595): the YANG Schema Item iDentifiers of a module,
 * read with libucl, attached to the schema model, verified, assigned to
 * new items, and written back.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct diags;
struct schema;

enum sid_ns {
	SID_NS_MODULE,
	SID_NS_IDENTITY,
	SID_NS_FEATURE,
	SID_NS_DATA,
	/* RFC 7952's annotations: draft-ietf-core-yang-metadata's 4 */
	SID_NS_ANNOTATION,
};

enum sid_status {
	SID_ST_NONE,		/* not said: stable in a published file */
	SID_ST_STABLE,
	SID_ST_UNSTABLE,
	SID_ST_OBSOLETE,
};

struct siditem {
	enum sid_ns	 ns;
	char		*id;	/* name, or schema node path for data */
	enum sid_status	 status;
	uint64_t	 sid;
};

struct sidfile {
	char		*module;
	char		*revision;	/* NULL: none */
	bool		 has_version;
	uint32_t	 version;
	char		*status;	/* "published", "unpublished", NULL */
	char		*description;
	struct {
		char	*module;
		char	*revision;
	}		*deps;
	size_t		 ndeps;
	struct {
		uint64_t entry;
		uint64_t size;
	}		*ranges;
	size_t		 nranges;
	struct siditem	*items;
	size_t		 nitems;
};

/*
 * Read a .sid file: its JSON text, or its YANG-CBOR form (below); NULL
 * and diagnostics on error.
 */
struct sidfile	*sid_read(const char *text, size_t len, struct diags *d);
void		 sid_free(struct sidfile *f);

/*
 * Give the schema's items their SIDs from f: the module, its identities
 * and features, and the data nodes it defines, by schema node path.
 * Items of f the schema does not have are diagnostics, unless absent_ok:
 * a schema compiled with some features off lacks what they guard, which
 * the file numbers all the same (RFC 9595: every item of the module).
 */
int		 sid_attach(struct schema *s, const struct sidfile *f,
		    struct diags *d, bool absent_ok);

/*
 * Verify f against the schema, after sid_attach(): no SID given twice,
 * no item named twice, every SID inside the file's assignment ranges,
 * and every item of the module (itself, its identities and features,
 * its structures and the data nodes it defines) with a SID.  Problems
 * are diagnostics; 0 when there are none.
 */
int		 sid_verify(struct schema *s, const struct sidfile *f,
		    struct diags *d);

/*
 * Give SIDs to the module's items that have none (RFC 9595 Appendix B):
 * sorted by namespace (module, identity, feature, data) and identifier,
 * each the next SID free in the file's ranges; the file's version goes
 * up when it had items, and its dependencies become the module's
 * imports as bound.  The number given, or -1 (diagnostics) when the
 * ranges are full or the module is not in the schema.
 */
int		 sid_assign(struct schema *s, struct sidfile *f,
		    struct diags *d);

/* The file as JSON, deterministically, its lists in the file's order. */
struct buf;
void		 sid_write(const struct sidfile *f, struct buf *b);

/*
 * The file in YANG-CBOR (RFC 9254), its ietf-sid-file structure keyed by
 * SIDs as GET-SID answers it; and read back.  sid_read() takes either.
 */
void		 sid_write_cbor(const struct sidfile *f, struct buf *b);
struct sidfile	*sid_read_cbor(const char *data, size_t len, struct diags *d);

const char	*sid_ns_name(enum sid_ns ns);

#endif /* !_CBLINK_GEN_SID_H_ */
