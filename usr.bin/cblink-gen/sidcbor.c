/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A .sid file in YANG-CBOR (RFC 9254): the ietf-sid-file structure of
 * RFC 9595, keyed by its SIDs, as GET-SID answers it.  The SIDs are
 * share/yang/ietf-sid-file@2024-07-31.sid's: IANA gave the module the
 * range 1300-1349 and published no .sid file for it, so they are the
 * ones RFC 9595 Appendix B's numbering gives (cblink-gen -a).
 *
 * The encoding is deterministic (RFC 8949 §4.2.1): shortest heads,
 * definite lengths, map keys ascending; lists keep the file's order.
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "gen.h"
#include "sid.h"

enum {
	S_FILE = 1301,
	S_RANGE, S_RANGE_ENTRY, S_RANGE_SIZE,
	S_DEP, S_DEP_MODULE, S_DEP_REVISION,
	S_DESCRIPTION,
	S_ITEM, S_ITEM_ID, S_ITEM_NS, S_ITEM_SID, S_ITEM_STATUS,
	S_MODULE, S_REVISION, S_STATUS, S_VERSION,
};

/* The enumerations' values, from the module. */
static const char *const file_status[] = { "unpublished", "published" };

/*
 * Writing.
 */

static void
head(struct buf *b, unsigned major, uint64_t v)
{
	unsigned char h[9];
	size_t n;

	if (v < 24) {
		h[0] = (unsigned char)(major << 5 | v);
		n = 1;
	} else {
		n = v <= UINT8_MAX ? 1 : v <= UINT16_MAX ? 2 :
		    v <= UINT32_MAX ? 4 : 8;
		h[0] = (unsigned char)(major << 5 |
		    (n == 1 ? 24 : n == 2 ? 25 : n == 4 ? 26 : 27));
		for (size_t i = 0; i < n; i++)
			h[n - i] = (unsigned char)(v >> (8 * i));
		n++;
	}
	buf_add(b, (const char *)h, n);
}

static void
text(struct buf *b, const char *s)
{
	size_t len = strlen(s);

	head(b, 3, len);
	buf_add(b, s, len);
}

/* A key: the delta from the parent's SID. */
#define	KEY(b, parent, sid)	head((b), 0, (uint64_t)((sid) - (parent)))

void
sid_write_cbor(const struct sidfile *f, struct buf *b)
{
	size_t n;

	head(b, 5, 1);
	head(b, 0, S_FILE);
	n = 1 + (f->ndeps > 0) + (f->nranges > 0) + (f->nitems > 0) +
	    (f->description != NULL) + (f->revision != NULL) +
	    (f->status != NULL) + f->has_version;
	head(b, 5, n);
	if (f->nranges > 0) {
		KEY(b, S_FILE, S_RANGE);
		head(b, 4, f->nranges);
		for (size_t i = 0; i < f->nranges; i++) {
			head(b, 5, 2);
			KEY(b, S_RANGE, S_RANGE_ENTRY);
			head(b, 0, f->ranges[i].entry);
			KEY(b, S_RANGE, S_RANGE_SIZE);
			head(b, 0, f->ranges[i].size);
		}
	}
	if (f->ndeps > 0) {
		KEY(b, S_FILE, S_DEP);
		head(b, 4, f->ndeps);
		for (size_t i = 0; i < f->ndeps; i++) {
			head(b, 5, 2);
			KEY(b, S_DEP, S_DEP_MODULE);
			text(b, f->deps[i].module);
			KEY(b, S_DEP, S_DEP_REVISION);
			text(b, f->deps[i].revision);
		}
	}
	if (f->description != NULL) {
		KEY(b, S_FILE, S_DESCRIPTION);
		text(b, f->description);
	}
	if (f->nitems > 0) {
		KEY(b, S_FILE, S_ITEM);
		head(b, 4, f->nitems);
		for (size_t i = 0; i < f->nitems; i++) {
			const struct siditem *it = &f->items[i];

			head(b, 5, it->status != SID_ST_NONE ? 4 : 3);
			KEY(b, S_ITEM, S_ITEM_ID);
			text(b, it->id);
			KEY(b, S_ITEM, S_ITEM_NS);
			head(b, 0, (uint64_t)it->ns);
			KEY(b, S_ITEM, S_ITEM_SID);
			head(b, 0, it->sid);
			if (it->status != SID_ST_NONE) {
				KEY(b, S_ITEM, S_ITEM_STATUS);
				/* stable 0, unstable 1, obsolete 2 */
				head(b, 0, (uint64_t)(it->status -
				    SID_ST_STABLE));
			}
		}
	}
	KEY(b, S_FILE, S_MODULE);
	text(b, f->module);
	if (f->revision != NULL) {
		KEY(b, S_FILE, S_REVISION);
		text(b, f->revision);
	}
	if (f->status != NULL) {
		KEY(b, S_FILE, S_STATUS);
		head(b, 0, strcmp(f->status, "published") == 0);
	}
	if (f->has_version) {
		KEY(b, S_FILE, S_VERSION);
		head(b, 0, f->version);
	}
}

/*
 * Reading: only what the writer above may write, in any key order.
 */

struct rd {
	const unsigned char	*start, *p, *end;
	struct diags		*d;
	bool			 bad;
};

static bool
fail(struct rd *r, const char *what)
{

	if (!r->bad)
		diag_add(r->d, 0, 0, "YANG-CBOR: %s at byte %td", what,
		    r->p - r->start);
	r->bad = true;
	return (false);
}

/* A head of the major type wanted; its argument in *vp. */
static bool
rd_head(struct rd *r, unsigned major, uint64_t *vp)
{
	unsigned ai;
	size_t n;

	if (r->bad)
		return (false);
	if (r->p >= r->end)
		return (fail(r, "truncated"));
	if ((unsigned)(*r->p >> 5) != major)
		return (fail(r, major == 0 ? "not an unsigned integer" :
		    major == 3 ? "not a text string" : major == 4 ?
		    "not an array" : "not a map"));
	ai = *r->p++ & 0x1f;
	if (ai < 24) {
		*vp = ai;
		return (true);
	}
	if (ai > 27)
		return (fail(r, "an indefinite length or a reserved head"));
	n = (size_t)1 << (ai - 24);
	if ((size_t)(r->end - r->p) < n)
		return (fail(r, "truncated"));
	*vp = 0;
	for (size_t i = 0; i < n; i++)
		*vp = *vp << 8 | *r->p++;
	return (true);
}

static char *
rd_text(struct rd *r)
{
	uint64_t len;

	if (!rd_head(r, 3, &len))
		return (NULL);
	if (len > (uint64_t)(r->end - r->p)) {
		fail(r, "truncated");
		return (NULL);
	}
	if (memchr(r->p, '\0', (size_t)len) != NULL) {
		fail(r, "a NUL in a text string");
		return (NULL);
	}
	r->p += len;
	return (xstrndup((const char *)r->p - len, (size_t)len));
}

static bool
rd_uint(struct rd *r, uint64_t max, uint64_t *vp)
{

	if (!rd_head(r, 0, vp))
		return (false);
	if (*vp > max)
		return (fail(r, "out of range"));
	return (true);
}

/* A map's key: a delta from parent; each once (seen: a bit a key). */
static bool
rd_key(struct rd *r, int parent, int first, int last, uint32_t *seen,
    int *keyp)
{
	uint64_t delta;
	int key;

	if (!rd_head(r, 0, &delta))
		return (false);
	if (delta > (uint64_t)(last - parent) ||
	    (key = parent + (int)delta) < first)
		return (fail(r, "a key not in ietf-sid-file"));
	if (*seen & (1u << (key - first)))
		return (fail(r, "a key given twice"));
	*seen |= 1u << (key - first);
	*keyp = key;
	return (true);
}

struct sidfile *
sid_read_cbor(const char *data, size_t len, struct diags *d)
{
	struct rd r = { (const unsigned char *)data,
	    (const unsigned char *)data, (const unsigned char *)data + len,
	    d, false };
	struct sidfile *sf;
	uint64_t n, m, v;
	uint32_t seen = 0, eseen;
	int key, ekey;

	sf = xcalloc(1, sizeof(*sf));
	if (!rd_head(&r, 5, &n) || n != 1 || !rd_head(&r, 0, &v) ||
	    v != S_FILE) {
		fail(&r, "not an ietf-sid-file:sid-file structure");
		goto out;
	}
	if (!rd_head(&r, 5, &n))
		goto out;
	for (; n > 0 && !r.bad; n--) {
		if (!rd_key(&r, S_FILE, S_RANGE, S_VERSION, &seen, &key))
			break;
		switch (key) {
		case S_MODULE:
			sf->module = rd_text(&r);
			break;
		case S_REVISION:
			sf->revision = rd_text(&r);
			break;
		case S_DESCRIPTION:
			sf->description = rd_text(&r);
			break;
		case S_VERSION:
			if (rd_uint(&r, UINT32_MAX, &v)) {
				sf->has_version = true;
				sf->version = (uint32_t)v;
			}
			break;
		case S_STATUS:
			if (rd_uint(&r, 1, &v))
				sf->status = xstrdup(file_status[v]);
			break;
		case S_RANGE:
			if (!rd_head(&r, 4, &m))
				break;
			if (m > (uint64_t)(r.end - r.p)) {
				fail(&r, "truncated");
				break;
			}
			sf->ranges = xcalloc((size_t)m + 1, sizeof(*sf->ranges));
			for (; m > 0 && !r.bad; m--) {
				uint64_t entry = 0, size = 0;

				if (!rd_head(&r, 5, &v) || v != 2) {
					fail(&r, "an assignment-range entry "
					    "without its two leaves");
					break;
				}
				eseen = 0;
				for (int k = 0; k < 2 && !r.bad; k++)
					if (rd_key(&r, S_RANGE, S_RANGE_ENTRY,
					    S_RANGE_SIZE, &eseen, &ekey))
						rd_uint(&r, ekey ==
						    S_RANGE_ENTRY ? INT64_MAX :
						    UINT64_MAX, ekey ==
						    S_RANGE_ENTRY ? &entry : &size);
				if (!r.bad && (size == 0 ||
				    size - 1 > INT64_MAX - entry))
					fail(&r, "an assignment-range empty or "
					    "past the largest SID");
				sf->ranges[sf->nranges].entry = entry;
				sf->ranges[sf->nranges++].size = size;
			}
			break;
		case S_DEP:
			if (!rd_head(&r, 4, &m))
				break;
			if (m > (uint64_t)(r.end - r.p)) {
				fail(&r, "truncated");
				break;
			}
			sf->deps = xcalloc((size_t)m + 1, sizeof(*sf->deps));
			for (; m > 0 && !r.bad; m--) {
				if (!rd_head(&r, 5, &v) || v != 2) {
					fail(&r, "a dependency-revision entry "
					    "without its two leaves");
					break;
				}
				eseen = 0;
				for (int k = 0; k < 2 && !r.bad; k++)
					if (rd_key(&r, S_DEP, S_DEP_MODULE,
					    S_DEP_REVISION, &eseen, &ekey)) {
						if (ekey == S_DEP_MODULE)
							sf->deps[sf->ndeps]
							    .module = rd_text(&r);
						else
							sf->deps[sf->ndeps]
							    .revision =
							    rd_text(&r);
					}
				sf->ndeps++;
			}
			break;
		case S_ITEM:
			if (!rd_head(&r, 4, &m))
				break;
			if (m > (uint64_t)(r.end - r.p)) {
				fail(&r, "truncated");
				break;
			}
			sf->items = xcalloc((size_t)m + 1, sizeof(*sf->items));
			for (; m > 0 && !r.bad; m--) {
				struct siditem *it = &sf->items[sf->nitems++];

				if (!rd_head(&r, 5, &v) || v < 3 || v > 4) {
					fail(&r, "an item without its leaves");
					break;
				}
				eseen = 0;
				for (; v > 0 && !r.bad; v--) {
					uint64_t x;

					if (!rd_key(&r, S_ITEM, S_ITEM_ID,
					    S_ITEM_STATUS, &eseen, &ekey))
						break;
					switch (ekey) {
					case S_ITEM_ID:
						it->id = rd_text(&r);
						break;
					case S_ITEM_NS:
						if (rd_uint(&r, SID_NS_DATA, &x))
							it->ns = (enum sid_ns)x;
						break;
					case S_ITEM_SID:
						rd_uint(&r, INT64_MAX, &it->sid);
						break;
					case S_ITEM_STATUS:
						if (rd_uint(&r, 2, &x))
							it->status =
							    (enum sid_status)
							    (SID_ST_STABLE + x);
						break;
					}
				}
				if (!r.bad && (eseen & 0x7) != 0x7)
					fail(&r, "an item without its "
					    "identifier, namespace or sid");
			}
			break;
		}
	}
	if (!r.bad && sf->module == NULL)
		fail(&r, "no module-name");
	if (!r.bad && r.p != r.end)
		fail(&r, "bytes after the structure");
out:
	if (r.bad) {
		sid_free(sf);
		return (NULL);
	}
	return (sf);
}
