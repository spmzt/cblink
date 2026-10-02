/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Frame header encoding and validation (docs/WIRE-FORMAT.md section 2). */

#include <errno.h>

#include "cbl_impl.h"

#define	CBL_F_LOW	(CBL_F_REQUEST | CBL_F_ACK | CBL_F_DUMP | \
			 CBL_F_MULTI | CBL_F_DONE | CBL_F_ERROR | CBL_F_NOTIFY)
#define	CBL_F_S_BASIC	(CBL_F_S_OPEN | CBL_F_S_DATA | CBL_F_S_HCLOSE)
#define	CBL_F_S_SOLO	(CBL_F_S_CLOSE | CBL_F_S_RESET | CBL_F_S_CREDIT)

/* Section 3.1: every valid frame is exactly one kind. */
bool
cbl_flags_valid(uint32_t f, uint32_t stream)
{
	uint32_t s, low;

	if ((f & ~(CBL_F_LOW | CBL_F_S_ANY)) != 0)
		return (false);
	s = f & CBL_F_S_ANY;
	low = f & CBL_F_LOW;

	if ((f & CBL_F_REQUEST) != 0) {
		if (s != 0) {
			/* Stream open: REQUEST|S_OPEN [|S_DATA] [|S_HCLOSE]. */
			return (low == CBL_F_REQUEST &&
			    (s & CBL_F_S_OPEN) != 0 &&
			    (s & ~CBL_F_S_BASIC) == 0 && stream != 0);
		}
		/* Do or dump request. */
		return ((low & ~(CBL_F_REQUEST | CBL_F_ACK |
		    CBL_F_DUMP)) == 0 && stream == 0);
	}
	if ((f & CBL_F_NOTIFY) != 0)
		return (f == CBL_F_NOTIFY && stream != 0);
	if ((f & CBL_F_ERROR) != 0) {
		if (s == CBL_F_S_OPEN)
			return (low == CBL_F_ERROR && stream != 0);
		if (s != 0 || stream != 0)
			return (false);
		return (low == CBL_F_ERROR ||
		    low == (CBL_F_ERROR | CBL_F_MULTI | CBL_F_DONE));
	}
	if (s != 0) {
		if (low != 0 || stream == 0)
			return (false);
		if ((s & CBL_F_S_SOLO) != 0)
			return (s == CBL_F_S_CLOSE || s == CBL_F_S_RESET ||
			    s == CBL_F_S_CREDIT);
		return ((s & ~CBL_F_S_BASIC) == 0);
	}
	/* Reply, ack, dump part, dump end. */
	if (stream != 0)
		return (false);
	return (low == 0 || low == CBL_F_ACK || low == CBL_F_MULTI ||
	    low == (CBL_F_MULTI | CBL_F_DONE));
}

/*
 * Validate the fixed header in "p" (at least CBL_HDRLEN bytes) without
 * allocating anything.  Returns:
 *   EAGAIN		fewer than CBL_HDRLEN bytes
 *   EPROTO		bad magic or hdrlen
 *   EPROTONOSUPPORT	unknown version
 *   EMSGSIZE		length out of range
 *   EINVAL		invalid flags
 * The decoded fields are filled in as far as they could be parsed, so the
 * caller can echo family/cmd/seq in an error reply.
 */
int
cbl_hdr_decode(const unsigned char *p, size_t len,
    const struct cbl_limits *lim, struct cbl_hdr *h)
{

	if (len < CBL_HDRLEN)
		return (EAGAIN);
	h->version = p[2];
	h->hdrlen = p[3];
	h->length = cbl_be32dec(p + 4);
	h->family = cbl_be16dec(p + 8);
	h->cmd = cbl_be16dec(p + 10);
	h->flags = cbl_be32dec(p + 12);
	h->seq = cbl_be32dec(p + 16);
	h->stream = cbl_be32dec(p + 20);

	if (cbl_be16dec(p) != CBL_MAGIC)
		return (EPROTO);
	if (h->version != CBL_PROTO_VERSION)
		return (EPROTONOSUPPORT);
	if (h->hdrlen < CBL_HDRLEN || h->hdrlen > CBL_HDRLEN_MAX ||
	    (h->hdrlen & 3) != 0)
		return (EPROTO);
	if (h->length < h->hdrlen || h->length > lim->v[CBL_LIM_MAX_FRAME])
		return (EMSGSIZE);
	if (!cbl_flags_valid(h->flags, h->stream))
		return (EINVAL);
	return (0);
}

void
cbl_hdr_encode(unsigned char *p, const struct cbl_hdr *h)
{

	cbl_be16enc(p, CBL_MAGIC);
	p[2] = CBL_PROTO_VERSION;
	p[3] = CBL_HDRLEN;
	cbl_be32enc(p + 4, h->length);
	cbl_be16enc(p + 8, h->family);
	cbl_be16enc(p + 10, h->cmd);
	cbl_be32enc(p + 12, h->flags);
	cbl_be32enc(p + 16, h->seq);
	cbl_be32enc(p + 20, h->stream);
}

/*
 * Strict UTF-8 (RFC 3629): no overlong forms, no surrogates, nothing
 * above U+10FFFF.  NUL is valid UTF-8; callers reject it where needed.
 */
bool
cbl_utf8_valid(const unsigned char *p, size_t len)
{
	size_t i, n;
	uint32_t cp, min;

	for (i = 0; i < len; i += n) {
		unsigned char c = p[i];

		if (c < 0x80) {
			n = 1;
			continue;
		} else if ((c & 0xe0) == 0xc0) {
			n = 2;
			cp = c & 0x1f;
			min = 0x80;
		} else if ((c & 0xf0) == 0xe0) {
			n = 3;
			cp = c & 0x0f;
			min = 0x800;
		} else if ((c & 0xf8) == 0xf0) {
			n = 4;
			cp = c & 0x07;
			min = 0x10000;
		} else
			return (false);
		if (len - i < n)
			return (false);
		for (size_t j = 1; j < n; j++) {
			if ((p[i + j] & 0xc0) != 0x80)
				return (false);
			cp = (cp << 6) | (p[i + j] & 0x3f);
		}
		if (cp < min || cp > 0x10ffff ||
		    (cp >= 0xd800 && cp <= 0xdfff))
			return (false);
	}
	return (true);
}
