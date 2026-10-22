/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Helpers shared by the libcblink atf-c tests. */

#ifndef _CBL_TEST_H_
#define	_CBL_TEST_H_

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "cblink.h"
#include "cbl_schema.h"

/* Decode a hex string, ignoring whitespace. */
static inline size_t
hex2bin(const char *hex, unsigned char *out, size_t max)
{
	size_t n = 0;
	unsigned v;

	while (*hex != '\0') {
		if (isspace((unsigned char)*hex)) {
			hex++;
			continue;
		}
		ATF_REQUIRE_MSG(sscanf(hex, "%2x", &v) == 1, "bad hex");
		ATF_REQUIRE(n < max);
		out[n++] = (unsigned char)v;
		hex += 2;
	}
	return (n);
}

static inline void
dump_hex(const char *label, const unsigned char *p, size_t len)
{

	fprintf(stderr, "%s (%zu bytes):", label, len);
	for (size_t i = 0; i < len; i++)
		fprintf(stderr, "%s%02X", i % 16 == 0 ? "\n  " : " ", p[i]);
	fprintf(stderr, "\n");
}

/* Encode "msg" and require it to equal the hex dump. */
static inline void
require_frame(cbl_msg *msg, const char *hex)
{
	unsigned char want[4096];
	const void *got;
	size_t wlen, glen;
	int error;

	wlen = hex2bin(hex, want, sizeof(want));
	error = cbl_msg_encode(msg, &got, &glen);
	ATF_REQUIRE_MSG(error == 0, "encode: %d (%s)", error,
	    cbl_msg_errstr(msg) != NULL ? cbl_msg_errstr(msg) : "");
	if (glen != wlen || memcmp(got, want, wlen) != 0) {
		dump_hex("expected", want, wlen);
		dump_hex("got", got, glen);
		atf_tc_fail("frame mismatch");
	}
}

/*
 * Build a raw frame from header fields and a hex body, bypassing the
 * builder, to feed hostile input to the decoder.
 */
static inline size_t
mkframe(unsigned char *out, size_t max, uint16_t family, uint16_t cmd,
    uint32_t flags, uint32_t seq, uint32_t stream, const char *bodyhex)
{
	size_t blen, len;

	ATF_REQUIRE(max >= CBL_HDRLEN);
	blen = bodyhex != NULL ?
	    hex2bin(bodyhex, out + CBL_HDRLEN, max - CBL_HDRLEN) : 0;
	len = CBL_HDRLEN + blen;
	out[0] = 0xCB;
	out[1] = 0x4C;
	out[2] = CBL_PROTO_VERSION;
	out[3] = CBL_HDRLEN;
	out[4] = len >> 24;
	out[5] = (len >> 16) & 0xff;
	out[6] = (len >> 8) & 0xff;
	out[7] = len & 0xff;
	out[8] = family >> 8;
	out[9] = family & 0xff;
	out[10] = cmd >> 8;
	out[11] = cmd & 0xff;
	for (int i = 0; i < 4; i++) {
		out[12 + i] = (flags >> (24 - 8 * i)) & 0xff;
		out[16 + i] = (seq >> (24 - 8 * i)) & 0xff;
		out[20 + i] = (stream >> (24 - 8 * i)) & 0xff;
	}
	return (len);
}

static inline cbl_ctx *
test_ctx(void)
{
	cbl_ctx *ctx;

	ATF_REQUIRE_EQ(0, cbl_ctx_new(&ctx));
	return (ctx);
}

/*
 * Version 2 bodies for tests about the wire, not YANG: top-level items
 * under small SIDs, each a uint, bytes or a string, in CBOR as RFC 8949
 * has them.  t_put_*() fail the message as cbl_msg_put_sid_raw() does;
 * t_get_*() are false when the item is not there or not of that kind.
 */
static inline size_t
t_head(uint8_t *p, unsigned major, uint64_t v)
{
	size_t k = v < 24 ? 0 : v <= UINT8_MAX ? 1 : v <= UINT16_MAX ? 2 :
	    v <= UINT32_MAX ? 4 : 8;

	p[0] = (uint8_t)(major << 5 | (k == 0 ? v : k == 1 ? 24 : k == 2 ?
	    25 : k == 4 ? 26 : 27));
	for (size_t i = 0; i < k; i++)
		p[1 + i] = (uint8_t)(v >> (8 * (k - 1 - i)));
	return (1 + k);
}

static inline int
t_put_uint(cbl_msg *m, uint64_t sid, uint64_t v)
{
	uint8_t b[9];

	return (cbl_msg_put_sid_raw(m, sid, b, t_head(b, 0, v)));
}

static inline int
t_put_raw(cbl_msg *m, uint64_t sid, unsigned major, const void *p,
    size_t len)
{
	uint8_t *b;
	size_t h;
	int error;

	if ((b = malloc(9 + len)) == NULL)
		return (ENOMEM);
	h = t_head(b, major, len);
	if (len > 0)
		memcpy(b + h, p, len);
	error = cbl_msg_put_sid_raw(m, sid, b, h + len);
	free(b);
	return (error);
}

static inline int
t_put_bytes(cbl_msg *m, uint64_t sid, const void *p, size_t len)
{

	return (t_put_raw(m, sid, 2, p, len));
}

static inline int
t_put_str(cbl_msg *m, uint64_t sid, const char *s)
{

	return (t_put_raw(m, sid, 3, s, strlen(s)));
}

/* An item's head: its major type, its value; where its content is. */
static inline bool
t_item(const cbl_msg *m, uint64_t sid, unsigned *major, uint64_t *v,
    const uint8_t **rest, size_t *restlen)
{
	const uint8_t *p;
	size_t len, k;

	if (cbl_msg_sid_raw(m, sid, (const void **)&p, &len) != 0 ||
	    len == 0)
		return (false);
	*major = p[0] >> 5;
	*v = p[0] & 0x1f;
	k = *v < 24 ? 0 : *v <= 27 ? (size_t)1 << (*v - 24) : SIZE_MAX;
	if (k == SIZE_MAX || len < 1 + k)
		return (false);
	if (k > 0)
		for (*v = 0, len -= 1, p++; k > 0; k--, len--)
			*v = *v << 8 | *p++;
	else {
		p++;
		len--;
	}
	*rest = p;
	*restlen = len;
	return (true);
}

static inline bool
t_get_uint(const cbl_msg *m, uint64_t sid, uint64_t *v)
{
	const uint8_t *p;
	unsigned major;
	size_t len;

	return (t_item(m, sid, &major, v, &p, &len) && major == 0 &&
	    len == 0);
}

static inline bool
t_get_bytes(const cbl_msg *m, uint64_t sid, const void **pp, size_t *lenp)
{
	const uint8_t *p;
	unsigned major;
	uint64_t n;
	size_t len;

	if (!t_item(m, sid, &major, &n, &p, &len) || major != 2 || n != len)
		return (false);
	*pp = p;
	*lenp = len;
	return (true);
}

/* A string, copied (and NUL-terminated) into buf; false if it does not fit. */
static inline bool
t_get_str(const cbl_msg *m, uint64_t sid, char *buf, size_t cap)
{
	const uint8_t *p;
	unsigned major;
	uint64_t n;
	size_t len;

	if (!t_item(m, sid, &major, &n, &p, &len) || major != 3 || n != len ||
	    len >= cap)
		return (false);
	memcpy(buf, p, len);
	buf[len] = '\0';
	return (true);
}

/* An item copied from one message to another, as it is. */
static inline int
t_copy(cbl_msg *to, const cbl_msg *from, uint64_t sid)
{
	const void *p;
	size_t len;
	int error;

	if ((error = cbl_msg_sid_raw(from, sid, &p, &len)) != 0)
		return (error);
	return (cbl_msg_put_sid_raw(to, sid, p, len));
}

#endif /* !_CBL_TEST_H_ */
