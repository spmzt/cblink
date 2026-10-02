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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "cblink.h"

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
	out[2] = 1;
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

#endif /* !_CBL_TEST_H_ */
