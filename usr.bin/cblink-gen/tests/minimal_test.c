/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Code generated from families that use only one kind of operation
 * compiles at WARNS=6 (no unused helpers) and registers.
 */

#include <errno.h>

#include <atf-c.h>

#include "onlydo.h"
#include "onlyevents.h"
#include "onlystreams.h"

int
onlydo_say_doit(cbl_req *req, const struct onlydo_say_req *rq,
    void *arg __unused)
{
	struct onlydo_say_rsp rsp = { .text = rq->text };

	return (onlydo_say_reply(req, &rsp));
}

int
onlystreams_feed_stream_open(cbl_req *req __unused,
    const struct onlystreams_feed_req *rq __unused, cbl_stream *s __unused,
    void *arg __unused)
{

	return (EOPNOTSUPP);
}

ATF_TC_WITHOUT_HEAD(register);
ATF_TC_BODY(register, tc)
{
	cbl_family *f1, *f2, *f3;
	cbl_ctx *ctx;

	ATF_REQUIRE_EQ(0, cbl_ctx_new(&ctx));
	ATF_REQUIRE_EQ(0, onlydo_register(ctx, NULL, &f1));
	ATF_REQUIRE_EQ(0, onlystreams_register(ctx, NULL, &f2));
	ATF_REQUIRE_EQ(0, onlyevents_register(ctx, NULL, &f3));
	ATF_REQUIRE(cbl_family_id(f1) != cbl_family_id(f2));
	ATF_REQUIRE_EQ(0, cbl_family_unregister(f3));
	ATF_REQUIRE_EQ(0, cbl_family_unregister(f2));
	ATF_REQUIRE_EQ(0, cbl_family_unregister(f1));
	cbl_ctx_free(ctx);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, register);
	return (atf_no_error());
}
