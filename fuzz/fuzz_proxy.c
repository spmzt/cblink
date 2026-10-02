/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: the PROXY protocol header that starts a connection on a
 * CBL_LF_PROXY listener.  The input arrives on a socket, as it would, so
 * the reads that must stop at the end of the header are exercised too:
 * whatever the reader leaves must be the input's unread tail.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cbl_impl.h"

#define	FUZZ_MAXLEN	1024

int	LLVMFuzzerInitialize(int *argc, char ***argv);
int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static cbl_ctx *ctx;
static struct cbl_limits lim;

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{

	if (cbl_ctx_new(&ctx) != 0)
		abort();
	cbl_ctx_freeze(ctx, &lim);
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned char rest[FUZZ_MAXLEN];
	cbl_conn *conn;
	size_t left;
	ssize_t n;
	int sv[2], error;

	if (size > FUZZ_MAXLEN)
		return (0);
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == -1)
		abort();
	if (size > 0 && write(sv[1], data, size) != (ssize_t)size)
		abort();
	(void)shutdown(sv[1], SHUT_WR);
	if (cbl_conn_alloc(ctx, &lim, &conn) != 0)
		abort();
	conn->fd = sv[0];
	error = cbl_proxy_read(conn);
	/* All of the input is there: the header is complete or refused. */
	if (error == EAGAIN)
		abort();
	n = read(sv[0], rest, sizeof(rest));
	left = n > 0 ? (size_t)n : 0;
	if (left > size || memcmp(rest, data + size - left, left) != 0)
		abort();
	if (error == 0 && size - left > 536)
		abort();
	cbl_conn_rele(conn);
	close(sv[1]);
	return (0);
}
