/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cbl-echo: the smallest cblink server and client, built from the YANG
 * module echo@2026-10-13.yang: its rpc served by family 1.
 *
 *	cbl-echo -l [-pt] [-c cert -k key -a ca] uri	serve
 *	cbl-echo [-p] [-c cert -k key -a ca] uri text	ask
 *
 * Without -p, TCP and SCTP use mutual TLS; unix: sockets need none.
 */

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "echo.h"

/* The rpc's handler, as echo.h declares it: what it allocates is a's. */
int
echo_echo_rpc(cbl_req *req, const struct echo_echo_input *in,
    struct echo_echo_output *out, cbl_yarena *a)
{
	const cbl_peer *p = cbl_req_peer(req);
	char *who;
	uid_t uid;

	out->text = in->text;
	if (cbl_peer_subject(p) != NULL)
		out->peer = cbl_peer_subject(p);
	else if (cbl_peer_cred(p, &uid, NULL) == 0) {
		if ((who = cbl_yarena_alloc(a, 32)) == NULL)
			return (ENOMEM);
		snprintf(who, 32, "uid %u", (unsigned)uid);
		out->peer = who;
	} else
		out->peer = "anonymous";
	return (0);
}

static cbl_tls *
tls_config(const char *cert, const char *key, const char *ca)
{
	cbl_tls *tls;

	if (cert == NULL && ca == NULL)
		return (NULL);
	if (cbl_tls_new(&tls) != 0 ||
	    (cert != NULL && cbl_tls_set_cert(tls, cert, key) != 0) ||
	    (ca != NULL && cbl_tls_set_ca(tls, ca, NULL) != 0))
		errx(1, "TLS configuration");
	return (tls);
}

static void
on_signal(int sig __unused, void *arg)
{

	cbl_loop_stop(arg);
}

static int
serve(cbl_ctx *ctx, const char *uri, uint32_t flags, cbl_tls *tls)
{
	cbl_listener *l;
	cbl_loop *loop;
	int error;

	if ((error = cbl_yserver_add(ctx, &echo_server, NULL)) != 0)
		errc(1, error, "serve");
	if ((error = cbl_loop_new(ctx, &loop)) != 0 ||
	    (error = cbl_listener_new(ctx, uri, flags, &l)) != 0)
		errc(1, error, "%s", uri);
	if (tls != NULL)
		(void)cbl_listener_set_tls(l, tls);
	if ((error = cbl_listener_start(l, loop)) != 0)
		errx(1, "%s: %s", uri, cbl_listener_errstr(l));
	(void)cbl_loop_signal(loop, SIGINT, on_signal, loop);
	(void)cbl_loop_signal(loop, SIGTERM, on_signal, loop);
	printf("listening on %s\n", uri);
	fflush(stdout);
	error = cbl_loop_run(loop);
	cbl_listener_free(l);
	cbl_loop_free(loop);
	return (error);
}

static int
ask(cbl_ctx *ctx, const char *uri, uint32_t flags, cbl_tls *tls,
    const char *text)
{
	struct echo_echo_input in = { .text = text };
	struct echo_echo_output out;
	cbl_yarena *a;
	cbl_conn *conn;
	int error;

	if ((error = cbl_conn_new(ctx, uri, flags, &conn)) != 0)
		errc(1, error, "%s", uri);
	if (tls != NULL)
		(void)cbl_conn_set_tls(conn, tls);
	if ((error = cbl_conn_connect(conn)) != 0)
		errx(1, "%s: %s", uri, cbl_conn_errstr(conn));
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	/* Family 1's RPC: the server serves the module by SID. */
	if ((error = echo_echo_call(conn, &in, &out, a, -1)) != 0)
		errc(1, error, "echo");
	printf("%s (as seen by the server: %s)\n", out.text,
	    out.peer != NULL ? out.peer : "?");
	cbl_yarena_free(a);
	cbl_conn_free(conn);
	return (0);
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: cbl-echo -l [-pt] [-c cert -k key -a ca] uri\n"
	    "       cbl-echo [-p] [-c cert -k key -a ca] uri text\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	const char *cert = NULL, *key = NULL, *ca = NULL;
	uint32_t flags = 0;
	bool listen = false;
	cbl_tls *tls;
	cbl_ctx *ctx;
	int ch, rv;

	while ((ch = getopt(argc, argv, "a:c:k:lpt")) != -1) {
		switch (ch) {
		case 'a':
			ca = optarg;
			break;
		case 'c':
			cert = optarg;
			break;
		case 'k':
			key = optarg;
			break;
		case 'l':
			listen = true;
			break;
		case 'p':
			flags |= CBL_PLAINTEXT;
			break;
		case 't':
			flags |= CBL_LF_UNIX_TRUSTED;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != (listen ? 1 : 2))
		usage();
	if (cbl_ctx_new(&ctx) != 0)
		errx(1, "cbl_ctx_new");
	tls = tls_config(cert, key, ca);
	rv = listen ? serve(ctx, argv[0], flags, tls) :
	    ask(ctx, argv[0], flags, tls, argv[1]);
	cbl_tls_free(tls);
	cbl_ctx_free(ctx);
	return (rv);
}
