/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cbl-notify: multicast notifications, built from notify.yaml.
 *
 *	cbl-notify -l [-p] [-i ms] [-c cert -k key -a ca] uri
 *		serve, announcing a tick every ms milliseconds (1000)
 *	cbl-notify [-p] [-c cert -k key -a ca] uri count
 *		subscribe and print count ticks
 */

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cblink.h>

#include "notify.h"

struct ticker {
	cbl_family	*fam;
	uint64_t	 seq;
	struct timespec	 start;
};

static uint64_t
msec_since(const struct timespec *t0)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return ((uint64_t)(now.tv_sec - t0->tv_sec) * 1000 +
	    (uint64_t)((now.tv_nsec - t0->tv_nsec) / 1000000));
}

/* Every subscriber gets the same message; nobody subscribed: no work. */
static void
tick(cbl_timer *t __unused, void *arg)
{
	struct ticker *tk = arg;
	struct notify_tick_ntf ntf = {
		.has_seq = true, .seq = ++tk->seq,
		.has_msec = true, .msec = msec_since(&tk->start),
	};

	(void)notify_tick_notify(tk->fam, &ntf);
}

static void
on_signal(int sig __unused, void *arg)
{

	cbl_loop_stop(arg);
}

static int
serve(cbl_ctx *ctx, const char *uri, uint32_t flags, cbl_tls *tls,
    unsigned long ms)
{
	struct ticker tk = { 0 };
	cbl_listener *l;
	cbl_timer *timer;
	cbl_loop *loop;
	int error;

	clock_gettime(CLOCK_MONOTONIC, &tk.start);
	if ((error = notify_register(ctx, NULL, &tk.fam)) != 0)
		errc(1, error, "register");
	if ((error = cbl_loop_new(ctx, &loop)) != 0 ||
	    (error = cbl_listener_new(ctx, uri, flags, &l)) != 0)
		errc(1, error, "%s", uri);
	if (tls != NULL)
		(void)cbl_listener_set_tls(l, tls);
	if ((error = cbl_listener_start(l, loop)) != 0)
		errx(1, "%s: %s", uri, cbl_listener_errstr(l));
	if ((error = cbl_loop_timer(loop, (uint32_t)ms, CBL_TF_REPEAT, tick,
	    &tk, &timer)) != 0)
		errc(1, error, "timer");
	(void)cbl_loop_signal(loop, SIGINT, on_signal, loop);
	(void)cbl_loop_signal(loop, SIGTERM, on_signal, loop);
	printf("listening on %s\n", uri);
	fflush(stdout);
	error = cbl_loop_run(loop);
	cbl_timer_cancel(timer);
	cbl_listener_free(l);
	cbl_loop_free(loop);
	(void)cbl_family_unregister(tk.fam);
	return (error);
}

struct watch {
	cbl_loop	*loop;
	long		 left;
	uint64_t	 last;
};

static void
on_tick(const struct notify_tick_ntf *ntf, void *arg)
{
	struct watch *w = arg;

	/* Notifications are never reordered on one connection. */
	if (w->last != 0 && ntf->seq <= w->last)
		warnx("tick %ju after %ju", (uintmax_t)ntf->seq,
		    (uintmax_t)w->last);
	w->last = ntf->seq;
	printf("tick %ju at %ju ms\n", (uintmax_t)ntf->seq,
	    (uintmax_t)ntf->msec);
	fflush(stdout);
	if (--w->left == 0)
		cbl_loop_stop(w->loop);
}

static int
client(cbl_ctx *ctx, const char *uri, uint32_t flags, cbl_tls *tls,
    long count)
{
	struct notify_ticks_handlers h = { .tick = on_tick };
	struct watch w = { .left = count };
	struct notify_client cl;
	cbl_conn *conn;
	cbl_sub *sub;
	int error;

	if ((error = cbl_conn_new(ctx, uri, flags, &conn)) != 0)
		errc(1, error, "%s", uri);
	if (tls != NULL)
		(void)cbl_conn_set_tls(conn, tls);
	if ((error = cbl_conn_connect(conn)) != 0)
		errx(1, "%s: %s", uri, cbl_conn_errstr(conn));
	if ((error = notify_client_init(&cl, conn)) != 0)
		errc(1, error, "notify family");
	if ((error = notify_ticks_subscribe(&cl, &h, &w, &sub)) != 0)
		errc(1, error, "subscribe");
	/* Notifications are delivered by the loop the connection is on. */
	if ((error = cbl_loop_new(ctx, &w.loop)) != 0 ||
	    (error = cbl_conn_attach(conn, w.loop)) != 0)
		errc(1, error, "loop");
	(void)cbl_loop_run(w.loop);
	cbl_loop_free(w.loop);
	notify_client_fini(&cl);
	cbl_conn_free(conn);
	return (w.left == 0 ? 0 : 1);
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
usage(void)
{

	fprintf(stderr,
	    "usage: cbl-notify -l [-p] [-i ms] [-c cert -k key -a ca] uri\n"
	    "       cbl-notify [-p] [-c cert -k key -a ca] uri count\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	const char *cert = NULL, *key = NULL, *ca = NULL;
	unsigned long ms = 1000;
	uint32_t flags = 0;
	bool listen = false;
	cbl_tls *tls;
	cbl_ctx *ctx;
	int ch, rv;

	while ((ch = getopt(argc, argv, "a:c:i:k:lp")) != -1) {
		switch (ch) {
		case 'a':
			ca = optarg;
			break;
		case 'c':
			cert = optarg;
			break;
		case 'i':
			ms = strtoul(optarg, NULL, 10);
			if (ms == 0)
				usage();
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
	rv = listen ? serve(ctx, argv[0], flags, tls, ms) :
	    client(ctx, argv[0], flags, tls, strtol(argv[1], NULL, 10));
	cbl_tls_free(tls);
	cbl_ctx_free(ctx);
	return (rv);
}
