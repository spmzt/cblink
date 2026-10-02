/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cbl-stream: streams and flow control, built from stream.yaml.
 *
 *	cbl-stream -l [-p] [-c cert -k key -a ca] uri	serve
 *	cbl-stream [-p] [...] uri count n	the numbers 1..n, as fast as
 *						the client grants credit
 *	cbl-stream [-p] [...] uri upper		stdin, line by line, back
 *						in upper case
 */

#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cblink.h>

#include "stream.h"

/* Server: "count" sends while it has credit, then waits to be writable. */
struct counting {
	uint64_t	next, last;
};

static void
count_pump(cbl_stream *s, struct counting *c)
{
	struct stream_line l = { .has_number = true };
	int error;

	while (c->next <= c->last) {
		l.number = c->next;
		if ((error = stream_count_server_send(s, &l)) == EAGAIN)
			return;		/* on_writable will call again */
		if (error != 0) {
			(void)cbl_stream_reset(s, error);
			return;
		}
		c->next++;
	}
	(void)cbl_stream_half_close(s);
}

static void
count_writable(cbl_stream *s, size_t credit __unused, void *arg)
{

	count_pump(s, arg);
}

static void
count_closed(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg)
{

	free(arg);
}

static const struct stream_count_server_cbs count_cbs = {
	.on_writable = count_writable,
	.on_close = count_closed,
};

int
stream_count_stream_open(cbl_req *req __unused,
    const struct stream_count_req *rq, cbl_stream *s, void *arg __unused)
{
	struct counting *c;
	int error;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		return (ENOMEM);
	c->next = 1;
	c->last = rq->count;
	if ((error = stream_count_accept(s, &count_cbs, c)) != 0) {
		free(c);
		return (error);
	}
	count_pump(s, c);
	return (0);
}

/* Server: "upper" answers each line; it ends when the client does. */
static void
upper_data(cbl_stream *s, const struct stream_line *data,
    void *arg __unused)
{
	struct stream_line out = { 0 };
	char *u;

	if (data->text == NULL || (u = strdup(data->text)) == NULL)
		return;
	for (char *p = u; *p != '\0'; p++)
		*p = (char)toupper((unsigned char)*p);
	out.text = u;
	/*
	 * The client returns credit as it reads.  A server answering
	 * faster than that would have to queue, or stop and resume in
	 * on_writable as "count" does.
	 */
	if (stream_upper_server_send(s, &out) != 0)
		(void)cbl_stream_reset(s, ENOBUFS);
	free(u);
}

static void
upper_hclose(cbl_stream *s, void *arg __unused)
{

	(void)cbl_stream_half_close(s);
}

static const struct stream_upper_server_cbs upper_cbs = {
	.on_data = upper_data,
	.on_hclose = upper_hclose,
};

int
stream_upper_stream_open(cbl_req *req __unused,
    const struct stream_upper_req *rq __unused, cbl_stream *s,
    void *arg __unused)
{

	return (stream_upper_accept(s, &upper_cbs, NULL));
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
	cbl_family *fam;
	cbl_loop *loop;
	int error;

	if ((error = stream_register(ctx, NULL, &fam)) != 0)
		errc(1, error, "register");
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
	(void)cbl_family_unregister(fam);
	return (error);
}

/* Client. */
struct run {
	cbl_loop	*loop;
	uint64_t	 expect;	/* count: the next number */
	char		**lines;	/* upper: what is left to send */
	size_t		 nlines, sent;
	int		 error;
};

static void
client_open(cbl_stream *s __unused, int error, void *arg)
{
	struct run *r = arg;

	if (error != 0) {
		r->error = error;
		cbl_loop_stop(r->loop);
	}
}

static void
client_closed(cbl_stream *s __unused, int code, const char *text,
    void *arg)
{
	struct run *r = arg;

	if (code != 0) {
		warnx("stream reset: %s", text != NULL ? text : strerror(code));
		r->error = code;
	}
	cbl_loop_stop(r->loop);
}

static void
count_data(cbl_stream *s, const struct stream_line *data, void *arg)
{
	struct run *r = arg;

	if (!data->has_number || data->number != r->expect) {
		warnx("expected %ju", (uintmax_t)r->expect);
		(void)cbl_stream_reset(s, EBADMSG);
		return;
	}
	r->expect++;
}

static const struct stream_count_cbs count_client_cbs = {
	.on_open = client_open,
	.on_data = count_data,
	.on_close = client_closed,
};

/* Send what credit allows; half-close after the last line. */
static void
upper_pump(cbl_stream *s, struct run *r)
{
	struct stream_line l = { 0 };
	int error;

	while (r->sent < r->nlines) {
		l.text = r->lines[r->sent];
		if ((error = stream_upper_send(s, &l)) == EAGAIN)
			return;
		if (error != 0) {
			r->error = error;
			cbl_loop_stop(r->loop);
			return;
		}
		r->sent++;
	}
	(void)cbl_stream_half_close(s);
}

static void
upper_client_open(cbl_stream *s, int error, void *arg)
{

	client_open(s, error, arg);
	if (error == 0)
		upper_pump(s, arg);
}

static void
upper_client_writable(cbl_stream *s, size_t credit __unused, void *arg)
{

	upper_pump(s, arg);
}

static void
upper_client_data(cbl_stream *s __unused, const struct stream_line *data,
    void *arg __unused)
{

	printf("%s\n", data->text != NULL ? data->text : "");
}

static const struct stream_upper_cbs upper_client_cbs = {
	.on_open = upper_client_open,
	.on_data = upper_client_data,
	.on_writable = upper_client_writable,
	.on_close = client_closed,
};

static void
read_lines(struct run *r)
{
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;

	while ((n = getline(&line, &cap, stdin)) > 0) {
		if (line[n - 1] == '\n')
			line[n - 1] = '\0';
		if ((r->lines = reallocarray(r->lines, r->nlines + 1,
		    sizeof(*r->lines))) == NULL ||
		    (r->lines[r->nlines++] = strdup(line)) == NULL)
			err(1, "stdin");
	}
	free(line);
}

static int
client(cbl_ctx *ctx, const char *uri, uint32_t flags, cbl_tls *tls,
    int argc, char **argv)
{
	struct stream_client cl;
	struct run r = { .expect = 1 };
	uint64_t n = 0;
	cbl_stream *s;
	cbl_conn *conn;
	int error;

	if ((error = cbl_conn_new(ctx, uri, flags, &conn)) != 0)
		errc(1, error, "%s", uri);
	if (tls != NULL)
		(void)cbl_conn_set_tls(conn, tls);
	if ((error = cbl_conn_connect(conn)) != 0)
		errx(1, "%s: %s", uri, cbl_conn_errstr(conn));
	if ((error = stream_client_init(&cl, conn)) != 0)
		errc(1, error, "stream family");
	if ((error = cbl_loop_new(ctx, &r.loop)) != 0)
		errc(1, error, "loop");

	if (strcmp(argv[0], "count") == 0 && argc == 2) {
		struct stream_count_req req = { .has_count = true };

		n = strtoull(argv[1], NULL, 10);
		req.count = (uint32_t)n;
		error = stream_count_open(&cl, &req, &count_client_cbs, &r,
		    &s);
	} else if (strcmp(argv[0], "upper") == 0 && argc == 1) {
		read_lines(&r);
		error = stream_upper_open(&cl, NULL, &upper_client_cbs, &r,
		    &s);
	} else
		errx(2, "unknown command or wrong arguments: %s", argv[0]);
	if (error != 0)
		errc(1, error, "%s", argv[0]);
	/* Stream callbacks run on the loop the connection is attached to. */
	if ((error = cbl_conn_attach(conn, r.loop)) != 0)
		errc(1, error, "attach");
	(void)cbl_loop_run(r.loop);
	if (r.error == 0 && strcmp(argv[0], "count") == 0) {
		if (r.expect != n + 1)
			errx(1, "got %ju of %ju numbers",
			    (uintmax_t)r.expect - 1, (uintmax_t)n);
		printf("received 1..%ju in order\n", (uintmax_t)n);
	}
	for (size_t i = 0; i < r.nlines; i++)
		free(r.lines[i]);
	free(r.lines);
	cbl_loop_free(r.loop);
	stream_client_fini(&cl);
	cbl_conn_free(conn);
	return (r.error != 0 ? 1 : 0);
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
	    "usage: cbl-stream -l [-p] [-c cert -k key -a ca] uri\n"
	    "       cbl-stream [-p] [-c cert -k key -a ca] uri count n\n"
	    "       cbl-stream [-p] [-c cert -k key -a ca] uri upper\n");
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

	while ((ch = getopt(argc, argv, "a:c:k:lp")) != -1) {
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
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (listen ? argc != 1 : argc < 2)
		usage();
	if (cbl_ctx_new(&ctx) != 0)
		errx(1, "cbl_ctx_new");
	tls = tls_config(cert, key, ca);
	rv = listen ? serve(ctx, argv[0], flags, tls) :
	    client(ctx, argv[0], flags, tls, argc - 1, argv + 1);
	cbl_tls_free(tls);
	cbl_ctx_free(ctx);
	return (rv);
}
