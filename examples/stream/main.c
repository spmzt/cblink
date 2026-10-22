/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cbl-stream: streams and flow control.  Its family, "stream", is its
 * own: two commands that open a stream, every body the "line" structure
 * of the YANG module stream@2026-10-13.yang, put and read with what
 * cblink-gen writes for it (stream_line_put(), stream_line_parse()).
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
#include <cbl_schema.h>

#include "stream.h"

#define	STREAM_COUNT	1	/* server to client */
#define	STREAM_UPPER	2	/* both ways */

/* A line as the stream's next message; EAGAIN: no credit for it. */
static int
send_line(cbl_stream *s, const struct stream_line *l)
{
	cbl_msg *msg;
	int error;

	if ((error = cbl_stream_msg_new(s, &msg)) != 0)
		return (error);
	if ((error = stream_line_put(msg, l)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	return (cbl_stream_send(s, msg));
}

/* A message's line, checked against the module (version 1's policy). */
static int
read_line(const cbl_msg *msg, struct stream_line *l, cbl_yarena **ap)
{

	if ((*ap = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	return (stream_line_parse(msg, l, *ap, CBL_YD_STRICT, NULL, 0));
}

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
		if ((error = send_line(s, &l)) == EAGAIN)
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

static const struct cbl_stream_cbs count_cbs = {
	.on_writable = count_writable,
	.on_close = count_closed,
};

static int
count_open(cbl_req *req __unused, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{
	struct stream_line rq;
	struct counting *c;
	cbl_yarena *a;
	int error;

	if ((error = read_line(msg, &rq, &a)) != 0 || !rq.has_count) {
		cbl_yarena_free(a);
		return (error != 0 ? error : EINVAL);
	}
	if ((c = calloc(1, sizeof(*c))) == NULL) {
		cbl_yarena_free(a);
		return (ENOMEM);
	}
	c->next = 1;
	c->last = rq.count;
	cbl_yarena_free(a);
	if ((error = cbl_stream_accept(s, NULL, 0, &count_cbs, c)) != 0) {
		free(c);
		return (error);
	}
	count_pump(s, c);
	return (0);
}

/* Server: "upper" answers each line; it ends when the client does. */
static void
upper_data(cbl_stream *s, cbl_msg *data, void *arg __unused)
{
	struct stream_line in, out = { 0 };
	cbl_yarena *a;
	char *u;

	if (read_line(data, &in, &a) != 0 || in.text == NULL ||
	    (u = strdup(in.text)) == NULL) {
		cbl_yarena_free(a);
		(void)cbl_stream_reset(s, EINVAL);
		return;
	}
	cbl_yarena_free(a);
	for (char *p = u; *p != '\0'; p++)
		*p = (char)toupper((unsigned char)*p);
	out.text = u;
	/*
	 * The client returns credit as it reads.  A server answering
	 * faster than that would have to queue, or stop and resume in
	 * on_writable as "count" does.
	 */
	if (send_line(s, &out) != 0)
		(void)cbl_stream_reset(s, ENOBUFS);
	free(u);
}

static void
upper_hclose(cbl_stream *s, void *arg __unused)
{

	(void)cbl_stream_half_close(s);
}

static const struct cbl_stream_cbs upper_cbs = {
	.on_data = upper_data,
	.on_hclose = upper_hclose,
};

static int
upper_open(cbl_req *req __unused, const cbl_msg *msg __unused,
    cbl_stream *s, void *arg __unused)
{

	return (cbl_stream_accept(s, NULL, 0, &upper_cbs, NULL));
}

static const struct cbl_op stream_ops[] = {
	{ .cmd = STREAM_COUNT, .flags = CBL_OPF_PUSH, .name = "count",
	    .stream_open = count_open },
	{ .cmd = STREAM_UPPER, .flags = CBL_OPF_STREAM, .name = "upper",
	    .stream_open = upper_open },
};

static const struct cbl_family_def stream_def = {
	.abi = CBL_FAMILY_ABI,
	.name = "stream",
	.version = 2,
	.ops = stream_ops,
	.nops = sizeof(stream_ops) / sizeof(stream_ops[0]),
};

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

	if ((error = cbl_family_register(ctx, &stream_def, NULL, &fam)) != 0)
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
client_open(cbl_stream *s __unused, cbl_msg *accept __unused, int error,
    void *arg)
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
count_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct run *r = arg;
	struct stream_line l;
	cbl_yarena *a;

	if (read_line(data, &l, &a) != 0 || !l.has_number ||
	    l.number != r->expect) {
		warnx("expected %ju", (uintmax_t)r->expect);
		(void)cbl_stream_reset(s, EBADMSG);
	} else
		r->expect++;
	cbl_yarena_free(a);
}

static const struct cbl_stream_cbs count_client_cbs = {
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
		if ((error = send_line(s, &l)) == EAGAIN)
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
upper_client_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{

	client_open(s, accept, error, arg);
	if (error == 0)
		upper_pump(s, arg);
}

static void
upper_client_writable(cbl_stream *s, size_t credit __unused, void *arg)
{

	upper_pump(s, arg);
}

static void
upper_client_data(cbl_stream *s __unused, cbl_msg *data,
    void *arg __unused)
{
	struct stream_line l;
	cbl_yarena *a;

	if (read_line(data, &l, &a) == 0)
		printf("%s\n", l.text != NULL ? l.text : "");
	cbl_yarena_free(a);
}

static const struct cbl_stream_cbs upper_client_cbs = {
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

/* A stream's opening: the family resolved, the request a line. */
static int
open_stream(cbl_conn *conn, uint16_t fam, uint16_t cmd,
    const struct stream_line *rq, uint32_t flags,
    const struct cbl_stream_cbs *cbs, struct run *r, cbl_stream **sp)
{
	cbl_msg *msg;
	int error;

	if ((error = cbl_msg_new(cbl_conn_ctx(conn), fam, cmd,
	    CBL_F_REQUEST | CBL_F_S_OPEN, &msg)) != 0)
		return (error);
	if ((error = stream_line_put(msg, rq)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	/* What we take before granting more: far less than is counted. */
	(void)cbl_msg_set_window(msg, 4096);
	return (cbl_stream_open(conn, msg, flags, cbs, r, sp));
}

static int
client(cbl_ctx *ctx, const char *uri, uint32_t flags, cbl_tls *tls,
    int argc, char **argv)
{
	struct run r = { .expect = 1 };
	struct stream_line rq = { 0 };
	cbl_family_info *info;
	uint64_t n = 0;
	cbl_stream *s;
	cbl_conn *conn;
	uint16_t fam;
	int error;

	if ((error = cbl_conn_new(ctx, uri, flags, &conn)) != 0)
		errc(1, error, "%s", uri);
	if (tls != NULL)
		(void)cbl_conn_set_tls(conn, tls);
	if ((error = cbl_conn_connect(conn)) != 0)
		errx(1, "%s: %s", uri, cbl_conn_errstr(conn));
	/* The family's id is the server's to choose: by its name. */
	if ((error = cbl_resolve(conn, "stream", &info)) != 0)
		errc(1, error, "stream family");
	fam = cbl_family_info_id(info);
	cbl_family_info_free(info);
	if ((error = cbl_loop_new(ctx, &r.loop)) != 0)
		errc(1, error, "loop");

	if (strcmp(argv[0], "count") == 0 && argc == 2) {
		n = strtoull(argv[1], NULL, 10);
		rq.has_count = true;
		rq.count = (uint32_t)n;
		error = open_stream(conn, fam, STREAM_COUNT, &rq, CBL_SF_PUSH,
		    &count_client_cbs, &r, &s);
	} else if (strcmp(argv[0], "upper") == 0 && argc == 1) {
		read_lines(&r);
		error = open_stream(conn, fam, STREAM_UPPER, &rq, 0,
		    &upper_client_cbs, &r, &s);
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
