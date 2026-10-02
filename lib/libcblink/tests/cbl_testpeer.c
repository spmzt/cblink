/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A small cblink peer for the atf-sh tests (TLS, transports).
 *
 *   cbl_testpeer serve [-pP] [-u mode] [-c cert -k key -a ca] uri
 *	Serve the "testpeer" family on "uri"; print "ready <port>" once
 *	listening, then run until SIGTERM or end of standard input.
 *   cbl_testpeer call [-p] [-c cert -k key -a ca] [-n name] [-o op]
 *	[-N count] uri
 *	Connect and run one operation: whoami (default), secret, echo, dump,
 *	feed, ping.  Prints results as key=value lines; exits non-zero with
 *	the error on standard error.
 *   cbl_testpeer relay [-1] [-d pidfile] port
 *	A TCP proxy to 127.0.0.1:port that sends a PROXY header (version 2,
 *	or 1 with -1) naming 192.0.2.7:4321 as the client.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cblink.h"

enum { TP_WHOAMI = 1, TP_SECRET, TP_ECHO, TP_DUMP, TP_FEED };
enum { TA_SUBJECT = 1, TA_SANS, TA_FP, TA_FLAGS, TA_TRANSPORT, TA_ISSUER,
    TA_VALUE, TA_N, TA_UID, TA_ADDR };

static int
whoami_doit(cbl_req *req, const cbl_msg *msg __unused, void *arg __unused)
{
	const cbl_peer *p = cbl_req_peer(req);
	struct sockaddr_storage ss;
	char addr[INET6_ADDRSTRLEN];
	uint8_t fp[32];
	size_t fplen = sizeof(fp);
	cbl_msg *rsp;
	uid_t uid;
	int error;

	if ((error = cbl_req_reply_new(req, 0, &rsp)) != 0)
		return (error);
	if (cbl_peer_subject(p) != NULL)
		cbl_put_str(rsp, TA_SUBJECT, cbl_peer_subject(p));
	if (cbl_peer_issuer(p) != NULL)
		cbl_put_str(rsp, TA_ISSUER, cbl_peer_issuer(p));
	if (cbl_peer_san_count(p) > 0) {
		cbl_array_start(rsp, TA_SANS);
		for (size_t i = 0; i < cbl_peer_san_count(p); i++)
			cbl_put_str(rsp, CBL_ELEM, cbl_peer_san(p, i));
		cbl_array_end(rsp);
	}
	if (cbl_peer_fingerprint(p, "sha256", fp, &fplen) == 0)
		cbl_put_bytes(rsp, TA_FP, fp, fplen);
	cbl_put_uint(rsp, TA_FLAGS, cbl_peer_flags(p));
	cbl_put_uint(rsp, TA_TRANSPORT, (uint64_t)cbl_peer_transport(p));
	if (cbl_peer_cred(p, &uid, NULL) == 0)
		cbl_put_uint(rsp, TA_UID, uid);
	if (cbl_peer_addr(p, &ss, NULL) == 0 && inet_ntop(ss.ss_family,
	    ss.ss_family == AF_INET ?
	    (void *)&((struct sockaddr_in *)&ss)->sin_addr :
	    (void *)&((struct sockaddr_in6 *)&ss)->sin6_addr, addr,
	    sizeof(addr)) != NULL)
		cbl_put_str(rsp, TA_ADDR, addr);
	return (cbl_req_send(req, rsp));
}

static int
secret_doit(cbl_req *req __unused, const cbl_msg *msg __unused,
    void *arg __unused)
{

	return (0);
}

static int
echo_doit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	cbl_msg *rsp;
	int error;

	if ((error = cbl_req_reply_new(req, 0, &rsp)) != 0)
		return (error);
	if (cbl_msg_attr(msg, TA_VALUE) != NULL)
		cbl_put_attr(rsp, TA_VALUE, cbl_msg_attr(msg, TA_VALUE));
	return (cbl_req_send(req, rsp));
}

static int
dump_dumpit(cbl_req *req, const cbl_msg *msg, struct cbl_dump_state *st,
    void *arg __unused)
{
	uint64_t n = 10;
	cbl_msg *item;
	int error;

	(void)cbl_attr_uint(cbl_msg_attr(msg, TA_N), &n);
	if (st->pos[0] >= n)
		return (0);
	if ((error = cbl_req_dump_item(req, &item)) != 0)
		return (error);
	cbl_put_uint(item, TA_VALUE, st->pos[0]++);
	if ((error = cbl_req_send(req, item)) != 0)
		return (error);
	return (EAGAIN);
}

struct feed {
	uint64_t	n, next;
};

static void
feed_pump(cbl_stream *s, struct feed *f)
{
	cbl_msg *m;
	int error;

	while (f->next < f->n) {
		if (cbl_stream_msg_new(s, &m) != 0)
			return;
		cbl_put_uint(m, TA_VALUE, f->next);
		if ((error = cbl_stream_send(s, m)) == EAGAIN) {
			cbl_msg_free(m);
			return;
		}
		if (error != 0)
			return;
		f->next++;
	}
	(void)cbl_stream_half_close(s);
}

static void
feed_writable(cbl_stream *s, size_t credit __unused, void *arg)
{

	feed_pump(s, arg);
}

static void
feed_close(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg)
{

	free(arg);
}

static const struct cbl_stream_cbs feed_cbs = {
	.on_writable = feed_writable,
	.on_close = feed_close,
};

static int
feed_open(cbl_req *req __unused, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{
	struct feed *f;
	int error;

	if ((f = calloc(1, sizeof(*f))) == NULL)
		return (ENOMEM);
	f->n = 10;
	(void)cbl_attr_uint(cbl_msg_attr(msg, TA_N), &f->n);
	if ((error = cbl_stream_accept(s, NULL, 0, &feed_cbs, f)) != 0) {
		free(f);
		return (error);
	}
	feed_pump(s, f);
	return (0);
}

static const struct cbl_op tp_ops[] = {
	{ .cmd = TP_WHOAMI, .name = "whoami", .flags = CBL_OPF_DO,
	  .doit = whoami_doit },
	{ .cmd = TP_SECRET, .name = "secret",
	  .flags = CBL_OPF_DO | CBL_OPF_AUTH, .doit = secret_doit },
	{ .cmd = TP_ECHO, .name = "echo", .flags = CBL_OPF_DO,
	  .doit = echo_doit },
	{ .cmd = TP_DUMP, .name = "dump", .flags = CBL_OPF_DUMP,
	  .dumpit = dump_dumpit },
	{ .cmd = TP_FEED, .name = "feed", .flags = CBL_OPF_PUSH,
	  .stream_open = feed_open },
};

static const struct cbl_family_def tp_def = {
	.abi = CBL_FAMILY_ABI, .name = "testpeer", .version = 1,
	.ops = tp_ops, .nops = nitems(tp_ops),
};

static void
usage(void)
{

	fprintf(stderr,
	    "usage: cbl_testpeer serve [-pPst] [-d pidfile] [-u mode]\n"
	    "           [-c cert -k key -a ca [-r crl]] uri\n"
	    "       cbl_testpeer call [-p] [-c cert -k key -a ca] [-n name]\n"
	    "           [-o op] [-N n] [-B bytes] uri\n"
	    "       cbl_testpeer relay [-1] [-d pidfile] port\n");
	exit(2);
}

static cbl_tls *
make_tls(const char *cert, const char *key, const char *ca, const char *crl,
    const char *name)
{
	cbl_tls *tls;

	if (cert == NULL && key == NULL && ca == NULL)
		return (NULL);
	if (cbl_tls_new(&tls) != 0)
		errx(1, "cbl_tls_new");
	if (cert != NULL && key != NULL && cbl_tls_set_cert(tls, cert,
	    key) != 0)
		errx(1, "cbl_tls_set_cert");
	if (ca != NULL && cbl_tls_set_ca(tls, ca, NULL) != 0)
		errx(1, "cbl_tls_set_ca");
	if (crl != NULL && cbl_tls_set_crl(tls, crl) != 0)
		errx(1, "cbl_tls_set_crl");
	if (name != NULL && cbl_tls_set_peer_name(tls, name) != 0)
		errx(1, "cbl_tls_set_peer_name");
	return (tls);
}

static void
stop(int sig __unused, void *arg)
{

	cbl_loop_stop(arg);
}

/* SIGHUP: reread the certificates and CRL, as a long-lived server would. */
static void
reload(int sig __unused, void *arg)
{

	if (cbl_tls_reload(arg) != 0)
		fprintf(stderr, "reload: %s\n", cbl_tls_errstr(arg));
}

/* End of standard input also stops the server. */
static void *
stdin_watch(void *arg)
{
	char buf[64];

	while (read(STDIN_FILENO, buf, sizeof(buf)) > 0)
		;
	cbl_loop_stop(arg);
	return (NULL);
}

/*
 * -d: run the server in a child and return once it listens, so that a
 * shell script needs no polling.  The parent prints the child's "ready"
 * line, writes its pid to "pidfile" and exits 0; if the child fails
 * first, the parent exits with the child's status.  Called before any
 * kqueue or thread exists: neither survives fork(2).  Returns the
 * descriptor the child writes its "ready" line to.
 */
static int
detach(const char *pidfile)
{
	char buf[256];
	size_t len = 0;
	ssize_t n;
	FILE *fp;
	pid_t child;
	int p[2], st;

	if (pipe(p) == -1)
		err(1, "pipe");
	if ((child = fork()) == -1)
		err(1, "fork");
	if (child == 0) {
		close(p[0]);
		return (p[1]);
	}
	close(p[1]);
	while (len < sizeof(buf) - 1 &&
	    (n = read(p[0], buf + len, sizeof(buf) - 1 - len)) > 0)
		len += (size_t)n;
	if (len == 0) {
		/* The child failed and said why on stderr. */
		if (waitpid(child, &st, 0) == -1)
			err(1, "waitpid");
		exit(WIFEXITED(st) && WEXITSTATUS(st) != 0 ?
		    WEXITSTATUS(st) : 1);
	}
	if ((fp = fopen(pidfile, "w")) == NULL)
		err(1, "%s", pidfile);
	fprintf(fp, "%d\n", (int)child);
	if (fclose(fp) != 0)
		err(1, "%s", pidfile);
	fwrite(buf, 1, len, stdout);
	exit(0);
}

static int
serve(int argc, char **argv)
{
	const char *cert = NULL, *key = NULL, *ca = NULL, *crl = NULL;
	uint32_t flags = 0;
	struct sockaddr_storage ss;
	cbl_listener *l;
	cbl_family *fam;
	cbl_loop *loop;
	cbl_ctx *ctx;
	cbl_tls *tls;
	pthread_t thr;
	mode_t mode = 0;
	const char *pidfile = NULL;
	bool watch = false;
	int ch, error, port = 0;
	int readyfd = -1;

	while ((ch = getopt(argc, argv, "a:c:d:k:pPr:stu:")) != -1) {
		switch (ch) {
		case 'd': pidfile = optarg; break;
		case 'a': ca = optarg; break;
		case 'c': cert = optarg; break;
		case 'k': key = optarg; break;
		case 'p': flags |= CBL_PLAINTEXT; break;
		case 'P': flags |= CBL_LF_PROXY; break;
		case 'r': crl = optarg; break;
		case 's': watch = true; break;
		case 't': flags |= CBL_LF_UNIX_TRUSTED; break;
		case 'u': mode = (mode_t)strtol(optarg, NULL, 8); break;
		default: usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();
	if (pidfile != NULL)
		readyfd = detach(pidfile);
	if (cbl_ctx_new(&ctx) != 0 || cbl_loop_new(ctx, &loop) != 0)
		errx(1, "init");
	if ((error = cbl_family_register(ctx, &tp_def, NULL, &fam)) != 0)
		errc(1, error, "register");
	if ((error = cbl_listener_new(ctx, argv[0], flags, &l)) != 0)
		errc(1, error, "listener %s", argv[0]);
	if ((tls = make_tls(cert, key, ca, crl, NULL)) != NULL)
		(void)cbl_listener_set_tls(l, tls);
	if (mode != 0)
		(void)cbl_listener_set_unix_perm(l, mode, (uid_t)-1,
		    (gid_t)-1);
	if ((error = cbl_listener_start(l, loop)) != 0)
		errx(1, "start: %s", cbl_listener_errstr(l) != NULL ?
		    cbl_listener_errstr(l) : strerror(error));
	if (cbl_listener_addr(l, &ss, NULL) == 0 &&
	    (ss.ss_family == AF_INET || ss.ss_family == AF_INET6))
		port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
	if (readyfd != -1) {
		dprintf(readyfd, "ready %d\n", port);
		close(readyfd);
	} else {
		printf("ready %d\n", port);
		fflush(stdout);
	}
	if (tls != NULL)
		(void)cbl_loop_signal(loop, SIGHUP, reload, tls);
	(void)cbl_loop_signal(loop, SIGTERM, stop, loop);
	(void)cbl_loop_signal(loop, SIGINT, stop, loop);
	if (watch)
		(void)pthread_create(&thr, NULL, stdin_watch, loop);
	(void)cbl_loop_run(loop);
	cbl_listener_free(l);
	cbl_loop_free(loop);
	(void)cbl_family_unregister(fam);
	cbl_tls_free(tls);
	cbl_ctx_free(ctx);
	return (0);
}

static void
print_reply(cbl_msg *rsp)
{
	const cbl_attr *a, *e;
	const char *s;
	const void *p;
	uint64_t v;
	size_t len;

	if ((a = cbl_msg_attr(rsp, TA_SUBJECT)) != NULL &&
	    cbl_attr_str(rsp, a, &s) == 0)
		printf("subject=%s\n", s);
	if ((a = cbl_msg_attr(rsp, TA_ISSUER)) != NULL &&
	    cbl_attr_str(rsp, a, &s) == 0)
		printf("issuer=%s\n", s);
	for (e = cbl_attr_first(cbl_msg_attr(rsp, TA_SANS)); e != NULL;
	    e = cbl_attr_next(e))
		if (cbl_attr_str(rsp, e, &s) == 0)
			printf("san=%s\n", s);
	if (cbl_attr_bytes(cbl_msg_attr(rsp, TA_FP), &p, &len) == 0) {
		printf("sha256=");
		for (size_t i = 0; i < len; i++)
			printf("%02x", ((const uint8_t *)p)[i]);
		printf("\n");
	}
	if (cbl_attr_uint(cbl_msg_attr(rsp, TA_FLAGS), &v) == 0)
		printf("authenticated=%d\nproxied=%d\n",
		    (v & CBL_PEER_AUTHENTICATED) != 0,
		    (v & CBL_PEER_PROXIED) != 0);
	if (cbl_attr_uint(cbl_msg_attr(rsp, TA_TRANSPORT), &v) == 0)
		printf("transport=%s\n", v == CBL_TR_TCP ? "tcp" :
		    v == CBL_TR_SCTP ? "sctp" :
		    v == CBL_TR_UNIX ? "unix" : "?");
	if (cbl_attr_uint(cbl_msg_attr(rsp, TA_UID), &v) == 0)
		printf("uid=%ju\n", (uintmax_t)v);
	if ((a = cbl_msg_attr(rsp, TA_ADDR)) != NULL &&
	    cbl_attr_str(rsp, a, &s) == 0)
		printf("addr=%s\n", s);
	if (cbl_attr_uint(cbl_msg_attr(rsp, TA_VALUE), &v) == 0)
		printf("value=%ju\n", (uintmax_t)v);
	if (cbl_attr_bytes(cbl_msg_attr(rsp, TA_VALUE), &p, &len) == 0)
		printf("bytes=%zu\n", len);
}

struct feedrec {
	atomic_int	done;
	atomic_int	n;
	atomic_int	error;
};

static void
fr_open(cbl_stream *s __unused, cbl_msg *acc __unused, int error, void *arg)
{
	struct feedrec *r = arg;

	r->error = error;
}

static void
fr_data(cbl_stream *s __unused, cbl_msg *d __unused, void *arg)
{
	struct feedrec *r = arg;

	r->n++;
}

static void
fr_close(cbl_stream *s __unused, int code, const char *text __unused,
    void *arg)
{
	struct feedrec *r = arg;

	if (r->error == 0)
		r->error = code;
	r->done = 1;
}

static const struct cbl_stream_cbs fr_cbs = {
	.on_open = fr_open,
	.on_data = fr_data,
	.on_close = fr_close,
};

static int
call(int argc, char **argv)
{
	const char *cert = NULL, *key = NULL, *ca = NULL, *name = NULL;
	const char *op = "whoami";
	uint64_t n = 10, v, bigsz = 0;
	uint32_t flags = 0;
	cbl_family_info *info;
	cbl_msg *req = NULL, *rsp, *item;
	cbl_stream *st;
	cbl_dump *d;
	cbl_conn *conn;
	cbl_ctx *ctx;
	cbl_tls *tls;
	uint16_t id;
	int ch, error, count;

	while ((ch = getopt(argc, argv, "a:B:c:k:n:N:o:p")) != -1) {
		switch (ch) {
		case 'B': bigsz = strtoull(optarg, NULL, 10); break;
		case 'a': ca = optarg; break;
		case 'c': cert = optarg; break;
		case 'k': key = optarg; break;
		case 'n': name = optarg; break;
		case 'N': n = strtoull(optarg, NULL, 10); break;
		case 'o': op = optarg; break;
		case 'p': flags |= CBL_PLAINTEXT; break;
		default: usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();
	if (cbl_ctx_new(&ctx) != 0)
		errx(1, "init");
	if ((error = cbl_conn_new(ctx, argv[0], flags, &conn)) != 0)
		errc(1, error, "%s", argv[0]);
	if ((tls = make_tls(cert, key, ca, NULL, name)) != NULL)
		(void)cbl_conn_set_tls(conn, tls);
	if ((error = cbl_conn_connect(conn)) != 0)
		errx(1, "connect: %s", cbl_conn_errstr(conn) != NULL ?
		    cbl_conn_errstr(conn) : strerror(error));
	if (strcmp(op, "ping") == 0) {
		if ((error = cbl_ping(conn, 5000)) != 0)
			errx(1, "ping: %s", cbl_conn_errstr(conn) != NULL ?
			    cbl_conn_errstr(conn) : strerror(error));
		printf("pong\n");
		goto out;
	}
	if ((error = cbl_resolve(conn, "testpeer", &info)) != 0)
		errx(1, "resolve: %s", cbl_conn_errstr(conn) != NULL ?
		    cbl_conn_errstr(conn) : strerror(error));
	id = cbl_family_info_id(info);
	cbl_family_info_free(info);

	if (strcmp(op, "dump") == 0) {
		cbl_msg_new(ctx, id, TP_DUMP, 0, &req);
		cbl_put_uint(req, TA_N, n);
		if ((error = cbl_dump_start(conn, req, &d)) != 0)
			errc(1, error, "dump");
		for (count = 0; (error = cbl_dump_next(d, &item)) == 0 &&
		    item != NULL; count++)
			;
		cbl_dump_free(d);
		if (error != 0)
			errc(1, error, "dump");
		printf("items=%d\n", count);
		goto out;
	}
	if (strcmp(op, "feed") == 0) {
		struct feedrec r = { 0 };
		struct pollfd pfd;
		struct timespec now, end;
		int events, timeout;

		cbl_msg_new(ctx, id, TP_FEED, 0, &req);
		cbl_put_uint(req, TA_N, n);
		if ((error = cbl_stream_open(conn, req, CBL_SF_PUSH, &fr_cbs,
		    &r, &st)) != 0)
			errc(1, error, "stream");
		/* Bounded by time: transports differ in frames per wakeup. */
		clock_gettime(CLOCK_MONOTONIC, &end);
		end.tv_sec += 10;
		for (;;) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (r.done || timespeccmp(&now, &end, >=))
				break;
			(void)cbl_conn_interest(conn, &events, &timeout);
			pfd.fd = cbl_conn_fd(conn);
			pfd.events = POLLIN |
			    ((events & CBL_EV_WRITE) ? POLLOUT : 0);
			pfd.revents = 0;
			(void)poll(&pfd, 1, 10);
			(void)cbl_conn_process(conn,
			    ((pfd.revents & (POLLIN | POLLHUP)) ?
			    CBL_EV_READ : 0) |
			    ((pfd.revents & POLLOUT) ? CBL_EV_WRITE : 0));
		}
		if (r.error != 0)
			errc(1, r.error, "stream");
		printf("items=%d\n", (int)r.n);
		goto out;
	}
	if (strcmp(op, "whoami") == 0)
		cbl_msg_new(ctx, id, TP_WHOAMI, 0, &req);
	else if (strcmp(op, "secret") == 0)
		cbl_msg_new(ctx, id, TP_SECRET, 0, &req);
	else if (strcmp(op, "echo") == 0) {
		cbl_msg_new(ctx, id, TP_ECHO, 0, &req);
		if (bigsz > 0) {
			void *blob = calloc(1, bigsz);

			cbl_put_bytes(req, TA_VALUE, blob, bigsz);
			free(blob);
		} else
			cbl_put_uint(req, TA_VALUE, n);
	} else
		usage();
	if ((error = cbl_request(conn, req, &rsp, 5000)) != 0)
		errx(1, "%s: %s%s%s", op, strerror(error),
		    rsp != NULL && cbl_msg_err_str(rsp) != NULL ? ": " : "",
		    rsp != NULL && cbl_msg_err_str(rsp) != NULL ?
		    cbl_msg_err_str(rsp) : "");
	if (rsp != NULL)
		print_reply(rsp);
	else
		printf("ok\n");
	if (strcmp(op, "whoami") == 0 && strncmp(argv[0], "sctp:", 5) == 0) {
		struct sockaddr *pa;
		int np;

		/* Multihoming: the paths of the association. */
		if ((np = sctp_getpaddrs(cbl_conn_fd(conn), 0, &pa)) > 0) {
			printf("paths=%d\n", np);
			sctp_freepaddrs(pa);
		}
	}
	(void)v;
	cbl_msg_free(rsp);
out:
	cbl_conn_free(conn);
	cbl_tls_free(tls);
	cbl_ctx_free(ctx);
	return (0);
}

static int
write_all(int fd, const void *p, size_t len)
{
	ssize_t n;

	while (len > 0) {
		if ((n = write(fd, p, len)) == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		p = (const char *)p + n;
		len -= (size_t)n;
	}
	return (0);
}

/* Copy bytes both ways until either side closes. */
static void
relay_copy(int a, int b)
{
	struct pollfd pfd[2] = {
		{ .fd = a, .events = POLLIN }, { .fd = b, .events = POLLIN },
	};
	char buf[16384];
	ssize_t n;

	for (;;) {
		if (poll(pfd, 2, -1) == -1) {
			if (errno == EINTR)
				continue;
			return;
		}
		for (int i = 0; i < 2; i++) {
			if (pfd[i].revents == 0)
				continue;
			if ((n = read(pfd[i].fd, buf, sizeof(buf))) <= 0 ||
			    write_all(pfd[1 - i].fd, buf, (size_t)n) != 0)
				return;
		}
	}
}

/*
 * relay: what nginx "stream" or HAProxy in mode tcp do in front of a
 * CBL_LF_PROXY listener.  One child per connection.
 */
static int
relay(int argc, char **argv)
{
	unsigned char v2[28] = {
		0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49,
		0x54, 0x0a, 0x21, 0x11, 0x00, 0x0c,
		192, 0, 2, 7, 127, 0, 0, 1, 0x10, 0xe1,
	};
	struct sockaddr_in sin = { .sin_len = sizeof(sin),
	    .sin_family = AF_INET };
	struct sockaddr_in to = sin;
	socklen_t len = sizeof(sin);
	const char *pidfile = NULL;
	unsigned long port = 0;
	char v1[128];
	int ch, lfd, cfd, sfd, readyfd = -1;
	bool version1 = false;

	while ((ch = getopt(argc, argv, "1d:")) != -1) {
		switch (ch) {
		case '1': version1 = true; break;
		case 'd': pidfile = optarg; break;
		default: usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1 || (port = strtoul(argv[0], NULL, 10)) == 0 ||
	    port > 65535)
		usage();
	if (pidfile != NULL)
		readyfd = detach(pidfile);
	sin.sin_addr.s_addr = to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	to.sin_port = htons((in_port_t)port);
	v2[26] = (unsigned char)(port >> 8);
	v2[27] = (unsigned char)port;
	snprintf(v1, sizeof(v1),
	    "PROXY TCP4 192.0.2.7 127.0.0.1 4321 %lu\r\n", port);
	if ((lfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
	    bind(lfd, (struct sockaddr *)&sin, sizeof(sin)) == -1 ||
	    listen(lfd, 16) == -1 ||
	    getsockname(lfd, (struct sockaddr *)&sin, &len) == -1)
		err(1, "relay");
	(void)signal(SIGCHLD, SIG_IGN);		/* no zombies */
	if (readyfd != -1) {
		dprintf(readyfd, "ready %u\n", ntohs(sin.sin_port));
		close(readyfd);
	} else {
		printf("ready %u\n", ntohs(sin.sin_port));
		fflush(stdout);
	}
	for (;;) {
		if ((cfd = accept(lfd, NULL, NULL)) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "accept");
		}
		switch (fork()) {
		case -1:
			err(1, "fork");
		case 0:
			close(lfd);
			if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
			    connect(sfd, (struct sockaddr *)&to,
			    sizeof(to)) == -1)
				_exit(1);
			if (version1 ? write_all(sfd, v1, strlen(v1)) :
			    write_all(sfd, v2, sizeof(v2)))
				_exit(1);
			relay_copy(cfd, sfd);
			_exit(0);
		default:
			close(cfd);
		}
	}
}

int
main(int argc, char **argv)
{

	if (argc < 2)
		usage();
	if (strcmp(argv[1], "serve") == 0)
		return (serve(argc - 1, argv + 1));
	if (strcmp(argv[1], "call") == 0)
		return (call(argc - 1, argv + 1));
	if (strcmp(argv[1], "relay") == 0)
		return (relay(argc - 1, argv + 1));
	usage();
	return (2);
}
