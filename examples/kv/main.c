/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cbl-kv: an in-memory key/value store built from kv.yaml.  It shows a
 * do operation, a dump, an operation that needs an authenticated peer,
 * multicast notifications and a server-to-client stream.
 *
 *	cbl-kv -l [-pt] [-c cert -k key -a ca] uri	serve
 *	cbl-kv [-p] [...] uri get key
 *	cbl-kv [-p] [...] uri set key value		needs authentication
 *	cbl-kv [-p] [...] uri list [prefix]		a dump
 *	cbl-kv [-p] [...] uri changes count		notifications
 *	cbl-kv [-p] [...] uri watch prefix count	a push stream
 *
 * On a unix: socket, -t makes local peers authenticated (filesystem
 * permissions are then the access control).
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cblink.h>

#include "kv.h"

/* The server's state; all of it lives on the loop thread. */
struct entry {
	TAILQ_ENTRY(entry)	 link;
	char			*key;
	void			*value;
	size_t			 len;
	uint32_t		 flags;
};

struct watcher {
	LIST_ENTRY(watcher)	 link;
	cbl_stream		*s;
	char			*prefix;
};

static TAILQ_HEAD(, entry) entries = TAILQ_HEAD_INITIALIZER(entries);
static LIST_HEAD(, watcher) watchers = LIST_HEAD_INITIALIZER(watchers);
static cbl_family *kv_fam;

static bool
has_prefix(const char *key, const char *prefix)
{

	return (prefix == NULL || strncmp(key, prefix, strlen(prefix)) == 0);
}

static struct entry *
lookup(const char *key)
{
	struct entry *e;

	TAILQ_FOREACH(e, &entries, link)
		if (strcmp(e->key, key) == 0)
			return (e);
	return (NULL);
}

int
kv_get_doit(cbl_req *req, const struct kv_get_req *rq, void *arg __unused)
{
	struct kv_get_rsp rsp = { 0 };
	struct entry *e;

	if ((e = lookup(rq->key)) == NULL) {
		(void)cbl_req_set_err(req, "no such key", NULL, 0, -1);
		return (ENOENT);
	}
	rsp.key = e->key;
	rsp.value.p = e->value;
	rsp.value.len = e->len;
	rsp.has_flags = true;
	rsp.flags = e->flags;
	return (kv_get_reply(req, &rsp));
}

/*
 * One item per call; st->pos[0] counts the entries already looked at.
 * EAGAIN asks for another call, 0 ends the dump.
 */
int
kv_get_dumpit(cbl_req *req, const struct kv_get_dump_req *rq,
    struct cbl_dump_state *st, void *arg __unused)
{
	struct kv_get_dump_rsp rsp = { 0 };
	struct entry *e;
	uint64_t i = 0;
	int error;

	TAILQ_FOREACH(e, &entries, link) {
		if (i++ < st->pos[0])
			continue;
		st->pos[0]++;
		if (!has_prefix(e->key, rq->prefix))
			continue;
		rsp.key = e->key;
		if ((e->flags & KV_ENTRY_FLAGS_SECRET) == 0) {
			rsp.value.p = e->value;
			rsp.value.len = e->len;
		}
		rsp.has_flags = true;
		rsp.flags = e->flags;
		if ((error = kv_get_dump_reply(req, &rsp)) != 0)
			return (error);
		return (EAGAIN);
	}
	return (0);
}

/* "auth: true" in kv.yaml: only called for authenticated peers. */
int
kv_set_doit(cbl_req *req __unused, const struct kv_set_req *rq,
    void *arg __unused)
{
	struct kv_changed_ntf ntf = { 0 };
	struct kv_kv item = { 0 };
	struct watcher *w;
	struct entry *e;
	void *v;

	if ((v = malloc(rq->value.len + 1)) == NULL)
		return (ENOMEM);
	memcpy(v, rq->value.p, rq->value.len);
	if ((e = lookup(rq->key)) == NULL) {
		if ((e = calloc(1, sizeof(*e))) == NULL ||
		    (e->key = strdup(rq->key)) == NULL) {
			free(e);
			free(v);
			return (ENOMEM);
		}
		TAILQ_INSERT_TAIL(&entries, e, link);
	}
	free(e->value);
	e->value = v;
	e->len = rq->value.len;
	e->flags = rq->has_flags ? rq->flags : 0;

	/* Everyone subscribed to "changes" hears about it ... */
	ntf.key = e->key;
	ntf.has_flags = true;
	ntf.flags = e->flags;
	(void)kv_changed_notify(kv_fam, &ntf);
	/* ... and watchers of a matching prefix get the new value. */
	item.key = e->key;
	item.value.p = e->value;
	item.value.len = e->len;
	LIST_FOREACH(w, &watchers, link)
		if (has_prefix(e->key, w->prefix))
			(void)kv_watch_server_send(w->s, &item);
	return (0);		/* an empty reply acknowledges */
}

static void
watch_closed(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg)
{
	struct watcher *w = arg;

	LIST_REMOVE(w, link);
	free(w->prefix);
	free(w);
}

static const struct kv_watch_server_cbs watch_cbs = {
	.on_close = watch_closed,
};

/* A watch starts with the current matching entries. */
int
kv_watch_stream_open(cbl_req *req __unused, const struct kv_watch_req *rq,
    cbl_stream *s, void *arg __unused)
{
	struct kv_kv item = { 0 };
	struct watcher *w;
	struct entry *e;
	int error;

	if ((w = calloc(1, sizeof(*w))) == NULL ||
	    (rq->prefix != NULL && (w->prefix = strdup(rq->prefix)) == NULL)) {
		free(w);
		return (ENOMEM);
	}
	w->s = s;
	if ((error = kv_watch_accept(s, &watch_cbs, w)) != 0) {
		free(w->prefix);
		free(w);
		return (error);
	}
	LIST_INSERT_HEAD(&watchers, w, link);
	TAILQ_FOREACH(e, &entries, link) {
		if (!has_prefix(e->key, w->prefix))
			continue;
		item.key = e->key;
		item.value.p = e->value;
		item.value.len = e->len;
		(void)kv_watch_server_send(s, &item);
	}
	return (0);
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
	struct entry *e;
	int error;

	if ((error = kv_register(ctx, NULL, &kv_fam)) != 0)
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
	cbl_loop_free(loop);		/* closes streams: watchers go */
	(void)cbl_family_unregister(kv_fam);
	while ((e = TAILQ_FIRST(&entries)) != NULL) {
		TAILQ_REMOVE(&entries, e, link);
		free(e->key);
		free(e->value);
		free(e);
	}
	return (error);
}

/* Client side. */

struct counter {
	cbl_loop	*loop;
	long		 left;
};

static void
changed(const struct kv_changed_ntf *ntf, void *arg)
{
	struct counter *c = arg;

	printf("changed %s flags=%u\n", ntf->key,
	    ntf->has_flags ? ntf->flags : 0);
	fflush(stdout);
	if (--c->left == 0)
		cbl_loop_stop(c->loop);
}

static void
watch_data(cbl_stream *s, const struct kv_kv *data, void *arg)
{
	struct counter *c = arg;

	printf("%s = %.*s\n", data->key, (int)data->value.len,
	    (const char *)data->value.p);
	fflush(stdout);
	if (--c->left == 0) {
		(void)cbl_stream_close(s, 0, NULL);
		cbl_loop_stop(c->loop);
	}
}

static void
watch_open(cbl_stream *s __unused, int error, void *arg)
{
	struct counter *c = arg;

	if (error != 0) {
		warnc(error, "watch");
		cbl_loop_stop(c->loop);
	}
}

static const struct kv_watch_cbs watch_client_cbs = {
	.on_open = watch_open,
	.on_data = watch_data,
};

/* Notifications and streams need the connection on an event loop. */
static int
listen_for(cbl_ctx *ctx, struct kv_client *cl, const char *what,
    const char *prefix, long count)
{
	struct kv_changes_handlers h = { .changed = changed };
	struct kv_watch_req wr = { .prefix = prefix };
	struct counter c = { .left = count };
	cbl_stream *s;
	cbl_sub *sub = NULL;
	int error;

	if ((error = cbl_loop_new(ctx, &c.loop)) != 0)
		errc(1, error, "loop");
	if (strcmp(what, "changes") == 0)
		error = kv_changes_subscribe(cl, &h, &c, &sub);
	else
		error = kv_watch_open(cl, &wr, &watch_client_cbs, &c, &s);
	if (error != 0)
		errc(1, error, "%s", what);
	printf("ready\n");
	fflush(stdout);
	if ((error = cbl_conn_attach(cl->conn, c.loop)) != 0)
		errc(1, error, "attach");
	error = cbl_loop_run(c.loop);
	cbl_loop_free(c.loop);
	return (error);
}

static int
client(cbl_ctx *ctx, const char *uri, uint32_t flags, cbl_tls *tls,
    int argc, char **argv)
{
	struct kv_get_dump_rsp *item;
	struct kv_get_rsp *rsp;
	struct kv_client cl;
	cbl_conn *conn;
	cbl_dump *d;
	int error;

	if ((error = cbl_conn_new(ctx, uri, flags, &conn)) != 0)
		errc(1, error, "%s", uri);
	if (tls != NULL)
		(void)cbl_conn_set_tls(conn, tls);
	if ((error = cbl_conn_connect(conn)) != 0)
		errx(1, "%s: %s", uri, cbl_conn_errstr(conn));
	if ((error = kv_client_init(&cl, conn)) != 0)
		errc(1, error, "kv family");

	if (strcmp(argv[0], "get") == 0 && argc == 2) {
		struct kv_get_req req = { .key = argv[1] };

		if ((error = kv_get(&cl, &req, &rsp)) == 0) {
			printf("%s = %.*s\n", rsp->key, (int)rsp->value.len,
			    (const char *)rsp->value.p);
			kv_get_rsp_free(rsp);
		}
	} else if (strcmp(argv[0], "set") == 0 && argc == 3) {
		struct kv_set_req req = { .key = argv[1] };

		req.value.p = argv[2];
		req.value.len = strlen(argv[2]);
		error = kv_set(&cl, &req);
	} else if (strcmp(argv[0], "list") == 0 && argc <= 2) {
		struct kv_get_dump_req req = {
			.prefix = argc == 2 ? argv[1] : NULL };

		/* Each item lives until the next call. */
		if ((error = kv_get_dump(&cl, &req, &d)) == 0) {
			while ((error = kv_get_dump_next(d, &item)) == 0 &&
			    item != NULL) {
				printf("%s = %.*s\n", item->key,
				    (int)item->value.len,
				    (const char *)item->value.p);
			}
			cbl_dump_free(d);
		}
	} else if (strcmp(argv[0], "changes") == 0 && argc == 2)
		error = listen_for(ctx, &cl, "changes", NULL,
		    strtol(argv[1], NULL, 10));
	else if (strcmp(argv[0], "watch") == 0 && argc == 3)
		error = listen_for(ctx, &cl, "watch", argv[1],
		    strtol(argv[2], NULL, 10));
	else
		errx(2, "unknown command or wrong arguments: %s", argv[0]);
	if (error != 0)
		errx(1, "%s: %s", argv[0], cl.err != NULL &&
		    cbl_msg_err_str(cl.err) != NULL ?
		    cbl_msg_err_str(cl.err) : strerror(error));
	kv_client_fini(&cl);
	cbl_conn_free(conn);
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
usage(void)
{

	fprintf(stderr,
	    "usage: cbl-kv -l [-pt] [-c cert -k key -a ca] uri\n"
	    "       cbl-kv [-p] [-c cert -k key -a ca] uri command ...\n"
	    "commands: get key | set key value | list [prefix] |\n"
	    "          changes count | watch prefix count\n");
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
