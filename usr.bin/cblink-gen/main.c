/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cblink-gen: generate C code and documentation from a cblink family
 * spec.  See cblink-gen(1) and docs/GENERATOR.md.  A YANG module
 * (name.yang or name@revision.yang) is read through libyang when the
 * generator is built with it (CBLINK_GEN_LIBYANG).
 */

#include <sys/capsicum.h>
#include <sys/stat.h>

#include <capsicum_helpers.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "spec.h"
#ifdef CBLINK_GEN_LIBYANG
#include "cbl_pattern.h"
#include "schema.h"
#include "sid.h"
#include "yang.h"

static void
count_node(struct snode *n __unused, void *arg)
{

	(*(size_t *)arg)++;
}

/* The tree diagrams or the Markdown, as base.tree or base.md. */
static int
doc_emit(const struct schema *s, int dirfd, const char *base,
    const char *from, bool md)
{
	struct buf b;
	char *name;
	int rv;

	buf_init(&b);
	if (md)
		gen_yang_md(s, from, &b);
	else
		gen_yang_tree(s, &b);
	name = xasprintf("%s.%s", base, md ? "md" : "tree");
	rv = write_file(dirfd, name, &b);
	free(name);
	buf_free(&b);
	return (rv);
}
#endif

#define	DEFAULT_PARTS	"h,c,client,server,md"
/* .sid files: one a module, a module set's modules. */
#define	MAX_SIDS	256

static void
usage(void)
{

	fprintf(stderr, "usage: cblink-gen [-BnV] [-b base] [-m parts] "
	    "[-o dir] spec.yaml\n"
	    "       cblink-gen [-adn] [-F module:feature,...] ... "
	    "[-b base] [-m h,md,sid,sidjson,tree]\n"
	    "                  [-o dir] [-p dir] ... [-s file.sid] ... "
	    "module.yang ...\n");
	exit(2);
}

/* Read the whole file, refusing anything larger than the YAML limit. */
static char *
read_file(int fd, const char *path, size_t *lenp)
{
	struct stat sb;
	size_t cap, len = 0;
	ssize_t n;
	char *data;

	if (fstat(fd, &sb) != 0)
		err(2, "%s", path);
	if (!S_ISREG(sb.st_mode))
		errx(2, "%s: not a regular file", path);
	if (sb.st_size > YAML_MAX_FILE)
		errx(1, "%s: file too large (limit %d bytes)", path,
		    YAML_MAX_FILE);
	cap = (size_t)sb.st_size + 1;
	data = xcalloc(cap + 1, 1);
	while ((n = read(fd, data + len, cap - len)) > 0) {
		len += (size_t)n;
		if (len > YAML_MAX_FILE)
			errx(1, "%s: file too large (limit %d bytes)", path,
			    YAML_MAX_FILE);
		if (len == cap) {
			data = xreallocarray(data, cap * 2 + 1, 1);
			cap *= 2;
		}
	}
	if (n < 0)
		err(2, "%s", path);
	*lenp = len;
	return (data);
}

#ifdef CBLINK_GEN_LIBYANG
/* A .sid file as asked: name@revision.sid, and .sid.cbor its CBOR. */
static int
sid_emit(const struct sidfile *sf, int dirfd, bool cbor, bool json)
{
	struct buf b;
	char *name;
	int rv = 0;

	name = sf->revision != NULL ? xasprintf("%s@%s.sid", sf->module,
	    sf->revision) : xasprintf("%s.sid", sf->module);
	if (strchr(name, '/') != NULL || name[0] == '.')
		errx(2, "%s: not a file name", name);
	if (json) {
		buf_init(&b);
		sid_write(sf, &b);
		rv |= write_file(dirfd, name, &b);
		buf_free(&b);
	}
	if (cbor) {
		char *cname = xasprintf("%s.cbor", name);

		buf_init(&b);
		sid_write_cbor(sf, &b);
		rv |= write_file(dirfd, cname, &b);
		buf_free(&b);
		free(cname);
	}
	free(name);
	return (rv);
}

/*
 * YANG modules: those they may import are read, from -p and from their
 * own directories, before capability mode.  -n says what was compiled,
 * -d dumps the generator's model of it a node a line.
 */
static int
yang_main(int argc, char *argv[], const char **paths, size_t npaths,
    const char **feats, size_t nfeats, const char **sids, size_t nsids,
    const char *parts, const char *outdir, const char *base, bool assign,
    bool check, bool dump)
{
	bool cbor = false, json = false, hdr = false, md = false, tree = false;
	bool tables = false, server = false;
	char *bname = NULL;
	int dirfd = -1;
	cap_rights_t rights;
	int sidfd[MAX_SIDS];
	struct diags d = { 0 };
	char *sidtext[MAX_SIDS];
	size_t sidlen[MAX_SIDS], nattached = 0;
	struct schema *s, *sall;
	struct ly_ctx *ctx, *ctxall = NULL;
	char *pathcopy;
	size_t nodes = 0, nmods = 0, nexprs, npats;
	int fd, nassigned;

	const char **dirs;
	size_t ndirs = 0;

	dirs = xcalloc(npaths + (size_t)argc, sizeof(*dirs));
	for (int i = 0; i < argc; i++) {
		if ((fd = open(argv[i], O_RDONLY | O_CLOEXEC)) == -1)
			err(2, "%s", argv[i]);
		yang_add_file(fd, argv[i], true);
		close(fd);
		pathcopy = xstrdup(argv[i]);
		dirs[ndirs] = xstrdup(dirname(pathcopy));
		free(pathcopy);
		yang_add_dir(dirs[ndirs++]);
	}
	for (size_t i = 0; i < npaths; i++) {
		yang_add_dir(paths[i]);
		dirs[ndirs++] = xstrdup(paths[i]);
	}
	/*
	 * .sid files, read now, attached once the schema is made; with -a
	 * kept open to be rewritten with the SIDs given.
	 */
	for (size_t i = 0; i < nsids; i++) {
		if ((fd = open(sids[i], (assign ? O_RDWR : O_RDONLY) |
		    O_CLOEXEC)) == -1)
			err(2, "%s", sids[i]);
		sidtext[i] = read_file(fd, sids[i], &sidlen[i]);
		if (!assign) {
			close(fd);
			continue;
		}
		cap_rights_init(&rights, CAP_PWRITE, CAP_FTRUNCATE);
		if (caph_rights_limit(fd, &rights) != 0)
			err(2, "%s", sids[i]);
		sidfd[i] = fd;
	}
	ctx = yang_ctx_new(dirs, ndirs);
	/*
	 * A .sid file numbers every item of its module, whatever features a
	 * program enables (RFC 9595): with -F, the files are read against
	 * the modules again, every feature on, and only attached to what -F
	 * leaves.
	 */
	if (nsids > 0 && nfeats > 0)
		ctxall = yang_ctx_new(dirs, ndirs);

	/*
	 * The parts written yet: "h", the structs; "md", the modules'
	 * Markdown; "sid", the .sid files' YANG-CBOR form as GET-SID
	 * answers it; "sidjson", their JSON; "tree", the modules' tree
	 * diagrams; "schema", the tables the library decodes by.
	 */
	if (!check && !dump) {
		for (const char *p = parts; *p != '\0';) {
			size_t n = strcspn(p, ",");

			if (n == 1 && *p == 'h')
				hdr = true;
			else if (n == 3 && strncmp(p, "sid", 3) == 0)
				cbor = true;
			else if (n == 7 && strncmp(p, "sidjson", 7) == 0)
				json = true;
			else if (n == 4 && strncmp(p, "tree", 4) == 0)
				tree = true;
			else if (n == 2 && strncmp(p, "md", 2) == 0)
				md = true;
			else if (n == 6 && strncmp(p, "schema", 6) == 0)
				tables = true;
			else if (n == 6 && strncmp(p, "server", 6) == 0)
				server = true;
			else
				errx(2, "-m %.*s: not written for YANG yet; "
				    "-m h,md,schema,server,sid,sidjson,tree are",
				    (int)n, p);
			p += n + (p[n] == ',');
		}
		if (!cbor && !json && !hdr && !md && !tree && !tables &&
		    !server)
			errx(2, "generating C from YANG is not written yet "
			    "but for -m h,md,schema,server,sid,sidjson,tree; -n "
			    "checks the modules, -d dumps them");
		if ((cbor || json) && nsids == 0)
			errx(2, "-m sid,sidjson: no -s file");
		/* The outputs' name: -b, or the first module's. */
		if (base == NULL) {
			pathcopy = xstrdup(argv[0]);
			bname = xstrdup(basename(pathcopy));
			free(pathcopy);
			bname[strcspn(bname, "@")] = '\0';
			if (strlen(bname) > 5 && strcmp(bname +
			    strlen(bname) - 5, ".yang") == 0)
				bname[strlen(bname) - 5] = '\0';
			base = bname;
		}
		if (*base == '\0' || strchr(base, '/') != NULL)
			errx(2, "invalid output base name '%s'", base);
		if ((dirfd = open(outdir, O_DIRECTORY | O_SEARCH |
		    O_CLOEXEC)) == -1)
			err(2, "%s", outdir);
	}
	/* Patterns are compiled in C.UTF-8, which cannot be loaded later. */
	if (cbl_pattern_init() != 0)
		errx(2, "no C.UTF-8 locale for the patterns");

	caph_cache_catpages();
	if (caph_limit_stdio() != 0 || caph_enter() != 0)
		err(2, "capsicum");

	if (yang_load(ctx, &d, feats, nfeats) != 0 ||
	    (ctxall != NULL && yang_load(ctxall, &d, NULL, 0) != 0)) {
		diag_print(&d);
		return (1);
	}
	s = yang_schema(ctx);
	sall = ctxall != NULL ? yang_schema(ctxall) : s;
	for (size_t i = 0; i < nsids; i++) {
		struct sidfile *sf;

		pathcopy = xstrdup(sids[i]);
		d.file = basename(pathcopy);
		if ((sf = sid_read(sidtext[i], sidlen[i], &d)) != NULL) {
			if (sid_attach(sall, sf, &d, false) == 0 && assign &&
			    (nassigned = sid_assign(sall, sf, &d)) > 0 &&
			    sid_attach(sall, sf, &d, false) == 0) {
				struct buf b;

				buf_init(&b);
				sid_write(sf, &b);
				if (ftruncate(sidfd[i], 0) != 0 ||
				    pwrite(sidfd[i], b.p, b.len, 0) !=
				    (ssize_t)b.len)
					err(2, "%s", sids[i]);
				buf_free(&b);
				printf("%s: %d SIDs assigned, version %u\n",
				    d.file, nassigned, sf->version);
			}
			if (d.n == 0 && sid_verify(sall, sf, &d) == 0)
				nattached += sf->nitems;
			if (d.n == 0 && sall != s)
				sid_attach(s, sf, &d, true);
			if (d.n == 0 && (cbor || json) &&
			    sid_emit(sf, dirfd, cbor, json) != 0)
				return (2);
			sid_free(sf);
		}
		if (assign)
			close(sidfd[i]);
		free(sidtext[i]);
		if (d.n > 0) {
			diag_print(&d);
			return (1);
		}
		free(pathcopy);
	}
	if (sall != s)
		schema_free(sall);
	d.file = argc == 1 ? basename(argv[0]) : "the modules";
	nexprs = schema_check_profile(s, &d, &npats);
	if (d.n > 0) {
		diag_print(&d);
		schema_free(s);
		return (1);
	}
	if (dump)
		schema_dump(s);
	else if (!check) {
		if (hdr) {
			struct buf b;
			char *name = xasprintf("%s.h", base);

			buf_init(&b);
			if (gen_yang_h(s, base, d.file, &b, &d) != 0) {
				diag_print(&d);
				return (1);
			}
			if (write_file(dirfd, name, &b) != 0)
				return (2);
			buf_free(&b);
			free(name);
		}
		if (tables) {
			struct buf b;
			char *name = xasprintf("%s_schema.c", base);

			buf_init(&b);
			if (gen_yang_schema(s, base, d.file, &b, stdout,
			    &d) != 0) {
				diag_print(&d);
				return (1);
			}
			if (write_file(dirfd, name, &b) != 0)
				return (2);
			buf_free(&b);
			free(name);
		}
		if (server) {
			struct buf b;
			char *name = xasprintf("%s_server.c", base);

			buf_init(&b);
			if (gen_yang_server(s, base, d.file, &b, &d) != 0) {
				diag_print(&d);
				return (1);
			}
			if (write_file(dirfd, name, &b) != 0)
				return (2);
			buf_free(&b);
			free(name);
		}
		if ((tree && doc_emit(s, dirfd, base, d.file, false) != 0) ||
		    (md && doc_emit(s, dirfd, base, d.file, true) != 0))
			return (2);
	} else {
		for (size_t i = 0; i < s->nmods; i++)
			nmods += s->mods[i]->implemented;
		schema_walk(s, count_node, &nodes);
		printf("%s: compiled, %zu modules implemented, %zu schema "
		    "nodes, %zu XPath expressions, %zu patterns", d.file, nmods,
		    nodes, nexprs, npats);
		if (nsids > 0)
			printf(", %zu SIDs from %zu .sid files", nattached,
			    nsids);
		printf("\n");
	}
	schema_free(s);
	diag_free(&d);
	free(bname);
	return (0);
}
#else
static int
yang_main(int argc __unused, char *argv[], const char **paths __unused,
    size_t npaths __unused, const char **feats __unused,
    size_t nfeats __unused, const char **sids __unused,
    size_t nsids __unused, const char *parts __unused,
    const char *outdir __unused, const char *base __unused,
    bool assign __unused, bool check __unused, bool dump __unused)
{

	errx(2, "%s: YANG input needs cblink-gen built with libyang "
	    "(CBLINK_GEN_LIBYANG=yes, net/libyang3)", argv[0]);
}
#endif

int
main(int argc, char *argv[])
{
	const char *outdir = ".", *parts = DEFAULT_PARTS, *base = NULL;
	struct diags d = { 0 };
	struct ynode *root;
	struct spec *s;
	bool assign = false, builtin = false, check = false, dump = false;
	bool mflag = false;
	char *data, *pathcopy, *file, *dot, *bname = NULL;
	const char *paths[16], *feats[64], *sids[MAX_SIDS];
	size_t len, npaths = 0, nfeats = 0, nsids = 0;
	int ch, fd, dirfd, rv;

	while ((ch = getopt(argc, argv, "aBb:dF:m:no:p:s:V")) != -1) {
		switch (ch) {
		case 'a':
			assign = true;
			break;
		case 'B':
			builtin = true;
			break;
		case 'b':
			base = optarg;
			break;
		case 'd':
			dump = true;
			break;
		case 'F':
			if (nfeats == nitems(feats))
				errx(2, "too many -F specs");
			feats[nfeats++] = optarg;
			break;
		case 'm':
			parts = optarg;
			mflag = true;
			break;
		case 'n':
			check = true;
			break;
		case 'o':
			outdir = optarg;
			break;
		case 's':
			if (nsids == nitems(sids))
				errx(2, "too many -s files");
			sids[nsids++] = optarg;
			break;
		case 'p':
			if (npaths == nitems(paths))
				errx(2, "too many -p directories");
			paths[npaths++] = optarg;
			break;
		case 'V':
			printf("cblink-gen %s\n", CBLGEN_VERSION);
			return (0);
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc >= 1 && (dot = strrchr(argv[0], '.')) != NULL &&
	    strcmp(dot, ".yang") == 0)
		return (yang_main(argc, argv, paths, npaths, feats, nfeats,
		    sids, nsids, mflag ? parts : "", outdir, base, assign,
		    check, dump));
	if (argc != 1 || assign || dump || nfeats > 0 || nsids > 0)
		usage();

	if ((fd = open(argv[0], O_RDONLY | O_CLOEXEC)) == -1)
		err(2, "%s", argv[0]);
	dirfd = -1;
	if (!check && (dirfd = open(outdir, O_DIRECTORY | O_SEARCH |
	    O_CLOEXEC)) == -1)
		err(2, "%s", outdir);
	pathcopy = xstrdup(argv[0]);
	file = xstrdup(basename(pathcopy));
	free(pathcopy);
	if (base == NULL) {
		bname = xstrdup(file);
		if ((dot = strrchr(bname, '.')) != NULL &&
		    strcmp(dot, ".yaml") == 0)
			*dot = '\0';
		base = bname;
	}
	if (*base == '\0' || strchr(base, '/') != NULL)
		errx(2, "invalid output base name '%s'", base);

	/* The spec is untrusted input: parse it in capability mode. */
	caph_cache_catpages();
	if (caph_limit_stdio() != 0 || caph_enter() != 0)
		err(2, "capsicum");

	data = read_file(fd, argv[0], &len);
	close(fd);
	d.file = file;
	root = yaml_parse(data, len, &d);
	free(data);
	if (root == NULL) {
		diag_print(&d);
		return (1);
	}
	s = spec_load(root, file, builtin, &d);
	yaml_free(root);
	if (s == NULL) {
		diag_print(&d);
		return (1);
	}
	rv = check ? 0 : gen_c(s, base, dirfd, parts) != 0 ? 2 : 0;
	spec_free(s);
	diag_free(&d);
	free(file);
	free(bname);
	return (rv);
}
