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
#include "schema.h"
#include "sid.h"
#include "yang.h"

static void
count_node(struct snode *n __unused, void *arg)
{

	(*(size_t *)arg)++;
}
#endif

#define	DEFAULT_PARTS	"h,c,client,server,md"

static void
usage(void)
{

	fprintf(stderr, "usage: cblink-gen [-BnV] [-b base] [-m parts] "
	    "[-o dir] spec.yaml\n"
	    "       cblink-gen -n | -d [-F module:feature,...] ... "
	    "[-p dir] ... [-s file.sid] ...\n"
	    "                  module.yang ...\n");
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
/*
 * YANG modules: those they may import are read, from -p and from their
 * own directories, before capability mode.  -n says what was compiled,
 * -d dumps the generator's model of it a node a line.
 */
static int
yang_main(int argc, char *argv[], const char **paths, size_t npaths,
    const char **feats, size_t nfeats, const char **sids, size_t nsids,
    bool check, bool dump)
{
	struct diags d = { 0 };
	char *sidtext[16];
	size_t sidlen[16], nattached = 0;
	struct schema *s;
	struct ly_ctx *ctx;
	char *pathcopy;
	size_t nodes = 0, nmods = 0, nexprs;
	int fd;

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
	/* .sid files, read now, attached once the schema is made. */
	for (size_t i = 0; i < nsids; i++) {
		if ((fd = open(sids[i], O_RDONLY | O_CLOEXEC)) == -1)
			err(2, "%s", sids[i]);
		sidtext[i] = read_file(fd, sids[i], &sidlen[i]);
		close(fd);
	}
	ctx = yang_ctx_new(dirs, ndirs);

	caph_cache_catpages();
	if (caph_limit_stdio() != 0 || caph_enter() != 0)
		err(2, "capsicum");

	if (yang_load(ctx, &d, feats, nfeats) != 0) {
		diag_print(&d);
		return (1);
	}
	s = yang_schema(ctx);
	for (size_t i = 0; i < nsids; i++) {
		struct sidfile *sf;

		pathcopy = xstrdup(sids[i]);
		d.file = basename(pathcopy);
		if ((sf = sid_read(sidtext[i], sidlen[i], &d)) != NULL) {
			if (sid_attach(s, sf, &d) == 0)
				nattached += sf->nitems;
			sid_free(sf);
		}
		free(sidtext[i]);
		if (d.n > 0) {
			diag_print(&d);
			return (1);
		}
		free(pathcopy);
	}
	d.file = argc == 1 ? basename(argv[0]) : "the modules";
	nexprs = schema_check_xpath(s, &d);
	if (d.n > 0) {
		diag_print(&d);
		schema_free(s);
		return (1);
	}
	if (dump)
		schema_dump(s);
	else if (check) {
		for (size_t i = 0; i < s->nmods; i++)
			nmods += s->mods[i]->implemented;
		schema_walk(s, count_node, &nodes);
		printf("%s: compiled, %zu modules implemented, %zu schema "
		    "nodes, %zu XPath expressions", d.file, nmods, nodes,
		    nexprs);
		if (nsids > 0)
			printf(", %zu SIDs from %zu .sid files", nattached,
			    nsids);
		printf("\n");
	} else
		errx(2, "generating C from YANG is not written yet; -n "
		    "checks the modules, -d dumps them");
	schema_free(s);
	diag_free(&d);
	return (0);
}
#else
static int
yang_main(int argc __unused, char *argv[], const char **paths __unused,
    size_t npaths __unused, const char **feats __unused,
    size_t nfeats __unused, const char **sids __unused,
    size_t nsids __unused, bool check __unused, bool dump __unused)
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
	bool builtin = false, check = false, dump = false;
	char *data, *pathcopy, *file, *dot, *bname = NULL;
	const char *paths[16], *feats[64], *sids[16];
	size_t len, npaths = 0, nfeats = 0, nsids = 0;
	int ch, fd, dirfd, rv;

	while ((ch = getopt(argc, argv, "Bb:dF:m:no:p:s:V")) != -1) {
		switch (ch) {
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
		    sids, nsids, check, dump));
	if (argc != 1 || dump || nfeats > 0 || nsids > 0)
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
