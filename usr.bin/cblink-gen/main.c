/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cblink-gen: generate C code and documentation from a cblink family
 * spec.  See cblink-gen(1) and docs/GENERATOR.md.
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

#define	DEFAULT_PARTS	"h,c,client,server,md"

static void
usage(void)
{

	fprintf(stderr, "usage: cblink-gen [-BnV] [-b base] [-m parts] "
	    "[-o dir] spec.yaml\n");
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

int
main(int argc, char *argv[])
{
	const char *outdir = ".", *parts = DEFAULT_PARTS, *base = NULL;
	struct diags d = { 0 };
	struct ynode *root;
	struct spec *s;
	bool builtin = false, check = false;
	char *data, *pathcopy, *file, *dot, *bname = NULL;
	size_t len;
	int ch, fd, dirfd, rv;

	while ((ch = getopt(argc, argv, "Bb:m:no:V")) != -1) {
		switch (ch) {
		case 'B':
			builtin = true;
			break;
		case 'b':
			base = optarg;
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
		case 'V':
			printf("cblink-gen %s\n", CBLGEN_VERSION);
			return (0);
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
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
