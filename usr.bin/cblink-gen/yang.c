/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The YANG front end: libyang 3 parses and compiles the modules (Arcana's
 * PLAN-SDN-YANG, decision D-3).  cblink-gen reads untrusted input in
 * capability mode, where libyang cannot open the files a module imports,
 * so every module the generator may need is read into memory first, from
 * the search directories, and libyang is given them through its import
 * callback; the context is made before capability mode too, while
 * libyang can still load its plugins.
 */

#include <sys/stat.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "gen.h"
#include "yang.h"

/* A module's text, by the name and revision its file name gives. */
struct ysrc {
	char	*name;
	char	*rev;		/* NULL: the file name has none */
	char	*text;
};

static struct ysrc	*srcs;
static size_t		 nsrcs;
static struct diags	*logto;		/* libyang's messages, while parsing */

static char *
read_all(int fd, const char *path)
{
	struct stat sb;
	size_t len = 0;
	ssize_t n;
	char *data;

	if (fstat(fd, &sb) != 0)
		err(2, "%s", path);
	if (!S_ISREG(sb.st_mode))
		errx(2, "%s: not a regular file", path);
	if (sb.st_size > YANG_MAX_FILE)
		errx(1, "%s: file too large (limit %d bytes)", path,
		    YANG_MAX_FILE);
	data = xcalloc((size_t)sb.st_size + 1, 1);
	while (len < (size_t)sb.st_size &&
	    (n = read(fd, data + len, (size_t)sb.st_size - len)) > 0)
		len += (size_t)n;
	if (len != (size_t)sb.st_size)
		errx(2, "%s: short read", path);
	return (data);
}

/* "name@rev.yang" or "name.yang"; anything else is not a module file. */
static bool
split_name(const char *file, char **namep, char **revp)
{
	const char *at, *dot;

	if ((dot = strrchr(file, '.')) == NULL || strcmp(dot, ".yang") != 0 ||
	    dot == file)
		return (false);
	if ((at = memchr(file, '@', (size_t)(dot - file))) != NULL) {
		*namep = xstrndup(file, (size_t)(at - file));
		*revp = xstrndup(at + 1, (size_t)(dot - at - 1));
	} else {
		*namep = xstrndup(file, (size_t)(dot - file));
		*revp = NULL;
	}
	return (true);
}

void
yang_add_file(int fd, const char *path)
{
	const char *file;
	struct ysrc *s;
	char *name, *rev;

	file = (file = strrchr(path, '/')) != NULL ? file + 1 : path;
	if (!split_name(file, &name, &rev))
		errx(2, "%s: not a YANG module file (name.yang or "
		    "name@revision.yang)", path);
	srcs = xreallocarray(srcs, nsrcs + 1, sizeof(*srcs));
	s = &srcs[nsrcs++];
	s->name = name;
	s->rev = rev;
	s->text = read_all(fd, path);
}

void
yang_add_dir(const char *dir)
{
	struct dirent *de;
	DIR *d;
	char *path, *name, *rev;
	int fd;

	if ((d = opendir(dir)) == NULL)
		err(2, "%s", dir);
	while ((de = readdir(d)) != NULL) {
		if (!split_name(de->d_name, &name, &rev))
			continue;
		free(name);
		free(rev);
		path = xasprintf("%s/%s", dir, de->d_name);
		if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
			err(2, "%s", path);
		yang_add_file(fd, path);
		close(fd);
		free(path);
	}
	closedir(d);
}

/* The text of a module: the revision asked for, or the latest. */
static const char *
find(const char *name, const char *rev)
{
	const struct ysrc *best = NULL;

	for (size_t i = 0; i < nsrcs; i++) {
		if (strcmp(srcs[i].name, name) != 0)
			continue;
		if (rev != NULL) {
			if (srcs[i].rev != NULL && strcmp(srcs[i].rev, rev) == 0)
				return (srcs[i].text);
			continue;
		}
		if (best == NULL || (srcs[i].rev != NULL && (best->rev == NULL ||
		    strcmp(srcs[i].rev, best->rev) > 0)))
			best = &srcs[i];
	}
	return (best != NULL ? best->text : NULL);
}

static LY_ERR
imp(const char *mod, const char *mod_rev, const char *sub,
    const char *sub_rev, void *arg __unused, LYS_INFORMAT *format,
    const char **data, ly_module_imp_data_free_clb *free_data)
{
	const char *text;

	text = sub != NULL ? find(sub, sub_rev) : find(mod, mod_rev);
	if (text == NULL)
		return (LY_ENOTFOUND);
	*format = LYS_IN_YANG;
	*data = text;
	*free_data = NULL;
	return (LY_SUCCESS);
}

static void
log_clb(LY_LOG_LEVEL level, const char *msg, const char *data_path __unused,
    const char *schema_path, uint64_t line)
{

	if (logto == NULL || level != LY_LLERR)
		return;
	if (schema_path != NULL)
		diag_add(logto, (int)line, 0, "%s (%s)", msg, schema_path);
	else
		diag_add(logto, (int)line, 0, "%s", msg);
}

struct ly_ctx *
yang_ctx_new(void)
{
	struct ly_ctx *ctx;

	ly_set_log_clb(log_clb);
	if (ly_ctx_new(NULL, LY_CTX_DISABLE_SEARCHDIRS | LY_CTX_REF_IMPLEMENTED,
	    &ctx) != LY_SUCCESS)
		errx(2, "libyang: cannot make a context");
	ly_ctx_set_module_imp_clb(ctx, imp, NULL);
	return (ctx);
}

static LY_ERR
count(struct lysc_node *n __unused, void *arg, ly_bool *cont __unused)
{

	(*(size_t *)arg)++;
	return (LY_SUCCESS);
}

/*
 * Parse and compile the first module added; its imports come from the
 * others.  Under -n, say what was compiled.
 */
int
yang_load(struct ly_ctx *ctx, struct diags *d, bool verbose)
{
	const struct lys_module *m;
	struct lys_module *mod;
	size_t nodes = 0, nmods = 0;
	uint32_t i = 0;
	LY_ERR e;

	if (nsrcs == 0)
		return (-1);
	logto = d;
	e = lys_parse_mem(ctx, srcs[0].text, LYS_IN_YANG, &mod);
	logto = NULL;
	if (e != LY_SUCCESS) {
		if (d->n == 0)
			diag_add(d, 0, 0, "libyang: the module does not compile");
		return (-1);
	}
	while ((m = ly_ctx_get_module_iter(ctx, &i)) != NULL)
		if (m->implemented && m->compiled != NULL) {
			nmods++;
			(void)lysc_module_dfs_full(m, count, &nodes);
		}
	if (verbose)
		printf("%s: %s@%s compiled, %zu modules implemented, %zu schema "
		    "nodes\n", d->file, mod->name, mod->revision != NULL ?
		    mod->revision : "-", nmods, nodes);
	return (0);
}
