/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the YANG parts of the library share and do not export: the
 * codec's reading of a struct, the validator's parsing of a default,
 * for the instance tree (cbl_data.c).
 */

#ifndef _CBL_YIMPL_H_
#define	_CBL_YIMPL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cbl_schema.h"

/* Whether child n has a value in struct p (its case's, if in a choice). */
bool	cbl_ypresent(const struct cbl_ynode *n, const void *p);
/* n's case, and its choices', set in struct p; EINVAL: another's is. */
int	cbl_yset_case(const struct cbl_ynode *n, void *p);
/* Leaf or leaf-list n's k-th default into out, as its member is. */
int	cbl_ydefault_parse(const struct cbl_ynode *n, uint16_t k, void *out,
	    cbl_yarena *a);



/* Family 1's, for cbl_ysub.c: a node of a served module, its server,
 * handlers and node; whether n is a top-level data node; an error said
 * for a request; the nodes v read into a tree; a notification's
 * envelope put; a CBOR integer's head. */
struct cbl_yfound {
	const struct cbl_yserver	*srv;
	void				*arg;
	const struct cbl_ynode		*n;
	const struct cbl_yhandler	*h;	/* NULL: none */
};

struct cbl_dtree;
bool	cbl_yfind(cbl_ctx *ctx, uint64_t sid, struct cbl_yfound *f);
bool	cbl_yis_top_data(const struct cbl_ynode *n);
int	cbl_ysay(cbl_req *req, int error, uint64_t sid, const char *tag,
	    const char *text);
int	cbl_yread_tree(cbl_req *req, const uint64_t *v, size_t n,
	    struct cbl_dtree **tp, bool *incomplete);
int	cbl_ynotif_put(cbl_msg *msg, uint64_t sid, const uint8_t *content,
	    size_t len);
struct timespec;
int	cbl_ynotif_put_at(cbl_msg *msg, uint64_t sid, const uint8_t *content,
	    size_t len, const struct timespec *when);
size_t	cbl_ycbor_int(uint8_t *p, int64_t v);
/* The codec's: the length of the CBOR item at p, 0 where it is none. */
size_t	cbl_ycbor_skip(const uint8_t *p, const uint8_t *end);

/* cbl_ysub.c: SUBSCRIBE's open; an event to the NETCONF stream's
 * subscriptions. */
int	cbl_ysub_open(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
	    void *arg);
void	cbl_ysub_event(cbl_ctx *ctx, const struct cbl_ynode *n,
	    const uint8_t *content, size_t len);

#endif /* !_CBL_YIMPL_H_ */
