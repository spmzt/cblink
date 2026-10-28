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
/* A handler's failure said for req; a value a node's EDIT puts, valid. */
int	cbl_yfailed(cbl_req *req, int error, uint64_t sid, const char *what);
int	cbl_yvalid_member(cbl_req *req, const struct cbl_ynode *n,
	    const void *parent);
/* cbl_yds.c, family 1's datastores: which a request names; a GET and an
 * EDIT of one; ietf-netconf's commit, cancel-commit, discard-changes
 * (handled: whether it was one). */
int	cbl_yds_of(cbl_req *req, enum cbl_yds_name *ds, bool *said);
int	cbl_yds_get(cbl_req *req, cbl_msg *reply, const uint64_t *v, size_t n,
	    const char *xpath, enum cbl_yds_name ds);
int	cbl_yds_edit(cbl_req *req, const cbl_msg *msg);
bool	cbl_yds_running_locked(cbl_req *req);
int	cbl_yds_rpc(cbl_req *req, const cbl_msg *msg, const struct cbl_ynode *n,
	    bool *handled);
int	cbl_yds_put_warnings(cbl_req *req, cbl_msg *reply);
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

/*
 * cbl_ynacm.c, NACM over family 1: who is asked about, a request's or a
 * subscription's.  An rpc's or an action's exec (EACCES, said for req,
 * where it is denied); a read of tree t, what who may not read taken out
 * of it; an EDIT of top-level node n from before to after (EACCES, said
 * for req, at the first node it may not change); whether a notification
 * of n may be sent to who.  conn: one of the context's, for a read of
 * the rules (NULL: none).
 */
struct cbl_ywho {
	const char	*user;
	bool		 recovery;
};

int	cbl_ynacm_exec(cbl_req *req, const struct cbl_ynode *n);
int	cbl_ynacm_read(cbl_ctx *ctx, cbl_conn *conn, const struct cbl_ywho *who,
	    struct cbl_dtree *t);
bool	cbl_ynacm_reads_all(cbl_ctx *ctx, cbl_conn *conn,
	    const struct cbl_ywho *who);
int	cbl_ynacm_write(cbl_req *req, const struct cbl_ynode *n,
	    const void *before, const void *after);
bool	cbl_ynacm_notif(cbl_ctx *ctx, cbl_conn *conn,
	    const struct cbl_ywho *who, const struct cbl_ynode *n);

#endif /* !_CBL_YIMPL_H_ */
