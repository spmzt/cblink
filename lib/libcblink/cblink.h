/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBLINK_H_
#define	_CBLINK_H_

/*
 * cblink: netlink-style messaging for userland applications.
 * See cblink(3) and docs/API.md.  No libcbor or OpenSSL type may ever
 * appear in this header.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	CBLINK_VERSION_MAJOR	0
#define	CBLINK_VERSION_MINOR	1
#define	CBLINK_VERSION_PATCH	0

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbl_ctx		cbl_ctx;
typedef struct cbl_msg		cbl_msg;
typedef struct cbl_attr		cbl_attr;
typedef struct cbl_loop		cbl_loop;
typedef struct cbl_listener	cbl_listener;
typedef struct cbl_conn		cbl_conn;
typedef struct cbl_timer	cbl_timer;
typedef struct cbl_family	cbl_family;
typedef struct cbl_req		cbl_req;
typedef struct cbl_peer		cbl_peer;
typedef struct cbl_family_info	cbl_family_info;
typedef struct cbl_stream	cbl_stream;
typedef struct cbl_dump		cbl_dump;
typedef struct cbl_sub		cbl_sub;
typedef struct cbl_tls		cbl_tls;

/* Wire constants (docs/WIRE-FORMAT.md). */
#define	CBL_MAGIC		0xCB4C
#define	CBL_PROTO_VERSION	1
#define	CBL_HDRLEN		24
#define	CBL_HDRLEN_MAX		64

/* Header flags. */
#define	CBL_F_REQUEST		0x00000001u
#define	CBL_F_ACK		0x00000002u
#define	CBL_F_DUMP		0x00000004u
#define	CBL_F_MULTI		0x00000008u
#define	CBL_F_DONE		0x00000010u
#define	CBL_F_ERROR		0x00000020u
#define	CBL_F_NOTIFY		0x00000040u
#define	CBL_F_S_OPEN		0x00010000u
#define	CBL_F_S_DATA		0x00020000u
#define	CBL_F_S_HCLOSE		0x00040000u
#define	CBL_F_S_CLOSE		0x00080000u
#define	CBL_F_S_RESET		0x00100000u
#define	CBL_F_S_CREDIT		0x00200000u
#define	CBL_F_S_ANY		0x003F0000u

/* Attribute keys. */
#define	CBL_ATTR_MIN		1
#define	CBL_ATTR_MAX		65535
#define	CBL_ELEM		0	/* "type" of an array element */

/* Framework attribute keys (negative CBOR keys). */
#define	CBL_FW_CODE		(-1)
#define	CBL_FW_MSG		(-2)
#define	CBL_FW_PATH		(-3)
#define	CBL_FW_COOKIE		(-4)
#define	CBL_FW_MISS_TYPE	(-5)
#define	CBL_FW_CREDIT		(-6)
#define	CBL_FW_MIN		(-64)

#define	CBL_ERRMSG_MAX		1024
#define	CBL_COOKIE_MAX		256
#define	CBL_PATH_MAX		32

/* Limits (docs/WIRE-FORMAT.md section 11). */
enum cbl_limit {
	CBL_LIM_MAX_FRAME,
	CBL_LIM_MAX_DEPTH,
	CBL_LIM_MAX_ATTRS,
	CBL_LIM_MAX_STREAMS,
	CBL_LIM_STREAM_WINDOW,
	CBL_LIM_MAX_INFLIGHT,
	CBL_LIM_SENDQ_BYTES,
	CBL_LIM_MAX_CONNS,
	CBL_LIM_HANDSHAKE_MS,
	CBL_LIM_IDLE_MS,
	CBL_LIM_STREAM_CLOSE_MS,
	CBL_LIM_REQUEST_MS,
	CBL_LIM__COUNT
};

/* Kinds of decoded values and of policy entries. */
enum cbl_kind {
	CBL_K_ANY,
	CBL_K_UINT,
	CBL_K_INT,
	CBL_K_BOOL,
	CBL_K_FLAG,
	CBL_K_TEXT,
	CBL_K_BYTES,
	CBL_K_FLOAT,
	CBL_K_NEST,
	CBL_K_NULL,
	CBL_K_ARRAY,
};

struct cbl_bytes {
	const void	*p;
	size_t		 len;
};

/* An element of an extended-ack attribute path. */
struct cbl_path_elem {
	uint32_t	v;	/* attribute key, or array index */
	bool		index;	/* true: v is an array index */
};

const char	*cbl_version(void);

/* Context. */
int		 cbl_ctx_new(cbl_ctx **ctxp);
int		 cbl_ctx_free(cbl_ctx *ctx);	/* EBUSY while in use */
int		 cbl_ctx_set_limit(cbl_ctx *ctx, enum cbl_limit lim,
		    uint64_t v);
int		 cbl_ctx_get_limit(cbl_ctx *ctx, enum cbl_limit lim,
		    uint64_t *vp);

/* Messages: building. */
int		 cbl_msg_new(cbl_ctx *ctx, uint16_t family, uint16_t cmd,
		    uint32_t flags, cbl_msg **msgp);
void		 cbl_msg_free(cbl_msg *msg);
int		 cbl_msg_ref(cbl_msg *msg);
void		*cbl_msg_alloc(cbl_msg *msg, size_t len);
char		*cbl_msg_strdup(cbl_msg *msg, const char *s);
const char	*cbl_msg_errstr(const cbl_msg *msg);
int		 cbl_msg_error(const cbl_msg *msg);
int		 cbl_msg_set_seq(cbl_msg *msg, uint32_t seq);
int		 cbl_msg_set_stream(cbl_msg *msg, uint32_t stream);
int		 cbl_msg_set_flags(cbl_msg *msg, uint32_t flags);

int		 cbl_put_uint(cbl_msg *msg, uint16_t type, uint64_t v);
int		 cbl_put_int(cbl_msg *msg, uint16_t type, int64_t v);
int		 cbl_put_bool(cbl_msg *msg, uint16_t type, bool v);
int		 cbl_put_flag(cbl_msg *msg, uint16_t type);
int		 cbl_put_str(cbl_msg *msg, uint16_t type, const char *s);
int		 cbl_put_strn(cbl_msg *msg, uint16_t type, const char *s,
		    size_t len);
int		 cbl_put_bytes(cbl_msg *msg, uint16_t type, const void *p,
		    size_t len);
int		 cbl_put_double(cbl_msg *msg, uint16_t type, double v);
int		 cbl_put_null(cbl_msg *msg, uint16_t type);
int		 cbl_put_attr(cbl_msg *msg, uint16_t type, const cbl_attr *a);
int		 cbl_nest_start(cbl_msg *msg, uint16_t type);
int		 cbl_nest_end(cbl_msg *msg);
int		 cbl_array_start(cbl_msg *msg, uint16_t type);
int		 cbl_array_end(cbl_msg *msg);

/* Extended error (extended ack) attributes on an outgoing ERROR/ack. */
int		 cbl_msg_put_error(cbl_msg *msg, int code, const char *text,
		    const struct cbl_path_elem *path, size_t pathlen,
		    int miss_type);
int		 cbl_msg_put_cookie(cbl_msg *msg, const void *p, size_t len);

/* Messages: encoding and decoding raw frames. */
int		 cbl_msg_encode(cbl_msg *msg, const void **framep,
		    size_t *lenp);
int		 cbl_frame_decode(cbl_ctx *ctx, const void *buf, size_t len,
		    size_t *usedp, cbl_msg **msgp);

/* Messages: reading. */
uint16_t	 cbl_msg_family(const cbl_msg *msg);
uint16_t	 cbl_msg_cmd(const cbl_msg *msg);
uint32_t	 cbl_msg_flags(const cbl_msg *msg);
uint32_t	 cbl_msg_seq(const cbl_msg *msg);
uint32_t	 cbl_msg_stream(const cbl_msg *msg);
size_t		 cbl_msg_len(const cbl_msg *msg);

const cbl_attr	*cbl_msg_body(const cbl_msg *msg);
const cbl_attr	*cbl_msg_attr(const cbl_msg *msg, uint16_t type);
const cbl_attr	*cbl_attr_get(const cbl_attr *nest, uint16_t type);
const cbl_attr	*cbl_attr_first(const cbl_attr *container);
const cbl_attr	*cbl_attr_next(const cbl_attr *a);
const cbl_attr	*cbl_attr_index(const cbl_attr *array, size_t i);
uint16_t	 cbl_attr_type(const cbl_attr *a);
enum cbl_kind	 cbl_attr_kind(const cbl_attr *a);
size_t		 cbl_attr_count(const cbl_attr *a);
int		 cbl_attr_uint(const cbl_attr *a, uint64_t *vp);
int		 cbl_attr_int(const cbl_attr *a, int64_t *vp);
int		 cbl_attr_bool(const cbl_attr *a, bool *vp);
int		 cbl_attr_double(const cbl_attr *a, double *vp);
int		 cbl_attr_bytes(const cbl_attr *a, const void **pp,
		    size_t *lenp);
int		 cbl_attr_str(cbl_msg *msg, const cbl_attr *a,
		    const char **sp);

/* Extended error accessors, valid on any received message. */
int		 cbl_msg_err_code(const cbl_msg *msg);
const char	*cbl_msg_err_str(const cbl_msg *msg);
size_t		 cbl_msg_err_path(const cbl_msg *msg,
		    struct cbl_path_elem *path, size_t max);
int		 cbl_msg_err_miss_type(const cbl_msg *msg);
int		 cbl_msg_err_cookie(const cbl_msg *msg, const void **pp,
		    size_t *lenp);

/* Transports. */
enum cbl_transport {
	CBL_TR_TCP,
	CBL_TR_SCTP,
	CBL_TR_UNIX,
};

/* Listener and connection flags. */
#define	CBL_PLAINTEXT		0x0001u	/* opt in: no TLS on tcp/sctp */
#define	CBL_LF_REUSEPORT	0x0002u	/* SO_REUSEPORT_LB */
#define	CBL_LF_UNIX_TRUSTED	0x0004u	/* AF_UNIX peers are authenticated */
#define	CBL_LF_PROXY		0x0008u	/* tcp: PROXY protocol header first */
#define	CBL_CF_NONBLOCK		0x0100u	/* connect returns EINPROGRESS */

/* Event loop. */
#define	CBL_TF_REPEAT		0x0001u

int		 cbl_loop_new(cbl_ctx *ctx, cbl_loop **loopp);
void		 cbl_loop_free(cbl_loop *loop);
int		 cbl_loop_run(cbl_loop *loop);
int		 cbl_loop_run_once(cbl_loop *loop, int timeout_ms);
int		 cbl_loop_stop(cbl_loop *loop);
int		 cbl_loop_fd(const cbl_loop *loop);
int		 cbl_loop_post(cbl_loop *loop, void (*fn)(void *), void *arg);
int		 cbl_loop_timer(cbl_loop *loop, uint32_t ms, uint32_t flags,
		    void (*fn)(cbl_timer *, void *), void *arg, cbl_timer **tp);
void		 cbl_timer_cancel(cbl_timer *t);
int		 cbl_loop_signal(cbl_loop *loop, int sig,
		    void (*fn)(int, void *), void *arg);

/* TLS and DTLS (mTLS: certificates on both sides). */
int		 cbl_tls_new(cbl_tls **tlsp);
void		 cbl_tls_free(cbl_tls *tls);
int		 cbl_tls_set_cert(cbl_tls *tls, const char *certfile,
		    const char *keyfile);
int		 cbl_tls_set_ca(cbl_tls *tls, const char *cafile,
		    const char *capath);
int		 cbl_tls_set_crl(cbl_tls *tls, const char *crlfile);
int		 cbl_tls_set_peer_name(cbl_tls *tls, const char *name);
int		 cbl_tls_set_verify_depth(cbl_tls *tls, int depth);
/*
 * Reread the certificate, key, CA and CRL (or new paths set since): new
 * connections use them, open ones keep what they had.  Any thread.
 */
int		 cbl_tls_reload(cbl_tls *tls);
const char	*cbl_tls_errstr(const cbl_tls *tls);
int		 cbl_ctx_set_tls(cbl_ctx *ctx, cbl_tls *tls);

/* Integration mode (no cbl_loop). */
#define	CBL_EV_READ		0x1
#define	CBL_EV_WRITE		0x2

/* Listeners. */
int		 cbl_listener_new(cbl_ctx *ctx, const char *uri, uint32_t flags,
		    cbl_listener **lp);
int		 cbl_listener_set_limit(cbl_listener *l, enum cbl_limit lim,
		    uint64_t v);
int		 cbl_listener_set_tls(cbl_listener *l, cbl_tls *tls);
/* CBL_LF_PROXY: "addr[/bits]" a PROXY header may come from (default: any). */
int		 cbl_listener_add_proxy(cbl_listener *l, const char *net);
int		 cbl_listener_set_unix_perm(cbl_listener *l, mode_t mode,
		    uid_t uid, gid_t gid);
int		 cbl_listener_start(cbl_listener *l, cbl_loop *loop);
int		 cbl_listener_fd(const cbl_listener *l);
int		 cbl_listener_process(cbl_listener *l, cbl_conn **connp);
int		 cbl_listener_addr(const cbl_listener *l,
		    struct sockaddr_storage *ss, socklen_t *lenp);
const char	*cbl_listener_errstr(const cbl_listener *l);
void		 cbl_listener_free(cbl_listener *l);

/* Connections. */
struct cbl_conn_cbs {
	void	(*on_open)(cbl_conn *conn, void *arg);
	void	(*on_close)(cbl_conn *conn, int error, void *arg);
};

int		 cbl_ctx_set_conn_cbs(cbl_ctx *ctx,
		    const struct cbl_conn_cbs *cbs, void *arg);
int		 cbl_conn_new(cbl_ctx *ctx, const char *uri, uint32_t flags,
		    cbl_conn **connp);
int		 cbl_conn_set_limit(cbl_conn *conn, enum cbl_limit lim,
		    uint64_t v);
int		 cbl_conn_set_tls(cbl_conn *conn, cbl_tls *tls);
int		 cbl_conn_connect(cbl_conn *conn);
int		 cbl_conn_attach(cbl_conn *conn, cbl_loop *loop);
int		 cbl_conn_close(cbl_conn *conn);
void		 cbl_conn_free(cbl_conn *conn);
const char	*cbl_conn_errstr(const cbl_conn *conn);
bool		 cbl_conn_is_open(const cbl_conn *conn);

/* What a connection is doing, for monitoring (cbl_conn_stats()). */
struct cbl_conn_stats {
	uint64_t	rx_dropped;	/* messages dropped on receipt (SCTP) */
	uint64_t	ntf_dropped;	/* notifications lost to a slow peer */
	size_t		txq_bytes;	/* queued for sending */
	size_t		txq_frames;
	uint32_t	inflight;	/* the peer's requests being handled */
	uint32_t	pending;	/* our requests waiting for an answer */
	uint32_t	streams;	/* open streams */
	bool		rx_paused;	/* not reading: backpressure */
};

int		 cbl_conn_stats(cbl_conn *conn, struct cbl_conn_stats *st);
enum cbl_transport cbl_conn_transport(const cbl_conn *conn);
void		 cbl_conn_set_udata(cbl_conn *conn, void *udata);
void		*cbl_conn_udata(const cbl_conn *conn);
cbl_ctx		*cbl_conn_ctx(const cbl_conn *conn);
int		 cbl_conn_fd(const cbl_conn *conn);
int		 cbl_conn_interest(cbl_conn *conn, int *eventsp, int *timeoutp);
int		 cbl_conn_process(cbl_conn *conn, int revents);

/* Client requests. */
typedef void cbl_reply_f(cbl_conn *conn, cbl_msg *reply, bool final,
    int error, void *arg);

int		 cbl_request(cbl_conn *conn, cbl_msg *req, cbl_msg **replyp,
		    int timeout_ms);
int		 cbl_request_async(cbl_conn *conn, cbl_msg *req,
		    cbl_reply_f *cb, void *arg);
int		 cbl_conn_send(cbl_conn *conn, cbl_msg *msg);

/* Declarative attribute policies (like nla_policy). */
#define	CBL_PF_REQUIRED		0x01	/* missing: EINVAL + MISS_TYPE */
#define	CBL_PF_MULTI		0x02	/* value is an array of "kind" */
#define	CBL_PF_MASK		0x04	/* uint: no bits outside u.max */
#define	CBL_PF_RANGE		0x08	/* u/i/len ranges are set */

struct cbl_enum {
	const uint64_t		*v;
	uint32_t		 n;
};

struct cbl_policy_set;

struct cbl_policy {
	uint16_t			 type;
	uint8_t				 kind;		/* enum cbl_kind */
	uint8_t				 flags;		/* CBL_PF_* */
	uint32_t			 min_count;	/* CBL_PF_MULTI */
	uint32_t			 max_count;	/* 0: no limit */
	union {
		struct { uint64_t min, max; }	u;
		struct { int64_t min, max; }	i;
		struct { uint32_t min, max; }	len;
	};
	const struct cbl_policy_set	*nested;	/* CBL_K_NEST */
	const struct cbl_enum		*values;	/* CBL_K_UINT */
	int				(*validate)(const cbl_attr *,
					    const void *);
	const void			*arg;
};

struct cbl_policy_set {
	const struct cbl_policy	*p;		/* sorted by type */
	uint32_t		 n;
};

#define	CBL_POLICY_SET(_name, _arr)					\
	static const struct cbl_policy_set _name = {			\
		.p = (_arr), .n = sizeof(_arr) / sizeof((_arr)[0]) }

/* Where and why validation failed. */
struct cbl_verr {
	const char		*msg;
	struct cbl_path_elem	 path[CBL_PATH_MAX];
	size_t			 pathlen;
	int			 miss_type;	/* -1: none */
};

int		 cbl_validate(const cbl_attr *map,
		    const struct cbl_policy_set *ps, struct cbl_verr *err);
int		 cbl_policy_set_check(const struct cbl_policy_set *ps);

/* Declarative parsers (like snl(3)). */
typedef int	 cbl_parse_attr_f(cbl_msg *msg, const cbl_attr *a,
		    const void *arg, void *target);
typedef int	 cbl_parse_post_f(cbl_msg *msg, void *target);

struct cbl_attr_parser {
	uint16_t		 type;		/* sorted ascending */
	uint32_t		 off;		/* offsetof(struct, field) */
	cbl_parse_attr_f	*cb;
	const void		*arg;
};

struct cbl_parser {
	uint32_t			 out_size;
	uint32_t			 np_size;
	const struct cbl_attr_parser	*np;
	cbl_parse_post_f		*post;
};

#define	CBL_DECLARE_PARSER(_name, _type, _np, _post)			\
	static const struct cbl_parser _name = {			\
		.out_size = sizeof(_type),				\
		.np_size = sizeof(_np) / sizeof((_np)[0]),		\
		.np = (_np),						\
		.post = (_post) }

struct cbl_array {
	size_t		 n;
	void		*v;
};

struct cbl_array_desc {
	cbl_parse_attr_f	*cb;
	const void		*arg;
	uint32_t		 elem_size;
};

int		 cbl_parse(cbl_msg *msg, const struct cbl_parser *p,
		    void *target);
int		 cbl_parse_nest(cbl_msg *msg, const cbl_attr *nest,
		    const struct cbl_parser *p, void *target);
int		 cbl_parser_check(const struct cbl_parser *p);

cbl_parse_attr_f cbl_get_u8;
cbl_parse_attr_f cbl_get_u16;
cbl_parse_attr_f cbl_get_u32;
cbl_parse_attr_f cbl_get_u64;
cbl_parse_attr_f cbl_get_s8;
cbl_parse_attr_f cbl_get_s16;
cbl_parse_attr_f cbl_get_s32;
cbl_parse_attr_f cbl_get_s64;
cbl_parse_attr_f cbl_get_bool;
cbl_parse_attr_f cbl_get_flag;
cbl_parse_attr_f cbl_get_double;
cbl_parse_attr_f cbl_get_str;
cbl_parse_attr_f cbl_get_bytes;
cbl_parse_attr_f cbl_get_attr;
cbl_parse_attr_f cbl_get_nested;
cbl_parse_attr_f cbl_get_nested_ptr;
cbl_parse_attr_f cbl_get_array;

/* Families. */
#define	CBL_OPF_DO		0x01
#define	CBL_OPF_DUMP		0x02
#define	CBL_OPF_STREAM		0x04
#define	CBL_OPF_PUSH		0x08
#define	CBL_OPF_AUTH		0x10

#define	CBL_MCF_AUTH		0x10

struct cbl_dump_state {
	uint64_t	 pos[4];
	void		*priv;
	void		(*priv_free)(void *);
};

typedef int	 cbl_doit_f(cbl_req *req, const cbl_msg *msg, void *arg);
typedef int	 cbl_dumpit_f(cbl_req *req, const cbl_msg *msg,
		    struct cbl_dump_state *st, void *arg);
typedef int	 cbl_stream_open_f(cbl_req *req, const cbl_msg *msg,
		    cbl_stream *stream, void *arg);

struct cbl_op {
	uint16_t			 cmd;
	uint32_t			 flags;		/* CBL_OPF_* */
	const char			*name;
	const struct cbl_policy_set	*policy;
	cbl_doit_f			*doit;
	cbl_dumpit_f			*dumpit;
	cbl_stream_open_f		*stream_open;
};

struct cbl_mcgrp {
	const char	*name;
	uint32_t	 flags;		/* CBL_MCF_* */
};

#define	CBL_FAMILY_ABI		1
#define	CBL_FAMILY_NAME_MAX	63

struct cbl_family_def {
	uint32_t		 abi;		/* CBL_FAMILY_ABI */
	const char		*name;
	uint32_t		 version;
	const struct cbl_op	*ops;		/* sorted by cmd */
	uint32_t		 nops;
	const struct cbl_mcgrp	*mcgrps;
	uint32_t		 nmcgrps;
};

int		 cbl_family_register(cbl_ctx *ctx,
		    const struct cbl_family_def *def, void *arg,
		    cbl_family **famp);
int		 cbl_family_unregister(cbl_family *fam);
uint16_t	 cbl_family_id(const cbl_family *fam);
uint32_t	 cbl_family_group_id(const cbl_family *fam, uint32_t idx);

/* Server-side request context. */
int		 cbl_req_reply_new(cbl_req *req, uint16_t cmd, cbl_msg **msgp);
int		 cbl_req_send(cbl_req *req, cbl_msg *msg);
int		 cbl_req_set_err(cbl_req *req, const char *text,
		    const struct cbl_path_elem *path, size_t pathlen,
		    int miss_type);
int		 cbl_req_set_cookie(cbl_req *req, const void *p, size_t len);
int		 cbl_req_defer(cbl_req *req);
int		 cbl_req_complete(cbl_req *req, int error);
int		 cbl_req_set_cancel(cbl_req *req,
		    void (*fn)(cbl_req *req, void *arg), void *arg);
bool		 cbl_req_cancelled(const cbl_req *req);
int		 cbl_req_dump_item(cbl_req *req, cbl_msg **msgp);
cbl_msg		*cbl_req_msg(const cbl_req *req);
const cbl_peer	*cbl_req_peer(const cbl_req *req);
cbl_conn	*cbl_req_conn(const cbl_req *req);
cbl_ctx		*cbl_req_ctx(const cbl_req *req);

/* Peer identity, the same on every transport. */
#define	CBL_PEER_AUTHENTICATED	0x01
#define	CBL_PEER_LOCAL		0x02
#define	CBL_PEER_PROXIED	0x04	/* address from a PROXY header */

const cbl_peer	*cbl_conn_peer(const cbl_conn *conn);
uint32_t	 cbl_peer_flags(const cbl_peer *peer);
enum cbl_transport cbl_peer_transport(const cbl_peer *peer);
const char	*cbl_peer_subject(const cbl_peer *peer);
const char	*cbl_peer_issuer(const cbl_peer *peer);
size_t		 cbl_peer_san_count(const cbl_peer *peer);
const char	*cbl_peer_san(const cbl_peer *peer, size_t i);
int		 cbl_peer_fingerprint(const cbl_peer *peer, const char *alg,
		    uint8_t *buf, size_t *lenp);
int		 cbl_peer_addr(const cbl_peer *peer,
		    struct sockaddr_storage *ss, socklen_t *lenp);
int		 cbl_peer_cred(const cbl_peer *peer, uid_t *uidp, gid_t *gidp);

/* Control family client helpers. */
#define	CBL_CTRL_FAMILY		0
#define	CBL_CTRL_GROUP_NOTIFY	1

int		 cbl_resolve(cbl_conn *conn, const char *family,
		    cbl_family_info **infop);
/*
 * Without waiting, for a client on a loop (the synchronous calls give
 * EDEADLK there): the callback runs on the I/O thread and owns "info".
 */
typedef void	 cbl_resolve_f(cbl_conn *conn, int error, cbl_family_info *info,
		    void *arg);
int		 cbl_resolve_async(cbl_conn *conn, const char *family,
		    cbl_resolve_f *cb, void *arg);
uint16_t	 cbl_family_info_id(const cbl_family_info *info);
uint32_t	 cbl_family_info_version(const cbl_family_info *info);
const char	*cbl_family_info_name(const cbl_family_info *info);
int		 cbl_family_info_group(const cbl_family_info *info,
		    const char *name, uint32_t *idp);
int		 cbl_family_info_op(const cbl_family_info *info, uint16_t cmd,
		    uint32_t *flagsp);
size_t		 cbl_family_info_nops(const cbl_family_info *info);
void		 cbl_family_info_free(cbl_family_info *info);
int		 cbl_ping(cbl_conn *conn, int timeout_ms);
int		 cbl_hello(cbl_conn *conn);

/* Client dump iterator. */
int		 cbl_dump_start(cbl_conn *conn, cbl_msg *req, cbl_dump **dp);
int		 cbl_dump_next(cbl_dump *d, cbl_msg **itemp);
const cbl_msg	*cbl_dump_error(const cbl_dump *d);
void		 cbl_dump_free(cbl_dump *d);

/* Multicast notifications. */
typedef void	 cbl_notify_f(cbl_conn *conn, cbl_msg *msg, void *arg);

int		 cbl_subscribe(cbl_conn *conn, const char *family,
		    const char *group, cbl_notify_f *cb, void *arg,
		    cbl_sub **subp);
int		 cbl_subscribe_id(cbl_conn *conn, uint16_t family,
		    uint32_t group, cbl_notify_f *cb, void *arg,
		    cbl_sub **subp);
/* Without waiting: "done" gets the subscription (or an error, and NULL). */
typedef void	 cbl_subscribed_f(cbl_conn *conn, int error, cbl_sub *sub,
		    void *arg);
int		 cbl_subscribe_async(cbl_conn *conn, const char *family,
		    const char *group, cbl_notify_f *cb, void *arg,
		    cbl_subscribed_f *done, void *done_arg);
int		 cbl_subscribe_id_async(cbl_conn *conn, uint16_t family,
		    uint32_t group, cbl_notify_f *cb, void *arg,
		    cbl_subscribed_f *done, void *done_arg);
int		 cbl_unsubscribe(cbl_sub *sub);
void		*cbl_sub_arg(const cbl_sub *sub);
int		 cbl_notify(cbl_family *fam, uint32_t group_idx, cbl_msg *msg);
int		 cbl_conn_notify(cbl_conn *conn, cbl_family *fam,
		    uint32_t group_idx, cbl_msg *msg);
int		 cbl_notify_msg_new(cbl_family *fam, uint16_t cmd,
		    cbl_msg **msgp);

/* Streams. */
struct cbl_stream_cbs {
	void	(*on_open)(cbl_stream *s, cbl_msg *accept, int error,
		    void *arg);
	void	(*on_data)(cbl_stream *s, cbl_msg *data, void *arg);
	void	(*on_hclose)(cbl_stream *s, void *arg);
	void	(*on_close)(cbl_stream *s, int code, const char *text,
		    void *arg);
	void	(*on_writable)(cbl_stream *s, size_t credit, void *arg);
};

#define	CBL_SF_MANUAL_CREDIT	0x0001u
#define	CBL_SF_PUSH		0x0002u	/* opener of a push stream */

int		 cbl_stream_open(cbl_conn *conn, cbl_msg *open_req,
		    uint32_t flags, const struct cbl_stream_cbs *cbs, void *arg,
		    cbl_stream **sp);
int		 cbl_stream_accept(cbl_stream *s, cbl_msg *accept,
		    uint32_t flags, const struct cbl_stream_cbs *cbs,
		    void *arg);
int		 cbl_stream_msg_new(cbl_stream *s, cbl_msg **msgp);
int		 cbl_msg_set_window(cbl_msg *msg, uint32_t window);
int		 cbl_stream_send(cbl_stream *s, cbl_msg *msg);
size_t		 cbl_stream_credit(const cbl_stream *s);
int		 cbl_stream_consumed(cbl_stream *s, size_t bytes);
int		 cbl_stream_half_close(cbl_stream *s);
int		 cbl_stream_close(cbl_stream *s, int code, const char *text);
int		 cbl_stream_reset(cbl_stream *s, int code);
/*
 * A stream is valid until its on_close returns, or, with a reference,
 * until the matching cbl_stream_rele(): calls on a stream that ended then
 * fail with EPIPE.  For streams used from other threads.
 */
void		 cbl_stream_ref(cbl_stream *s);
void		 cbl_stream_rele(cbl_stream *s);
uint32_t	 cbl_stream_id(const cbl_stream *s);
cbl_conn	*cbl_stream_conn(const cbl_stream *s);

#ifdef __cplusplus
}
#endif

#endif /* !_CBLINK_H_ */
