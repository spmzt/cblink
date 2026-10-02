/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBL_IMPL_H_
#define	_CBL_IMPL_H_

/* Private to libcblink.  libcbor types may appear here, never in cblink.h. */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/uio.h>

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cblink.h"

#define	CBL_DEPTH_HARD_MAX	64

/* Per-message arena: a chain of linear buffers, like snl(3). */
struct cbl_chunk {
	struct cbl_chunk	*next;
	size_t			 size;
	size_t			 off;
	alignas(max_align_t) unsigned char data[];
};

struct cbl_arena {
	struct cbl_chunk	*head;
	size_t			 total;
};

void	 cbl_arena_init(struct cbl_arena *ar);
void	*cbl_arena_alloc(struct cbl_arena *ar, size_t len);
void	 cbl_arena_free(struct cbl_arena *ar);

/* TLS (cbl_tls.c).  OpenSSL types stay opaque here. */
struct ssl_ctx_st;
struct x509_st;
struct cbl_peer;

enum cbl_tls_kind {
	CBL_TLS_SERVER,
	CBL_TLS_CLIENT,
	CBL_DTLS_SERVER,
	CBL_DTLS_CLIENT,
	CBL_TLS__KINDS
};

void	cbl_tls_ref(cbl_tls *tls);
struct ssl_ctx_st *cbl_tls_ctx(cbl_tls *tls, enum cbl_tls_kind kind);
int	cbl_tls_prepare(cbl_tls *tls, enum cbl_tls_kind kind, char *err,
	    size_t errlen);
int	cbl_peer_from_x509(struct cbl_peer *peer, struct x509_st *x);

/* Effective limits, copied into objects so hot paths take no locks. */
struct cbl_limits {
	uint64_t	v[CBL_LIM__COUNT];
};

void	cbl_limits_default(struct cbl_limits *lim);
int	cbl_limit_check(enum cbl_limit l, uint64_t v);

/* Decoded header. */
struct cbl_hdr {
	uint8_t		version;
	uint8_t		hdrlen;
	uint32_t	length;
	uint16_t	family;
	uint16_t	cmd;
	uint32_t	flags;
	uint32_t	seq;
	uint32_t	stream;
};

/* A registered family. */
struct cbl_family {
	RB_ENTRY(cbl_family)		 link;
	cbl_ctx				*ctx;
	uint16_t			 id;
	const struct cbl_family_def	*def;
	void				*arg;
	uint32_t			 group_base;	/* id of group 0 */
	atomic_uint			 refs;
	atomic_bool			 dead;	/* being unregistered */
};

RB_HEAD(cbl_fam_tree, cbl_family);

/* Multicast groups (cbl_notify.c). */
struct cbl_member;
LIST_HEAD(cbl_member_list, cbl_member);

struct cbl_group {
	RB_ENTRY(cbl_group)	 link;
	uint32_t		 gid;
	struct cbl_member_list	 members;
};

RB_HEAD(cbl_group_tree, cbl_group);

struct cbl_member {
	LIST_ENTRY(cbl_member)	 glink;		/* in the group */
	LIST_ENTRY(cbl_member)	 clink;		/* in the connection */
	struct cbl_group	*g;
	cbl_conn		*conn;
};

/* A client-side subscription. */
struct cbl_sub {
	LIST_ENTRY(cbl_sub)	 link;
	cbl_conn		*conn;
	uint16_t		 family;
	uint32_t		 group;
	cbl_notify_f		*cb;
	void			*arg;
	unsigned		 refs;		/* running callbacks */
	bool			 dead;
	/* cbl_unsubscribe() waits; it frees. */
	bool			 waiter;
};

void	cbl_notify_rx(cbl_conn *conn, cbl_msg *msg);
void	cbl_notify_conn_closed(cbl_conn *conn);
void	cbl_notify_family_gone(cbl_ctx *ctx, const cbl_family *fam);
void	cbl_sub_free_all(cbl_conn *conn);

struct cbl_ctx {
	pthread_mutex_t		 mtx;
	struct cbl_limits	 lim;
	bool			 frozen;
	atomic_uint		 nconns;	/* for max_conns */
	atomic_uint		 nobjs;		/* loops, listeners, conns */
	struct cbl_conn_cbs	 conn_cbs;
	void			*conn_cbs_arg;
	cbl_tls			*tls;		/* default for endpoints */

	/* Multicast membership: group id -> member connections. */
	pthread_mutex_t		 submtx;
	struct cbl_group_tree	 groups;

	/* Family registry. */
	pthread_rwlock_t	 famlock;
	pthread_cond_t		 famcv;
	atomic_uint		 fam_waiters;	/* in cbl_family_unregister() */
	struct cbl_fam_tree	 fams;
	uint32_t		 next_fam;
	uint32_t		 next_group;
	cbl_family		*ctrl;
};

cbl_family *cbl_family_lookup(cbl_ctx *ctx, uint16_t id);
cbl_family *cbl_family_lookup_name(cbl_ctx *ctx, const char *name);
void	cbl_family_rele(cbl_family *fam);
const struct cbl_op *cbl_family_op(const cbl_family *fam, uint16_t cmd);
cbl_family *cbl_family_next(cbl_ctx *ctx, uint32_t from);
void	cbl_family_free_all(cbl_ctx *ctx);
int	cbl_ctx_add_builtin(cbl_ctx *ctx, const struct cbl_family_def *def,
	    void *arg);
void	cbl_ctrl_notify_family(cbl_ctx *ctx, cbl_family *fam, bool added);
int	cbl_sub_change(cbl_req *req, uint16_t family, uint32_t group,
	    bool subscribe);
int	cbl_ctrl_register(cbl_ctx *ctx);

/* Server-side request. */
struct cbl_req {
	cbl_conn		*conn;
	cbl_family		*fam;
	const struct cbl_op	*op;
	cbl_msg			*msg;
	struct cbl_hdr		 hdr;
	atomic_int		 refs;		/* dispatch, deferral, dump */
	bool			 deferred;
	atomic_bool		 completed;
	atomic_bool		 cancelled;	/* its connection is gone */
	void			(*cancel_fn)(cbl_req *, void *);
	void			*cancel_arg;
	bool			 on_deferred;	/* in conn->deferred */
	TAILQ_ENTRY(cbl_req)	 defer_link;
	cbl_stream		*stream;	/* a deferred stream open */
	char			*err_msg;
	struct cbl_path_elem	 err_path[CBL_PATH_MAX];
	size_t			 err_pathlen;
	int			 err_miss;
	unsigned char		 cookie[CBL_COOKIE_MAX];
	size_t			 cookie_len;
	bool			 has_cookie;
	struct cbl_dump_state	 dump;
	TAILQ_ENTRY(cbl_req)	 dump_link;
};

/* Peer identity. */
struct cbl_peer {
	uint32_t		 flags;
	enum cbl_transport	 transport;
	char			*subject;
	char			*issuer;
	char			**sans;
	size_t			 nsans;
	uint8_t			 fp_sha256[32];
	bool			 has_sha256;
	uint8_t			 fp_sha1[20];
	bool			 has_sha1;
	struct sockaddr_storage	 addr;
	socklen_t		 addrlen;
	uid_t			 uid;
	gid_t			 gid;
	bool			 has_cred;
};

void	cbl_peer_clear(struct cbl_peer *peer);
void	cbl_peer_clear_identity(struct cbl_peer *peer);

void	cbl_ctx_freeze(cbl_ctx *ctx, struct cbl_limits *lim);

int	cbl_hdr_decode(const unsigned char *p, size_t len,
	    const struct cbl_limits *lim, struct cbl_hdr *h);
void	cbl_hdr_encode(unsigned char *p, const struct cbl_hdr *h);
bool	cbl_flags_valid(uint32_t flags, uint32_t stream);

/*
 * A decoded value.  Children of a container occupy a contiguous block
 * of the node array; map children are sorted by key.
 */
#define	CBL_NF_NEGBIG	0x01	/* negint below INT64_MIN */
#define	CBL_NF_FLOAT32	0x02

struct cbl_attr {
	int64_t		 key;		/* map key; 0 inside arrays */
	uint8_t		 kind;		/* enum cbl_kind */
	uint8_t		 nflags;
	uint8_t		 inmap;		/* 1: child of a map */
	uint32_t	 count;		/* containers: number of children */
	cbl_attr	*child;		/* containers: first child */
	const cbl_attr	*parent;	/* NULL for the body root */
	union {
		uint64_t	 u;
		int64_t		 i;
		double		 d;
		bool		 b;
		struct {
			const unsigned char	*p;
			size_t			 len;
		} s;
	} v;
};

/* Builder stack entry. */
struct cbl_bframe {
	size_t		 hoff;		/* offset of the 1-byte reserved head */
	uint32_t	 count;
	bool		 is_map;
	int64_t		 lastkey;
	int64_t		*keys;
	uint32_t	 nkeys;
	uint32_t	 capkeys;
};

struct cbl_msg {
	atomic_uint		 refs;
	struct cbl_limits	 lim;
	struct cbl_hdr		 hdr;

	unsigned char		*buf;	/* frame: header + body */
	size_t			 len;
	size_t			 cap;

	/* Builder. */
	bool			 decoded;	/* received: read only */
	bool			 finalized;
	uint32_t		 window;	/* stream window, 0: default */
	int			 error;		/* sticky */
	const char		*errstr;
	struct cbl_bframe	*stack;		/* max_depth entries, lazy */
	int			 depth;		/* 0: root not open yet */
	uint32_t		 nvalues;

	/* Decoder. */
	cbl_attr		*nodes;
	uint32_t		 nnodes;
	cbl_attr		 empty;		/* root for an empty body */

	/* Framework attributes of a received message. */
	int			 err_code;
	const char		*err_str;
	const cbl_attr		*err_path;
	int			 err_miss;
	const cbl_attr		*err_cookie;

	struct cbl_arena	 arena;
};

int	cbl_msg_alloc_empty(const struct cbl_limits *lim, cbl_msg **msgp);
int	cbl_msg_decode_body(cbl_msg *msg);
int	cbl_msg_from_frame(const struct cbl_limits *lim, unsigned char *buf,
	    size_t len, cbl_msg **msgp);
int	cbl_msg_put_fw_uint(cbl_msg *msg, int key, uint64_t v);
int	cbl_msg_put_fw_str(cbl_msg *msg, int key, const char *s);
int	cbl_msg_put_fw_bytes(cbl_msg *msg, int key, const void *p,
	    size_t len);
int	cbl_msg_fail(cbl_msg *msg, int error, const char *why);
const cbl_attr *cbl_map_lookup(const cbl_attr *map, int64_t key);

bool	cbl_utf8_valid(const unsigned char *p, size_t len);

static inline uint16_t
cbl_be16dec(const unsigned char *p)
{
	return ((uint16_t)((p[0] << 8) | p[1]));
}

static inline uint32_t
cbl_be32dec(const unsigned char *p)
{
	return (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | p[3]);
}

static inline void
cbl_be16enc(unsigned char *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

static inline void
cbl_be32enc(unsigned char *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >> 8) & 0xff;
	p[3] = v & 0xff;
}

uint64_t cbl_now_ms(void);

/*
 * Event loop.  Every kevent udata points at a cbl_src so one dispatcher
 * can route events for connections, listeners, timers and signals.
 */
enum cbl_src_type {
	CBL_SRC_CONN = 1,
	CBL_SRC_LISTENER,
	CBL_SRC_TIMER,
	CBL_SRC_SIGNAL,
};

struct cbl_src {
	enum cbl_src_type	 type;
	void			*obj;
};

struct cbl_post {
	STAILQ_ENTRY(cbl_post)	 link;
	void			(*fn)(void *);
	void			*arg;
};

struct cbl_timer {
	struct cbl_src		 src;
	LIST_ENTRY(cbl_timer)	 link;
	cbl_loop		*loop;
	void			(*fn)(cbl_timer *, void *);
	void			*arg;
	bool			 repeat;
	bool			 held;		/* the caller has the handle */
	bool			 fired;		/* one-shot, done */
};

struct cbl_sig {
	struct cbl_src		 src;
	LIST_ENTRY(cbl_sig)	 link;
	int			 sig;
	void			(*fn)(int, void *);
	void			*arg;
	struct sigaction	 old;		/* cbl_loop_free() restores */
};

struct cbl_loop {
	cbl_ctx				*ctx;
	int				 kq;
	pthread_mutex_t			 mtx;
	STAILQ_HEAD(, cbl_post)		 posts;
	LIST_HEAD(, cbl_conn)		 conns;
	LIST_HEAD(, cbl_timer)		 timers;
	LIST_HEAD(, cbl_sig)		 sigs;
	TAILQ_HEAD(, cbl_conn)		 dead;
	/* pthread_self() of the runner. */
	atomic_uintptr_t		 thread;
	atomic_bool			 running;
	atomic_bool			 stop;
};

bool	cbl_loop_on_thread(const cbl_loop *loop);
void	cbl_loop_kick(cbl_loop *loop, cbl_conn *conn);
void	cbl_loop_update(cbl_loop *loop, cbl_conn *conn);
void	cbl_loop_detach(cbl_loop *loop, cbl_conn *conn);
int	cbl_loop_add_listener(cbl_loop *loop, cbl_listener *l);
void	cbl_loop_del_listener(cbl_loop *loop, cbl_listener *l);
void	cbl_loop_pause_listener(cbl_loop *loop, cbl_listener *l, int ms);
void	cbl_loop_resume_listener(cbl_loop *loop, cbl_listener *l);
void	cbl_listener_on_ready(cbl_listener *l);

/* Parsed endpoint URI. */
#define	CBL_URI_MAXADDR	8

struct cbl_uri {
	enum cbl_transport	 transport;
	char			 host[256];	/* first host, for TLS names */
	char			 port[16];
	char			 path[104];	/* AF_UNIX */
	int			 naddr;		/* resolved, filled by caller */
	struct sockaddr_storage	 addr[CBL_URI_MAXADDR];
	socklen_t		 addrlen[CBL_URI_MAXADDR];
};

int	cbl_uri_parse(const char *s, struct cbl_uri *u, char *err,
	    size_t errlen);
int	cbl_uri_resolve(struct cbl_uri *u, bool passive, char *err,
	    size_t errlen);
bool	cbl_uri_dualstack(const struct cbl_uri *u);

/*
 * Transport operations.  Byte-stream transports provide "read" and are
 * framed by the connection core using the length field; message
 * transports (SCTP) provide "rx_frames" and hand over whole frames.
 */
struct cbl_tr_ops {
	const char		*name;
	/* Drive connect/handshake: 0 done, EAGAIN in progress. */
	int	(*handshake)(cbl_conn *);
	/* 0 with *got > 0, 0 with *got == 0 for EOF, EAGAIN, or errno. */
	int	(*read)(cbl_conn *, void *, size_t, size_t *got);
	int	(*write)(cbl_conn *, const void *, size_t, size_t *put);
	/* Optional: several frames in one call (plain byte streams). */
	int	(*writev)(cbl_conn *, const struct iovec *, int, size_t *put);
	/*
	 * Message transports that reassemble frames themselves (SCTP): read
	 * up to "budget" frames and hand each to cbl_conn_rx_message().
	 */
	int	(*rx_frames)(cbl_conn *, int budget);
	/* A frame starts on the next write (SCTP: choose its stream). */
	void	(*frame_start)(cbl_conn *, const void *frame, size_t len);
	/* Transport timer (DTLS over SCTP): ms until due, or -1. */
	int	(*timeout)(cbl_conn *);
	void	(*on_timeout)(cbl_conn *);
	void	(*shutdown)(cbl_conn *);
	void	(*free)(cbl_conn *);
};

extern const struct cbl_tr_ops cbl_tr_tcp_ops;
extern const struct cbl_tr_ops cbl_tr_tls_ops;
extern const struct cbl_tr_ops cbl_tr_unix_ops;
extern const struct cbl_tr_ops cbl_tr_sctp_ops;
extern const struct cbl_tr_ops cbl_tr_dtls_sctp_ops;

int	cbl_sctp_socket(const struct cbl_uri *u, bool dtls, int *fdp);
int	cbl_sctp_bind_more(int fd, const struct cbl_uri *u);
int	cbl_sctp_connect(cbl_conn *conn, cbl_tls *tls, uint64_t deadline);
int	cbl_sctp_attach(cbl_conn *conn);
int	cbl_dtls_sctp_attach(cbl_conn *conn, cbl_tls *tls, bool server);
void	cbl_sctp_buffers(cbl_conn *conn);

/* Reassembly of frames per SCTP stream (cbl_sctp.c). */
struct cbl_sctp_mux;
struct cbl_sctp_mux *cbl_sctp_mux_new(void);
void	cbl_sctp_mux_free(struct cbl_sctp_mux *m);
uint16_t cbl_sctp_mux_sid(struct cbl_sctp_mux *m, int fd, const void *frame,
	    size_t len);
int	cbl_sctp_mux_bytes(cbl_conn *conn, struct cbl_sctp_mux *m, uint16_t sid,
	    const void *data, size_t n);

void	cbl_conn_rx_message(cbl_conn *conn, const void *buf, size_t len);
bool	cbl_conn_bad_header(cbl_conn *conn, int error, const struct cbl_hdr *h);

int	cbl_tls_attach(cbl_conn *conn, cbl_tls *tls, bool server);

/* The PROXY protocol header of an accepted connection (cbl_proxy.c). */
int	cbl_proxy_read(cbl_conn *conn);
bool	cbl_proxy_allowed(const cbl_listener *l,
	    const struct sockaddr_storage *ss);

/* Outgoing frame queue entry. */
struct cbl_txent {
	STAILQ_ENTRY(cbl_txent)	 link;
	cbl_msg			*msg;
	size_t			 off;
};

/* Outstanding request issued by this endpoint. */
enum cbl_pend_kind {
	CBL_PEND_SYNC,
	CBL_PEND_ASYNC,
};

struct cbl_pending {
	RB_ENTRY(cbl_pending)	 link;
	/* Async: callbacks in progress + 1. */
	atomic_int		 refs;
	uint32_t		 seq;
	enum cbl_pend_kind	 kind;
	bool			 dump;
	bool			 done;
	int			 error;
	uint64_t		 deadline;
	cbl_msg			*reply;		/* sync: first reply or ERROR */
	cbl_reply_f		*cb;
	void			*arg;
};

RB_HEAD(cbl_pend_tree, cbl_pending);
RB_HEAD(cbl_stream_tree, cbl_stream);

enum cbl_conn_state {
	CBL_CS_NEW,
	CBL_CS_CONNECTING,	/* TCP connect or TLS handshake */
	CBL_CS_OPEN,
	CBL_CS_CLOSING,		/* flush, then close */
	CBL_CS_CLOSED,
};

struct cbl_conn {
	struct cbl_src			 src;
	pthread_mutex_t			 mtx;
	pthread_cond_t			 cv;
	atomic_uint			 refs;
	cbl_ctx				*ctx;
	struct cbl_limits		 lim;
	const struct cbl_tr_ops		*ops;
	void				*trpriv;
	cbl_tls				*tls;
	struct cbl_uri			 uri;
	uint32_t			 flags;
	enum cbl_conn_state		 state;
	bool				 initiator;
	bool				 counted;	/* in ctx->nconns */
	atomic_bool			 dead;		/* detached from loop */
	int				 fd;
	int				 error;
	char				 errstr[256];
	int				 want;		/* transport wants */

	/* Event loop attachment. */
	cbl_loop			*loop;
	LIST_ENTRY(cbl_conn)		 loop_link;
	TAILQ_ENTRY(cbl_conn)		 dead_link;
	int				 kq_events;
	uint64_t			 kq_deadline;
	bool				 kicked;

	/* Receive side. */
	unsigned char			*rx;
	size_t				 rx_start;
	size_t				 rx_end;
	size_t				 rx_cap;
	unsigned char			*big;
	size_t				 big_len;
	size_t				 big_have;
	size_t				 discard;	/* body bytes to skip */
	bool				 rx_pending;	/* frames in the ring */
	atomic_bool			 rx_paused;	/* tx queue backed up */
	/* Full client dump queues. */
	atomic_int			 rx_holds;
	atomic_uint_fast64_t		 rx_dropped;	/* messages dropped */

	/* Send side. */
	STAILQ_HEAD(, cbl_txent)	 txq;
	size_t				 txq_bytes;
	size_t				 txq_frames;

	/* Requests issued by this endpoint. */
	uint32_t			 next_seq;
	struct cbl_pend_tree		 pending;
	uint32_t			 npending;

	/* Notifications. */
	struct cbl_member_list		 memberships;	/* ctx->submtx */
	LIST_HEAD(, cbl_sub)		 subs;		/* conn->mtx */
	bool				 ntf_missed;
	atomic_uint_fast64_t		 ntf_dropped;

	/* Streams. */
	struct cbl_stream_tree		 streams;
	uint32_t			 nstreams;
	uint32_t			 next_stream_id;
	/* The highest seen. */
	uint32_t			 peer_stream_id;
	/* Highest never-opened id answered with S_RESET, per parity. */
	uint32_t			 unknown_reset[2];
	TAILQ_HEAD(, cbl_stream)	 ended;		/* deferred on_close */

	/* Requests received and not yet completed. */
	atomic_uint			 inflight;
	TAILQ_HEAD(, cbl_req)		 dumps;	/* throttled dumps */
	TAILQ_HEAD(, cbl_req)		 deferred;	/* conn->mtx */

	/* Timers. */
	uint64_t			 open_deadline;
	/* For CBL_CS_CLOSING. */
	uint64_t			 close_deadline;
	/* Nearest request and stream deadlines, cached; conn->mtx. */
	uint64_t			 pend_next;
	uint64_t			 strm_next;
	bool				 pend_dirty;
	bool				 strm_dirty;
	uint64_t			 last_rx;	/* last frame read */
	uint64_t			 last_tx;	/* last frame written */
	bool				 ka_pending;	/* keepalive ping out */
	/* CBL_CF_NONBLOCK client: connect(2) to uri.addr[next_addr - 1]. */
	int				 next_addr;
	bool				 tcp_pending;
	bool				 tls_after_tcp;

	struct cbl_peer			 peer;
	uint64_t			 peer_max_frame;	/* from hello */
	/* A PROXY header still to read (CBL_LF_PROXY), and what has come. */
	bool				 proxy_wait;
	unsigned char			*proxy_buf;
	size_t				 proxy_len;
	void				*udata;
};

int	cbl_conn_alloc(cbl_ctx *ctx, const struct cbl_limits *lim,
	    cbl_conn **connp);
void	cbl_conn_ref(cbl_conn *conn);
void	cbl_conn_rele(cbl_conn *conn);
int	cbl_conn_seterr(cbl_conn *conn, int error, const char *fmt, ...)
	    __printflike(3, 4);
int	cbl_conn_enqueue(cbl_conn *conn, cbl_msg *msg);
uint64_t cbl_conn_wants(cbl_conn *conn, int *eventsp);
int	cbl_conn_enqueue_ctl(cbl_conn *conn, cbl_msg *msg);
void	cbl_conn_rx_hold(cbl_conn *conn, bool hold);
void	cbl_conn_fail(cbl_conn *conn, int error);
void	cbl_conn_accepted(cbl_conn *conn);
void	cbl_conn_opened(cbl_conn *conn);
bool	cbl_conn_io_thread(const cbl_conn *conn);

/*
 * The loop of a live connection, or NULL: no loop, or the connection is
 * dead and its loop may be gone already.  conn->loop itself never changes
 * once set; code that may run on any thread asks here.
 */
static inline cbl_loop *
cbl_conn_loop(const cbl_conn *conn)
{

	return (atomic_load(&conn->dead) ? NULL : conn->loop);
}
int	cbl_conn_send_error(cbl_conn *conn, const struct cbl_hdr *h,
	    int code, const char *text);
int	cbl_conn_wait(cbl_conn *conn, bool (*cond)(void *), void *arg);

/* Server-side dispatch of incoming requests (cbl_server.c). */
void	cbl_server_dispatch(cbl_conn *conn, cbl_msg *msg);
void	cbl_server_resume(cbl_conn *conn);
bool	cbl_server_dump_ready(cbl_conn *conn);
void	cbl_server_abort(cbl_conn *conn);
void	cbl_server_stream_open(cbl_req *req);

/* Streams (cbl_stream.c). */
enum cbl_stream_state {
	CBL_SS_OPENING,		/* open sent or received, not accepted */
	CBL_SS_OPEN,
	CBL_SS_CLOSING,		/* our S_CLOSE sent, waiting for the peer's */
	CBL_SS_DONE,
};

struct cbl_stream {
	RB_ENTRY(cbl_stream)	 link;
	TAILQ_ENTRY(cbl_stream)	 done_link;
	cbl_conn		*conn;
	/* The library's + cbl_stream_ref(). */
	atomic_int		 refs;
	uint32_t		 id;
	uint16_t		 family;
	uint16_t		 cmd;
	uint32_t		 open_seq;
	bool			 local;		/* we opened it */
	bool			 push;		/* opener never sends data */
	bool			 accepted;
	enum cbl_stream_state	 state;
	bool			 tx_hclosed;
	bool			 rx_hclosed;
	bool			 blocked;	/* a send hit zero credit */
	bool			 ending;	/* final callback deferred */
	int			 close_code;
	char			*close_text;
	uint64_t		 tx_credit;
	uint64_t		 rx_window;
	uint64_t		 rx_unacked;	/* consumed, not yet granted */
	uint64_t		 window;		/* our initial window */
	uint32_t		 flags;		/* CBL_SF_* */
	uint64_t		 deadline;
	struct cbl_stream_cbs	 cbs;
	void			*arg;
};

void	cbl_stream_rx(cbl_conn *conn, cbl_msg *msg);
void	cbl_stream_rx_malformed(cbl_conn *conn, const struct cbl_hdr *h,
	    int error);
void	cbl_stream_reap(cbl_conn *conn);
void	cbl_stream_conn_closed(cbl_conn *conn, int error);
uint64_t cbl_stream_expire(cbl_conn *conn, uint64_t now);
uint64_t cbl_stream_next_deadline(cbl_conn *conn);
int	cbl_stream_server_open(cbl_req *req, cbl_conn *conn, cbl_msg *msg,
	    bool push);
int	cbl_stream_settle(cbl_stream *s, int error);

/* Listener. */
#define	CBL_PROXY_NETS	16

struct cbl_listener {
	struct cbl_src		 src;
	cbl_ctx			*ctx;
	pthread_mutex_t		 mtx;		/* tls, once started */
	cbl_tls			*tls;
	mode_t			 unix_mode;	/* 0: default */
	uid_t			 unix_uid;
	gid_t			 unix_gid;
	struct cbl_limits	 lim;
	struct cbl_uri		 uri;
	uint32_t		 flags;
	int			 fd;
	cbl_loop		*loop;
	bool			 started;
	/* Chosen by cbl_listener_start(). */
	bool			 use_tls;
	/* CBL_LF_PROXY: who may send the header (none: anyone). */
	struct cbl_proxy_net {
		int		 family;
		unsigned char	 addr[16];
		int		 bits;
	}			 proxies[CBL_PROXY_NETS];
	int			 nproxies;
	char			 errstr[256];
};

/* Socket helpers. */
int	cbl_sock_nonblock(int fd);
int	cbl_sock_connect(cbl_conn *conn);
int	cbl_sock_connect_done(cbl_conn *conn);

#endif /* !_CBL_IMPL_H_ */
