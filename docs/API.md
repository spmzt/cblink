# libcblink API

The shape of `<cblink.h>` in cblink 0.1.0: the types, the functions and
the rules for using them across threads. The header itself has the exact
prototypes. For the protocol, see WIRE-FORMAT.md.

## 0. Conventions

- **One public header:** `#include <cblink.h>`. It includes only `<stdbool.h>`,
  `<stddef.h>`, `<stdint.h>`, `<sys/types.h>` and `<sys/socket.h>`. No
  libcbor or OpenSSL type appears in it.
- **Prefix:** `cbl_` for functions and types, and `CBL_` for macros and
  enumerators.
- **Opaque types**, all declared as `typedef struct cbl_x cbl_x;`:

  | Type           | What it is |
  |----------------|------------|
  | `cbl_ctx`      | Shared configuration, limits, family registry, TLS settings. Thread-safe. |
  | `cbl_loop`     | A kqueue event loop. Run by one thread at a time. |
  | `cbl_listener` | A listening socket bound to a loop. |
  | `cbl_conn`     | A connection or association (TCP, SCTP, AF_UNIX). |
  | `cbl_tls`      | A TLS/DTLS configuration (certificates, CA, CRL, names). |
  | `cbl_msg`      | A message being built or received. Owns its arena. |
  | `cbl_attr`     | A read-only handle to one decoded attribute inside a `cbl_msg`. |
  | `cbl_family`   | A registered family. |
  | `cbl_req`      | Server-side context of one incoming request. |
  | `cbl_stream`   | A stream. |
  | `cbl_dump`     | A client-side dump iterator. |
  | `cbl_sub`      | A client-side multicast subscription. |
  | `cbl_peer`     | A verified peer identity (read-only). |
  | `cbl_timer`    | A loop timer. |

- **Errors are errno-style.** Every function that can fail returns `int`:
  `0` on success, or a positive `errno` value on failure. Objects are
  returned through out-parameters. No function sets `errno` as its only
  error report. Extended details are attached to the object involved, not
  kept in global or thread-local state:
  - for a failed request, the returned `ERROR` message itself
    (`cbl_msg_err_*()`, section 6);
  - for a builder error, `cbl_msg_errstr(msg)`;
  - for connection and listener errors, `cbl_conn_errstr(conn)` and
    `cbl_listener_errstr(l)`;
  - for context configuration errors, an optional
    `char *errbuf, size_t errlen` pair on the functions that parse files.
- **Sending consumes the message.** A function that sends a `cbl_msg`
  (`cbl_request()`, `cbl_request_async()`, `cbl_req_send()`,
  `cbl_notify()`, `cbl_stream_send()`, ...) takes ownership of it, also
  when it fails. The one exception is `cbl_stream_send()` returning
  `EAGAIN` (no credit): the message stays the caller's, to send again from
  `on_writable` or to free.
- **No global mutable state.** Everything hangs off a `cbl_ctx`. OpenSSL is
  initialized implicitly; it is thread-safe in OpenSSL 3.

## 1. Threading model

- `cbl_ctx` is fully thread-safe. The family registry uses a read-write lock,
  so families can be registered and unregistered at any time from any
  thread. Limit setters may be called only until the first
  `cbl_listener_start()` or `cbl_conn_connect()` on that context. Later
  calls return `EBUSY`, so connection code never takes locks on limits.
  A `cbl_tls` can be changed and reloaded at any time (section 2).
- `cbl_ctx_free()` returns `EBUSY` while a loop, listener or connection
  made from the context still exists.
- `cbl_loop` is single-threaded: `cbl_loop_run()` must not be called from
  two threads at once. An application that wants N threads creates N loops
  on one context. To spread accepts, it creates one listener per loop on
  the same address with `CBL_LF_REUSEPORT`, which uses
  `SO_REUSEPORT_LB`.
- A `cbl_conn`, `cbl_stream` or `cbl_req` belongs to the loop that runs it.
  Handlers and callbacks always run on that loop's thread.
- **Cross-thread entry points** are explicitly documented as thread-safe:
  - `cbl_conn_send()`, `cbl_stream_send()`, `cbl_req_send()` and
    `cbl_req_complete()` queue the message under the connection mutex and
    wake the loop through `EVFILT_USER`;
  - `cbl_conn_close()` and `cbl_conn_free()`, which hand the work to the
    loop thread;
  - `cbl_stream_ref()`, `cbl_stream_rele()`, `cbl_req_cancelled()`,
    `cbl_conn_stats()`, `cbl_tls_reload()` and `cbl_listener_set_tls()`;
  - `cbl_notify()`;
  - `cbl_loop_post()` and `cbl_loop_stop()`;
  - `cbl_ctx_*` registry calls.
- **Synchronous client calls**, such as `cbl_request()`:
  - On a connection **not** attached to a loop, the call drives the
    socket itself. This is the simple blocking client, like snl(3).
  - On a connection attached to a loop that another thread is running,
    the call queues the request and waits on a condition variable.
  - Calling a synchronous function **from that connection's own loop
    thread** returns `EDEADLK`. The asynchronous forms work there:
    `cbl_request_async()`, `cbl_resolve_async()`, `cbl_subscribe_async()`
    and the generated `P_op_async()` wrappers.
- A `cbl_msg` is not thread-safe while it is being built. Once sent, it
  belongs to the library.

## 2. Context, limits, TLS

```c
int	cbl_ctx_new(cbl_ctx **ctxp);
int	cbl_ctx_free(cbl_ctx *ctx);	/* EBUSY while loops, listeners or conns use it */

enum cbl_limit {
	CBL_LIM_MAX_FRAME, CBL_LIM_MAX_DEPTH, CBL_LIM_MAX_ATTRS,
	CBL_LIM_MAX_STREAMS, CBL_LIM_STREAM_WINDOW,
	CBL_LIM_MAX_INFLIGHT, CBL_LIM_SENDQ_BYTES, CBL_LIM_MAX_CONNS,
	CBL_LIM_HANDSHAKE_MS, CBL_LIM_IDLE_MS, CBL_LIM_STREAM_CLOSE_MS,
	CBL_LIM_REQUEST_MS,		/* default sync request timeout */
};
int	cbl_ctx_set_limit(cbl_ctx *, enum cbl_limit, uint64_t);	/* EINVAL out of range */
int	cbl_ctx_get_limit(const cbl_ctx *, enum cbl_limit, uint64_t *);

int	cbl_tls_new(cbl_tls **);
void	cbl_tls_free(cbl_tls *);
int	cbl_tls_set_cert(cbl_tls *, const char *certfile, const char *keyfile);
int	cbl_tls_set_ca(cbl_tls *, const char *cafile, const char *capath);
int	cbl_tls_set_crl(cbl_tls *, const char *crlfile);
int	cbl_tls_set_peer_name(cbl_tls *, const char *name);	/* client: verify server SAN */
int	cbl_tls_set_verify_depth(cbl_tls *, int);
int	cbl_tls_reload(cbl_tls *);	/* reread files: new connections use them */
const char *cbl_tls_errstr(const cbl_tls *);
int	cbl_ctx_set_tls(cbl_ctx *, cbl_tls *);	/* default for listeners and conns */
```

TLS policy (SECURITY.md has the details):

- TCP uses TLS 1.3 only.
- SCTP uses DTLS 1.2. Base OpenSSL 3.5 has no DTLS 1.3. The cipher
  list is restricted to ECDHE with AEAD ciphers.
- A server always requires and verifies a client certificate
  (`SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`). A client always
  verifies the server certificate.
- The `cbl_tls_set_*()` setters may be called at any time. Contexts built
  already keep what they were built with; `cbl_tls_reload()` rebuilds
  them from the current settings and files (renewed certificates, a new
  CRL) for the connections made from then on, and changes nothing if any
  of them fails to build. Open connections keep their configuration.

## 3. Event loop and integration mode

```c
int	cbl_loop_new(cbl_ctx *, cbl_loop **);
void	cbl_loop_free(cbl_loop *);
int	cbl_loop_run(cbl_loop *);			/* until cbl_loop_stop() */
int	cbl_loop_run_once(cbl_loop *, int timeout_ms);	/* -1 = block */
int	cbl_loop_stop(cbl_loop *);			/* thread-safe; a stop before cbl_loop_run() starts is kept */
int	cbl_loop_fd(const cbl_loop *);			/* kqueue fd: poll for read */
int	cbl_loop_post(cbl_loop *, void (*fn)(void *), void *arg);	/* thread-safe */
/*
 * Timers belong to the loop thread.  A handle asked for (last argument
 * not NULL) stays valid until cbl_timer_cancel(), even after a one-shot
 * timer fired; without one, a one-shot timer is freed once it fires.
 * cbl_loop_signal() ignores the signal's default action until
 * cbl_loop_free() restores it.
 */
int	cbl_loop_timer(cbl_loop *, uint32_t ms, uint32_t flags /* CBL_TF_REPEAT */,
	    void (*fn)(cbl_timer *, void *), void *arg, cbl_timer **);
void	cbl_timer_cancel(cbl_timer *);
int	cbl_loop_signal(cbl_loop *, int sig, void (*fn)(int, void *), void *arg);
```

There are two levels of integration with a foreign event loop:

1. **Loop level.** A kqueue descriptor is itself pollable. Add
   `cbl_loop_fd()` to your own poll, select or kqueue. When it becomes
   readable, call `cbl_loop_run_once(loop, 0)`.
2. **Connection level, with no `cbl_loop` at all.** This is the mode the
   requirements ask for:

```c
#define	CBL_EV_READ	0x1
#define	CBL_EV_WRITE	0x2
int	cbl_conn_fd(const cbl_conn *);
int	cbl_conn_interest(cbl_conn *, int *events, int *timeout_ms);
int	cbl_conn_process(cbl_conn *, int revents);	/* revents 0 = timer tick */
int	cbl_listener_fd(const cbl_listener *);
int	cbl_listener_process(cbl_listener *, cbl_conn **newconn);	/* one accept */
```

`cbl_conn_process()` performs non-blocking I/O, runs TLS state machines,
dispatches complete frames to handlers and callbacks, and enforces timeouts.
It returns `0`, or an errno value when the connection has died; the
application then calls `cbl_conn_free()`. Afterwards, the application calls
`cbl_conn_interest()` again to learn which events and timeout to wait for
next.

## 4. Listeners and connections

Endpoints are given as URIs:

| URI                                        | Transport |
|--------------------------------------------|-----------|
| `tcp://host:port`, `tcp://[v6]:port`       | TCP (TLS 1.3 unless `CBL_PLAINTEXT`). |
| `sctp://h1[,h2…]:port`                     | SCTP one-to-one; several hosts means multihoming (`sctp_bindx`, `sctp_connectx`). DTLS 1.2/SCTP unless `CBL_PLAINTEXT`. |
| `unix:/path`                               | AF_UNIX `SOCK_STREAM`. Never TLS. |

```c
/* flags for listeners and connections */
#define	CBL_PLAINTEXT		0x0001	/* explicit opt-in: no TLS on tcp/sctp */
#define	CBL_LF_REUSEPORT	0x0002	/* SO_REUSEPORT_LB */
#define	CBL_LF_UNIX_TRUSTED	0x0004	/* AF_UNIX: treat peers as authenticated */
#define	CBL_LF_PROXY		0x0008	/* tcp listener: a PROXY protocol header comes first (TRANSPORTS.md) */
#define	CBL_CF_NONBLOCK		0x0100	/* cbl_conn_connect() returns EINPROGRESS */

int	cbl_listener_new(cbl_ctx *, const char *uri, uint32_t flags, cbl_listener **);
int	cbl_listener_set_tls(cbl_listener *, cbl_tls *);	/* also on a started TLS listener */
int	cbl_listener_add_proxy(cbl_listener *, const char *net);	/* CBL_LF_PROXY: "addr[/bits]" */
int	cbl_listener_set_limit(cbl_listener *, enum cbl_limit, uint64_t);
int	cbl_listener_set_unix_perm(cbl_listener *, mode_t, uid_t, gid_t);	/* AF_UNIX */
int	cbl_listener_start(cbl_listener *, cbl_loop *);	/* NULL loop: integration mode */
const char *cbl_listener_errstr(const cbl_listener *);
void	cbl_listener_free(cbl_listener *);

int	cbl_conn_new(cbl_ctx *, const char *uri, uint32_t flags, cbl_conn **);
int	cbl_conn_set_tls(cbl_conn *, cbl_tls *);
int	cbl_conn_set_limit(cbl_conn *, enum cbl_limit, uint64_t);
int	cbl_conn_connect(cbl_conn *);		/* blocking unless CBL_CF_NONBLOCK */
/*
 * CBL_CF_NONBLOCK: connect(2) and the TLS handshake are finished by
 * cbl_conn_process(), trying the resolved addresses in turn, so the
 * descriptor (cbl_conn_fd()) may change until the connection is open.
 * Name resolution, getaddrinfo(3), still blocks: pass an address to avoid it.
 */
int	cbl_conn_attach(cbl_conn *, cbl_loop *);
int	cbl_conn_close(cbl_conn *);		/* graceful: flush, TLS close_notify */
void	cbl_conn_free(cbl_conn *);
const char *cbl_conn_errstr(const cbl_conn *);
const cbl_peer *cbl_conn_peer(const cbl_conn *);
void	cbl_conn_set_udata(cbl_conn *, void *);
void	*cbl_conn_udata(const cbl_conn *);

struct cbl_conn_stats {
	uint64_t	rx_dropped;	/* messages dropped on receipt (SCTP) */
	uint64_t	ntf_dropped;	/* notifications lost: the peer was slow */
	size_t		txq_bytes, txq_frames;	/* queued for sending */
	uint32_t	inflight;	/* the peer's requests being handled */
	uint32_t	pending;	/* our requests waiting for an answer */
	uint32_t	streams;
	bool		rx_paused;	/* not reading: backpressure */
};
int	cbl_conn_stats(cbl_conn *, struct cbl_conn_stats *);	/* any thread */

/* server-side lifecycle callbacks (accepted conns) */
struct cbl_conn_cbs {
	void	(*on_open)(cbl_conn *, void *arg);
	void	(*on_close)(cbl_conn *, int error, void *arg);
};
int	cbl_ctx_set_conn_cbs(cbl_ctx *, const struct cbl_conn_cbs *, void *arg);
```

If a TCP or SCTP endpoint has neither TLS configured nor `CBL_PLAINTEXT`
set, `cbl_listener_start()` and `cbl_conn_connect()` fail with `EPERM`,
and the error string reads `"mTLS required: configure TLS or pass
CBL_PLAINTEXT"`.

## 5. Messages: building

```c
int	cbl_msg_new(cbl_ctx *, uint16_t family, uint16_t cmd, uint32_t flags, cbl_msg **);
void	cbl_msg_free(cbl_msg *);
void	*cbl_msg_alloc(cbl_msg *, size_t);	/* arena: freed with the message */
char	*cbl_msg_strdup(cbl_msg *, const char *);

int	cbl_put_uint(cbl_msg *, uint16_t type, uint64_t);
int	cbl_put_int(cbl_msg *, uint16_t type, int64_t);
int	cbl_put_bool(cbl_msg *, uint16_t type, bool);
int	cbl_put_flag(cbl_msg *, uint16_t type);
int	cbl_put_str(cbl_msg *, uint16_t type, const char *);
int	cbl_put_strn(cbl_msg *, uint16_t type, const char *, size_t);
int	cbl_put_bytes(cbl_msg *, uint16_t type, const void *, size_t);
int	cbl_put_double(cbl_msg *, uint16_t type, double);
int	cbl_put_null(cbl_msg *, uint16_t type);
int	cbl_put_attr(cbl_msg *, uint16_t type, const cbl_attr *);	/* copy a decoded subtree */

int	cbl_nest_start(cbl_msg *, uint16_t type);
int	cbl_nest_end(cbl_msg *);
int	cbl_array_start(cbl_msg *, uint16_t type);
int	cbl_array_end(cbl_msg *);
#define	CBL_ELEM	0	/* the "type" argument for an element inside an array */

const char *cbl_msg_errstr(const cbl_msg *);	/* sticky builder error */
```

- Builder errors are **sticky**, as with the snl(3) writer. After the first
  failure, further puts are no-ops that return the same error, and the send
  call fails with it too. A caller can therefore chain puts and check once.
  The failures are: exceeding `max_frame`, `max_depth` or `max_attrs`;
  unbalanced start/end; a non-`CBL_ELEM` type inside an array; a duplicate
  key in a map; `type == 0`.
- Encoding uses preferred serialization and definite lengths. A map or
  array header is reserved as one byte. On `_end`, the real count is
  written, and the contents are moved only when the count is 24 or more.
- Each message has its own **arena**, a chain of linear buffers like snl's
  `struct linear_buffer`. The encoded frame, decoded nodes and parse results
  all live in it. `cbl_msg_free()` releases everything at once.

## 6. Messages: receiving and reading

```c
uint16_t cbl_msg_family(const cbl_msg *);
uint16_t cbl_msg_cmd(const cbl_msg *);
uint32_t cbl_msg_flags(const cbl_msg *);
uint32_t cbl_msg_seq(const cbl_msg *);
uint32_t cbl_msg_stream(const cbl_msg *);	/* group id for NOTIFY */
int	cbl_msg_ref(cbl_msg *);		/* keep a received msg past the callback */

const cbl_attr *cbl_msg_attr(const cbl_msg *, uint16_t type);	/* top level; NULL if absent */
const cbl_attr *cbl_attr_get(const cbl_attr *nest, uint16_t type);
const cbl_attr *cbl_attr_first(const cbl_attr *container);	/* iterate map or array */
const cbl_attr *cbl_attr_next(const cbl_attr *);
uint16_t cbl_attr_type(const cbl_attr *);	/* key in parent map; 0 in arrays */
enum cbl_kind cbl_attr_kind(const cbl_attr *);
size_t	cbl_attr_count(const cbl_attr *);	/* entries or elements */
int	cbl_attr_uint(const cbl_attr *, uint64_t *);	/* EINVAL wrong kind */
int	cbl_attr_int(const cbl_attr *, int64_t *);	/* ERANGE out of range */
int	cbl_attr_bool(const cbl_attr *, bool *);
int	cbl_attr_double(const cbl_attr *, double *);
int	cbl_attr_bytes(const cbl_attr *, const void **, size_t *);	/* zero-copy */
int	cbl_attr_str(cbl_msg *, const cbl_attr *, const char **);	/* NUL-terminated arena copy */

/* extended error (NLMSG_ERROR) accessors: valid on any received msg */
int	cbl_msg_err_code(const cbl_msg *);	/* ERROR, S_RESET, S_CLOSE; else 0 */
const char *cbl_msg_err_str(const cbl_msg *);	/* NULL if absent */
size_t	cbl_msg_err_path(const cbl_msg *, struct cbl_path_elem *, size_t max);
int	cbl_msg_err_miss_type(const cbl_msg *);	/* -1 if absent */
int	cbl_msg_err_cookie(const cbl_msg *, const void **, size_t *);

/* raw frame helpers (tests, fuzzers, custom transports) */
int	cbl_frame_decode(cbl_ctx *, const void *buf, size_t len, size_t *used, cbl_msg **);
int	cbl_msg_encode(cbl_msg *, const void **frame, size_t *len);
```

Within a map, attributes are kept in key order after decoding, so lookups
use binary search.

## 7. Policies (nla_policy)

```c
enum cbl_kind {
	CBL_K_ANY, CBL_K_UINT, CBL_K_INT, CBL_K_BOOL, CBL_K_FLAG,
	CBL_K_TEXT, CBL_K_BYTES, CBL_K_FLOAT, CBL_K_NEST, CBL_K_NULL,
};
#define	CBL_PF_REQUIRED	0x01	/* missing -> EINVAL + MISS_TYPE */
#define	CBL_PF_MULTI	0x02	/* value is an array of `kind` */
#define	CBL_PF_MASK	0x04	/* uint: value & ~u.max must be 0 (flag sets) */

struct cbl_policy {
	uint16_t	type;		/* attribute key */
	uint8_t		kind;		/* enum cbl_kind */
	uint8_t		flags;		/* CBL_PF_* */
	uint32_t	min_count;	/* CBL_PF_MULTI: element count range */
	uint32_t	max_count;	/*   0 = no limit (max_attrs still applies) */
	union {
		struct { uint64_t min, max; } u;	/* CBL_K_UINT */
		struct { int64_t min, max; } i;		/* CBL_K_INT */
		struct { uint32_t min, max; } len;	/* TEXT, BYTES: byte length */
		const struct cbl_policy_set *nested;	/* CBL_K_NEST */
		const struct cbl_enum *values;		/* UINT with an enum */
	};
	int	(*validate)(const cbl_attr *, void *arg, cbl_msg *err);	/* optional */
	void	*arg;
};
struct cbl_policy_set {
	const struct cbl_policy	*p;	/* sorted by type (verified at register) */
	uint32_t		n;
	uint16_t		maxtype;
};
#define	CBL_POLICY_SET(name, arr)	/* static const struct cbl_policy_set name = ... */

int	cbl_validate(const cbl_msg *, const cbl_attr *nest_or_NULL,
	    const struct cbl_policy_set *, cbl_msg *errout);
```

The framework runs `cbl_validate()` on the request against the op's policy
**before** calling the handler. On failure it sends the `ERROR` frame with
`CODE`, `MSG`, `PATH` and `MISS_TYPE` filled in, and the handler is never
called. Attributes that are not in the policy are ignored (WIRE-FORMAT.md
section 5.4).

## 8. Declarative parsers (snl-style)

```c
typedef int cbl_parse_attr_f(cbl_msg *, const cbl_attr *, const void *arg, void *target);
typedef int cbl_parse_post_f(cbl_msg *, void *target);

struct cbl_attr_parser {
	uint16_t		type;	/* sorted ascending */
	uint32_t		off;	/* offsetof(target struct, field) */
	cbl_parse_attr_f	*cb;
	const void		*arg;
};
struct cbl_parser {
	uint32_t			out_size;	/* for nested allocations */
	uint32_t			np_size;
	const struct cbl_attr_parser	*np;
	cbl_parse_post_f		*post;
};
#define	CBL_DECLARE_PARSER(name, type_t, np, post)	/* static const struct cbl_parser */

int	cbl_parse(cbl_msg *, const struct cbl_parser *, void *target);	/* body */
int	cbl_parse_nest(cbl_msg *, const cbl_attr *, const struct cbl_parser *, void *target);

/* stock callbacks; target field types in comments */
cbl_parse_attr_f cbl_get_u8, cbl_get_u16, cbl_get_u32, cbl_get_u64;	/* uintN_t */
cbl_parse_attr_f cbl_get_s8, cbl_get_s16, cbl_get_s32, cbl_get_s64;	/* intN_t */
cbl_parse_attr_f cbl_get_bool, cbl_get_flag;		/* bool */
cbl_parse_attr_f cbl_get_double;			/* double */
cbl_parse_attr_f cbl_get_str;		/* const char * (arena copy) */
cbl_parse_attr_f cbl_get_bytes;		/* struct cbl_bytes { const void *p; size_t len; } */
cbl_parse_attr_f cbl_get_attr;		/* const cbl_attr * */
cbl_parse_attr_f cbl_get_nested;	/* embedded struct; arg = const struct cbl_parser * */
cbl_parse_attr_f cbl_get_nested_ptr;	/* struct * in arena; arg = parser */
cbl_parse_attr_f cbl_get_array;		/* struct cbl_array { size_t n; void *v; }; arg = elem desc */
struct cbl_array_desc { cbl_parse_attr_f *cb; const void *arg; uint32_t elem_size; };
```

Usage mirrors snl(3). A hand-written example:

```c
struct kv_entry { const char *key; struct cbl_bytes value; uint32_t ttl; };
#define	_OUT(f)	offsetof(struct kv_entry, f)
static const struct cbl_attr_parser kv_entry_np[] = {
	{ .type = KV_A_KEY,   .off = _OUT(key),   .cb = cbl_get_str },
	{ .type = KV_A_VALUE, .off = _OUT(value), .cb = cbl_get_bytes },
	{ .type = KV_A_TTL,   .off = _OUT(ttl),   .cb = cbl_get_u32 },
};
#undef _OUT
CBL_DECLARE_PARSER(kv_entry_parser, struct kv_entry, kv_entry_np, NULL);

struct kv_entry e = {};
error = cbl_parse(reply, &kv_entry_parser, &e);
```

## 9. Families (server side, and client side for symmetric use)

```c
#define	CBL_OPF_DO	0x01
#define	CBL_OPF_DUMP	0x02
#define	CBL_OPF_STREAM	0x04	/* opens a bidirectional stream */
#define	CBL_OPF_PUSH	0x08	/* opens a server-to-client stream */
#define	CBL_OPF_AUTH	0x10	/* requires an authenticated peer, else EACCES */

typedef int cbl_doit_f(cbl_req *, const cbl_msg *, void *arg);
typedef int cbl_dumpit_f(cbl_req *, const cbl_msg *, struct cbl_dump_state *, void *arg);
typedef int cbl_stream_open_f(cbl_req *, const cbl_msg *, cbl_stream *, void *arg);

struct cbl_dump_state { uint64_t pos[4]; void *priv; void (*priv_free)(void *); };

struct cbl_op {
	uint16_t			cmd;
	uint32_t			flags;		/* CBL_OPF_* */
	const char			*name;		/* for ctrl getfamily */
	const struct cbl_policy_set	*policy;	/* request policy; NULL = accept all */
	cbl_doit_f			*doit;
	cbl_dumpit_f			*dumpit;
	cbl_stream_open_f		*stream_open;
};
#define	CBL_MCF_AUTH	0x10
struct cbl_mcgrp { const char *name; uint32_t flags; };

#define	CBL_FAMILY_ABI	1
struct cbl_family_def {
	uint32_t			abi;		/* = CBL_FAMILY_ABI */
	const char			*name;
	uint32_t			version;
	const struct cbl_op		*ops;		/* sorted by cmd */
	uint32_t			nops;
	const struct cbl_mcgrp		*mcgrps;
	uint32_t			nmcgrps;
};

int	cbl_family_register(cbl_ctx *, const struct cbl_family_def *, void *arg, cbl_family **);
int	cbl_family_unregister(cbl_family *);	/* waits for in-flight handlers */
uint16_t cbl_family_id(const cbl_family *);
uint32_t cbl_family_group_id(const cbl_family *, uint32_t idx);
```

Handler return conventions:

- `doit` returns `0` (the framework sends an ack if one was requested) or an
  errno value (the framework sends `ERROR`, together with any details set
  through `cbl_req_set_err()`).
- To answer later, possibly from another thread and out of order, call
  `cbl_req_defer(req)` and return `0`. Then call
  `cbl_req_complete(req, error)` exactly once.
  - If the connection goes away first, the request is cancelled:
    `cbl_req_cancelled()` turns true, and the callback set with
    `cbl_req_set_cancel()` runs on the loop thread, so the work can stop.
    `cbl_req_complete()` is still needed, to release the request.
  - A `stream_open` handler may defer too. The open is then accepted with
    `cbl_stream_accept()`, from any thread, followed by
    `cbl_req_complete(req, 0)`; `cbl_req_complete()` with an error, or
    without an accept, refuses it.
- `dumpit` is called repeatedly. On each call it appends items with
  `cbl_req_dump_item()`. It returns `EAGAIN` to be called again once the
  connection's send queue has drained below its threshold (backpressure),
  or for its next turn (a dump runs 64 parts at a time, so others get a
  turn too),
  `0` when finished (the framework sends `DONE`), or an errno value (the
  framework sends `ERROR|MULTI|DONE`). The `state` cursor persists between
  calls, like `netlink_callback->args`.

```c
int	cbl_req_reply_new(cbl_req *, uint16_t cmd, cbl_msg **);	/* pre-filled seq/family */
int	cbl_req_send(cbl_req *, cbl_msg *);			/* thread-safe */
int	cbl_req_dump_item(cbl_req *, cbl_msg **);		/* new MULTI part builder */
int	cbl_req_set_err(cbl_req *, const char *msg, const struct cbl_path_elem *, size_t,
	    int miss_type);
int	cbl_req_set_cookie(cbl_req *, const void *, size_t);
int	cbl_req_defer(cbl_req *);
int	cbl_req_complete(cbl_req *, int error);			/* thread-safe */
int	cbl_req_set_cancel(cbl_req *, void (*)(cbl_req *, void *), void *arg);
bool	cbl_req_cancelled(const cbl_req *);			/* thread-safe */
const cbl_peer *cbl_req_peer(const cbl_req *);
cbl_conn *cbl_req_conn(const cbl_req *);

int	cbl_notify(cbl_family *, uint32_t group_idx, cbl_msg *);	/* thread-safe broadcast */
int	cbl_conn_notify(cbl_conn *, cbl_family *, uint32_t group_idx, cbl_msg *); /* unicast */
```

## 10. Peer identity (same for every transport)

```c
#define	CBL_PEER_AUTHENTICATED	0x01	/* verified client certificate */
#define	CBL_PEER_LOCAL		0x02	/* AF_UNIX: uid/gid valid */
#define	CBL_PEER_PROXIED	0x04	/* address from a PROXY protocol header */

enum cbl_transport { CBL_TR_TCP, CBL_TR_SCTP, CBL_TR_UNIX };

uint32_t	cbl_peer_flags(const cbl_peer *);
enum cbl_transport cbl_peer_transport(const cbl_peer *);
const char	*cbl_peer_subject(const cbl_peer *);	/* RFC 2253, NULL if none */
const char	*cbl_peer_issuer(const cbl_peer *);
size_t		 cbl_peer_san_count(const cbl_peer *);
const char	*cbl_peer_san(const cbl_peer *, size_t i);	/* "DNS:x", "URI:x", "IP:x", "email:x" */
int		 cbl_peer_fingerprint(const cbl_peer *, const char *alg /* "sha256" */,
		    uint8_t *, size_t *);
int		 cbl_peer_addr(const cbl_peer *, struct sockaddr_storage *, socklen_t *);
int		 cbl_peer_cred(const cbl_peer *, uid_t *, gid_t *);	/* AF_UNIX via getpeereid(3) */
```

`CBL_OPF_AUTH` passes if and only if `CBL_PEER_AUTHENTICATED` is set.
- On direct transports, this means mTLS succeeded.
- On AF_UNIX, the flag is never set. Applications authorize on
  `cbl_peer_cred()`, or pass `CBL_LF_UNIX_TRUSTED`, which marks every
  AF_UNIX peer authenticated so that filesystem permissions alone decide.

## 11. Client API

```c
/* synchronous; always sets ACK; *reply is the first reply, or the ERROR msg */
int	cbl_request(cbl_conn *, cbl_msg *req, cbl_msg **reply, int timeout_ms);
/* asynchronous: cb runs once per reply/part, then once with the terminal frame */
typedef void cbl_reply_f(cbl_conn *, const cbl_msg *reply, bool final, int error, void *arg);
int	cbl_request_async(cbl_conn *, cbl_msg *req, cbl_reply_f *, void *arg);
int	cbl_conn_send(cbl_conn *, cbl_msg *);	/* raw send, no tracking; thread-safe */

int	cbl_dump_start(cbl_conn *, cbl_msg *req, cbl_dump **);
int	cbl_dump_next(cbl_dump *, const cbl_msg **item);	/* *item NULL at DONE */
const cbl_msg *cbl_dump_error(const cbl_dump *);	/* ERROR frame if it failed */
void	cbl_dump_free(cbl_dump *);
/*
 * A dump buffers up to sendq_bytes of parts; then the connection stops
 * reading until the consumer has taken half of them, so a slow consumer
 * slows the server down instead of losing the dump.
 */

/* control family wrappers (built on the generated cbl_ctrl_* code) */
struct cbl_family_info;	/* opaque */
int	cbl_resolve(cbl_conn *, const char *family, struct cbl_family_info **);
/* the same from a loop callback: cb owns "info" */
typedef void cbl_resolve_f(cbl_conn *, int error, struct cbl_family_info *info, void *arg);
int	cbl_resolve_async(cbl_conn *, const char *family, cbl_resolve_f *, void *arg);
uint16_t cbl_family_info_id(const struct cbl_family_info *);
uint32_t cbl_family_info_version(const struct cbl_family_info *);
int	cbl_family_info_group(const struct cbl_family_info *, const char *name, uint32_t *id);
int	cbl_family_info_op(const struct cbl_family_info *, uint16_t cmd, uint32_t *flags);
void	cbl_family_info_free(struct cbl_family_info *);
int	cbl_hello(cbl_conn *);		/* exchange limits */
int	cbl_ping(cbl_conn *, int timeout_ms);

typedef void cbl_notify_f(cbl_conn *, const cbl_msg *, void *arg);
int	cbl_subscribe(cbl_conn *, const char *family, const char *group,
	    cbl_notify_f *, void *arg, cbl_sub **);
typedef void cbl_subscribed_f(cbl_conn *, int error, cbl_sub *, void *arg);
int	cbl_subscribe_async(cbl_conn *, const char *family, const char *group,
	    cbl_notify_f *, void *arg, cbl_subscribed_f *done, void *done_arg);
int	cbl_subscribe_id_async(cbl_conn *, uint16_t family, uint32_t group,
	    cbl_notify_f *, void *arg, cbl_subscribed_f *done, void *done_arg);
int	cbl_unsubscribe(cbl_sub *);
```

Unsolicited frames arriving at a client are handled as follows:
- **Requests** are dispatched to families registered on the client's
  context, exactly as on a server.
- **Notifications** go to the matching subscription callback.
- Anything else is counted and dropped.

## 12. Streams

```c
struct cbl_stream_cbs {
	void	(*on_open)(cbl_stream *, const cbl_msg *accept, int error, void *arg);
	void	(*on_data)(cbl_stream *, const cbl_msg *data, void *arg);
	void	(*on_hclose)(cbl_stream *, void *arg);	/* peer half-closed */
	void	(*on_close)(cbl_stream *, int code, const char *msg, void *arg);	/* closed or reset */
	void	(*on_writable)(cbl_stream *, size_t credit, void *arg);
};
#define	CBL_SF_MANUAL_CREDIT	0x01	/* app calls cbl_stream_consumed() */

int	cbl_stream_open(cbl_conn *, cbl_msg *open_req, uint32_t flags,
	    const struct cbl_stream_cbs *, void *arg, cbl_stream **);
int	cbl_stream_accept(cbl_stream *, cbl_msg *accept_or_NULL, uint32_t flags,
	    const struct cbl_stream_cbs *, void *arg);	/* in stream_open, or later if deferred */
int	cbl_stream_msg_new(cbl_stream *, cbl_msg **);	/* S_DATA builder */
int	cbl_stream_send(cbl_stream *, cbl_msg *);	/* EAGAIN if no credit; thread-safe */
size_t	cbl_stream_credit(const cbl_stream *);
int	cbl_stream_consumed(cbl_stream *, size_t bytes);	/* manual credit */
int	cbl_stream_half_close(cbl_stream *);
int	cbl_stream_close(cbl_stream *, int code, const char *reason);
int	cbl_stream_reset(cbl_stream *, int code);
uint32_t cbl_stream_id(const cbl_stream *);
/* keep a stream past on_close (other threads): calls then give EPIPE */
void	cbl_stream_ref(cbl_stream *);
void	cbl_stream_rele(cbl_stream *);
```

With automatic credit (the default), the library grants credit back once
`on_data` returns. It sends `S_CREDIT` when at least half the window has
been consumed. With `CBL_SF_MANUAL_CREDIT`, credit is returned only by
`cbl_stream_consumed()`. This lets the application apply backpressure all
the way to the sender.

## 13. Versioning and ABI policy

- The shared library is `libcblink.so.1` (`SHLIB_MAJOR=1`). Symbols are
  versioned with `Symbol.map` and `Versions.def` (bsd.symver.mk), starting at
  `CBLINK_1.0`.
- Adding functions is allowed within a major version; new symbols go in a
  new version node (`CBLINK_1.1`, …).
- Public structs are **tables**: `cbl_policy`, `cbl_attr_parser`, `cbl_op`,
  `cbl_family_def`, `cbl_stream_cbs`, `cbl_conn_cbs` and so on. They never
  change layout within a major version. `cbl_family_def.abi` lets the
  library recognise newer table layouts if the major version is bumped.
  Every other type is opaque.
- Enumerations and flag values are append-only.
- `cbl_version()` returns the run-time library version string. The header
  defines `CBLINK_VERSION_MAJOR`, `_MINOR` and `_PATCH`.
- Generated code records the version of `cblink-gen` that produced it.
  Generated code compiled against a header with a newer **major** version
  fails to compile (a `_Static_assert` in the generated `.c`).
