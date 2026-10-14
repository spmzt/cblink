# libcblink API

The shape of `<cblink.h>` in cblink 0.1.0: the types, the functions and
the rules for using them across threads. The header itself has the exact
prototypes. For the protocol, see WIRE-FORMAT.md.

## 0. Conventions

- **Two public headers:** `<cblink.h>`, the transport, messages and
  families, which includes only `<stdbool.h>`, `<stddef.h>`, `<stdint.h>`,
  `<sys/types.h>` and `<sys/socket.h>`; and `<cbl_schema.h>`, YANG: the
  schema tables, the YANG-CBOR codec and the YANG family (section 7). No
  libcbor or OpenSSL type appears in either.
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
  | `cbl_yarena`   | Where a YANG-CBOR decode puts what it allocates (`<cbl_schema.h>`). |
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
    `cbl_request_async()`, `cbl_resolve_async()` and
    `cbl_subscribe_async()`.
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

A version 2 body is one map whose top-level keys are SIDs (RFC 9595),
each a node's data in YANG-CBOR (RFC 9254). A program puts items by SID;
`cblink-gen` writes typed helpers over these for each struct (section 7).

```c
int	cbl_msg_new(cbl_ctx *, uint16_t family, uint16_t cmd, uint32_t flags, cbl_msg **);
void	cbl_msg_free(cbl_msg *);
int	cbl_msg_ref(cbl_msg *);		/* keep a received msg past the callback */

int	cbl_msg_put_sid_raw(cbl_msg *, uint64_t sid, const void *cbor, size_t len);

/* <cbl_schema.h> */
int	cbl_msg_put_ynode(cbl_msg *, const struct cbl_ynode *, const void *p);
int	cbl_msg_put_ymember(cbl_msg *, const struct cbl_ynode *, const void *parent);
int	cbl_msg_put_ynull(cbl_msg *, uint64_t sid);	/* in an EDIT: deleted */

/* an ERROR's, or an ack's, error and cookie: the cblink:error structure */
int	cbl_msg_put_error(cbl_msg *, int code, const char *text,
	    const struct cbl_path_elem *, size_t pathlen, int miss_type);
int	cbl_msg_put_cookie(cbl_msg *, const void *, size_t);

const char *cbl_msg_errstr(const cbl_msg *);	/* sticky builder error */
int	cbl_msg_error(const cbl_msg *);
```

- A SID is 1 to 2^63 − 1. `cbl_msg_put_ynode()` puts a node's own struct
  under its SID (an rpc's or an action's input and output under the rpc's
  or the action's, as CORECONF does); `cbl_msg_put_ymember()` a module's
  top-level node from the module's data struct (a container's pointer, a
  list's array, a leaf); `cbl_msg_put_sid_raw()` a value already encoded,
  one well-formed item that the receiver checks as it checks any body.
- Builder errors are **sticky**, as with the snl(3) writer. After the first
  failure, further puts are no-ops that return the same error, and the send
  call fails with it too. A caller can therefore chain puts and check once.
  The failures are: exceeding `max_frame` or `max_attrs`; a SID twice
  (`EEXIST`); a SID out of range; a put after the message was encoded.
- Encoding uses preferred serialization and definite lengths. The error
  structure is written last, as the message is encoded.
- Each message has its own **arena**, a chain of linear buffers like snl's
  `struct linear_buffer`. The encoded frame and the decoder's tree live in
  it. `cbl_msg_free()` releases everything at once.

## 6. Messages: receiving and reading

```c
uint16_t cbl_msg_family(const cbl_msg *);
uint16_t cbl_msg_cmd(const cbl_msg *);
uint32_t cbl_msg_flags(const cbl_msg *);
uint32_t cbl_msg_seq(const cbl_msg *);
uint32_t cbl_msg_stream(const cbl_msg *);	/* group id for NOTIFY */

int	cbl_msg_sid_raw(const cbl_msg *, uint64_t sid, const void **, size_t *);	/* ENOENT */

/* <cbl_schema.h>: decoded into the node's struct, what it points to a's */
int	cbl_msg_ydecode(const cbl_msg *, const struct cbl_ynode *, void *p,
	    cbl_yarena *a, int flags, char *why, size_t whylen);
int	cbl_msg_ydecode_member(const cbl_msg *, const struct cbl_ynode *, void *parent,
	    cbl_yarena *a, int flags, char *why, size_t whylen);

/* the cblink:error structure of a received msg: valid on any */
int	cbl_msg_err_code(const cbl_msg *);	/* errno: ERROR, S_RESET, S_CLOSE; else 0 */
const char *cbl_msg_err_str(const cbl_msg *);	/* NULL if absent */
size_t	cbl_msg_err_path(const cbl_msg *, struct cbl_path_elem *, size_t max);
int	cbl_msg_err_miss_type(const cbl_msg *);	/* missing-element: -1 if absent */
uint64_t cbl_msg_err_sid(const cbl_msg *);	/* the node at fault, family 1; 0 */
int	cbl_msg_err_cookie(const cbl_msg *, const void **, size_t *);

/* raw frame helpers (tests, fuzzers, custom transports) */
int	cbl_frame_decode(cbl_ctx *, const void *buf, size_t len, size_t *used, cbl_msg **);
int	cbl_msg_encode(cbl_msg *, const void **frame, size_t *len);
```

Before a received message reaches the program, the decoder has checked
its whole body under the limits: definite lengths, integer keys, no key
twice in a map, valid UTF-8, YANG-CBOR's tags (4, 43 to 47) only on the
kinds of value they belong to. The top-level items are kept in SID
order, so `cbl_msg_sid_raw()` is a binary search. A top-level key that is
not a SID (0, negative, beyond 2^63 − 1) is taken and never found.

## 7. YANG: schema tables, codec, the YANG family

`<cbl_schema.h>` holds what a program speaks YANG with. `cblink-gen`
(GENERATOR.md) writes, from the program's modules, the structs (`-m h`),
the schema tables (`-m schema`) and the server's handler table
(`-m server`); YANG.md says what of YANG they cover.

```c
/* the tables: nodes by SID, types, identities, features */
struct cbl_yschema, struct cbl_ymodule, struct cbl_ynode, struct cbl_ytype,
    struct cbl_yident, struct cbl_yfeature;
const struct cbl_ynode *cbl_ynode_child(const struct cbl_ynode *, int64_t delta);
uint64_t cbl_ynode_base(const struct cbl_ynode *);	/* what its children's deltas are from */
const struct cbl_ynode *cbl_yschema_node(const struct cbl_yschema *, uint64_t sid);
const struct cbl_yident *cbl_yschema_ident(const struct cbl_yschema *, uint64_t sid);
bool	cbl_yderived_from(const struct cbl_yschema *, uint64_t ident, uint64_t base, bool self);

/* the codec: a node's struct as YANG-CBOR and back */
int	cbl_yencode(const struct cbl_ynode *, const void *p, struct cbl_ybuf *);
int	cbl_yencode_sid(const struct cbl_ynode *, const void *p, struct cbl_ybuf *);	/* {SID: value} */
int	cbl_yencode_member(const struct cbl_ynode *, const void *parent, struct cbl_ybuf *);
int	cbl_ydecode(const struct cbl_ynode *, const void *, size_t, void *p,
	    cbl_yarena *, int flags, char *why, size_t whylen);	/* CBL_YD_STRICT */
int	cbl_ydecode_member(const struct cbl_ynode *, const void *, size_t, void *parent,
	    cbl_yarena *, int flags, char *why, size_t whylen);
void	cbl_ybuf_free(struct cbl_ybuf *);
cbl_yarena *cbl_yarena_new(void);
void	*cbl_yarena_alloc(cbl_yarena *, size_t);	/* zeroed */
void	cbl_yarena_set_limit(cbl_yarena *, size_t);	/* 64 MiB by default */
void	cbl_yarena_free(cbl_yarena *);

/* family 1, "cblink.yang": a program's modules served by SID */
#define	CBL_YANG_FAMILY	1
enum cbl_ycmd { CBL_YCMD_GET = 1, CBL_YCMD_EDIT, CBL_YCMD_RPC, CBL_YCMD_NOTIFY,
    CBL_YCMD_GET_SID };
int	cbl_yserver_add(cbl_ctx *, const struct cbl_yserver *, void *arg);
void	*cbl_req_yarg(const cbl_req *);
int	cbl_req_set_yerr(cbl_req *, const char *text, uint64_t sid);
int	cbl_msg_put_yget(cbl_msg *, const uint64_t *sids, size_t n);

/* the static validator; defaults */
#define	CBL_YV_EDIT	0x0001	/* config false nodes refused */
struct cbl_yverr { const struct cbl_ynode *node; const char *tag, *apptag; char msg[160]; };
int	cbl_yvalidate(const struct cbl_ynode *, const void *p, int flags, struct cbl_yverr *);
int	cbl_yvalidate_member(const struct cbl_ynode *, const void *parent, int flags,
	    struct cbl_yverr *);
int	cbl_ydefaults(const struct cbl_ynode *, void *p, cbl_yarena *);

/* YANG notifications, to family 1's group "notify" */
int	cbl_ynotify(cbl_ctx *, const struct cbl_ynode *, const void *p);
struct cbl_ynotif { uint64_t sid; const char *event_time; const void *content; size_t len; };
int	cbl_msg_ynotif(const cbl_msg *, struct cbl_ynotif *, cbl_yarena *);
```

`<cbl_data.h>`, the instance tree: YANG data as nodes of the tables, for
what keeps data and works on it as YANG does (a datastore, an edit, a
diff, XPath), where the structs are what one handler fills or reads.

```c
cbl_dtree *cbl_dtree_new(const struct cbl_yschema *);	/* its root: no schema node */
void	cbl_dtree_free(cbl_dtree *);
cbl_dnode *cbl_dtree_root(const cbl_dtree *);
size_t	cbl_dtree_count(const cbl_dtree *);
/* walking: the children in schema order, entries as added */
const struct cbl_ynode *cbl_dnode_schema(const cbl_dnode *);
cbl_dnode *cbl_dnode_parent(const cbl_dnode *), *cbl_dnode_first(const cbl_dnode *),
    *cbl_dnode_last(const cbl_dnode *), *cbl_dnode_next(const cbl_dnode *),
    *cbl_dnode_prev(const cbl_dnode *);
const void *cbl_dnode_value(const cbl_dnode *);	/* as its struct member is */
/* making: EINVAL where the schema has it not, EEXIST a second */
int	cbl_dnode_add(cbl_dnode *parent, const struct cbl_ynode *, const void *value,
	    cbl_dnode **out);
int	cbl_dnode_add_entry(cbl_dnode *parent, const struct cbl_ynode *list,
	    const void *const *keys, cbl_dnode **out);
int	cbl_dnode_set(cbl_dnode *, const void *value);
int	cbl_dnode_remove(cbl_dnode *);
/* finding: a list's entries by their keys, from an index */
cbl_dnode *cbl_dnode_child(const cbl_dnode *, const struct cbl_ynode *);
cbl_dnode *cbl_dnode_entry(const cbl_dnode *parent, const struct cbl_ynode *list,
    const void *const *keys);
cbl_dnode *cbl_dnode_llentry(const cbl_dnode *parent, const struct cbl_ynode *,
    const void *value);
/* defaults: on demand, or made (CBL_DN_DEFAULT) */
const void *cbl_dnode_leaf(const cbl_dnode *, const struct cbl_ynode *leaf, bool *isdflt);
ssize_t	cbl_dtree_defaults(cbl_dnode *);
/* RFC 6243: CBL_WD_REPORT_ALL, CBL_WD_TRIM, CBL_WD_EXPLICIT */
int	cbl_dtree_with_defaults(cbl_dnode *, int mode);
/* the structs and YANG-CBOR */
int	cbl_dnode_from_struct(cbl_dnode *parent, const struct cbl_ynode *, const void *p,
	    cbl_dnode **out);
int	cbl_dnode_to_struct(const cbl_dnode *, void *p, cbl_yarena *);
int	cbl_dtree_from_module(cbl_dtree *, const struct cbl_ymodule *, const void *p);
int	cbl_dtree_to_module(const cbl_dtree *, const struct cbl_ymodule *, void *p,
	    cbl_yarena *);
int	cbl_dnode_decode(cbl_dnode *parent, const struct cbl_ynode *, const void *, size_t,
	    int flags, char *why, size_t whylen, cbl_dnode **out);
int	cbl_dnode_encode(const cbl_dnode *, struct cbl_ybuf *);
/* edits (RFC 6241 section 7.2): all or nothing */
#define	CBL_DOP_MERGE	1	/* and REPLACE, CREATE, DELETE, REMOVE; NONE, a default;
				   INSERT and MOVE, YANG Patch's */
int	cbl_dnode_set_op(cbl_dnode *, int op);	/* 0: its parent's */
#define	CBL_DWHERE_FIRST 1	/* and LAST, BEFORE, AFTER */
int	cbl_dnode_set_where(cbl_dnode *, int where, const void *const *point);
struct cbl_dederr { const cbl_dnode *node; const char *tag; char msg[160]; };
int	cbl_dtree_edit(cbl_dtree *target, const cbl_dtree *edit, int dflt,
	    struct cbl_dederr *);
/* the edit that makes a b, applied with none: a YANG Patch's changes */
cbl_dtree *cbl_dtree_diff(const cbl_dtree *a, const cbl_dtree *b);
/* leafrefs and instance-identifiers that require an instance: there? */
int	cbl_dtree_check_refs(const cbl_dtree *, struct cbl_dederr *);
/* every when and must: hold? */
int	cbl_dtree_check_conds(const cbl_dtree *, struct cbl_dederr *);
/* filters: what one selects, a tree of its own */
cbl_dtree *cbl_dtree_select(const cbl_dtree *, const cbl_dnode *const *, size_t);
cbl_dtree *cbl_dtree_filter_xpath(const cbl_dtree *, const char *expr,
	    char *why, size_t whylen);
cbl_dfilter *cbl_dfilter_new(const struct cbl_yschema *);
int	cbl_dfilter_add(cbl_dfnode *parent, const struct cbl_ynode *,
	    const void *value, cbl_dfnode **);	/* parent: cbl_dfilter_root() */
cbl_dtree *cbl_dtree_filter_subtree(const cbl_dtree *, const cbl_dfilter *);
/* a mount point's parent references, and the mounted tree given them */
cbl_dtree *cbl_dtree_parent_refs(const cbl_dtree *, const cbl_dnode *mp,
	    const char *const *exprs, size_t n, char *why, size_t whylen);
int	cbl_dtree_set_refs(cbl_dtree *mounted, const cbl_dtree *refs);
/* NACM's data-node rule paths: compiled once, matched against nodes */
cbl_dnacm_path *cbl_dnacm_path_new(const struct cbl_yschema *, const char *path,
	    char *why, size_t whylen);
bool	cbl_dnacm_path_match(const cbl_dnacm_path *, const cbl_dnode *,
	    const char *user);
bool	cbl_dnacm_path_match_schema(const cbl_dnacm_path *,
	    const struct cbl_ynode *);
/* XPath-lite: an expression as the tables hold one, over a tree */
struct cbl_xval { enum cbl_xv_kind kind; bool b; double num; char *s;
    const cbl_dnode **nodes; size_t n; };	/* NODES, BOOL, NUMBER, STRING */
int	cbl_xp_eval(const cbl_dtree *, const char *expr, const cbl_dnode *ctx,
	    const cbl_dnode *cur, struct cbl_xval *, char *why, size_t whylen);
void	cbl_xval_free(struct cbl_xval *);
```

- **A tree's shape** is kept: a node only where its schema node is, one
  container or leaf of a kind, one entry of a list's keys, a
  configuration leaf-list's values once, never two cases of a choice. A
  key is its entry's: neither set nor taken away alone. The rest of what
  the schema says is the validator's and the evaluator's.
- **Values** are held as their struct members are, the tree owning a
  copy of what they point to; `cbl_dnode_to_struct()` points into the
  tree. Through the structs, the codec reads and writes a tree: a value
  decoded, made a tree, and encoded again is the same bytes.
- **Defaults**: `cbl_dnode_leaf()` gives a leaf's default where it is
  in use and has no node, its case taken into account;
  `cbl_dtree_defaults()` makes a node of each, and of the non-presence
  containers that hold them; not of one under a `when` that does not
  hold, and it removes one made before. `cbl_dtree_with_defaults()`
  makes a subtree as RFC 6243's retrieval modes report it: report-all
  makes the defaults; explicit keeps what was set, by a client or the
  server, whatever its value, and takes the defaults made out; trim
  takes out too every leaf whose value is its default and a leaf-list
  whose values are its defaults (never a key). Both take out a
  non-presence container left empty. report-all-tagged waits for the
  codec's metadata.
- **Edits** are another tree of the schema, each node with an
  operation or its parent's: merge, replace, create (data-exists where
  the node is), delete (data-missing where it is not), remove; the
  default none changes nothing not asked for. A node of a choice's case
  takes the other cases' place; a replaced entry keeps its place. An
  ordered-by user list's entry, or leaf-list's value, goes where its
  edit says: first, last, or before or after another, by its keys or
  value (RFC 7950 section 7.8.6); YANG Patch's insert and move (RFC 8072)
  must say where, and a move's entry must be there.
- **References**: `cbl_dtree_check_refs()` finds the first leafref
  that requires an instance and has none of its value among its target
  node's (the tables name the target), or instance-identifier naming no
  node of the tree (read from its YANG-CBOR, found by its lists' keys):
  data-missing, instance-required. A leafref whose path has predicates
  is looked for among the nodes the path finds (`cbl_xp_eval()`).
- **Conditions**: `cbl_dtree_check_conds()` finds the first node whose
  `when`s do not all hold (its choices' and cases', an augment's or a
  uses', its own; each from its context node, the tree altered as RFC
  7950 section 7.21.5 says): unknown-element, but for a default, which
  is then not in use; or whose `must` does not: operation-failed, the
  must's error-message and error-app-tag (must-violation by default).
  The tree's defaults should be made first: the expressions see them.
- **Filters** select nodes of a tree, and what they select is a tree of
  its own: each node with all below it, the nodes above it with an
  entry's keys. An XPath filter selects the node set its expression
  finds from the root (RFC 6241 section 8.9). A subtree filter (section
  6) is a tree of the schema's nodes: one with a value is a content
  match node, one with children a containment node, one with neither a
  selection node. Its content match nodes all matching, a node is
  selected whole if it has no other filter nodes under it, else with
  what they match and select; an empty filter selects nothing.
- **NACM paths**: a data-node rule's `path` (RFC 8341 section 3.4.5) is
  an instance-identifier whose key predicates may be left out, any
  entry then, and whose values may be `$USER`; `/` is every node. It is
  compiled once against the schema, each step to its node and each
  value to its key's type, and matches the node it names and all below
  it. An rpc or a notification with no instance is matched by its
  schema node, which a path with predicates never matches.
- **Parent references** (RFC 8528 section 4): a mounted tree's
  expressions see only it, and what its mount point's parent-reference
  expressions select of the parent tree, each a node set evaluated from
  the mount point. `cbl_dtree_parent_refs()` makes that a tree as a
  filter's is; `cbl_dtree_set_refs()` gives it to the mounted tree, whose
  `when`s, `must`s and leafrefs then see its nodes beside their own.
- **A difference** of two trees is the edit that makes the first the
  second with the default none, what a YANG Patch carries: creates of
  what only the second has, merges of the leaves that differ, removes
  of what only the first has (but where another case's create takes its
  place), and, where an ordered-by user list's order would not be the
  second's, each of its entries said where. A keyless list's entries
  cannot be named: the node they are in is replaced. Every
  change goes in an undo log as it is made, played back on an error:
  the target is as it was, and the error names the edit's node, its
  error-tag and why.

- **Decoding** checks what the CBOR is: its shape, its kinds, its tags,
  UTF-8, and with `CBL_YD_STRICT` a key the node has no child for.
  What a decode allocates is the arena's, bounded by its limit, since a
  list entry may be one byte of input and a struct of many.
- **Validating** is what RFC 7950 says within one tree (YANG.md section
  4): `cbl_yvalidate()` gives the first violation with its node, error-tag,
  error-app-tag and message. `cbl_ydefaults()` sets what is unset to the
  module's defaults.
- **The YANG family** serves the handlers of the tables given to
  `cbl_yserver_add()`, in CORECONF's shape (WIRE-FORMAT.md section 7.6):
  GET reads top-level data nodes through their `get` handlers, a dump a
  node a frame; EDIT creates, replaces or deletes them through their
  `edit` handlers, all or nothing, each value validated first; RPC calls
  an rpc's handler with its input validated; GET-SID
  sends the `.sid` files the table carries. A handler names the node at
  fault with `cbl_req_set_yerr()`: the error's `error-path`, read with
  `cbl_msg_err_sid()`.
- **What `cblink-gen` writes per struct** (`-m h,schema`): `X_encode()`
  and `X_decode()` (the value alone), `X_put()` and `X_parse()` (in a
  message, as `cbl_msg_put_ynode()` and `cbl_msg_ydecode()`); per rpc,
  `X_call(conn, in, out, a, timeout)`, the rpc called through family 1;
  per notification, `X_notify(ctx, p)` and, as for every struct,
  `X_parse()`, which reads it from family 1's envelope and is `ENOENT`
  for another notification. With `-m server`, the handlers the program
  defines: `node_get()` and `node_edit()` per top-level data node,
  `rpc_rpc()`, `action_action()`.

## 8. Families (server side, and client side for symmetric use)

A program's own operations, when the YANG family's do not fit (a stream
of its own, a command of its own): its handlers receive the request as
it came, and check what they take themselves, the YANG codec decoding
strictly.

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
	const char			*name;		/* for ctrl get-family */
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
bool	cbl_conn_subscribed(cbl_conn *, cbl_family *, uint32_t group_idx); /* thread-safe */
```

## 9. Peer identity (same for every transport)

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

## 10. Client API

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

/* the control family (the module cblink-ctrl): its rpcs as calls */
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

## 11. Streams

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

## 12. Versioning and ABI policy

- The shared library is `libcblink.so.1` (`SHLIB_MAJOR=1`). Symbols are
  versioned with `Symbol.map` and `Versions.def` (bsd.symver.mk), starting at
  `CBLINK_1.0`.
- Adding functions is allowed within a major version; new symbols go in a
  new version node (`CBLINK_1.1`, …).
- Public structs are **tables**: `cbl_op`, `cbl_family_def`,
  `cbl_stream_cbs`, `cbl_conn_cbs`, `cbl_yserver`, `cbl_yhandler` and the
  schema tables (`cbl_ynode`, `cbl_ytype`, ...). They never change layout
  within a major version. `cbl_family_def.abi` lets the library recognise
  newer table layouts if the major version is bumped. Every other type is
  opaque.
- Enumerations and flag values are append-only.
- `cbl_version()` returns the run-time library version string. The header
  defines `CBLINK_VERSION_MAJOR`, `_MINOR` and `_PATCH`.
- Generated code records the version of `cblink-gen` that produced it.
  Its tables are written with designated initializers against
  `<cbl_schema.h>`, so they compile against the header they are built
  with or not at all.
