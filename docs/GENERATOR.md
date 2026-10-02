# cblink-gen: the code generator

`cblink-gen` reads a family spec (SPEC-FORMAT.md) and writes C code and
documentation for it, in the way Linux's YNL tools do for netlink. This
document describes how the generator works and the API it generates.
cblink-gen(1) describes the command line.

```
cblink-gen [-BnV] [-b base] [-m parts] [-o dir] spec.yaml
```

## 1. How it works

```
spec.yaml ──▶ YAML-subset parser ──▶ spec model + checks ──▶ C emitter ──▶ base.h base.c
              (yaml.c)               (spec.c)               (gen_c.c)     base_client.c
                                                            Markdown      base_server.c
                                                            (gen_md.c)    base.md
```

- **Input is untrusted.** cblink-gen opens the spec and the output
  directory, enters capsicum(4) capability mode, and only then reads and
  parses the spec.
  - Files larger than 1 MiB are refused.
  - The YAML subset (SPEC-FORMAT.md) has no flow collections,
    anchors, aliases, tags, or complex or merge keys.
  - Lines are at most 4096 bytes, scalars at most 64 KiB, nesting at
    most 32 levels deep, and a spec has at most 100000 nodes.
  - The parser is fuzzed (`fuzz/fuzz_spec`).
- **All problems at once.** Errors are reported as
  `file:line:column: error: message` and collected up to a limit, so one
  run shows every mistake. Nothing is written if there is any error.
- **Checks before output.** The checks include:
  - names and C identifiers;
  - unknown and duplicate keys;
  - references between attribute sets, operations, groups and streams;
  - limits on numbers of things;
  - every pair of generated C identifiers that would collide. For example,
    an operation and an attribute set that would both be named
    `echo_echo` are rejected with the locations of both.
- **Deterministic output.** The output depends only on the spec and the
  generator version: no timestamps, no paths, no host details. Running
  twice gives byte-identical files. The tests check this.
- **Atomic writes.** Each file is written to a temporary name in the output
  directory (`mkostempsat`) and renamed into place (`renameat`). An
  interrupted run leaves the previous files intact.

## 2. Names

The prefix `P` is the spec's `c-prefix`, or the family name with `-` and
`.` turned into `_`. Below, `P` is the lower-case prefix and `PU` the
upper-case one. Spec names such as `max-key-len` become C names such as
`max_key_len`.

## 3. The generated API

The examples use the `kv` family from SPEC-FORMAT.md. Its golden output is
in `usr.bin/cblink-gen/tests/golden/kv/`.

### 3.1 Constants and enumerations (`kv.h`)

| Spec | C |
|------|---|
| family | `KV_FAMILY_NAME "kv"`, `KV_FAMILY_VERSION 1`; `KV_FAMILY_ID` for a `fixed-id` family |
| `const` definition | `#define KV_MAX_KEY_LEN 255` |
| `enum` definition | `#define KV_<ENUM>_<ENTRY> n`, and the value table `kv_<enum>_values` used by policies |
| `flags` definition | `#define KV_ENTRY_FLAGS_SECRET (UINT64_C(1) << 1)`, and `kv_entry_flags_values` |
| attribute set | `enum { KV_A_KEY = 1, …, KV_A_MAX }` (the set named like the family), or `KV_<SET>_A_<ATTR>` |
| operation | `enum { KV_CMD_GET = 1, … }` |
| multicast group | `enum { KV_MCGRP_CHANGES = 0, … }` (indexes), `KV_MCGRP_COUNT` |

### 3.2 Structures, policies, parsers, builders (`kv.c`)

For every attribute set, and for every request, reply, dump and
notification shape:

```c
struct kv_get_rsp {
	const char		*key;		/* NULL when absent */
	struct cbl_bytes	 value;		/* { p, len } */
	bool			 has_flags;	/* optional scalars */
	uint32_t		 flags;
	struct {
		size_t		 n;
		const char *const *v;
	}			 tags;		/* multi-attr */
	cbl_msg			*_msg;		/* replies only: owns the memory */
};

extern const struct cbl_policy_set kv_get_rsp_policy;	/* validation */
extern const struct cbl_parser kv_get_rsp_parser;	/* message -> struct */
int	kv_get_rsp_parse(cbl_msg *, const cbl_attr *map, struct kv_get_rsp *);
int	kv_get_rsp_put_fields(cbl_msg *, const struct kv_get_rsp *);
```

- **Parsed values point into the message.** Strings and byte strings are
  not copied. They stay valid as long as the message that was parsed.
  Nested sets become nested structures. Arrays of nested sets are
  allocated in the message's arena.
- **Policies are derived from the spec's `checks`.** Types, ranges,
  lengths, `required`, `max-count`, enum and flags membership, and nesting
  all come from it. The library validates a request against its
  operation's policy before the handler sees it.
- **Builders, one per attribute:** `kv_put_key(cbl_msg *, const char *)`
  when the set is named like the family, otherwise
  `kv_<set>_put_<attr>()`. Multi-attributes take an array and a count.

### 3.3 Client side (`kv_client.c`)

```c
struct kv_client {
	cbl_conn	*conn;
	uint16_t	 family;		/* resolved id */
	uint32_t	 version;
	uint32_t	 groups[KV_MCGRP_COUNT];	/* resolved group ids */
	cbl_msg		*err;			/* ERROR of the last failed call */
};

int	kv_client_init(struct kv_client *, cbl_conn *);
int	kv_client_init_info(struct kv_client *, cbl_conn *,
	    const cbl_family_info *);	/* from cbl_resolve_async() */
void	kv_client_fini(struct kv_client *);
```

- **Initialisation.** `kv_client_init()` looks the family up by name
  (`ctrl getfamily`) and records its id and group ids. A `fixed-id` family
  uses its constant. It is a synchronous request, so call it before
  attaching the connection to a loop, or from a thread other than the
  loop's. On the loop thread, resolve with `cbl_resolve_async()` and
  hand the result to `kv_client_init_info()`.
- **Requests.** `kv_get(cl, &req, &rsp)` builds the request from the
  structure, waits for the reply and parses it.
  - `rsp` owns its message; free it with `kv_get_rsp_free()`.
  - An operation without a reply returns only the error code.
  - On failure, `cl->err` holds the server's `ERROR` message for its
    extended ack: `cbl_msg_err_str()`, `cbl_msg_err_path()`, and so on.
  - `kv_get_async(cl, &req, cb, arg)` sends the same request without
    waiting, for use from loop callbacks. `cb(cl, error, rsp, arg)` runs on
    the loop thread with the parsed reply (it owns `rsp`), or an error,
    and then `cl->err` as above. The client must outlive the callback.
- **Dumps.** `kv_get_dump(cl, &req, &d)` starts a dump and
  `kv_get_dump_next(d, &item)` returns the items. An item is valid until
  the next call, and `item` is `NULL` after the last one. `cbl_dump_free()`
  ends the dump.
- **Notifications.**
  `kv_changes_subscribe(cl, &handlers, arg, &sub)` joins the group.
  `struct kv_changes_handlers` has one typed callback for each
  notification of the group. A notification structure is valid for the
  duration of its callback.
- **Streams.**
  - `kv_watch_open(cl, &req, &cbs, arg, &s)` opens a stream.
  - The callbacks are typed: `on_data(const struct kv_kv *)`, and
    `on_open(…, const struct <op>_rsp *accept, …)` when the open operation
    has a reply.
  - Stream data is checked against its payload set's policy before
    `on_data` runs, on the client and on the server. Data that breaks it
    (a missing `required` attribute, a value out of range) or does not
    parse resets the stream with `EBADMSG`; it is never dropped quietly.
  - `kv_<stream>_send()` exists for streams the client may send on.
  - Push streams (`direction: server-to-client`) are opened with
    `CBL_SF_PUSH`.
  - `initial-credit` from the spec is the receive window each end
    announces: in the open, and in the server's accept.

### 3.4 Server side (`kv_server.c`)

```c
extern const struct cbl_family_def kv_family_def;
int	kv_register(cbl_ctx *, void *arg, cbl_family **);

/* Handlers the server program defines, under exactly these names: */
int	kv_get_doit(cbl_req *, const struct kv_get_req *, void *arg);
int	kv_get_dumpit(cbl_req *, const struct kv_get_dump_req *,
	    struct cbl_dump_state *, void *arg);
int	kv_set_doit(cbl_req *, const struct kv_set_req *, void *arg);
int	kv_watch_stream_open(cbl_req *, const struct kv_watch_req *,
	    cbl_stream *, void *arg);

/* Helpers: */
int	kv_get_reply(cbl_req *, const struct kv_get_rsp *);
int	kv_get_dump_reply(cbl_req *, const struct kv_get_dump_rsp *);
int	kv_changed_notify(cbl_family *, const struct kv_changed_ntf *);
int	kv_watch_accept(cbl_stream *, const struct kv_watch_server_cbs *,
	    void *arg);
int	kv_watch_server_send(cbl_stream *, const struct kv_kv *);
```

- **Trampolines.** `kv_server.c` holds the operation table with each
  operation's policy, flags (`auth: true` becomes `CBL_OPF_AUTH`) and
  small trampolines. A trampoline parses the validated request into its
  structure and calls the handler.
  - When an operation has both `do` and `dump`, the request is validated
    against the policy of whichever was asked for.
- **Handler results.** A handler returns 0 when it has replied or wants an
  empty acknowledgement. Otherwise it returns an errno value, and may
  describe it with `cbl_req_set_err()`.
- **Dump handlers** return `EAGAIN` while there is more, after sending one
  item, and 0 at the end. They keep their position in `st->pos[]`.
- **Helpers are only generated for what the spec has.** A family with only
  notifications has no handlers at all. Generated files never contain
  unused static functions, which a test enforces at `WARNS=6`.

A client-only program does not compile `kv_server.c`, so it needs no
handlers.

### 3.5 Documentation (`kv.md`)

A reference page lists:
- the family;
- every attribute with its type and checks;
- every operation with its request and reply attributes, its flags and its
  stream;
- notifications, groups and streams.

## 4. Building programs from specs

`share/cblink/cblink.mk` (installed in `${LOCALBASE}/share/cblink/`)
generates and compiles a program's specs with bsd.prog.mk:

```make
PROG=		kvd
SRCS=		kvd.c
CBLINK_SPECS=	kv.yaml
.include "${LOCALBASE}/share/cblink/cblink.mk"
.include <bsd.prog.mk>
```

Its variables:
- `CBLINK_PARTS`: which files to generate;
- `CBLINK_DOCS=yes`: also write `kv.md`;
- `CBLINK_GEN`, `CBLINK_CFLAGS` and `CBLINK_LIBS`: point it at a build tree,
  as `examples/examples.mk` does.

The files are written into the object directory and added to `SRCS`.

## 5. The control family

Family 0 is described by `share/cblink/specs/control.yaml` and generated
with `-B`, which allows `fixed-id` and the reserved names. The output is
committed in `lib/libcblink` (`cbl_ctrl_gen*.{c,h}`), because the library
cannot depend on its own generator at build time.
- `make -C lib/libcblink regen` refreshes the committed files.
- The `ctrl_regen` test fails if they differ from what the generator now
  produces.

## 6. Tests (`usr.bin/cblink-gen/tests`)

- **golden:** `types.yaml`, which uses every feature, and `kv.yaml` are
  compared byte for byte with committed output.
- **determinism:** repeated runs give identical output.
- **errors:** each spec in `errors/` must fail with the exact diagnostics
  in its `.err` file.
- **ctrl_regen:** the committed control-family files are up to date.
- **roundtrip_test:** code generated from `types.yaml` at build time is
  compiled at `WARNS=6`. It then round-trips every structure through
  builders and parsers, and runs clients against servers.
- **minimal_test:** families with only a `do`, only streams or only
  notifications compile at `WARNS=6`.
- **cli and big_input:** command-line handling, and the size limits.
