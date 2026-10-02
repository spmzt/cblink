# cblink

Netlink-style messaging over CBOR between userland programs on FreeBSD.

A cblink message is a fixed 24-byte binary header (family, command, flags,
sequence number, stream id) followed by a CBOR map of typed attributes.
Servers register **families** of operations with declarative attribute
policies. Clients find a family by name at run time and then use:

- **request/response**, with extended acks: a failed request says which
  attribute was wrong and why;
- **dumps** that list large tables one item at a time;
- **streams** in one or both directions, with credit-based flow control;
- **multicast notifications**.

Transports and their security:
- **TCP:** TLS 1.3.
- **SCTP:** DTLS 1.2 (RFC 6083), with each cblink stream on its own SCTP
  stream, and multihoming.
- **Local sockets.**
- Mutual TLS is the default. Plaintext needs an explicit opt-in.
- No HTTP: behind a load balancer, cblink runs under a TCP proxy with TLS
  passthrough, and can learn the client's address from a PROXY protocol
  header (docs/TRANSPORTS.md).

`cblink-gen` reads a family's YAML spec and generates typed C structures,
policies, parsers, builders, client wrappers, server glue and
documentation, as YNL does for Linux netlink.

## A family in a few lines

```yaml
# kv.yaml (abridged; see examples/kv)
name: kv
version: 1
attribute-sets:
  - name: kv
    attributes:
      - name: key
        type: text
        checks:
          min-len: 1
          max-len: 255
      - name: value
        type: bytes
operations:
  - name: get
    attribute-set: kv
    do:
      request:
        attributes:
          - key
        required:
          - key
      reply:
        attributes:
          - key
          - value
```

```c
/* Client */
struct kv_client cl;
struct kv_get_req req = { .key = "colour" };
struct kv_get_rsp *rsp;

cbl_ctx_new(&ctx);
cbl_conn_new(ctx, "unix:/var/run/kv.sock", 0, &conn);
cbl_conn_connect(conn);
kv_client_init(&cl, conn);		/* finds the family by name */
if (kv_get(&cl, &req, &rsp) == 0)
	printf("%.*s\n", (int)rsp->value.len, (const char *)rsp->value.p);

/* Server: the handler cblink-gen declared */
int
kv_get_doit(cbl_req *req, const struct kv_get_req *rq, void *arg)
{
	struct kv_get_rsp rsp = { .key = rq->key, .value = lookup(rq->key) };

	return (kv_get_reply(req, &rsp));
}
```

The program's Makefile only needs:

```make
PROG=		kvd
SRCS=		kvd.c
CBLINK_SPECS=	kv.yaml
.include "${LOCALBASE}/share/cblink/cblink.mk"
.include <bsd.prog.mk>
```

`examples/` has four complete programs, each built from its spec and
tested:
- `echo`: the smallest family;
- `kv`: do, dump, auth, notifications and a watch stream;
- `stream`: flow control and a bidirectional stream;
- `notify`: multicast notifications.

## Building

The tree builds three ways, all with base `make(1)` and `bsd.*.mk`:

| How | Command | libcbor |
|-----|---------|---------|
| Out of the source tree | `make && make install` (`PREFIX`, `DESTDIR` as usual) | `devel/libcbor` in `${LOCALBASE}` |
| As the port | `port/devel/cblink`: `make install` | `devel/libcbor` |
| In `/usr/src` | `lib/libcblink`, `usr.bin/cblink-gen` as base directories | base's private libcbor (`LIBADD+= cbor`) |

Out of tree, install libcbor first: `pkg install libcbor` (or build
`devel/libcbor`). The build stops with a clear message without it.

Out of tree, everything is built under `obj/` at the top of the tree, never
in the source directories, unless `MAKEOBJDIRPREFIX` or `MAKEOBJDIR` says
otherwise. Build from the top: a `make` started in a subdirectory uses that
directory.

Dependencies:
- libc;
- libcbor;
- OpenSSL (base by default, or the port's `USES=ssl` choice);
- libpthread;
- kqueue;
- SCTP, which is optional at run time.

The public header `<cblink.h>` exposes no libcbor or OpenSSL types. The
library is `libcblink.so.1`, with symbol versioning.

## Testing

```sh
make && make install DESTDIR=/tmp/r
cd /tmp/r/usr/local/tests/cblink
LD_LIBRARY_PATH=/tmp/r/usr/local/lib kyua test -k Kyuafile
```

The suite has about 130 cases, using atf-c, atf-sh and kyua. It covers:
- the wire format against the documented hex examples;
- malformed and hostile input;
- every transport, with mTLS and its failure cases;
- the generator, through golden files, determinism, error diagnostics and
  compiled output;
- the examples.

CI also runs the suite under ASan, UBSan and TSan, and runs the libFuzzer
harnesses in `fuzz/` (frames, PROXY headers, specs) for a minute each.
docs/TESTING.md has the details.

## Documentation

| Document | Contents |
|----------|----------|
| [docs/WIRE-FORMAT.md](docs/WIRE-FORMAT.md) | The protocol, with hex examples |
| [docs/API.md](docs/API.md) | The C API and threading model |
| [docs/FAMILIES.md](docs/FAMILIES.md) | Designing families; the control family ([docs/ctrl.md](docs/ctrl.md)) |
| [docs/SPEC-FORMAT.md](docs/SPEC-FORMAT.md) | The YAML spec format |
| [docs/GENERATOR.md](docs/GENERATOR.md) | cblink-gen and the generated API |
| [docs/STREAMS.md](docs/STREAMS.md) | Streams and flow control |
| [docs/TRANSPORTS.md](docs/TRANSPORTS.md) | TCP, SCTP, AF_UNIX: framing, features, caveats, proxies |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, TLS policy, limits |
| [docs/TESTING.md](docs/TESTING.md) | The test suite, sanitizers, fuzzing |

Man pages: cblink(3), cblink-gen(1).

## Layout

```
lib/libcblink/        the library, its man page and tests
usr.bin/cblink-gen/   the generator, its man page and tests
share/cblink/         control family spec, cblink.mk, cblink.pc
examples/             echo, kv, stream, notify, and their tests
fuzz/                 libFuzzer harnesses and seed corpora
port/devel/cblink/    the FreeBSD port
docs/                 documentation
```

## License

BSD-2-Clause. See [LICENSE](LICENSE).
