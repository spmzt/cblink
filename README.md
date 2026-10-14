# cblink

Netlink-style messaging between userland programs on FreeBSD, its data
modelled in YANG.

A cblink message is a fixed 24-byte binary header (family, command,
flags, sequence number, stream id) followed by one CBOR map of YANG data:
its keys are SIDs (RFC 9595), its values YANG-CBOR (RFC 9254). A program
describes its configuration, state, rpcs and notifications in YANG
modules; the built-in YANG family serves them by SID, in CORECONF's
shape, and clients use:

- **GET, EDIT and RPC**: reads, all-or-nothing edits and calls, with
  errors that name the node at fault and why;
- **dumps** that list large tables one item at a time;
- **streams** in one or both directions, with credit-based flow control;
- **notifications** to subscribers.

Transports and their security:
- **TCP:** TLS 1.3.
- **SCTP:** DTLS 1.2 (RFC 6083), with each cblink stream on its own SCTP
  stream, and multihoming.
- **Local sockets.**
- Mutual TLS is the default. Plaintext needs an explicit opt-in.
- No HTTP: behind a load balancer, cblink runs under a TCP proxy with TLS
  passthrough, and can learn the client's address from a PROXY protocol
  header (docs/TRANSPORTS.md).

`cblink-gen` compiles the modules with libyang and writes their C
structs, the schema tables the codec works by, helpers for messages,
rpcs and notifications, a server's handler table, documentation and
`.sid` files, as YNL does for Linux netlink.

## A module in a few lines

```yang
// kv@2026-10-13.yang (abridged; see examples/kv)
module kv {
  yang-version 1.1;
  namespace "urn:cblink:example:kv";
  prefix kv;

  container store {
    list entry {
      key "key";
      leaf key { type string { length "1..255"; } }
      leaf value { type binary; }
      leaf ttl { type uint32; units "seconds"; }
    }
  }
  rpc clear {
    input { leaf prefix { type string; } }
    output { leaf removed { type uint32; } }
  }
}
```

```c
/* Server: the handlers kv.h declares, served by SID */
int
kv_store_get(cbl_req *req, struct kv *data, cbl_yarena *a)
{
	data->store = current_store(a);
	return (0);
}

int
kv_clear_rpc(cbl_req *req, const struct kv_clear_input *in,
    struct kv_clear_output *out, cbl_yarena *a)
{
	out->has_removed = true;
	out->removed = remove_prefix(in->prefix);
	return (0);
}

cbl_yserver_add(ctx, &kv_server, NULL);

/* Client: the rpc called through the YANG family */
struct kv_clear_input in = { .prefix = "tmp/" };
struct kv_clear_output out;

if (kv_clear_call(conn, &in, &out, a, -1) == 0)
	printf("%u removed\n", out.removed);
```

The program's Makefile only needs:

```make
PROG=		kvd
SRCS=		kvd.c
CBLINK_YANG=	kv@2026-10-13.yang
CBLINK_SIDS=	kv@2026-10-13.sid
.include "${LOCALBASE}/share/cblink/cblink.mk"
.include <bsd.prog.mk>
```

`examples/` has four complete programs, each built from its module and
tested:
- `echo`: one rpc;
- `kv`: GET, EDIT, RPC, GET-SID and a notification, over a socket;
- `stream`: a family of its own, flow control and a bidirectional stream;
- `notify`: notifications to subscribers.

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
- libyang 3, for cblink-gen (`pkg install libyang3`);
- OpenSSL (base by default, or the port's `USES=ssl` choice);
- libpthread;
- kqueue;
- SCTP, which is optional at run time.

The public headers `<cblink.h>` and `<cbl_schema.h>` expose no libcbor or
OpenSSL types. The library is `libcblink.so.1`, with symbol versioning.

## Testing

```sh
make && make install DESTDIR=/tmp/r
cd /tmp/r/usr/local/tests/cblink
LD_LIBRARY_PATH=/tmp/r/usr/local/lib kyua test -k Kyuafile
```

The suite has about 155 cases, using atf-c, atf-sh and kyua. It covers:
- the wire format against the documented hex examples;
- malformed and hostile input;
- every transport, with mTLS and its failure cases;
- the generator: the YANG front end, the structs and tables of every
  shape and type, the codec's round trips, the YANG family over a
  connection, `.sid` files, determinism;
- the examples.

CI also runs the suite under ASan, UBSan and TSan, and runs the libFuzzer
harnesses in `fuzz/` (frames, PROXY headers, XPath, patterns) for a
minute each.
docs/TESTING.md has the details.

## Documentation

| Document | Contents |
|----------|----------|
| [docs/WIRE-FORMAT.md](docs/WIRE-FORMAT.md) | The protocol, with hex examples |
| [docs/API.md](docs/API.md) | The C API and threading model |
| [docs/YANG.md](docs/YANG.md) | The YANG taken, its encoding, what is left out |
| [docs/FAMILIES.md](docs/FAMILIES.md) | Families; the control family ([docs/ctrl.md](docs/ctrl.md)) |
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
share/yang/           cblink's own YANG modules and their .sid files
share/cblink/         cblink.mk, cblink.pc
examples/             echo, kv, stream, notify, and their tests
fuzz/                 libFuzzer harnesses and seed corpora
port/devel/cblink/    the FreeBSD port
docs/                 documentation
```

## License

BSD-2-Clause. See [LICENSE](LICENSE).
