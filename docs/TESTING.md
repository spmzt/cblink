# Testing

cblink's tests use atf-c, atf-sh and kyua from the base system, plus
openssl(1) for certificates. They need nothing else. The SCTP tests skip
themselves when SCTP is not available.

## 1. Running the tests

From a build:

```sh
make && make install DESTDIR=/tmp/cblink-root
cd /tmp/cblink-root/usr/local/tests/cblink
LD_LIBRARY_PATH=/tmp/cblink-root/usr/local/lib kyua test -k Kyuafile
kyua report --verbose --results-filter broken,failed
```

From the port: `make -C devel/cblink test`. This builds everything with
the tests, installs it into a scratch root under `WRKDIR`, and runs the
same suite.

An installed package does not include the tests: the port builds without
them.

## 2. What is tested

The suite has about 130 test cases.

### 2.1 libcblink (`lib/libcblink/tests`)

| Program | Covers |
|---------|--------|
| `frame_test` | The wire format: every hex example in WIRE-FORMAT.md, header fields and extensions, flag combinations, error frames, frame sequences. |
| `attr_test` | Building and reading attributes: scalars, nesting, large containers and strings, copying, builder errors and limits, extended acks. |
| `malformed_test` | Hostile input: bad headers and lengths, truncation, invalid CBOR, profile violations (tags, indefinite lengths, duplicate keys, bad UTF-8), excessive nesting and attribute counts, and systematic mutations of valid frames. |
| `policy_test` | Policies, validation errors with paths, declarative parsers. |
| `family_test` | The registry, the control family, dispatch, dumps with backpressure, deferred replies completed out of order, deferred requests completed before their handler returned and cancelled when their client left, read backpressure (a client that does not read its replies, a slow dump consumer), the in-flight limit. |
| `tcp_test` | Connections: non-blocking clients (idle past the handshake timeout, failing over to the next address), `tcp://*` on IPv4 and IPv6, accept(2) out of descriptors, timers and signals, `cbl_ctx_free()` while in use, a peer that floods requests without reading the answers, plaintext opt-in, refusals, unknown families, out-of-order and fragmented replies, big replies, timeouts (request, first frame, idle), oversize and garbage input, recovery, a client on a loop. |
| `stream_test` | Streams: echo, push, rejection, flow control, the close handshake, `max_streams`, open timeouts, protocol violations (unknown and closed ids, malformed frames, accepts that do not match), streams ended from their own callbacks, deferred opens, `cbl_stream_ref()`, use from other threads. |
| `notify_test` | Subscriptions, errors, many subscribers, control-family notifications, slow subscribers and their stats, a notifying thread while subscribers abort, notifications from a timer to a late reader, keepalives on a quiet subscription, a close that the peer stalls, resolving and subscribing from the loop thread, unicast, unsubscribing while a notification is delivered. |
| `proxy_test` | The PROXY protocol on `CBL_LF_PROXY` listeners: the allowed proxies, versions 1 and 2 over IPv4 and IPv6, TLVs, `LOCAL` and `UNKNOWN`, headers in pieces and together with the first frame, malformed and oversized headers, missing headers, the timeout, and which endpoints accept the flag. |
| `sctp_raw_test` | SCTP seen from a raw socket: cblink streams on their own SCTP streams, messages larger than one SCTP chunk, messages over `max_frame` dropped while the association stays up. |
| `tls_test.sh` | mTLS over TCP with openssl(1)-made certificates: identity, a missing client certificate, a wrong CA, expired certificates, a chain with an intermediate CA and a CRL for each CA, revocation picked up by `cbl_tls_reload()`, plaintext rules, mTLS end to end through a relay that sends PROXY headers. |
| `sctp_test.sh` | SCTP plain (requests, dumps, streams, frames of 900 KB), multihoming over 127.0.0.1 and ::1 (two paths), and DTLS over SCTP with mTLS. |
| `unix_test.sh` | AF_UNIX: credentials, `CBL_LF_UNIX_TRUSTED`, the default `0600` mode, stale socket files. |

`cbl_testpeer` is the program the shell tests drive. It serves the
`testpeer` family on any URI and calls it.

### 2.2 cblink-gen (`usr.bin/cblink-gen/tests`)

| Test | Covers |
|------|--------|
| `golden` | `types.yaml` (every feature) and `kv.yaml` against committed output, byte for byte. |
| `determinism` | Repeated runs give identical output. |
| `errors` | Each invalid spec in `errors/` fails with exactly the diagnostics in its `.err` file. |
| `ctrl_regen` | The control-family code committed in `lib/libcblink` matches what the generator produces now. |
| `cli`, `big_input` | Options, exit codes, size limits. |
| `roundtrip_test` | Code generated from `types.yaml` at build time, compiled at `WARNS=6`: structures round-trip through builders and parsers, policies hold, clients talk to servers, streams and notifications work. |
| `minimal_test` | Families with only a `do`, only streams or only notifications compile at `WARNS=6`, so no unused helpers are generated. |

### 2.3 Examples (`examples/tests`)

`examples_test.sh` runs `cbl-echo`, `cbl-kv`, `cbl-stream` and
`cbl-notify`, each against its own server. This checks that the examples,
built from their specs with `cblink.mk`, work as their comments say.

## 3. Sanitizers

The whole suite runs under AddressSanitizer with UndefinedBehaviorSanitizer,
and under ThreadSanitizer, in CI on every push and pull request, together
with a short run of each fuzzer. `.github/ci/sanitize.sh` does it, also
locally:

```sh
.github/ci/sanitize.sh asan	# or tsan, or fuzz
```

The flags must reach make(1) through the environment
(`CFLAGS=... LDFLAGS=... make`): on the command line they would replace
the Makefiles' own include paths.

Several bugs were found this way: a use-after-free in streams, a lost loop
stop, a timer firing after its connection was freed, and lock-order and
data races.

## 4. Fuzzing

`fuzz/` has libFuzzer harnesses for the three parsers that see untrusted
input. They are built with ASan and UBSan, and seeded from `fuzz/corpus/`:

| Harness | Input |
|---------|-------|
| `fuzz_frame` | A frame: decoding, every attribute accessor, validation and parsing as a control-family message. |
| `fuzz_proxy` | A PROXY protocol header, read from a socket: the reader must stop exactly at the end of the header. |
| `fuzz_spec` | A family spec: the YAML parser and spec checks. |

New inputs go to the first corpus directory given, so give a scratch one
first to keep the committed seeds as they are:

```sh
make -C fuzz
mkdir -p /tmp/corpus
$(make -C fuzz -V .OBJDIR)/fuzz_frame -max_total_time=600 /tmp/corpus fuzz/corpus/frame
```
