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

The suite has about 155 test cases.

### 2.1 libcblink (`lib/libcblink/tests`)

| Program | Covers |
|---------|--------|
| `frame_test` | The wire format: every hex example in WIRE-FORMAT.md, header fields and extensions, flag combinations, error frames, frame sequences, version 1 refused. |
| `ybody_test` | Version 2 bodies: SID keys past 65535 to 2^63 - 1, negative and large nested keys, each value's bytes found again exactly after an out-of-order body is sorted, a key twice refused, SIDs out of range refused, the depth, value and frame limits; the builder's errors; every field of the `cblink:error` structure there and back. |
| `malformed_test` | Hostile input: bad headers and lengths, truncation, invalid CBOR, profile violations (indefinite lengths, duplicate keys, bad UTF-8), YANG-CBOR's tags where they may be and every other tag refused, top-level keys that are not SIDs, excessive nesting and value counts, and systematic mutations of valid frames. |
| `family_test` | The registry, the control family, dispatch, dumps with backpressure, deferred replies completed out of order, deferred requests completed before their handler returned and cancelled when their client left, read backpressure (a client that does not read its replies, a slow dump consumer), the in-flight limit. |
| `tcp_test` | Connections: non-blocking clients (idle past the handshake timeout, failing over to the next address), `tcp://*` on IPv4 and IPv6, accept(2) out of descriptors, timers and signals, `cbl_ctx_free()` while in use, a peer that floods requests without reading the answers, plaintext opt-in, refusals, unknown families, out-of-order and fragmented replies, big replies, timeouts (request, first frame, idle), oversize and garbage input, recovery, a client on a loop. |
| `sid_test` | YANG-CBOR bodies (RFC 9254) by hand, ahead of wire version 2: an `ietf-interfaces` entry written with libcbor, an absolute SID at the top and SID deltas below, negative ones included, read back through a SID table and written again to the same bytes; unknown SIDs and misplaced ones refused. |
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
| `yang_frontend` | Modules compiled through libyang, features and deviations, extensions, the profile's refusals (XPath outside XPath-lite, patterns outside the translator) named. |
| `sid_cbor` | `.sid` files numbered with `-a`, in JSON and YANG-CBOR and back, `ietf-sid-file`'s own SIDs, the server table's copy of a file. |
| `yang_h`, `yang_h_test` | The structs and tables of every shape and type compile at `WARNS=6`; lookups by delta and SID, identities, the codec's kinds (decimal64, bits, identityref, instance-identifier, unions with tags 43 to 46), an rpc's deltas from its SID, the arena's limit, the `cblink` structures in a message, and a round trip of every struct. |
| `yfamily_test` | Family 1 serving those tables over a connection: GET and EDIT, an edit undone when another fails, refusals with the node at fault (the validator's among them), RPC, a dump, a notification heard. |
| `yvalid_test` | The static validator on a module of RFC 7950's examples, a rule a case: ranges, lengths in characters, patterns and their app-tags, enums, bits, identities, unions, mandatory leaves and choices, counts, keys, `unique`, `config false` in edits; and the defaults of every kind. |
| `ydata_test` | The instance tree: built, walked and freed; entries by their keys, thousands of them; leaf-lists' order and values once; a choice's cases never two; defaults on demand and made; every struct through a tree to the same bytes, and a module's data struct. |
| `yedit_test` | Edits of the tree: RFC 6241 section 7.2's examples, by merge and by none; data-exists, data-missing, remove either way; a choice's case in the other's place; leaf-lists and an ordered list; a failing edit leaving the target as it was; RFC 8072's insert and move of a playlist's songs, first, last, before and after, refused where they must be, undone with the rest; the difference of every pair of trees yfill fills, applied, making one the other (a system-ordered list's entries in any order), and none left after; references, a leafref and an instance-identifier (by a list's key, of no list, a leaf-list's value) to what is there and dangling. |
| `yang_tree` | Tree diagrams equal to `yanglint -f tree`. |
| `corpus` | The IETF and IANA modules Arcana builds on (`tests/corpus`, 51 of them, as published): each tree equal to `yanglint -f tree`'s with the same features on; the structs, tables and server table of all of them compiled at `-Werror`, and every struct through YANG-CBOR and back to the same bytes; every leafref's path evaluated on data filled three ways, each node found its target; RFC 8349's router advertisement musts on an interface's configuration with its defaults made, true and false as they should be; RFC 8349's IPv4 augments' whens, each refused in a RIB made IPv6. |
| `yfilter_test` | Filters: RFC 6241 section 6.4's subtree filter examples on its configuration (`filters`, a test module), each output as the RFC has it; content match nodes on another leaf than a key, two of them ANDed; XPath filters selecting the same, a union, an entry's keys kept; a filter node out of place refused; NACM's paths: a node and all below it, entries by key or all, `$USER`, a uint32 key, a leaf-list's value, schema nodes, and what is not a node-instance-identifier refused; parent references, a mounted tree's leafref to the parent tree's OSPF areas by a predicate, seeing the areas they reference from the mount point, and no other. |
| `yxpath_test` | XPath-lite over a tree: paths, the four axes, predicates, `current()`; node sets compared with numbers, strings and node sets; arithmetic, `and`, `or`, union, `count()`; string values, decimal64's canonical forms, an instance-identifier's path; each function, one test at least (`deref` of a leafref and of an instance-identifier, identities, enums, bits, `re-match`, the string functions on UTF-8); a position, another axis, a variable refused; `when` and `must` over a tree (`conds`, a test module: a node's own `when`, a case's, an augment's not seeing its own nodes, a `must` with an error-message and an error-app-tag and one without, a default under a `when` not made or removed); a leafref whose path has a predicate. |
| `ymod_regen` | The structs and tables of cblink's own modules, and `docs/ctrl.md`, committed in `lib/libcblink` and `docs`, match what the generator produces now. |
| `determinism`, `cli`, `big_input`, `cblink_mk` | Repeated runs give identical output; options and exit codes; the size limit; cblink.mk finds a module given relative, with `../`, or absolute. |

`tools/yangwalk/tablecheck.sh` runs the same round trip over any
directory of modules, every struct filled as the tables say, encoded,
decoded and encoded again to the same bytes.

### 2.3 Examples (`examples/tests`)

`examples_test.sh` runs `cbl-echo`, `cbl-kv`, `cbl-stream` and
`cbl-notify`, each against its own server. This checks that the examples,
built from their YANG modules with `cblink.mk`, work as their comments
say.

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

`fuzz/` has libFuzzer harnesses for the parsers that see untrusted
input. They are built with ASan and UBSan, and seeded from `fuzz/corpus/`:

| Harness | Input |
|---------|-------|
| `fuzz_frame` | A frame: decoding, the decoder's tree, each top-level item found again at its bytes, and the YANG codec reading it as every control-family input and output, the hello and get structures, a notification, and its error. |
| `fuzz_proxy` | A PROXY protocol header, read from a socket: the reader must stop exactly at the end of the header. |
| `fuzz_ycodec` | YANG-CBOR decoded into every struct of the test module `shapes` (every kind of node and type: tags 4 and 43 to 47, deltas from a node's and from an rpc's SID, unions, choices, lists), strictly and not; what decodes validated, encoded, decoded and encoded again to the same bytes, and likewise with its defaults. Its tables are committed (`fuzz/yshapes.*`, `make -C fuzz regen`; `ymod_regen` checks them). |
| `fuzz_xpath` | An XPath expression: what parses is printed, and the print parses again to the same print. |
| `fuzz_pattern` | An XSD pattern: the translation to an ERE, compiled by regcomp(3). |

New inputs go to the first corpus directory given, so give a scratch one
first to keep the committed seeds as they are:

```sh
make -C fuzz
mkdir -p /tmp/corpus
$(make -C fuzz -V .OBJDIR)/fuzz_frame -max_total_time=600 /tmp/corpus fuzz/corpus/frame
```
