# cblink wire format, version 2

Status: version 2. Version 1 is not spoken: a version 1 frame is refused
like any other unknown version. This document is normative. The key
words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

cblink is a netlink-style protocol for userland applications. A connection
carries **frames**. Each frame has a fixed 24-byte binary header in network
byte order, followed by an optional CBOR body. The body is **YANG data**:
one CBOR map whose top-level keys are SIDs (RFC 9595) and whose values are
YANG-CBOR (RFC 9254); YANG.md says what of YANG is taken.

The design follows netlink(4) and genetlink(4) closely:

| netlink                     | cblink                                     |
|-----------------------------|--------------------------------------------|
| `struct nlmsghdr`           | 24-byte cblink header (section 2)          |
| `nlmsg_type` (genl family)  | `family` header field                      |
| `genlmsghdr.cmd`            | `cmd` header field                         |
| `NLM_F_REQUEST/ACK/MULTI/DUMP` | `REQUEST`, `ACK`, `MULTI`, `DUMP` flags |
| `NLMSG_DONE`                | `DONE` flag                                |
| `NLMSG_ERROR` + ext ack TLVs| `ERROR` flag + the `cblink:error` structure (section 6) |
| TLV attributes (`nlattr`)   | YANG nodes, keyed by SID (section 5)       |
| nested attributes           | containers and list entries: maps keyed by SID deltas |
| repeated attributes         | lists and leaf-lists: CBOR arrays          |
| multicast groups            | `NOTIFY` frames + control family subscribe |
| `GENL_ID_CTRL` / `nlctrl`   | family 0, `ctrl`                           |

cblink adds bidirectional, flow-controlled **streams** (section 8), which have
no netlink equivalent.

---

## 1. Transport framing

The frame format is the same on every transport. How frames are delimited
depends on the transport:

| Transport             | Delimiting                                                     |
|-----------------------|----------------------------------------------------------------|
| TCP, TLS 1.3 over TCP | Byte stream; the `length` header field delimits frames.        |
| AF_UNIX `SOCK_STREAM` | Same as TCP.                                                   |
| SCTP (plaintext)      | Exactly one frame per SCTP message (`MSG_EOR`). Message size MUST equal `length`. |
| DTLS 1.2 over SCTP    | Each SCTP stream is an ordered byte stream of frames delimited by `length` (DTLS records are at most 16 KiB, so a frame may span records). |

Section 10 has per-transport rules.

---

## 2. Header

All multi-byte integers are big-endian (network byte order).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+---------------+---------------+
|         magic (0xCB4C)        |  version (2)  | hdrlen (24)   |  0
+-------------------------------+---------------+---------------+
|                       length (total frame)                    |  4
+-------------------------------+-------------------------------+
|           family              |             cmd               |  8
+-------------------------------+-------------------------------+
|                             flags                             | 12
+---------------------------------------------------------------+
|                              seq                              | 16
+---------------------------------------------------------------+
|                    stream (or mcast group)                    | 20
+---------------------------------------------------------------+
|                    CBOR body (length - hdrlen bytes) ...       | 24
```

| Off | Size | Field     | Description |
|----:|-----:|-----------|-------------|
| 0   | 2    | `magic`   | `0xCB 0x4C`. The first byte is not printable ASCII and is not a TLS record type (`0x14`–`0x18`), so HTTP or TLS traffic sent to a plaintext cblink port is rejected immediately. |
| 2   | 1    | `version` | Protocol version. This document defines `2`. |
| 3   | 1    | `hdrlen`  | Header length in bytes. Version 2 senders MUST send `24`. Receivers MUST accept any multiple of 4 in `[24, 64]` and MUST ignore header bytes past offset 24. This is the extension point for future versions. |
| 4   | 4    | `length`  | Total frame length in bytes, including the header. `hdrlen <= length <= max_frame`. |
| 8   | 2    | `family`  | Family id. `0` is the control family; other ids are assigned dynamically per server (section 7). |
| 10  | 2    | `cmd`     | Command within the family. `0` is reserved and MUST NOT be used. |
| 12  | 4    | `flags`   | Section 3. |
| 16  | 4    | `seq`     | Sequence number (section 4). |
| 20  | 4    | `stream`  | Stream id for stream frames (section 8). Multicast group id for `NOTIFY` frames (section 9). `0` otherwise. |

A frame whose `length == hdrlen` has an **empty body**. An empty body is
equivalent to an empty map.

### 2.1 Header validation

Receivers MUST perform these checks, in this order, on the first
`hdrlen` bytes and **before allocating any buffer for the body**:

1. `magic == 0xCB4C`. Otherwise: protocol error. On byte-stream transports
   the connection is closed without a reply. On message transports (plain
   SCTP) the message is dropped.
2. `version == 2`. Otherwise the receiver sends an `ERROR` frame with code
   `EPROTONOSUPPORT` (formatted as version 2), then closes (byte-stream
   transports) or drops the message (message transports).
3. `hdrlen` is a multiple of 4 in `[24, 64]`. Otherwise: protocol error.
4. `hdrlen <= length <= max_frame` (default 1 MiB, section 11).
   Otherwise the receiver sends `ERROR` with code `EMSGSIZE`, echoing
   `family`, `cmd` and `seq`. A byte-stream transport cannot
   resynchronize without reading the oversized body, so it then **closes
   the connection**. A message transport drops the message.
5. On message transports (plain SCTP), the message size equals `length`.
   Otherwise the message is dropped.
6. `flags` contains no reserved bits and is a valid combination
   (section 3.2). Otherwise: `ERROR` `EINVAL`.

---

## 3. Flags

| Bit | Value        | Name       | Meaning |
|----:|--------------|------------|---------|
| 0   | `0x00000001` | `REQUEST`  | The frame is a request. Without it, the frame is a response (or a notification or stream frame). |
| 1   | `0x00000002` | `ACK`      | On a request: an acknowledgement is requested. On a response: this frame **is** the acknowledgement (success). |
| 2   | `0x00000004` | `DUMP`     | Request modifier: dump (list) instead of do. Like `NLM_F_DUMP`. |
| 3   | `0x00000008` | `MULTI`    | Part of a multipart response. Like `NLM_F_MULTI`. |
| 4   | `0x00000010` | `DONE`     | Final part of a multipart response. Always set together with `MULTI`. |
| 5   | `0x00000020` | `ERROR`    | Error response. The body carries the `cblink:error` structure (section 6). Terminal. |
| 6   | `0x00000040` | `NOTIFY`   | Unsolicited multicast notification. The `stream` field holds the group id. |
| 7–15|              |            | Reserved. Senders MUST send 0; receivers MUST reject frames with these bits set. |
| 16  | `0x00010000` | `S_OPEN`   | Stream open (with `REQUEST`) or stream accept (without `REQUEST`). |
| 17  | `0x00020000` | `S_DATA`   | Stream data. |
| 18  | `0x00040000` | `S_HCLOSE` | Half-close: the sender sends no more `S_DATA`. May be combined with `S_DATA` ("last data"). |
| 19  | `0x00080000` | `S_CLOSE`  | Graceful full close (close handshake). |
| 20  | `0x00100000` | `S_RESET`  | Abort the stream immediately. |
| 21  | `0x00200000` | `S_CREDIT` | Flow-control credit grant. |
| 22–31|             |            | Reserved, as bits 7–15. |

`S_ANY` denotes the mask `0x003F0000`.

### 3.1 Frame kinds

Every valid frame is exactly one of these kinds:

| Kind              | Required flags              | Allowed extra flags          | `seq`             | `stream`     |
|-------------------|-----------------------------|------------------------------|-------------------|--------------|
| do request        | `REQUEST`                   | `ACK`                        | sender's next seq | 0            |
| dump request      | `REQUEST\|DUMP`             | `ACK` (ignored)              | sender's next seq | 0            |
| reply             | (none)                      | —                            | echoes request    | 0            |
| acknowledgement   | `ACK`                       | —                            | echoes request    | 0            |
| error             | `ERROR`                     | `MULTI\|DONE`, `S_OPEN`      | echoes request    | 0 or stream  |
| dump part         | `MULTI`                     | —                            | echoes request    | 0            |
| dump end          | `MULTI\|DONE`               | —                            | echoes request    | 0            |
| notification      | `NOTIFY`                    | —                            | 0                 | group id ≠ 0 |
| stream open       | `REQUEST\|S_OPEN`           | `S_DATA`, `S_HCLOSE`         | sender's next seq | new id       |
| stream accept     | `S_OPEN`                    | `S_DATA`, `S_HCLOSE`         | echoes open       | stream id    |
| stream data       | `S_DATA`                    | `S_HCLOSE`                   | 0                 | stream id    |
| stream half-close | `S_HCLOSE`                  | `S_DATA`                     | 0                 | stream id    |
| stream close      | `S_CLOSE`                   | —                            | 0                 | stream id    |
| stream reset      | `S_RESET`                   | —                            | 0                 | stream id    |
| stream credit     | `S_CREDIT`                  | —                            | 0                 | stream id    |

### 3.2 Invalid combinations

Any combination not listed in section 3.1 is invalid. In particular:

- `DONE` without `MULTI`;
- `REQUEST` with any of `MULTI`, `DONE`, `ERROR` or `NOTIFY`;
- `NOTIFY` with any other flag;
- more than one of `S_CLOSE`, `S_RESET` and `S_CREDIT`, or any of them
  combined with another `S_*` flag;
- an `S_*` flag with `stream == 0`, or `stream != 0` without an `S_*` flag
  (except on `NOTIFY` frames and on `ERROR` replies to a stream open).

---

## 4. Sequence numbers and correlation

- Each endpoint keeps its own 32-bit counter for the requests and stream
  opens it sends. Counters start at 1 and wrap from `0xFFFFFFFF` to 1;
  `0` is never used for a request.
- Responses (reply, ack, error, dump part and end, stream accept) echo the
  request's `seq`. The `REQUEST` bit tells the two sequence spaces apart.
  Both ends may send requests at the same time, and a response is always
  matched against the receiver's own outstanding requests.
- **Replies may arrive out of order.** A server may complete requests in any
  order, for example after deferring a handler. Clients match responses by
  `seq` only.
- A requester MUST NOT have two outstanding requests with the same `seq`.
- A response whose `seq` matches no outstanding request is dropped and
  counted. It is not a protocol error, because the request may have timed
  out locally.

### 4.1 Completion rules

A **do** request completes with exactly one *terminal* frame:

| Request flags | Possible responses, in order |
|---------------|------------------------------|
| `REQUEST`     | zero or one reply, **or** one `ERROR`. (Like netlink: if the handler produces no reply and succeeds, nothing is sent.) |
| `REQUEST\|ACK`| zero or more replies, then exactly one terminal: an acknowledgement (`ACK`) or an `ERROR`. |

The library's synchronous client API always sets `ACK`, so every request
has a well-defined end.

A **dump** request completes with zero or more dump parts (`MULTI`), then
exactly one terminal: dump end (`MULTI|DONE`) or `ERROR|MULTI|DONE` if the
dump failed part-way. An `ERROR` with neither `MULTI` nor `DONE` is allowed
before the first part (for example, a request refused). `ACK` on a dump
request is ignored, because `DONE` is already terminal.

An acknowledgement MAY carry the `error` structure with an `error-message`
(a warning) and a `cookie`, as netlink extended ack allows on success.

---

## 5. Body: YANG data in CBOR

### 5.1 Encoding

The body, if present, MUST be **exactly one** CBOR data item (RFC 8949): a
**map**. That item MUST consume the body exactly; trailing bytes are an
error.

Restrictions (a strict profile of RFC 8949):

| Item                             | Rule |
|----------------------------------|------|
| Indefinite-length items (any)    | MUST NOT be sent; receivers MUST reject. Every collection's size is then known before its contents are read, so limits can be checked before allocation. |
| Tags (major type 6)              | Only the tags of YANG-CBOR (RFC 9254): 4 on a two-element array, 43 on a text string (bits in a union, by name), 44 on a text string, 45 on an unsigned integer or text string, 46 on an unsigned integer, text string or array, 47 on an unsigned integer; one tag per value, never on the body; on a key, 47 alone, an absolute SID (RFC 9254 section 4.2.1). Every other tag is rejected. |
| Simple values                    | Only `false` (`0xF4`), `true` (`0xF5`) and `null` (`0xF6`). `undefined` and other simple values are rejected. |
| Floats                           | Half, single and double precision are accepted by the decoder; YANG has none to send. |
| Map keys                         | MUST be integers (major type 0 or 1). Any other key type is rejected. |
| Duplicate keys in one map        | MUST be rejected. |
| Text strings                     | MUST be valid UTF-8. |
| Integer width                    | Senders SHOULD use the shortest ("preferred") encoding. Receivers MUST accept any width. |

Violations are reported as `ERROR` `EBADMSG` (malformed CBOR) or
`EPROTO` (a restriction above), with `error-message` and, where possible,
`error-path`.

### 5.2 Keys

| Key                    | Meaning |
|------------------------|---------|
| `1` … `2⁶³ − 1` at the top | **SIDs** (RFC 9595): each a node's value, or a structure of the `cblink` module (section 6). |
| any integer below the top | **SID deltas** (RFC 9254 section 3.2), negative ones too: a child's SID minus its parent's (an rpc's or an action's, for their input's and output's children). |
| `0`, negative, or beyond `2⁶³ − 1` at the top | Not a SID. Taken, and never found. |

The framework's metadata, such as error details and stream credit, is the
`cblink` module's structures, at their SIDs beside the other items.

### 5.3 Values

Each node's value is encoded as RFC 9254 says, YANG.md section 3 has the
table: containers, list entries, notifications and structures as maps;
lists and leaf-lists as arrays; each type of leaf as its own kind, with
tags where a union's members could be told apart no other way.

### 5.4 Unknown nodes

A receiver reading operational data MUST ignore a SID it does not know,
so that an old receiver interoperates with a new sender. Its value is
still subject to the encoding rules and limits in sections 5.1 and 11,
because it is decoded. An EDIT that names a SID the receiver does not
implement is refused (`unknown-element`), as every YANG protocol does.

---

## 6. The framework: the cblink module's structures

What version 1 carried under negative keys is, in version 2, the data
structures (RFC 8791) of the YANG module `cblink`
(`share/yang/cblink@2026-10-13.yang`), each at its SID in the body like
any other item, its value YANG-CBOR (RFC 9254):

| Structure | SID (provisional) | Fields | Used in |
|-----------|-------------------|--------|---------|
| `error`   | 60 000 + 22 | `error-type`, `error-tag` (an identity), `error-app-tag`, `error-path` (an instance-identifier), `error-message` (≤ 1024 characters), `error-info`, `errno`, `cookie` (≤ 256 B) | `ERROR`, ack (warning, cookie), `S_RESET`; and the next notification after some were missed, with `errno` `ENOBUFS` |
| `credit`  | 60 000 + 31 | `increment` (≤ 2³¹−1) | `S_OPEN`, its accept, `S_CREDIT` |
| `close`   | 60 000 + 42 | `code`, `message` | `S_CLOSE` |
| `hello`   | 60 000 + 33 | `limits`, `implementation`, `content-id` | the control family's `hello` |
| `notification` | 60 000 + 45 | `event-time`, `event` | `NOTIFY` of YANG notifications |
| `user`    | 60 000 + 53 | `name` | beside a request: the user it is made for (RFC 8341), taken only from a peer the receiver trusts to say so |
| `accept`  | 60 000 + 55 | `warning` (error-app-tags) | beside a request: the warnings it goes on despite |
| `datastore` | 60 000 + 57 | `name` (running, candidate, operational) | beside a family-1 GET or EDIT: the datastore (RFC 8342) |
| `warnings` | 60 000 + 59 | `warning[]` (`error-path`, `error-app-tag`, `error-message`) | in an answer: RFC 6241's errors of severity warning |

An `ERROR` frame's `error` structure also carries `error-app-tag` where
the refusal has one: a warning the request may accept.

The SIDs are the module's `.sid` file's (`share/yang/cblink@2026-10-13.sid`);
see `share/yang/SIDS.md` in Arcana for the block they are taken from.

### 6.1 Error frames (`NLMSG_ERROR` with extended ack)

An `ERROR` frame echoes the request's `family`, `cmd` and `seq`. Its body
holds the `error` structure:

- `errno` (**required** in `ERROR`): an errno-style code ≥ 1. The **wire
  numbering is FreeBSD's `<sys/errno.h>`**. Implementations on other
  systems MUST map to and from it. The library exposes these values
  unchanged as `E*` constants.
- `error-type` and `error-tag`: RFC 8040's, the tag an identity derived
  from `cblink:error-tag`, which gives a console answering RESTCONF the
  HTTP status of RFC 8040 section 7. The library sends `application` and
  the tag of the errno: `access-denied` for `EACCES` and `EPERM`,
  `data-exists`, `data-missing`, `invalid-value`, `too-big`, `in-use`,
  `operation-not-supported`, `resource-denied`, `malformed-message`, or
  `operation-failed`.
- `error-message` (optional): a human-readable message, like
  `NLMSGERR_ATTR_MSG`.
- `error-path` (optional): what is at fault, an instance-identifier: a
  SID, or an array of the target's SID and keys. A path within a
  program's own body, `cbl_req_set_err()`'s, is sent in that array
  shape.
- A required item missing: `error-tag` `missing-element`, its key the
  last element of `error-path`, like `NLMSGERR_ATTR_MISS_TYPE`.
- `cookie` (optional): opaque, command-specific bytes, on an ack too.

### 6.2 Standard error codes

| Code              | Value | Meaning in cblink |
|-------------------|------:|-------------------|
| `ENOENT`          | 2     | Unknown family name, unknown group. |
| `E2BIG`           | 7     | Too many values in a body (`max_attrs`). |
| `EACCES`          | 13    | Command requires an authenticated peer. |
| `EEXIST`          | 17    | Family name already registered; stream id reused. |
| `EINVAL`          | 22    | Policy violation (wrong kind, out of range); invalid flags. |
| `ENOSPC`          | 28    | Stream table full (`max_streams`). |
| `EAGAIN`          | 35    | Server busy (`max_inflight`). Retry later. |
| `EMSGSIZE`        | 40    | Frame larger than `max_frame` or the transport limit. |
| `EPROTONOSUPPORT` | 43    | Unsupported protocol version. |
| `EOPNOTSUPP`      | 45    | Unknown command; dump not supported. |
| `ENOBUFS`         | 55    | Stream flow-control violation (sender exceeded credit). |
| `ETIMEDOUT`       | 60    | Handler or stream idle timeout. |
| `ELOOP`           | 62    | Nesting deeper than `max_depth`. |
| `ECANCELED`       | 85    | Stream reset by application. |
| `EBADMSG`         | 89    | Malformed CBOR, or trailing bytes. |
| `EPROTO`          | 92    | Valid CBOR that violates section 5.1, or a stream state violation. |

### 6.3 Example: error frame

The request was a `kv` (family 17) `get` (cmd 1) with seq 1. It failed with
`ENOENT`, the message `"no such key"`, and path `[1]`:

```
CB 4C 02 18  00 00 00 35  00 11 00 01  00 00 00 20  magic,v2,hdrlen=24 len=53 fam=17 cmd=1 flags=ERROR
00 00 00 01  00 00 00 00                            seq=1 stream=0
A1                                                  map(1)
   19 EA 76                                         60 022 (cblink:error):
   A5                                                 map(5), keys deltas from it
      01 03                                           +1 error-type: application (3)
      02 19 EA 71                                     +2 error-tag: 60 017 (data-missing)
      04 81 01                                        +4 error-path: [1]
      05 6B 6E 6F 20 73 75 63 68 20 6B 65 79          +5 error-message: "no such key"
      07 02                                           +7 errno: 2 (ENOENT)
```

---

## 7. Families and the control family

### 7.1 Family ids

- `0` is the built-in control family `"ctrl"`, the YANG module
  `cblink-ctrl` (section 7.2).
- `1` is the built-in YANG family `"cblink.yang"` (section 7.6), present
  once a program serves YANG modules.
- `2` … `65535` are assigned dynamically by each endpoint when a family is
  registered. Clients MUST resolve names to ids with `ctrl get-family` and
  MUST NOT hard-code them. Ids are not reused while the endpoint runs,
  unless all 65534 have been used.
- Both ends of a connection have their own registry. A client may register
  families too, and the server may then send requests to the client (section
  12). A family id is meaningful only towards the endpoint that assigned it.
- Family names match `[a-z][a-z0-9_.-]{0,62}`. Names starting with `cblink.`
  and the name `ctrl` are reserved.

### 7.2 Control family (`family = 0`)

The control family is the YANG module `cblink-ctrl`
(`share/yang/cblink-ctrl@2026-10-13.yang`, its SIDs from 60 200 in
`cblink-ctrl@2026-10-13.sid`; reference: [ctrl.md](ctrl.md)). Each command
is one of its rpcs: the request's body is `{SID(rpc): input}`, the reply's
`{SID(rpc): output}`, the input's and output's children keyed by deltas
from the rpc's SID, as family 1's RPC (section 7.6). A request without the
rpc's item has an empty input.

| cmd | Name             | Kind          | Request (input)             | Reply (output) |
|----:|------------------|---------------|-----------------------------|----------------|
| 1   | `get-family`     | do, dump      | `id` **or** `name` (do); none (dump) | `id`, `name`, `version`, `op[]` (`cmd`, `name`, `flags`), `group[]` (`id`, `name`, `flags`) |
| 2   | `subscribe`      | do            | `family-id`, `group-id` (required) | — (ack) |
| 3   | `unsubscribe`    | do            | `family-id`, `group-id` (required) | — (ack) |
| 4   | `ping`           | do            | `cookie` (optional, ≤ 64 B) | `cookie` (echo) |
| 5   | `hello`          | do            | the `cblink:hello` structure | the `cblink:hello` structure |
| 6   | `family-added`   | notification  | —                           | as `get-family`'s output |
| 7   | `family-removed` | notification  | —                           | `id`, `name` |

`op/flags` are bits: `do` (position 0), `dump` (1), `stream` (2), `push`
(3), `auth` (4), the `CBL_OPF_*` values; `group/flags` has `auth`
(position 4), `CBL_MCF_AUTH`.

The control multicast group `"notify"` has the fixed group id **1**. It
carries `family-added` and `family-removed`, each as family 1's
notifications are sent: the `cblink:notification` structure, the
notification's content in its `event`. Other group ids are assigned
dynamically, starting at 2, and are unique per endpoint.

`hello` is optional. It lets a sender learn the receiver's limits
(`max-frame`, `max-depth`, `max-attrs`, `max-streams`, `stream-window`)
and implementation before exceeding them; the `cblink:hello` structure
goes both ways. Without it, a sender assumes the defaults in section 11.

### 7.3 Example: resolving family `"kv"`

Request: `ctrl` (0), `get-family` (1), flags `REQUEST`, seq 7, body
`{60 216 (get-family): {+3 name: "kv"}}`:

```
CB 4C 02 18  00 00 00 21  00 00 00 01  00 00 00 01   len=33 fam=0 cmd=1 flags=REQUEST
00 00 00 07  00 00 00 00                             seq=7 stream=0
A1 19 EB 38                                          {60 216 (get-family):
   A1 03 62 6B 76                                      {+3 name: "kv"}}
```

Reply: flags `0`, seq 7, the output: `kv` is family 2, version 1, with
command 1 `get` (do) and group 2 `changes`:

```
CB 4C 02 18  00 00 00 42  00 00 00 01  00 00 00 00   len=66 fam=0 cmd=1 flags=0
00 00 00 07  00 00 00 00                             seq=7 stream=0
A1 19 EB 38                                          {60 216 (get-family):
   A5                                                  map(5), deltas from 216
      05 81 A3 01 40 02 02 03 67 63 68 61 6E 67 65 73  +5 group: [{+1 flags: h'', +2 id: 2, +3 name: "changes"}]
      09 02                                            +9 id: 2
      0A 62 6B 76                                      +10 name: "kv"
      0B 81 A3 01 01 02 41 01 03 63 67 65 74           +11 op: [{+1 cmd: 1, +2 flags: h'01' (do), +3 name: "get"}]
      0F 01                                            +15 version: 1
```

### 7.4 Example: a do request and its acknowledgement

`kv` (17) `get` (1), flags `REQUEST|ACK`, seq 1, body `{1: "foo"}`:

```
CB 4C 02 18  00 00 00 1E  00 11 00 01  00 00 00 03   len=30 fam=17 cmd=1 flags=REQUEST|ACK
00 00 00 01  00 00 00 00                             seq=1
A1 01 63 66 6F 6F                                    {1: "foo"}
```

The reply follows with flags `0`, seq 1, body `{1: "foo", 2: h'0102'}`.
Then comes the acknowledgement, a header-only frame:

```
CB 4C 02 18  00 00 00 18  00 11 00 01  00 00 00 02   len=24 flags=ACK
00 00 00 01  00 00 00 00                             seq=1, empty body
```

### 7.5 Example: dump

A request with flags `REQUEST|DUMP` (`0x05`) is answered by N frames with
flags `MULTI` (`0x08`), one object each, then a header-only frame with flags
`MULTI|DONE` (`0x18`). All of them carry the request's seq.

### 7.6 The YANG family (`family = 1`)

`"cblink.yang"` serves the data, rpcs and actions of the YANG
modules a program implements, by SID, in the shape of CORECONF's methods
(draft-ietf-core-comi, section 3). Its bodies are version 2's: top-level
keys are SIDs, values YANG-CBOR (RFC 9254).

| cmd | Name   | Kind     | Request | Reply |
|----:|--------|----------|---------|-------|
| 1   | `GET`  | do, dump | `{cblink:get: {target: [SID, ...]}}`, or empty: every top-level data node served | do: `{SID: value, ...}`; dump: one `MULTI` frame per node, `{SID: value}` |
| 2   | `EDIT` | do       | `{SID: value or null, ...}` | ack |
| 3   | `RPC`  | do       | `{SID(rpc): input or null}`; an action's, `{SID(action): input or null, cblink:action: {target: instance-identifier}}` | `{SID(rpc): output}`, or `{SID(rpc): null}` when the rpc has no output; an action's likewise |
| 4   | `NOTIFY` | notification, group `notify` | — | `{cblink:notification: {event-time, event: {delta: content}}}` |
| 5   | `GET-SID` | dump | empty | one `MULTI` frame per module: `{1301: sid-file}` |
| 6   | `SUBSCRIBE` | push stream | `{SID(establish-subscription): input}` | accept `{SID(establish-subscription): output}`; data, one `cblink:notification` each |

- **GET** is CORECONF's FETCH. A node that is not instantiated is left
  out of the reply. A target is a top-level node's SID; a list entry's
  (`[SID, keys...]`) is for a later revision. With `cblink:get`'s
  `xpath-filter`, only what the expression selects of the nodes read
  comes back, with the nodes above it and a list entry's keys (NETCONF's
  xpath filter, RFC 6241 section 8.9; XPath-lite, its prefixes the
  modules' names); the nodes are of one server's modules. An expression
  that does not parse is `invalid-value`; a dump takes none.
- **EDIT** is CORECONF's iPATCH: a value creates or replaces the node, null
  deletes it. Only configuration (`config true`) is edited. The request
  is all or nothing: every value is decoded and validated (YANG.md
  section 4) before any change is made,
  and if one node's edit fails, those already made are undone (RFC 6241
  section 7.2, rollback-on-error).
- **RPC** is CORECONF's POST, its input validated. An rpc's input and
  output are keyed by the
  rpc's SID, and their children's deltas are from the rpc's SID, not the
  `input` or `output` node's (RFC 9254 section 3.2). An action is
  called likewise, keyed by its SID, with `cblink:action`'s `target`
  beside it: the instance-identifier (RFC 9254 section 6.13.1) of the
  node it acts on, its parent, a list entry as `[SID, keys...]` with the
  keys of every list from the top down. A target that is no instance of
  the action's parent is refused (`bad-element`), as is an action
  without one (`missing-element`).
- **NOTIFY** frames carry YANG notifications to the subscribers of group
  `notify` (section 9). The envelope is the `cblink:notification`
  structure: `event-time` (RFC 3339, UTC) and the anydata `event`, whose
  one key is the notification's SID as a delta from `event`'s own (RFC
  9254: an anydata's keys are as a container's), and whose value is the
  notification's content.
- **GET-SID** sends each served module's `.sid` file as RFC 9595's
  `ietf-sid-file` structure (SID 1301, in IANA's range 1300–1349 for that
  module), so a client that has the module but not its numbering can
  decode what the server speaks. `cblink-gen -m server` puts the `.sid`
  files given with `-s` in the server's table.
- **SUBSCRIBE** is a dynamic subscription (RFC 8639) on a push stream
  (section 8), where the server's modules have
  `ietf-subscribed-notifications`. The open carries
  `establish-subscription`'s input as an rpc's; the accept its output,
  the subscription's `id`; each data frame one record in `NOTIFY`'s
  envelope. Two targets are served: the `NETCONF` stream, every
  notification the server sends to group `notify` that the
  `stream-xpath-filter` selects; and, with `ietf-yang-push` and
  `ietf-datastores`, the `operational` datastore with `periodic`
  (RFC 8641): a `push-update` every `period` (10 centiseconds at least)
  from `anchor-time` (without one, at once), its
  `datastore-contents` what the `datastore-xpath-filter` selects of the
  data the server's get handlers read on the stream's connection, and
  `incomplete-update` where a read failed. With `on-change` (where
  `ietf-yang-push`'s feature is on), the data is read every
  `dampening-period`, a second at least, and compared with the last
  read: the first read is a `push-update` unless `sync-on-start` is
  false, and each change after a `push-change-update` whose
  `yang-patch` (RFC 8072) has an edit per node made (`create`), changed
  (`replace`) or gone (`delete`), its `target` the node's RFC 8040
  api-path and its `value` the node; `excluded-change` leaves those types
  out. A `stop-time` closes the stream ("stop-time reached"); the
  subscription ends with its stream. A stream's `replay-start-time`
  replays what the program keeps since then (its replay hook), each
  record at its own time, then `replay-completed`, then the live ones;
  `replay-start-time-revision` in the output says where it began when
  the program keeps less. When a record does not fit in the stream's
  credit the subscription is suspended, its records counted as
  excluded; once the subscriber grants credit again it is told
  `subscription-suspended` (`unsupportable-volume`) and
  `subscription-resumed`, and an on-change subscription pushes the whole
  of it again. `modify-subscription` and `resync-subscription` are the
  program's rpcs, answered by `cbl_ysub_modify()` and
  `cbl_ysub_resync()`; the first sends `subscription-modified`. Subtree
  filters, filters by reference and configured subscriptions are not
  served: a record that does not fit the
  stream's credit is left out. An input member that is not served is
  refused by name (`operation-not-supported`), and the open fails with
  the error.
- **Errors.** The `cblink:error` structure's `error-path` is the SID of
  the node at fault, alone; its `error-tag` says why, e.g.
  `unknown-element` for a SID no served module has,
  `operation-not-supported` for a node without the handler asked for or
  a `config false` node edited, `bad-element` for a value that is not
  the node's.

---

## 8. Streams

A stream is a long-lived, ordered, bidirectional channel of `S_DATA` frames,
like a WebSocket connection, multiplexed on a connection. Either end can
open one.

### 8.1 Stream ids

- `stream` is a 32-bit id, never `0`.
- The endpoint that **initiated the connection** opens streams with **odd**
  ids. The accepting endpoint uses **even** ids. Simultaneous opens therefore never collide.
- Each endpoint's ids are strictly increasing within a connection. An open
  that reuses or decreases an id is rejected with `EPROTO`.
- All frames of a stream carry the `family` and `cmd` of the opening
  request. A mismatch is a stream protocol error and resets the stream with
  `EPROTO`.

### 8.2 Lifecycle

```
           opener                                   acceptor
             |  REQUEST|S_OPEN  seq=s id=n {credit: W_o, ...}|
             |---------------------------------------------->|  handler checks,
             |                                               |  accepts
             |  S_OPEN          seq=s id=n {credit: W_a}     |
             |<----------------------------------------------|  (or ERROR|S_OPEN seq=s: rejected)
             |                                               |
             |  S_DATA  id=n {payload attrs}  ...            |  both directions,
             |<--------------------------------------------->|  within credit
             |  S_CREDIT id=n {cblink:credit: {increment: k}}|
             |<--------------------------------------------->|
             |  S_HCLOSE id=n          (no more data from me)|
             |---------------------------------------------->|
             |  S_DATA|S_HCLOSE id=n   (last data from peer) |
             |<----------------------------------------------|  both half-closed:
             |                                               |  stream is gone
```

| Event      | Meaning |
|------------|---------|
| `S_OPEN` request | Body: the opening command's request, which its handler checks, plus the `credit` structure, the opener's initial receive window in bytes. If it is absent, the opener's configured default window applies. The opener may send `S_DATA` only after it receives the accept, because the acceptor's window is unknown until then. |
| accept     | Body: the `credit` structure, the acceptor's initial window, and optionally the family's own items (an open reply). It may carry `S_DATA` or `S_HCLOSE` too. |
| reject     | `ERROR|S_OPEN` with the stream id and the `cblink:error` structure. The stream never existed. |
| `S_HCLOSE` | The sender sends no more `S_DATA`. It still receives data and still sends `S_CREDIT`. When both directions are half-closed, the stream is closed and its id is released. |
| `S_CLOSE`  | Graceful close of both directions, with the optional `close` structure, a `code` and a `message` (like the WebSocket close frame). After sending it, an endpoint sends nothing more on the stream except a reply `S_CLOSE`. The receiver delivers any data already received, replies with `S_CLOSE`, and the stream is gone. If no reply arrives within `stream_close_timeout` (default 10 s), the stream is reset locally. |
| `S_RESET`  | Abort. Optional `error` structure: its `errno` and `error-message`. Pending data is discarded. No reply is sent. The stream is gone immediately. A frame for a stream id that was never opened (above the highest id opened with its parity) is answered with `S_RESET` (`EPROTO`), at most once per id. Frames for a closed stream (its id at or below that) are dropped silently. A stream frame whose body does not decode resets its stream. |

### 8.3 Credit-based flow control

- Each direction has a **window** in bytes, granted by the receiver.
- An `S_DATA` frame costs its **total frame length**, header included. This
  means an empty-body data frame still costs 24 bytes and cannot be sent
  without limit. A sender MUST NOT send an `S_DATA` frame larger than its
  remaining credit.
- The receiver grants more credit with `S_CREDIT {cblink:credit: {increment}}`, typically
  after the application has consumed data. Increments are added to the
  window. A window above 2³¹−1 is a flow-control error.
- A receiver whose window is exceeded resets the stream with `ENOBUFS`.
- An initial window smaller than `max_frame` is allowed. A sender facing a
  window smaller than the frame it wants to send waits for more credit and
  never splits frames.
- Credit applies only to `S_DATA`. Control frames (`S_OPEN`, `S_HCLOSE`
  without data, `S_CLOSE`, `S_RESET`, `S_CREDIT`) are always allowed.
- Connection-level protection: an endpoint limits concurrently open streams
  (`max_streams`, default 64; an excess open is rejected with `ENOSPC`). It
  also bounds per-connection buffered input and output (section 11).

### 8.4 Example: stream open, accept, data, credit, half-close

`kv` (17) `watch` (cmd 3), stream id 1 (opened by the connection
initiator), opener window 65536, acceptor window 32768:

```
CB 4C 02 18  00 00 00 2A  00 11 00 03  00 01 00 01   len=42 fam=17 cmd=3 flags=REQUEST|S_OPEN
00 00 00 08  00 00 00 01                             seq=8 stream=1
A2 01 65 75 73 65 72 2F                              {1: "user/",
   19 EA 7F  A1 01 1A 00 01 00 00                     cblink:credit: {increment: 65536}}

CB 4C 02 18  00 00 00 21  00 11 00 03  00 01 00 00   len=33 flags=S_OPEN (accept)
00 00 00 08  00 00 00 01                             seq=8 stream=1
A1 19 EA 7F A1 01 19 80 00                           {cblink:credit: {increment: 32768}}

CB 4C 02 18  00 00 00 21  00 11 00 03  00 02 00 00   len=33 flags=S_DATA
00 00 00 00  00 00 00 01                             seq=0 stream=1
A1 01 66 75 73 65 72 2F 61                           {1: "user/a"}     costs 33 credit

CB 4C 02 18  00 00 00 20  00 11 00 03  00 20 00 00   len=32 flags=S_CREDIT
00 00 00 00  00 00 00 01                             seq=0 stream=1
A1 19 EA 7F A1 01 18 21                              {cblink:credit: {increment: 33}}

CB 4C 02 18  00 00 00 18  00 11 00 03  00 04 00 00   len=24 flags=S_HCLOSE
00 00 00 00  00 00 00 01                             stream=1, empty body
```

### 8.5 Push streams

A command may be declared **push** (op flag `0x8`). The acceptor (normally
the server) sends data, and the opener sends no `S_DATA`: the opener's
direction is half-closed implicitly when the stream is accepted.

---

## 9. Multicast notifications

- A family declares named multicast groups. Each group has an id assigned
  by the endpoint (control `notify` is fixed at 1).
- A peer subscribes with `ctrl subscribe {family-id, group-id}` and
  unsubscribes with `ctrl unsubscribe`. Subscribing to a group flagged
  "authentication required" from an unauthenticated peer fails with `EACCES`.
- A notification is a frame with flags `NOTIFY`, `seq = 0`, `family` and
  `cmd` set to the notification command, and **`stream` = group id**.
- Notifications are best-effort per subscriber. If a subscriber's send queue
  is over its limit (`sendq_bytes`), the notification is dropped for that
  subscriber and a per-connection drop counter is incremented. The next
  notification delivered to that subscriber includes the `error`
  structure with `errno` `ENOBUFS`, signalling "you missed notifications",
  like
  `ENOBUFS` on a netlink socket overrun.

Example: `kv` (17) notification `changed` (cmd 4), group 2, body
`{1: "k"}`:

```
CB 4C 02 18  00 00 00 1C  00 11 00 04  00 00 00 40   len=28 flags=NOTIFY
00 00 00 00  00 00 00 02                             seq=0 group=2
A1 01 61 6B                                          {1: "k"}
```

---

## 10. Transport rules

### 10.1 TCP and AF_UNIX (`SOCK_STREAM`)

Frames are concatenated on the byte stream. The receiver reads 24 bytes,
validates the header (section 2.1), then reads `length - hdrlen` body bytes
into a buffer allocated only after validation.

### 10.2 SCTP (one-to-one style, `SOCK_STREAM` + `IPPROTO_SCTP`)

- **Plaintext:** one frame per SCTP message. Message boundaries replace the
  `length` scan, and `length` MUST equal the message size.
- **SCTP stream mapping:** SCTP stream 0 carries everything that is not a
  cblink stream frame. cblink stream `n` is mapped to SCTP stream
  `1 + (n mod (os − 1))`, where `os` is the negotiated number of outbound
  streams. Ordering within a cblink stream is preserved, and cblink streams
  do not block each other or control traffic. When `os == 1`, everything uses
  SCTP stream 0.
- **DTLS over SCTP (RFC 6083), mTLS:** base OpenSSL supports it
  (`BIO_new_dgram_sctp`), and it requires SCTP-AUTH
  (`net.inet.sctp.auth_enable=1`, the default). DTLS records are limited to
  16 KiB, so in DTLS mode each SCTP stream is an ordered byte stream of
  frames delimited by `length`, as on TCP. The same stream mapping applies.
- Other SCTP features used are listed in TRANSPORTS.md. They do not change
  the wire format.

---

## 11. Limits

All limits are per context and can be overridden per listener or connection.
They are enforced **before allocation**:

- The header is validated in a fixed 24-byte buffer before the body buffer
  is allocated (`max_frame`).
- The body is decoded in two passes. The first pass checks well-formedness,
  depth, item count and the section 5.1 restrictions, and allocates nothing.
  The second pass allocates the exact node array from the message arena.
  Strings and byte strings are not copied; they point into the frame buffer.

| Limit                  | Default | Range           | Applies to |
|------------------------|--------:|-----------------|------------|
| `max_frame`            | 1 MiB   | 4 KiB … 64 MiB  | `length` |
| `max_depth`            | 16      | 1 … 64          | Nesting of maps and arrays; the body map is depth 1. |
| `max_attrs`            | 4096    | 16 … 1 Mi       | Total decoded values in one body (map values and array elements, recursively; keys are not counted). |
| `max_streams`          | 64      | 0 … 65536       | Concurrent streams per connection. |
| `stream_window`        | 256 KiB | 0 … 2³¹−1       | Default initial window. |
| `max_inflight`         | 256     | 1 … 65536       | Outstanding requests a server processes per connection. Excess requests get `EAGAIN`. |
| `sendq_bytes`          | 8 MiB   | 64 KiB … 1 GiB  | Per-connection output buffer. A server stops reading a connection whose queue is over three quarters of it, until it is under a quarter, so a peer that does not read its replies is not read either. Dumps pause at half of it and take turns of 64 parts; notifications and other replies are dropped above it, but terminal frames (`ACK`, `ERROR`, `DONE`) and stream control frames are not: they queue up to twice `sendq_bytes`, and a connection that reaches that (its peer keeps asking and never reads the answers) is closed. A client's own requests get `ENOBUFS` above it. A client dump buffers up to it, then the connection stops reading until the consumer catches up. |
| `handshake_timeout`    | 10 s    |                 | TLS/DTLS handshake, and the first full frame on plaintext. |
| `idle_timeout`         | 300 s   | 0 = off         | Dead-peer detection. After half of it with no frame in either direction, the endpoint sends `ctrl ping`; a peer that has not answered when the other half is over is dropped. An application that drives a connection itself (no loop) answers pings only while it keeps calling `cbl_conn_process()`. |
| `stream_close_timeout` | 10 s    |                 | Section 8.2; also how long a closing connection may take to send what is queued. |

---

## 12. Symmetry

The protocol does not distinguish client and server roles. Either endpoint
may send requests, dump requests, stream opens and notifications, provided
the receiver has registered the family. The only asymmetries are the
stream-id parity rule (section 8.1) and the transport's connect/accept
direction.

---

## 13. Versioning

- An incompatible change increments `version`. A receiver rejects unknown
  versions (section 2.1).
- Compatible extensions use reserved flag bits only with a new version, new
  structures and leaves of the `cblink` module (new SIDs, never reused),
  header bytes past offset 24 (`hdrlen`), and new control-family rpcs or
  nodes. Unknown nodes are ignored on reads (section 5.4).
- A module evolves through its revisions: new nodes, at new SIDs, are
  compatible; removing or retyping one is not, and needs a new module.
  A family of a program's own evolves through its `version` (reported by
  `get-family`); new commands are compatible.
