# Families

A **family** is a named set of operations an endpoint offers, with its
multicast groups and streams. It plays the part of a generic netlink
family. Every body is YANG data (YANG.md): its items keyed by SID, its
values YANG-CBOR. This document covers the families an endpoint has, how
a program chooses between serving its YANG modules and a family of its
own, how families are registered and found, and the built-in control
family.

## 1. Anatomy

| Part | What it is |
|------|------------|
| name | `[a-z][a-z0-9_.-]{0,62}`, unique on an endpoint. `ctrl` and names starting with `cblink.` are reserved. |
| version | A number reported to clients (`ctrl get-family`). It is the family's own; cblink does not interpret it. |
| operations | Commands `1 … 65535`. Each supports any of: `do` (request and reply), `dump` (request and a series of items), opening a stream, or a notification. `auth` restricts it to authenticated peers. |
| multicast groups | Named groups that notifications are sent to. A group can require an authenticated subscriber. |
| streams | Long-lived channels opened through an operation (STREAMS.md). |

Three families are the library's: `ctrl` (id 0, section 4), the YANG
family `cblink.yang` (id 1, present once a program serves a module), and
none other; a program's own families get ids from 2.

## 2. Designing what a program offers

**Model the data in YANG.** A program's configuration, state, rpcs and
notifications are YANG modules; `cblink-gen` writes their structs, tables
and the server's handler table, and the YANG family serves them by SID:
GET, EDIT, RPC and NOTIFY, in CORECONF's shape (WIRE-FORMAT.md section
7.6). Clients read with the same tables, and generic ones fetch the
modules' `.sid` files with GET-SID.

**A family of its own** is for what is not data: a stream (a feed, a
conversation), or a command whose shape is the program's. Its bodies are
YANG data all the same, put and read with the helpers `cblink-gen`
writes (`X_put()`, `X_parse()`); `examples/stream` is one.

**Numbers are forever.** A SID is never reused or removed: an item that
goes is marked obsolete in its `.sid` file, and a module revision adds
items at the end of its range. A family's command numbers likewise.

**Old and new peers coexist.**
- A receiver reading operational data skips what it does not know; an
  EDIT with a SID the server does not implement is refused
  (`unknown-element`), as every YANG protocol does.
- New optional nodes are compatible; making a node mandatory, changing
  its type, or narrowing its range is not.
- An incompatible redesign is a new module revision, or a new module.

**Choose the operation by the shape of the data:**
- **`do`** for one answer. The reply carries the result; a failure is an
  errno value plus the `cblink:error` structure, which names the node at
  fault and the error-tag.
- **`dump`** for listing many objects. Items are produced one at a time as
  the client keeps up, so a large table never has to fit in memory or in
  the send queue.
- **Notifications** for telling every interested peer that something
  changed. Subscribers that fall behind lose notifications and are told
  so; they should then re-read the state with a dump.
- **Streams** for continuous data in one or both directions, with flow
  control. Use a push stream for a feed, and a bidirectional stream for a
  conversation.

**Let the module check.** Types, ranges, lengths, patterns and
enumerations belong in the module. The codec decodes strictly
(`CBL_YD_STRICT`) and the YANG family refuses what is not a node's;
handlers are left with the checks that need state.

**Mark privileged operations `CBL_OPF_AUTH`.** They then run only for
peers authenticated by mTLS or a trusted local socket. Handlers that need
finer control read the peer's identity with `cbl_req_peer()`.

## 3. Registration and discovery

- **Registration.** `cbl_family_register()` adds a family to a context and
  assigns it an id `2 … 65535`; `cbl_yserver_add()` serves a program's
  modules, bringing the YANG family (id 1) about the first time.
  - Ids are per endpoint and dynamic. A client must not hard-code a
    program's family's id.
  - Every subscriber to the control family's `notify` group is told with a
    `family-added` notification.
- **Unregistration.** `cbl_family_unregister()` removes the family at once
  for new requests, sends `family-removed`, and waits until requests already
  running in it have finished. Its subscriptions end.
- **Discovery.** Clients resolve a name with `ctrl get-family`, through
  `cbl_resolve()`. They get:
  - the id and version;
  - the operations, with their flags;
  - the multicast groups, with their global group ids.
- **Both directions.** Families are not only for servers. A client may
  register families too, and the server can then send requests to it over
  the same connection.

## 4. The control family

Family id 0, `ctrl`, is built into every endpoint. It is the YANG module
`cblink-ctrl` (`share/yang/cblink-ctrl@2026-10-13.yang`), each command one
of its rpcs; `ctrl.md` is its generated reference.

| Command | Kind | Purpose |
|---------|------|---------|
| `get-family` (1) | do, dump | Resolve one family by name or id, or list all families with their operations and groups. |
| `subscribe` (2) | do | Join a family's multicast group, by global group id. |
| `unsubscribe` (3) | do | Leave it. |
| `ping` (4) | do | Liveness: the reply echoes `cookie`. |
| `hello` (5) | do | Exchange the `cblink:hello` structure: receive limits (`max-frame`, `max-depth`, `max-attrs`, `max-streams`, `stream-window`) and implementation names. A sender that knows its peer's `max-frame` never sends larger frames. |
| `family-added` (6) | notification | A family was registered. |
| `family-removed` (7) | notification | A family was unregistered. |

Both notifications go to the group `notify` (global id 1). The
library's client helpers are `cbl_resolve()`, `cbl_family_info_*()`,
`cbl_ping()`, `cbl_hello()`, `cbl_subscribe()` and `cbl_unsubscribe()`.
