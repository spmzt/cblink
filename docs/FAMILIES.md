# Families

A **family** is a named set of operations an endpoint offers, with its
attributes, multicast groups and streams. It plays the part of a generic
netlink family. This document covers designing families, how they are
registered and found, and the built-in control family. SPEC-FORMAT.md
describes how to write one down, and GENERATOR.md describes the code
generated from it.

## 1. Anatomy

| Part | What it is |
|------|------------|
| name | `[a-z][a-z0-9_.-]{0,62}`, unique on an endpoint. `ctrl` and names starting with `cblink.` are reserved. |
| version | A number reported to clients (`ctrl getfamily`). It is the family's own; cblink does not interpret it. |
| operations | Commands `1 … 65535`. Each has a request policy and supports any of: `do` (request and reply), `dump` (request and a series of items), opening a stream, or a notification. `auth` restricts it to authenticated peers. |
| attribute sets | Attribute keys `1 … 65535` with types and checks. Sets nest. |
| multicast groups | Named groups that notifications are sent to. A group can require an authenticated subscriber. |
| streams | Long-lived channels opened through an operation (STREAMS.md). |

## 2. Designing a family

**Numbers are forever.** Once a family is in use, never renumber or reuse
an attribute key or a command number. Add new ones at the end, and leave
retired numbers unused.

**Old and new peers coexist.**
- A receiver ignores attributes it does not know (WIRE-FORMAT.md
  section 5.4). New optional attributes are therefore always compatible.
- Making an attribute required, changing its type, or narrowing its checks
  is not compatible.
- Bump the family's `version` when clients need to tell the difference.
  Clients see it in `ctrl getfamily`, and generated clients record it in
  `struct P_client`.
- An incompatible redesign is better done as a new family with a new
  name.

**Choose the operation by the shape of the data:**
- **`do`** for one answer. The reply carries the result; a failure is an
  errno value plus an extended ack that says which attribute was wrong
  and why.
- **`dump`** for listing many objects. Items are produced one at a time as
  the client keeps up, so a large table never has to fit in memory or in
  the send queue.
- **Notifications** for telling every interested peer that something
  changed. Subscribers that fall behind lose notifications and are told
  so; they should then re-read the state with a dump.
- **Streams** for continuous data in one or both directions, with flow
  control. Use a push stream for a feed, and a bidirectional stream for a
  conversation.

**Validate in the policy, not the handler.** Types, ranges, lengths,
enumerations and required attributes belong in the spec's `checks`. The
library enforces them before the handler runs and reports violations
precisely. Handlers are left with the checks that need state.

**Mark privileged operations `auth: true`.** They then run only for peers
authenticated by mTLS or a trusted local socket.
Handlers that need finer control read the peer's identity with
`cbl_req_peer()`.

## 3. Registration and discovery

- **Registration.** `cbl_family_register()` (or the generated
  `P_register()`) adds a family to a context and assigns it an id
  `1 … 65535`.
  - Ids are per endpoint and dynamic. A client must not hard-code them.
  - Every subscriber to the control family's `notify` group is told with a
    `newfamily` notification.
- **Unregistration.** `cbl_family_unregister()` removes the family at once
  for new requests, sends `delfamily`, and waits until requests already
  running in it have finished. Its subscriptions end.
- **Discovery.** Clients resolve a name with `ctrl getfamily`, through
  `cbl_resolve()` or the generated `P_client_init()`. They get:
  - the id and version;
  - the operations, with their flags;
  - the multicast groups, with their global group ids.
- **Both directions.** Families are not only for servers. A client may
  register families too, and the server can then send requests to it over
  the same connection.

## 4. The control family

Family id 0, `ctrl`, is built into every endpoint. Its spec is
`share/cblink/specs/control.yaml`; `ctrl.md` is its generated reference.

| Command | Kind | Purpose |
|---------|------|---------|
| `getfamily` (1) | do, dump | Resolve one family by name or id, or list all families with their operations and groups. |
| `subscribe` (2) | do | Join a family's multicast group, by global group id. |
| `unsubscribe` (3) | do | Leave it. |
| `ping` (4) | do | Liveness: the reply echoes `cookie`. |
| `hello` (5) | do | Exchange receive limits (`max-frame`, `max-depth`, `max-attrs`, `max-streams`, `stream-window`) and implementation names. A sender that knows its peer's `max-frame` never sends larger frames. |
| `newfamily` (6) | notification | A family was registered. |
| `delfamily` (7) | notification | A family was unregistered. |

Both notifications go to the group `notify` (global id 1). The
library's client helpers are `cbl_resolve()`, `cbl_family_info_*()`,
`cbl_ping()`, `cbl_hello()`, `cbl_subscribe()` and `cbl_unsubscribe()`.
