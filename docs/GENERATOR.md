# cblink-gen: the code generator

`cblink-gen` compiles YANG modules (RFC 7950) and writes what a cblink
program speaks them with, in the way Linux's YNL tools do for netlink:
the structs, the schema tables libcblink's YANG-CBOR codec (RFC 9254)
works by, helpers for messages, rpcs and notifications, a server's
handler table, the modules' reference, and their `.sid` files (RFC 9595).
This document describes how the generator works and what it writes;
cblink-gen(1) describes the command line, YANG.md what of YANG it takes.

```
cblink-gen [-adnV] [-F module:feature,...] ... [-b base]
           [-m h,schema,server,md,sid,sidjson,tree] [-o dir] [-p dir] ...
           [-s file.sid] ... module.yang ...
```

## 1. How it works

```
modules ──▶ libyang ──▶ schema model ──▶ .sid files ──▶ emitters ──▶ base.h
(.yang)     (yang.c)    + the profile   attached and    gen_yang.c   base_schema.c
                        (schema.c)      checked         gen_yschema.c base_server.c
                                        (sid.c,         gen_yserver.c base.md
                                        sidcbor.c)      gen_ymd.c     base.tree
                                                        gen_ytree.c   *.sid, *.sid.cbor
```

- **libyang compiles.** The modules named, and every module they may
  import (from their own directories and each `-p`), are read and
  compiled by libyang 3, features as `-F` says and deviations applied.
  The generator then works from its own model of the compiled schema
  (`schema.c`): nodes, types resolved through typedefs and leafrefs,
  choices and cases, `when` and `must`, defaults, identities, features.
- **The profile is checked.** What the runtime cannot do is refused at
  generation time, so it never meets it: an XPath expression outside
  XPath-lite, a pattern the translator does not know (`cbl_pattern.c`,
  XSD regular expressions to POSIX ERE), and the other limits YANG.md
  lists. Each refusal names the node and the construct.
- **Input is untrusted.** Every module is read before the generator
  enters capsicum(4) capability mode; the output directory is opened
  before, and only written in, after. A `.sid` file larger than 16 MiB is
  refused.
- **SIDs.** Every node, structure and identity is keyed by its SID, from
  the modules' `.sid` files (`-s`), in JSON or in their YANG-CBOR form.
  They are verified (no SID twice, none outside the file's ranges, every
  item of the module with one, empty `input` and `output` included).
  `-a` numbers the items that have none, as RFC 9595 Appendix B says, and
  rewrites the file: by namespace (module, identities, features, data),
  each in identifier order, from the file's assignment ranges. A file
  numbers every item of its module, whatever features a program enables:
  with `-F`, the files are verified and numbered against the modules
  compiled again with every feature on, and attached to what `-F`
  leaves.
- **All problems at once.** Errors are reported as
  `file:line:column: error: message` and collected up to a limit, so one
  run shows every mistake. Nothing is written if there is any error.
- **Deterministic output.** The output depends only on the modules, the
  `.sid` files and the generator version: no timestamps, no paths, no
  host details. The tests check this.
- **Atomic writes.** Each file is written to a temporary name in the output
  directory (`mkostempsat`) and renamed into place (`renameat`). An
  interrupted run leaves the previous files intact.

## 2. Names

A struct is named after its module, then the path to its node, with `-`
and `.` made `_`: `/kv:store/entry` is `struct kv_store_entry`, an rpc's
input `struct kv_clear_input`. A member is the node's name, likewise; one
that is a C keyword, or a macro a header may define in lower case
(`errno`, `assert`, `offsetof`, `unix`, ...), gets a `_` after it
(`errno_`). Two nodes that would have one name are an error.

## 3. What it writes

The examples use the module `kv` (`examples/kv/kv@2026-10-13.yang`).

### 3.1 Structs (`-m h`: `kv.h`)

A struct for each container, list entry, rpc and action input and
output, notification and structure (RFC 8791) of the modules named and
of those whose trees they add to, and one for each module's top-level
data (`struct kv`).

| YANG | C |
|------|---|
| container | a pointer to its struct, `NULL` when absent |
| list, leaf-list | `struct { size_t n; const T *v; }` |
| leaf other than a key | its value, and `bool has_<name>` |
| choice | `enum <struct>_<choice>`, the case given (0: none); the cases' members beside it |
| `int8` … `uint64` | `int8_t` … `uint64_t` |
| `decimal64` | `int64_t`, the value times 10^fraction-digits |
| `string` | `const char *` (UTF-8, checked) |
| `boolean`, `empty` | `bool` |
| `enumeration` | `enum <struct>_<leaf>` with the values of the module |
| `bits` | `struct cbl_bytes`, the bits by position, byte 0 first, and `#define`s of the positions |
| `binary` | `struct cbl_bytes` |
| `identityref` | `uint64_t`, the identity's SID |
| `instance-identifier` | `struct cbl_bytes`, as YANG-CBOR has it (a SID, or `[SID, keys...]`) |
| `leafref` | its target's type |
| `union` | `struct <struct>_<leaf>`: which member is set, and the member |
| anydata, anyxml | `struct cbl_bytes`, YANG-CBOR as it came |

### 3.2 Schema tables (`-m schema`: `kv_schema.c`)

The structures of `<cbl_schema.h>` the library decodes, encodes and
validates YANG-CBOR by:

- every node with its SID, its kind and flags, its type, its children
  sorted by SID, its keys, its choice and case, its `when` and `must`
  expressions, its defaults and its limits, a list's `unique` statements
  (each leaf by the data nodes from an entry down to it); and where it is
  in the
  structs, with `offsetof()` and `sizeof()`, so that the two cannot
  differ. An rpc's or an action's input and output carry the rpc's or
  the action's SID as the base their children's deltas are from (RFC 9254
  section 3.2);
- types shared between the nodes that have the same one, a pattern also
  as the POSIX ERE it translates to;
- each module's features, enabled or not;
- the identities a value may name, the modules' own and every one derived
  from a base an identityref has, wherever it is defined, each with all
  those derived from it, for `derived-from()`;
- every node again in one array by SID.

A node's children are found by a key's delta at once where their SIDs
follow one another, by a table of their places where they lie close, by
a binary search otherwise. What each module's tables come to is printed
and written at the top of the file.

### 3.3 Helpers (`kv.h`, defined in `kv_schema.c`)

| For | Functions |
|-----|-----------|
| each struct `X` | `X_encode(p, buf)`, `X_decode(data, len, p, a, flags, why, whylen)`: the value alone, in YANG-CBOR and back |
| | `X_put(msg, p)`, `X_parse(msg, p, a, flags, why, whylen)`: in a message, `{SID: value}`; an rpc's input and output under the rpc's SID |
| each rpc `R` | `R_call(conn, in, out, a, timeout_ms)`: the rpc called through family 1, its output read back |
| each notification `N` | `N_notify(ctx, p)`: sent to family 1's group `notify`; `N_notification(p, buf)`: `{SID: value}` as bytes; `N_parse()` reads one received, `ENOENT` for another |

`a` is a `cbl_yarena`: what a decode allocates is its, freed in one.

### 3.4 Server table (`-m server`: `kv_server.c`)

`const struct cbl_yserver kv_server`, which `cbl_yserver_add()` serves:
for each node a handler entry, by SID, and the handlers the program
defines as the header declares them:

| For | Handler |
|-----|---------|
| a top-level data node | `int kv_store_get(cbl_req *, struct kv *, cbl_yarena *)`: fill the node's member |
| a configuration one, too | `int kv_store_edit(cbl_req *, const struct kv *before, const struct kv *after)` |
| an rpc | `int kv_clear_rpc(cbl_req *, const struct kv_clear_input *, struct kv_clear_output *, cbl_yarena *)` |
| an action | `int kv_store_entry_touch_action(cbl_req *, const struct cbl_bytes *target, const ... *in, ... *out, cbl_yarena *)` |

The table also carries the `.sid` files given with `-s`, as GET-SID sends
them: the `ietf-sid-file` structure's value in YANG-CBOR.

### 3.5 Documentation and `.sid` files

- `-m md` (`kv.md`): a page for each module named: its tree diagram, and
  a table of the nodes it defines with their kind, type, config,
  mandatory, defaults, units and SIDs; its features and identities.
- `-m tree` (`kv.tree`): the RFC 8340 tree diagrams, exactly as
  `yanglint -f tree` prints them.
- `-m sid` (`kv@2026-10-13.sid.cbor`) and `-m sidjson`
  (`kv@2026-10-13.sid`): each `-s` file, in YANG-CBOR or in JSON.

## 4. Building programs from modules

`share/cblink/cblink.mk` (installed in `${LOCALBASE}/share/cblink/`)
generates and compiles a program's modules with bsd.prog.mk:

```make
PROG=		kvd
SRCS=		kvd.c
CBLINK_YANG=	kv@2026-10-13.yang
CBLINK_SIDS=	kv@2026-10-13.sid
.include "${LOCALBASE}/share/cblink/cblink.mk"
.include <bsd.prog.mk>
```

Its variables:
- `CBLINK_PARTS`: `h,server` by default; `h` alone for a program that
  serves no table;
- `CBLINK_YANG_BASE`: the outputs' name, the first module's by default;
- `CBLINK_DOCS=yes`: also write the modules' Markdown;
- `CBLINK_GEN`, `CBLINK_CFLAGS` and `CBLINK_LIBS`: point it at a build tree,
  as `examples/examples.mk` does.

The files are written into the object directory and added to `SRCS`.

## 5. cblink's own modules

The framework's structures are the module `cblink`, and family 0 the
module `cblink-ctrl` (`share/yang`). Their structs and schema tables are
committed in `lib/libcblink` (`cbl_ymod.h`, `cbl_ymod_schema.c`,
`cbl_yctrl.h`, `cbl_yctrl_schema.c`), with the control family's reference
`docs/ctrl.md`, because the library cannot depend on its own generator at
build time.
- `make -C lib/libcblink regen` refreshes the committed files.
- The `ymod_regen` test fails if they differ from what the generator now
  produces.

## 6. Tests (`usr.bin/cblink-gen/tests`)

- **yang_frontend:** modules compiled through libyang, features and
  deviations, the profile's refusals named.
- **sid_cbor:** `.sid` files numbered (`-a`), in JSON and YANG-CBOR and
  back, ietf-sid-file's own SIDs, and the server table's copy.
- **yang_h, yang_h_test:** the structs and tables of every shape and type
  compile at `WARNS=6`; lookups, the codec's kinds (decimal64, bits,
  identityref, instance-identifier, unions with tags 43 to 46), an rpc's
  deltas, the arena's limit, a round trip of every struct.
- **yang_tree:** tree diagrams equal to `yanglint -f tree`.
- **yfamily_test:** family 1 serving those tables over a connection: get,
  edit and its rollback, refusals, rpc, dump, notifications.
- **yvalid_test:** the static validator, a rule a case, on RFC 7950's
  examples; the defaults.
- **ymod_regen:** the committed files of cblink's modules are up to date.
- **determinism, cli, big_input, cblink_mk:** repeated runs give identical
  output, the command line, the size limit, and cblink.mk finding a
  module given in each form of path.
- `tools/yangwalk/tablecheck.sh` runs the same round trip over a corpus
  of modules (Arcana's `share/yang`: 51 modules, 8406 round trips).
