# cblink family spec format

The YAML that cblink-gen 0.1.0 reads.

A **family spec** describes one cblink family: its name, version,
definitions, attribute sets, operations, multicast groups, notifications
and streams. `cblink-gen` turns it into C code and Markdown documentation
(GENERATOR.md). The model is Linux YNL (`Documentation/netlink/specs/`),
adapted to CBOR kinds and cblink streams. One file describes one family.

The file is written in a **strict YAML subset**, defined in part 1. Every
valid spec is also valid YAML 1.2, but not every YAML document is a valid
spec.

---

## Part 1: the YAML subset

### 1.1 Lexical rules

| Rule | |
|------|--|
| Encoding | UTF-8 without a byte-order mark. NUL bytes are an error. |
| Line endings | LF. A CR is an error. |
| Indentation | Spaces only. A tab anywhere in indentation is an error. A tab inside a scalar's content is allowed only in quoted scalars. |
| Comments | `#` at the start of a line or after whitespace, to the end of the line. Comments are allowed wherever whitespace is allowed, except inside block scalars. |
| Document marker | An optional single `---` line before any content. `...`, `%` directives and multiple documents are errors. |
| Limits | File ≤ 1 MiB; line ≤ 4096 bytes; nesting depth ≤ 32; scalar ≤ 64 KiB; total nodes ≤ 100 000. |

### 1.2 Grammar

The grammar below is EBNF. `INDENT(n)` means exactly `n` spaces. Inside a
block, all entries use the same indentation, which is greater than the
parent's.

```
stream        = [ "---" NL ] { blank } block(0) { blank } EOF
block(n)      = mapping(n) | sequence(n)
mapping(n)    = map_entry(n) { { blank } map_entry(n) }
map_entry(n)  = INDENT(n) key ":" ( SP value_inline NL
                                  | [ SP comment ] NL nested(n) )
nested(n)     = block(m) with m > n
              | sequence(n)             (* "- " items may sit at the key's indentation *)
sequence(n)   = seq_entry(n) { { blank } seq_entry(n) }
seq_entry(n)  = INDENT(n) "-" ( SP value_inline NL
                              | SP map_entry_inline(n + 2)   (* "- name: x" *)
                              | [ SP comment ] NL block(m) )   (* m > n *)
map_entry_inline(k) = key ":" ... like map_entry(k), then optional further
                      map_entry(k) lines continuing the same mapping
value_inline  = plain | single_quoted | double_quoted | block_scalar
key           = plain_key        (* [A-Za-z0-9][A-Za-z0-9_-]* *)
blank         = [ SP* comment ] NL
```

**Scalars:**

- **plain**: does not start with any of
  ``- ? : , [ ] { } # & * ! | > ' " % @ ` `` or a space. It must not contain
  `": "` or `" #"`, and must not end with `:`. Trailing spaces are stripped.
  A plain scalar continues on the same line only; multi-line plain scalars
  are an error.
- **single_quoted**: `'…'`. The only escape is `''` for `'`. Single line.
- **double_quoted**: `"…"`. Single line. Escapes are `\\ \" \n \t \r \0 \/`
  and `\xHH`, `\uHHHH`, `\UHHHHHHHH`, where the code point must be a valid
  Unicode scalar value and not NUL. Any other escape is an error.
- **block_scalar**: `|` (literal) or `>` (folded), optionally followed by a
  chomping indicator `-` or `+`. Explicit indentation indicators are not
  supported. Content lines are indented more than the parent key. Used for
  `doc:`.

**Not supported** (each is an error with its own diagnostic): flow
collections (`[` … `]`, `{` … `}`), anchors (`&`), aliases (`*`), tags
(`!`), complex keys (`?`), merge keys (`<<`), multi-line plain or quoted
scalars, duplicate keys in one mapping, empty values (`key:` followed by no
nested block). An empty sequence or mapping is written by omitting the key.

**Scalar typing** is decided by the schema, never by YAML. A scalar is
always read as a string, and the schema says whether a field is a string,
an integer or a boolean:

- **Integers:** decimal `-?[0-9]+`, hex `0x[0-9a-fA-F]+`, or a reference to
  a `const` definition by name. They must fit the field's range.
- **Booleans:** exactly `true` or `false`. `yes`, `on` and `True` are
  errors.

### 1.3 Diagnostics

All errors and warnings use this form:

```
<file>:<line>:<column>: error: <message>
```

`line` and `column` are 1-based, and `column` counts bytes. The location
points at the first byte of the offending token, or at the key whose value
is wrong. `cblink-gen` stops after the first syntax error. After a
successful parse, it reports **all** semantic errors (up to 50) in file
order, then exits with status 1.

Examples:

```
kv.yaml:14:9: error: tabs are not allowed in indentation
kv.yaml:22:15: error: flow sequences ('[') are not supported; use a block sequence
kv.yaml:30:5: error: duplicate key 'name' (first defined at 29:5)
kv.yaml:41:19: error: undefined attribute-set 'entyr'
kv.yaml:47:11: error: attribute id 3 already used by 'value' (kv.yaml:18:11)
kv.yaml:52:16: error: invalid range: min-len (10) > max-len (4)
```

---

## Part 2: the schema

Field reference:

- `R` = required, `O` = optional.
- `name` values match `[a-z][a-z0-9-]*` (at most 63 characters). In C
  identifiers, `-` becomes `_`.
- `doc` is optional free text. It is copied into the generated header as a
  comment and into the Markdown documentation.

### 2.1 Top level

| Key | | Type | Meaning |
|-----|--|------|---------|
| `name` | R | name | Family name used for resolution (`ctrl getfamily`). The pattern is `[a-z][a-z0-9_.-]*`, matching WIRE-FORMAT.md section 7.1. |
| `version` | R | int 1 … 2³²−1 | Family version reported to clients. |
| `doc` | O | text | |
| `c-prefix` | O | C identifier | Prefix for every generated identifier. Default: `name` with `.` and `-` replaced by `_`. |
| `definitions` | O | seq of definition | Constants, enums and flag sets. |
| `attribute-sets` | R | seq of attribute-set | |
| `operations` | R | seq of operation | |
| `mcast-groups` | O | seq of group | |
| `streams` | O | seq of stream | |
| `fixed-id` | O | int | Accepted only with `cblink-gen -B` (builtin). It is used by `control.yaml` (`fixed-id: 0`). |

### 2.2 `definitions`

| Key | | Applies to | Meaning |
|-----|--|-----------|---------|
| `name` | R | all | |
| `type` | R | | `const`, `enum` or `flags` |
| `value` | R | const | Integer. |
| `entries` | R | enum, flags | Sequence. Each item is either a plain name or a mapping `{name, value?, doc?}`. |
| `doc` | O | all | |

- `enum` values start at 0, or after the previous explicit value, and
  increment by 1.
- `flags` values are bit masks starting at `1 << 0`. An explicit `value` on
  a flags entry is a **bit number** (0 … 63).

### 2.3 `attribute-sets`

| Key | | Meaning |
|-----|--|---------|
| `name` | R | |
| `doc` | O | |
| `attributes` | R | Sequence of attribute. |

Attribute:

| Key | | Type | Meaning |
|-----|--|------|---------|
| `name` | R | name | |
| `value` | O | int 1 … 65535 | Attribute key. Default: previous + 1, starting at 1. |
| `type` | R | see below | |
| `doc` | O | | |
| `nested-attributes` | R if `nest` | set name | |
| `multi-attr` | O | bool | The value is a CBOR array of `type`. |
| `enum` | O | definition name | Only for unsigned types. With an `enum` definition, the value must be one of its entries. With a `flags` definition, no bits outside the set are allowed. |
| `required` | O | bool | The default for every operation that lists this attribute. Can be overridden per operation (2.4). |
| `checks` | O | mapping | See below. |

Types (`type`):

| `type` | CBOR kind | C field type | Implicit range |
|--------|-----------|--------------|----------------|
| `u8`, `u16`, `u32`, `u64` | uint | `uint8_t` … `uint64_t` | 0 … 2ᴺ−1 |
| `s8`, `s16`, `s32`, `s64` | int | `int8_t` … `int64_t` | −2ᴺ⁻¹ … 2ᴺ⁻¹−1 |
| `bool` | bool | `bool` | |
| `flag` | flag | `bool` (presence) | |
| `text` (alias `string`) | text | `const char *` | UTF-8, no NUL |
| `bytes` (alias `binary`) | bytes | `struct cbl_bytes` | |
| `float` | float | `double` | |
| `nest` | map | `struct <prefix>_<set> *` | |

`checks`:

| Check | Types | Meaning |
|-------|-------|---------|
| `min`, `max` | integer types | Inclusive range. It must lie within the type's implicit range. |
| `min-len`, `max-len` | text, bytes | Inclusive range of byte lengths. |
| `exact-len` | bytes | Shorthand for `min-len` = `max-len`. |
| `min-count`, `max-count` | any type with `multi-attr` | Array element count. |

Values in `checks` may be integers or names of `const` definitions.

### 2.4 `operations`

| Key | | Meaning |
|-----|--|---------|
| `name` | R | |
| `value` | O | Command id, 1 … 65535. Default: previous + 1, starting at 1. Shared with notifications. |
| `doc` | O | |
| `attribute-set` | R | The set that the `request`, `reply` and `event` attribute lists refer to. |
| `auth` | O | bool. Requires an authenticated peer (`CBL_OPF_AUTH`). |
| `do` | O | `{request?, reply?}` |
| `dump` | O | `{request?, reply?}`. The reply describes one dump item. |
| `event` | O | `{attributes}`. Makes this operation a **notification**; `mcgrp` is then required. It cannot be combined with `do` or `dump`. |
| `mcgrp` | O | Group name, for `event`. |

At least one of `do`, `dump`, `event`, or a stream that references this
operation (2.6), is required.

`request`, `reply` and `event` mappings:

| Key | | Meaning |
|-----|--|---------|
| `attributes` | R | Sequence of attribute names from `attribute-set`. Order is preserved in generated structs. |
| `required` | O | Sequence of names: a subset of `attributes` that must be present (`CBL_PF_REQUIRED`). This overrides the attribute-level `required`. Only valid in `request`. |

### 2.5 `mcast-groups`

| Key | | Meaning |
|-----|--|---------|
| `name` | R | |
| `doc` | O | |
| `auth` | O | bool. Subscribing requires an authenticated peer. |

### 2.6 `streams`

| Key | | Meaning |
|-----|--|---------|
| `name` | R | |
| `doc` | O | |
| `open` | R | The operation that opens the stream. Its `do.request`, if present, lists the open-request attributes, and its `do.reply` lists the accept attributes. The operation must not have `dump` or `event`, and may be referenced by only one stream. |
| `direction` | R | `bidirectional`, `client-to-server` or `server-to-client`. `server-to-client` sets `CBL_OPF_PUSH`; the others set `CBL_OPF_STREAM`. |
| `payload` | R | Attribute set of `S_DATA` frames in **both** directions. Alternatively, use `payload-up` and `payload-down` for different sets in each direction. |
| `initial-credit` | O | Bytes. The default initial window advertised by generated code. |

---

## Part 3: semantic validation

`cblink-gen` rejects all of the following. Each error points at the
offending key or scalar.

1. **Duplicates:** names within definitions, within each set's attributes,
   among sets, among operations (including notifications), among groups,
   among streams, and among the entries of each enum or flags definition.
   Also duplicate **ids**: attribute values within a set, operation values,
   enum values, and flag bits.
2. **Undefined references:** `nested-attributes`, `enum`, `attribute-set`,
   names in `request`, `reply`, `event` and `required`, `mcgrp`, `open`,
   `payload`, and `const` names inside `checks`.
3. **Kind mismatches:** `nested-attributes` on a non-`nest` type; `enum` on
   a non-unsigned type; `checks` that do not apply to the type (for example
   `min-len` on `u32`, or `min` on `text`); `required` not a subset of
   `attributes`; `event` without `mcgrp`; a `mcgrp` with no `event`; a
   stream `open` operation that also has `dump` or `event`.
4. **Invalid ranges:** `min > max`, `min-len > max-len`,
   `min-count > max-count`; bounds outside the type's implicit range (for
   example `max: 300` on `u8`, or `min: -1` on `u16`); ids out of range;
   `version: 0`; `flags` bit numbers above 63; a const value used where it
   does not fit.
5. **Unknown keys** anywhere in the schema are errors. This is stricter
   than the wire rule, because a spec is source code.
6. **Identifier collisions:** two names that give the same generated C
   identifier, checked for every name the generator emits and within each
   C name space (struct and enum tags, functions and objects, macros). An
   operation `put-key` collides with the builder of attribute `key`, a
   set `get-req` with the request struct of operation `get`, a set
   `client` with the generated client struct. A set and an operation of
   the same name do not collide.

Recursion through `nested-attributes`, a set nesting itself directly or
indirectly, is allowed. Generated structs use pointers for nested sets, and
the run-time `max_depth` bounds decoding.

---

## Part 4: example (`examples/kv/kv.yaml`)

```yaml
# SPDX-License-Identifier: BSD-2-Clause
---
name: kv
version: 1
doc: |
  A small key/value store. Demonstrates do, dump, notifications,
  a push stream and authenticated operations.

definitions:
  - name: max-key-len
    type: const
    value: 255
  - name: entry-flags
    type: flags
    entries:
      - persistent
      - name: secret
        doc: Value is redacted in dumps.

attribute-sets:
  - name: kv
    attributes:
      - name: key
        type: text
        checks:
          min-len: 1
          max-len: max-key-len
      - name: value
        type: bytes
        checks:
          max-len: 65536
      - name: flags
        type: u32
        enum: entry-flags
      - name: ttl
        type: u32
        checks:
          max: 86400
      - name: tags
        type: text
        multi-attr: true
        checks:
          max-count: 16
          max-len: 32
      - name: prefix
        type: text
        checks:
          max-len: max-key-len

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
          - flags
          - ttl
          - tags
    dump:
      request:
        attributes:
          - prefix
      reply:
        attributes:
          - key
          - value
          - flags
  - name: set
    attribute-set: kv
    auth: true
    do:
      request:
        attributes:
          - key
          - value
          - flags
          - ttl
          - tags
        required:
          - key
          - value
  - name: watch
    attribute-set: kv
    do:
      request:
        attributes:
          - prefix
  - name: changed
    attribute-set: kv
    mcgrp: changes
    event:
      attributes:
        - key
        - flags

mcast-groups:
  - name: changes

streams:
  - name: watch
    open: watch
    direction: server-to-client
    payload: kv
    initial-credit: 65536
```

---

## Part 5: what the generator produces

GENERATOR.md has the full generated API. In brief, for the example above
(`c-prefix` `kv`):

| Spec element | Generated |
|--------------|-----------|
| `max-key-len` | `#define KV_MAX_KEY_LEN 255` |
| `entry-flags` | `#define KV_ENTRY_FLAGS_PERSISTENT (UINT64_C(1) << 0)`, `KV_ENTRY_FLAGS_SECRET (UINT64_C(1) << 1)`, and the value table `kv_entry_flags_values` |
| set `kv` | `enum { KV_A_KEY = 1, KV_A_VALUE, …, KV_A_MAX = 6 };`<br>`struct kv_kv`: a field per attribute; optional scalars have a `has_<attr>` flag, strings are `NULL` when absent, multi-attrs are `{ size_t n; const T *v; }`<br>policy `kv_kv_policy`, parser `kv_kv_parser`, `kv_kv_parse()`, `kv_kv_put_fields()`<br>builders `kv_put_key(cbl_msg *, const char *)`, …: the set name equals the family name, so the set part of the name is dropped; otherwise the name is `kv_<set>_put_<attr>()` |
| operation `get` | `KV_CMD_GET = 1`<br>`struct kv_get_req`, `struct kv_get_rsp` (with `cbl_msg *_msg`, which owns its strings), `struct kv_get_dump_req`/`_rsp`, each with a policy, parser and `_put_fields()`<br>client: `kv_get(struct kv_client *, const struct kv_get_req *, struct kv_get_rsp **)`, `kv_get_rsp_free()`<br>client: `kv_get_dump(struct kv_client *, const struct kv_get_dump_req *, cbl_dump **)`, `kv_get_dump_next()`<br>server: the handlers `kv_get_doit(cbl_req *, const struct kv_get_req *, void *)` and `kv_get_dumpit(…)`, and `kv_get_reply(cbl_req *, const struct kv_get_rsp *)`, `kv_get_dump_reply()` |
| notification `changed` | `KV_CMD_CHANGED = 4`, `struct kv_changed_ntf`<br>server: `kv_changed_notify(cbl_family *, const struct kv_changed_ntf *)`<br>client: `kv_changes_subscribe(struct kv_client *, const struct kv_changes_handlers *, void *, cbl_sub **)`, with one typed callback per notification of the group |
| group `changes` | `KV_MCGRP_CHANGES` (index), `KV_MCGRP_COUNT` |
| stream `watch` | client: `kv_watch_open(struct kv_client *, const struct kv_watch_req *, const struct kv_watch_cbs *, void *, cbl_stream **)` with typed `on_data(const struct kv_kv *)`<br>server: the handler `kv_watch_stream_open(…)`, and `kv_watch_accept()`, `kv_watch_server_send(cbl_stream *, const struct kv_kv *)` |
| family | `KV_FAMILY_NAME`, `KV_FAMILY_VERSION`, `kv_family_def`, `kv_register(cbl_ctx *, void *arg, cbl_family **)`<br>client: `struct kv_client`, `kv_client_init()` (resolves the family by name), `kv_client_fini()` |
| docs | `kv.md` |

Output files are `kv.h`, `kv.c` (common: tables, builders, parsers),
`kv_client.c`, `kv_server.c` and `kv.md`. The server implements the
handler functions declared in `kv.h` under fixed names; `kv_server.c`
refers to them from the family's operation table. A client-only program
therefore does not need to define server handlers: it simply does not
compile `kv_server.c`.
