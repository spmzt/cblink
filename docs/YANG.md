# YANG in cblink: the profile

A cblink program describes its data, rpcs, actions and notifications in
YANG modules (RFC 7950). `cblink-gen` compiles them (GENERATOR.md), and
libcblink speaks them on the wire: every item keyed by its SID (RFC 9595),
every value in YANG-CBOR (RFC 9254). This document says what of YANG is
taken, how each piece is encoded, and what is left out.

## 1. Modules

- **YANG 1.1 and 1.0**, compiled by libyang 3: typedefs, groupings and
  `uses`, `augment` from other modules, `deviation`, `feature` and
  `if-feature` (as `cblink-gen -F` enables them), identities and their
  derivation, `choice` and `case`, `when` and `must`, defaults,
  `mandatory`, `min-elements` and `max-elements`, `unique`, `ordered-by
  user`, `config false`, `status`.
- **Structures**: `sx:structure` (RFC 8791) and `rc:yang-data` (RFC 8040),
  numbered and encoded as data. cblink's own framework is such
  structures (the module `cblink`: error, credit, hello, close, get,
  notification).
- **Imports** are found in a module's own directory and each `-p`
  directory; one imported without a revision is the latest found.

## 2. SIDs

Each module has a `.sid` file (RFC 9595): the SIDs of its module name,
identities, features and data nodes, from assignment ranges the file
names. `cblink-gen -a` numbers what has none, as RFC 9595 Appendix B says,
and never renumbers: a SID is never reused or removed, an item that goes
is marked obsolete, and a module revision adds items at the end of its
range. An rpc's and an action's empty `input` and `output` have SIDs too.

The `ietf-sid-file` module's own SIDs, by which a `.sid` file is encoded
in YANG-CBOR (GET-SID), are those of IANA's range for it, 1300 to 1349,
numbered as Appendix B says; IANA publishes no `.sid` file for it.

## 3. The encoding

A body is one CBOR map. Its keys are SIDs; a node's children are keyed
by their SID **deltas** from the node's own SID, negative ones too
(RFC 9254 section 3.2). An rpc's or an action's input and output are
keyed under the rpc's or the action's SID, and their children's deltas
are from that SID, not the `input` or `output` node's.

| YANG | YANG-CBOR |
|------|-----------|
| container, list entry, notification, structure, input, output | a map |
| list, leaf-list | an array |
| `int*`, `uint*` | an integer |
| `decimal64` | tag 4, `[exponent, mantissa]`, the exponent minus the fraction digits |
| `string` | a text string, UTF-8 |
| `boolean` | `true` or `false` |
| `empty` | `null` |
| `enumeration` | its value; in a union, tag 44 and its name |
| `bits` | a byte string, the bits by position, byte 0 first, no zero bytes at its end; or the sparse array of byte strings and counts of zero bytes; in a union, tag 43 and the names |
| `binary` | a byte string |
| `identityref` | the identity's SID; or its name, prefixed when it is another module's; in a union, tag 45 |
| `instance-identifier` | a SID, or `[SID, keys...]`; in a union, tag 46 |
| `leafref` | as its target's type |
| `union` | as the member that matches, with the tags above where members could be told apart no other way |
| anydata, anyxml | as a container, its keys deltas from its own SID |

Tag 47, an absolute SID as a value, is taken too, never on a key; no
other tag is. Lengths are definite; the encoder writes integers and keys
in their shortest form. The decoder checks the CBOR (its shape, kinds, tags, UTF-8, no key twice,
the limits) before a program sees it; the codec decodes a value into its
struct and, with `CBL_YD_STRICT`, refuses a key the node has no child
for. What a decode may allocate is bounded (64 MiB unless set).

## 4. Validation

`cbl_yvalidate()` checks a tree, a node's struct as the codec or a
program filled it, against what RFC 7950 says of it within the tree:

| Rule | error-tag | error-app-tag |
|------|-----------|---------------|
| a value's range, length (in characters for a string), pattern (and `invert-match`), enum, bits, identity derived from every base, union member | `invalid-value` | the restriction's own, if any |
| a mandatory leaf missing | `missing-element` | |
| a mandatory choice with no case | `data-missing` | `missing-choice` |
| a node of a case other than the one given | `bad-element` | |
| fewer than `min-elements`, more than `max-elements` | `operation-failed` | `too-few-elements`, `too-many-elements` |
| a list entry without its key, two entries of one key | `missing-element`, `data-exists` | |
| two entries alike in a `unique` statement's leaves (where all of them are) | `operation-failed` | `data-not-unique` |
| a configuration leaf-list's value twice | `data-exists` | |
| a `config false` node in an edit | `invalid-value` | |

The error's message is the restriction's `error-message` when it has
one. A non-presence container that is absent is there in effect: a
mandatory node below it is missing. The YANG family validates every
EDIT and every rpc's input before a handler sees them, never what it
reads back (RFC 8342 section 5.3).

`cbl_ydefaults()` sets what a tree leaves unset to the module's
defaults: a leaf's, a leaf-list's values, a choice's default case and
the defaults in it, in every struct that is there (an absent container
stays absent).

The instance tree (`<cbl_data.h>`, API.md section 7) keeps data as
nodes of the tables, for datastores, edits and XPath: it keeps a tree's
shape (keys one entry, a configuration leaf-list's values once, a
choice's cases never two), gives a default where it is in use, and makes
nodes of them, non-presence containers too, as RFC 6243's report-all
shows them. Edits apply NETCONF's operations to it (RFC 6241 section
7.2: merge, replace, create, delete, remove; none as the default) and
YANG Patch's insert and move (RFC 8072), an ordered-by user list's
entries where they say, all or nothing; the difference of two trees is
such an edit. Its references are checked against it: a leafref's value
among its target's instances, an instance-identifier's node there,
where they require an instance.

## 5. Expressions and patterns

`when`, `must` and a leafref's `path` are recorded in the schema tables
as written, for the evaluator (what they say needs more than one tree). They must lie within **XPath-lite**; the
generator refuses one that does not, naming the node and what is outside:

- the axes `child`, `parent`, `self` and `descendant-or-self`, with their
  abbreviations (`..`, `.`, `//`);
- key predicates and other predicates;
- `current()`, `deref()`, `derived-from()`, `derived-from-or-self()`,
  `enum-value()`, `bit-is-set()`, `re-match()`, `count()`, `not()`,
  `boolean()`, `true()`, `false()`, `number()`, `string()`, `concat()`,
  `contains()`, `starts-with()`, `string-length()`, `substring()`,
  `substring-before()`, `substring-after()`, `normalize-space()`,
  `translate()`;
- arithmetic, comparisons with node-set semantics, `and`, `or`, `|`.

A `pattern` is an XSD regular expression, translated at generation time
to a POSIX ERE that `regcomp(3)` compiles, and refused with the reason
where it cannot be: back-references and escapes XSD has not, character
class subtraction, Unicode categories and blocks no POSIX class matches,
a complement inside a class, counts over `RE_DUP_MAX`. `\d`, `\p{L}`,
`\p{Lu}`, `\p{Ll}` and `\p{Nd}` are FreeBSD's Unicode classes in
`C.UTF-8`; `\p{N}` and `\w` are narrower than XSD's.

## 6. The protocol

The YANG family (family 1, WIRE-FORMAT.md section 7.6) serves a
program's modules in CORECONF's shape: GET, EDIT (create, replace,
delete; all or nothing), RPC, NOTIFY, GET-SID. The control family (family
0, section 7.2) is the module `cblink-ctrl`; errors, credit and closes
are the module `cblink`'s structures (section 6).

## 7. Left out

- **Validation of anyxml content**, and of anydata's against a schema.
- **XPath 1.0** beyond XPath-lite, and XSD regular expressions beyond
  what is translated.
- **Datastores**: the YANG family edits what the handlers keep; it has no
  `startup`, no `candidate` and no locks.
- **Actions** and **list entries as targets** are not yet carried by the
  YANG family: an action's handler is in the server table, and a target
  is a top-level node's SID.
- A recursive grouping cannot be compiled; a tree that would need one is
  modelled flat, with a leafref to the parent.
