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

Tag 47, an absolute SID, is taken as a value and as a key in any inner
map (RFC 9254 section 4.2.1), the key then the child of that SID. Tag
109 is draft-ietf-core-yang-metadata's: a node's annotations (RFC
7952), `[metadata, value]` in place of its value, the metadata a map
keyed by each annotation's delta from the node's own SID (an entry's:
its list's). IANA has not assigned 109; cblink holds it as provisional.
The instance tree writes and reads it (`cbl_dnode_meta_set()`); the
structs have no place for an annotation, and their decoder passes it
over, as a reader may. No other tag is. Lengths are definite; the encoder writes integers and keys
in their shortest form. The decoder checks the CBOR (its shape, kinds, tags, UTF-8, no key twice,
the limits) before a program sees it; the codec decodes a value into its
struct and, with `CBL_YD_STRICT`, refuses a key the node has no child
for. What a decode may allocate is bounded (64 MiB unless set).

A schema mount point (RFC 8528, a node with `yangmnt:mount-point`) has
below it the schema's own top-level nodes, a shared schema: in
YANG-CBOR keyed by their absolute SIDs (tag 47), in RFC 7951's JSON
named with their modules as at the top, in the instance tree as the
mount point's children. Its struct has `mounted` (`struct
cbl_ymounts`), a module's data struct each, made and found by
`cbl_ymount_data()` and `cbl_ymount_find()`; the validator, NACM's
paths and the difference of two trees go inside. A mount point with
nodes of its own beside is not generated.

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
mandatory node below it is missing, but for a case's (none is given)
and one under a `when`. What a `when` decides, `cbl_yvalidate()`
cannot: a mandatory node an augment or a uses brings under a `when` is
left to the tree's check below. The YANG family validates every EDIT
and every rpc's input before a handler sees them, never what it reads
back (RFC 8342 section 5.3).

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
where they require an instance. `cbl_dtree_check_conds()` (or
`cbl_dnode_check_conds()`, a node and what is under it) evaluates every
`when` and `must` (RFC 7950 sections 7.21.5 and 7.5.3) and finds a
mandatory node missing where the `when` that brings it holds; an EDIT
of the candidate is checked so, the nodes it edits with their defaults
made.

## 5. Expressions and patterns

`when`, `must` and a leafref's `path` are recorded in the schema tables
for the evaluator (what they say needs more than one tree), each name
by its module rather than by a prefix (libyang's map of the prefixes
the expression was written with; an unprefixed name the node's module,
RFC 7950 section 6.4.1), and each step with its axis:
`parent::node()/child::shapes:id` for `../id`. `cbl_xp_eval()`
evaluates them over an instance tree (API.md section 7): node sets,
paths on the four axes, predicates, comparisons with node sets,
arithmetic, `and`, `or`, `|`; XPath 1.0's functions that XPath-lite
has (`count`, `not`, `true`, `false`, `boolean`, `number`, `string`,
`concat`, `contains`, `starts-with`, `substring`, `substring-before`,
`substring-after`, `string-length`, `normalize-space`, `translate`,
counting characters, not bytes) and YANG's (`current`, `deref`,
`derived-from`, `derived-from-or-self`, `enum-value`, `bit-is-set`,
`re-match` with an XSD pattern, as `pattern` takes one). A leaf's string
value is its canonical form, an identityref's `module:name`, an
instance-identifier's path with each name by its module.
The evaluator is held to libyang's on the corpus (TESTING.md: `xpdiff`),
and agrees with it but where libyang departs from XPath 1.0 or RFC 7950.
`cbl_dtree_check_conds()` holds a tree to its `when`s and `must`s
(unknown-element; operation-failed and the `must`'s `error-message` and
`error-app-tag`, `must-violation` if it has none), a node's own `when`
seeing it as a node with no value and no children, an augment's, a
uses', a choice's or a case's not seeing the nodes it brings (RFC 7950
section 7.21.5); `cbl_yvalidate()`, which sees one struct, does not.
They must lie within **XPath-lite**; the
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
delete; all or nothing), RPC, NOTIFY, GET-SID, and SUBSCRIBE: RFC
8639's dynamic subscriptions and RFC 8641's YANG-Push, periodic and
on-change (changes as a YANG Patch), on a push stream. Configured
subscriptions (RFC 8639 section 2.5, the `configured` feature) are the
entries of running's `subscriptions` list, which the program keeps and
tells `cbl_ysub_configure()` whenever it changes (from its edit handler
of the container, and at its start): each is made, changed (its
receivers told `subscription-modified`) or ended (`subscription-terminated`)
by the difference from what was told last, and reads as the recovery
session. Its records go to its receivers through the program's
transport (`cbl_ysub_set_transport()`: connect, send a record, disconnect),
on a thread of the subscription's own, each receiver with its state
(connecting, active): connected, told `subscription-started`; down, what
it misses is excluded and it is connected again later, a second on and
doubling to a minute; a stream subscription with `configured-replay`
(or a `replay-start-time`) is then replayed from the last record the
receiver had, by the program's replay, and told `replay-completed`. At
the stop-time the receivers are told `subscription-completed` and the
subscription stays, concluded. `cbl_ysub_each()` lists both kinds, with
a configured one's receivers. Anydata is shown in RFC 7951's JSON as its members, where the
tables have its nodes. The control family (family
0, section 7.2) is the module `cblink-ctrl`; errors, credit and closes
are the module `cblink`'s structures (section 6).

NACM (RFC 8341) is checked where a server serves `ietf-netconf-acm` and
a get handler for its `nacm` container: an rpc's or an action's exec,
a read (what is denied left out, as RFC 8341 reads it), an EDIT (all
or nothing, every node it creates, changes or deletes), each
notification of group `notify` and of a subscription, and the ops of a
program's family flagged `nacm` (an rpc of the module named as the
family). The user is a request's, as the program's `cbl_user_f` names
it from the peer and from the `user` structure a trusted peer sends; the
recovery session (by default root on a unix socket) is let through.
`nacm:default-deny-write` and `-all` are the tables' node flags.

Datastores (RFC 8342), where a program asks for them
(`cbl_ydatastores()`): `running`, the configuration its handlers keep;
`candidate`, one configuration being made, every session's (RFC 6241
section 8.3). A GET or an EDIT names the datastore in the `datastore`
structure; without it a GET reads the operational state and an EDIT
changes running. The server serves `ietf-netconf` with its features
`candidate` and `confirmed-commit`, and cblink answers its `commit`,
`cancel-commit` and `discard-changes` itself: a commit changes, through
the handlers, every top-level node the candidate has otherwise than
running, all or nothing, NACM's write checks each; a confirmed commit
(section 8.4) is undone at its `confirm-timeout`, by `cancel-commit`, or
when its session goes without `persist`, unless a commit confirms it
(its session's, or any with its `persist-id`). A GET's `with-defaults`
(RFC 6243) reads `explicit` (what the server has, the basic mode),
`report-all` (the defaults in use too) or `trim` (a leaf at its default
left out) or `report-all-tagged` (report-all, a leaf whose value is its
default annotated `ietf-defaults:default`, draft-ietf-netconf-default-attribute),
of any datastore (`cbl_msg_put_yget_wd()`). Its `with-origin` (RFC 8342
section 5.3.4, RFC 8527 section 3.2.2), of the operational datastore
alone, annotates each configuration node with `ietf-origin:origin` where
it is not its parent's: `intended` where running has it (a leaf with the
same value), `default` where it is a default in use, and where running
has it not what the server says (`cbl_yorigin_set()`: `system`,
`learned`, ...), `unknown` where it says nothing; what is below such a
node has its origin (`cbl_msg_put_yget_opts()`). Both need their module among the server's.
A client reads such a reply into an instance tree (`cbl_msg_ydtree()`)
and writes it as JSON with its annotations (`cbl_dtree_json()`, RFC 7952
section 5.2). An undo a handler fails
is the program's to hear of, and the undo stops there; an undo needs
no consent its commit had (`cbl_req_yundo()`). A get handler
reading for running (`cbl_req_ydatastore()`) leaves out what is no
configuration. With `CBL_YDS_CONFIRMED` running changes by
a confirmed commit alone. A handler refuses what its requester should be
warned of with an `error-app-tag`, unless the request `accept`s it, and
tells what it did in the answer's `warnings`.

## 7. Left out

- **Validation of anyxml content**, and of anydata's against a schema.
- **XPath 1.0** beyond XPath-lite, and XSD regular expressions beyond
  what is translated.
- **Datastores**: no `startup` and no `intended`, and no locks.
- **List entries as GET targets** are not yet carried by the YANG
  family: a GET's target is a top-level node's SID.  (An action's target
  is a list entry: `cblink:action`, WIRE-FORMAT.md section 7.6.)
- A recursive grouping cannot be compiled; a tree that would need one is
  modelled flat, with a leafref to the parent.
