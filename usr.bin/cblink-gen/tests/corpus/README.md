# The corpus

The YANG modules `cblink_gen_test:corpus` runs cblink-gen over: the IETF
and IANA modules Arcana implements or builds on, as published (each
extracted from its RFC, or taken from IANA's YANG parameters registry
for the modules IANA maintains), copied unedited from Arcana's
`share/yang`, whose README names each one's source. Nothing here is
edited.

For each module, its tree diagram (RFC 8340) must be what `yanglint -f
tree` prints, with the same features on; and the structs and tables of
all of them together must compile and take every struct through
YANG-CBOR and back to the same bytes.
