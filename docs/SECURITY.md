# Security

What cblink protects against, how, and what it leaves to the
application and the system.

## 1. Threat model

- **Peers are untrusted.** Any connected peer, authenticated or not, may
  send arbitrary bytes. Every frame is hostile input until it has been
  validated.
- **The network is hostile.** TCP and SCTP traffic is encrypted and
  mutually authenticated unless the application explicitly asks for
  plaintext.
- **Local users are not trusted by default.** On AF_UNIX the socket's
  filesystem permissions decide who may connect at all. Credentials
  (`getpeereid(3)`) count as authentication only when the listener says
  so.
- **Specs are untrusted input to cblink-gen.**

Out of scope: denial of service by a peer with a legitimate share of the
resources, which is bounded by the limits below but not prevented;
compromise of the host; and the security of what families do with the
data they receive.

## 2. Transport security

| | TCP | SCTP |
|-|-----|------|
| Protocol | TLS 1.3 only | DTLS 1.2 only (RFC 6083) |
| Ciphers | OpenSSL's TLS 1.3 suites (AEAD) | ECDHE + AES-GCM or ChaCha20-Poly1305, ECDSA or RSA |

- **Base OpenSSL.** Base OpenSSL 3.5 has no DTLS 1.3, so DTLS is 1.2,
  limited to forward-secret AEAD suites. Renegotiation and compression
  are disabled.
- **No resumption.** Session caches and tickets are off, so every
  connection does the full mutual verification, CRL check included.
- **Mutual TLS by default.** A server requests a client certificate and
  refuses peers without a valid one. A client verifies the server's
  certificate against its CA. It also checks the name: the URI host, or
  the name set with `cbl_tls_set_peer_name()`, through `SSL_set1_host()`,
  or `X509_VERIFY_PARAM_set1_ip_asc()` for an address.
- **CRLs.** With `cbl_tls_set_crl()`, every certificate in the chain is
  checked against a CRL from its issuer. The file holds one CRL per CA,
  intermediates included, and all of them are loaded.
- **Keys.** Private keys must not be encrypted: an encrypted one fails to
  load rather than prompting for a passphrase.
- **Renewal.** `cbl_tls_reload()` rereads certificates, keys, CAs and CRLs
  without a restart; new connections use them. `cbl_listener_set_tls()`
  swaps the configuration of a running listener.
- **Chain depth.** `cbl_tls_set_verify_depth()` limits it (default 8, at
  most 32).
- **Plaintext is an explicit opt-in.** A TCP or SCTP endpoint without
  a TLS configuration fails to start or connect with `EPERM` ("mTLS
  required"), unless it was created with `CBL_PLAINTEXT`.
- **PROXY protocol.** A listener created with `CBL_LF_PROXY` takes the
  client address from the header a TCP proxy sends first. List the
  proxies with `cbl_listener_add_proxy()`: a connection from anywhere else
  is closed before its header is read. Without a list, the listener must
  be reachable only through the proxy. The header never affects
  authentication: TLVs are ignored, and `CBL_PEER_AUTHENTICATED` comes from
  mTLS alone. Headers are bounded (536 bytes) and covered by
  `handshake_timeout` (TRANSPORTS.md section 5.1).
- **Identity.** `cbl_peer_*()` report what the verified certificate says:
  subject and issuer (RFC 2253), SANs, and SHA-256 and SHA-1
  fingerprints. The flag `CBL_PEER_AUTHENTICATED` is set only after
  successful verification. Operations flagged `CBL_OPF_AUTH` (`auth: true`
  in a spec) refuse other peers with `EACCES` before the handler runs.

## 3. Local sockets

- **Permissions.** A `unix:` listener sets its socket's mode, and its
  owner when asked (`cbl_listener_set_unix_perm()`), before `listen(2)`.
  Until then every `connect(2)` is refused, so no peer can get in under a
  looser mode left by the umask.
  - The default mode is `0600`.
  - Put the socket in a directory only the intended users can search, for
    example mode `0750`.
- **Stale sockets.** A stale socket left by a dead server is replaced. A
  live one, where `connect` succeeds, never is: starting fails with
  `EADDRINUSE`.
- **Credentials.** Peers are identified by `getpeereid(3)`. They count as
  authenticated only on a listener created with `CBL_LF_UNIX_TRUSTED`,
  which declares that the filesystem permissions are the access control.

## 4. Hostile input

- **Headers before allocation.** The 24-byte header is validated before
  any memory is allocated for the body (`max_frame`, default 1 MiB): magic,
  version, header length, flag combinations, stream ids.
- **Strict CBOR.** Bodies are decoded with libcbor's streaming decoder in
  two passes. The first pass allocates nothing and checks:
  - well-formedness;
  - definite lengths only;
  - no tags;
  - integer map keys;
  - no duplicate keys;
  - valid UTF-8 in text strings;
  - nesting (`max_depth`, default 16) and item count (`max_attrs`).

  The second pass allocates exactly what the first measured.
- **Validation before handlers.** Requests are validated against their
  operation's policy before a handler sees them, and the error says
  exactly what was wrong (an extended ack).
- **Resource limits.** Each limit is per context, listener or connection
  (WIRE-FORMAT.md section 11), and peers that exceed one get an error,
  not memory:
  - connections (`max_conns`);
  - outstanding requests per connection (`max_inflight`);
  - queued output (`sendq_bytes`);
  - open streams (`max_streams`) and stream windows;
  - handshake, idle and request timeouts.
  - read backpressure: a server stops reading a peer that does not read
    its replies (sendq_bytes, WIRE-FORMAT.md section 11). Replies that
    end a request are not dropped; they queue up to twice sendq_bytes,
    and a connection that gets there is closed, so a peer that never
    reads costs bounded memory on either side of a connection;
  - a closing connection gets `stream_close_timeout` to flush.
- **Notifications.** A subscriber that cannot keep up loses notifications
  and is told so. It does not hold up the server or other subscribers.

## 5. Code

- **No global mutable state.** All state hangs off a `cbl_ctx`, and the
  library is thread-safe as documented in API.md section 1.
- **Fuzzing.** The parsers that see untrusted input are fuzzed with
  libFuzzer under ASan and UBSan (`fuzz/`): frames, PROXY protocol
  headers and specs.
- **Sanitizers.** The test suite also runs under ASan+UBSan and TSan.
- **Generator sandbox.** cblink-gen parses specs in capsicum(4) capability
  mode, with only the output directory open.

## 6. Reporting problems

Send reports about security problems to the maintainer listed in the
port (`port/devel/cblink/Makefile`) rather than to a public tracker.
