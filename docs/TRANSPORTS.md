# cblink transports

This document describes how each transport carries cblink frames, which
kernel and OpenSSL features it uses, and the limits and caveats an operator
should know. The frame format is the same everywhere (WIRE-FORMAT.md);
only the delimiting and the security layer differ.

| URI                         | Transport                 | Security (default)        | Streams |
|-----------------------------|---------------------------|---------------------------|---------|
| `tcp://host:port`           | TCP                       | TLS 1.3, mutual           | yes     |
| `unix:/path`                | AF_UNIX `SOCK_STREAM`     | peer credentials (`getpeereid`) | yes |
| `sctp://h1[,h2…]:port`      | SCTP, one-to-one style    | DTLS 1.2 (RFC 6083), mutual | yes   |

`CBL_PLAINTEXT` turns the security layer off on TCP and SCTP. It is
an explicit opt-in. Without it, and without a `cbl_tls` configured, connecting
or starting a listener fails with `EPERM` ("mTLS required").

Every transport implements the internal `struct cbl_tr_ops` vtable
(`cbl_impl.h`). The connection core (`cbl_conn.c`) does not know which
transport it runs on. It only knows whether the transport is a byte stream
(frames are delimited by their `length` field) or delivers whole frames.

---

## 1. TCP and TLS 1.3

- Frames are concatenated on the byte stream. A receiver validates the
  24-byte header before it allocates the body (WIRE-FORMAT.md section 11).
  A frame that does not fit the receive ring is read straight into a buffer
  of exactly its size.
- Socket options: `TCP_NODELAY` (frames are small and latency matters) and
  `SO_NOSIGPIPE`. A peer that goes away is reported as `EPIPE` or
  `ECONNRESET` on the connection, never as a signal.
- TLS policy:
  - TLS 1.3 only, with OpenSSL's default TLS 1.3 suites.
  - No renegotiation and no compression.
  - A server always requests and verifies a client certificate.
  - A client verifies the server certificate and its name (SNI plus
    `SSL_set1_host()`, or `X509_VERIFY_PARAM_set1_ip_asc()` for an
    address). The name is the URI host unless
    `cbl_tls_set_peer_name()` overrides it.
  - `SSL_CTX`s are built lazily per role and are immutable after that, so
    any number of connections share them without locking.
- Peer identity (`cbl_peer_*`) is taken from the verified leaf certificate:
  subject, issuer, SANs and SHA-256 fingerprint.

## 2. AF_UNIX

- Framing is the same as TCP.
- Listener sockets:
  - A stale socket file left by a dead server is detected (`connect()`
    fails with `ECONNREFUSED`) and replaced.
  - A live socket is never stolen: starting fails with `EADDRINUSE`.
  - The default mode is `0600`. `cbl_listener_set_unix_perm()` sets the
    mode and ownership.
- Peers are identified by `getpeereid(2)` (uid and gid). A peer counts as
  authenticated only when the listener has `CBL_LF_UNIX_TRUSTED`. That
  flag says: filesystem permissions are the access control.

## 3. SCTP

cblink uses one-to-one style sockets (`SOCK_STREAM`, `IPPROTO_SCTP`). One
association is one `cbl_conn`.

### 3.1 Features used

- **Message framing (plaintext).** One frame is one SCTP message. The
  message boundary (`MSG_EOR`) does the framing, and a partially sent
  message is treated as an error, never as a short write.
- **Multiple streams.**
  - SCTP stream 0 carries requests, responses, dumps and notifications.
  - cblink stream *n* is sent on SCTP stream `1 + n mod (os − 1)`, where
    *os* is the number of outbound streams negotiated (cblink asks for 64).
  - A slow or large cblink stream therefore does not hold up control
    traffic or other cblink streams.
  - The receiver does not trust the SCTP stream number. Frames are routed
    by their header, as on every transport.
- **Fragment interleaving (plaintext).**
  - `SCTP_FRAGMENT_INTERLEAVE` is set to level 2, and I-DATA
    (`SCTP_INTERLEAVING_SUPPORTED`, RFC 8260) is used when both ends
    support it.
  - A large message on one stream is then delivered in pieces interleaved
    with other streams.
  - The receiver reassembles each SCTP stream separately. No stream may
    grow beyond `max_frame`; a longer message is skipped up to its end and
    counted as dropped, and the association stays up.
- **Multihoming.**
  - Several hosts in the URI (`sctp://192.0.2.1,[2001:db8::1]:7000`) are
    bound with `sctp_bindx()` on a listener and passed to `sctp_connectx()`
    by a client. The association then has a path to each address and fails
    over between them.
  - IPv4 and IPv6 hosts can be mixed. cblink then uses an IPv6 socket with
    `IPV6_V6ONLY` off.
- **Buffers.** The socket buffers are sized so that a `max_frame` message
  fits, as a best effort bounded by `kern.ipc.maxsockbuf`.
- **Orderly shutdown.** Closing sends SHUTDOWN after the queued frames
  (`shutdown(SHUT_WR)`), not ABORT.

### 3.2 DTLS 1.2 over SCTP (RFC 6083)

- This mode uses OpenSSL's SCTP BIO (`BIO_new_dgram_sctp`). SCTP-AUTH must
  be enabled (`net.inet.sctp.auth_enable=1`, the FreeBSD default). The
  socket is prepared for SCTP-AUTH before `listen()` and `connect()`,
  because auth chunks must be negotiated when the association is set up.
- A DTLS record holds at most 16 KiB. Each SCTP stream therefore carries
  a byte stream of frames, delimited by `length` as on TCP.
  - The stream mapping of section 3.1 applies.
  - On receive, OpenSSL reports the SCTP stream of every record. This
    includes records it buffered across the handshake.
  - cblink reassembles each SCTP stream's byte stream separately and
    handles bad headers as on TCP.
- OpenSSL's SCTP BIO fixes the link MTU at 16 KiB, including record
  overhead. cblink writes at most `DTLS_get_data_mtu()` bytes of plaintext
  per record.
- Fragment interleaving is **not** used in this mode. The BIO turns off
  partial delivery and expects every record in one read; with interleaving
  enabled, records above roughly 16 KB were never delivered.
- OpenSSL disables the DTLS replay window on SCTP. Reordering records
  across SCTP streams is therefore safe.
- **Handshake caveat.**
  - Before switching keys, OpenSSL waits for the SCTP `SENDER_DRY` event,
    meaning everything sent so far has been acknowledged.
  - If that event arrives while OpenSSL is reading for alerts, its BIO
    consumes it, and nothing else ever makes the socket readable.
  - cblink therefore re-polls the handshake every 50 ms until it completes.
    Re-arming the event makes FreeBSD raise it at once on an idle
    association.
  - Waiting for the peer's delayed SACK makes a DTLS/SCTP handshake take
    about 200 ms on FreeBSD's default `net.inet.sctp.delayed_sack_time`.

### 3.3 Availability

SCTP is in the GENERIC kernel, or available as the `sctp` module. The tests
skip SCTP cases when an SCTP socket cannot be created. The multihoming
test also needs `::1` on `lo0`.

## 4. Choosing a transport

| Need | Use |
|------|-----|
| Local IPC, identity by uid | `unix:` |
| General network use | `tcp://` with mTLS |
| Many independent streams, multihoming, no head-of-line blocking between streams | `sctp://` |
| Load balancing or a proxy in front | `tcp://` behind a TCP proxy (section 5) |

## 5. Behind a proxy

cblink does not speak HTTP. To put a server behind a load balancer, use a
TCP-level proxy, such as the nginx `stream` module or HAProxy in `mode tcp`,
with TLS passthrough:

- The proxy forwards the TCP connection unchanged, so mTLS stays end to end
  and the server sees and verifies the client's own certificate.
- Each connection stays on the server it was first sent to, so streams and
  subscriptions keep working.

### 5.1 The client's address: the PROXY protocol

Through a proxy, `cbl_peer_addr()` reports the proxy's address. To see the
client's, have the proxy send a PROXY protocol header (nginx
`proxy_protocol on;` in a `stream` server, HAProxy `send-proxy` or
`send-proxy-v2`) and create the listener with `CBL_LF_PROXY`:

- Versions 1 (text) and 2 (binary) are both accepted.
- Every connection must start with a header. One without it, or with a
  malformed one, is closed.
- `cbl_listener_add_proxy(l, "10.0.0.0/8")` (IPv4 or IPv6, up to 16) says
  who may send the header: a connection from any other address is closed
  before anything is read. Without such a list, a `CBL_LF_PROXY` listener
  must be reachable only through the proxy: anyone who can connect
  directly can claim any address.
- The header is read before TLS, and never past its end, so the TLS
  handshake that follows is the client's own.
- For TCP over IPv4 or IPv6, `cbl_peer_addr()` then reports the client's
  address and port, and `cbl_peer_flags()` includes `CBL_PEER_PROXIED`.
  A `LOCAL` header (version 2, used for health checks), `UNKNOWN`
  (version 1) or any other address family keeps the proxy's address.
- Only the addresses are used. TLVs, including the TLS details some proxies
  add, are ignored: identity comes from the end-to-end mTLS.
- A version 2 header may be at most 536 bytes. The header counts against
  `handshake_timeout`.
- `CBL_LF_PROXY` is for `tcp://` listeners only.

```nginx
stream {
	upstream cblink { server 192.0.2.10:7000; server 192.0.2.11:7000; }
	server {
		listen 7000;
		proxy_pass cblink;
		proxy_protocol on;
	}
}
```
