# Streams

A stream is a long-lived, ordered channel of messages between two
endpoints, multiplexed on a connection with its own flow control. WebSocket
is the obvious comparison, minus HTTP. WIRE-FORMAT.md section 8 specifies
the protocol. This document covers using streams from programs. The
`examples/stream` program shows each piece.

## 1. Kinds of stream

| Direction | Opened with | Who sends data |
|-----------|-------------|----------------|
| bidirectional | an operation with `CBL_OPF_STREAM` | both ends |
| server-to-client ("push") | `CBL_OPF_PUSH`, opened with `CBL_SF_PUSH` | the acceptor only; the opener's direction is closed from the start |
| client-to-server | `CBL_OPF_STREAM` | the opener only; the acceptor half-closes its own direction itself, at once or after the opener's half-close (`on_hclose`); until it does, the stream stays open |

Either end of a connection may open a stream. It does so by sending a
request with `S_OPEN` for an operation of a family the other end has
registered. Stream ids keep simultaneous opens apart: the connection's
initiator uses odd ids, the acceptor even ids.

## 2. Life of a stream

```c
/* Opener */
cbl_msg_new(ctx, family, cmd, 0, &open);	/* the operation's request */
cbl_put_str(open, ATTR, "...");
cbl_stream_open(conn, open, flags, &cbs, arg, &s);
	/* -> cbs.on_open(s, accept, error, arg) */

/* Acceptor: the operation's stream_open handler */
int
op_stream_open(cbl_req *req, const cbl_msg *msg, cbl_stream *s, void *arg)
{
	return (cbl_stream_accept(s, NULL, 0, &cbs, state));
	/* or return an errno value: the open is rejected (ERROR|S_OPEN) */
}
```

- **Opening.** The open request is validated against the operation's
  policy like any request. The handler accepts by calling
  `cbl_stream_accept()`, optionally with an accept message of its own.
  It may already send data inside the handler.
  - If `cbl_stream_accept()` fails (an accept message that cannot be
    encoded, a connection that is closing), the stream is not accepted
    and none of the callbacks given to it will run: the caller still owns
    their argument.
  - A handler that returns 0 without accepting rejects the open with
    `ECONNREFUSED`.
  - A handler that returns an error after accepting resets the stream. Its
    `on_close` still runs, so per-stream state can always be freed there.
  - A handler that needs time (a lookup, say) defers with `cbl_req_defer()`
    and returns 0. Another thread then accepts with `cbl_stream_accept()`
    and calls `cbl_req_complete(req, 0)`, or refuses with
    `cbl_req_complete(req, error)`. The opener waits meanwhile, bounded by
    its request timeout.
- **Data.** `cbl_stream_msg_new()` starts a data message and
  `cbl_stream_send()` sends it. Each data message arrives at `on_data`.
- **Ending.**
  - `cbl_stream_half_close(s)`: "I have nothing more to send". When both
    directions are half-closed, the stream ends normally.
  - `cbl_stream_close(s, code, text)`: a graceful close of both directions.
    The peer answers with its own close. Without an answer within
    `stream_close_timeout` (default 10 s), the stream is reset.
  - `cbl_stream_reset(s, code)`: abort. Data still in flight is
    discarded.
- **`on_close(s, code, text, arg)` runs exactly once** for every stream,
  whichever way it ended. This includes an open the peer rejected, after
  `on_open` has reported the error, and the connection closing, which
  gives `ECONNRESET`. After `on_close` the stream pointer is invalid.
- **`on_close` never runs inside the call that ends the stream.** A
  stream ended by `cbl_stream_reset()`, a last `cbl_stream_send()` or
  `cbl_stream_half_close()` stays valid until that call, and any callback
  it was made from, returns. `on_close` then runs on the loop thread, or
  at the next `cbl_conn_process()` of a connection without a loop. So a
  callback may end its own stream. After that, no other callback of the
  stream runs but `on_close`.

All callbacks of a connection run on the thread of the loop it is attached
to. A stream may be used from other threads. Sends are thread-safe, and the
final callbacks are still delivered on the loop thread. A thread that may
call a stream after it ended takes a reference with `cbl_stream_ref()`:
the stream then stays valid, answering `EPIPE`, until `cbl_stream_rele()`.

## 3. Flow control

Every direction has a window in bytes, granted by the receiver. A data
frame costs its full length, header included.

- **Sending.** When a message does not fit in the credit left,
  `cbl_stream_send()` returns `EAGAIN` and does not take the message. The
  sender keeps it (or frees it) and stops sending. Once the receiver has
  granted at least some credit, `on_writable(s, credit, arg)` runs, and the
  sender resumes. Frames are never split: a sender always waits for enough
  credit for the next whole frame.
- **Receiving.** By default credit is returned automatically after
  `on_data` returns. To keep control traffic down, it is returned in
  batches, once half the window has been consumed.
  - With `CBL_SF_MANUAL_CREDIT` (on open or accept), credit is returned
    only when the application calls `cbl_stream_consumed(s, bytes)`. This
    lets a slow consumer (writing to disk, forwarding elsewhere) push
    backpressure all the way to the sender.
- **Window size.**
  - The default window is the `stream_window` limit, 256 KiB by default.
  - An opener announces its window in the open, and an acceptor in its
    accept.
  - `cbl_msg_set_window(msg, bytes)` on the open or accept message changes
    it for one stream. Generated code does this for a spec's
    `initial-credit`.
  - A peer that sends beyond the window has the stream reset with
    `ENOBUFS`.

Streams also share their connection's limits:
- `max_streams` open streams per connection (default 64); further opens
  are rejected with `ENOSPC`;
- `sendq_bytes` of queued output.

## 4. Transports

| Transport | Streams |
|-----------|---------|
| TCP, TLS, AF_UNIX | all kinds |
| SCTP, DTLS over SCTP | all kinds; each stream travels on its own SCTP stream, so streams do not block each other (TRANSPORTS.md) |

## 5. Generated streams

For a `streams:` entry in a spec, cblink-gen generates typed wrappers
(GENERATOR.md section 3):
- `P_<stream>_open()` with typed callbacks, and `P_<stream>_send()` for
  the opener;
- the `P_<stream>_stream_open()` handler prototype, `P_<stream>_accept()`
  and `P_<stream>_server_send()` for the acceptor.

The data structures are those of the stream's payload attribute set.
