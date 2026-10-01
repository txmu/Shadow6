# C11Relay

`bridge_relay` is a bounded, bidirectional UDP relay. It maintains one connected
upstream socket per client mapping so replies return to the correct client.

```sh
./bridge_relay --bind 127.0.0.1 --port 4433 \
  --dest 127.0.0.1:4434 --mode normal
```

Modes:

- `normal`: ordinary datagram forwarding.
- `high-speed`: on Linux, processes up to 256 datagrams per `recvmmsg` call
  in each direction and sends a client's queued replies with `sendmmsg`, with
  one reusable bounded buffer and the same per-peer limits. Partial sends
  advance only the completed prefix; backpressure drops the unsent remainder
  with metrics instead of blocking other peers. It uses ordinary UDP sockets
  and needs no capabilities or root.
  Other supported hosts retain the ordinary receive loop with the same wire
  format. The current implementation is bounded by configured peer, queue,
  packet-rate and burst limits; it is not limited to one batch size overall.
- `data-saving`: framed RLE transport. Both ends must be C11Relay instances in
  data-saving mode; it is not compatible with an ordinary UDP endpoint.

The relay bounds peers, mapping lifetime, packet rate, and burst size. Run
`bash test.sh` for sanitizer self-tests and a real local UDP echo integration
test.

## Node FastRPC and RawIPC companion

The dependency-free `Node-IPC/c11relay.mjs` companion exposes the existing
fixed-target UDP relay through authenticated local IPC. FastRPC methods are
`c11relay.capabilities`, `c11relay.status`, `c11relay.exchange`, and bounded
`c11relay.batch`. RawIPC types are datagram (`17`), metrics (`19`), and batch
(`20`). The companion enforces configured peer, queue, packet-rate, burst,
timeout, and batch limits; it never exposes arbitrary C11Relay control or
changes admission policy. Run `node --test Node-IPC/test_ipc.mjs` for the
loopback UDP, encryption, authentication, replay, and peer-isolation tests.
