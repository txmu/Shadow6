# Privacy Envelope Exposure Audit

| Surface | Classification | Decision |
| --- | --- | --- |
| Native Core feature reports | PUBLIC_INTENTIONAL | Native contracts remain unchanged. |
| Control Center Web API | LOCAL_ONLY | Loopback, bearer authenticated, bounded and read-only by default. |
| S6EPE v3 hello on raw carrier | PUBLIC_INTENTIONAL | Version magic, ephemeral public key, random nonce and epoch; no Core identity or product credential. Identifiable by DPI. |
| TLS Carrier hello/proofs/records | ENCRYPTED_AUTHENTICATED | Genuine mTLS 1.3 encapsulates the entire envelope exchange; certificates, SNI, IPs, timing and volume remain observable. |
| WebRTC provider test sessions | ENCRYPTED_AUTHENTICATED | Native ICE/DTLS encrypts DataChannel records; standard handshake and network metadata remain observable. Provider/bridge loopback evidence does not mean the executable or Named Service currently deploys this carrier. |
| S6EPE v3 payload records | ENCRYPTED_AUTHENTICATED | Directional XChaCha20-Poly1305 secretstream/AEAD; no plaintext fallback. |
| Core/Gate behind envelope | LOCAL_ONLY | Private declaration must also match actual process-owned listeners. |
| Metrics and required datagram replay state | LOCAL_ONLY | Private bounded aggregate counters / nonce hashes; datagram startup requires the owner-controlled persistent store; no payload, PSK or credentials. |

Mutual PSK transcript proofs bind fresh ephemeral X25519 keys. The server opens
its native upstream only after authentication/key setup. UDP verifies AEAD,
direction, timestamp, epoch and replay before forwarding; a bounded reply credit
limits amplification. Optional private replay storage commits before forwarding
and survives restart. Stream sequence state rejects replay and reordering.

IPv4, IPv6 and Unix stream endpoints are supported. Unix datagrams are explicitly
unavailable. Deployment observations must verify the actual owned endpoints,
component graph and upstreams. Socket ownership does not prove authentication or
native protocol semantics. Unknown observations remain unavailable.

Optional padding/jitter/cover records have explicit byte, count and lifetime
limits and default off. S6EPE does not provide anonymity, undetectability or a
promise against DPI/blocking; traffic metadata remains visible; the v3 hello is visible on raw and encrypted
inside the TLS Carrier. No browser fingerprint equivalence is claimed.
Historical 10.3 review documents describe the preceding v2 implementation and
verification, not the v3 wire introduced in this follow-up.
