# Shadow6 application layer

This optional layer rides over the existing authenticated Shadow6 local TCP
proxy. Compile both cores with `APP_TRANSPORT=1` to advertise and grant the
Crosed `transport.application` capability. Existing opaque TCP forwarding and
all default configurations remain unchanged when it is disabled.

- `ProtocolFactory` performs bounded 32-bit framing and strict protocol/version
  dispatch without dynamic imports.
- `ShadowIdentity` creates Ed25519-signed, expiring identity assertions bound to
  compartment domains and arbitrary bounded JSON claims.
- `ShadowChat` provides authenticated UTF-8 messages using ChaCha20-Poly1305,
  Ed25519 sender signatures, timestamps, unique IDs, and a bounded replay
  window.

Text is normalized to Unicode NFC, encoded as UTF-8, rejects NUL, and is bounded
before encryption or framing. Protocol documents use explicit version 1
schemas; unsupported versions fail closed. Session-key establishment is left to
the already authenticated Shadow6 tunnel or a deployment-specific key exchange;
keys must never be passed on a command line or embedded in chat documents.

The Python module is a base API rather than a privileged daemon:

```python
from shadow_protocols import ShadowIdentity, ShadowChat, encode_frame

alice = ShadowIdentity.generate("alice")
chat = ShadowChat(session_key, alice)
wire_frame = encode_frame(chat.encrypt("bob", "你好，Shadow6"))
```
